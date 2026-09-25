"""
Rules engine.
=============
Detection rules live in YAML so the person running the site can edit them
without touching the engine — add a watched name, raise a threshold, silence a
rule for a device that is known to be odd.

A rule is field comparisons against an enriched event:

    - id: bacnet_control
      title: BACnet control write outside the allowlist
      severity: high
      tier: push
      when:
        kind: bacnet
        service: [WriteProperty, WritePropertyMultiple]
      unless:
        bacnet_write_allowed: true
      device: src_name
      key: "{dst_ip}"
      describe: "{src_name} sent {service} to {dst_name}"

`when` must all match; `unless` cancels the match if it all matches. Everything
the profile knows was resolved by `enrich()` before the rule ran, so a rule can
say `flow_expected: false` or `src_zone: ot` and mean it.

The condition language
----------------------
A bare value is equality, a list is membership, and a mapping is an operator:

    port: 443                     equals
    port: [80, 443]               one of
    bytes: {gt: 1000000}          gt gte lt lte
    sni: {matches: "anydesk"}     regex, case-insensitive
    name: {contains: "wpad"}      substring
    service: {not: Read}          negation
    sni: {exists: true}           present and non-empty
    any: [{...}, {...}]           at least one sub-condition

Nothing is evaluated as code. Templates substitute `{field}` by name and
nothing else — no attribute access, no formatting specs — so a rule file cannot
reach into the interpreter.

Stateful rules
--------------
Beaconing, new-device and baseline-deviation rules cannot be expressed as a test
on one event. Those declare `type: stateful` with a `handler` naming a function
registered in Python, and keep their thresholds in YAML where they can still be
tuned:

    - id: beaconing
      type: stateful
      handler: beaconing
      tier: digest
      params: {min_samples: 12, max_jitter: 0.15}

The split is deliberate: the declarative language stays small enough to be
obviously correct, and the handful of rules that genuinely need memory get real
code instead of a YAML dialect slowly growing into a programming language.
"""

from __future__ import annotations

import logging
import os
import re

import yaml

from netmon.events import Finding, Severity, Tier

logger = logging.getLogger("netmon.rules")

__all__ = ['Rule', 'RuleSet', 'RuleError', 'load_rules', 'register_handler',
           'evaluate_condition', 'render']


class RuleError(ValueError):
    """A rule file is malformed. Raised naming the rule and the offending key."""


# ─── Stateful handler registry ───────────────────────────────────────────────

_HANDLERS = {}


def register_handler(name):
    """
    Decorator registering a stateful rule handler.

    A handler is called as `handler(event, rule, state)` and returns a Finding,
    a list of Findings, or None. `state` is a dict private to that rule instance,
    so a handler keeps its history without a global.
    """
    def decorate(function):
        _HANDLERS[name] = function
        return function
    return decorate


def available_handlers():
    return sorted(_HANDLERS)


# ─── Condition evaluation ────────────────────────────────────────────────────

_OPERATORS = {'eq', 'ne', 'not', 'in', 'not_in', 'gt', 'gte', 'lt', 'lte',
              'matches', 'contains', 'exists'}


def _as_number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _equal(actual, expected):
    """Case-insensitive for strings, tolerant of 3 vs '3' across sources."""
    if isinstance(actual, str) and isinstance(expected, str):
        return actual.lower() == expected.lower()
    if isinstance(actual, bool) or isinstance(expected, bool):
        return bool(actual) == bool(expected)
    if actual == expected:
        return True
    left, right = _as_number(actual), _as_number(expected)
    return left is not None and right is not None and left == right


def _compare(actual, expected, operator):
    left, right = _as_number(actual), _as_number(expected)
    if left is None or right is None:
        return False
    return {'gt': left > right, 'gte': left >= right,
            'lt': left < right, 'lte': left <= right}[operator]


def _apply_operator(actual, operator, operand):
    if operator == 'eq':
        return _equal(actual, operand)
    if operator in ('ne', 'not'):
        if isinstance(operand, list):
            return not any(_equal(actual, item) for item in operand)
        return not _equal(actual, operand)
    if operator == 'in':
        return any(_equal(actual, item) for item in operand or [])
    if operator == 'not_in':
        return not any(_equal(actual, item) for item in operand or [])
    if operator in ('gt', 'gte', 'lt', 'lte'):
        return _compare(actual, operand, operator)
    if operator == 'matches':
        if actual is None:
            return False
        return re.search(str(operand), str(actual), re.IGNORECASE) is not None
    if operator == 'contains':
        if actual is None:
            return False
        haystack = str(actual).lower()
        if isinstance(operand, list):
            return any(str(item).lower() in haystack for item in operand)
        return str(operand).lower() in haystack
    if operator == 'exists':
        present = actual not in (None, '', [], {})
        return present is bool(operand)
    raise RuleError(f'unknown operator {operator!r}')


def evaluate_condition(condition, event):
    """
    True when every clause matches. An empty condition matches everything.

    `any:` takes a list of sub-conditions and matches when one of them does,
    which is the only nesting the language has — deeper structure is a sign the
    rule wants to be two rules.
    """
    if not condition:
        return True
    if not isinstance(condition, dict):
        raise RuleError(f'condition must be a mapping, got {type(condition).__name__}')

    for field_name, expected in condition.items():
        if field_name == 'any':
            if not any(evaluate_condition(sub, event) for sub in expected or []):
                return False
            continue
        if field_name == 'all':
            if not all(evaluate_condition(sub, event) for sub in expected or []):
                return False
            continue

        actual = event.get(field_name)

        if isinstance(expected, dict):
            for operator, operand in expected.items():
                if operator not in _OPERATORS:
                    raise RuleError(
                        f'{field_name}: unknown operator {operator!r}; '
                        f'known operators are {", ".join(sorted(_OPERATORS))}')
                if not _apply_operator(actual, operator, operand):
                    return False
        elif isinstance(expected, list):
            if not any(_equal(actual, item) for item in expected):
                return False
        elif not _equal(actual, expected):
            return False

    return True


# ─── Templates ───────────────────────────────────────────────────────────────

_PLACEHOLDER = re.compile(r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}')


def render(template, event, fallback='?'):
    """
    Substitute `{field}` from the event. Deliberately not str.format.

    str.format on a rule-supplied string would allow `{x.__class__.__mro__}` and
    friends, which turns an editable rule file into a way to read the
    interpreter. This handles names and nothing else.
    """
    if not template:
        return ''

    def replace(match):
        value = event.get(match.group(1))
        if value is None or value == '':
            return fallback
        return str(value)

    return _PLACEHOLDER.sub(replace, str(template))


# ─── Rules ───────────────────────────────────────────────────────────────────

class Rule:
    """One detection rule, loaded from YAML."""

    def __init__(self, spec):
        if not isinstance(spec, dict):
            raise RuleError(f'a rule must be a mapping, got {type(spec).__name__}')

        self.id = spec.get('id') or ''
        if not self.id:
            raise RuleError('a rule needs an id')

        self.title = spec.get('title', self.id)
        self.severity = Severity.normalise(spec.get('severity', Severity.MEDIUM))
        self.tier = str(spec.get('tier', Tier.DIGEST)).lower()
        self.enabled = bool(spec.get('enabled', True))
        self.type = spec.get('type', 'field')
        self.handler_name = spec.get('handler', '')
        self.params = dict(spec.get('params') or {})

        self.when = spec.get('when') or {}
        self.unless = spec.get('unless') or {}
        self.describe = spec.get('describe', '')
        self.next_check = spec.get('next_check', '')
        self.device_field = spec.get('device', 'src_name')
        self.key_template = spec.get('key', '')
        self.evidence_fields = list(spec.get('evidence') or [])
        self.grounded_in = spec.get('grounded_in', '')

        # "Push on building VLANs, else digest" — one rule, context-dependent
        # delivery, rather than two near-identical rules that drift apart.
        self.escalate = spec.get('escalate') or None

        self._validate()
        self.state = {}

    def _validate(self):
        if self.type not in ('field', 'stateful'):
            raise RuleError(f'{self.id}: type must be field or stateful')
        if self.type == 'stateful':
            if not self.handler_name:
                raise RuleError(f'{self.id}: a stateful rule needs a handler')
            if self.handler_name not in _HANDLERS:
                raise RuleError(
                    f'{self.id}: no handler named {self.handler_name!r}; '
                    f'registered handlers are {", ".join(available_handlers()) or "none"}')
        elif not self.when:
            raise RuleError(f'{self.id}: a field rule needs a `when` condition')

        if self.tier not in (Tier.PUSH, Tier.DIGEST, Tier.WEEKLY):
            raise RuleError(f'{self.id}: tier must be push, digest or weekly')

        # Catch operator typos at load time rather than at 3am on a live feed.
        for name, condition in (('when', self.when), ('unless', self.unless)):
            try:
                _check_operators(condition)
            except RuleError as e:
                raise RuleError(f'{self.id}.{name}: {e}') from e

        if self.escalate is not None:
            if not isinstance(self.escalate, dict):
                raise RuleError(f'{self.id}: escalate must be a mapping')
            try:
                _check_operators(self.escalate.get('when') or {})
            except RuleError as e:
                raise RuleError(f'{self.id}.escalate.when: {e}') from e

    def matches(self, event):
        if not self.enabled:
            return False
        if not evaluate_condition(self.when, event):
            return False
        if self.unless and evaluate_condition(self.unless, event):
            return False
        return True

    def finding_for(self, event):
        """Build the Finding this rule produces for an event it matched."""
        severity, tier = self.severity, self.tier
        if self.escalate and evaluate_condition(self.escalate.get('when') or {}, event):
            severity = Severity.normalise(self.escalate.get('severity', severity))
            tier = str(self.escalate.get('tier', tier)).lower()

        device = event.get(self.device_field) or event.src_ip or event.src_mac or ''
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=severity,
            tier=tier,
            description=render(self.describe, event) or self.title,
            ts=event.ts,
            device=str(device),
            key=render(self.key_template, event, fallback=''),
            next_check=render(self.next_check, event),
            event=event,
            evidence={name: event.get(name) for name in self.evidence_fields},
        )

    def evaluate(self, event):
        """Return a list of Findings — empty when the rule does not fire."""
        if not self.enabled:
            return []

        if self.type == 'stateful':
            if self.when and not evaluate_condition(self.when, event):
                return []
            result = _HANDLERS[self.handler_name](event, self, self.state)
            if result is None:
                return []
            return list(result) if isinstance(result, (list, tuple)) else [result]

        return [self.finding_for(event)] if self.matches(event) else []

    def __repr__(self):
        return f'<Rule {self.id} {self.severity}/{self.tier}>'


def _check_operators(condition):
    """Walk a condition and reject unknown operators before anything runs."""
    if not isinstance(condition, dict):
        return
    for field_name, expected in condition.items():
        if field_name in ('any', 'all'):
            for sub in expected or []:
                _check_operators(sub)
        elif isinstance(expected, dict):
            for operator in expected:
                if operator not in _OPERATORS:
                    raise RuleError(
                        f'{field_name}: unknown operator {operator!r}; known '
                        f'operators are {", ".join(sorted(_OPERATORS))}')


class RuleSet:
    """A loaded collection of rules, evaluated against one event at a time."""

    def __init__(self, rules=None):
        self.rules = list(rules or [])
        self._check_unique_ids()

    def _check_unique_ids(self):
        seen = set()
        for rule in self.rules:
            if rule.id in seen:
                raise RuleError(f'duplicate rule id {rule.id!r}')
            seen.add(rule.id)

    def evaluate(self, event):
        """
        Every rule sees every event. A misbehaving rule is logged and skipped
        rather than allowed to stop the others — one bad regex should not take
        the monitor down.
        """
        findings = []
        for rule in self.rules:
            try:
                findings.extend(rule.evaluate(event))
            except Exception:
                logger.exception('rule %s raised on a %s event; skipping it',
                                 rule.id, event.kind)
        return findings

    def by_id(self, rule_id):
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def enable(self, rule_id, enabled=True):
        rule = self.by_id(rule_id)
        if rule is not None:
            rule.enabled = enabled
        return rule is not None

    def summary(self):
        by_tier, by_severity = {}, {}
        for rule in self.rules:
            if not rule.enabled:
                continue
            by_tier[rule.tier] = by_tier.get(rule.tier, 0) + 1
            by_severity[rule.severity] = by_severity.get(rule.severity, 0) + 1
        return {
            'rules': len(self.rules),
            'enabled': sum(1 for r in self.rules if r.enabled),
            'stateful': sum(1 for r in self.rules if r.type == 'stateful'),
            'by_tier': dict(sorted(by_tier.items())),
            'by_severity': dict(sorted(by_severity.items())),
        }

    def __len__(self):
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)


def _ensure_handlers():
    """
    Make sure the stateful handlers are registered before rules are validated.

    Imported here rather than at module scope because netmon.handlers imports
    this module; by the time load_rules is called, this one is fully
    initialised and the cycle resolves.

    Doing it here rather than in each entry point is deliberate. Leaving it to
    the caller means a program that happens to import netmon.handlers for some
    other reason works, and one that does not fails at startup with "no handler
    named overlapping_ip" — a bug that reaches whichever entry point nobody
    tried, which is how it was found.
    """
    if _HANDLERS:
        return
    try:
        import netmon.handlers                        # noqa: F401
    except ImportError as e:
        logger.warning('stateful rule handlers unavailable: %s', e)


def load_rules(path):
    """
    Load rules from a YAML file, or every *.yaml in a directory.

    A directory is the usual case: the shipped core rules plus whatever the site
    has added, loaded in sorted order so behaviour does not depend on the
    filesystem.
    """
    _ensure_handlers()
    paths = []
    if os.path.isdir(path):
        paths = sorted(os.path.join(path, name) for name in os.listdir(path)
                       if name.endswith(('.yaml', '.yml')))
        if not paths:
            raise RuleError(f'no rule files in {path}')
    elif os.path.exists(path):
        paths = [path]
    else:
        raise RuleError(f'rules not found: {path}')

    rules = []
    for file_path in paths:
        with open(file_path, encoding='utf-8') as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise RuleError(f'{file_path}: {e}') from e
        if data is None:
            continue
        if isinstance(data, dict):
            data = data.get('rules', [])
        if not isinstance(data, list):
            raise RuleError(f'{file_path}: expected a list of rules')
        for spec in data:
            try:
                rules.append(Rule(spec))
            except RuleError as e:
                raise RuleError(f'{os.path.basename(file_path)}: {e}') from e

    return RuleSet(rules)


def _main(argv=None):
    """`python -m netmon.rules_engine --check` — validate a rule file."""
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog='python -m netmon.rules_engine',
        description='Validate detection rules and describe what they cover.')
    parser.add_argument('path', nargs='?',
                        default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                             'rules'),
                        help='a rule file or a directory of them')
    parser.add_argument('--check', action='store_true',
                        help='validate only, print nothing on success')
    parser.add_argument('--json', action='store_true', help='machine-readable')
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

    try:
        rules = load_rules(args.path)
    except RuleError as e:
        print(f'invalid: {e}')
        return 1

    if args.check:
        return 0

    summary = rules.summary()
    if args.json:
        print(json.dumps(summary, indent=2))
        return 0

    print(f"{summary['rules']} rules from {args.path}")
    print(f"  {summary['enabled']} enabled, {summary['stateful']} stateful")
    print(f"  by tier:     " + ', '.join(f'{k} {v}' for k, v in summary['by_tier'].items()))
    print(f"  by severity: " + ', '.join(f'{k} {v}' for k, v in summary['by_severity'].items()))
    print()
    for rule in rules:
        flag = ' ' if rule.enabled else '-'
        print(f"  {flag} {rule.id:24} {rule.severity:8} {rule.tier:7} {rule.title}")

    ungrounded = [r.id for r in rules if not r.grounded_in.strip()]
    if ungrounded:
        print()
        print('no grounded_in (a rule nobody can trace to an observation is one '
              'nobody will trust): ' + ', '.join(ungrounded))
    return 0


if __name__ == '__main__':
    import sys

    # Delegate to this module under its real name. Run as `python -m`, this file
    # is `__main__`, and netmon.handlers' `from netmon.rules_engine import
    # register_handler` would then import a *second* copy with its own empty
    # registry — so every stateful rule would fail to find a handler that had in
    # fact just been registered, into the other copy.
    from netmon.rules_engine import _main as main
    sys.exit(main())
