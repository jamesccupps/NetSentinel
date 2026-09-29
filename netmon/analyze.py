"""
Offline analyzer.
=================
Point it at a profile and an export and it tells you what it found:

    python -m netmon.analyze --profile my-site.yaml --unifi flows.csv

Offline first, deliberately. Everything here can be run against yesterday's
export on a laptop, which means the rules can be tuned, argued with and
re-tuned before anything is installed on a live network — and a rule that has
never been run over real traffic is a guess.

It is advisory. It reads files and prints findings. Nothing here touches the
network, changes a device, or sends anything anywhere.
"""

from __future__ import annotations

import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.events import Deduplicator, Severity, Tier, enrich  # noqa: E402
from netmon.profile import ProfileError, load_profile           # noqa: E402
from netmon.rules_engine import RuleError, load_rules           # noqa: E402

import netmon.handlers                                          # noqa: E402,F401

logger = logging.getLogger("netmon.analyze")

__all__ = ['Analyzer', 'analyze_unifi_export']

DEFAULT_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules')


class Analyzer:
    """Runs a stream of events through enrichment, the rules and deduplication."""

    def __init__(self, profile, rules, dedup_window_sec=3600):
        self.profile = profile
        self.rules = rules
        self.dedup = Deduplicator(window_sec=dedup_window_sec)
        self.findings = []
        self.events_seen = 0
        self.started = time.time()

    def feed(self, events):
        """Consume an iterable of Events, keeping the findings that survive dedup."""
        for event in events:
            self.events_seen += 1
            enrich(event, self.profile)
            for finding in self.rules.evaluate(event):
                admitted = self.dedup.admit(finding)
                if admitted is not None:
                    self.findings.append(admitted)
        return self.findings

    def by_severity(self):
        ordered = sorted(self.findings,
                         key=lambda f: (-Severity.rank(f.severity), f.ts))
        return ordered

    def push_findings(self):
        return [f for f in self.findings if f.tier == Tier.PUSH]

    def report(self):
        by_rule, by_severity = {}, {}
        for finding in self.findings:
            by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        return {
            'events': self.events_seen,
            'findings': len(self.findings),
            'push': len(self.push_findings()),
            'by_severity': dict(sorted(by_severity.items(),
                                       key=lambda kv: -Severity.rank(kv[0]))),
            'by_rule': dict(sorted(by_rule.items(), key=lambda kv: -kv[1])),
            'suppressed_repeats': sum(
                count - 1 for count in self.dedup.suppressed_counts().values()),
            'seconds': round(time.time() - self.started, 2),
        }


def analyze_unifi_export(path, profile_path, rules_path=DEFAULT_RULES, limit=None):
    """Convenience wrapper: one export, one profile, findings out."""
    from netmon.sources.unifi_csv import read_flows

    analyzer = Analyzer(load_profile(profile_path), load_rules(rules_path))
    analyzer.feed(read_flows(path, limit=limit))
    return analyzer


# ─── Output ──────────────────────────────────────────────────────────────────

_SEVERITY_MARK = {
    Severity.CRITICAL: '!!', Severity.HIGH: '! ', Severity.MEDIUM: '~ ',
    Severity.LOW: '  ', Severity.INFO: '  ',
}


def format_findings(analyzer, show_next_check=True, limit=None):
    """Findings as text, worst first, grouped by tier."""
    lines = []
    findings = analyzer.by_severity()
    if limit:
        findings = findings[:limit]

    if not findings:
        return ['Nothing found.',
                f'  {analyzer.events_seen} events, '
                f'{len(analyzer.rules)} rules, no findings.',
                '',
                '  That is a result, not a failure — but check the export covers',
                '  the VLANs you care about before reading it as an all-clear.']

    for tier, heading in ((Tier.PUSH, 'Needs attention now'),
                          (Tier.DIGEST, 'For the daily report'),
                          (Tier.WEEKLY, 'Weekly')):
        group = [f for f in findings if f.tier == tier]
        if not group:
            continue
        lines.append(f'{heading} ({len(group)})')
        lines.append('─' * 78)
        for finding in group:
            mark = _SEVERITY_MARK.get(finding.severity, '  ')
            repeat = f'  (x{finding.count})' if finding.count > 1 else ''
            lines.append(f'{mark} [{finding.severity:8}] {finding.rule_id}{repeat}')
            lines.append(f'      {finding.description}')
            if finding.evidence:
                shown = ', '.join(f'{k}={v}' for k, v in finding.evidence.items()
                                  if v not in (None, '', [], {}))
                if shown:
                    lines.append(f'      {shown}')
            if show_next_check and finding.next_check:
                lines.append(f'      next: {finding.next_check}')
            lines.append('')
    return lines


def _main(argv=None):
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog='python -m netmon.analyze',
        description='Run detection rules over an export or capture. '
                    'Reads files and prints findings; changes nothing.')
    parser.add_argument('--profile', required=True, help='site profile YAML')
    parser.add_argument('--rules', default=DEFAULT_RULES,
                        help='rule file or directory (default: the shipped rules)')
    parser.add_argument('--unifi', metavar='CSV',
                        help='UniFi flow export (.csv or .csv.gz)')
    parser.add_argument('--pcap', metavar='FILE',
                        help='a capture file. Protocol-aware rules — BACnet, '
                             'TLS server names, DNS, DHCP — need this; a flow '
                             'export does not carry any of it')
    parser.add_argument('--no-dedup-router', action='store_true',
                        help='keep the router-relayed copy of routed packets. '
                             'A trunk mirror shows each one twice')
    parser.add_argument('--limit', type=int, help='stop after N events')
    parser.add_argument('--dedup-window', type=int, default=3600,
                        metavar='SEC', help='collapse repeats within this window')
    parser.add_argument('--min-severity', default='info',
                        choices=['info', 'low', 'medium', 'high', 'critical'])
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--quiet', action='store_true',
                        help='summary only, no individual findings')
    parser.add_argument('--notify', action='store_true',
                        help='push the findings that need attention now. '
                             'Configure with NETMON_NTFY_SERVER and '
                             'NETMON_NTFY_TOPIC, or --secrets')
    parser.add_argument('--digest', action='store_true',
                        help='send the daily report')
    parser.add_argument('--summarise', '--summarize', action='store_true',
                        dest='summarise',
                        help='ask a model to triage the findings. Sends a '
                             'redacted summary — no payload, nothing from a '
                             'metadata-only segment — and prints its reasoning')
    parser.add_argument('--investigate', metavar='DEVICE',
                        help='ask about one device rather than the whole window')
    parser.add_argument('--secrets', metavar='FILE',
                        help='JSON file with the ntfy settings. Must be mode '
                             '600; the environment overrides it')
    parser.add_argument('--dry-run', action='store_true',
                        help='with --notify or --digest, print what would be '
                             'sent instead of sending it')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format='%(levelname)s: %(message)s')

    if not args.unifi and not args.pcap:
        parser.error('nothing to read — pass --unifi with an export '
                     'or --pcap with a capture')

    try:
        profile = load_profile(args.profile)
    except ProfileError as e:
        print(f'profile: {e}', file=sys.stderr)
        return 1
    try:
        rules = load_rules(args.rules)
    except RuleError as e:
        print(f'rules: {e}', file=sys.stderr)
        return 1

    analyzer = Analyzer(profile, rules, dedup_window_sec=args.dedup_window)
    sources = []

    if args.unifi:
        from netmon.sources.unifi_csv import UnifiCsvError, read_flows
        try:
            analyzer.feed(read_flows(args.unifi, limit=args.limit))
        except UnifiCsvError as e:
            print(f'export: {e}', file=sys.stderr)
            return 1
        sources.append(os.path.basename(args.unifi))

    if args.pcap:
        from netmon.sources.pcap import PcapError, read_pcap
        try:
            analyzer.feed(read_pcap(args.pcap, profile, limit=args.limit,
                                    dedup_router=not args.no_dedup_router))
        except PcapError as e:
            print(f'capture: {e}', file=sys.stderr)
            return 1
        sources.append(os.path.basename(args.pcap))

    floor = Severity.rank(args.min_severity)
    analyzer.findings = [f for f in analyzer.findings
                         if Severity.rank(f.severity) >= floor]

    if args.json:
        print(json.dumps({'sources': sources, 'report': analyzer.report(),
                          'findings': [f.as_dict() for f in analyzer.by_severity()]},
                         indent=2, default=str))
        return 0

    report = analyzer.report()
    print(f"{profile.name} — {' + '.join(sources)}")
    print(f"  {report['events']} events, {len(rules)} rules, "
          f"{report['seconds']}s")
    if report['suppressed_repeats']:
        print(f"  {report['suppressed_repeats']} repeats collapsed")
    print()
    if not args.quiet:
        for line in format_findings(analyzer):
            print(line)
    print(f"{report['findings']} findings"
          + (f", {report['push']} needing attention now" if report['push'] else ''))
    if report['by_severity']:
        print('  ' + ', '.join(f'{k} {v}' for k, v in report['by_severity'].items()))

    if args.summarise or args.investigate:
        code = _summarise(analyzer, profile, args)
        if code:
            return code

    if args.notify or args.digest:
        code = _notify(analyzer, profile, args)
        if code:
            return code

    # A non-zero exit when something needs attention, so this can be a cron job.
    return 2 if report['push'] else 0


def _summarise(analyzer, profile, args):
    """Ask a model to triage. Advisory: nothing it returns is executed."""
    from netmon.summarise import (Summariser, SummaryError,
                                  format_summary, load_summariser_config)
    try:
        config = load_summariser_config(args.secrets)
    except Exception as e:
        print(f'summariser: {e}', file=sys.stderr)
        return 1

    summariser = Summariser(config)
    try:
        if args.investigate:
            result = summariser.investigate(analyzer, profile, args.investigate)
        else:
            result = summariser.summarise(analyzer, profile)
    except SummaryError as e:
        print(f'summariser: {e}', file=sys.stderr)
        return 1

    print()
    print('─' * 78)
    print('Model triage — advisory only, nothing here has been run')
    print('─' * 78)
    print(format_summary(result))
    return 0


def _notify(analyzer, profile, args):
    """Deliver the findings. Returns a non-zero code only on a real failure."""
    from netmon.alerting import AlertingError, Notifier, load_config

    try:
        config = load_config(args.secrets)
    except AlertingError as e:
        print(f'alerting: {e}', file=sys.stderr)
        return 1
    if args.dry_run:
        config.dry_run = True

    notifier = Notifier(config, profile)
    try:
        if args.notify:
            sent, skipped = notifier.send(analyzer.findings)
            print()
            print(f'pushed {len(sent)}, held back {len(skipped)} for the digest')
        if args.digest:
            notifier.send_digest(analyzer)
            print('digest sent')
    except AlertingError as e:
        print(f'alerting: {e}', file=sys.stderr)
        return 1

    if config.dry_run:
        for message in notifier.sent:
            print()
            print(f'--- would POST to {message["url"]} ---')
            print(message['body'])
    if notifier.failures:
        print(f'{len(notifier.failures)} could not be delivered', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    from netmon.analyze import _main as main
    sys.exit(main())
