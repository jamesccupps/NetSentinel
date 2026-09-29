"""
Getting findings to a person.
==============================
Push for what needs attention now, a digest for the rest. Everything goes
through `netmon.redact` first; nothing in this module decides what is safe to
send, it only decides how and when.

    from netmon.alerting import Notifier, load_config
    notifier = Notifier(load_config(), profile)
    notifier.send(findings)

Why an open topic is refused
----------------------------
ntfy's public server has no access control on a topic: anyone who guesses or
overhears the name receives everything sent to it, forever. This monitor's
alerts name devices, addresses and weaknesses — publishing them to a guessable
string is worse than not alerting at all, because it is a live feed of the
site's soft spots to anyone who wants one.

So the public server is refused without a token, and the error says why. A
self-hosted server, or ntfy.sh with an access token, is fine.

Secrets
-------
From the environment, or a file readable only by the user running this. Never
from the profile, never from the repository, and never logged. `load_config`
checks the file's mode and refuses one that is group- or world-readable, because
a secrets file everyone can read is not a secrets file.

Quiet by design
---------------
Push is reserved for the `push` tier. A notification for something low is how
push gets muted, after which nothing gets through at all. Deduplication happens
before this module sees anything — one laptop produced 1,017 NAT-PMP requests in
an afternoon, and that is one notification, not 1,017.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import time
import urllib.error
import urllib.request

from netmon.events import Severity, Tier
from netmon.redact import ALERT, redact_finding

logger = logging.getLogger("netmon.alerting")

__all__ = ['Notifier', 'NotifierConfig', 'load_config', 'AlertingError',
           'build_digest']


class AlertingError(ValueError):
    """Alerting is misconfigured. The message says what to fix."""


#: ntfy priorities. Findings below `high` never push, so only these are mapped.
_PRIORITY = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
             Severity.LOW: 2, Severity.INFO: 1}

_TAGS = {Severity.CRITICAL: 'rotating_light', Severity.HIGH: 'warning',
         Severity.MEDIUM: 'eyes', Severity.LOW: 'information_source',
         Severity.INFO: 'information_source'}

#: Public ntfy servers, where a topic is readable by anyone who knows its name.
_OPEN_SERVERS = ('ntfy.sh', 'https://ntfy.sh', 'http://ntfy.sh')


class NotifierConfig:
    """Where alerts go, and how loud."""

    def __init__(self, server='', topic='', token='', enabled=True,
                 min_push_severity=Severity.HIGH, timeout=10,
                 digest_topic='', dry_run=False, extract_seconds=30):
        self.server = (server or '').rstrip('/')
        self.topic = topic or ''
        self.token = token or ''
        self.enabled = bool(enabled)
        self.min_push_severity = Severity.normalise(min_push_severity)
        self.timeout = int(timeout)
        self.digest_topic = digest_topic or topic or ''
        self.dry_run = bool(dry_run)
        self.extract_seconds = int(extract_seconds)

    def validate(self):
        """Raise AlertingError on anything that would fail or leak at send time."""
        if not self.enabled:
            return True
        if not self.server:
            raise AlertingError('no ntfy server configured')
        if not self.topic:
            raise AlertingError('no ntfy topic configured')

        host = self.server.split('//')[-1].split('/')[0].lower()
        if host in ('ntfy.sh',) and not self.token:
            raise AlertingError(
                'refusing to publish to a public ntfy topic without a token. '
                'Anyone who guesses the topic name would receive every alert — '
                'a live feed of this site\'s weaknesses. Use an access token, '
                'or host your own server.')
        if self.server.startswith('http://') and self.token:
            raise AlertingError(
                'refusing to send a token over plain http; use https, or drop '
                'the token and use a server reachable only on your network')
        return True

    def describe(self):
        """For logs and the UI. Never includes the token."""
        return {'server': self.server, 'topic': self.topic,
                'authenticated': bool(self.token), 'enabled': self.enabled,
                'min_push_severity': self.min_push_severity,
                'dry_run': self.dry_run}


def load_config(path=None, environ=None):
    """
    Read alerting settings from the environment, or from a secrets file.

    The file is JSON and must not be readable by anyone but its owner. A secrets
    file the group can read is not a secrets file, and finding that out after it
    leaks is too late.

    Environment wins over the file, so a systemd unit or a container can set
    NETMON_NTFY_TOKEN without editing anything on disk.
    """
    environ = environ if environ is not None else os.environ
    data = {}

    path = path or environ.get('NETMON_SECRETS')
    if path:
        data = _read_secrets_file(path)

    def pick(key, env_name, default=''):
        return environ.get(env_name) or data.get(key) or default

    return NotifierConfig(
        server=pick('ntfy_server', 'NETMON_NTFY_SERVER'),
        topic=pick('ntfy_topic', 'NETMON_NTFY_TOPIC'),
        token=pick('ntfy_token', 'NETMON_NTFY_TOKEN'),
        digest_topic=pick('ntfy_digest_topic', 'NETMON_NTFY_DIGEST_TOPIC'),
        enabled=str(pick('enabled', 'NETMON_ALERTS_ENABLED', 'true')).lower()
        not in ('0', 'false', 'no', 'off'),
        min_push_severity=pick('min_push_severity', 'NETMON_MIN_PUSH_SEVERITY',
                               Severity.HIGH),
        dry_run=str(pick('dry_run', 'NETMON_ALERTS_DRY_RUN', 'false')).lower()
        in ('1', 'true', 'yes', 'on'))


def _read_secrets_file(path):
    if not os.path.exists(path):
        raise AlertingError(f'secrets file not found: {path}')

    mode = os.stat(path).st_mode
    if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
        raise AlertingError(
            f'{path} is readable or writable beyond its owner '
            f'(mode {stat.filemode(mode)}). Run: chmod 600 {path}')

    try:
        with open(path, encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as e:
        # Deliberately does not echo the file's contents into the error.
        raise AlertingError(f'could not read {path}: {type(e).__name__}') from e
    if not isinstance(data, dict):
        raise AlertingError(f'{path}: expected a JSON object')
    return data


class Notifier:
    """Sends findings. Holds no state beyond what it has already sent."""

    def __init__(self, config, profile=None, opener=None, ring=None):
        self.config = config
        self.profile = profile
        # Injectable so tests exercise the real body-building and header logic
        # without a network. The default is urllib, not requests: one fewer
        # dependency on a sensor that may have no route to a package index.
        self._opener = opener or self._post
        # When a rolling capture is configured, each pushed finding gets the
        # packets around it written out and named in the alert. An alert saying
        # "a controller was commanded at 03:14" is worth much more with the
        # thirty seconds either side attached.
        self.ring = ring
        self.sent = []
        self.failures = []
        self.extracts = []

    # ─── Sending ─────────────────────────────────────────────────────────

    def send(self, findings):
        """
        Push whatever qualifies, and report what was sent.

        Returns (sent, skipped). Skipped is not a failure: most findings belong
        in the digest, and pushing them is how push gets muted.
        """
        if not self.config.enabled:
            return [], list(findings)

        self.config.validate()
        floor = Severity.rank(self.config.min_push_severity)

        sent, skipped = [], []
        for finding in findings:
            if finding.tier != Tier.PUSH or Severity.rank(finding.severity) < floor:
                skipped.append(finding)
                continue
            record = redact_finding(finding, self.profile, audience=ALERT)
            if record is None:                       # cannot happen for ALERT
                skipped.append(finding)              # but fail closed anyway
                continue
            extract = self._extract(finding)
            if extract:
                record['pcap'] = extract
            if self._deliver(record):
                sent.append(finding)
            else:
                skipped.append(finding)
        return sent, skipped

    def send_digest(self, analyzer, title=None):
        """Send the daily report. One message, whatever it contains."""
        if not self.config.enabled:
            return False
        self.config.validate()
        body = build_digest(analyzer, self.profile)
        return self._deliver({
            'rule': 'digest',
            'title': title or f'{getattr(self.profile, "name", "site")} — daily report',
            'severity': Severity.INFO,
            'description': body,
        }, topic=self.config.digest_topic, priority=2, tags='memo')

    def _extract(self, finding):
        """
        The packets around a finding, if a rolling capture is configured.

        Failure here never stops the alert. The alert is the point; the capture
        extract is a convenience, and a full disk or a rotated-away window is
        not a reason for nobody to hear about a BACnet write.
        """
        if self.ring is None:
            return ''
        try:
            result = self.ring.extract_for_finding(
                finding, seconds=int(self.config.extract_seconds))
        except Exception as e:
            logger.info('no capture extract for %s: %s', finding.rule_id, e)
            return ''
        self.extracts.append(result)
        return result['path']

    def _deliver(self, record, topic=None, priority=None, tags=None):
        severity = record.get('severity', Severity.MEDIUM)
        message = record.get('description') or record.get('title') or ''

        headers = {
            'Title': _header_safe(record.get('title') or record.get('rule', '')),
            'Priority': str(priority or _PRIORITY.get(severity, 3)),
            'Tags': tags or _TAGS.get(severity, 'warning'),
            'Content-Type': 'text/plain; charset=utf-8',
        }
        if self.config.token:
            headers['Authorization'] = f'Bearer {self.config.token}'

        url = f'{self.config.server}/{topic or self.config.topic}'
        body = _format_message(record)

        if self.config.dry_run:
            self.sent.append({'url': url, 'headers': _without_auth(headers),
                              'body': body})
            return True

        try:
            self._opener(url, body.encode('utf-8'), headers, self.config.timeout)
        except Exception as e:
            # The exception may carry the URL, which carries the topic. It does
            # not carry the token — that is in a header — but the message is
            # kept short and the record is not echoed.
            logger.error('could not deliver %s: %s', record.get('rule'),
                         type(e).__name__)
            self.failures.append((record.get('rule'), type(e).__name__))
            return False

        self.sent.append({'url': url, 'headers': _without_auth(headers),
                          'body': body})
        return True

    @staticmethod
    def _post(url, body, headers, timeout):
        request = urllib.request.Request(url, data=body, headers=headers,
                                         method='POST')
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status


def _without_auth(headers):
    """Headers minus the token, for the record this keeps of what it sent."""
    return {k: v for k, v in headers.items() if k.lower() != 'authorization'}


def _header_safe(text):
    """
    HTTP headers cannot carry newlines, and a device name comes from the
    network. Without this, a crafted hostname could inject headers.
    """
    cleaned = str(text).replace('\r', ' ').replace('\n', ' ')
    cleaned = ''.join(c for c in cleaned if 32 <= ord(c) < 127)
    return cleaned[:200] or 'netmon'


def _format_message(record):
    """The notification body: what happened, where, and what to check next."""
    lines = [record.get('description') or record.get('title', '')]

    where = []
    for key in ('device', 'role', 'vlan', 'zone', 'switch_port'):
        value = record.get(key)
        if value:
            where.append(f'{key.replace("_", " ")}: {value}')
    if where:
        lines.append('')
        lines.append('  '.join(where))

    evidence = record.get('evidence') or {}
    if evidence:
        lines.append('')
        lines.append('  '.join(f'{k}={v}' for k, v in evidence.items()))

    if record.get('count', 1) > 1:
        lines.append('')
        lines.append(f"seen {record['count']} times")

    if record.get('next_check'):
        lines.append('')
        lines.append(f"next: {record['next_check']}")

    if record.get('pcap'):
        lines.append('')
        lines.append(f"packets: {record['pcap']}")
    return '\n'.join(lines)


# ─── The digest ──────────────────────────────────────────────────────────────

def build_digest(analyzer, profile=None, limit=40):
    """
    The daily report, as plain text.

    Ordered worst first and grouped by rule rather than by time, because the
    question a digest answers is "what kinds of thing happened", not "in what
    order". Counts are the true counts, including everything deduplication
    collapsed.
    """
    findings = analyzer.by_severity()
    report = analyzer.report()

    site = getattr(profile, 'name', 'site')
    lines = [f'{site} — {report["events"]} events, {report["findings"]} findings']

    if report.get('by_severity'):
        lines.append('  ' + ', '.join(f'{k} {v}'
                                      for k, v in report['by_severity'].items()))
    if report.get('suppressed_repeats'):
        lines.append(f'  {report["suppressed_repeats"]} repeats collapsed')

    if not findings:
        lines.append('')
        lines.append('Nothing found. Check the sources covered the VLANs you')
        lines.append('care about before reading that as an all-clear.')
        return '\n'.join(lines)

    by_rule = {}
    for finding in findings[:limit]:
        by_rule.setdefault(finding.rule_id, []).append(finding)

    for rule_id, group in sorted(
            by_rule.items(),
            key=lambda kv: -Severity.rank(kv[1][0].severity)):
        worst = group[0]
        total = sum(f.count for f in group)
        lines.append('')
        lines.append(f'{worst.severity.upper()}  {rule_id}'
                     + (f'  ({len(group)} devices, {total} occurrences)'
                        if len(group) > 1 else ''))
        for finding in group[:6]:
            record = redact_finding(finding, profile, audience=ALERT)
            if record is None:
                continue
            suffix = f'  ×{finding.count}' if finding.count > 1 else ''
            lines.append(f'  · {record["description"]}{suffix}')
        if len(group) > 6:
            lines.append(f'  · … and {len(group) - 6} more')

    if len(findings) > limit:
        lines.append('')
        lines.append(f'{len(findings) - limit} further findings not listed.')
    return '\n'.join(lines)
