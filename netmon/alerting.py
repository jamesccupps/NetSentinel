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

Email
-----
The digest can also be emailed (`EmailConfig`, `send_email_digest`): STARTTLS
or SMTPS with the certificate verified, settings and credentials from the same
owner-only secrets file and nowhere else, and plain SMTP refused except to a
relay on this machine with nothing to log in with.

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
           'build_digest', 'EmailConfig', 'load_email_config',
           'send_email_digest', 'digest_title']


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

    def __init__(self, config, profile=None, opener=None, ring=None,
                 silences=None):
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
        # Acks, snoozes and maintenance windows (netmon.silence). Anything they
        # cover is held back from push; the digest still lists it.
        self.silences = silences
        self.silenced = []
        # Extracts that had to leave restricted frames out: the ring buffer
        # holds what it never should. Pushed once per set of files.
        self.leaks = []
        self._leak_keys = set()

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
            if self.silences is not None and self.silences.decide(finding) != 'push':
                skipped.append(finding)
                self.silenced.append(finding)
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

        for leak in self.leaks:
            if leak.key in self._leak_keys:
                continue
            self._leak_keys.add(leak.key)
            if self._deliver(redact_finding(leak, self.profile, audience=ALERT)):
                sent.append(leak)
        self.leaks = []
        return sent, skipped

    def send_digest(self, analyzer, title=None, open_items=None, body=None):
        """Send the daily report. One message, whatever it contains."""
        if not self.config.enabled:
            return False
        self.config.validate()
        if body is None:
            body = build_digest(analyzer, self.profile, open_items=open_items)
        return self._deliver({
            'rule': 'digest',
            'title': title or digest_title(self.profile),
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
        if result.get('excluded_restricted'):
            from netmon.leakcheck import extraction_finding
            leak = extraction_finding(result, self.profile)
            if leak is not None:
                self.leaks.append(leak)
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

def digest_title(profile=None):
    return f'{getattr(profile, "name", "site")} — daily report'


#: How a silence is shown against a finding in the digest.
_SILENCE_MARKS = {'ack': 'acknowledged', 'maintenance': 'maintenance',
                  'snooze': 'snoozed'}


def _silence_mark(finding):
    silenced = getattr(finding, 'silenced', None)
    if not silenced:
        return ''
    mark = _SILENCE_MARKS.get(silenced.get('kind'), str(silenced.get('kind')))
    reason = str(silenced.get('reason') or '').strip()
    return f'  [{mark}' + (f': {reason}' if reason else '') + ']'


def _when(ts):
    try:
        return time.strftime('%Y-%m-%d %H:%M', time.localtime(float(ts)))
    except (TypeError, ValueError, OverflowError):
        return '?'


def _open_items(open_items, limit=20):
    """
    The checklist: what is still waiting on a person.

    First in the digest, because a list of what happened yesterday is history
    and this is the part someone has to do something about.
    """
    if not open_items:
        return []
    pushes = open_items.get('pushes') or []
    standing = open_items.get('standing') or []
    silences = open_items.get('silences') or []
    lines = ['', 'Open items']
    if not (pushes or standing or silences):
        lines.append('  [x] nothing waiting: every push answered, no standing '
                     'configuration problems, nothing silenced')
        return lines

    if pushes:
        lines.append(f'  Pushed and not yet acknowledged ({len(pushes)}):')
        for item in pushes[:limit]:
            count = int(item.get('count') or 1)
            lines.append(
                f'  [ ] {str(item.get("severity", "")).upper()} '
                f'{item.get("rule")} — {item.get("description")}'
                f' (pushed {_when(item.get("first_pushed"))}'
                + (f', seen {count} times' if count > 1 else '') + ')')
        if len(pushes) > limit:
            lines.append(f'  … and {len(pushes) - limit} more')
    if standing:
        lines.append(f'  Configuration wrong now ({len(standing)}):')
        for item in standing[:limit]:
            lines.append(f'  [ ] {item.get("rule")} — {item.get("description")}')
        if len(standing) > limit:
            lines.append(f'  … and {len(standing) - limit} more')
    if silences:
        lines.append(f'  Silences in effect ({len(silences)}):')
        for entry in silences[:limit]:
            scope = ' '.join(f'{k}={entry[k]}' for k in ('rule', 'device', 'key')
                             if entry.get(k))
            until = (f'until {_when(entry["until"])}' if entry.get('until')
                     else 'until cleared')
            reason = f' — {entry["reason"]}' if entry.get('reason') else ''
            lines.append(f'  [ ] {entry.get("kind")} {scope} {until}{reason}'
                         f' (id {entry.get("id")})')
    return lines


def build_digest(analyzer, profile=None, limit=40, open_items=None):
    """
    The daily report, as plain text.

    Ordered worst first and grouped by rule rather than by time, because the
    question a digest answers is "what kinds of thing happened", not "in what
    order". Counts are the true counts, including everything deduplication
    collapsed. A finding an ack or a maintenance window covers is marked as
    such: it stopped pushing, and the digest is where that is on the record.

    `open_items` is the service's checklist — unanswered pushes, standing
    configuration problems, active silences — and leads the report.
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
    silenced = sum(1 for f in findings if getattr(f, 'silenced', None))
    if silenced:
        lines.append(f'  {silenced} acknowledged or under maintenance, marked below')

    lines += _open_items(open_items)

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
            lines.append(f'  · {record["description"]}{suffix}'
                         f'{_silence_mark(finding)}')
        if len(group) > 6:
            lines.append(f'  · … and {len(group) - 6} more')

    if len(findings) > limit:
        lines.append('')
        lines.append(f'{len(findings) - limit} further findings not listed.')
    return '\n'.join(lines)


# ─── Email ───────────────────────────────────────────────────────────────────

class EmailConfig:
    """
    Where the digest is emailed, if anywhere.

    From the secrets file only — the same file, under the same owner-only
    check, as the ntfy token. Never the environment for the credentials: a
    unit file's Environment= is readable by anyone who can read the unit.
    """

    SECURITY = ('starttls', 'ssl', 'none')

    def __init__(self, host='', port=0, security='starttls', username='',
                 password='', sender='', recipients=(), timeout=30,
                 enabled=True):
        self.host = str(host or '').strip()
        self.security = str(security or 'starttls').lower().strip()
        self.port = int(port or (465 if self.security == 'ssl' else 587))
        self.username = str(username or '')
        self.password = str(password or '')
        self.sender = str(sender or '').strip()
        if isinstance(recipients, str):
            recipients = [r for r in recipients.replace(';', ',').split(',')]
        self.recipients = [str(r).strip() for r in (recipients or []) if str(r).strip()]
        self.timeout = int(timeout)
        self.enabled = bool(enabled)

    @property
    def configured(self):
        return self.enabled and bool(self.host and self.recipients)

    def validate(self):
        """Raise AlertingError on anything that would fail or leak at send time."""
        if self.security not in self.SECURITY:
            raise AlertingError(
                f'smtp_security must be one of {", ".join(self.SECURITY)}')
        if not self.host:
            raise AlertingError('no smtp_host configured')
        if not self.recipients:
            raise AlertingError('no smtp_to configured')
        if not self.sender:
            raise AlertingError('no smtp_from configured')
        for address in [self.sender] + self.recipients:
            # A newline in an address is a header injection; the rest is the
            # mail server's to judge.
            if '@' not in address or any(c in address for c in '\r\n<>,'):
                raise AlertingError(f'not an email address: {address!r}')
        if self.security == 'none':
            # The digest names devices and weaknesses, and a password sent in
            # the clear is a password given away. Plain SMTP is only for a
            # relay on this machine, with nothing to log in with.
            if self.host not in ('localhost', '127.0.0.1', '::1'):
                raise AlertingError(
                    'refusing to email the digest unencrypted to another host; '
                    'use smtp_security "starttls" or "ssl"')
            if self.username or self.password:
                raise AlertingError(
                    'refusing to send SMTP credentials without TLS; use '
                    'smtp_security "starttls" or "ssl"')
        return True

    def describe(self):
        """For logs and the UI. Never includes the password."""
        return {'host': self.host, 'port': self.port, 'security': self.security,
                'from': self.sender, 'to': list(self.recipients),
                'authenticated': bool(self.username), 'enabled': self.enabled}


def load_email_config(path=None, environ=None):
    """
    The email settings from the secrets file, or None when there are none.

    Keys: smtp_host, smtp_port, smtp_security (starttls | ssl | none),
    smtp_username, smtp_password, smtp_from, smtp_to (a list or a comma-
    separated string), email_digest (false to turn it off).
    """
    environ = environ if environ is not None else os.environ
    path = path or environ.get('NETMON_SECRETS')
    if not path:
        return None
    data = _read_secrets_file(path)
    if not data.get('smtp_host'):
        return None
    return EmailConfig(
        host=data.get('smtp_host'), port=data.get('smtp_port') or 0,
        security=data.get('smtp_security') or 'starttls',
        username=data.get('smtp_username') or '',
        password=data.get('smtp_password') or '',
        sender=data.get('smtp_from') or data.get('smtp_username') or '',
        recipients=data.get('smtp_to') or [],
        timeout=data.get('smtp_timeout') or 30,
        enabled=str(data.get('email_digest', 'true')).lower()
        not in ('0', 'false', 'no', 'off'))


def _smtp(security, host, port, timeout, context):
    """The real connection. Replaced in tests by a fake with the same calls."""
    import smtplib
    if security == 'ssl':
        return smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    return smtplib.SMTP(host, port, timeout=timeout)


def send_email_digest(config, body, subject, smtp_factory=None):
    """
    Email the digest. Raises AlertingError, naming only the kind of failure.

    The certificate is verified against the system's trust store: an SMTP
    server that cannot prove who it is should not be handed a password or a
    list of the site's weaknesses.
    """
    import smtplib
    import ssl
    from email.message import EmailMessage
    from email.utils import formatdate, make_msgid

    config.validate()
    message = EmailMessage()
    # The site name comes from the profile and may not be ASCII, which an
    # email header can carry where an HTTP one cannot; a newline it cannot.
    message['Subject'] = ' '.join(str(subject).split())[:200] or 'netmon'
    message['From'] = config.sender
    message['To'] = ', '.join(config.recipients)
    message['Date'] = formatdate(localtime=True)
    message['Message-ID'] = make_msgid(domain=config.sender.rsplit('@', 1)[-1])
    message.set_content(body)

    context = ssl.create_default_context()
    factory = smtp_factory or _smtp
    try:
        connection = factory(config.security, config.host, config.port,
                             config.timeout, context)
        try:
            if config.security == 'starttls':
                connection.ehlo()
                connection.starttls(context=context)
                connection.ehlo()
            if config.username:
                connection.login(config.username, config.password)
            connection.send_message(message)
        finally:
            try:
                connection.quit()
            except Exception:
                pass
    except (smtplib.SMTPException, OSError, ssl.SSLError) as e:
        # The exception text can quote the server's reply to the login; only
        # the kind of failure is kept.
        raise AlertingError(f'could not email the digest: {type(e).__name__}') from e
    return True
