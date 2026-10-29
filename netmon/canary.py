"""
Canary hits.
============
A canary has no legitimate users. Every other finding in this system needs a
judgement about whether the traffic was normal; this one does not. Something
connected to a service that exists only to be connected to, and that is the
whole finding.

    python -m netmon.canary --profile my-site.yaml --log /var/log/opencanary.log
    python -m netmon.canary --profile my-site.yaml --listen 0.0.0.0:8790 --token-file ...

Read the log file if you can
---------------------------
OpenCanary writes JSON lines. Reading them needs no listener, no open port and
no shared secret — three things that can be got wrong — so the log file is the
default and the webhook is for when the canary cannot reach the sensor's disk.

The webhook, when you need it, takes a token compared with `compare_digest`,
caps the body, caps the rate, and binds where you tell it. It accepts nothing
else: there is one route and one verb.

Attempted credentials
---------------------
A canary's most useful intelligence is what the visitor tried, because a
scanner using `admin/admin` and someone using your actual service account are
very different problems. So the **username is reported** — sanitised, bounded,
the same as any other name from the network.

The **password never is**. Not logged, not alerted, not stored, not counted
beyond "a password was supplied". If it happens to be a real one, recording it
in an alert is the same mistake as finding it in a packet and keeping it. What
you need to know is that someone knew a username; what the password was is the
attacker's business and, if it was right, far too much to write down.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import socket
import time
from collections import deque

from netmon.events import Event, Finding, Severity, Tier

logger = logging.getLogger("netmon.canary")

__all__ = ['parse_event', 'read_log', 'finding_for', 'CanaryError',
           'LOGTYPES', 'CanaryListener']


class CanaryError(RuntimeError):
    """A canary feed could not be read."""


#: OpenCanary's log types, from its logger constants. An unrecognised code is
#: reported as its number rather than guessed at — the same discipline as
#: elsewhere, since an invented service name would send someone to the wrong
#: machine.
LOGTYPES = {
    1000: ('boot', 'the canary started'),
    2000: ('ftp', 'an FTP login was attempted'),
    3000: ('http', 'a page was requested'),
    3001: ('http', 'an HTTP login was attempted'),
    4000: ('ssh', 'an SSH connection was opened'),
    4001: ('ssh', 'an SSH client announced itself'),
    4002: ('ssh', 'an SSH login was attempted'),
    5000: ('smb', 'a file was opened over SMB'),
    6001: ('portscan', 'a port was probed'),
    6002: ('portscan', 'an OS fingerprint was attempted'),
    7001: ('telnet', 'a telnet login was attempted'),
    8001: ('http-proxy', 'a proxy login was attempted'),
    9001: ('mysql', 'a MySQL login was attempted'),
    10001: ('mssql', 'a SQL Server login was attempted'),
    11001: ('tftp', 'a TFTP request was made'),
    12001: ('ntp', 'an NTP monlist was requested'),
    13001: ('vnc', 'a VNC login was attempted'),
    14001: ('snmp', 'an SNMP command was sent'),
    15001: ('rdp', 'an RDP connection was attempted'),
    16001: ('sip', 'a SIP request was made'),
    17001: ('git', 'a repository clone was attempted'),
    18001: ('redis', 'a Redis command was sent'),
    19001: ('tcp-banner', 'a banner service was connected to'),
}

#: Log types that are the canary talking about itself rather than a visitor.
_SELF_REPORTING = frozenset({1000})

#: Fields in `logdata` that may be reported. Everything else is dropped — an
#: allowlist, because OpenCanary's modules each add their own keys and the next
#: version will add more.
_SAFE_LOGDATA = frozenset({
    'USERNAME', 'SKIN', 'PATH', 'HOSTNAME', 'USERAGENT', 'VERSION',
    'LOCALVERSION', 'REMOTEVERSION', 'CLIENT', 'COMMAND', 'FILENAME',
    'REQUEST', 'METHOD', 'SESSION', 'COMMUNITY_STRING_TYPE', 'REPO',
})

#: Fields that must never be reported, whatever they are called. The allowlist
#: above is the mechanism; this is the check that a careless addition to it is
#: caught.
_FORBIDDEN = ('password', 'passwd', 'pass', 'secret', 'token', 'hash',
              'credential', 'key', 'cookie', 'session_id', 'auth')


def _clean(value, limit=200):
    """
    A value fit to put in an alert.

    This arrives from whoever is poking the canary, so it is adversarial by
    definition: bounded, and restricted to characters that cannot carry a
    newline into a notification header.
    """
    text = str(value if value is not None else '')
    text = re.sub(r'[^\x20-\x7e]', '', text)[:limit].strip()
    return text


def _safe_logdata(logdata):
    """
    The fields of a canary's logdata that may be reported.

    `USERNAME` is here because a scanner using admin/admin and someone using
    your real service account are very different problems. No password field is,
    and none ever will be: if it happens to be a real one, writing it into an
    alert is the same mistake as keeping one found in a packet.
    """
    if not isinstance(logdata, dict):
        return {}, False

    # Present *and* non-empty. A blank password field is a scanner working
    # through a list; a filled one is someone who had something to try, and
    # saying "with a password" about an empty string blurs the two.
    had_password = any(
        any(word in str(key).lower() for word in ('password', 'passwd'))
        and str(value or '').strip()
        for key, value in logdata.items())

    out = {}
    for key, value in logdata.items():
        name = str(key)
        if name.upper() not in _SAFE_LOGDATA:
            continue
        if any(word in name.lower() for word in _FORBIDDEN):
            continue                       # belt and braces over the allowlist
        if isinstance(value, (dict, list)):
            continue                       # nested structures are not names
        cleaned = _clean(value)
        if cleaned:
            out[name.lower()] = cleaned
    return out, had_password


def parse_event(raw):
    """
    One OpenCanary record, as a dict of what may be kept.

    Returns None for a record that is not a canary event or that the canary
    emitted about itself. Never raises: these arrive from a log file that may be
    half-written, or from a listener.
    """
    if isinstance(raw, (str, bytes, bytearray)):
        try:
            raw = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
    if not isinstance(raw, dict):
        return None

    try:
        logtype = int(raw.get('logtype'))
    except (TypeError, ValueError):
        return None
    if logtype in _SELF_REPORTING:
        return None

    service, what_happened = LOGTYPES.get(
        logtype, (f'logtype-{logtype}', f'something happened (log type {logtype})'))

    logdata, had_password = _safe_logdata(raw.get('logdata'))

    return {
        'logtype': logtype,
        'service': service,
        'what_happened': what_happened,
        'src_ip': _clean(raw.get('src_host'), 64),
        'src_port': _port(raw.get('src_port')),
        'dst_ip': _clean(raw.get('dst_host'), 64),
        'dst_port': _port(raw.get('dst_port')),
        'node': _clean(raw.get('node_id'), 64),
        'ts': _timestamp(raw),
        'details': logdata,
        'password_supplied': had_password,
    }


def _port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def _timestamp(raw):
    """
    When it happened. OpenCanary writes several time fields depending on
    version; the first that parses wins, and failing that, now.
    """
    for key in ('utc_time', 'local_time_adjusted', 'local_time'):
        text = str(raw.get(key) or '').strip()
        if not text:
            continue
        for shape in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S',
                      '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S'):
            try:
                return time.mktime(time.strptime(text.replace('Z', ''), shape))
            except ValueError:
                continue
    return time.time()


# ─── Findings ────────────────────────────────────────────────────────────────

def finding_for(record, profile=None):
    """
    A canary hit as a finding.

    Always high, always push. Every other rule in this system needs a judgement
    about whether the traffic was normal; this one does not, because a canary
    has no legitimate users. The only question is who.
    """
    event = Event(kind='canary', ts=record['ts'], src_ip=record['src_ip'],
                  dst_ip=record['dst_ip'], src_port=record['src_port'],
                  dst_port=record['dst_port'], source='opencanary')
    event.fields.update({
        'canary_service': record['service'],
        'canary_node': record['node'],
        'logtype': record['logtype'],
    })
    event.fields.update(record['details'])

    who = record['src_ip'] or 'something'
    if profile is not None and record['src_ip']:
        device = profile.identify(ip=record['src_ip'])
        if device.name and device.name != record['src_ip']:
            who = f'{device.name} ({record["src_ip"]})'

    described = f'{who}: {record["what_happened"]}'
    if record['dst_ip']:
        described += f' on the canary at {record["dst_ip"]}'
        if record['dst_port']:
            described += f':{record["dst_port"]}'
    username = record['details'].get('username')
    if username:
        described += f', as "{username}"'
    if record['password_supplied']:
        described += ' with a password'

    evidence = {'service': record['service'], 'src_ip': record['src_ip'],
                'dst_ip': record['dst_ip'], 'dst_port': record['dst_port'],
                'node': record['node']}
    evidence.update(record['details'])

    return Finding(
        'canary_hit', 'Something touched the canary',
        severity=Severity.HIGH, tier=Tier.PUSH, description=described,
        ts=record['ts'], device=record['src_ip'] or record['node'],
        key=f"{record['src_ip']}/{record['service']}", event=event,
        evidence=evidence,
        next_check='Nothing has a reason to reach this host. Find out what '
                   + (f'{record["src_ip"]} is and what else it has been doing — '
                      'the beaconing and new-destination findings for it, same '
                      'day.' if record['src_ip'] else 'reached it.'))


# ─── Reading a log file ──────────────────────────────────────────────────────

def read_log(path, since=None, limit=None):
    """
    OpenCanary's JSON-lines log, yielding parsed records.

    A generator, and tolerant: a half-written last line is normal on a file
    being appended to, and one unreadable record must not end the read.
    """
    if not os.path.exists(path):
        raise CanaryError(f'canary log not found: {path}')

    emitted = skipped = 0
    try:
        handle = open(path, encoding='utf-8', errors='replace')
    except OSError as e:
        raise CanaryError(f'{path}: {e}') from e

    with handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = parse_event(line)
            if record is None:
                skipped += 1
                continue
            if since is not None and record['ts'] < since:
                continue
            yield record
            emitted += 1
            if limit and emitted >= limit:
                break

    if skipped:
        logger.debug('%s: skipped %d unreadable or self-reporting lines',
                     os.path.basename(path), skipped)


def findings_from_log(path, profile=None, since=None, limit=None):
    """Every hit in the log as a finding."""
    return [finding_for(record, profile)
            for record in read_log(path, since, limit)]


# ─── The listener ────────────────────────────────────────────────────────────

#: After refusing a request without reading its body, how long and how much of
#: it to read before closing. Small, because this listens on a network an
#: attacker may be on, and a real canary event is far under the body cap.
_LINGER_SECONDS = 2.0
_LINGER_BYTES = 1024 * 1024


def _drain(sock):
    """
    Finish the reply, then read and discard what the client is still sending.

    Closing a socket with unread data makes Windows reset the connection, and a
    reset throws away a reply the client has not read yet.
    """
    try:
        sock.shutdown(socket.SHUT_WR)
        deadline = time.monotonic() + _LINGER_SECONDS
        received = 0
        while received < _LINGER_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            chunk = sock.recv(65536)
            if not chunk:
                break
            received += len(chunk)
    except OSError:
        pass


class CanaryListener:
    """
    An inbound webhook, for when the canary cannot reach the sensor's disk.

    One route, one verb, one token. The token is compared with `compare_digest`,
    the body is capped, and the rate is capped — a canary being hammered is
    exactly the situation where an unbounded queue becomes the outage.

    Prefer the log file. A listener is an open port and a shared secret, which
    are two more things that can be wrong.
    """

    max_body_bytes = 64 * 1024
    max_per_minute = 120

    def __init__(self, token, profile=None, host='0.0.0.0', port=8790,
                 on_finding=None):
        if not token or len(str(token)) < 16:
            raise CanaryError(
                'the canary webhook needs a token of at least 16 characters. '
                'Generate one with: python -c '
                '"import secrets; print(secrets.token_urlsafe(32))"')
        self.token = str(token)
        self.profile = profile
        self.host = host
        self.port = port
        self.on_finding = on_finding
        self.findings = []
        self._recent = deque(maxlen=self.max_per_minute)
        self._httpd = None
        self._thread = None
        self.rejected = {'token': 0, 'rate': 0, 'body': 0, 'parse': 0}

    def _rate_ok(self, now=None):
        now = now if now is not None else time.time()
        while self._recent and now - self._recent[0] > 60:
            self._recent.popleft()
        if len(self._recent) >= self.max_per_minute:
            return False
        self._recent.append(now)
        return True

    def accept(self, body, token, now=None):
        """
        Handle one delivery. Returns (status, payload).

        Separate from the HTTP plumbing so the decisions — the token, the rate,
        the parse — are testable without a socket.
        """
        if not hmac.compare_digest(str(token or ''), self.token):
            self.rejected['token'] += 1
            return 403, {'error': 'bad token'}
        if len(body or b'') > self.max_body_bytes:
            self.rejected['body'] += 1
            return 413, {'error': 'too large'}
        if not self._rate_ok(now):
            # Shedding beats queueing: a canary under a flood is the moment an
            # unbounded queue turns into the outage.
            self.rejected['rate'] += 1
            return 429, {'error': 'too many'}

        record = parse_event(body)
        if record is None:
            self.rejected['parse'] += 1
            return 400, {'error': 'not a canary event'}

        finding = finding_for(record, self.profile)
        self.findings.append(finding)
        if self.on_finding is not None:
            try:
                self.on_finding(finding)
            except Exception:
                logger.exception('the finding handler raised')
        return 200, {'ok': True, 'service': record['service']}

    def start(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading

        listener = self

        class Handler(BaseHTTPRequestHandler):
            server_version = 'netmon-canary'
            sys_version = ''
            protocol_version = 'HTTP/1.1'
            body_unread = False

            def log_message(self, fmt, *args):
                logger.debug('%s - %s', self.address_string(), fmt % args)

            def _refuse(self, status, payload):
                # Answered without reading the body. Kept alive, the body would
                # be parsed as the next request; so close, draining it first.
                self.close_connection = True
                self.body_unread = True
                return self._send(status, payload)

            def finish(self):
                super().finish()
                if self.body_unread:
                    _drain(self.connection)

            def _send(self, status, payload):
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_POST(self):
                if self.path.rstrip('/') not in ('', '/canary'):
                    return self._refuse(404, {'error': 'not found'})
                try:
                    length = int(self.headers.get('Content-Length') or 0)
                except ValueError:
                    return self._refuse(400, {'error': 'bad content length'})
                if length > listener.max_body_bytes:
                    return self._refuse(413, {'error': 'too large'})
                body = self.rfile.read(length) if length else b''
                token = (self.headers.get('X-Netmon-Token')
                         or self.headers.get('Authorization', '').removeprefix('Bearer '))
                status, payload = listener.accept(body, token)
                self._send(status, payload)

            def do_GET(self):
                # Deliberately not a status page: this listens on a network the
                # canary is on, and anything it says is something an attacker
                # learns for free.
                self._send(405, {'error': 'post only'})

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={'poll_interval': 0.1},
            name='netmon-canary', daemon=True)
        self._thread.start()
        return self.port

    def stop(self):
        if self._httpd is None:
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._httpd = self._thread = None


def _main(argv=None):
    import argparse
    import sys

    from netmon.profile import ProfileError, load_profile

    parser = argparse.ArgumentParser(
        prog='python -m netmon.canary',
        description='Turn canary hits into findings. A canary has no '
                    'legitimate users, so every hit is one.')
    parser.add_argument('--profile', required=True)

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--log', metavar='FILE',
                        help="OpenCanary's JSON-lines log. Preferred: no "
                             'listener, no open port, no shared secret')
    source.add_argument('--listen', metavar='HOST:PORT',
                        help='run a webhook, for when the canary cannot reach '
                             "this host's disk")

    parser.add_argument('--since', type=float, metavar='TIMESTAMP',
                        help='only hits after this unix time')
    parser.add_argument('--token-file',
                        help='file holding the webhook token (mode 600)')
    parser.add_argument('--notify', action='store_true')
    parser.add_argument('--secrets', metavar='FILE')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    try:
        profile = load_profile(args.profile)
    except ProfileError as e:
        print(f'profile: {e}', file=sys.stderr)
        return 1

    notifier = None
    if args.notify:
        from netmon.alerting import AlertingError, Notifier, load_config
        try:
            config = load_config(args.secrets)
            if args.dry_run:
                config.dry_run = True
            notifier = Notifier(config, profile)
        except AlertingError as e:
            print(f'alerting: {e}', file=sys.stderr)
            return 1

    if args.log:
        try:
            findings = findings_from_log(args.log, profile, args.since)
        except CanaryError as e:
            print(str(e), file=sys.stderr)
            return 1

        if args.json:
            print(json.dumps([f.as_dict() for f in findings], indent=2,
                             default=str))
        elif not findings:
            print('No canary hits.')
        else:
            print(f'{len(findings)} canary hits:')
            for finding in findings:
                print()
                print(f'  {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(finding.ts))}'
                      f'  {finding.description}')
                print(f'  next: {finding.next_check}')

        if notifier is not None and findings:
            sent, held = notifier.send(findings)
            print()
            print(f'pushed {len(sent)}, held back {len(held)}')
            if notifier.config.dry_run:
                for message in notifier.sent:
                    print()
                    print(f'--- would POST to {message["url"]} ---')
                    print(message['body'])
        return 2 if findings else 0

    # The listener.
    token = ''
    if args.token_file:
        try:
            mode = os.stat(args.token_file).st_mode
            if mode & 0o077:
                print(f'{args.token_file} is readable beyond its owner; '
                      f'run: chmod 600 {args.token_file}', file=sys.stderr)
                return 1
            with open(args.token_file, encoding='utf-8') as handle:
                token = handle.read().strip()
        except OSError as e:
            print(f'could not read {args.token_file}: {type(e).__name__}',
                  file=sys.stderr)
            return 1
    else:
        token = os.environ.get('NETMON_CANARY_TOKEN', '')

    host, _, port = args.listen.rpartition(':')
    try:
        port = int(port)
    except ValueError:
        parser.error('--listen takes HOST:PORT')

    def deliver(finding):
        print(f'{time.strftime("%H:%M:%S")}  {finding.description}')
        if notifier is not None:
            notifier.send([finding])

    try:
        listener = CanaryListener(token, profile, host or '0.0.0.0', port,
                                  on_finding=deliver)
    except CanaryError as e:
        print(str(e), file=sys.stderr)
        return 1

    listener.start()
    print(f'canary webhook on http://{listener.host}:{listener.port}/canary')
    print('  POST OpenCanary JSON with the token in X-Netmon-Token')
    print('  Prefer --log if the canary can write where this host can read it:')
    print('  a listener is an open port and a shared secret, which are two')
    print('  more things that can be wrong.')
    print()
    print('Ctrl-C to stop.')
    try:
        while True:
            listener._thread.join(timeout=1.0)
    except KeyboardInterrupt:
        print()
        print(f'{len(listener.findings)} hits; rejected {listener.rejected}')
    finally:
        listener.stop()
    return 0


if __name__ == '__main__':
    import sys
    from netmon.canary import _main as main
    sys.exit(main())
