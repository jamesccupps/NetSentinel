"""
Review mode: keep what it takes to judge alerts, then hand it over as text.
============================================================================
The point is to give Claude chat, or anyone, real alerts with the traffic behind
them, so they can say which are real. Claude chat reads text, not pcaps, and the
bundle leaves the machine, so most of this module is about what never gets
written.

While review mode is on (``--review DIR``, or the Settings toggle):
- every alert gets a snippet of the traffic around it, whatever its severity,
  cut before verification can lower that severity;
- a rolling full capture is kept within a disk budget;
- alerts.jsonl gets one line per alert, written when its verdict is final.

A bundle (``python -m src.review build DIR``, the desktop app, or the dashboard)
is a folder and a zip, under 20 MB and about 30 files:
- README.md   what is in it, and how to answer;
- summary.md  counts by rule, the busiest hosts, rules firing over and over on
              one host (the usual false positives);
- alerts.json the alerts, redacted;
- traffic/    one text digest per group of alerts: a line per packet with time,
              addresses, ports, protocol, DNS names, TLS SNI and HTTP host/path.

Private by default: no payloads and no pcaps unless asked for; query strings,
cookies, credentials, tokens and user-profile paths are never written; LAN
addresses can be replaced by stable labels; and every file is audited for secret
shapes before it is written, with anything that looks like one masked.

Verdicts go back the other way: record "real" or "false positive" per alert (the
dashboard, or ``python -m src.review import DIR answer.json`` with the JSON the
README asks for). A false positive is never alerted on again for that rule and
subject; see baseline_whitelist.ConfirmedFalsePositives.
"""

import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import threading
import time
import zipfile
from collections import Counter, defaultdict
from datetime import datetime

logger = logging.getLogger("NetSentinel.Review")

BUNDLE_MAX_BYTES = 20 * 1024 * 1024
BUNDLE_MAX_FILES = 30
DIGEST_MAX_LINES = 400
MAX_ALERTS_IN_BUNDLE = 2000
MAX_TEXT = 500

_SEVERITY_RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}


def review_id(alert):
    """A stable id for an alert: its process-local id changes on every restart."""
    get = alert.get if isinstance(alert, dict) else (lambda k: getattr(alert, k, ''))
    key = f"{float(get('timestamp') or 0):.6f}|{get('rule_id')}|{get('src_ip')}|{get('dst_ip')}"
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def default_directory():
    from src.config import APP_DIR
    return os.path.join(APP_DIR, 'review')


# ─── Recording ───────────────────────────────────────────────────────────────

class _Defaults:
    """Stands in for Config when there is none: every setting at its default."""

    def get(self, *keys, default=None):
        return default


class ReviewRecorder:
    """The live half: snippets, the rolling capture and alerts.jsonl."""

    def __init__(self, directory, pcap_writer, config=None):
        config = config if config is not None else _Defaults()
        self.directory = os.path.abspath(directory or default_directory())
        self.snippet_dir = os.path.join(self.directory, 'snippets')
        self.capture_dir = os.path.join(self.directory, 'capture')
        self.jsonl_path = os.path.join(self.directory, 'alerts.jsonl')
        for d in (self.directory, self.snippet_dir, self.capture_dir):
            os.makedirs(d, exist_ok=True)
        self.pcap_writer = pcap_writer
        self.snippet_seconds = config.get('review', 'snippet_seconds', default=60)
        self.snippet_budget = int(config.get(
            'review', 'snippet_budget_mb', default=500)) * 1024 * 1024
        self.capture_budget = int(config.get(
            'review', 'capture_budget_mb', default=2048)) * 1024 * 1024
        self.capture_max_age = float(config.get(
            'review', 'capture_max_hours', default=24)) * 3600
        self._lock = threading.Lock()
        self._owns_recording = False
        self._snippet_bytes = _dir_bytes(self.snippet_dir)
        self.skipped_snippets = 0

    def start(self):
        """Begin the rolling capture, unless the user is already recording."""
        if self.pcap_writer is None or self.pcap_writer.is_recording:
            return
        if self.pcap_writer.start_recording(
                directory=self.capture_dir, budget_bytes=self.capture_budget,
                max_age_sec=self.capture_max_age):
            self._owns_recording = True

    def stop(self):
        if self._owns_recording and self.pcap_writer is not None:
            self.pcap_writer.stop_recording()
        self._owns_recording = False

    def snippet(self, alert, referenced=None):
        """
        Save the traffic around an alert into the snippet folder.

        Over budget, the oldest snippets no stored alert still points at go first.
        If every one is still referenced, this one is skipped rather than break a
        reference, and the alert says so.
        """
        with self._lock:
            if self._snippet_bytes >= self.snippet_budget:
                self._prune(referenced() if referenced else set())
            if self._snippet_bytes >= self.snippet_budget:
                self.skipped_snippets += 1
                alert.evidence['packet_capture_note'] = (
                    'No traffic saved: the review snippet budget is full of '
                    'captures that other alerts still point at.')
                return None
        path = self.pcap_writer.export_for_alert(
            alert, seconds=self.snippet_seconds, directory=self.snippet_dir)
        if path:
            with self._lock:
                try:
                    self._snippet_bytes += os.path.getsize(path)
                except OSError:
                    pass
        return path

    def _prune(self, referenced):
        referenced = {os.path.abspath(p) for p in referenced if p}
        files = _files_oldest_first(self.snippet_dir, '.pcap')
        for path, size in files:
            if self._snippet_bytes < self.snippet_budget:
                break
            if path in referenced:
                continue
            try:
                os.remove(path)
                self._snippet_bytes -= size
            except OSError:
                pass

    def record(self, alert):
        """One line in alerts.jsonl. Called once the alert's verdict is final."""
        entry = alert.to_dict()
        entry['review_id'] = review_id(alert)
        path = entry.get('evidence', {}).get('packet_capture')
        if path and os.path.dirname(os.path.abspath(path)) == self.snippet_dir:
            entry['snippet'] = os.path.basename(path)
        line = json.dumps(entry, default=str, ensure_ascii=False)
        with self._lock:
            try:
                with open(self.jsonl_path, 'a', encoding='utf-8') as f:
                    f.write(line + '\n')
            except OSError as e:
                logger.error("Could not record alert for review: %s", e)


def _dir_bytes(directory):
    return sum(size for _, size in _files_oldest_first(directory, ''))


def _files_oldest_first(directory, suffix):
    out = []
    try:
        for name in os.listdir(directory):
            if not name.endswith(suffix):
                continue
            path = os.path.join(directory, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            out.append((st.st_mtime, os.path.abspath(path), st.st_size))
    except OSError:
        return []
    return [(p, s) for _, p, s in sorted(out)]


# ─── Redaction ───────────────────────────────────────────────────────────────

# Evidence keys never written, whatever they hold.
_DROP_KEYS = {'value', 'raw', 'value_raw', 'value_masked', 'raw_value', 'payload',
              'packet_capture', 'packet_capture_note', 'cookies', 'headers'}
# Nor any key containing one of these.
_FORBIDDEN_IN_KEY = ('cookie', 'password', 'passwd', 'secret', 'token', 'credential',
                     'authorization', 'session', 'api_key', 'apikey', 'private_key')

_URL_QUERY = re.compile(r'''((?:https?|ftp|wss?)://[^\s?#"'<>]+)[?#][^\s"'<>]*''', re.I)
_PROFILE_PATH = [
    (re.compile(r'(?i)([a-z]:\\(?:users|documents and settings)\\)[^\\/\s"\']+'), r'\1<user>'),
    (re.compile(r'(/home/|/Users/)[^/\s"\']+'), r'\1<user>'),
]
_AUDIT = [
    re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'),
    re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[^\n]*'),
    re.compile(r'\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}'),                  # JWT
    re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),                          # AWS key id
    re.compile(r'\bgh[pousr]_[A-Za-z0-9]{30,}'),                          # GitHub
    re.compile(r'\bxox[abposr]-[\w-]{10,}'),                              # Slack
    re.compile(r'\bsk_live_[0-9A-Za-z]{16,}'),                            # Stripe
    re.compile(r'\bsk-[A-Za-z0-9_-]{20,}'),                               # API keys
    re.compile(r'\bAIza[0-9A-Za-z_-]{30,}'),                              # Google
    re.compile(r'(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}'),
    re.compile(r'(?i)\b[\w.-]*(?:passw(?:or)?d|pwd|secret|token|api[_-]?key|session|cookie|auth)'
               r'[\w.-]*\s*[:=]\s*(?:"[^"]*"|\'[^\']*\'|[^\s,;&"\'\\]+)'),
    re.compile(r'(?i)\b(?:set-)?cookie:\s*[^\r\n]+'),
]
_CARD = re.compile(r'\b(?:\d[ -]?){13,19}\b')


def _luhn(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


class _Auditor:
    """Masks anything shaped like a secret and counts what it masked."""

    def __init__(self):
        self.masked = 0

    def __call__(self, text):
        for pattern in _AUDIT:
            text, n = pattern.subn('[masked]', text)
            self.masked += n

        def card(match):
            digits = re.sub(r'\D', '', match.group(0))
            if 13 <= len(digits) <= 19 and _luhn(digits):
                self.masked += 1
                return '[masked]'
            return match.group(0)
        return _CARD.sub(card, text)


class Pseudonymiser:
    """Stable labels for LAN addresses: the same host is lan-3 in every file."""

    _IPV4 = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
    _IPV6 = re.compile(r'(?i)(?<![\w:])(?:fe80|fd[0-9a-f]{2}|fc[0-9a-f]{2})(?::[0-9a-f]{0,4}){2,7}(?:%\w+)?')
    _MAC = re.compile(r'(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b')
    # Named, not ipaddress's is_private, which also covers documentation and
    # reserved ranges that are nobody's LAN.
    _LAN = [ipaddress.ip_network(n) for n in (
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16',
        '100.64.0.0/10', 'fc00::/7', 'fe80::/10')]

    def __init__(self):
        self._labels = {}
        self._counts = Counter()

    def _label(self, kind, value):
        key = (kind, value.lower())
        if key not in self._labels:
            self._counts[kind] += 1
            self._labels[key] = f"{kind}-{self._counts[kind]}"
        return self._labels[key]

    def ip(self, value):
        try:
            addr = ipaddress.ip_address(value.split('%')[0])
        except ValueError:
            return value
        if any(addr.version == net.version and addr in net for net in self._LAN):
            return self._label('lan', str(addr))
        return value

    def text(self, s):
        s = self._IPV4.sub(lambda m: self.ip(m.group(0)), s)
        s = self._IPV6.sub(lambda m: self.ip(m.group(0)), s)
        return self._MAC.sub(lambda m: self._label('mac', m.group(0)), s)


class _Redactor:
    def __init__(self, pseudonymiser=None):
        self.pseudo = pseudonymiser
        self.audit = _Auditor()

    def text(self, s, limit=MAX_TEXT):
        s = _URL_QUERY.sub(r'\1?[query removed]', str(s))
        for pattern, replacement in _PROFILE_PATH:
            s = pattern.sub(replacement, s)
        if self.pseudo is not None:
            s = self.pseudo.text(s)
        s = self.audit(s)
        return s if len(s) <= limit else s[:limit] + '…'

    def value(self, v, depth=0):
        if isinstance(v, dict):
            return self.evidence(v, depth + 1)
        if isinstance(v, (list, tuple, set)):
            return [self.value(x, depth + 1) for x in list(v)[:25]]
        if isinstance(v, (int, float, bool)) or v is None:
            return v
        return self.text(v)

    def evidence(self, evidence, depth=0):
        if depth > 4 or not isinstance(evidence, dict):
            return {}
        out = {}
        for key, v in evidence.items():
            name = str(key).lower()
            if name in _DROP_KEYS or any(word in name for word in _FORBIDDEN_IN_KEY):
                continue
            out[self.text(key, 100)] = self.value(v, depth)
        return out

    def ip(self, value):
        if not value or self.pseudo is None:
            return value
        return self.pseudo.ip(value)

    def alert(self, record, verdict=None):
        evidence = record.get('evidence') or {}
        verification = evidence.get('alert_verification') or {}
        out = {
            'review_id': record.get('review_id') or review_id(record),
            'time': record.get('time_str', ''),
            'rule_id': record.get('rule_id', ''),
            'severity': record.get('severity', ''),
            'severity_before_verification': evidence.get('severity_before_verification'),
            'title': self.text(record.get('title', '')),
            'description': self.text(record.get('description', '')),
            'category': record.get('category', ''),
            'src': self.ip(record.get('src_ip', '')),
            'src_port': record.get('src_port') or None,
            'dst': self.ip(record.get('dst_ip', '')),
            'dst_port': record.get('dst_port') or None,
            'protocol': record.get('protocol', ''),
            'netsentinel_verdict': verification.get('verdict'),
            'evidence': self.evidence(evidence),
        }
        if verdict:
            out['your_verdict'] = verdict.get('verdict')
        return {k: v for k, v in out.items() if v not in (None, '', {})}


# ─── Traffic digests ─────────────────────────────────────────────────────────

_HTTP_METHODS = (b'GET ', b'POST ', b'PUT ', b'HEAD ', b'DELETE ', b'PATCH ',
                 b'OPTIONS ', b'CONNECT ')


def _http_request(payload):
    """Method, host and path of an HTTP request. Nothing else from it is used."""
    if not payload.startswith(_HTTP_METHODS):
        return None
    head = payload.split(b'\r\n\r\n', 1)[0].split(b'\r\n')
    try:
        method, target = head[0].decode('latin-1').split(' ')[:2]
    except ValueError:
        return None
    host = ''
    for line in head[1:]:
        if line[:5].lower() == b'host:':
            host = line[5:].strip().decode('latin-1')
            break
    path = target.split('?', 1)[0].split('#', 1)[0]
    query = '?[query removed]' if '?' in target else ''
    return f"HTTP {method} {host}{path}{query}"


def _dns_names(dns):
    def as_list(field):
        if field is None:
            return []
        return list(field) if isinstance(field, list) else [field]

    def name(raw):
        return (raw.decode('latin-1', 'replace') if isinstance(raw, bytes) else str(raw)).rstrip('.')

    queries = [name(q.qname) for q in as_list(dns.qd)]
    if not dns.qr:
        return f"DNS query {', '.join(queries)}"
    answers = []
    for rr in as_list(dns.an)[:4]:
        data = rr.rdata
        if isinstance(data, bytes):
            data = name(data)
        answers.append(str(data))
    rcode = {0: '', 3: ' NXDOMAIN', 2: ' SERVFAIL'}.get(int(dns.rcode), f' rcode={dns.rcode}')
    return f"DNS answer {', '.join(queries)}{rcode}" + (f" → {', '.join(answers)}" if answers else '')


def _packet_line(pkt, redact, include_payloads):
    from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP
    when = datetime.fromtimestamp(float(pkt.time)).strftime('%H:%M:%S.%f')[:-3]
    if ARP in pkt:
        arp = pkt[ARP]
        what = 'who-has' if arp.op == 1 else 'is-at'
        return redact.text(f"{when}  ARP   {what} {arp.pdst} tell {arp.psrc} ({arp.hwsrc})", 300)
    layer = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
    if layer is None:
        return f"{when}  {pkt.summary()[:80]}"
    src, dst = redact.ip(layer.src), redact.ip(layer.dst)
    info, payload, proto = '', b'', 'IP'
    if TCP in pkt:
        tcp, proto = pkt[TCP], 'TCP'
        src, dst = f"{src}:{tcp.sport}", f"{dst}:{tcp.dport}"
        payload = bytes(tcp.payload)
        info = f"[{tcp.sprintf('%TCP.flags%')}]"
        if payload:
            from src.tls_inspect import parse_client_hello
            hello = parse_client_hello(payload)
            http = _http_request(payload)
            if hello:
                info += f" TLS ClientHello SNI={hello.get('sni') or '-'} JA4={hello.get('ja4') or '-'}"
            elif http:
                info += ' ' + http
    elif UDP in pkt:
        udp, proto = pkt[UDP], 'UDP'
        src, dst = f"{src}:{udp.sport}", f"{dst}:{udp.dport}"
        payload = bytes(udp.payload)
        if DNS in pkt:
            info = _dns_names(pkt[DNS])
        elif 443 in (udp.sport, udp.dport):
            info = 'QUIC'
    elif ICMP in pkt:
        proto = 'ICMP'
        info = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"
    line = f"{when}  {proto:<4}  {src} → {dst}  len={len(pkt)}  {info}".rstrip()
    if include_payloads and payload:
        preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload[:64])
        line += f"  payload: {preview}"
    return redact.text(line, 600)


def digest_pcap(path, redact, include_payloads=False, max_lines=DIGEST_MAX_LINES):
    """A line per packet of a capture, as text. Packets past max_lines are counted."""
    from scapy.utils import PcapReader
    lines, total, first, last = [], 0, None, None
    talkers = Counter()
    try:
        with PcapReader(path) as reader:
            for pkt in reader:
                total += 1
                first = first if first is not None else float(pkt.time)
                last = float(pkt.time)
                if len(lines) < max_lines:
                    try:
                        lines.append(_packet_line(pkt, redact, include_payloads))
                    except Exception as e:      # one odd frame must not lose the rest
                        lines.append(f"(could not read packet {total}: {type(e).__name__})")
                else:
                    talkers[redact.text(pkt.summary()[:80], 120)] += 1
    except (OSError, EOFError, ValueError) as e:
        return f"(could not read this capture: {e})\n"
    if not total:
        return "(the capture was empty)\n"
    span = (f"{datetime.fromtimestamp(first):%Y-%m-%d %H:%M:%S} to "
            f"{datetime.fromtimestamp(last):%H:%M:%S}")
    out = [f"{total} packets, {span}", ""] + lines
    if total > max_lines:
        out += ["", f"... {total - max_lines} more packets, most common:"]
        out += [f"  {n:>5}  {what}" for what, n in talkers.most_common(15)]
    return "\n".join(out) + "\n"


# ─── Bundles ─────────────────────────────────────────────────────────────────

def read_alerts(directory):
    """alerts.jsonl as records, last line per review_id, oldest first."""
    path = os.path.join(directory, 'alerts.jsonl')
    records = {}
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue                 # a half-written last line
                if isinstance(record, dict):
                    records[record.get('review_id') or review_id(record)] = record
    except OSError:
        return []
    return sorted(records.values(), key=lambda r: r.get('timestamp') or 0)


def _group_key(record):
    return record.get('rule_id', ''), record.get('src_ip') or record.get('dst_ip') or ''


def build_bundle(directory, out_dir=None, *, pseudonymise=False, include_pcaps=False,
                 include_payloads=False, version=None):
    """
    Build a bundle from a review directory. Returns a summary dict with 'folder'
    and 'zip'. Raises FileNotFoundError when there is nothing to review.
    """
    directory = os.path.abspath(directory)
    records = read_alerts(directory)
    if not records:
        raise FileNotFoundError(
            f"No alerts recorded in {directory} yet. Review mode records them as "
            "they are raised.")
    verdicts = VerdictStore(directory).all()
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    folder = os.path.abspath(out_dir or os.path.join(directory, 'bundles', f'bundle_{stamp}'))
    if os.path.exists(folder):
        shutil.rmtree(folder)
    os.makedirs(os.path.join(folder, 'traffic'))

    redact = _Redactor(Pseudonymiser() if pseudonymise else None)
    groups = defaultdict(list)
    for record in records:
        groups[_group_key(record)].append(record)
    ordered = sorted(groups.items(), key=lambda kv: (
        -max(_SEVERITY_RANK.get(r.get('severity'), 0) for r in kv[1]), -len(kv[1])))

    writer = _BundleWriter(folder, redact.audit)
    snippet_dir = os.path.join(directory, 'snippets')
    max_digests = BUNDLE_MAX_FILES - 4
    if include_pcaps:
        max_digests //= 2
    digests, omitted = [], 0
    for index, ((rule, host), members) in enumerate(ordered, 1):
        snippet = next((r['snippet'] for r in sorted(
            members, key=lambda r: -_SEVERITY_RANK.get(r.get('severity'), 0))
            if r.get('snippet') and os.path.exists(os.path.join(snippet_dir, r['snippet']))), None)
        if snippet is None:
            continue
        if len(digests) >= max_digests or writer.full():
            omitted += 1
            continue
        name = f"traffic/{len(digests) + 1:02d}_{re.sub(r'[^A-Za-z0-9_.-]', '_', rule)}.txt"
        head = (f"Group {index}: {rule} for {redact.ip(host) or '(no host)'}, "
                f"{len(members)} alert(s). Representative: {members[0].get('review_id')}\n"
                f"Traffic around {snippet_alert_time(members, snippet)}:\n\n")
        body = digest_pcap(os.path.join(snippet_dir, snippet), redact, include_payloads)
        if writer.write(name, head + body):
            digests.append((index, name))
            if include_pcaps:
                writer.copy(f"pcaps/{len(digests):02d}_{snippet}",
                            os.path.join(snippet_dir, snippet))
        else:
            omitted += 1

    shown = records[-MAX_ALERTS_IN_BUNDLE:]
    alerts = [redact.alert(r, verdicts.get(r.get('review_id'))) for r in shown]
    # Every string in it has been through the redactor's audit already. Auditing the
    # JSON text as well could swallow an escaped quote and break the file.
    writer.write('alerts.json', json.dumps(alerts, indent=1, ensure_ascii=False),
                 force=True, audited=True)
    writer.write('summary.md', _summary(records, ordered, redact, verdicts, digests,
                                        omitted, len(shown)), force=True)
    writer.write('README.md', _readme(records, version, pseudonymise, include_pcaps,
                                      include_payloads, redact.audit), force=True)

    zip_path = folder + '.zip'
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(folder):
            for f in files:
                full = os.path.join(root, f)
                z.write(full, os.path.relpath(full, folder))
    return {'folder': folder, 'zip': zip_path, 'alerts': len(records),
            'groups': len(ordered), 'digests': len(digests), 'files': writer.files,
            'bytes': writer.bytes, 'masked': redact.audit.masked}


def snippet_alert_time(members, snippet):
    for r in members:
        if r.get('snippet') == snippet:
            return r.get('time_str', '')
    return ''


class _BundleWriter:
    """Writes through the audit, within the bundle's size and file limits."""

    def __init__(self, folder, audit):
        self.folder, self.audit = folder, audit
        self.files, self.bytes = 0, 0

    def full(self):
        return self.files >= BUNDLE_MAX_FILES - 3 or self.bytes >= BUNDLE_MAX_BYTES * 0.9

    def write(self, name, text, force=False, audited=False):
        data = (text if audited else self.audit(text)).encode('utf-8')
        if not force and (self.files + 1 > BUNDLE_MAX_FILES - 3
                          or self.bytes + len(data) > BUNDLE_MAX_BYTES * 0.9):
            return False
        path = os.path.join(self.folder, *name.split('/'))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(data)
        self.files += 1
        self.bytes += len(data)
        return True

    def copy(self, name, source):
        size = os.path.getsize(source)
        if self.files + 1 > BUNDLE_MAX_FILES - 3 or self.bytes + size > BUNDLE_MAX_BYTES * 0.9:
            return False
        path = os.path.join(self.folder, *name.split('/'))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        shutil.copyfile(source, path)
        self.files += 1
        self.bytes += size
        return True


def _summary(records, ordered, redact, verdicts, digests, omitted, shown):
    first, last = records[0].get('time_str', ''), records[-1].get('time_str', '')
    rules = Counter(r.get('rule_id', '') for r in records)
    lines = [
        "# Summary", "",
        f"{len(records)} alerts from {first} to {last}, from {len(rules)} rules, "
        f"in {len(ordered)} groups (one rule, one host).", "",
        "## Alerts by rule", "",
        "| Rule | Alerts | Severities | NetSentinel's verdicts |",
        "|---|---|---|---|",
    ]
    for rule, n in rules.most_common():
        members = [r for r in records if r.get('rule_id') == rule]
        sev = Counter(r.get('severity', '') for r in members)
        ver = Counter(((r.get('evidence') or {}).get('alert_verification') or {})
                      .get('verdict', 'none') for r in members)
        lines.append(f"| {rule} | {n} | " + ", ".join(f"{k} {v}" for k, v in sev.most_common())
                     + " | " + ", ".join(f"{k} {v}" for k, v in ver.most_common()) + " |")

    hosts = Counter()
    for r in records:
        for ip in (r.get('src_ip'), r.get('dst_ip')):
            if ip:
                hosts[redact.ip(ip)] += 1
    lines += ["", "## Busiest hosts", ""]
    lines += [f"- {host}: in {n} alerts" for host, n in hosts.most_common(10)]

    repeats = [(rule, host, members) for (rule, host), members in ordered if len(members) >= 5]
    lines += ["", "## Firing over and over on one host", "",
              "Usually the first place to look for false positives.", ""]
    if repeats:
        for rule, host, members in repeats[:20]:
            lines.append(f"- {rule} for {redact.ip(host) or '(no host)'}: {len(members)} times, "
                         f"{members[0].get('time_str', '')} to {members[-1].get('time_str', '')}"
                         f" (representative {members[0].get('review_id')})")
    else:
        lines.append("- None: no rule fired five times or more for one host.")

    lines += ["", "## Groups", "",
              "Each group is one rule on one host. Its representative's review_id is "
              "the one to answer for.", ""]
    digest_for = dict(digests)
    for index, ((rule, host), members) in enumerate(ordered, 1):
        own = Counter((verdicts.get(r.get('review_id')) or {}).get('verdict') for r in members)
        own.pop(None, None)
        traffic = f", traffic in {digest_for[index]}" if index in digest_for else ''
        judged = f", already judged: {dict(own)}" if own else ''
        lines.append(f"{index}. {rule} for {redact.ip(host) or '(no host)'}: {len(members)} "
                     f"alert(s), representative {members[0].get('review_id')}{traffic}{judged}")
    if omitted:
        lines += ["", f"{omitted} groups had traffic that did not fit in the bundle."]
    if shown < len(records):
        lines += ["", f"alerts.json holds the newest {shown} of {len(records)} alerts."]
    return "\n".join(lines) + "\n"


def _readme(records, version, pseudonymise, include_pcaps, include_payloads, audit):
    left_out = ["packet payloads" if not include_payloads else None,
                "packet captures" if not include_pcaps else None,
                "URL query strings", "cookies, credentials and tokens",
                "user names in file paths",
                "LAN addresses (shown as lan-N and mac-N labels)" if pseudonymise else None]
    left_out = [x for x in left_out if x]
    return "\n".join([
        "# NetSentinel review bundle", "",
        f"Made by NetSentinel{' ' + version if version else ''} on "
        f"{datetime.now():%Y-%m-%d %H:%M} from "
        f"{len(records)} alerts. NetSentinel is a network monitor on one home or office "
        "network; these are the alerts it raised, with the traffic around them.", "",
        "## For the reviewer", "",
        "Say, for each group in summary.md, whether it looks like a real problem or a "
        "false positive, and why. Most groups are one rule firing for one host.", "",
        "- summary.md: what fired, how often, and where.",
        "- alerts.json: the alerts. `review_id` identifies each one. `netsentinel_verdict` "
        "is NetSentinel's own automatic check, which is often right about the obvious "
        "cases and can be wrong.",
        "- traffic/: one file per group, a line per packet: time, addresses, ports, "
        "protocol, DNS names, TLS server name (SNI) and HTTP host and path.", "",
        "Not included: " + ", ".join(left_out) + ". Anything that still looked like a "
        f"secret was replaced by [masked] ({audit.masked} times in this bundle).", "",
        "## How to answer", "",
        "Reply with a JSON array, one entry per group (use its representative's "
        "review_id) or per alert:", "",
        "```json",
        '[{"review_id": "0123456789ab", "verdict": "false_positive", "reason": "..."},',
        ' {"review_id": "ba9876543210", "verdict": "real", "reason": "..."}]',
        "```", "",
        '`verdict` is "real" or "false_positive". Saved as a file, it can be imported '
        "in NetSentinel (Review → Import verdicts in the desktop app, or "
        "`python -m src.review import <review folder> <file>`), and NetSentinel then "
        "stops raising that rule for that host or domain.", "",
    ])


# ─── Verdicts ────────────────────────────────────────────────────────────────

VERDICTS = ('real', 'false_positive')


def normalise_verdict(value):
    v = str(value or '').strip().lower().replace('-', '_').replace(' ', '_')
    if v in ('fp', 'false', 'false_positive', 'falsepositive', 'benign'):
        return 'false_positive'
    if v in ('real', 'true', 'true_positive', 'tp', 'malicious', 'genuine'):
        return 'real'
    return None


class VerdictStore:
    """verdicts.json in a review folder: what someone decided about each alert."""

    def __init__(self, directory):
        self.path = os.path.join(directory, 'verdicts.json')
        self._lock = threading.Lock()

    def all(self):
        try:
            with open(self.path, encoding='utf-8') as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def set(self, rid, verdict, note='', source='you'):
        with self._lock:
            data = self.all()
            data[rid] = {'verdict': verdict, 'note': str(note or '')[:500],
                         'source': source, 'at': time.time()}
            from src.config import atomic_write_json
            atomic_write_json(self.path, data, indent=1)


def record_verdict(directory, record, verdict, confirmed, note='', source='you'):
    """
    Record a verdict for an alert record. A false positive is confirmed in the
    ConfirmedFalsePositives store passed in. Returns the confirmed entry, if any.
    """
    verdict = normalise_verdict(verdict)
    if verdict is None:
        raise ValueError('verdict must be "real" or "false_positive"')
    rid = record.get('review_id') or review_id(record)
    entry = None
    if verdict == 'false_positive':
        entry = confirmed.add(record, note=note, review_id=rid)
    if directory:
        VerdictStore(directory).set(rid, verdict, note, source)
    return entry


def import_verdicts(directory, text, confirmed):
    """
    Apply an answer in the README's format. Takes the first JSON array in the text,
    so a reply pasted with its explanation or code fences around it still works.
    """
    start, end = text.find('['), text.rfind(']')
    if start < 0 or end <= start:
        raise ValueError('No JSON array found in the answer.')
    answers = json.loads(text[start:end + 1])
    records = {r.get('review_id'): r for r in read_alerts(directory)}
    result = {'real': 0, 'false_positive': 0, 'unknown_ids': [], 'no_subject': [],
              'bad_verdicts': []}
    for answer in answers:
        if not isinstance(answer, dict):
            continue
        rid = str(answer.get('review_id', ''))
        record = records.get(rid)
        if record is None:
            result['unknown_ids'].append(rid)
            continue
        verdict = normalise_verdict(answer.get('verdict'))
        if verdict is None:
            result['bad_verdicts'].append(rid)
            continue
        entry = record_verdict(directory, record, verdict, confirmed,
                               note=answer.get('reason', ''), source='import')
        result[verdict] += 1
        if verdict == 'false_positive' and entry is None:
            result['no_subject'].append(rid)
    return result


# ─── Command line ────────────────────────────────────────────────────────────

def _confirmed_store():
    from src.config import DB_DIR
    from src.baseline_whitelist import ConfirmedFalsePositives
    return ConfirmedFalsePositives(os.path.join(DB_DIR, 'confirmed_false_positives.json'))


def _main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(
        prog='python -m src.review',
        description='Build a review bundle from review mode, or apply verdicts.')
    sub = parser.add_subparsers(dest='command', required=True)
    b = sub.add_parser('build', help='build a bundle (folder and zip)')
    b.add_argument('directory', nargs='?', default=None,
                   help='review folder (default ~/.netsentinel/review)')
    b.add_argument('--out', help='bundle folder to write (default: under the review folder)')
    b.add_argument('--pseudonymise', action='store_true', help='replace LAN addresses with labels')
    b.add_argument('--pcaps', action='store_true', help='include the raw snippet captures')
    b.add_argument('--payloads', action='store_true', help='include payload previews')
    i = sub.add_parser('import', help='apply an answer in the README format')
    i.add_argument('directory')
    i.add_argument('answer', help='file holding the JSON answer')
    v = sub.add_parser('verdict', help='record one verdict')
    v.add_argument('directory')
    v.add_argument('review_id')
    v.add_argument('verdict', choices=['real', 'false_positive', 'fp'])
    v.add_argument('--note', default='')
    args = parser.parse_args(argv)

    directory = os.path.abspath(args.directory or default_directory())
    if args.command == 'build':
        from src import __version__
        try:
            result = build_bundle(directory, args.out, pseudonymise=args.pseudonymise,
                                  include_pcaps=args.pcaps, include_payloads=args.payloads,
                                  version=__version__)
        except FileNotFoundError as e:
            print(e)
            return 1
        print(f"{result['alerts']} alerts in {result['groups']} groups; "
              f"{result['digests']} traffic digests; {result['files']} files, "
              f"{result['bytes'] / 1024:.0f} KB; {result['masked']} values masked.")
        print(f"Folder: {result['folder']}\nZip:    {result['zip']}")
        return 0
    if args.command == 'import':
        with open(args.answer, encoding='utf-8-sig') as f:
            result = import_verdicts(directory, f.read(), _confirmed_store())
        print(json.dumps(result, indent=1))
        return 0
    records = {r.get('review_id'): r for r in read_alerts(directory)}
    record = records.get(args.review_id)
    if record is None:
        print(f"No alert with review_id {args.review_id} in {directory}.")
        return 1
    entry = record_verdict(directory, record, args.verdict, _confirmed_store(), args.note)
    if normalise_verdict(args.verdict) == 'false_positive' and entry is None:
        print("Recorded, but this alert names no host or domain to suppress by.")
    else:
        print("Recorded.")
    return 0


if __name__ == '__main__':
    raise SystemExit(_main())
