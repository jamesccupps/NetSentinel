"""
UniFi logs, received here over syslog.
======================================
A UniFi gateway without a drive keeps its traffic log for a short while and
will not export it. It can, though, send each entry as it happens to a syslog
server (its SIEM or remote logging setting), and NetSentinel can be that
server: opt-in, on the address and port set, from the senders listed.

- Receive only. Nothing is ever sent back, and nothing received runs or changes
  anything: a message is untrusted text, parsed and stored.
- A sender not on syslog.allowed_senders is dropped unread. (UDP's source can be
  forged by something on the LAN; what is stored is advisory either way.)
- Each day is a JSON-lines file under data/unifi_logs/, kept syslog.keep_days
  and within syslog.max_mb, the oldest first to go. Today's may use half of
  max_mb: past that its own oldest records go, so a flood can neither fill the
  disk nor push the other days out. The dashboard exports them.
- Per device, the destinations it reached and how often, allowed or blocked,
  are kept for the dashboard: what each device needs to talk to.

Formats: CEF (UniFi's SIEM output), iptables-style KEY=value lines, and plain
key=value. RFC 3164 and RFC 5424 headers are stripped. Anything unrecognised
is kept, trimmed, so the parser can be taught it.
"""

import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
from collections import OrderedDict
from datetime import datetime

logger = logging.getLogger("NetSentinel.Syslog")

MAX_MESSAGE = 8192
MAX_PER_SECOND = 5000
MAX_CLIENTS = 1000
MAX_DESTINATIONS = 300      # per client
RAW_KEPT = 400

_PRI = re.compile(r'^<(\d{1,3})>')
_RFC5424 = re.compile(r'^1 (\S+) (\S+) (\S+) (\S+) (\S+) (?:-|(?:\[.*?\])+) ?')
# A UniFi gateway's own lines name the host twice: "HOME-UDM HOME-UDM ulogd[26]: ..."
_RFC3164 = re.compile(r'^[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d (\S+) (?:[^:\s]+ )?([^:\s]+?)(?:\[\d+\])?: ?')
# A CEF extension key: a word and '=' at the start or after whitespace.
_CEF_KEY = re.compile(r'(?:^|(?<=\s))(\w+)=')
_KV = re.compile(r'(\w+)=("[^"]*"|\S*)')

# Field names, as UniFi's CEF and iptables lines spell them, in preference order.
# UniFi 10.6's "Blocked by Firewall" has no src=: the client is UNIFIsrcClient*.
FIELDS = {
    'src': ('src', 'SRC', 'UNIFIsrcClientIp', 'sourceAddress'),
    'dst': ('dst', 'DST', 'destinationAddress'),
    'sport': ('spt', 'SPT', 'sourcePort'),
    'dport': ('dpt', 'DPT', 'destinationPort'),
    'proto': ('proto', 'PROTO', 'transportProtocol', 'app'),
    'domain': ('UNIFIdstDomain', 'UNIFIdomain', 'dhost', 'destinationHostName',
               'destinationDnsDomain', 'domain'),
    'action': ('act', 'UNIFIaction', 'action', 'deviceAction'),
    'rule': ('UNIFIpolicyName', 'UNIFIfirewallPolicy', 'UNIFIruleName', 'cs1', 'rule', 'policy'),
    'client': ('UNIFIsrcClientAlias', 'UNIFIclientAlias', 'UNIFIsrcClientHostname',
               'UNIFIclientHostname', 'suser', 'shost'),
    'client_mac': ('UNIFIsrcClientMac', 'UNIFIclientMac', 'smac', 'MAC'),
    # Seen in real UniFi 10.6 messages: what kind of event, and its own words.
    'category': ('UNIFIcategory',),
    'message': ('msg',),
}


def parse(text):
    """One message as a dict of the fields above (those present), plus 'raw'."""
    text = text.strip()
    m = _PRI.match(text)
    if m:
        text = text[m.end():]
    # CEF first: UniFi sends "Nov 02 17:22:17 HOME-UDM CEF:0|...", and the RFC 3164
    # header pattern took "CEF" for the program name and cut it off.
    program = ''
    if 'CEF:' in text:
        text = text[text.index('CEF:'):]
    else:
        m = _RFC5424.match(text) or _RFC3164.match(text)
        if m:
            text = text[m.end():]
            program = m.group(2) if m.re is _RFC3164 else m.group(3)
    fields = {}
    if text.startswith('CEF:'):
        head, _, rest = text[text.index('CEF:'):].partition('|')
        parts = re.split(r'(?<!\\)\|', rest, maxsplit=6)
        if len(parts) == 7:
            fields['event'] = parts[4][:120]
            fields['severity'] = parts[5][:10]
            fields.update(_cef_extension(parts[6]))
    else:
        for k, v in _KV.findall(text):
            fields[k] = v.strip('"')
        # iptables puts the rule name in brackets: "[LAN_IN-RET-3] IN=...", after the
        # kernel's own "[12345.678]" uptime when there is one.
        rule = re.search(r'\[([A-Za-z][^\]\s]{0,79})\]', text) if 'SRC=' in text else None
        if rule:
            fields.setdefault('rule', rule.group(1))
    out = {}
    for name, keys in FIELDS.items():
        for k in keys:
            if fields.get(k):
                out[name] = str(fields[k])[:200]
                break
    if 'event' in fields:
        out['event'] = fields['event']
    action = out.get('action', '').lower()
    if not action and out.get('rule'):
        action = 'block' if re.search(r'(?i)drop|block|reject|-d-|_d\b', out['rule']) else ''
    if action:
        out['action'] = 'block' if re.search(r'(?i)block|drop|deny|reject', action) else 'allow'
    if program and program != '-':
        out['program'] = program[:60]
    out['raw'] = text[:RAW_KEPT]
    return out


def _cef_extension(ext):
    """
    A CEF extension's key=value pairs: each value runs to the next key.

    The regex this replaced matched a value lazily up to a lookahead for the
    next key, so 'key=' and a long run of whitespace before a non-space tail
    took most of a second per 8 KB datagram, holding the GIL: one forged
    packet a second stalled the whole app. It also stopped a value at an
    unescaped '=', so request=http://x/?a=b&c=1 lost request and gained c.
    """
    keys = list(_CEF_KEY.finditer(ext))
    out = {}
    for i, m in enumerate(keys):
        end = keys[i + 1].start() if i + 1 < len(keys) else len(ext)
        out[m.group(1)] = ext[m.end():end].replace('\\=', '=').replace('\\\\', '\\').strip()
    return out


def _day(when):
    return datetime.fromtimestamp(when).strftime('%Y-%m-%d')


def _size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


_COPY = 1024 * 1024


def _drop_oldest(path, keep):
    """
    Drop a day file's oldest records so at most `keep` bytes of the newest
    remain: (records dropped, bytes left). Rewritten in place, since a copy
    beside it would need the free space a flood is using up; a crash part-way
    costs a torn record or a few repeated ones, not the day. Keeping half the
    cap makes the next rewrite wait for as many bytes again, so the cost is
    linear in what is received.
    """
    with open(path, 'r+b') as f:
        size = f.seek(0, os.SEEK_END)
        if size <= keep:
            return 0, size
        # the first whole record at or after size - keep
        cut, at = size, size - keep - 1
        f.seek(at)
        while True:
            chunk = f.read(_COPY)
            if not chunk:
                break
            newline = chunk.find(b'\n')
            if newline >= 0:
                cut = at + newline + 1
                break
            at += len(chunk)
        f.seek(0)
        dropped, left = 0, cut
        while left > 0:
            chunk = f.read(min(_COPY, left))
            if not chunk:
                break
            dropped += chunk.count(b'\n')
            left -= len(chunk)
        src, dst = cut, 0
        while True:
            f.seek(src)
            chunk = f.read(_COPY)
            if not chunk:
                break
            f.seek(dst)
            f.write(chunk)
            src += len(chunk)
            dst += len(chunk)
        f.truncate(dst)
    return dropped, dst


def _sender_list(value):
    if isinstance(value, str):
        value = [v for v in re.split(r'[,\s]+', value) if v]
    out = set()
    for v in value or ():
        try:
            out.add(str(ipaddress.ip_address(str(v).strip())))
        except ValueError:
            continue
    return out


class SyslogReceiver:
    """Listens when enabled; stores days to disk; keeps per-device destinations."""

    def __init__(self, config, data_dir=None, clock=time.time, names=None):
        get = config.get
        self.enabled = bool(get('syslog', 'enabled', default=False))
        self.bind = str(get('syslog', 'bind', default='') or '').strip()
        self.port = int(get('syslog', 'port', default=5514) or 5514)
        self.allowed = _sender_list(get('syslog', 'allowed_senders', default=[]))
        self.keep_days = max(1, int(get('syslog', 'keep_days', default=30) or 30))
        self.max_bytes = max(1, int(get('syslog', 'max_mb', default=500) or 500)) * 1024 * 1024
        # Today's share of max_mb. Senders can be forged, so a flood must not be
        # able to fill the disk, nor push every older day out to make room.
        self.day_cap = self.max_bytes // 2
        if data_dir is None:
            from src.config import DB_DIR
            data_dir = os.path.join(DB_DIR, 'unifi_logs')
        self.data_dir = data_dir
        self._clock = clock
        self._names = names           # callable(ip) -> name, e.g. the UniFi inventory's
        self._lock = threading.Lock()
        self._clients = OrderedDict()   # ip -> {'dests': {key: [allow, block, last]}, ...}
        self.received = self.dropped_sender = self.dropped_rate = self.stored = 0
        self.dropped_cap = 0          # today's oldest records, dropped to keep within day_cap
        self._today, self._today_bytes = None, 0
        self.last_message = None
        self.error = ''
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self._second, self._in_second = 0, 0

    # ─── Receiving ──────────────────────────────────────────────────────────

    def start(self):
        if not self.enabled or self._thread is not None:
            return False
        if not self.bind or not self.allowed:
            self.error = 'Needs the address to listen on and the gateway allowed to send.'
            return False
        try:
            sock = socket.socket(socket.AF_INET6 if ':' in self.bind else socket.AF_INET,
                                 socket.SOCK_DGRAM)
            sock.bind((self.bind, self.port))
            sock.settimeout(1.0)
        except OSError as e:
            self.error = f'Could not listen on {self.bind}:{self.port} ({type(e).__name__}).'
            logger.warning("Syslog: %s", self.error)
            return False
        self._sock = sock
        self._thread = threading.Thread(target=self._loop, daemon=True, name='SyslogReceiver')
        self._thread.start()
        logger.info("Syslog receiver listening on %s:%d for %s",
                    self.bind, self.port, ', '.join(sorted(self.allowed)))
        return True

    def stop(self):
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, (sender, *_rest) = self._sock.recvfrom(MAX_MESSAGE + 1)
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                continue
            self.handle(data, sender)

    def handle(self, data, sender, now=None):
        """One datagram. Returns the parsed record, or None if it was dropped."""
        now = self._clock() if now is None else now
        if sender not in self.allowed:
            self.dropped_sender += 1
            return None
        second = int(now)
        if second != self._second:
            self._second, self._in_second = second, 0
        self._in_second += 1
        if self._in_second > MAX_PER_SECOND:
            self.dropped_rate += 1
            return None
        record = parse(data[:MAX_MESSAGE].decode('utf-8', errors='replace'))
        record['time'] = round(now, 3)
        record['sender'] = sender
        self.received += 1
        self.last_message = now
        self._count(record)
        self._store(record, now)
        return record

    # ─── Per device ─────────────────────────────────────────────────────────

    def _count(self, record):
        src, dst = record.get('src'), record.get('dst')
        if not src or not dst:
            return
        try:
            if not ipaddress.ip_address(src).is_private:
                return              # an inbound connection; the device is the destination
        except ValueError:
            return
        dest = record.get('domain') or dst
        key = f"{dest}:{record['dport']}" if record.get('dport') else dest
        with self._lock:
            client = self._clients.pop(src, None) or {'dests': {}, 'client': '', 'mac': ''}
            self._clients[src] = client
            if record.get('client'):
                client['client'] = record['client']
            if record.get('client_mac'):
                client['mac'] = record['client_mac'].lower()
            dests = client['dests']
            entry = dests.get(key)
            if entry is None:
                if len(dests) >= MAX_DESTINATIONS:
                    return
                entry = dests[key] = [0, 0, 0.0]
            entry[1 if record.get('action') == 'block' else 0] += 1
            entry[2] = record['time']
            while len(self._clients) > MAX_CLIENTS:
                self._clients.popitem(last=False)

    def devices(self, top=25):
        """Each device that reached out, with its busiest destinations."""
        with self._lock:
            clients = [(ip, dict(c, dests=dict(c['dests']))) for ip, c in self._clients.items()]
        out = []
        for ip, c in clients:
            name = (self._names(ip) if self._names else None) or c['client'] or ''
            dests = sorted(c['dests'].items(), key=lambda kv: -(kv[1][0] + kv[1][1]))
            out.append({'ip': ip, 'name': name, 'mac': c['mac'],
                        'destinations': len(c['dests']),
                        'blocked': sum(v[1] for v in c['dests'].values()),
                        'top': [{'to': k, 'allowed': v[0], 'blocked': v[1], 'last': v[2]}
                                for k, v in dests[:top]]})
        out.sort(key=lambda d: -sum(t['allowed'] + t['blocked'] for t in d['top']))
        return out

    # ─── Storage ────────────────────────────────────────────────────────────

    def day_path(self, day):
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', day or ''):
            raise ValueError('a day is YYYY-MM-DD')
        return os.path.join(self.data_dir, f'{day}.jsonl')

    def days(self):
        try:
            return sorted(n[:-6] for n in os.listdir(self.data_dir)
                          if re.fullmatch(r'\d{4}-\d{2}-\d{2}\.jsonl', n))
        except OSError:
            return []

    def _store(self, record, now):
        day = _day(now)
        # bytes, not text: the cap counts what is on disk, and text mode on
        # Windows writes two bytes for each '\n'
        line = (json.dumps(record, ensure_ascii=False) + '\n').encode('utf-8')
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            path = self.day_path(day)
            if day != self._today:
                self._today, self._today_bytes = day, _size(path)
            if self._today_bytes + len(line) > self.day_cap:
                dropped, self._today_bytes = _drop_oldest(path, self.day_cap // 2)
                self.dropped_cap += dropped
            with open(path, 'ab') as f:
                f.write(line)
            self._today_bytes += len(line)
            self.stored += 1
            if self.stored % 1000 == 1:
                self.prune(now)
        except OSError as e:
            self.error = f'Could not store a message ({type(e).__name__}).'

    def prune(self, now=None):
        """
        Days past keep_days, then the oldest until the rest fit max_mb with
        today's counted. Today's is never removed: it is kept within day_cap
        by dropping its own oldest records. Today is the clock's date, not
        the newest file: after the clock steps back, a file named for a later
        day is just another day.
        """
        now = self._clock() if now is None else now
        today = _day(now)
        cutoff = _day(now - self.keep_days * 86400)
        for day in self.days():
            if day < cutoff and day != today:
                self._remove(day)
        days = [d for d in self.days() if d != today]
        sizes = {d: _size(self.day_path(d)) for d in days}
        total = sum(sizes.values()) + min(_size(self.day_path(today)), self.day_cap)
        for day in days:
            if total <= self.max_bytes:
                break
            total -= sizes[day]
            self._remove(day)

    def _remove(self, day):
        try:
            os.remove(self.day_path(day))
        except OSError:
            pass

    # ─── Status, for the Threat data page ───────────────────────────────────

    def status(self):
        row = {'name': 'unifi_syslog', 'category': 'Device traffic',
               'description': 'UniFi traffic log, received over syslog',
               'updated': self.last_message, 'entries': self.received, 'refresh_hours': None,
               'dropped_sender': self.dropped_sender, 'dropped_rate': self.dropped_rate,
               'dropped_cap': self.dropped_cap}
        if not self.enabled:
            return dict(row, state='off', note='Off in settings (syslog.enabled).')
        if self.error and self._thread is None:
            return dict(row, state='failed', note=self.error)
        if not self.received:
            return dict(row, state='waiting', note=(
                f'Listening on {self.bind}:{self.port} for {", ".join(sorted(self.allowed))}; '
                'nothing received yet.'))
        days = len(self.days())
        note = f'{days} day{"" if days == 1 else "s"} kept on disk.'
        if self.dropped_sender:
            note += f' {self.dropped_sender} from senders not allowed, dropped.'
        if self.dropped_rate:
            note += f' {self.dropped_rate} past {MAX_PER_SECOND:,} a second, dropped.'
        if self.dropped_cap:
            note += (f" {self.dropped_cap} of the day's oldest dropped to keep it within "
                     f"{self.day_cap / 1024 ** 2:g} MB.")
        return dict(row, state='ok', note=note)
