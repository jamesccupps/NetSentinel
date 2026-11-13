"""
Exposures: what is set up unsafely, kept apart from what is happening.
======================================================================
A plaintext login, an unencrypted service, a device that answers SNMP's default
community or runs software with a known exploited flaw: each is true of a
device until someone changes it, not an event. They came through the alert
stream as events, rated CRITICAL and "[CONFIRMED]", and again every day: in a
week of the owner's alerts, 248 of 277 were 43 such conditions repeated, among
them Home Assistant's token over plain HTTP four times and an energy monitor's
Modbus port rated CRITICAL. They buried the alerts about something happening.

Now each is one entry here, per device and issue, with when it was first and
last seen and how often. A new one raises one alert; a repeat only updates its
entry. An entry stays open until it is marked fixed (it alerts again if it is
seen after that) or accepted (it never alerts again unless it gets worse).
Exposures are rated at most HIGH: CRITICAL is for signs of an attack.

Nothing secret is kept: the entry holds the alert's title, description, advice
and the hosts involved, never the evidence's credential value.
"""

import hashlib
import logging
import threading
import time

from src.ipcache import is_private

logger = logging.getLogger("NetSentinel.Exposures")

STATE_FILE = 'exposures.json'
MAX_ENTRIES = 2000
MAX_CLIENTS = 10
SAVE_EVERY = 30
STATES = ('open', 'accepted', 'fixed')
_RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
CAP = 'HIGH'

# Sensitive-data findings that are something being done, not a standing
# condition: they stay alerts.
ACTIVITY_DATA_TYPES = frozenset({
    'Suspicious User Agent', 'Scripted HTTP Client', 'Missing User Agent',
    'HTTP Attack Pattern', 'BACnet WRITE', 'BACnet RESET', 'BACnet Discovery',
    'Modbus WRITE',
})

_TITLE_PREFIXES = ('[CONFIRMED] ', '[LIKELY THREAT] ', '[LIKELY SAFE] ', '[FALSE POSITIVE] ')


def _sev(alert):
    return str(getattr(alert.severity, 'name', alert.severity) or 'MEDIUM').upper()


def _bare_title(title):
    title = str(title or '')
    for prefix in _TITLE_PREFIXES:
        if title.startswith(prefix):
            title = title[len(prefix):]
    return title


# Raised on the packet the server sent, so the alert's source is the device.
_SERVER_SENT_RULES = frozenset({'TLS-CERT-SELF-SIGNED', 'TLS-CERT-INVALID'})


def _ends(alert):
    """
    (device, port, client, device's name field, client's name field). Filed by
    the destination like the rest, a certificate alert was an exposure of this
    PC at the random port it connected from, and every hour's repeat for the
    same server a new one.
    """
    if alert.rule_id in _SERVER_SENT_RULES:
        return alert.src_ip, alert.src_port, alert.dst_ip, 'src_name', 'dst_name'
    return alert.dst_ip, alert.dst_port, alert.src_ip, 'dst_name', 'src_name'


def exposure_key(alert):
    """
    The device-and-issue an alert is about, as a tuple, or None for an alert
    about something happening (an attack, a scan, an upload, a new device).
    """
    rule = alert.rule_id
    ev = alert.evidence or {}
    port = alert.dst_port or 0
    if rule == 'FORENSICS-CREDENTIAL':
        extra = ev.get('extra') or {}
        # Someone asking with SNMP's default community is a scanner or a monitor
        # at work; the device that answers it is the exposure.
        if extra.get('answered') is False:
            return None
        if ev.get('credential_type') == 'control_command':      # a Modbus write
            return None
        server = (extra.get('host') or alert.dst_ip or '').lower()
        return ('credential', ev.get('protocol', ''), ev.get('credential_type', ''), server, port)
    if rule == 'FORENSICS-INSECURE-SVC':
        return ('service', ev.get('service', ''), alert.dst_ip, port)
    if rule == 'FORENSICS-SENSITIVE-DATA':
        data_type = ev.get('data_type', '')
        if data_type in ACTIVITY_DATA_TYPES:
            return None
        return ('data', data_type, alert.dst_ip, port)
    if rule == 'VULN-KEV':
        return ('vulnerability', alert.dst_ip, port)
    if rule in _SERVER_SENT_RULES:
        server, server_port = _ends(alert)[:2]
        return ('certificate', rule, server, server_port or 0)
    return None


def _id_for(key):
    return hashlib.sha256('|'.join(str(k) for k in key).encode('utf-8')).hexdigest()[:12]


class ExposureRegistry:
    """One entry per device and issue (see the module notes). Thread-safe."""

    def __init__(self):
        self.path = None
        self._lock = threading.Lock()
        self._entries = {}
        self._dirty = False
        self._last_save = 0.0
        self.repeats = 0            # alerts folded into an entry, this run

    # ─── Observing ──────────────────────────────────────────────────────────

    def observe(self, alert, now=None):
        """
        Note an alert. None if it is not an exposure. Otherwise a dict with
        'report' (raise the alert or not), 'why' ('new', 'worse', 'seen again',
        or 'repeat'/'accepted' when not reported) and the entry's 'id'. A
        reported alert is capped at HIGH and tagged with its exposure.
        """
        key = exposure_key(alert)
        if key is None:
            return None
        now = now or time.time()
        severity = _sev(alert)
        if _RANK.get(severity, 1) > _RANK[CAP]:
            alert.evidence.setdefault('severity_before_exposure_cap', severity)
            alert.severity = CAP
            severity = CAP
        ident = _id_for(key)
        ev = alert.evidence or {}
        with self._lock:
            entry = self._entries.get(ident)
            if entry is None:
                entry = self._new_entry(ident, key, alert, severity, now)
                self._entries[ident] = entry
                why = 'new'
                if len(self._entries) > MAX_ENTRIES:
                    self._prune()
            else:
                worse = _RANK.get(severity, 1) > _RANK.get(entry['severity'], 1)
                entry['last_seen'] = now
                entry['count'] += 1
                if worse:
                    entry['severity'] = severity
                    entry['title'] = _bare_title(alert.title)
                    entry['description'] = str(alert.description or '')[:500]
                if worse and entry['state'] != 'open':
                    entry['state'], entry['state_changed'] = 'open', now
                    why = 'worse'
                elif worse:
                    why = 'worse'
                elif entry['state'] == 'fixed':
                    entry['state'], entry['state_changed'] = 'open', now
                    why = 'seen again'
                else:
                    why = 'accepted' if entry['state'] == 'accepted' else 'repeat'
            device, _, client, device_name, client_name = _ends(alert)
            if client and client != device and client not in entry['clients']:
                entry['clients'] = (entry['clients'] + [client])[-MAX_CLIENTS:]
            if ev.get(client_name) and client:
                entry['client_names'][client] = ev[client_name]
            if ev.get(device_name):
                entry['device_name'] = ev[device_name]
            self._dirty = True
            report = why in ('new', 'worse', 'seen again')
            if not report:
                self.repeats += 1
            snapshot = dict(entry)
        if report:
            alert.evidence['exposure'] = {
                'id': ident, 'why': why, 'first_seen': snapshot['time_first'],
                'note': ('A standing condition, listed under Exposures. It is not '
                         'alerted on again unless it gets worse or comes back after '
                         'being marked fixed.')}
        return {'report': report, 'why': why, 'id': ident}

    def _new_entry(self, ident, key, alert, severity, now):
        ev = alert.evidence or {}
        device, port, _, device_name, _ = _ends(alert)
        return {
            'id': ident, 'kind': key[0], 'key': [str(k) for k in key],
            'rule_id': alert.rule_id, 'severity': severity,
            'title': _bare_title(alert.title),
            'description': str(alert.description or '')[:500],
            'recommendation': str(ev.get('recommendation') or ev.get('how_to_fix') or '')[:500],
            'device': device or '', 'port': port or 0,
            'device_name': ev.get(device_name, ''),
            'clients': [], 'client_names': {},
            'first_seen': now, 'last_seen': now, 'count': 1,
            'time_first': time.strftime('%Y-%m-%d %H:%M', time.localtime(now)),
            'state': 'open', 'state_changed': now, 'note': '',
        }

    def _prune(self):
        """Fixed and accepted entries first, oldest first; open ones only if they must."""
        order = sorted(self._entries.values(),
                       key=lambda e: (e['state'] == 'open', e['last_seen']))
        for e in order[:len(self._entries) - MAX_ENTRIES]:
            del self._entries[e['id']]

    # ─── Reading and changing ───────────────────────────────────────────────

    def entries(self):
        """Open first, then accepted, then fixed; worst and latest first within each."""
        with self._lock:
            out = [dict(e, clients=list(e['clients']), client_names=dict(e['client_names']))
                   for e in self._entries.values()]
        out.sort(key=lambda e: (STATES.index(e['state']), -_RANK.get(e['severity'], 1),
                                -e['last_seen']))
        return out

    def counts(self):
        out = {s: 0 for s in STATES}
        by_severity = {s: 0 for s in _RANK}
        with self._lock:
            for e in self._entries.values():
                out[e['state']] += 1
                if e['state'] == 'open':
                    by_severity[e['severity']] = by_severity.get(e['severity'], 0) + 1
        out['open_by_severity'] = by_severity
        out['repeats_folded'] = self.repeats
        return out

    def set_state(self, ident, state, note=''):
        """Mark an entry open, accepted or fixed. KeyError for an unknown id, ValueError for a state."""
        if state not in STATES:
            raise ValueError(state)
        with self._lock:
            entry = self._entries[ident]
            entry['state'], entry['state_changed'] = state, time.time()
            entry['note'] = str(note or '')[:500]
            self._dirty = True
            snapshot = dict(entry)
        self.save(force=True)
        return snapshot

    # ─── Storage ────────────────────────────────────────────────────────────

    def attach(self, path):
        """Keep the list in path from now on, starting from what is there."""
        self.path = path
        try:
            import json
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
        except FileNotFoundError:
            return
        except Exception as e:
            logger.warning("Exposures %s unreadable, starting fresh: %s", path, e)
            return
        loaded = {}
        for e in (data.get('entries') if isinstance(data, dict) else None) or []:
            try:
                if e['state'] not in STATES or not isinstance(e['id'], str):
                    continue
                # Certificates are only judged on internet servers, so one filed
                # under a private address is the old misfiling: this PC and the
                # port it connected from. Its server's entry comes back with the
                # next alert.
                if e.get('kind') == 'certificate' and is_private(str(e.get('device', ''))):
                    continue
                # A BACnet device announcing itself was filed as a plaintext
                # login, under the broadcast address it answered to. It never was
                # one (forensics_db.NOT_CREDENTIALS), and nothing raises it now.
                if e.get('kind') == 'credential' and list(e.get('key') or [])[1:3] == [
                        'BACnet', 'device_identity']:
                    continue
                e['first_seen'], e['last_seen'] = float(e['first_seen']), float(e['last_seen'])
                e['count'] = int(e['count'])
                e.setdefault('clients', [])
                e.setdefault('client_names', {})
                loaded[e['id']] = e
            except (KeyError, TypeError, ValueError):
                continue
        with self._lock:
            loaded.update(self._entries)
            self._entries = loaded

    def save(self, force=False):
        if not self.path:
            return
        now = time.time()
        if not force and (not self._dirty or now - self._last_save < SAVE_EVERY):
            return
        with self._lock:
            snapshot = {'version': 1, 'entries': [dict(e) for e in self._entries.values()]}
            self._dirty = False
            self._last_save = now
        try:
            from src.config import atomic_write_json
            atomic_write_json(self.path, snapshot, indent=1)
        except Exception as e:
            logger.debug("Exposures save failed: %s", e)
