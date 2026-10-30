"""
The day's findings, kept on disk.
=================================
What the service has found since the last digest, one entry per finding
identity (rule, device, key), with the true count and whether it was pushed.

    window = FindingWindow('/var/lib/netmon/state/findings.json')
    if window.admit(finding):        # new today: push it
        ...

Three problems this exists to fix
---------------------------------
**A restart lost the day.** The list was in memory, capped at 2,000 and
cleared after each digest, so a restart at 4pm produced a digest the next
morning covering eight hours, and nothing said so.

**Every capture file was a new start.** The service builds a fresh analyzer
per rotated file, so per-file deduplication meant a finding that recurs —
one laptop's NAT-PMP requests, a controller polled every minute — pushed
again every fifteen minutes. Admission here is across files and restarts: an
identity pushes once, and later sightings add to its count.

**A push nobody answered vanished.** The digest is where an unanswered push
should keep appearing until someone acknowledges it, and the window is
cleared every day. So pushed findings are also kept as open items, across
digests, until a silence covers them or they have not been seen for a week.
While one is open, the same finding does not push again: it is on the
digest's checklist every morning instead, which is the louder place.

What is kept
------------
Findings and a slimmed copy of their event: addresses, names, VLANs and
zones — what redaction and the UI need — and never a payload. The file names
devices and addresses, so it is written owner-only.
"""

from __future__ import annotations

import functools
import json
import logging
import os
import threading
import time
from collections import OrderedDict

from netmon.events import Event, Finding

logger = logging.getLogger("netmon.window")

__all__ = ['FindingWindow']

#: Event fields carried over a restart. Enough to redact a finding and to
#: describe where it happened; nothing that could hold content.
_EVENT_FIELDS = ('src_vlan', 'dst_vlan', 'observed_vlan', 'src_name', 'dst_name',
                 'src_zone', 'dst_zone', 'src_role', 'dst_role', 'direction',
                 'metadata_only', 'may_store_payload', 'canary_service',
                 'config_object', 'dst_country', 'dst_asn', 'src_country',
                 'src_asn')


def _event_to_dict(event):
    if event is None:
        return None
    data = {key: getattr(event, key) for key in
            ('kind', 'ts', 'src_ip', 'dst_ip', 'src_mac', 'dst_mac',
             'src_port', 'dst_port', 'protocol', 'vlan', 'source')}
    data['fields'] = {key: event.fields[key] for key in _EVENT_FIELDS
                      if key in event.fields}
    return data


def _event_from_dict(data):
    if not isinstance(data, dict):
        return None
    event = Event(kind=str(data.get('kind') or 'event'),
                  ts=float(data.get('ts') or 0) or 1.0)
    for key in ('src_ip', 'dst_ip', 'src_mac', 'dst_mac', 'protocol', 'source'):
        setattr(event, key, str(data.get(key) or ''))
    for key in ('src_port', 'dst_port', 'vlan'):
        value = data.get(key)
        setattr(event, key, int(value) if isinstance(value, int) else None)
    fields = data.get('fields') or {}
    if isinstance(fields, dict):
        event.fields.update({k: v for k, v in fields.items() if k in _EVENT_FIELDS})
    return event


def _finding_to_dict(finding):
    return {'rule_id': finding.rule_id, 'title': finding.title,
            'severity': finding.severity, 'tier': finding.tier,
            'description': finding.description, 'ts': finding.ts,
            'device': finding.device, 'key': finding.key,
            'next_check': finding.next_check, 'count': finding.count,
            'evidence': finding.evidence or {},
            'event': _event_to_dict(finding.event)}


def _finding_from_dict(data):
    return Finding(
        str(data.get('rule_id') or ''), str(data.get('title') or ''),
        severity=data.get('severity') or 'medium',
        tier=str(data.get('tier') or 'digest'),
        description=str(data.get('description') or ''),
        ts=float(data.get('ts') or 0) or 1.0,
        device=str(data.get('device') or ''), key=str(data.get('key') or ''),
        next_check=str(data.get('next_check') or ''),
        event=_event_from_dict(data.get('event')),
        count=int(data.get('count') or 1),
        evidence=dict(data.get('evidence') or {}))


def _identity(finding):
    return '\x1f'.join(str(part) for part in finding.dedup_key())


def _locked(method):
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return wrapper


class FindingWindow:
    """
    Findings since the last digest, deduplicated by identity, on disk.

    The service writes it from its own thread while the UI reads it from
    request threads, so every method holds one lock.
    """

    def __init__(self, path='', cap=2000, open_days=7, clock=time.time):
        self.path = path
        self.cap = int(cap)
        self.open_seconds = float(open_days) * 86400
        self._clock = clock
        self._lock = threading.RLock()
        self._entries = OrderedDict()   # identity -> {finding, first, last, pushed}
        self.events = 0                 # since the last digest
        self.started = clock()          # when this window opened
        self.standing = []              # the latest configuration check's
        self.open_pushes = {}           # identity -> summary, across digests
        self.loaded = self._load()

    # ─── Admission ───────────────────────────────────────────────────────

    @_locked
    def admit(self, finding, now=None):
        """
        Keep a finding. True if it is new — the first of its identity since
        the last digest, and not an open push already — so worth pushing.

        A repeat adds its count to the one already kept, which is the one the
        UI and the digest show.
        """
        now = self._clock() if now is None else now
        identity = _identity(finding)
        entry = self._entries.get(identity)
        if entry is not None:
            kept = entry['finding']
            kept.count += max(1, int(finding.count or 1))
            entry['last'] = now
            self._entries.move_to_end(identity)
            if identity in self.open_pushes:
                self.open_pushes[identity]['last_seen'] = now
                self.open_pushes[identity]['count'] = kept.count
            return False

        self._entries[identity] = {'finding': finding, 'first': now, 'last': now,
                                   'pushed': False}
        while len(self._entries) > self.cap:
            self._entries.popitem(last=False)

        if identity in self.open_pushes:
            # Pushed on an earlier day and still unanswered: the checklist
            # carries it, so it does not push again.
            self.open_pushes[identity]['last_seen'] = now
            self.open_pushes[identity]['count'] = \
                int(self.open_pushes[identity].get('count', 1)) + int(finding.count or 1)
            return False
        return True

    @_locked
    def mark_pushed(self, finding, now=None):
        now = self._clock() if now is None else now
        identity = _identity(finding)
        entry = self._entries.get(identity)
        if entry is not None:
            entry['pushed'] = True
        self.open_pushes[identity] = {
            'rule': finding.rule_id, 'device': finding.device, 'key': finding.key,
            'title': finding.title, 'severity': finding.severity,
            'description': finding.description, 'first_pushed': now,
            'last_seen': now, 'count': int(finding.count or 1)}

    @_locked
    def add_events(self, count):
        self.events += int(count or 0)

    @_locked
    def set_standing(self, problems):
        """
        The configuration problems the latest check found standing, as
        Findings or as the dicts `netmon.drift.check` reports.
        """
        out = []
        for item in problems or []:
            if isinstance(item, Finding):
                item = {'rule': item.rule_id, 'key': item.key,
                        'device': item.device, 'severity': item.severity,
                        'description': item.description}
            if isinstance(item, dict) and item.get('rule'):
                out.append({k: item.get(k, '') for k in
                            ('rule', 'key', 'device', 'severity', 'description')})
        self.standing = out

    # ─── Reading ─────────────────────────────────────────────────────────

    @_locked
    def findings(self):
        return [entry['finding'] for entry in self._entries.values()]

    def __len__(self):
        return len(self._entries)

    @_locked
    def open_items(self, silences=None, now=None):
        """
        What is still waiting on a person, for the digest's checklist.

        A push that a silence now covers is answered, and leaves the list; one
        not seen for a week has gone away by itself, and leaves too.
        """
        now = self._clock() if now is None else now
        self.prune_open(silences, now)
        active = silences.active(now) if silences is not None else []
        pushes = sorted(self.open_pushes.values(),
                        key=lambda p: p.get('first_pushed', 0))
        return {'silences': active, 'standing': list(self.standing),
                'pushes': [dict(p) for p in pushes]}

    @_locked
    def prune_open(self, silences=None, now=None):
        now = self._clock() if now is None else now
        entries = silences.active(now) if silences is not None else []
        for identity, item in list(self.open_pushes.items()):
            if now - float(item.get('last_seen', 0)) > self.open_seconds:
                del self.open_pushes[identity]
                continue
            if entries:
                probe = Finding(item['rule'], item.get('title', ''),
                                device=item.get('device', ''),
                                key=item.get('key', ''), ts=1.0)
                if silences.match(probe, now, entries) is not None:
                    del self.open_pushes[identity]

    # ─── The day boundary ────────────────────────────────────────────────

    @_locked
    def rollover(self, now=None):
        """
        Start a new window after a digest. Open pushes carry over; the day's
        findings and event count do not.
        """
        now = self._clock() if now is None else now
        self._entries.clear()
        self.events = 0
        self.started = now
        self.save()

    # ─── Disk ────────────────────────────────────────────────────────────

    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return False
        try:
            with open(self.path, encoding='utf-8') as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.warning('could not read %s (%s); starting an empty window',
                           self.path, type(e).__name__)
            return False
        if not isinstance(data, dict):
            return False
        try:
            for item in data.get('entries') or []:
                finding = _finding_from_dict(item['finding'])
                self._entries[_identity(finding)] = {
                    'finding': finding, 'first': float(item.get('first', 0)),
                    'last': float(item.get('last', 0)),
                    'pushed': bool(item.get('pushed'))}
            self.events = int(data.get('events') or 0)
            self.started = float(data.get('started') or self.started)
            self.standing = [s for s in (data.get('standing') or [])
                             if isinstance(s, dict)]
            self.open_pushes = {k: v for k, v in
                                (data.get('open_pushes') or {}).items()
                                if isinstance(v, dict) and v.get('rule')}
        except (KeyError, TypeError, ValueError) as e:
            logger.warning('%s is damaged (%s); starting an empty window',
                           self.path, type(e).__name__)
            self._entries.clear()
            self.events, self.standing, self.open_pushes = 0, [], {}
            return False
        while len(self._entries) > self.cap:
            self._entries.popitem(last=False)
        return True

    @_locked
    def save(self):
        if not self.path:
            return
        data = {'started': self.started, 'events': self.events,
                'standing': self.standing, 'open_pushes': self.open_pushes,
                'entries': [{'finding': _finding_to_dict(e['finding']),
                             'first': e['first'], 'last': e['last'],
                             'pushed': e['pushed']}
                            for e in self._entries.values()]}
        try:
            os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
            temporary = self.path + '.tmp'
            with open(temporary, 'w', encoding='utf-8') as handle:
                json.dump(data, handle, default=str)
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            os.replace(temporary, self.path)
        except OSError as e:
            logger.warning('could not keep the day\'s findings: %s', e)
