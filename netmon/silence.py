"""
Acknowledge, snooze, maintenance.
=================================
The three ways a person tells the monitor "I know".

    python -m netmon ack         --rule bacnet_control --device ahu-controller-1 --key ...
    python -m netmon snooze      --device ahu-controller-1 --hours 4 --reason "commissioning"
    python -m netmon maintenance --device chiller-controller --reason "vendor on site"
    python -m netmon silence list

**ack** covers one finding: one rule, one device, one key. It stops that finding
pushing for 30 days by default. It stays in the digest, marked, and a different
finding from the same device still pushes.

**maintenance** covers a device or a rule. Nothing about it pushes, but
everything still goes in the digest, so the work leaves a record. It can be
open-ended, because nothing is hidden by it.

**snooze** covers a device or a rule and hides it completely, so it must end.
Snoozes are capped at 30 days. Anything longer is a decision about the site,
and it belongs in the profile with a note saying why, where the next person
will see it.

Two refusals are deliberate. Nothing silences everything: a monitor muted
wholesale has stopped without saying so. A silence file that cannot be read
applies no silences, which errs towards noise. The alternative is a corrupt
file silently swallowing a BACnet write.

The store is a small JSON file under the service's state directory. It is
written owner-only and atomically, and re-read whenever it changes, so a
silence added from the command line takes effect in a running service on its
next pass.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import time

logger = logging.getLogger("netmon.silence")

__all__ = ['Silences', 'SilenceError', 'KINDS']

KINDS = ('ack', 'snooze', 'maintenance')
#: When several apply, the one that hides most wins.
_PRECEDENCE = {'snooze': 0, 'maintenance': 1, 'ack': 2}
MAX_SNOOZE = 30 * 86400
DEFAULT_ACK = 30 * 86400


class SilenceError(ValueError):
    """A silence was refused. The message says why."""


def _norm(value):
    return str(value or '').strip().lower()


def _expired(entry, now):
    until = entry.get('until')
    return until is not None and float(until) <= now


def _identities(finding):
    """
    The names a device-scoped silence can match: the device the finding is
    about, and the source's name, address and MAC. bacnet_control names the
    controller that was written to, so maintenance on the controller covers
    it, and maintenance on the engineer's laptop covers it too.
    """
    names = {_norm(finding.device)}
    event = getattr(finding, 'event', None)
    if event is not None:
        names |= {_norm(event.src_ip), _norm(event.src_mac),
                  _norm(event.get('src_name'))}
    names.discard('')
    return names


def _applies(entry, finding):
    if entry['kind'] == 'ack':
        return (entry.get('rule') == finding.rule_id
                and _norm(entry.get('device')) == _norm(finding.device)
                and str(entry.get('key') or '') == str(finding.key or ''))
    if entry.get('rule') and entry['rule'] != finding.rule_id:
        return False
    if entry.get('device') and entry['device'] not in _identities(finding):
        return False
    return True


class Silences:
    """The persisted set of acks, snoozes and maintenance windows."""

    def __init__(self, path, clock=time.time):
        self.path = path
        self._clock = clock
        self._stamp = None
        self.entries = []
        self.refresh()

    def _stat(self):
        try:
            stat = os.stat(self.path)
        except OSError:
            return None
        return (stat.st_ino, stat.st_size, stat.st_mtime_ns)

    def refresh(self):
        """Re-read if the file changed, e.g. a CLI command while the service runs."""
        stamp = self._stat()
        if stamp is None:
            self.entries, self._stamp = [], None
            return
        if stamp == self._stamp:
            return
        try:
            with open(self.path, encoding='utf-8') as handle:
                data = json.load(handle)
            entries = data.get('entries', []) if isinstance(data, dict) else []
        except (OSError, json.JSONDecodeError) as e:
            logger.warning('could not read %s (%s); no silences apply until it '
                           'is fixed', self.path, e)
            entries = []
        self.entries = [e for e in entries
                        if isinstance(e, dict) and e.get('kind') in KINDS]
        self._stamp = stamp

    def _save(self):
        now = self._clock()
        self.entries = [e for e in self.entries if not _expired(e, now)]
        os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
        temporary = self.path + '.tmp'
        with open(temporary, 'w', encoding='utf-8') as handle:
            json.dump({'entries': self.entries}, handle, indent=1, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, self.path)
        self._stamp = self._stat()

    def add(self, kind, rule='', device='', key='', until=None, reason=''):
        if kind not in KINDS:
            raise SilenceError(f'kind must be one of {", ".join(KINDS)}')
        rule, device, key = str(rule or '').strip(), _norm(device), str(key or '').strip()
        now = self._clock()

        if kind == 'ack':
            if not rule or not device:
                raise SilenceError(
                    'an acknowledgement needs the finding\'s rule and device. It '
                    'covers that one finding, not a rule everywhere')
            if until is None:
                until = now + DEFAULT_ACK
        elif not rule and not device:
            raise SilenceError(
                f'refusing to {kind} everything. Name a rule, a device or both: '
                f'a monitor muted wholesale has stopped without saying so')
        if kind == 'snooze':
            if until is None:
                raise SilenceError('a snooze needs an end. Without one it is a '
                                   'mute, and mutes get forgotten')
            if until - now > MAX_SNOOZE:
                raise SilenceError(
                    'a snooze longer than 30 days is a mute. Put it in the profile '
                    '(known_dead_references or an allowlist) with a note saying why')
        if until is not None and until <= now:
            raise SilenceError('that time has already passed')

        self.refresh()
        entry = {'id': secrets.token_hex(4), 'kind': kind, 'rule': rule,
                 'device': device, 'key': key, 'until': until,
                 'reason': str(reason or '')[:200], 'created': now}
        self.entries.append(entry)
        self._save()
        return entry

    def remove(self, entry_id):
        self.refresh()
        before = len(self.entries)
        self.entries = [e for e in self.entries if e.get('id') != entry_id]
        if len(self.entries) == before:
            return False
        self._save()
        return True

    def active(self, now=None):
        self.refresh()
        now = self._clock() if now is None else now
        return [dict(e) for e in self.entries if not _expired(e, now)]

    def match(self, finding, now=None, entries=None):
        best = None
        for entry in (self.active(now) if entries is None else entries):
            if _applies(entry, finding) and (
                    best is None
                    or _PRECEDENCE[entry['kind']] < _PRECEDENCE[best['kind']]):
                best = entry
        return best

    def decide(self, finding, now=None, entries=None):
        """'push', 'digest' (ack or maintenance) or 'drop' (snooze)."""
        entry = self.match(finding, now, entries)
        if entry is None:
            return 'push'
        try:
            finding.silenced = {'kind': entry['kind'], 'id': entry['id'],
                                'reason': entry.get('reason', '')}
        except AttributeError:
            pass
        return 'drop' if entry['kind'] == 'snooze' else 'digest'

    def visible(self, findings, now=None):
        """
        Findings as they should be shown now: snoozed ones left out, acked and
        maintenance ones marked.

        Decided afresh on every call rather than once on arrival. A silence
        added after a finding was kept has to hide it from the UI and the
        digest too, and one cleared has to bring it back — so the mark left by
        an earlier decision is wiped before deciding again.
        """
        entries = self.active(now)
        shown = []
        for finding in findings:
            try:
                finding.silenced = None
            except AttributeError:
                pass
            if self.decide(finding, now, entries) != 'drop':
                shown.append(finding)
        return shown


def _main(argv=None):
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog='python -m netmon silence',
        description='Acknowledge a finding, snooze a device or rule, or mark '
                    'one as under maintenance.')
    sub = parser.add_subparsers(dest='action', required=True)

    def common(p):
        p.add_argument('--state', default=os.path.expanduser('~/.local/state/netmon'),
                       help='the service state directory (its --state)')

    p = sub.add_parser('ack', help='stop one finding pushing; it stays in the digest')
    common(p)
    p.add_argument('--rule', required=True)
    p.add_argument('--device', required=True)
    p.add_argument('--key', default='')
    p.add_argument('--days', type=float, default=30)
    p.add_argument('--reason', default='')

    for name, text in (('snooze', 'hide a device or rule entirely, for a while'),
                       ('maintenance', 'stop pushes for a device or rule; '
                                       'keep it in the digest')):
        p = sub.add_parser(name, help=text)
        common(p)
        p.add_argument('--rule', default='')
        p.add_argument('--device', default='')
        p.add_argument('--hours', type=float, required=(name == 'snooze'))
        p.add_argument('--reason', default='')

    p = sub.add_parser('list', help='what is in effect')
    common(p)
    p = sub.add_parser('clear', help='remove one by id')
    common(p)
    p.add_argument('id')

    args = parser.parse_args(argv)
    store = Silences(os.path.join(args.state, 'silences.json'))
    now = time.time()

    try:
        if args.action == 'list':
            entries = store.active()
            if not entries:
                print('Nothing is silenced.')
            for e in entries:
                until = ('until ' + time.strftime('%Y-%m-%d %H:%M', time.localtime(e['until']))
                         if e.get('until') else 'until cleared')
                scope = ' '.join(f'{k}={e[k]}' for k in ('rule', 'device', 'key') if e.get(k))
                print(f"{e['id']}  {e['kind']:11} {scope}  {until}"
                      + (f"  ({e['reason']})" if e.get('reason') else ''))
            return 0
        if args.action == 'clear':
            if store.remove(args.id):
                print(f'cleared {args.id}')
                return 0
            print(f'no silence {args.id}', file=sys.stderr)
            return 1
        if args.action == 'ack':
            entry = store.add('ack', args.rule, args.device, args.key,
                              now + args.days * 86400, args.reason)
        else:
            until = now + args.hours * 3600 if args.hours else None
            entry = store.add(args.action, args.rule, args.device, '', until,
                              args.reason)
    except SilenceError as e:
        print(str(e), file=sys.stderr)
        return 1

    print(f"{entry['kind']} {entry['id']} recorded")
    return 0


if __name__ == '__main__':
    import sys
    from netmon.silence import _main as main
    sys.exit(main())
