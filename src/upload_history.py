"""
What each program has uploaded where, by day.
==============================================
The large-upload rule (DATA-EXFIL) counted bytes per destination address,
alerted at 100 MB and doubled after each alert, and forgot a destination as
soon as it went quiet for a few minutes. Every day started again at 100 MB: a
week of Tailscale to one peer, Chrome Remote Desktop and Claude was 13 HIGH
alerts for three routine pairs, rated more suspicious as the bytes grew.

Now each program and destination keeps how much went there each day, for 30
days. A program's first large upload to a destination in that time is still
reported, at the configured floor (ids.large_upload_mb). After that a day is
reported only once it passes four times the biggest day the pair has had,
and again at four times that. A destination is known by its address and by
its owner (the registrable domain a DNS answer gave it, or its network when
GeoIP is on), so a service spread over many addresses keeps one history.

A program is its process name, which malware can borrow; the alert's check
looks at the program's signature for that. A pair someone marked as real
exfiltration is held: it is reported from the floor again and learns nothing.
"""

import logging
import threading
import time
from datetime import datetime

logger = logging.getLogger("NetSentinel.UploadHistory")

MB = 1024 * 1024
KEEP_DAYS = 30
GROWTH = 4              # how far past its biggest day a known pair may go unreported
MAX_PAIRS = 5000        # program-and-destination histories kept
MAX_TODAY = 20000       # program-and-address counters for the current day
SAVE_EVERY = 300
STATE_FILE = 'upload_history.json'


def day_of(ts):
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d')


def program_of(name):
    """The history's name for a program: its process name, lower case, or 'unknown'."""
    return (name or '').strip().lower() or 'unknown'


class UploadHistory:
    """
    Per program and destination, MB uploaded per day (see the module notes).
    Memory only until attach() gives it a file; the IDS engine's tests build
    many engines, and one engine's history must not set another's levels.
    """

    def __init__(self, floor_mb=100):
        self.floor = float(floor_mb)
        self.path = None
        self._lock = threading.Lock()
        self._pairs = {}        # 'program|key' -> {'days': {day: mb}, 'held': bool}
        self._today = {}        # (program, dst_ip) -> today's counter, see add()
        self._dirty = False
        self._last_save = time.time()

    # ─── Counting ───────────────────────────────────────────────────────────

    def add(self, process, dst_ip, nbytes, now, owner_keys=None):
        """
        Count nbytes that process sent to dst_ip at time now. None, or once
        today's total for the pair passes the level it is reported at, what the
        alert needs: 'mb' today, the 'level' passed, 'next_mb', and the pair's
        history ('history_days', 'usual_max_mb', 'held'). owner_keys is called
        once per pair and day, for the destination's other names.
        """
        program = program_of(process)
        day = day_of(now)
        with self._lock:
            counter = self._today.get((program, dst_ip))
            if counter is None or counter['day'] != day:
                if counter is not None:
                    self._record(program, counter)
                counter = self._start(program, dst_ip, day, now, owner_keys)
            counter['bytes'] += nbytes
            mb = counter['bytes'] / MB
            if mb <= counter['next']:
                return None
            level = counter['next']
            while counter['next'] < mb:         # one alert, however far a burst went
                counter['next'] *= GROWTH
            self._record(program, counter)
            history = counter['history']
            return {'mb': mb, 'level': level, 'next_mb': counter['next'],
                    'history_days': history['days'], 'usual_max_mb': history['max_mb'],
                    'held': history['held']}

    def _start(self, program, dst_ip, day, now, owner_keys):
        keys = [f'ip:{dst_ip}']
        if owner_keys is not None:
            try:
                keys += [k for k in owner_keys() if k and k not in keys]
            except Exception as e:
                logger.debug("Owner of %s: %s", dst_ip, e)
        history = self._history(program, keys, day, now)
        level = self.floor
        if history['days'] and not history['held']:
            level = max(self.floor, GROWTH * history['max_mb'])
        counter = {'day': day, 'bytes': 0.0, 'next': level, 'keys': keys, 'history': history}
        if len(self._today) >= MAX_TODAY:
            self._roll(day, everything=True)
        self._today[(program, dst_ip)] = counter
        return counter

    def _history(self, program, keys, day, now):
        """The pair's days before today within KEEP_DAYS, over all its keys."""
        since = day_of(now - KEEP_DAYS * 86400)
        days, biggest, held = set(), 0.0, False
        for key in keys:
            entry = self._pairs.get(f'{program}|{key}')
            if entry is None:
                continue
            held = held or entry.get('held', False)
            for d, mb in entry['days'].items():
                if since <= d < day:
                    days.add(d)
                    biggest = max(biggest, mb)
        return {'days': len(days), 'max_mb': round(biggest, 1), 'held': held}

    def _record(self, program, counter):
        """
        Today's total into the pair's history, under each of its keys. Two
        addresses of one owner each record their own total under the owner's
        key, the larger standing: an owner's day is under-counted, never over,
        so its level errs low and reports more, not less.
        """
        mb = round(counter['bytes'] / MB, 2)
        if mb <= 0:
            return
        for key in counter['keys']:
            entry = self._pairs.setdefault(f'{program}|{key}', {'days': {}, 'held': False})
            if mb > entry['days'].get(counter['day'], 0):
                entry['days'][counter['day']] = mb
                self._dirty = True

    def _roll(self, day, everything=False):
        """Close counters from before day (all of them with everything) into history."""
        for key in [k for k, c in self._today.items() if everything or c['day'] != day]:
            self._record(key[0], self._today.pop(key))

    # ─── Upkeep ─────────────────────────────────────────────────────────────

    def flush(self, now):
        """Record today's totals, close yesterday's counters, drop days past KEEP_DAYS."""
        day, since = day_of(now), day_of(now - KEEP_DAYS * 86400)
        with self._lock:
            self._roll(day)
            for (program, _dst), counter in self._today.items():
                self._record(program, counter)
            for name in list(self._pairs):
                entry = self._pairs[name]
                entry['days'] = {d: mb for d, mb in entry['days'].items() if d >= since}
                if not entry['days'] and not entry.get('held'):
                    del self._pairs[name]
                    self._dirty = True
            if len(self._pairs) > MAX_PAIRS:
                by_last = sorted(self._pairs, key=lambda n: max(self._pairs[n]['days'] or ['']))
                for name in by_last[:len(self._pairs) - MAX_PAIRS]:
                    del self._pairs[name]
                self._dirty = True

    def hold(self, process, dst_ip, owner_keys=()):
        """
        A person said this pair's upload was real: report it from the floor
        again, and learn nothing more from it.
        """
        program = program_of(process)
        with self._lock:
            for key in [f'ip:{dst_ip}', *[k for k in owner_keys if k]]:
                entry = self._pairs.setdefault(f'{program}|{key}', {'days': {}, 'held': False})
                entry['held'] = True
            counter = self._today.get((program, dst_ip))
            if counter is not None:
                counter['history']['held'] = True
                counter['next'] = self.floor
                while counter['next'] < counter['bytes'] / MB:
                    counter['next'] *= GROWTH
            self._dirty = True

    def today_mb(self, process, dst_ip):
        counter = self._today.get((program_of(process), dst_ip))
        return round(counter['bytes'] / MB, 3) if counter else 0.0

    def next_level(self, process, dst_ip):
        counter = self._today.get((program_of(process), dst_ip))
        return counter['next'] if counter else None

    # ─── Storage ────────────────────────────────────────────────────────────

    def attach(self, path):
        """Keep the history in path from now on, starting from what is there."""
        self.path = path
        try:
            import json
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
        except FileNotFoundError:
            return
        except Exception as e:
            logger.warning("Upload history %s unreadable, starting fresh: %s", path, e)
            return
        pairs = data.get('pairs') if isinstance(data, dict) else None
        if not isinstance(pairs, dict):
            return
        loaded = {}
        for name, entry in pairs.items():
            if not (isinstance(name, str) and isinstance(entry, dict)
                    and isinstance(entry.get('days'), dict)):
                continue
            days = {d: float(mb) for d, mb in entry['days'].items()
                    if isinstance(d, str) and len(d) == 10 and isinstance(mb, (int, float))}
            loaded[name] = {'days': days, 'held': bool(entry.get('held'))}
        with self._lock:
            loaded.update(self._pairs)          # this run's counts win
            self._pairs = loaded

    def save(self, force=False):
        if not self.path:
            return
        now = time.time()
        if not force and (not self._dirty or now - self._last_save < SAVE_EVERY):
            return
        with self._lock:
            snapshot = {'version': 1,
                        'pairs': {n: {'days': dict(e['days']), 'held': e.get('held', False)}
                                  for n, e in self._pairs.items()}}
            self._dirty = False
            self._last_save = now
        try:
            from src.config import atomic_write_json
            atomic_write_json(self.path, snapshot, indent=0)
        except Exception as e:
            logger.debug("Upload history save failed: %s", e)
