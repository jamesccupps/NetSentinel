"""
NetSentinel - File Scan Ignore List
Known false positives a file scan should stop reporting.

A secret's raw value never leaves src.file_scan, so it cannot be stored here
either. Instead each finding carries an `ignore_key`: an HMAC-SHA256 of its
kind and raw value under a random key made once per install and kept in
~/.netsentinel/data/scan_ignore.key. The list stores that HMAC. Without the
key the HMAC cannot be tested against guesses, so a short password stays
unguessable even if the list or a report is copied elsewhere.

Card numbers and Social Security numbers are never hashed, even keyed: they
can only be ignored by file and line.

Indicators (domains, addresses, URLs) are not secret, so they can be ignored
by value; the list still stores only their HMAC, and shows the value itself.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import stat
import threading
import time

from src.file_scan import INDICATOR_KINDS, LOCATION_ONLY

logger = logging.getLogger(__name__)

MAX_ENTRIES = 10_000
_KEY_BYTES = 32


def _norm_file(name):
    return str(name or '').replace('\\', '/')


class IgnoreList:
    """The per-install ignore list. Safe to share between threads."""

    def __init__(self, path=None, key_path=None):
        if path is None or key_path is None:
            from src.config import DB_DIR
            path = path or os.path.join(DB_DIR, 'scan_ignore.json')
            key_path = key_path or os.path.join(DB_DIR, 'scan_ignore.key')
        self.path = path
        self.key_path = key_path
        self._key = None
        self._lock = threading.RLock()
        self._entries = []
        self._values = set()       # (kind, hmac)
        self._locations = set()    # (kind, file, line)
        self.reload()

    # ─── Storage ────────────────────────────────────────────────────────

    def reload(self):
        with self._lock:
            entries = []
            try:
                with open(self.path, encoding='utf-8') as f:
                    data = json.load(f)
                entries = [e for e in data.get('entries', []) if isinstance(e, dict)]
            except FileNotFoundError:
                pass
            except (OSError, ValueError, AttributeError) as e:
                logger.warning("Scan ignore list unreadable (%s); starting empty", e)
            self._entries = entries[:MAX_ENTRIES]
            self._rebuild()

    def _rebuild(self):
        self._values = {(e.get('kind'), e.get('digest')) for e in self._entries
                        if e.get('type') == 'value'}
        self._locations = {(e.get('kind'), _norm_file(e.get('file')), e.get('line'))
                           for e in self._entries if e.get('type') == 'location'}

    def _save(self):
        from src.config import atomic_write_json
        atomic_write_json(self.path, {'version': 1, 'entries': self._entries}, indent=1)

    def _load_key(self):
        if self._key is not None:
            return self._key
        with self._lock:
            if self._key is not None:
                return self._key
            try:
                with open(self.key_path, 'rb') as f:
                    key = f.read()
                if len(key) == _KEY_BYTES:
                    self._key = key
                    return key
                logger.warning("Scan ignore key has the wrong length; making a new one")
            except FileNotFoundError:
                pass
            key = secrets.token_bytes(_KEY_BYTES)
            os.makedirs(os.path.dirname(self.key_path) or '.', exist_ok=True)
            tmp = f'{self.key_path}.{os.getpid()}.tmp'
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_BINARY', 0),
                         stat.S_IRUSR | stat.S_IWUSR)
            try:
                os.write(fd, key)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, self.key_path)
            self._key = key
            return key

    # ─── Matching (called by the scanner) ───────────────────────────────

    def digest(self, kind, value):
        """The keyed hash a finding of this kind and raw value is ignored by."""
        data = f'{kind}\x00{value}'.encode('utf-8', 'surrogatepass')
        return hmac.new(self._load_key(), data, hashlib.sha256).hexdigest()

    @property
    def has_values(self):
        return bool(self._values)

    @property
    def has_locations(self):
        return bool(self._locations)

    def ignores_digest(self, kind, digest):
        return (kind, digest) in self._values

    def ignores_value(self, kind, value):
        return bool(self._values) and (kind, self.digest(kind, value)) in self._values

    def ignores_location(self, kind, file, line):
        return bool(self._locations) and (kind, _norm_file(file), line) in self._locations

    # ─── Editing (called by the UI) ─────────────────────────────────────

    def add_finding(self, finding, note=''):
        """
        Ignore a finding from a scan report: a secret or script finding (with
        its 'kind', 'ignore_key', 'file' and 'line') or an indicator ('kind'
        and 'value'). Cards and SSNs, and anything without an ignore_key, are
        ignored by file and line. Returns the new entry as entries() shows it.
        """
        kind = str(finding.get('kind') or '')
        key = finding.get('ignore_key')
        if kind not in LOCATION_ONLY and isinstance(key, str) and _is_hex64(key):
            return self._add({'type': 'value', 'kind': kind, 'digest': key.lower(),
                              'shown': str(finding.get('value', ''))[:200],
                              'label': str(finding.get('label', ''))[:200]}, note)
        if finding.get('file') and isinstance(finding.get('line'), int):
            return self.add_location(kind, finding['file'], finding['line'], note,
                                     shown=finding.get('value', ''),
                                     label=finding.get('label', ''))
        if kind in LOCATION_ONLY:
            raise ValueError(f'{kind} findings can only be ignored by file and line')
        if 'value' in finding and kind in INDICATOR_KINDS:
            # a secret's value here is already masked, so it could never match
            return self.add_value(kind, finding['value'], note)
        raise ValueError('nothing in this finding to ignore it by')

    def add_value(self, kind, value, note=''):
        """Ignore an indicator value (a domain, address, URL...) wherever it appears."""
        kind = str(kind)
        if kind in LOCATION_ONLY:
            raise ValueError(f'{kind} findings can only be ignored by file and line')
        if kind not in INDICATOR_KINDS:
            raise ValueError(f'{kind} is not an indicator; ignore it by its ignore_key')
        return self._add({'type': 'value', 'kind': kind, 'digest': self.digest(kind, str(value)),
                          'shown': str(value)[:200]}, note)

    def add_location(self, kind, file, line, note='', shown='', label=''):
        """Ignore whatever of this kind is found on this line of this file."""
        return self._add({'type': 'location', 'kind': str(kind), 'file': _norm_file(file)[:4096],
                          'line': int(line), 'shown': str(shown)[:200],
                          'label': str(label)[:200]}, note)

    def _add(self, entry, note):
        with self._lock:
            for existing in self._entries:
                if all(existing.get(k) == entry.get(k)
                       for k in ('type', 'kind', 'digest', 'file', 'line')):
                    return _public(existing)
            if len(self._entries) >= MAX_ENTRIES:
                raise ValueError(f'the ignore list is full ({MAX_ENTRIES} entries)')
            entry.update(id=secrets.token_hex(6), note=str(note or '')[:500],
                         added=int(time.time()))
            self._entries.append(entry)
            self._rebuild()
            self._save()
            return _public(entry)

    def entries(self):
        """Every entry, newest first, without the stored hashes."""
        with self._lock:
            return [_public(e) for e in reversed(self._entries)]

    def remove(self, entry_id):
        """Drop an entry by id. Returns whether one was removed."""
        with self._lock:
            kept = [e for e in self._entries if e.get('id') != entry_id]
            if len(kept) == len(self._entries):
                return False
            self._entries = kept
            self._rebuild()
            self._save()
            return True


def _is_hex64(s):
    return len(s) == 64 and all(c in '0123456789abcdefABCDEF' for c in s)


def _public(entry):
    return {k: v for k, v in entry.items() if k != 'digest'}
