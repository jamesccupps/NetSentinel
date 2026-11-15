"""
Files something other than NetSentinel changed.
===============================================
~/.netsentinel is in the owner's profile and written by an elevated process;
on Windows chmod does nothing there, so any program running as the owner,
without rights, can edit what steers detection: config.json (turn the IDS
off, whitelist itself), known_good_hashes.json (process verification counts
a listed hash in a program's favour) and the confirmed false positives (each
silences a rule for its subject). Outside review, 2026-11-14, N5.

NetSentinel records each file's SHA-256 when it writes it, in the registry
under HKLM\\SOFTWARE\\NetSentinel\\FileDigests, which only administrators can
write. At load, a digest that differs means something else wrote the file:
it is logged, and the caller decides whether to trust it. config.json is
edited by hand on purpose, and verdicts can come from the command line, so
those are only logged; the known-good hashes are NetSentinel's alone and are
set aside. A file seen for the first time is adopted.

Off Windows, and under the tests (NETSENTINEL_TEST), the digests are kept in
memory.
"""

import hashlib
import logging
import os

logger = logging.getLogger("NetSentinel.OutsideEdits")

__all__ = ['record', 'changed_outside', 'file_digest']

KEY = r'SOFTWARE\NetSentinel\FileDigests'


class _MemoryStore:
    def __init__(self):
        self.values = {}

    def get(self, name):
        return self.values.get(name)

    def put(self, name, digest):
        self.values[name] = digest


class _RegistryStore:
    """HKLM\\SOFTWARE\\NetSentinel\\FileDigests. Writing needs Administrator; a
    copy of NetSentinel not running elevated reads, and its writes are skipped."""

    def __init__(self, winreg=None):
        if winreg is None:
            import winreg
        self.winreg = winreg

    def get(self, name):
        reg = self.winreg
        try:
            with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, KEY) as key:
                return str(reg.QueryValueEx(key, name)[0])
        except OSError:
            return None

    def put(self, name, digest):
        reg = self.winreg
        try:
            with reg.CreateKeyEx(reg.HKEY_LOCAL_MACHINE, KEY, 0, reg.KEY_SET_VALUE) as key:
                reg.SetValueEx(key, name, 0, reg.REG_SZ, digest)
        except OSError as e:
            logger.debug("Could not record %s's digest (not elevated?): %s", name, e)


_store = None


def _digests():
    global _store
    if _store is None:
        if os.name == 'nt' and not os.environ.get('NETSENTINEL_TEST'):
            try:
                _store = _RegistryStore()
            except ImportError:
                _store = _MemoryStore()
        else:
            _store = _MemoryStore()
    return _store


def _name(path):
    return os.path.basename(path).lower()


def file_digest(path):
    """The SHA-256 of the file, or None when there is none."""
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def record(path):
    """Note what NetSentinel just wrote to path."""
    digest = file_digest(path)
    if digest is not None:
        _digests().put(_name(path), digest)


def changed_outside(path, what='', adopt=True):
    """
    True if path differs from what NetSentinel last wrote there, with a warning
    in the log. adopt records the file as it is now, so the warning is given
    once per change. A file with no record yet is adopted silently.
    """
    current = file_digest(path)
    if current is None:
        return False
    stored = _digests().get(_name(path))
    if stored is None:
        _digests().put(_name(path), current)
        return False
    if stored == current:
        return False
    logger.warning("%s (%s) was changed by something other than NetSentinel since it last "
                   "wrote it. If that was not you, a program on this PC may be changing "
                   "what NetSentinel watches for.", os.path.basename(path), what or 'settings')
    if adopt:
        _digests().put(_name(path), current)
    return True
