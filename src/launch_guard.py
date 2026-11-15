"""
Starting an exe from this elevated process, without a swap in between.
======================================================================
NetSentinel runs as Administrator and starts NetSentinel exes by path: the
Restart button and the tray's Restart start this exe again, the updater
starts the checked download, and the new exe, finishing an update, starts the
copy it put in place. The exe ships bare and often lives in a folder the
owner's ordinary programs can write (Downloads, Scoop's folder under the
profile). A program running as the owner, not elevated, that renamed the
file and put another in its place between the check and the start, or any
time before a restart, was started as Administrator with no UAC prompt
(outside review, 2026-11-14, N2). CLAUDE.md: never trust a file a program
running as the owner could write.

So a file to be started is held: opened with read sharing only, which on
Windows refuses anyone a write, a rename or a delete while the handle is
open. Its SHA-256 is read through that handle, compared with what it must be,
and the program is started while it is still held. This exe holds itself for
as long as it runs (hold_own_exe), so a restart starts the same bytes.

Off Windows nothing is held (there is no exe to guard there) and the checks
still run.
"""

import hashlib
import logging
import os
import subprocess
import sys
from contextlib import contextmanager

logger = logging.getLogger("NetSentinel.LaunchGuard")

__all__ = ['LaunchRefused', 'held', 'sha256_of', 'start_held', 'hold_own_exe', 'own_exe_hold']

_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80


class LaunchRefused(Exception):
    """The file to start is not the one that was checked."""


def _open_held(path):
    """A binary file object for path that, on Windows, nobody can write, rename
    or delete while it is open."""
    if os.name != 'nt':
        return open(path, 'rb')
    import ctypes
    import msvcrt
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel32.CreateFileW
    create.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    create.restype = wintypes.HANDLE
    handle = create(os.path.abspath(path), _GENERIC_READ, _FILE_SHARE_READ, None,
                    _OPEN_EXISTING, _FILE_ATTRIBUTE_NORMAL, None)
    if handle in (None, wintypes.HANDLE(-1).value):
        error = ctypes.get_last_error()
        raise OSError(error, ctypes.FormatError(error).strip(), path)
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
    except OSError:
        kernel32.CloseHandle(handle)
        raise
    return os.fdopen(fd, 'rb')


@contextmanager
def held(path):
    """Hold path (see the module notes) for the length of the block."""
    f = _open_held(path)
    try:
        yield f
    finally:
        f.close()


def sha256_of(f):
    """The SHA-256 of an open binary file, read from its start."""
    f.seek(0)
    digest = hashlib.sha256()
    for chunk in iter(lambda: f.read(1024 * 1024), b''):
        digest.update(chunk)
    return digest.hexdigest()


def start_held(command, sha256=None, held_file=None, popen=None, **kwargs):
    """
    Start command[0] only if, held, its SHA-256 is sha256 (when given), and
    while it is still held. held_file is a handle already holding it (this
    exe's own, or a download kept held since it was checked).
    """
    path = command[0]
    popen = popen or subprocess.Popen

    def go(f):
        if sha256 is not None and sha256_of(f).lower() != sha256.lower():
            raise LaunchRefused(f"{os.path.basename(path)} changed after it was checked; "
                                f"not starting it.")
        return popen(command, **kwargs)

    if held_file is not None:
        return go(held_file)
    with held(path) as f:
        return go(f)


_own = {'file': None, 'path': ''}


def hold_own_exe(executable=None):
    """
    Hold this exe for as long as this process runs, so nothing can put
    another file in its place for a restart to start. Only for the frozen exe;
    a Python install is not this program's to hold. Returns the handle or None.
    """
    if not getattr(sys, 'frozen', False) and executable is None:
        return None
    path = os.path.abspath(executable or sys.executable)
    if _own['file'] is not None and _own['path'] == path:
        return _own['file']
    try:
        _own['file'] = _open_held(path)
        _own['path'] = path
    except OSError as e:
        logger.warning("Could not hold %s against replacement: %s", path, e)
        return None
    return _own['file']


def own_exe_hold(path):
    """This process's hold on path, if it holds it (hold_own_exe), else None."""
    if _own['file'] is not None and os.path.normcase(_own['path']) == \
            os.path.normcase(os.path.abspath(path)):
        return _own['file']
    return None


def release_own_exe():
    """Let go of this exe (tests, and a process about to be replaced)."""
    if _own['file'] is not None:
        try:
            _own['file'].close()
        finally:
            _own['file'], _own['path'] = None, ''
