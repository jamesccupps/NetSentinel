"""
Where the Windows programs NetSentinel runs really are.
=========================================================
NetSentinel runs as Administrator. Given a bare name such as 'ipconfig',
Windows looks first in the folder the running exe came from, then in the
current folder, and only then in System32. The exe usually sits in Downloads,
where any program running as the owner (or a browser download) can put an
ipconfig.exe, which the next start would then run as Administrator, without a
prompt.

So every program is started by absolute path, and the folders come from
Windows itself, not from %SystemRoot% or %ProgramFiles%: a program running as
the owner can set those variables, and the elevated process inherits them.
"""

import ctypes
import os

__all__ = ['system_directory', 'system_tool', 'program_files_dirs']

_MAX_PATH = 260
_CSIDL_PROGRAM_FILES = 0x26
_CSIDL_PROGRAM_FILESX86 = 0x2a


def _windll():
    return getattr(ctypes, 'windll', None) if os.name == 'nt' else None


def system_directory():
    """System32, as Windows reports it; None off Windows or on failure."""
    windll = _windll()
    if windll is None:
        return None
    buf = ctypes.create_unicode_buffer(_MAX_PATH)
    n = windll.kernel32.GetSystemDirectoryW(buf, len(buf))
    return buf.value if 0 < n < len(buf) else None


def system_tool(*parts):
    """The absolute path of a program under System32, or None off Windows."""
    root = system_directory()
    return os.path.join(root, *parts) if root else None


def program_files_dirs():
    """Program Files (and its x86 twin), as Windows reports them."""
    windll = _windll()
    if windll is None:
        return []
    found = []
    for csidl in (_CSIDL_PROGRAM_FILES, _CSIDL_PROGRAM_FILESX86):
        buf = ctypes.create_unicode_buffer(_MAX_PATH)
        if windll.shell32.SHGetFolderPathW(None, csidl, None, 0, buf) == 0 and buf.value:
            if buf.value not in found:
                found.append(buf.value)
    return found
