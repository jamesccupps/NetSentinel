"""
NetSentinel - Archive Reading
Recognises archives by their first bytes rather than their names, so a .jar,
an .apk or a renamed zip opens like any other, and walks their members for
src.batch_scan: zip, tar (plain, gzip, bzip2 or xz), single gzip/bzip2/xz
files, and 7z through py7zr when it is installed.

Nothing here writes a member to disk under its own name or extracts with the
library's own extract-to-folder calls. Each member is handed to the caller as
a stream (or, for 7z, written through a writer the caller supplies), so the
caller decides where the bytes go and how many it will take. Links and special
files are reported, never followed.

RAR is recognised and reported as not opened: reading it needs the non-free
UnRAR library.
"""

import bz2
import gzip
import lzma
import os
import stat
import tarfile
import zipfile
import zlib

ZIP, TAR, GZIP, BZIP2, XZ, SEVENZIP, RAR = 'zip', 'tar', 'gzip', 'bzip2', 'xz', '7z', 'rar'
RAR_REASON = 'RAR archive not opened (reading RAR needs the non-free UnRAR library)'

_TAR_MODES = {GZIP: ('r:gz', 'r|gz'), BZIP2: ('r:bz2', 'r|bz2'), XZ: ('r:xz', 'r|xz')}
_OPENERS = {GZIP: gzip.open, BZIP2: bz2.open, XZ: lzma.open}
_SUFFIXES = {GZIP: ('.gz', '.gzip', '.z'), BZIP2: ('.bz2', '.bzip2'), XZ: ('.xz', '.lzma')}
_READ_ERRORS = (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError, lzma.LZMAError,
                zlib.error, ValueError)


class ArchiveError(Exception):
    """An archive that cannot be opened; the message is the reason to report."""


class Member:
    """One regular file inside an archive."""

    __slots__ = ('name', 'size', 'compressed', '_open', 'writer')

    def __init__(self, name, opener=None, size=None, compressed=None, writer=None):
        self.name = name
        self.size = size
        self.compressed = compressed
        self._open = opener
        self.writer = writer      # 7z only: the caller's writer, already filled

    def open(self):
        return self._open()


def detect(path, name=''):
    """The archive kind of the file at `path`, judged by its first bytes, or None."""
    try:
        with open(path, 'rb') as f:
            head = f.read(512)
    except OSError:
        return None
    return detect_bytes(head)


def detect_bytes(head):
    if head[:4] in (b'PK\x03\x04', b'PK\x05\x06'):
        return ZIP
    if head[:6] == b'7z\xbc\xaf\x27\x1c':
        return SEVENZIP
    if head[:6] == b'Rar!\x1a\x07':
        return RAR
    if head[:2] == b'\x1f\x8b':
        return GZIP
    if head[:3] == b'BZh' and head[3:4].isdigit() and head[4:10] == b'1AY&SY':
        return BZIP2
    if head[:6] == b'\xfd7zXZ\x00':
        return XZ
    if head[257:262] == b'ustar':
        return TAR
    return None


def walk(path, kind, name, visit, skip, make_writer=None):
    """
    Call visit(member) for each regular file in the archive, in archive order,
    and skip(member_name, reason) for each entry left out. A member's stream
    is only valid during its visit, because tar and 7z are read front to back.

    For 7z, make_writer(member_name) must return an object with write(bytes)
    and close(); the member arrives at visit() with that writer already
    filled. Raises ArchiveError when the archive itself cannot be read.
    """
    if kind == RAR:
        raise ArchiveError(RAR_REASON)
    try:
        if kind == ZIP:
            _walk_zip(path, visit, skip)
        elif kind == TAR:
            _walk_tar(path, 'r|', visit, skip)
        elif kind in _TAR_MODES:
            if _holds_tar(path, kind):
                _walk_tar(path, _TAR_MODES[kind][1], visit, skip)
            else:
                visit(Member(_inner_name(name, kind), opener=lambda: _OPENERS[kind](path, 'rb'),
                             compressed=os.path.getsize(path)))
        elif kind == SEVENZIP:
            _walk_7z(path, visit, skip, make_writer)
        else:
            raise ArchiveError(f'not an archive ({kind})')
    except ArchiveError:
        raise
    except (zipfile.BadZipFile, tarfile.TarError) as e:
        raise ArchiveError(f'unreadable {kind} archive ({e})') from e


def _inner_name(name, kind):
    base = os.path.basename(name.replace('\\', '/'))
    lower = base.lower()
    for suffix in _SUFFIXES[kind]:
        if lower.endswith(suffix) and len(base) > len(suffix):
            return base[:-len(suffix)]
    return base + '.decompressed'


def _holds_tar(path, kind):
    # tarfile reads and checks only the first header block here, so this costs
    # one small decompression, not the whole file.
    try:
        with tarfile.open(path, _TAR_MODES[kind][0]) as tf:
            return tf.firstmember is not None
    except _READ_ERRORS:
        return False


def _zip_link(info):
    return info.create_system == 3 and stat.S_ISLNK(info.external_attr >> 16)


def _walk_zip(path, visit, skip):
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                skip(info.filename, 'password-protected')
            elif _zip_link(info):
                skip(info.filename, 'symlink not followed')
            else:
                visit(Member(info.filename, opener=lambda i=info: zf.open(i),
                             size=info.file_size, compressed=info.compress_size))


def _walk_tar(path, mode, visit, skip):
    # Stream mode ('r|'): members are read in order without seeking, which is
    # the only cheap way through a compressed tar.
    with tarfile.open(path, mode) as tf:
        for ti in tf:
            if ti.isdir():
                continue
            if ti.issym() or ti.islnk():
                skip(ti.name, 'link not followed')
            elif not ti.isfile():
                skip(ti.name, 'special file')
            else:
                visit(Member(ti.name, opener=lambda t=ti: tf.extractfile(t), size=ti.size))
            # stream mode keeps every header it has read; nothing needs them
            tf.members = []


def _walk_7z(path, visit, skip, make_writer):
    try:
        import py7zr
        import py7zr.io
    except ImportError as e:
        raise ArchiveError('7z archive not opened (py7zr is not installed)') from e
    if make_writer is None:
        raise ArchiveError('7z needs a writer')

    class _Writer(py7zr.io.Py7zIO):
        """Adapts the caller's writer to the interface py7zr writes through."""

        def __init__(self, name):
            self.name = name
            self.inner = make_writer(name)
            self.done = False

        def write(self, s):
            self.inner.write(bytes(s))
            return len(s)

        def read(self, size=None):
            return b''

        def seek(self, offset, whence=0):
            return 0

        def seekable(self):
            return False

        def flush(self):
            pass

        def size(self):
            return getattr(self.inner, 'written', 0)

        def close(self):
            finish(self)

    pending = []

    def finish(writer):
        # py7zr 1.x calls close() when a member is complete; older versions may
        # not, so the next create() and the end of extraction finish it too.
        if writer.done:
            return
        writer.done = True
        writer.inner.close()
        visit(Member(writer.name, writer=writer.inner, size=writer.size()))

    class _Factory(py7zr.io.WriterFactory):
        def create(self, filename):
            for w in pending:
                finish(w)
            pending.clear()
            w = _Writer(filename)
            pending.append(w)
            return w

    try:
        # A file object rather than a path keeps py7zr to one thread, so
        # members arrive one at a time and in order.
        with open(path, 'rb') as fp, py7zr.SevenZipFile(fp) as z:
            if z.needs_password():
                raise ArchiveError('password-protected 7z archive not opened')
            targets = []
            for f in z.files:
                if f.is_directory:
                    continue
                if f.is_symlink or f.is_junction:
                    skip(f.filename, 'link not followed')
                elif f.is_socket:
                    skip(f.filename, 'special file')
                elif not _safe_7z_name(f.filename):
                    skip(f.filename, 'unsafe member name')
                else:
                    targets.append(f.filename)
            if targets:
                z.extract(targets=targets, factory=_Factory())
            for w in pending:
                finish(w)
    except ArchiveError:
        raise
    except py7zr.exceptions.PasswordRequired as e:
        raise ArchiveError('password-protected 7z archive not opened') from e
    except (py7zr.exceptions.ArchiveError, py7zr.exceptions.UnsupportedCompressionMethodError,
            lzma.LZMAError, EOFError) as e:
        # ArchiveError is py7zr's base for bad, damaged and CRC-failing archives
        raise ArchiveError(f'unreadable 7z archive ({e})') from e
    finally:
        for w in pending:
            if not w.done:
                abort = getattr(w.inner, 'abort', None)
                if abort:
                    abort()


def _safe_7z_name(name):
    # py7zr refuses to extract anything when one member's name climbs out of
    # the target folder, so such members are left out up front instead.
    try:
        from py7zr.helpers import get_sanitized_output_path
        get_sanitized_output_path(name, None)
        return True
    except ImportError:
        return True
    except Exception:
        return False
