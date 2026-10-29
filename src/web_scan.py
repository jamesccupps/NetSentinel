"""
NetSentinel - Browser File Scans
Holds the files a browser uploads for scanning and runs src.batch_scan over
them in the background, one scan at a time.

Each scan gets a private temporary folder. Uploaded names are reduced to safe
path components before anything is written, so a name like ../../evil or
C:\\Windows lands inside that folder as evil. The folder is deleted when the
scan finishes; only the report, whose secrets are already masked, is kept.
"""

import os
import re
import secrets
import shutil
import tempfile
import threading
import time

from src import batch_scan

MAX_SESSIONS = 5
MAX_SESSION_BYTES = 8 * 1024 ** 3
MAX_SESSION_FILES = batch_scan.MAX_FILES
CHUNK = 1024 * 1024


class ScanError(Exception):
    """A request the scan cannot honour; status is the HTTP status to send."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def safe_relpath(name):
    """An uploaded name as path components that cannot leave the scan folder."""
    parts = []
    for part in re.split(r'[\\/]+', str(name or '')):
        part = re.sub(r'[\x00-\x1f<>:"|?*]', '_', part).strip().strip('.')
        if part:
            parts.append(part[:200])
    return os.path.join(*parts[-8:]) if parts else 'upload'


def _read_exact(stream, n):
    data = stream.read(n)
    if len(data) != n:
        raise ScanError('upload ended early')
    return data


class _Session:
    def __init__(self):
        self.id = secrets.token_hex(8)
        self.dir = tempfile.mkdtemp(prefix='netsentinel_upload_')
        self.files = 0
        self.bytes = 0
        self.state = 'uploading'
        self.progress = {'index': 0, 'total': 0, 'name': ''}
        self.report = None
        self.error = None
        self.cancel = False
        self.created = time.time()

    def view(self):
        return {'id': self.id, 'state': self.state, 'files': self.files,
                'bytes': self.bytes, 'progress': dict(self.progress),
                'error': self.error, 'report': self.report}

    def remove_files(self):
        shutil.rmtree(self.dir, ignore_errors=True)


class ScanSessions:
    """Upload-then-scan sessions for the web dashboard."""

    def __init__(self, analyzer_factory):
        self._analyzer_factory = analyzer_factory
        self._analyzer = None
        self._sessions = {}
        self._lock = threading.Lock()
        self._running = None

    def create(self):
        with self._lock:
            if len(self._sessions) >= MAX_SESSIONS:
                for old in sorted(self._sessions.values(), key=lambda s: s.created):
                    if old.state != 'running':
                        old.remove_files()
                        del self._sessions[old.id]
                        break
            session = _Session()
            self._sessions[session.id] = session
            return session.view()

    def _get(self, session_id):
        session = self._sessions.get(session_id or '')
        if session is None:
            raise ScanError('no such scan', 404)
        return session

    def get(self, session_id):
        return self._get(session_id).view()

    def add_file(self, session_id, name, stream, length):
        """Copy `length` bytes from `stream` into the scan's folder."""
        session = self._get(session_id)
        if session.state != 'uploading':
            raise ScanError('this scan has already started', 409)
        if session.files >= MAX_SESSION_FILES:
            raise ScanError(f'at most {MAX_SESSION_FILES} files per scan', 413)
        if length < 0 or session.bytes + length > MAX_SESSION_BYTES:
            raise ScanError(f'at most {MAX_SESSION_BYTES // 1024 ** 3} GB per scan', 413)

        rel = safe_relpath(name)
        target = os.path.join(session.dir, rel)
        root = os.path.realpath(session.dir)
        if os.path.commonpath([root, os.path.realpath(target)]) != root:
            raise ScanError('bad file name')
        os.makedirs(os.path.dirname(target), exist_ok=True)
        base, ext = os.path.splitext(target)
        n = 1
        while os.path.exists(target):
            target = f'{base} ({n}){ext}'
            n += 1

        remaining = length
        try:
            with open(target, 'wb') as out:
                while remaining > 0:
                    chunk = stream.read(min(CHUNK, remaining))
                    if not chunk:
                        raise ScanError('upload ended early')
                    out.write(chunk)
                    remaining -= len(chunk)
        except BaseException:
            if os.path.exists(target):
                os.remove(target)
            raise
        session.files += 1
        session.bytes += length
        return os.path.relpath(target, session.dir)

    def add_batch(self, session_id, stream, length):
        """
        Several files in one request, so a folder of 40,000 small files is a
        few dozen requests rather than 40,000. Each record is a big-endian u16
        name length, the UTF-8 name, a big-endian u32 size, then the bytes.
        """
        stored, remaining = 0, length
        while remaining > 0:
            if remaining < 6:
                raise ScanError('malformed batch')
            name_len = int.from_bytes(_read_exact(stream, 2), 'big')
            if not 0 < name_len <= 4096 or name_len + 4 > remaining - 2:
                raise ScanError('malformed batch')
            name = _read_exact(stream, name_len).decode('utf-8', 'replace')
            size = int.from_bytes(_read_exact(stream, 4), 'big')
            remaining -= 6 + name_len
            if size > remaining:
                raise ScanError('malformed batch')
            self.add_file(session_id, name, stream, size)
            remaining -= size
            stored += 1
        return stored

    def start(self, session_id):
        with self._lock:
            session = self._get(session_id)
            if session.state != 'uploading':
                raise ScanError('this scan has already started', 409)
            if self._running is not None:
                raise ScanError('another scan is running; wait for it to finish', 409)
            if session.files == 0:
                raise ScanError('no files were uploaded')
            session.state = 'running'
            self._running = session
        threading.Thread(target=self._run, args=(session,), daemon=True,
                         name='WebFileScan').start()
        return session.view()

    def cancel(self, session_id):
        session = self._get(session_id)
        session.cancel = True
        if session.state == 'uploading':
            session.state = 'cancelled'
            session.remove_files()
        return session.view()

    def _run(self, session):
        try:
            if self._analyzer is None:
                self._analyzer = self._analyzer_factory()
            entries = [os.path.join(session.dir, e) for e in sorted(os.listdir(session.dir))]

            def progress(index, total, name):
                session.progress = {'index': index, 'total': total, 'name': name}

            session.report = batch_scan.scan(entries, self._analyzer, on_progress=progress,
                                             cancelled=lambda: session.cancel)
            session.state = 'cancelled' if session.report.get('cancelled') else 'done'
        except Exception as e:
            session.state = 'error'
            session.error = str(e)
        finally:
            session.remove_files()
            with self._lock:
                self._running = None

    def close(self):
        for session in list(self._sessions.values()):
            session.cancel = True
            session.remove_files()
