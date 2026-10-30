"""
NetSentinel - Known-Bad File Hashes
File scans take the SHA-256 of every file and archive member, streamed, and
look it up here: in lists of known-bad hashes kept on this machine. Nothing is
looked up online, and no hash or file name ever leaves the machine.

MalwareBazaar was meant to be the source. abuse.ch now asks for a (free)
Auth-Key even for its bulk exports, and the old keyless export URLs answer
410 Gone, so NetSentinel does not download it. A list fetched by hand (for
example MalwareBazaar's full SHA-256 export, with your own Auth-Key) works
when dropped into the lists folder, ~/.netsentinel/data/hash_lists/ by
default: any text or CSV file whose lines hold 64-hex-digit SHA-256 values.
"""

import hashlib
import logging
import os
import re
import threading

logger = logging.getLogger(__name__)

CHUNK = 1024 * 1024
MAX_LIST_BYTES = 512 * 1024 * 1024      # per list file
_SHA256 = re.compile(rb'(?<![0-9A-Fa-f])([0-9A-Fa-f]{64})(?![0-9A-Fa-f])')
_LIST_EXTS = ('.txt', '.csv', '.tsv', '.sha256', '.lst')


def sha256_file(path):
    """The SHA-256 of a file, read in chunks so its size does not matter."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(CHUNK), b''):
            h.update(chunk)
    return h.hexdigest()


def default_folder():
    from src.config import DB_DIR
    return os.path.join(DB_DIR, 'hash_lists')


class _SortedDigests:
    """Raw 32-byte digests, sorted, in one bytes object: a million hashes in
    32 MB rather than the ~150 MB a set of hex strings would take."""

    def __init__(self, digests):
        self.blob = b''.join(sorted(set(digests)))
        self.count = len(self.blob) // 32

    def __contains__(self, digest):
        lo, hi = 0, self.count
        blob = self.blob
        while lo < hi:
            mid = (lo + hi) // 2
            probe = blob[mid * 32:mid * 32 + 32]
            if probe < digest:
                lo = mid + 1
            elif probe > digest:
                hi = mid
            else:
                return True
        return False


class HashLists:
    """Known-bad SHA-256 lists read from a local folder."""

    def __init__(self, folder=None):
        self.folder = folder or default_folder()
        self._lists = []          # [(name, _SortedDigests)]
        self._signature = None
        self._lock = threading.Lock()

    def _current_signature(self):
        try:
            names = sorted(n for n in os.listdir(self.folder) if n.lower().endswith(_LIST_EXTS))
        except OSError:
            return ()
        sig = []
        for n in names:
            try:
                st = os.stat(os.path.join(self.folder, n))
            except OSError:
                continue
            sig.append((n, st.st_size, st.st_mtime_ns))
        return tuple(sig)

    def load(self):
        """(Re)read the lists if the folder changed. Returns the hash count."""
        with self._lock:
            sig = self._current_signature()
            if sig == self._signature:
                return self.count
            lists = []
            for name, size, _ in sig:
                if size > MAX_LIST_BYTES:
                    logger.warning("Hash list %s is over %d MB; not loaded", name,
                                   MAX_LIST_BYTES // 1024 ** 2)
                    continue
                try:
                    digests = self._read(os.path.join(self.folder, name))
                except OSError as e:
                    logger.warning("Hash list %s unreadable: %s", name, e)
                    continue
                if digests.count:
                    lists.append((name, digests))
            self._lists = lists
            self._signature = sig
            return self.count

    @staticmethod
    def _read(path):
        digests = []
        with open(path, 'rb') as f:
            for line in f:
                if line.startswith((b'#', b';')):
                    continue
                m = _SHA256.search(line)
                if m:
                    digests.append(bytes.fromhex(m.group(1).decode('ascii')))
        return _SortedDigests(digests)

    @property
    def count(self):
        return sum(d.count for _, d in self._lists)

    def lookup(self, sha256_hex):
        """{'feed': list file, 'category': ...} if the hash is listed, else None."""
        if not self._lists or not sha256_hex:
            return None
        try:
            digest = bytes.fromhex(sha256_hex)
        except ValueError:
            return None
        for name, digests in self._lists:
            if digest in digests:
                return {'feed': name, 'category': 'Known-bad file hash', 'confidence': 'HIGH'}
        return None
