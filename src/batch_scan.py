"""
NetSentinel - Batch Scan
Scans everything in a folder, an archive, or a list of files and combines the
results into one report. Packet captures go through the PCAP analyzer; every
other file has its contents searched by src.file_scan. The report lists each
exposed credential or secret (masked), suspicious script patterns, every IP
address, domain, host name, UNC path, URL, email and MAC address found and
which files held it, and the SHA-256 of every file. It flags the public
indicators the threat feeds know and the hashes the local known-bad lists
hold; internal names are never looked up anywhere.

Archives are recognised by their first bytes, so .jar, .apk and renamed zips
open too: zip, tar (plain or compressed), gzip, bzip2, xz and 7z, nested ones
to a depth limit. Members are never extracted under their own names. Each
one is streamed, size-capped and hashed to a numbered file in a private
temporary directory, scanned, and deleted before the next, so a hostile
archive cannot write outside that directory. One budget caps what a
top-level archive may decompress in all, nested archives included, and an
archive that expands far beyond its own size is stopped as a likely bomb.
Links inside archives, password-protected members and RAR files are
reported, not opened.

Big scans give way to the rest of the machine: the scanning thread runs at
background I/O priority where the OS allows, and pauses between files.

Secret values in the report are masked; the raw values never enter it.
"""

import contextlib
import fnmatch
import hashlib
import ipaddress
import logging
import os
import re
import sys
import tempfile
import threading
import time
import zipfile

from src import archives, file_scan, hash_feed

logger = logging.getLogger(__name__)

CAPTURE_EXTS = ('.pcap', '.pcapng', '.cap')
MAX_FILES = 100_000
MAX_MEMBER_BYTES = 2 * 1024 ** 3   # per file taken out of an archive
MAX_ARCHIVE_DEPTH = 3              # an archive in an archive in an archive, and no deeper
MAX_ARCHIVE_BYTES = 8 * 1024 ** 3  # decompressed from one top-level archive, nested ones included
MAX_ARCHIVE_RATIO = 250            # decompressed bytes per byte of archive...
RATIO_FLOOR = 256 * 1024 ** 2      # ...once past this much, so small archives of zeros pass
MAX_REPORT_SECRETS = 20_000
MAX_REPORT_FINDINGS = 20_000
PAUSE_FRACTION = 0.05              # of each file's scan time, spent paused after it
CHUNK = 1024 * 1024
SKIP_DIRS = {'.git', '.svn', '.hg', 'node_modules', '__pycache__', '.venv', 'venv'}
INDICATOR_KINDS = file_scan.INDICATOR_KINDS
KNOWN_BAD_CONFIDENCE = ('HIGH', 'MEDIUM')
_ARCHIVE_EXTS = ('.zip', '.jar', '.war', '.ear', '.apk', '.aab', '.whl', '.nupkg', '.xpi', '.7z',
                 '.tar', '.tgz', '.tbz', '.tbz2', '.txz', '.gz', '.bz2', '.xz', '.lzma', '.rar')
_SEVERITY_ORDER = ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')


class ArchiveLimit(Exception):
    """An archive hit a decompression limit; the message says which."""


class _Cancelled(Exception):
    pass


class _StopArchive(Exception):
    pass


class _Budget:
    def __init__(self, limit):
        self.limit = limit
        self.used = 0


class _Container:
    """An archive being read, and what it has cost to decompress so far."""

    def __init__(self, name, size, budget, ratio, floor):
        self.name = name
        self.size = max(size, 1)
        self.budget = budget
        self.ratio = ratio
        self.floor = floor
        self.extracted = 0
        self.stopped = None
        self.entry = None

    def charge(self, n):
        self.extracted += n
        self.budget.used += n
        if self.budget.used > self.budget.limit:
            raise ArchiveLimit(f'the decompression budget of {_size(self.budget.limit)} '
                               'for one archive is used up')
        if self.extracted > max(self.floor, self.ratio * self.size):
            raise ArchiveLimit(f'expands more than {self.ratio}:1, which looks like a '
                               'decompression bomb')


def _size(n):
    return f'{n / 1024 ** 3:g} GB' if n >= 1024 ** 3 else f'{n / 1024 ** 2:g} MB'


def _safe_ext(name):
    # The extension says how to read the member (a capture, a document); it is
    # filtered so a hostile name cannot smuggle a path into the temp file name.
    base = re.split(r'[\\/]', name)[-1]
    ext = os.path.splitext(base)[1].lower()
    return ext if re.fullmatch(r'\.[a-z0-9]{1,10}', ext) else ''


class _MemberFile:
    """
    Writes one archive member to its numbered temp file: capped, hashed as it
    goes, and charged to its archive's budget. With overflow='discard' a
    member over the cap is noted instead of raising, for 7z, where raising
    would end the whole archive.
    """

    def __init__(self, path, max_bytes, container, overflow='raise'):
        self.path = path
        self.max_bytes = max_bytes
        self.container = container
        self.overflow = overflow
        self.written = 0
        self.sha256 = None
        self.error = None
        self._hash = hashlib.sha256()
        self._f = open(path, 'wb')

    def write(self, data):
        self.written += len(data)
        if self.container is not None:
            self.container.charge(len(data))
        if self.written > self.max_bytes:
            self.error = f'larger than {self.max_bytes:,} bytes uncompressed'
            if self.overflow == 'raise':
                raise ValueError(self.error)
            return
        self._hash.update(data)
        self._f.write(data)

    def close(self):
        if not self._f.closed:
            self._f.close()
            self.sha256 = None if self.error else self._hash.hexdigest()

    def abort(self):
        if not self._f.closed:
            self._f.close()
        if os.path.exists(self.path):
            os.remove(self.path)


class _Item:
    """One thing to scan: a file on disk, or a member of an archive."""

    def __init__(self, name, path=None, archive=None, member=None, opener=None,
                 extracted=None, sha256=None, container=None, depth=0):
        self.name = name
        self.path = path
        self.archive = archive        # a zip listed by collect(): its path...
        self.member = member          # ...and this member's ZipInfo
        self.opener = opener          # or a callable giving the member's stream
        self.extracted = extracted    # or a temp file already written (7z)
        self.sha256 = sha256
        self.container = container
        self.depth = depth if member is None else max(depth, 1)
        source = member.filename if member is not None else (path or name)
        self.is_capture = os.path.splitext(source)[1].lower() in CAPTURE_EXTS

    @property
    def is_member(self):
        return not self.path

    def materialise(self, workdir, index, max_bytes):
        """Return a path to scan, extracting an archive member if need be."""
        if self.path:
            return self.path
        if self.extracted:
            return self.extracted
        source = self.member.filename if self.member is not None else self.name
        target = os.path.join(workdir, f'{index:05d}{_safe_ext(source)}')
        out = _MemberFile(target, max_bytes, self.container)
        try:
            with contextlib.ExitStack() as stack:
                if self.member is not None:
                    zf = stack.enter_context(zipfile.ZipFile(self.archive))
                    src = stack.enter_context(zf.open(self.member))
                else:
                    src = stack.enter_context(contextlib.closing(self.opener()))
                for chunk in iter(lambda: src.read(CHUNK), b''):
                    out.write(chunk)
            out.close()
        except BaseException:
            out.abort()
            raise
        self.sha256 = out.sha256
        return target


def _printable(name):
    return ''.join(c if c.isprintable() else '?' for c in name)


def _skipped(name, patterns):
    base = os.path.basename(name.replace('\\', '/')).lower()
    return any(fnmatch.fnmatch(base, p.lower()) for p in patterns)


def _from_zip(path, label, skip, found, skipped):
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as e:
        skipped.append({'file': label, 'reason': f'unreadable zip ({e})'})
        return
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = f'{label}/{_printable(info.filename)}'
            ext = os.path.splitext(info.filename)[1].lower()
            if ext in file_scan.MEDIA_EXTS:
                skipped.append({'file': name, 'reason': 'media file'})
            elif _skipped(info.filename, skip):
                skipped.append({'file': name, 'reason': 'excluded by --skip'})
            elif info.flag_bits & 0x1:
                skipped.append({'file': name, 'reason': 'password-protected'})
            elif archives._zip_link(info):
                skipped.append({'file': name, 'reason': 'symlink not followed'})
            else:
                item = _Item(name, archive=path, member=info)
                item.archive_label = label
                found.append(item)


def _add_file(path, label, skip, found, skipped):
    ext = os.path.splitext(path)[1].lower()
    if _skipped(path, skip):
        skipped.append({'file': label, 'reason': 'excluded by --skip'})
    elif ext == '.zip':
        _from_zip(path, label, skip, found, skipped)
    elif ext in file_scan.MEDIA_EXTS:
        skipped.append({'file': label, 'reason': 'media file'})
    else:
        found.append(_Item(label, path=path))


def collect(paths, skip=(), max_files=MAX_FILES):
    """
    Expand files, folders and zips into the items to scan.

    Returns (items, skipped). Folders are walked without following symlinks,
    and version-control and dependency folders are left out. Other archives,
    and archives inside these, are opened as the scan reaches them.
    """
    found, skipped = [], []
    for path in paths:
        if os.path.isdir(path):
            root_label = os.path.basename(os.path.normpath(path)) or path
            for root, dirs, files in os.walk(path, followlinks=False):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for fname in sorted(files):
                    full = os.path.join(root, fname)
                    label = os.path.join(root_label, os.path.relpath(full, path))
                    if os.path.islink(full):
                        skipped.append({'file': label, 'reason': 'symlink not followed'})
                        continue
                    _add_file(full, label, skip, found, skipped)
        elif os.path.isfile(path):
            _add_file(path, os.path.basename(path), skip, found, skipped)
        else:
            skipped.append({'file': path, 'reason': 'not found'})
    if len(found) > max_files:
        for item in found[max_files:]:
            skipped.append({'file': item.name, 'reason': f'over the {max_files}-file limit'})
        found = found[:max_files]
    return found, skipped


class _Indicators:
    """Indicators across every file, with the files each was found in."""

    def __init__(self):
        self.kinds = {k: {} for k in INDICATOR_KINDS}

    def add(self, kind, value, source, count=1, **info):
        entry = self.kinds[kind].get(value)
        if entry is None:
            entry = self.kinds[kind][value] = dict(info, value=value, count=0, files=[])
        entry['count'] += count
        if source not in entry['files'] and len(entry['files']) < 50:
            entry['files'].append(source)

    def add_ip(self, ip, source, count=1):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        kind = 'ipv4' if addr.version == 4 else 'ipv6'
        self.add(kind, addr.compressed, source, count, scope=file_scan.ip_scope(addr))

    def as_lists(self):
        return {k: sorted(v.values(), key=lambda e: (-e['count'], e['value']))
                for k, v in self.kinds.items()}


def _alert(rule_id, severity, title, description, category, evidence):
    from src.ids_engine import Alert
    return Alert(rule_id=rule_id, severity=severity, title=title, description=description,
                 category=category, evidence=evidence)


# ─── Being a good neighbour ────────────────────────────────────────────

class _Throttle:
    """Pause after each file for a fraction of the time it took, so a big
    scan leaves the GIL and the disk to the GUI, the dashboard and capture."""

    def __init__(self, fraction):
        try:
            self.fraction = min(max(float(fraction), 0.0), 0.5)
        except (TypeError, ValueError):
            self.fraction = PAUSE_FRACTION
        self._since = time.monotonic()

    def pause(self):
        busy = time.monotonic() - self._since
        time.sleep(min(0.1, busy * self.fraction))
        self._since = time.monotonic()


@contextlib.contextmanager
def low_priority(enabled=True):
    """
    Run the calling thread at background priority while the block runs.

    Windows: the thread's background mode, which lowers its I/O and CPU
    priority; psutil can only change the whole process there, which would
    slow capture and the GUI too. Linux: psutil's ionice on this thread
    (the idle I/O class). Elsewhere: nothing.
    """
    restore = None
    if enabled:
        try:
            restore = _lower_this_thread()
        except Exception as e:
            logger.debug("Batch scan: could not lower I/O priority: %s", e)
    try:
        yield
    finally:
        if restore is not None:
            try:
                restore()
            except Exception as e:
                logger.debug("Batch scan: could not restore I/O priority: %s", e)


def _lower_this_thread():
    if sys.platform == 'win32':
        import ctypes
        kernel32 = ctypes.windll.kernel32
        thread = kernel32.GetCurrentThread()
        if not kernel32.SetThreadPriority(thread, 0x00010000):     # THREAD_MODE_BACKGROUND_BEGIN
            return None
        return lambda: kernel32.SetThreadPriority(thread, 0x00020000)   # ..._END
    if sys.platform.startswith('linux'):
        import psutil
        proc = psutil.Process(threading.get_native_id())   # a thread id names one thread
        old = proc.ionice()
        proc.ionice(psutil.IOPRIO_CLASS_IDLE)
        return lambda: proc.ionice(old.ioclass, old.value)
    return None


# ─── The scan ───────────────────────────────────────────────────────────

_HASH_LISTS = {}


def _hash_lists(folder):
    folder = folder or hash_feed.default_folder()
    lists = _HASH_LISTS.get(folder)
    if lists is None:
        lists = _HASH_LISTS[folder] = hash_feed.HashLists(folder)
    return lists


def _default_ignore():
    try:
        from src.scan_ignore import IgnoreList
        return IgnoreList()
    except Exception as e:
        logger.warning("Batch scan: ignore list unavailable: %s", e)
        return None


def scan(paths, analyzer, skip=(), on_alert=None, on_progress=None, cancelled=None,
         max_files=MAX_FILES, max_member_bytes=MAX_MEMBER_BYTES, threat_intel=None,
         config=None, ignore=None, hash_lists=None):
    """
    Scan everything under `paths`. Captures go to `analyzer` (a PcapAnalyzer).

    on_alert(alert) is called for each alert, tagged with the file it came
    from; on_progress(index, total, name) before each file; cancelled() is
    checked between files. threat_intel and config default to the
    analyzer's, ignore to the install's ignore list (src.scan_ignore), and
    hash_lists to the local known-bad hash lists (src.hash_feed). Leaves
    analyzer.alerts holding every alert and analyzer.stats the summary and
    indicators, so the analyzer's own export covers the whole scan.
    """
    if threat_intel is None:
        threat_intel = getattr(analyzer, 'threat_intel', None)
    if config is None:
        config = getattr(analyzer, 'config', None)
    if ignore is None:
        ignore = _default_ignore()
    settings = _settings(config)
    if hash_lists is None:
        hash_lists = _hash_lists(settings['hash_lists_dir'])
    items, skipped = collect(paths, skip, max_files)
    report = {'files': [], 'skipped': skipped, 'alerts': [], 'credentials': [],
              'secrets': [], 'findings': [], 'cancelled': False}
    run = _Run(analyzer, report, file_scan.ScanOptions.from_config(config, ignore), settings,
               on_alert, on_progress, cancelled, max_files, max_member_bytes)

    with low_priority(settings['low_priority']), \
            tempfile.TemporaryDirectory(prefix='netsentinel_scan_',
                                        ignore_cleanup_errors=True) as workdir:
        run.workdir = workdir
        run.scan_all(items)
    for entry in report['files']:
        if entry['type'] == 'archive':
            # the desktop and browser file tables read these from every entry
            # that is not a capture
            entry.setdefault('indicators', 0)
            entry.setdefault('secrets', 0)
            members = entry.get('members', 0)
            entry.setdefault('note', f"{entry.get('archive', '')} archive, {members} "
                                     f"member{'' if members == 1 else 's'}")

    found = run.indicators.as_lists()
    threats, suspicious = _check_threats(found, threat_intel)
    for hit in threats:
        run.emit(_alert('FILESCAN-THREAT-INTEL', 'HIGH',
                        f"Known-bad {hit['kind']} found: {hit['value']}",
                        f"{hit['value']} is listed by {hit.get('feed') or 'a threat feed'}.",
                        'Threat Intelligence',
                        {'indicator': hit['value'], 'kind': hit['kind'],
                         'feed': hit.get('feed', ''), 'category': hit.get('category', ''),
                         'confidence': hit.get('confidence', ''), 'files': hit['files']}))
    for hit in suspicious:
        run.emit(_alert('FILESCAN-SUSPICIOUS-INDICATOR', 'LOW',
                        f"Suspicious {hit['kind']} found: {hit['value']}",
                        f"{hit['value']} is not on a threat feed, but matches a weak pattern: "
                        f"{hit.get('description') or hit.get('category') or 'suspicious'}.",
                        'Threat Intelligence',
                        {'indicator': hit['value'], 'kind': hit['kind'],
                         'category': hit.get('category', ''), 'confidence': hit.get('confidence', ''),
                         'files': hit['files']}))
    malware = run.check_hashes(hash_lists)

    report['credentials'] = list(run.creds.values())
    report['indicators'] = found
    report['threats'] = threats
    report['suspicious'] = suspicious
    report['malware'] = malware
    entries = report['files']
    report['summary'] = dict({
        'items': len(items) + run.discovered,
        'captures': sum(1 for f in entries if f['type'] == 'capture'),
        'files': sum(1 for f in entries if f['type'] == 'file'),
        'archives': sum(1 for f in entries if f['type'] == 'archive'),
        'scanned': sum(1 for f in entries if f['type'] != 'archive' and 'error' not in f),
        'failed': sum(1 for f in entries if 'error' in f),
        'skipped': len(skipped),
        'alerts': len(report['alerts']),
        'credentials': len(report['credentials']),
        'secrets': run.secret_total,
        'findings': run.finding_total,
        'ignored': run.ignored,
        'threats': len(threats),
        'suspicious': len(suspicious),
        'malware': len(malware),
    }, **{k: len(v) for k, v in found.items()})
    analyzer.alerts = run.alert_objects
    analyzer.stats = dict(report['summary'], file='batch scan', indicators=found)
    return report


class _NoConfig:
    def get(self, *keys, default=None):
        return default


def _settings(config):
    config = config if config is not None else _NoConfig()
    return {
        'archive_max_depth': int(config.get('file_scan', 'archive_max_depth', default=MAX_ARCHIVE_DEPTH)),
        'archive_max_bytes': int(config.get('file_scan', 'archive_max_bytes', default=MAX_ARCHIVE_BYTES)),
        'archive_max_ratio': int(config.get('file_scan', 'archive_max_ratio', default=MAX_ARCHIVE_RATIO)),
        'low_priority': bool(config.get('file_scan', 'low_priority', default=True)),
        'pause_fraction': config.get('file_scan', 'pause_fraction', default=PAUSE_FRACTION),
        'hash_lists_dir': config.get('file_scan', 'hash_lists_dir', default='') or '',
        'internal_domains': tuple(config.get('file_scan', 'internal_domains', default=[]) or ()),
    }


class _Run:
    """The state of one batch scan."""

    def __init__(self, analyzer, report, options, settings, on_alert, on_progress, cancelled,
                 max_files, max_member_bytes):
        self.analyzer = analyzer
        self.report = report
        self.options = options
        self.settings = settings
        self.on_alert = on_alert
        self.on_progress = on_progress
        self.cancelled = cancelled
        self.max_files = max_files
        self.max_member_bytes = max_member_bytes
        self.workdir = None
        self.alert_objects = []
        self.creds = {}
        self.indicators = _Indicators()
        self.throttle = _Throttle(settings['pause_fraction'])
        self.discovered = 0
        self.secret_total = 0
        self.finding_total = 0
        self.ignored = 0
        self._index = 0
        self._position = (0, 0)
        self._zips = {}

    # ── plumbing ──

    def emit(self, alert, key=None, name=None):
        if key and isinstance(getattr(alert, 'evidence', None), dict):
            alert.evidence[key] = name
        self.alert_objects.append(alert)
        self.report['alerts'].append(alert.to_dict())
        if self.on_alert:
            self.on_alert(alert)

    def _next_index(self):
        self._index += 1
        return self._index - 1

    def _skip(self, name, reason, **extra):
        self.report['skipped'].append(dict({'file': name, 'reason': reason}, **extra))

    def _check_cancel(self):
        if self.cancelled and self.cancelled():
            raise _Cancelled()

    def scan_all(self, items):
        try:
            for index, item in enumerate(items):
                self._check_cancel()
                self._position = (index, len(items))
                if self.on_progress:
                    self.on_progress(index, len(items), item.name)
                self.scan_item(item)
        except _Cancelled:
            self.report['cancelled'] = True

    # ── one item ──

    def _zip_container(self, item):
        container = self._zips.get(item.archive)
        if container is None:
            label = getattr(item, 'archive_label', os.path.basename(item.archive))
            entry = {'file': label, 'type': 'archive', 'archive': archives.ZIP, 'members': 0}
            try:
                entry['sha256'] = hash_feed.sha256_file(item.archive)
                size = os.path.getsize(item.archive)
            except OSError as e:
                entry['error'] = str(e)
                size = 0
            container = self._new_container(label, size, None)
            container.entry = entry
            self.report['files'].append(entry)
            self._zips[item.archive] = container
        container.entry['members'] += 1
        return container

    def _new_container(self, name, size, parent):
        budget = parent.budget if parent is not None else _Budget(self.settings['archive_max_bytes'])
        return _Container(name, size, budget, self.settings['archive_max_ratio'], RATIO_FLOOR)

    def scan_item(self, item):
        if item.member is not None and item.container is None:
            item.container = self._zip_container(item)
        if item.container is not None and item.container.stopped:
            self._skip(item.name, f'not opened: {item.container.stopped}')
            return
        entry = {'file': item.name, 'type': 'capture' if item.is_capture else 'file'}
        path = None
        record = True
        try:
            path = item.materialise(self.workdir, self._next_index(), self.max_member_bytes)
            if item.sha256:
                entry['sha256'] = item.sha256
            kind = None if item.name.lower().endswith(file_scan.OFFICE_EXTS) else archives.detect(path)
            if kind == archives.RAR:
                record = False
                self._skip(item.name, archives.RAR_REASON,
                           sha256=entry.get('sha256') or hash_feed.sha256_file(path))
            elif kind is not None and item.depth >= self.settings['archive_max_depth']:
                record = False
                self._skip(item.name, f"archive nested more than {self.settings['archive_max_depth']} "
                                      'deep; not opened',
                           sha256=entry.get('sha256') or hash_feed.sha256_file(path))
            else:
                if kind is not None:
                    # listed ahead of its members, and taken back out if it
                    # turns out not to be an archive after all
                    self.report['files'].append(entry)
                    record = False
                    if not self._open_archive(item, path, kind, entry):
                        self.report['files'].remove(entry)
                        record = True
                        kind = None
                if kind is None and item.is_capture:
                    self._scan_capture(item, path, entry)
                elif kind is None:
                    self._scan_file(item, path, entry)
        except (_Cancelled, _StopArchive):
            record = False
            raise
        except ArchiveLimit as e:
            entry['error'] = str(e)
            if item.container is not None:
                item.container.stopped = str(e)
        except Exception as e:
            logger.warning("Batch scan: %s failed: %s", item.name, e)
            self.analyzer.is_analyzing = False   # a raise leaves it set
            entry['error'] = str(e)
        finally:
            if path and item.is_member and os.path.exists(path):
                os.remove(path)
            if record:
                self.report['files'].append(entry)
            self.throttle.pause()

    def _open_archive(self, item, path, kind, entry):
        """Scan an archive's members. False if it turns out not to be one."""
        entry.update(type='archive', archive=kind, members=0)
        if 'sha256' not in entry:
            entry['sha256'] = hash_feed.sha256_file(path)
        container = self._new_container(item.name, os.path.getsize(path), item.container)
        container.entry = entry
        depth = item.depth + 1

        def visit(member):
            self._check_cancel()
            name = f'{item.name}/{_printable(member.name)}'
            entry['members'] += 1
            writer = member.writer
            reason = None
            if os.path.splitext(member.name)[1].lower() in file_scan.MEDIA_EXTS:
                reason = 'media file'
            elif self.discovered >= self.max_files:
                reason = f'over the {self.max_files}-file limit'
            if reason:
                if writer is not None:
                    writer.abort()
                self._skip(name, reason)
                return
            self.discovered += 1
            if self.on_progress:
                self.on_progress(self._position[0], self._position[1], name)
            if writer is not None and writer.error:
                writer.abort()
                self.report['files'].append({'file': name, 'type': 'file', 'error': writer.error})
            else:
                child = _Item(name, opener=member.open if writer is None else None,
                              extracted=writer.path if writer is not None else None,
                              sha256=writer.sha256 if writer is not None else None,
                              container=container, depth=depth)
                self.scan_item(child)
            if container.stopped:
                raise _StopArchive()

        def skip(member_name, reason):
            self._skip(f'{item.name}/{_printable(member_name)}', reason)

        def make_writer(member_name):
            target = os.path.join(self.workdir, f'{self._next_index():05d}{_safe_ext(member_name)}')
            return _MemberFile(target, self.max_member_bytes, container, overflow='discard')

        try:
            archives.walk(path, kind, item.name, visit, skip, make_writer)
        except _StopArchive:
            self._skip(item.name, f'rest not opened: {container.stopped}')
        except ArchiveLimit as e:
            container.stopped = str(e)
            self._skip(item.name, f'rest not opened: {e}')
        except archives.ArchiveError as e:
            if entry['members'] == 0 and not item.name.lower().endswith(_ARCHIVE_EXTS):
                # starts like an archive but is not one: read it as a file
                entry.update(type='capture' if item.is_capture else 'file')
                for key in ('archive', 'members'):
                    entry.pop(key, None)
                return False
            entry['error'] = str(e)
        return True

    def _scan_capture(self, item, path, entry):
        analyzer = self.analyzer
        if 'sha256' not in entry:
            entry['sha256'] = hash_feed.sha256_file(path)
        result = analyzer.analyze_file(path)
        alerts = list(getattr(analyzer, 'alerts', []) or [])
        found = 0
        for obj in alerts:
            self.emit(obj, 'capture', item.name)
            if obj.rule_id != 'FORENSICS-CREDENTIAL':
                continue
            found += 1
            ev = obj.evidence
            # 'connection' since the capture's alert became the live one's.
            source = ev.get('connection') or ev.get('source', '')
            key = (ev.get('protocol'), ev.get('credential_type'), ev.get('value'), source)
            cred = self.creds.setdefault(key, {
                'protocol': ev.get('protocol', ''),
                'credential_type': ev.get('credential_type', ''),
                'value': ev.get('value', ''),
                'source': source,
                'captures': [],
            })
            if item.name not in cred['captures']:
                cred['captures'].append(item.name)
        stats = result.get('stats', {})
        for key in ('top_talkers', 'top_destinations'):
            for ip, _bytes in stats.get(key) or []:
                self.indicators.add_ip(ip, item.name)
        internal = self.settings['internal_domains']
        for name, count in stats.get('top_dns_queries') or []:
            name = str(name or '').lower().rstrip('.')
            if not name:
                continue
            if '.' in name:
                self.indicators.add('domain', name, item.name, count,
                                    scope=file_scan.domain_scope(name, internal))
            else:
                self.indicators.add('host', name, item.name, count, scope='internal')
        entry.update(packets=stats.get('packets_analyzed', 0), alerts=len(alerts),
                     credentials=found)

    def _scan_file(self, item, path, entry):
        data, sha = _read_for_scan(path, file_scan.MAX_TEXT_BYTES, item.sha256)
        entry['sha256'] = sha
        result = file_scan.scan_bytes(item.name, data, self.options)
        for kind, values in result['indicators'].items():
            for value, info in values.items():
                info = dict(info)
                count = info.pop('count', 1)
                self.indicators.add(kind, value, item.name, count, **info)
        self.ignored += result['ignored']
        secrets = sum(result['secret_counts'].values())
        findings = sum(result['finding_counts'].values())
        self.secret_total += secrets
        self.finding_total += findings
        for secret in result['secrets']:
            if len(self.report['secrets']) < MAX_REPORT_SECRETS:
                self.report['secrets'].append(dict(secret, file=item.name))
        for finding in result['findings']:
            if len(self.report['findings']) < MAX_REPORT_FINDINGS:
                self.report['findings'].append(dict(finding, file=item.name))
        self._grouped_alerts(item, result['secrets'], result['secret_counts'], secret=True)
        self._grouped_alerts(item, result['findings'], result['finding_counts'], secret=False)
        entry.update(secrets=secrets, findings=findings,
                     indicators=sum(len(v) for v in result['indicators'].values()))
        notes = list(result['notes'])
        if result['truncated']:
            notes.insert(0, f'only the first {file_scan.MAX_TEXT_BYTES // 1024 ** 2} MB searched')
        if notes:
            entry['note'] = '; '.join(notes)

    def _grouped_alerts(self, item, listed, counts, secret):
        """One alert per kind per file, however many of that kind it holds."""
        by_kind = {}
        for f in listed:
            by_kind.setdefault(f['kind'], []).append(f)
        base = os.path.basename(item.name.replace('\\', '/'))
        for kind, group in by_kind.items():
            total = max(counts.get(kind, 0), len(group))
            first = group[0]
            severity = max((f['severity'] for f in group), key=_severity_rank)
            lines = sorted({f['line'] for f in group})
            where = _lines_text(lines, total)
            title = f"{first['label']} in {base}" + (f' ({total} found)' if total > 1 else '')
            evidence = {'kind': kind, 'value': first['value'], 'line': first['line'],
                        'count': total, 'lines': lines[:20],
                        'values': [f['value'] for f in group[:10]]}
            if secret:
                self.emit(_alert('FILESCAN-SECRET', severity, title,
                                 f"{first['label']} found {where} of {item.name}. "
                                 "If it is real, treat it as exposed: rotate or revoke it.",
                                 'Secret Exposure', evidence), 'file', item.name)
            else:
                rule = 'FILESCAN-YARA' if kind == 'yara' else 'FILESCAN-SCRIPT'
                self.emit(_alert(rule, severity, title,
                                 f"{first['label']} ({first['value']}) found {where} of {item.name}.",
                                 'Suspicious Script', evidence), 'file', item.name)

    def check_hashes(self, hash_lists):
        """Alerts and hits for every file whose SHA-256 a local known-bad list holds."""
        try:
            if not hash_lists.load():
                return []
        except Exception as e:
            logger.warning("Batch scan: hash lists unreadable: %s", e)
            return []
        hits = []
        for entry in self.report['files'] + self.report['skipped']:
            info = hash_lists.lookup(entry.get('sha256'))
            if not info:
                continue
            entry['known_bad'] = info
            hit = dict(info, file=entry['file'], sha256=entry['sha256'])
            hits.append(hit)
            self.emit(_alert('FILESCAN-KNOWN-BAD-HASH', 'CRITICAL',
                             f"Known-bad file: {os.path.basename(entry['file'].replace(chr(92), '/'))}",
                             f"{entry['file']} has SHA-256 {entry['sha256']}, which the list "
                             f"{info['feed']} holds as known-bad.",
                             'Malware', {'sha256': entry['sha256'], 'feed': info['feed']}),
                      'file', entry['file'])
        return hits


def _severity_rank(severity):
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def _lines_text(lines, total):
    if len(lines) == 1 and total == 1:
        return f'on line {lines[0]}'
    shown = ', '.join(str(n) for n in lines[:5])
    more = total - min(len(lines), 5)
    return f"on lines {shown}{f' and {more} more' if more > 0 else ''}"


def _read_for_scan(path, limit, known_sha=None):
    """
    The first `limit` + 1 bytes of a file, and its SHA-256: the whole file
    is read for the hash, in chunks, but only the head is kept.
    """
    h = None if known_sha else hashlib.sha256()
    head = bytearray()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            if h is not None:
                h.update(chunk)
            if len(head) <= limit:
                head += chunk[:limit + 1 - len(head)]
            elif h is None:
                break
    return bytes(head), known_sha or h.hexdigest()


def _check_threats(found, threat_intel):
    """
    Look up public addresses and domains in the threat feeds.

    Returns (known_bad, suspicious). Only a feed listing (HIGH) or a listed
    parent domain (MEDIUM) makes something known-bad; the feeds' weak signals
    (a dynamic-DNS service, a high-abuse TLD) are reported as suspicious.
    Internal and reserved names are never looked up.
    """
    if threat_intel is None:
        return [], []
    bad, suspicious = [], []
    for kind, check in (('ipv4', 'check_ip'), ('ipv6', 'check_ip'), ('domain', 'check_domain')):
        lookup = getattr(threat_intel, check, None)
        if lookup is None:
            continue
        for entry in found[kind]:
            scope = entry.get('scope')
            if scope is None and kind == 'domain':
                scope = file_scan.domain_scope(entry['value'])
            if (scope or 'public') != 'public':
                continue
            try:
                info = lookup(entry['value'])
            except Exception:
                continue
            if not info:
                continue
            hit = dict(info, kind=kind, value=entry['value'], files=entry['files'])
            if str(info.get('confidence', 'HIGH')).upper() in KNOWN_BAD_CONFIDENCE:
                entry['threat'] = info
                bad.append(hit)
            else:
                entry['suspicious'] = info
                suspicious.append(hit)
    return bad, suspicious


def main(argv=None):
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog='python -m src.batch_scan',
        description='Scan files, folders and archives for leaked secrets, suspicious '
                    'scripts and network indicators; packet captures get the full PCAP '
                    'analysis.')
    parser.add_argument('paths', nargs='+', help='files, folders or archives')
    parser.add_argument('--skip', action='append', default=[], metavar='GLOB',
                        help="leave out files whose name matches, e.g. 'flash*'")
    parser.add_argument('--json', action='store_true', help='print the report as JSON')
    args = parser.parse_args(argv)

    from src.config import Config
    from src.pcap_analyzer import PcapAnalyzer
    report = scan(args.paths, PcapAnalyzer(Config().load()), skip=args.skip)

    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0
    s = report['summary']
    print(f"{s['scanned']} of {s['items']} files scanned ({s['captures']} captures), "
          f"{s['credentials'] + s['secrets']} exposed secrets, {s['alerts']} alerts")
    for hit in report['malware']:
        print(f"  KNOWN-BAD FILE: {hit['file']}  sha256 {hit['sha256']}  ({hit['feed']})")
    for cred in report['credentials']:
        print(f"  {cred['protocol']} {cred['credential_type']} {cred['value']}  "
              f"{cred['source']}  in {', '.join(cred['captures'])}")
    for sec in report['secrets']:
        print(f"  {sec['label']}: {sec['value']}  {sec['file']}:{sec['line']}")
    for f in report['findings']:
        print(f"  {f['label']}: {f['value']}  {f['file']}:{f['line']}")
    for t in report['threats']:
        print(f"  known-bad {t['kind']}: {t['value']}  ({t.get('feed', '')})")
    for t in report['suspicious']:
        print(f"  suspicious {t['kind']}: {t['value']}  ({t.get('category', '')})")
    for kind in INDICATOR_KINDS:
        values = report['indicators'][kind]
        if values:
            shown = ', '.join(v['value'] for v in values[:10])
            more = f' and {len(values) - 10} more' if len(values) > 10 else ''
            print(f"  {kind}: {shown}{more}")
    for f in report['files']:
        if 'error' in f:
            print(f"  failed: {f['file']}: {f['error']}")
    for f in report['skipped']:
        print(f"  skipped: {f['file']} ({f['reason']})")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
