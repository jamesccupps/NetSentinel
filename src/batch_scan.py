"""
NetSentinel - Batch Capture Scan
Runs every capture in a folder, a zip, or a list of files through the PCAP
analyzer and combines the results into one report: what leaked, where, and
which captures it was in.

Zip members are never extracted under their own names. Each one is streamed,
size-capped, to a numbered file in a private temporary directory, analysed,
and deleted before the next, so a hostile archive cannot write outside that
directory and only one capture is on disk at a time. Nested archives and
password-protected members are skipped and reported, not opened.

Credential values in the report are the masked forms the forensics engine
produces for display; the raw values never enter it.
"""

import fnmatch
import logging
import os
import tempfile
import zipfile

logger = logging.getLogger(__name__)

CAPTURE_EXTS = ('.pcap', '.pcapng', '.cap')
MAX_FILES = 1000
MAX_MEMBER_BYTES = 2 * 1024 ** 3   # per capture taken out of a zip


class _Capture:
    """One capture to analyse: a file on disk, or a member of a zip."""

    def __init__(self, name, path=None, archive=None, member=None):
        self.name = name
        self.path = path
        self.archive = archive
        self.member = member

    def materialise(self, workdir, index, max_bytes):
        """Return a path to analyse, extracting a zip member if need be."""
        if self.path:
            return self.path
        ext = os.path.splitext(self.member.filename)[1].lower()
        target = os.path.join(workdir, f'{index:05d}{ext}')
        written = 0
        try:
            with zipfile.ZipFile(self.archive) as zf, zf.open(self.member) as src, \
                    open(target, 'wb') as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_bytes:
                        raise ValueError(f'larger than {max_bytes:,} bytes uncompressed')
                    dst.write(chunk)
        except BaseException:
            if os.path.exists(target):
                os.remove(target)
            raise
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
            if ext == '.zip':
                skipped.append({'file': name, 'reason': 'nested archive'})
            elif ext not in CAPTURE_EXTS:
                continue
            elif _skipped(info.filename, skip):
                skipped.append({'file': name, 'reason': 'excluded by --skip'})
            elif info.flag_bits & 0x1:
                skipped.append({'file': name, 'reason': 'password-protected'})
            else:
                found.append(_Capture(name, archive=path, member=info))


def _add_file(path, label, skip, found, skipped):
    ext = os.path.splitext(path)[1].lower()
    if _skipped(path, skip):
        skipped.append({'file': label, 'reason': 'excluded by --skip'})
    elif ext == '.zip':
        _from_zip(path, label, skip, found, skipped)
    elif ext in CAPTURE_EXTS:
        found.append(_Capture(label, path=path))


def collect(paths, skip=(), max_files=MAX_FILES):
    """
    Expand files, folders and zips into the captures to analyse.

    Returns (captures, skipped). Folders are walked without following
    symlinks; files that are neither captures nor zips are ignored.
    """
    found, skipped = [], []
    for path in paths:
        if os.path.isdir(path):
            root_label = os.path.basename(os.path.normpath(path)) or path
            for root, dirs, files in os.walk(path, followlinks=False):
                dirs.sort()
                for fname in sorted(files):
                    full = os.path.join(root, fname)
                    label = os.path.join(root_label, os.path.relpath(full, path))
                    if os.path.islink(full):
                        skipped.append({'file': label, 'reason': 'symlink not followed'})
                        continue
                    _add_file(full, label, skip, found, skipped)
        elif os.path.isfile(path):
            before = len(found) + len(skipped)
            _add_file(path, os.path.basename(path), skip, found, skipped)
            if len(found) + len(skipped) == before:
                skipped.append({'file': os.path.basename(path),
                                'reason': 'not a capture or zip'})
        else:
            skipped.append({'file': path, 'reason': 'not found'})
    if len(found) > max_files:
        for cap in found[max_files:]:
            skipped.append({'file': cap.name, 'reason': f'over the {max_files}-file limit'})
        found = found[:max_files]
    return found, skipped


def scan(paths, analyzer, skip=(), on_alert=None, on_progress=None, cancelled=None,
         max_files=MAX_FILES, max_member_bytes=MAX_MEMBER_BYTES):
    """
    Analyse every capture under `paths` with `analyzer` (a PcapAnalyzer).

    on_alert(alert) is called for each alert as it is found, tagged with the
    capture it came from; on_progress(index, total, name) before each capture;
    cancelled() is checked between captures. Leaves analyzer.alerts holding
    every capture's alerts and analyzer.stats the scan summary, so the
    analyzer's own export covers the whole scan.
    """
    captures, skipped = collect(paths, skip, max_files)
    report = {'files': [], 'skipped': skipped, 'alerts': [], 'credentials': [],
              'cancelled': False}
    alert_objects = []
    creds = {}

    with tempfile.TemporaryDirectory(prefix='netsentinel_scan_',
                                     ignore_cleanup_errors=True) as workdir:
        for index, cap in enumerate(captures):
            if cancelled and cancelled():
                report['cancelled'] = True
                break
            if on_progress:
                on_progress(index, len(captures), cap.name)

            def tag(alert, name=cap.name):
                if isinstance(getattr(alert, 'evidence', None), dict):
                    alert.evidence['capture'] = name
                if on_alert:
                    on_alert(alert)

            entry = {'file': cap.name}
            path = None
            try:
                path = cap.materialise(workdir, index, max_member_bytes)
                result = analyzer.analyze_file(path, callback=tag)
            except Exception as e:
                logger.warning("Batch scan: %s failed: %s", cap.name, e)
                analyzer.is_analyzing = False   # a raise leaves it set
                entry['error'] = str(e)
                report['files'].append(entry)
                continue
            finally:
                if path and not cap.path and os.path.exists(path):
                    os.remove(path)

            for obj in getattr(analyzer, 'alerts', []) or []:
                if isinstance(getattr(obj, 'evidence', None), dict):
                    obj.evidence['capture'] = cap.name
                alert_objects.append(obj)
            alerts = result.get('alerts', [])
            found = 0
            for alert in alerts:
                alert.setdefault('evidence', {})['capture'] = cap.name
                report['alerts'].append(alert)
                if alert.get('rule_id') != 'FORENSICS-CREDENTIAL':
                    continue
                found += 1
                ev = alert['evidence']
                key = (ev.get('protocol'), ev.get('credential_type'),
                       ev.get('value'), ev.get('source'))
                cred = creds.setdefault(key, {
                    'protocol': ev.get('protocol', ''),
                    'credential_type': ev.get('credential_type', ''),
                    'value': ev.get('value', ''),
                    'source': ev.get('source', ''),
                    'captures': [],
                })
                if cap.name not in cred['captures']:
                    cred['captures'].append(cap.name)
            stats = result.get('stats', {})
            entry.update(packets=stats.get('packets_analyzed', 0),
                         alerts=len(alerts), credentials=found)
            report['files'].append(entry)

    report['credentials'] = list(creds.values())
    report['summary'] = {
        'captures': len(captures),
        'scanned': sum(1 for f in report['files'] if 'error' not in f),
        'failed': sum(1 for f in report['files'] if 'error' in f),
        'skipped': len(skipped),
        'alerts': len(report['alerts']),
        'credentials': len(report['credentials']),
    }
    analyzer.alerts = alert_objects
    analyzer.stats = dict(report['summary'], file='batch scan')
    return report


def main(argv=None):
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog='python -m src.batch_scan',
        description='Scan captures in folders and zips for leaked credentials '
                    'and insecure protocols.')
    parser.add_argument('paths', nargs='+', help='capture files, folders or zips')
    parser.add_argument('--skip', action='append', default=[], metavar='GLOB',
                        help="leave out captures whose name matches, e.g. 'flash*'")
    parser.add_argument('--json', action='store_true', help='print the report as JSON')
    args = parser.parse_args(argv)

    from src.config import Config
    from src.pcap_analyzer import PcapAnalyzer
    report = scan(args.paths, PcapAnalyzer(Config().load()), skip=args.skip)

    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0
    s = report['summary']
    print(f"{s['scanned']} of {s['captures']} captures scanned, {s['alerts']} alerts, "
          f"{s['credentials']} exposed credentials")
    for cred in report['credentials']:
        print(f"  {cred['protocol']} {cred['credential_type']} {cred['value']}  "
              f"{cred['source']}  in {', '.join(cred['captures'])}")
    for f in report['files']:
        if 'error' in f:
            print(f"  failed: {f['file']}: {f['error']}")
    for f in report['skipped']:
        print(f"  skipped: {f['file']} ({f['reason']})")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
