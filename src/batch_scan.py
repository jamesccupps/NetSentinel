"""
NetSentinel - Batch Scan
Scans everything in a folder, a zip, or a list of files and combines the
results into one report. Packet captures go through the PCAP analyzer; every
other file has its contents searched by src.file_scan. The report lists each
exposed credential or secret (masked), every IP address, domain, URL, email and
MAC address found and which files held it, and flags any the threat feeds know.

Zip members are never extracted under their own names. Each one is streamed,
size-capped, to a numbered file in a private temporary directory, scanned, and
deleted before the next, so a hostile archive cannot write outside that
directory and only one member is on disk at a time. Nested archives and
password-protected members are skipped and reported, not opened.

Secret values in the report are masked; the raw values never enter it.
"""

import fnmatch
import ipaddress
import logging
import os
import tempfile
import zipfile

from src import file_scan

logger = logging.getLogger(__name__)

CAPTURE_EXTS = ('.pcap', '.pcapng', '.cap')
MAX_FILES = 100_000
MAX_MEMBER_BYTES = 2 * 1024 ** 3   # per file taken out of a zip
SKIP_DIRS = {'.git', '.svn', '.hg', 'node_modules', '__pycache__', '.venv', 'venv'}
INDICATOR_KINDS = ('ipv4', 'ipv6', 'domain', 'url', 'email', 'mac')


class _Item:
    """One thing to scan: a file on disk, or a member of a zip."""

    def __init__(self, name, path=None, archive=None, member=None):
        self.name = name
        self.path = path
        self.archive = archive
        self.member = member
        source = member.filename if member is not None else path
        self.is_capture = os.path.splitext(source)[1].lower() in CAPTURE_EXTS

    def materialise(self, workdir, index, max_bytes):
        """Return a path to scan, extracting a zip member if need be."""
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
            elif ext in file_scan.MEDIA_EXTS:
                skipped.append({'file': name, 'reason': 'media file'})
            elif _skipped(info.filename, skip):
                skipped.append({'file': name, 'reason': 'excluded by --skip'})
            elif info.flag_bits & 0x1:
                skipped.append({'file': name, 'reason': 'password-protected'})
            else:
                found.append(_Item(name, archive=path, member=info))


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
    and version-control and dependency folders are left out.
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


def scan(paths, analyzer, skip=(), on_alert=None, on_progress=None, cancelled=None,
         max_files=MAX_FILES, max_member_bytes=MAX_MEMBER_BYTES, threat_intel=None):
    """
    Scan everything under `paths`. Captures go to `analyzer` (a PcapAnalyzer).

    on_alert(alert) is called for each alert, tagged with the file it came
    from; on_progress(index, total, name) before each file; cancelled() is
    checked between files. threat_intel defaults to the analyzer's. Leaves
    analyzer.alerts holding every alert and analyzer.stats the summary and
    indicators, so the analyzer's own export covers the whole scan.
    """
    if threat_intel is None:
        threat_intel = getattr(analyzer, 'threat_intel', None)
    items, skipped = collect(paths, skip, max_files)
    report = {'files': [], 'skipped': skipped, 'alerts': [], 'credentials': [],
              'secrets': [], 'cancelled': False}
    alert_objects = []
    creds = {}
    indicators = _Indicators()

    def emit(alert, key=None, name=None):
        if key and isinstance(getattr(alert, 'evidence', None), dict):
            alert.evidence[key] = name
        alert_objects.append(alert)
        report['alerts'].append(alert.to_dict())
        if on_alert:
            on_alert(alert)

    with tempfile.TemporaryDirectory(prefix='netsentinel_scan_',
                                     ignore_cleanup_errors=True) as workdir:
        for index, item in enumerate(items):
            if cancelled and cancelled():
                report['cancelled'] = True
                break
            if on_progress:
                on_progress(index, len(items), item.name)

            entry = {'file': item.name, 'type': 'capture' if item.is_capture else 'file'}
            path = None
            try:
                path = item.materialise(workdir, index, max_member_bytes)
                if item.is_capture:
                    _scan_capture(item, path, analyzer, entry, emit, creds, indicators)
                else:
                    _scan_file(item, path, entry, emit, report, indicators)
            except Exception as e:
                logger.warning("Batch scan: %s failed: %s", item.name, e)
                analyzer.is_analyzing = False   # a raise leaves it set
                entry['error'] = str(e)
            finally:
                if path and not item.path and os.path.exists(path):
                    os.remove(path)
            report['files'].append(entry)

    found = indicators.as_lists()
    threats = _check_threats(found, threat_intel)
    for hit in threats:
        emit(_alert('FILESCAN-THREAT-INTEL', 'HIGH',
                    f"Known-bad {hit['kind']} found: {hit['value']}",
                    f"{hit['value']} is listed by {hit.get('feed') or 'a threat feed'}.",
                    'Threat Intelligence',
                    {'indicator': hit['value'], 'kind': hit['kind'],
                     'feed': hit.get('feed', ''), 'category': hit.get('category', ''),
                     'files': hit['files']}))

    report['credentials'] = list(creds.values())
    report['indicators'] = found
    report['threats'] = threats
    report['summary'] = dict({
        'items': len(items),
        'captures': sum(1 for i in items if i.is_capture),
        'files': sum(1 for i in items if not i.is_capture),
        'scanned': sum(1 for f in report['files'] if 'error' not in f),
        'failed': sum(1 for f in report['files'] if 'error' in f),
        'skipped': len(skipped),
        'alerts': len(report['alerts']),
        'credentials': len(report['credentials']),
        'secrets': len(report['secrets']),
        'threats': len(threats),
    }, **{k: len(v) for k, v in found.items()})
    analyzer.alerts = alert_objects
    analyzer.stats = dict(report['summary'], file='batch scan', indicators=found)
    return report


def _scan_capture(item, path, analyzer, entry, emit, creds, indicators):
    result = analyzer.analyze_file(path)
    alerts = list(getattr(analyzer, 'alerts', []) or [])
    found = 0
    for obj in alerts:
        emit(obj, 'capture', item.name)
        if obj.rule_id != 'FORENSICS-CREDENTIAL':
            continue
        found += 1
        ev = obj.evidence
        key = (ev.get('protocol'), ev.get('credential_type'), ev.get('value'), ev.get('source'))
        cred = creds.setdefault(key, {
            'protocol': ev.get('protocol', ''),
            'credential_type': ev.get('credential_type', ''),
            'value': ev.get('value', ''),
            'source': ev.get('source', ''),
            'captures': [],
        })
        if item.name not in cred['captures']:
            cred['captures'].append(item.name)
    stats = result.get('stats', {})
    for key in ('top_talkers', 'top_destinations'):
        for ip, _bytes in stats.get(key) or []:
            indicators.add_ip(ip, item.name)
    for name, count in stats.get('top_dns_queries') or []:
        if name:
            indicators.add('domain', str(name).lower().rstrip('.'), item.name, count)
    entry.update(packets=stats.get('packets_analyzed', 0), alerts=len(alerts),
                 credentials=found)


def _scan_file(item, path, entry, emit, report, indicators):
    with open(path, 'rb') as f:
        data = f.read(file_scan.MAX_TEXT_BYTES + 1)
    result = file_scan.scan_bytes(item.name, data)
    for kind, values in result['indicators'].items():
        for value, info in values.items():
            info = dict(info)
            count = info.pop('count', 1)
            indicators.add(kind, value, item.name, count, **info)
    for secret in result['secrets']:
        secret = dict(secret, file=item.name)
        report['secrets'].append(secret)
        emit(_alert('FILESCAN-SECRET', secret['severity'],
                    f"{secret['label']} in {os.path.basename(item.name)}",
                    f"{secret['label']} found on line {secret['line']} of {item.name}. "
                    "If it is real, treat it as exposed: rotate or revoke it.",
                    'Secret Exposure',
                    {'kind': secret['kind'], 'value': secret['value'],
                     'line': secret['line']}), 'file', item.name)
    entry.update(secrets=len(result['secrets']),
                 indicators=sum(len(v) for v in result['indicators'].values()))
    if result['truncated']:
        entry['note'] = f'only the first {file_scan.MAX_TEXT_BYTES // 1024 ** 2} MB searched'


def _check_threats(found, threat_intel):
    """Look up public addresses and domains in the threat feeds."""
    if threat_intel is None:
        return []
    hits = []
    for kind, check in (('ipv4', 'check_ip'), ('ipv6', 'check_ip'), ('domain', 'check_domain')):
        lookup = getattr(threat_intel, check, None)
        if lookup is None:
            continue
        for entry in found[kind]:
            if entry.get('scope', 'public') != 'public':
                continue
            try:
                info = lookup(entry['value'])
            except Exception:
                continue
            if info:
                entry['threat'] = info
                hits.append(dict(info, kind=kind, value=entry['value'], files=entry['files']))
    return hits


def main(argv=None):
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog='python -m src.batch_scan',
        description='Scan files, folders and zips for leaked secrets and network '
                    'indicators; packet captures get the full PCAP analysis.')
    parser.add_argument('paths', nargs='+', help='files, folders or zips')
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
    for cred in report['credentials']:
        print(f"  {cred['protocol']} {cred['credential_type']} {cred['value']}  "
              f"{cred['source']}  in {', '.join(cred['captures'])}")
    for sec in report['secrets']:
        print(f"  {sec['label']}: {sec['value']}  {sec['file']}:{sec['line']}")
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
