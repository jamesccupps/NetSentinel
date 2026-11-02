"""
Known exploited vulnerabilities in the software devices on this network run.
=============================================================================
CISA's Known Exploited Vulnerabilities catalog (KEV) lists the CVEs attackers
are known to use, some 1,500, and adds a few a week. NVD gives each its affected
products and version ranges. Both are downloaded whole, daily, and matched here
against what devices say they run: a web server's Server and X-Powered-By
headers, and the greeting of an SSH, FTP or mail server, as seen in traffic on
this network or read by the network audit. Nothing about the devices is sent
anywhere: the downloads are the same for everyone.

A match says a version sits in a range NVD lists for a CVE that is being
exploited. That is a reason to check, not proof: a banner can hide or misstate
its version, and Linux distributions patch old version numbers in place
("OpenSSH_8.9p1 Ubuntu-3ubuntu0.10" may well be fixed). The alerts say so.

KEV is a US government work (CISA), free to use. NVD asks that products using
its data say: "This product uses the NVD API but is not endorsed or certified
by the NVD."
"""

import json
import logging
import os
import re
import threading
import time
import zlib

logger = logging.getLogger("NetSentinel.Vulns")

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
# Every CVE in KEV, with its configurations (CPE version ranges). Paged: at most
# 2,000 a page, and without an API key five requests in 30 seconds.
NVD_URL = ('https://services.nvd.nist.gov/rest/json/cves/2.0'
           '?hasKev&resultsPerPage={per_page}&startIndex={start}')
NVD_PAGE = 2000
NVD_PAGE_GAP_SEC = 6.5
NVD_NOTICE = 'This product uses the NVD API but is not endorsed or certified by the NVD.'

REFRESH_SEC = 24 * 3600
FIRST_UPDATE_DELAY = 90
MAX_AGE_SEC = 14 * 86400         # older than this, a match would be out of date
MAX_KEV_BYTES = 32 * 1024 * 1024
MAX_NVD_BYTES = 256 * 1024 * 1024

# What a banner says it runs: (pattern, name, NVD (vendor, product) pairs). The
# version is the pattern's first group. nginx moved from nginx:nginx to f5:nginx
# in NVD, so both are looked up.
SOFTWARE = (
    (r'Apache/(\d+\.\d+\.\d+)', 'Apache HTTP Server', (('apache', 'http_server'),)),
    (r'Apache[ -]Tomcat/(\d+\.\d+\.\d+)', 'Apache Tomcat', (('apache', 'tomcat'),)),
    (r'nginx/(\d+\.\d+\.\d+)', 'nginx', (('f5', 'nginx'), ('nginx', 'nginx'))),
    (r'Microsoft-IIS/(\d+\.\d+)', 'Microsoft IIS',
     (('microsoft', 'internet_information_services'),)),
    (r'OpenSSH_(\d+\.\d+)', 'OpenSSH', (('openbsd', 'openssh'),)),
    (r'dropbear_(\d{4}\.\d+)', 'Dropbear SSH', (('dropbear_ssh_project', 'dropbear_ssh'),)),
    (r'lighttpd/(\d+\.\d+\.\d+)', 'lighttpd', (('lighttpd', 'lighttpd'),)),
    (r'PHP/(\d+\.\d+\.\d+)', 'PHP', (('php', 'php'),)),
    (r'OpenSSL/(\d+\.\d+\.\d+[a-z]?)', 'OpenSSL', (('openssl', 'openssl'),)),
    (r'MiniUPnPd/(\d+\.\d+(?:\.\d+)?)', 'MiniUPnPd', (('miniupnp_project', 'miniupnpd'),)),
    (r'GoAhead-(?:Webs|http)/(\d+\.\d+\.\d+)', 'GoAhead', (('embedthis', 'goahead'),)),
    (r'RomPager/(\d+\.\d+)', 'Allegro RomPager', (('allegrosoft', 'rompager'),)),
    (r'Exim (\d+\.\d+(?:\.\d+)?)', 'Exim', (('exim', 'exim'),)),
    (r'ProFTPD (\d+\.\d+\.\d+[a-z]?)', 'ProFTPD', (('proftpd', 'proftpd'),)),
    (r'vsFTPd (\d+\.\d+\.\d+)', 'vsftpd', (('beasts', 'vsftpd'),)),
    (r'Jetty\((\d+\.\d+\.\d+)', 'Eclipse Jetty', (('eclipse', 'jetty'),)),
    (r'Drupal (\d+(?:\.\d+)*)', 'Drupal', (('drupal', 'drupal'),)),
    (r'WordPress (\d+\.\d+(?:\.\d+)?)', 'WordPress', (('wordpress', 'wordpress'),)),
    (r'Werkzeug/(\d+\.\d+\.\d+)', 'Werkzeug', (('palletsprojects', 'werkzeug'),)),
)
_SOFTWARE = tuple((re.compile(p), name, pairs) for p, name, pairs in SOFTWARE)

# A distribution's build string after the version: patched in place, maybe.
_DISTRO = re.compile(r'(?i)ubuntu|debian|deb\d|el\d|\.el\d|centos|red ?hat|fedora|raspbian|'
                     r'\bfreebsd\b|suse')


def identify(text):
    """[(name, version, pairs)] for each product a banner names with a version."""
    found = []
    for pattern, name, pairs in _SOFTWARE:
        m = pattern.search(text or '')
        if m and m.group(1):
            found.append((name, m.group(1), pairs))
    return found


def version_key(version):
    """
    Comparable form of a version: numbers numerically, letters after them, so
    1.0.2 < 1.0.2k < 1.0.10 (OpenSSL's letter releases) and 2.4.9 < 2.4.49.
    """
    parts = re.findall(r'\d+|[a-z]+', (version or '').lower())
    return tuple((1, int(p)) if p.isdigit() else (0, p) for p in parts)


def affects(rule, version):
    """
    Whether one NVD version rule takes in this version. A rule is
    (cve, exact, start_incl, start_excl, end_incl, end_excl); an exact of '*'
    with no bounds means every version.
    """
    _, exact, si, se, ei, ee = rule
    v = version_key(version)
    if exact not in ('*', ''):
        return exact != '-' and version_key(exact) == v
    if si and v < version_key(si):
        return False
    if se and v <= version_key(se):
        return False
    if ei and v > version_key(ei):
        return False
    if ee and v >= version_key(ee):
        return False
    return True


def _cpe_rules(nvd_items):
    """{'vendor:product': [rule, ...]} from NVD CVE items, vulnerable entries only."""
    rules = {}
    for item in nvd_items:
        cve = item.get('cve') or item
        cve_id = cve.get('id')
        if not cve_id:
            continue
        for config in cve.get('configurations') or ():
            for node in config.get('nodes') or ():
                if node.get('negate'):
                    continue
                for match in node.get('cpeMatch') or ():
                    if not match.get('vulnerable'):
                        continue
                    parts = str(match.get('criteria', '')).split(':')
                    if len(parts) < 6 or parts[2] not in ('a', 'o', 'h'):
                        continue
                    key = f'{parts[3]}:{parts[4]}'
                    rules.setdefault(key, []).append((
                        cve_id, parts[5],
                        match.get('versionStartIncluding', ''),
                        match.get('versionStartExcluding', ''),
                        match.get('versionEndIncluding', ''),
                        match.get('versionEndExcluding', '')))
    return rules


class Catalog:
    """KEV and NVD's version ranges for it, cached on disk and matched locally."""

    def __init__(self, config=None, data_dir=None, fetch=None, sleep=time.sleep):
        get = (lambda *keys, default=None: default) if config is None else config.get
        self.enabled = bool(get('vulns', 'enabled', default=True))
        self.auto_update = bool(get('vulns', 'auto_update', default=True))
        if data_dir is None:
            from src.config import DB_DIR
            data_dir = os.path.join(DB_DIR, 'vulns')
        self.data_dir = data_dir
        self._fetch = fetch or _http_fetch
        self._sleep = sleep
        self._lock = threading.Lock()
        self._kev = {}            # cve -> KEV record (selected fields)
        self._rules = {}          # 'vendor:product' -> [rule]
        self._catalog_version = ''
        self._loaded_at = {}      # 'kev'/'nvd' -> mtime of the cache used
        self.last_error = {}      # 'kev'/'nvd' -> text of the last failure
        self._thread = None
        self._stop = threading.Event()
        if self.enabled:
            self.load()

    # ─── Cache ──────────────────────────────────────────────────────────────

    def _path(self, name):
        return os.path.join(self.data_dir, name)

    def load(self):
        """Read the cached downloads. True if both are there and fresh enough."""
        kev = _read_json(self._path('kev.json'))
        rules = _read_json(self._path('nvd_kev_rules.json'))
        now = time.time()
        fresh = {}
        for name in ('kev', 'nvd'):
            path = self._path('kev.json' if name == 'kev' else 'nvd_kev_rules.json')
            try:
                fresh[name] = os.path.getmtime(path)
            except OSError:
                fresh[name] = None
        if not kev or not rules or any(
                t is None or now - t > MAX_AGE_SEC for t in fresh.values()):
            with self._lock:
                self._kev, self._rules = {}, {}
                self._loaded_at = fresh
            return False
        records = {}
        for v in kev.get('vulnerabilities') or ():
            cve = v.get('cveID')
            if cve:
                records[cve] = {k: str(v.get(k, ''))[:300] for k in (
                    'vendorProject', 'product', 'vulnerabilityName', 'dateAdded',
                    'shortDescription', 'requiredAction', 'dueDate',
                    'knownRansomwareCampaignUse')}
        table = {}
        for key, items in (rules.get('rules') or {}).items():
            kept = [tuple(r) for r in items if len(r) == 6 and r[0] in records]
            if kept:
                table[key] = kept
        with self._lock:
            self._kev, self._rules = records, table
            self._catalog_version = str(kev.get('catalogVersion', ''))
            self._loaded_at = fresh
        return True

    # ─── Downloads ──────────────────────────────────────────────────────────

    def update(self, force=False):
        """Download what is older than a day. Returns True if anything changed."""
        if not self.enabled:
            return False
        os.makedirs(self.data_dir, exist_ok=True)
        changed = False
        if force or _age(self._path('kev.json')) > REFRESH_SEC:
            try:
                blob = self._fetch(KEV_URL, MAX_KEV_BYTES)
                data = json.loads(blob)
                if not isinstance(data.get('vulnerabilities'), list):
                    raise ValueError('no vulnerabilities list')
                _write(self._path('kev.json'), blob)
                self.last_error.pop('kev', None)
                changed = True
            except Exception as e:
                self.last_error['kev'] = f'{type(e).__name__}: {e}'[:200]
                logger.warning("KEV catalog not downloaded: %s", self.last_error['kev'])
        if force or _age(self._path('nvd_kev_rules.json')) > REFRESH_SEC:
            try:
                items = self._nvd_items()
                rules = _cpe_rules(items)
                _write(self._path('nvd_kev_rules.json'), json.dumps(
                    {'fetched': time.time(), 'cves': len(items), 'rules': rules}).encode())
                self.last_error.pop('nvd', None)
                changed = True
            except Exception as e:
                self.last_error['nvd'] = f'{type(e).__name__}: {e}'[:200]
                logger.warning("NVD version ranges not downloaded: %s", self.last_error['nvd'])
        if changed:
            self.load()
        return changed

    def _nvd_items(self):
        items, start, total = [], 0, None
        while total is None or start < total:
            if start:
                self._sleep(NVD_PAGE_GAP_SEC)
            page = json.loads(self._fetch(
                NVD_URL.format(per_page=NVD_PAGE, start=start), MAX_NVD_BYTES))
            batch = page.get('vulnerabilities') or []
            total = int(page.get('totalResults', len(batch)))
            items.extend(batch)
            if not batch:
                break
            start += len(batch)
        return items

    def start_updating(self):
        if not (self.enabled and self.auto_update) or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name='VulnUpdate')
        self._thread.start()

    def stop_updating(self):
        self._stop.set()

    def _loop(self):
        if self._stop.wait(FIRST_UPDATE_DELAY):
            return
        while True:
            try:
                self.update()
            except Exception as e:
                logger.debug("Vulnerability update error: %s", e)
            if self._stop.wait(3600):
                return

    # ─── Matching ───────────────────────────────────────────────────────────

    @property
    def ready(self):
        return bool(self._rules)

    def match(self, text):
        """
        The exploited CVEs a banner's software and version fall in, as dicts:
        product, version, cve, name, date_added, ransomware, required_action,
        every_version (the range takes in all versions), distro_build.
        """
        if not text or not self._rules:
            return []
        out, seen = [], set()
        distro = bool(_DISTRO.search(text))
        with self._lock:
            rules, kev = self._rules, self._kev
        for name, version, pairs in identify(text):
            for vendor, product in pairs:
                for rule in rules.get(f'{vendor}:{product}', ()):
                    if rule[0] in seen or not affects(rule, version):
                        continue
                    seen.add(rule[0])
                    record = kev.get(rule[0], {})
                    out.append({
                        'product': name, 'version': version, 'cve': rule[0],
                        'name': record.get('vulnerabilityName', ''),
                        'date_added': record.get('dateAdded', ''),
                        'ransomware': record.get('knownRansomwareCampaignUse', '') == 'Known',
                        'required_action': record.get('requiredAction', ''),
                        'every_version': rule[1] in ('*', '') and not any(rule[2:]),
                        'distro_build': distro,
                    })
        out.sort(key=lambda m: m['date_added'], reverse=True)
        return out

    # ─── Status, for the Threat data page ───────────────────────────────────

    def status(self):
        rows = []
        for name, description, refresh in (
                ('kev', "CISA KEV - Vulnerabilities known to be exploited", 24),
                ('nvd', "NVD - Affected versions of each KEV vulnerability", 24)):
            updated = self._loaded_at.get(name)
            if not self.enabled:
                state, note = 'off', 'Off in settings (vulns.enabled).'
            elif self.last_error.get(name) and not updated:
                state, note = 'failed', self.last_error[name]
            elif updated is None:
                state, note = 'waiting', 'Not downloaded yet.'
            elif time.time() - updated > MAX_AGE_SEC:
                state, note = 'stale', (f'{int((time.time() - updated) // 86400)} days old, '
                                        'so not used.')
            else:
                state, note = 'ok', ''
            if name == 'kev':
                entries = len(self._kev) if state == 'ok' else 0
                if state == 'ok' and self._catalog_version:
                    note = f'Catalog {self._catalog_version}.'
            else:
                entries = sum(len(v) for v in self._rules.values()) if state == 'ok' else 0
                note = (note + ' ' if note else '') + NVD_NOTICE
            rows.append({'name': f'vulns_{name}', 'description': description,
                         'category': 'Vulnerabilities', 'state': state, 'note': note,
                         'updated': updated, 'entries': entries, 'refresh_hours': refresh})
        return rows


def describe(matches, limit=5):
    """One line for an alert or finding: the newest CVEs first."""
    shown = matches[:limit]
    more = len(matches) - len(shown)
    text = '; '.join(f"{m['cve']} ({m['name'] or 'exploited'})" for m in shown)
    return text + (f'; and {more} more' if more > 0 else '')


def caveat(matches):
    if any(m['distro_build'] for m in matches):
        return ("The banner shows a distribution's build, which may carry the fix "
                "without a new version number: check the distribution's notice "
                "for each CVE before treating this as unpatched.")
    return ("A banner can hide or misstate its version, so confirm the version on "
            "the device before acting.")


def _age(path):
    try:
        return time.time() - os.path.getmtime(path)
    except OSError:
        return float('inf')


def _read_json(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
        if data[:2] == b'\x1f\x8b':
            data = _gunzip(data, MAX_NVD_BYTES)
        return json.loads(data)
    except (OSError, ValueError):
        return None


def _write(path, blob):
    tmp = path + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(blob)
    os.replace(tmp, path)


def _http_fetch(url, limit):
    import urllib.request
    req = urllib.request.Request(url, headers={
        'User-Agent': 'NetSentinel vulnerability data', 'Accept-Encoding': 'gzip'})
    with urllib.request.urlopen(req, timeout=120) as response:
        if not response.geturl().lower().startswith('https://'):
            raise ValueError(f'redirected off HTTPS: {response.geturl()}')
        data = response.read(limit + 1)
        gzipped = response.headers.get('Content-Encoding', '') == 'gzip'
    if len(data) > limit:
        raise ValueError('download larger than expected')
    return _gunzip(data, limit) if gzipped else data


def _gunzip(data, limit):
    """Decompress, refusing more than limit bytes out: the cap on the download
    means nothing if what it inflates to is not capped too."""
    inflater = zlib.decompressobj(wbits=31)
    out = inflater.decompress(data, limit + 1)
    if len(out) > limit or inflater.unconsumed_tail:
        raise ValueError('download inflates past its limit')
    return out


_shared = None
_shared_lock = threading.Lock()


def get_catalog(config=None):
    """The process's one Catalog, built from the cache on first use."""
    global _shared
    with _shared_lock:
        if _shared is None:
            _shared = Catalog(config)
        return _shared
