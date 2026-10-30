"""
GeoIP: country and network operator for an address, looked up locally.
=======================================================================
Uses DB-IP's free "Lite" databases (IP to Country Lite and IP to ASN Lite), in
the MaxMind DB format, read with the `maxminddb` package. Lookups are entirely
local: the databases are downloaded once a month and nothing about the traffic
being looked up leaves this machine.

Off by default (`geoip.enabled`). When on, the files are fetched on first use
and then monthly into ~/.netsentinel/data/geoip/, each written to a temporary
file, opened to prove it is a valid database, and only then moved into place.

DB-IP Lite is licensed under Creative Commons Attribution 4.0, which requires
crediting DB-IP wherever results are shown. ATTRIBUTION is that credit, for
the UI to display.

`maxminddb` is imported only when GeoIP is enabled, so NetSentinel runs without it.
"""

import gzip
import ipaddress
import logging
import os
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger("NetSentinel.GeoIP")

__all__ = ['GeoIP', 'get_geoip', 'ATTRIBUTION', 'ATTRIBUTION_URL', 'ATTRIBUTION_HTML']

ATTRIBUTION = 'IP Geolocation by DB-IP (https://db-ip.com), licensed under CC BY 4.0'
ATTRIBUTION_URL = 'https://db-ip.com'
ATTRIBUTION_HTML = "<a href='https://db-ip.com'>IP Geolocation by DB-IP</a>"

# DB-IP publishes each month's file under its year and month.
DOWNLOAD_URL = 'https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz'
DATABASES = {
    'country': 'dbip-country-lite.mmdb',
    'asn': 'dbip-asn-lite.mmdb',
}
# Country Lite is ~10 MB compressed, ASN Lite ~5 MB; nothing legitimate is bigger.
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024
CACHE_MAX = 20000


def _data_dir():
    from src.config import DB_DIR
    return os.path.join(DB_DIR, 'geoip')


def _month(now=None):
    moment = datetime.fromtimestamp(now, tz=timezone.utc) if now else datetime.now(timezone.utc)
    return moment.strftime('%Y-%m')


def _public(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return addr.is_global


class GeoIP:
    """
    Country and ASN lookups. `lookup()` returns {} when disabled, when the
    databases are not there yet, for private addresses, or for anything not
    found — callers never need to check.
    """

    def __init__(self, config=None, data_dir=None, fetch=None):
        get = (lambda *keys, default=None: default) if config is None else config.get
        self.enabled = bool(get('geoip', 'enabled', default=False))
        self.auto_update = bool(get('geoip', 'auto_update', default=True))
        self.data_dir = data_dir or _data_dir()
        self._fetch = fetch or _http_fetch
        self._readers = {}
        self._cache = {}
        self._lock = threading.Lock()
        self._updater = None
        self.last_error = ''
        self.lookups = 0
        if self.enabled:
            self._open()

    # ─── Databases ──────────────────────────────────────────────────────────

    def _path(self, kind):
        return os.path.join(self.data_dir, DATABASES[kind])

    def _open(self):
        try:
            import maxminddb
        except ImportError:
            self.last_error = 'the maxminddb package is not installed'
            logger.warning("GeoIP is enabled but %s.", self.last_error)
            return False
        readers = {}
        for kind in DATABASES:
            path = self._path(kind)
            if not os.path.exists(path):
                continue
            try:
                readers[kind] = maxminddb.open_database(path)
            except Exception as e:
                logger.warning("GeoIP database %s unreadable: %s", path, e)
        with self._lock:
            old = self._readers
            self._readers = readers
            self._cache.clear()
        for reader in old.values():
            try:
                reader.close()
            except Exception:
                pass
        return bool(readers)

    @property
    def available(self):
        return self.enabled and bool(self._readers)

    def needs_update(self, now=None):
        """True when a database is missing or was fetched before this month."""
        month = _month(now)
        for kind in DATABASES:
            stamp = self._path(kind) + '.month'
            try:
                with open(stamp, encoding='utf-8') as f:
                    if f.read().strip() != month:
                        return True
            except OSError:
                return True
            if not os.path.exists(self._path(kind)):
                return True
        return False

    def update(self, force=False, now=None):
        """
        Download this month's databases if they are not already here. Each file
        is decompressed to a temporary name, opened as a database to prove it is
        one, and then atomically renamed over the old. Returns True if anything
        changed.
        """
        if not self.enabled:
            return False
        if not force and not self.needs_update(now):
            return False
        try:
            import maxminddb
        except ImportError:
            self.last_error = 'the maxminddb package is not installed'
            return False
        os.makedirs(self.data_dir, exist_ok=True)
        month = _month(now)
        changed = False
        for kind, name in DATABASES.items():
            url = DOWNLOAD_URL.format(kind=kind, month=month)
            final = self._path(kind)
            tmp = final + '.download'
            try:
                blob = self._fetch(url)
                data = gzip.decompress(blob)
                if len(data) > MAX_DOWNLOAD_BYTES:
                    raise ValueError('database larger than expected')
                with open(tmp, 'wb') as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                probe = maxminddb.open_database(tmp)
                probe.close()
                os.replace(tmp, final)
                with open(final + '.month', 'w', encoding='utf-8') as f:
                    f.write(month)
                changed = True
                logger.info("GeoIP %s database updated for %s", kind, month)
            except Exception as e:
                self.last_error = f'{kind} database not updated: {e}'
                logger.warning("GeoIP %s", self.last_error)
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        if changed:
            self._open()
        return changed

    def start_updates(self, interval_sec=6 * 3600):
        """A daemon thread that keeps the databases current. Idempotent."""
        if not (self.enabled and self.auto_update):
            return
        if self._updater is not None and self._updater.is_alive():
            return

        def _loop():
            while True:
                try:
                    self.update()
                except Exception as e:
                    logger.debug("GeoIP update error: %s", e)
                time.sleep(interval_sec)

        self._updater = threading.Thread(target=_loop, daemon=True, name="GeoIPUpdate")
        self._updater.start()

    # ─── Lookups ────────────────────────────────────────────────────────────

    def lookup(self, ip):
        """{'country': 'DE', 'country_name': 'Germany', 'asn': 3320,
        'as_org': 'Deutsche Telekom AG'} — any of them may be missing."""
        if not self.enabled or not self._readers or not _public(ip):
            return {}
        cached = self._cache.get(ip)
        if cached is not None:
            return cached
        self.lookups += 1
        result = {}
        readers = self._readers
        country = readers.get('country')
        if country is not None:
            try:
                rec = country.get(ip) or {}
                c = rec.get('country') or {}
                if c.get('iso_code'):
                    result['country'] = str(c['iso_code'])[:2]
                name = (c.get('names') or {}).get('en')
                if name:
                    result['country_name'] = str(name)[:80]
            except Exception as e:
                logger.debug("GeoIP country lookup failed for %s: %s", ip, e)
        asn = readers.get('asn')
        if asn is not None:
            try:
                rec = asn.get(ip) or {}
                if rec.get('autonomous_system_number') is not None:
                    result['asn'] = int(rec['autonomous_system_number'])
                if rec.get('autonomous_system_organization'):
                    result['as_org'] = str(rec['autonomous_system_organization'])[:120]
            except Exception as e:
                logger.debug("GeoIP ASN lookup failed for %s: %s", ip, e)
        if len(self._cache) >= CACHE_MAX:
            self._cache.clear()
        self._cache[ip] = result
        return result

    def annotate(self, ip, prefix):
        """Fields for an evidence dict: {prefix+'_country': ..., ...}."""
        info = self.lookup(ip)
        out = {}
        if info.get('country'):
            out[f'{prefix}_country'] = info['country']
        if info.get('asn') is not None:
            out[f'{prefix}_asn'] = info['asn']
        if info.get('as_org'):
            out[f'{prefix}_as_org'] = info['as_org']
        return out

    def annotate_talkers(self, talkers):
        """
        Top-talker rows with country and ASN added, for the dashboard. Accepts
        {ip: bytes} or [(ip, bytes), ...] and returns a list of dicts.
        """
        items = talkers.items() if isinstance(talkers, dict) else talkers
        rows = []
        for ip, value in items:
            row = {'ip': ip, 'bytes': value}
            row.update(self.lookup(ip))
            rows.append(row)
        return rows

    def get_stats(self):
        return {
            'enabled': self.enabled,
            'available': self.available,
            'databases': sorted(self._readers),
            'lookups': self.lookups,
            'last_error': self.last_error,
            'attribution': ATTRIBUTION,
        }


def _http_fetch(url):
    import urllib.request
    req = urllib.request.Request(url, headers={'User-Agent': 'NetSentinel GeoIP update'})
    with urllib.request.urlopen(req, timeout=120) as response:
        if not response.geturl().lower().startswith('https://'):
            raise ValueError(f'redirected off HTTPS: {response.geturl()}')
        data = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise ValueError('download larger than expected')
    return data


_shared = None
_shared_lock = threading.Lock()


def get_geoip(config=None):
    """
    The process-wide GeoIP, created on first call; starts the monthly updater
    when enabled. Several engines (live and PCAP analysis) share one set of
    open databases and one updater.
    """
    global _shared
    with _shared_lock:
        if _shared is None:
            _shared = GeoIP(config)
            _shared.start_updates()
        return _shared
