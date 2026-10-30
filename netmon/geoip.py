"""
Country and network for an internet address.
============================================
A controller that starts talking to a network in another country, or a kiosk
reaching anything but its payment processor's network, is a finding a list of
addresses cannot show. This reads DB-IP's free country and ASN databases from
disk and answers both, offline.

    python -m netmon geoip --update --dir /var/lib/netmon/geoip
    python -m netmon geoip --dir /var/lib/netmon/geoip --lookup 203.0.113.9

Then point the profile at the directory:

    geoip:
      directory: /var/lib/netmon/geoip

Nothing about the site's traffic leaves
---------------------------------------
Lookups are local. The only network call is `--update`, which downloads the
two database files from DB-IP and sends nothing about this network — not an
address, not a count. It is opt-in and run by a person (or a monthly timer
they set up), never by the service on its own.

The data
--------
DB-IP Lite, licensed CC BY 4.0, which asks for attribution: "IP Geolocation by
DB-IP" (https://db-ip.com). It is credited here, in the README, and in the
SOURCE.txt written beside the files. The databases are updated monthly; a file
older than about two months is reported as stale.

`maxminddb` reads the files and is imported only when a lookup is made, so a
sensor without it, or without the files, runs exactly as before: the fields
are simply absent.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import threading
import time
import zlib

logger = logging.getLogger("netmon.geoip")

__all__ = ['GeoIP', 'GeoIPError', 'for_directory', 'update', 'status',
           'ATTRIBUTION', 'normalise_asn']

ATTRIBUTION = 'IP Geolocation by DB-IP (https://db-ip.com), licensed CC BY 4.0'

#: What to download, and the name each is kept under. The month in the URL is
#: the release; the current month's appears early in the month, so the
#: previous one is tried when it is not there yet.
DATABASES = {
    'country': ('https://download.db-ip.com/free/dbip-country-lite-{month}.mmdb.gz',
                'dbip-country-lite.mmdb'),
    'asn': ('https://download.db-ip.com/free/dbip-asn-lite-{month}.mmdb.gz',
            'dbip-asn-lite.mmdb'),
}

#: Every MMDB file ends its data section with this marker before the metadata.
_MMDB_MARKER = b'\xab\xcd\xefMaxMind.com'

#: A ceiling on what one download may decompress to. The real files are tens
#: of megabytes; anything near this is not one of them.
MAX_DATABASE_BYTES = 512 * 1024 * 1024

#: How often a reader checks whether its file was replaced or appeared.
RECHECK_SECONDS = 300

#: Older than this and `status` calls the file stale.
STALE_DAYS = 62


class GeoIPError(RuntimeError):
    """The databases could not be downloaded or read. The message says why."""


def normalise_asn(value):
    """'AS13335', 'as13335', 13335 and '13335' are all 13335; else None."""
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip().upper()
    if text.startswith('AS'):
        text = text[2:]
    try:
        number = int(text)
    except ValueError:
        return None
    return number if 0 < number < 2 ** 32 else None


class GeoIP:
    """
    Lookups against the two databases in one directory.

    Opens lazily, survives the files being absent (lookups return nothing),
    and reopens a file that `--update` replaced, so a running service picks
    up a new month without a restart.
    """

    def __init__(self, directory, open_database=None, clock=time.time,
                 cache_size=20000):
        self.directory = directory
        self._open_database = open_database
        self._clock = clock
        self._readers = {}          # kind -> (reader, mtime)
        self._checked = {}          # kind -> last check time
        self._cache = {}
        self._cache_size = int(cache_size)
        self._lock = threading.Lock()
        self._warned = False

    def _opener(self):
        if self._open_database is not None:
            return self._open_database
        try:
            import maxminddb
        except ImportError:
            if not self._warned:
                logger.warning('GeoIP files are configured but maxminddb is not '
                               'installed: pip install maxminddb')
                self._warned = True
            return None
        return maxminddb.open_database

    def _reader(self, kind):
        now = self._clock()
        current = self._readers.get(kind)
        last = self._checked.get(kind)
        # At most one stat per file per interval, present or not: this runs
        # for every event, and a missing file is the common case.
        if last is not None and now - last < RECHECK_SECONDS:
            return current[0] if current is not None else None
        self._checked[kind] = now
        path = os.path.join(self.directory, DATABASES[kind][1])
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            self._close(kind)
            return None
        if current is not None and current[1] == mtime:
            return current[0]
        opener = self._opener()
        if opener is None:
            return None
        try:
            reader = opener(path)
        except Exception as e:                      # a damaged or partial file
            logger.warning('could not open %s: %s', path, type(e).__name__)
            self._close(kind)
            return None
        self._close(kind)
        self._readers[kind] = (reader, mtime)
        self._cache.clear()
        return reader

    def _close(self, kind):
        current = self._readers.pop(kind, None)
        if current is not None:
            try:
                current[0].close()
            except Exception:
                pass

    def available(self):
        with self._lock:
            return any(self._reader(kind) is not None for kind in DATABASES)

    def lookup(self, ip):
        """
        {'country': 'NL', 'asn': 1136, 'as_org': '...'} for what is known,
        an empty dict when nothing is. Never raises.
        """
        if not ip:
            return {}
        with self._lock:
            # Checked first: a replaced file has to be seen even for an address
            # that is already cached, or the cache would keep last month's
            # answer until it filled.
            country_db, asn_db = self._reader('country'), self._reader('asn')
            if ip in self._cache:
                return dict(self._cache[ip])
            out = {}
            for reader, parse in ((country_db, _country_of), (asn_db, _asn_of)):
                if reader is None:
                    continue
                try:
                    record = reader.get(ip)
                except (ValueError, TypeError):
                    record = None                   # not an address
                except Exception as e:
                    logger.debug('lookup of %s failed: %s', ip, e)
                    record = None
                if isinstance(record, dict):
                    out.update(parse(record))
            if len(self._cache) >= self._cache_size:
                self._cache.clear()
            self._cache[ip] = out
            return dict(out)

    def close(self):
        with self._lock:
            for kind in list(self._readers):
                self._close(kind)


def _country_of(record):
    for key in ('country', 'registered_country'):
        section = record.get(key)
        if isinstance(section, dict) and section.get('iso_code'):
            return {'country': str(section['iso_code']).upper()[:3]}
    return {}


def _asn_of(record):
    out = {}
    asn = normalise_asn(record.get('autonomous_system_number', record.get('asn')))
    if asn is not None:
        out['asn'] = asn
    org = record.get('autonomous_system_organization') or record.get('as_org')
    if org:
        # Names come from a registry anyone can write to; kept short and on
        # one line, like any other name that ends up in an alert.
        out['as_org'] = ' '.join(str(org).split())[:80]
    return out


_INSTANCES = {}
_INSTANCES_LOCK = threading.Lock()


def for_directory(directory):
    """The shared reader for a directory, or None when none is configured."""
    if not directory:
        return None
    key = os.path.abspath(directory)
    with _INSTANCES_LOCK:
        if key not in _INSTANCES:
            _INSTANCES[key] = GeoIP(key)
        return _INSTANCES[key]


# ─── Downloading ─────────────────────────────────────────────────────────────

def _fetch(url, timeout):
    import urllib.request
    if not url.startswith('https://'):
        raise GeoIPError(f'refusing a non-HTTPS download: {url}')
    request = urllib.request.Request(url, headers={'User-Agent': 'netmon-geoip'})
    return urllib.request.urlopen(request, timeout=timeout)


def _months(now, back=2):
    """This month and the ones before it, as YYYY-MM, newest first."""
    parts = time.gmtime(now)
    year, month = parts.tm_year, parts.tm_mon
    out = []
    for _ in range(back + 1):
        out.append(f'{year:04d}-{month:02d}')
        month -= 1
        if month == 0:
            year, month = year - 1, 12
    return out


def _valid_mmdb(path, open_database=None):
    """Whether the file is a readable MMDB, by its marker and, if possible, by
    opening it."""
    try:
        size = os.path.getsize(path)
        with open(path, 'rb') as handle:
            handle.seek(max(0, size - 128 * 1024))
            tail = handle.read()
    except OSError:
        return False
    if _MMDB_MARKER not in tail:
        return False
    opener = open_database
    if opener is None:
        try:
            import maxminddb
            opener = maxminddb.open_database
        except ImportError:
            return True                 # the marker is all that can be checked
    try:
        opener(path).close()
    except Exception:
        return False
    return True


def update(directory, fetch=None, now=None, timeout=60, open_database=None):
    """
    Download both databases into `directory`, replacing each atomically.

    Each file is downloaded to a temporary name beside the final one,
    decompressed, checked, and only then renamed into place — so a lookup in
    a running service sees the old file or the new one, never half of one. A
    failed download leaves the previous file untouched.

    Returns {kind: {'url', 'bytes', 'month'}}; raises GeoIPError if neither
    could be fetched.
    """
    fetch = fetch or _fetch
    now = time.time() if now is None else now
    os.makedirs(directory, exist_ok=True)
    done, problems = {}, {}

    for kind, (pattern, filename) in DATABASES.items():
        final = os.path.join(directory, filename)
        for month in _months(now):
            url = pattern.format(month=month)
            compressed = final + '.download'
            expanded = final + '.new'
            try:
                response = fetch(url, timeout)
                try:
                    status = getattr(response, 'status', 200)
                    if status != 200:
                        raise GeoIPError(f'HTTP {status}')
                    with open(compressed, 'wb') as out:
                        total = 0
                        while True:
                            chunk = response.read(1 << 20)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > MAX_DATABASE_BYTES:
                                raise GeoIPError('download larger than any real '
                                                 'database')
                            out.write(chunk)
                finally:
                    close = getattr(response, 'close', None)
                    if close is not None:
                        close()
                written = 0
                with gzip.open(compressed, 'rb') as source, \
                        open(expanded, 'wb') as out:
                    while True:
                        chunk = source.read(1 << 20)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > MAX_DATABASE_BYTES:
                            raise GeoIPError('decompresses to more than any real '
                                             'database')
                        out.write(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                if not _valid_mmdb(expanded, open_database):
                    raise GeoIPError('not a readable MMDB file')
                os.replace(expanded, final)
                done[kind] = {'url': url, 'bytes': written, 'month': month}
                problems.pop(kind, None)
                break
            except (GeoIPError, OSError, EOFError, ValueError, zlib.error) as e:
                # A month not published yet answers 404; try the one before.
                problems[kind] = f'{url}: {type(e).__name__}: {e}'
            finally:
                for leftover in (compressed, expanded):
                    try:
                        os.remove(leftover)
                    except OSError:
                        pass

    if done:
        _write_source(directory, done, now)
    if not done:
        raise GeoIPError('could not download either database: '
                         + '; '.join(problems.values()))
    for kind, problem in problems.items():
        logger.warning('%s database not updated: %s', kind, problem)
    return done


def _write_source(directory, done, now):
    path = os.path.join(directory, 'SOURCE.txt')
    lines = [ATTRIBUTION, '',
             f'Downloaded {time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(now))}:']
    lines += [f'  {kind}: {info["url"]}' for kind, info in sorted(done.items())]
    temporary = path + '.tmp'
    try:
        with open(temporary, 'w', encoding='utf-8') as handle:
            handle.write('\n'.join(lines) + '\n')
        os.replace(temporary, path)
    except OSError as e:
        logger.warning('could not write %s: %s', path, e)


def status(directory, now=None):
    """What is installed, how big, and how old."""
    now = time.time() if now is None else now
    out = {}
    for kind, (_, filename) in DATABASES.items():
        path = os.path.join(directory, filename)
        try:
            stat = os.stat(path)
        except OSError:
            out[kind] = {'path': path, 'present': False}
            continue
        age = (now - stat.st_mtime) / 86400
        out[kind] = {'path': path, 'present': True, 'bytes': stat.st_size,
                     'age_days': round(age, 1), 'stale': age > STALE_DAYS}
    return out


def _main(argv=None):
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog='python -m netmon geoip',
        description='Country and network (ASN) lookups from DB-IP Lite, read '
                    'offline. ' + ATTRIBUTION + '.')
    parser.add_argument('--dir', default=os.environ.get('NETMON_GEOIP_DIR', ''),
                        help='where the databases live (or NETMON_GEOIP_DIR). '
                             'Put the same path under geoip: directory: in the '
                             'profile')
    parser.add_argument('--profile', help='read the directory from this profile')
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--update', action='store_true',
                        help='download both databases from DB-IP and replace '
                             'the installed ones atomically. Sends nothing '
                             'about this network')
    action.add_argument('--lookup', metavar='IP', help='look one address up')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)

    directory = args.dir
    if args.profile and not directory:
        from netmon.profile import ProfileError, load_profile
        try:
            directory = load_profile(args.profile).geoip_dir
        except ProfileError as e:
            print(f'profile: {e}', file=sys.stderr)
            return 1
    if not directory:
        parser.error('pass --dir, set NETMON_GEOIP_DIR, or name a profile with '
                     'geoip: directory: set')

    if args.update:
        try:
            done = update(directory)
        except GeoIPError as e:
            print(str(e), file=sys.stderr)
            return 1
        for kind, info in sorted(done.items()):
            print(f'{kind}: {info["bytes"] / 1048576:.1f} MB from {info["url"]}')
        print(ATTRIBUTION)
        return 0 if len(done) == len(DATABASES) else 1

    if args.lookup:
        result = GeoIP(directory).lookup(args.lookup)
        print(json.dumps(result) if args.json else
              (', '.join(f'{k}: {v}' for k, v in result.items()) or 'not found'))
        return 0

    report = status(directory)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for kind, info in report.items():
            if not info['present']:
                print(f'{kind:8} missing — run: python -m netmon geoip --update '
                      f'--dir {directory}')
            else:
                print(f'{kind:8} {info["bytes"] / 1048576:.1f} MB, '
                      f'{info["age_days"]:g} days old'
                      + ('  (stale: update it)' if info['stale'] else ''))
        print(ATTRIBUTION)
    return 0 if all(info['present'] for info in report.values()) else 1


if __name__ == '__main__':
    import sys
    from netmon.geoip import _main as main
    sys.exit(main())
