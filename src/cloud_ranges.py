"""
Published cloud and CDN address ranges.
========================================
Clouds and CDNs publish the address blocks they own. Addresses in them are
shared and recycled: today's attacker VM is tomorrow's customer website, and a
CDN edge serves thousands of unrelated sites from one address. Feeds that list
attacking hosts (blocklist.de, the Emerging Threats compromised list, DShield)
are right that a scan came from such an address, and wrong to imply that
connecting *to* it is a compromise.

The ranges ship as a dated file, rules/cloud_ranges.json, so nothing is fetched
at run time. Refresh it with:

    python -m src.cloud_ranges --update

which downloads each provider's own published list and writes the file again.
A copy in ~/.netsentinel/rules/ overrides the bundled one.
"""

import argparse
import bisect
import csv
import io
import ipaddress
import json
import logging
import os
import re
import sys
import threading
from datetime import date

logger = logging.getLogger("NetSentinel.CloudRanges")

__all__ = ['CloudRanges', 'get_cloud_ranges']

FILE_NAME = 'cloud_ranges.json'

# Each provider's own publication. `kind` separates CDNs (one address, many
# unrelated sites) from clouds (rented machines); both are shared.
SOURCES = {
    'cloudflare': {
        'kind': 'cdn',
        'urls': ['https://www.cloudflare.com/ips-v4', 'https://www.cloudflare.com/ips-v6'],
        'format': 'lines',
    },
    'fastly': {
        'kind': 'cdn',
        'urls': ['https://api.fastly.com/public-ip-list'],
        'format': 'fastly',
    },
    'aws-cloudfront': {
        'kind': 'cdn',
        'urls': ['https://ip-ranges.amazonaws.com/ip-ranges.json'],
        'format': 'aws-cloudfront',
    },
    'aws': {
        'kind': 'cloud',
        'urls': ['https://ip-ranges.amazonaws.com/ip-ranges.json'],
        'format': 'aws',
    },
    'google': {
        'kind': 'cloud',
        'urls': ['https://www.gstatic.com/ipranges/goog.json'],
        'format': 'google',
    },
    'oracle': {
        'kind': 'cloud',
        'urls': ['https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json'],
        'format': 'oracle',
    },
    'digitalocean': {
        'kind': 'cloud',
        'urls': ['https://digitalocean.com/geo/google.csv'],
        'format': 'csv-first-column',
    },
    'linode': {
        'kind': 'cloud',
        'urls': ['https://geoip.linode.com/'],
        'format': 'csv-first-column',
    },
}


def _candidates():
    paths = []
    try:
        from src.config import RULES_DIR
        paths.append(os.path.join(RULES_DIR, FILE_NAME))
    except Exception:
        pass
    base = getattr(sys, '_MEIPASS', None) or os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    paths.append(os.path.join(base, 'rules', FILE_NAME))
    return paths


class CloudRanges:
    """
    Address -> provider lookups. One sorted, non-overlapping table per provider
    (each provider's list is collapsed when built), searched with bisect. CDNs
    are searched first, since a CDN's block can sit inside its cloud's.
    """

    def __init__(self, data=None):
        data = data or {}
        self.generated = data.get('generated', '')
        self.providers = {}
        self._tables = {}          # name -> {version: (starts, ends)}
        self.prefix_count = 0
        for name, entry in (data.get('providers') or {}).items():
            self.providers[name] = entry.get('kind', 'cloud')
            per_version = {4: [], 6: []}
            for key in ('v4', 'v6'):
                for cidr in entry.get(key, ()):
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                    except ValueError:
                        continue
                    per_version[net.version].append(
                        (int(net.network_address), int(net.broadcast_address)))
            table = {}
            for version, items in per_version.items():
                items.sort()
                table[version] = ([s for s, _ in items], [e for _, e in items])
                self.prefix_count += len(items)
            self._tables[name] = table
        self._order = sorted(self._tables, key=lambda n: self.providers[n] != 'cdn')

    def provider(self, ip):
        """The provider whose published range holds `ip`, or None."""
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return None
        value = int(addr)
        for name in self._order:
            starts, ends = self._tables[name].get(addr.version, ((), ()))
            idx = bisect.bisect_right(starts, value) - 1
            # Collapsed ranges do not overlap, so only the nearest start can hold it.
            if idx >= 0 and value <= ends[idx]:
                return name
        return None

    def kind(self, ip):
        name = self.provider(ip)
        return self.providers.get(name) if name else None

    def is_cdn(self, ip):
        return self.kind(ip) == 'cdn'

    def __contains__(self, ip):
        return self.provider(ip) is not None


_lock = threading.Lock()
_shared = None


def load_data():
    for path in _candidates():
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding='utf-8') as f:
                return json.load(f)
        except (OSError, ValueError) as e:
            logger.error("Could not load %s: %s", path, e)
    return {}


def get_cloud_ranges():
    """The process-wide table, loaded once."""
    global _shared
    with _lock:
        if _shared is None:
            _shared = CloudRanges(load_data())
            if _shared.prefix_count:
                logger.info("Cloud/CDN ranges: %d prefixes, generated %s",
                            _shared.prefix_count, _shared.generated or 'unknown')
        return _shared


# ─── Building the file ───────────────────────────────────────────────────────

def _parse(fmt, text):
    """CIDR strings from one provider document."""
    if fmt == 'lines':
        return [line.strip() for line in text.splitlines() if line.strip()]
    if fmt == 'fastly':
        doc = json.loads(text)
        return list(doc.get('addresses', [])) + list(doc.get('ipv6_addresses', []))
    if fmt in ('aws', 'aws-cloudfront'):
        doc = json.loads(text)
        want = (lambda s: s == 'CLOUDFRONT') if fmt == 'aws-cloudfront' else (lambda s: True)
        out = [p['ip_prefix'] for p in doc.get('prefixes', []) if want(p.get('service'))]
        out += [p['ipv6_prefix'] for p in doc.get('ipv6_prefixes', []) if want(p.get('service'))]
        return out
    if fmt == 'google':
        doc = json.loads(text)
        return [p.get('ipv4Prefix') or p.get('ipv6Prefix') for p in doc.get('prefixes', [])]
    if fmt == 'oracle':
        doc = json.loads(text)
        return [c['cidr'] for region in doc.get('regions', []) for c in region.get('cidrs', [])]
    if fmt == 'csv-first-column':
        out = []
        for row in csv.reader(io.StringIO(text)):
            if row and not row[0].startswith('#'):
                out.append(row[0].strip())
        return out
    raise ValueError(f'unknown format {fmt}')


def _collapse(cidrs):
    v4, v6 = [], []
    for cidr in cidrs:
        if not cidr or not re.match(r'^[0-9a-fA-F:.]+/\d{1,3}$', cidr):
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        (v4 if net.version == 4 else v6).append(net)
    return ([str(n) for n in ipaddress.collapse_addresses(v4)],
            [str(n) for n in ipaddress.collapse_addresses(v6)])


def build(fetch, sources=None, today=None):
    """
    Build the file's contents. `fetch(url) -> str` does the downloading, so this
    is testable without a network. A provider that fails is left out and named
    in `failed`, rather than failing the whole file.
    """
    sources = sources or SOURCES
    providers, failed, cache = {}, {}, {}
    for name, spec in sources.items():
        cidrs = []
        try:
            for url in spec['urls']:
                if url not in cache:
                    cache[url] = fetch(url)
                cidrs.extend(_parse(spec['format'], cache[url]))
        except Exception as e:
            failed[name] = str(e)[:200]
            continue
        v4, v6 = _collapse(cidrs)
        if v4 or v6:
            providers[name] = {'kind': spec['kind'], 'v4': v4, 'v6': v6}
    return {
        'generated': (today or date.today()).isoformat(),
        'note': 'Published address ranges of clouds and CDNs. Regenerate with '
                'python -m src.cloud_ranges --update',
        'sources': {name: spec['urls'] for name, spec in sources.items() if name in providers},
        'failed': failed,
        'providers': providers,
    }


def _http_fetch(url, limit=32 * 1024 * 1024):
    import urllib.request
    req = urllib.request.Request(url, headers={'User-Agent': 'NetSentinel cloud-range update'})
    with urllib.request.urlopen(req, timeout=60) as response:
        if not response.geturl().lower().startswith('https://'):
            raise ValueError(f'redirected off HTTPS: {response.geturl()}')
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('document too large')
    return data.decode('utf-8', errors='replace')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--update', action='store_true',
                        help="download each provider's published ranges")
    parser.add_argument('--out', default=os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'rules', FILE_NAME))
    args = parser.parse_args(argv)
    if not args.update:
        table = CloudRanges(load_data())
        print(f"{table.prefix_count} prefixes, generated {table.generated or 'unknown'}")
        return 0
    data = build(_http_fetch)
    tmp = args.out + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=0, sort_keys=True)
    os.replace(tmp, args.out)
    counts = {n: len(p['v4']) + len(p['v6']) for n, p in data['providers'].items()}
    print(f"Wrote {args.out}: {counts}; failed: {data['failed'] or 'none'}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
