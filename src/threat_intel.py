"""
Threat Intelligence Engine
===========================
Downloads and caches free, public threat intelligence feeds.
Checks IPs and domains against known malicious indicators.
Auto-refreshes feeds periodically.

Every lookup is local: feeds are downloaded as whole lists and matched here, so
nothing about this machine's traffic is sent anywhere.

Sources (all free; those marked * need the free abuse.ch Auth-Key):
- abuse.ch Feodo Tracker (botnet C2 IPs)
- abuse.ch SSL Blacklist (malicious SSL IPs, and JA3 client fingerprints)
- abuse.ch URLhaus* (malicious URLs/domains)
- abuse.ch ThreatFox* (C2 addresses with ports, domains, URLs, file hashes)
- abuse.ch MalwareBazaar* (malware file hashes, for file scans)
- Emerging Threats compromised IPs
- DShield top attacking /24 blocks
- blocklist.de brute-force and scanner IPs
- CINS Army attacking hosts
- Spamhaus DROP hijacked and criminal networks (credit: The Spamhaus Project)
- Tor Project relay addresses (marks Tor, not malice)
- WhoisDS newly registered domains (daily list, opt-out via config)
FoxIO's JA4DB is not used: it went behind an enterprise sign-up in 2026.
"""

import os
import re
import csv
import time
import json
import array
import bisect
import hashlib
import logging
import threading
import ipaddress
import zipfile
import io
import base64
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlsplit, urlunsplit

logger = logging.getLogger("NetSentinel.ThreatIntel")

try:
    import urllib.request
    URLLIB_AVAILABLE = True
except ImportError:
    URLLIB_AVAILABLE = False

# Hard ceiling on a single feed download. The largest real feed here is a few MB.
MAX_FEED_BYTES = 64 * 1024 * 1024

# ─── Feed Definitions ───────────────────────────────────────────────────────
#
# `attacker`: the feed lists hosts seen *attacking* (scanning, brute forcing).
# Those are right about where an attack came from, and say little about a
# connection this machine makes *to* the address — especially inside a cloud or
# CDN, where addresses are shared and recycled. See src/cloud_ranges.py.
#
# `background`: downloaded only by the background updater, never while the
# engine is being constructed, so a slow or unreachable host cannot hold up
# startup. Older feeds keep their existing behaviour.

THREAT_FEEDS = {
    "feodo_c2": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "ip",
        "category": "Botnet C2",
        "description": "Feodo Tracker - Active botnet C2 servers",
        "refresh_hours": 6,
        "parser": "comment_lines",
    },
    "sslbl_ips": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "type": "ip",
        "category": "Malicious SSL",
        "description": "SSL Blacklist - IPs with malicious SSL certificates",
        "refresh_hours": 12,
        "parser": "comment_lines",
    },
    "urlhaus_domains": {
        # The keyless text_online export now answers 410 Gone: since mid-2025 every
        # URLhaus export needs a (free) abuse.ch Auth-Key in the URL. Without one
        # in threat_intel.abuse_ch_auth_key this feed is skipped, not retried.
        "url": "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv",
        "needs_auth_key": True,
        "type": "url",
        "category": "Malware Distribution",
        "description": "URLhaus - Active malware distribution URLs",
        "refresh_hours": 6,
        "parser": "url_lines",
    },
    "et_compromised": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip",
        "category": "Compromised Host",
        "description": "Emerging Threats - Known compromised IPs",
        "refresh_hours": 12,
        "parser": "plain_ips",
        "attacker": True,
    },
    "dshield_top": {
        "url": "https://feeds.dshield.org/block.txt",
        "type": "ip",
        "category": "Active Attacker",
        "description": "DShield - Top attacking /24 subnets (last 3 days)",
        "refresh_hours": 4,
        "parser": "dshield",
        "attacker": True,
    },
    "blocklist_de": {
        "url": "https://lists.blocklist.de/lists/all.txt",
        "type": "ip",
        "category": "Brute Force / Scanner",
        "description": "blocklist.de - Brute force and scanner IPs",
        "refresh_hours": 12,
        "parser": "plain_ips",
        "attacker": True,
    },
    "cins_army": {
        # Sentinel IPS's list of hosts its sensors saw attacking, capped at
        # 15,000. Free to use as you see fit, it says; also in ET's community set.
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "type": "ip",
        "category": "Active Attacker",
        "description": "CINS Army - Hosts seen attacking Sentinel IPS sensors",
        "refresh_hours": 12,
        "parser": "plain_ips",
        "attacker": True,
        "background": True,
    },
    "spamhaus_drop_v4": {
        # Don't Route Or Peer: networks hijacked or run by criminals, which no
        # one should be talking to at all. Free to use with credit to Spamhaus,
        # its date and copyright kept with the data (the file's last line).
        # Spamhaus asks for no more than one download a day.
        "url": "https://www.spamhaus.org/drop/drop_v4.json",
        "type": "network",
        "category": "Hijacked Network",
        "description": "Spamhaus DROP - Hijacked and criminal networks (IPv4)",
        "refresh_hours": 24,
        "parser": "spamhaus_ndjson",
        "background": True,
    },
    "spamhaus_drop_v6": {
        "url": "https://www.spamhaus.org/drop/drop_v6.json",
        "type": "network",
        "category": "Hijacked Network",
        "description": "Spamhaus DROP - Hijacked and criminal networks (IPv6)",
        "refresh_hours": 24,
        "parser": "spamhaus_ndjson",
        "background": True,
    },
    "tor_relays": {
        # Every running relay's OR addresses, from the Tor Project's Onionoo
        # (CC0). Not malicious: it says a connection is Tor, where the old test
        # was a port number. The field list keeps it to ~2 MB from 64.
        "url": ("https://onionoo.torproject.org/details?type=relay&running=true"
                "&fields=or_addresses,exit_addresses"),
        "type": "tor",
        "category": "Tor Relay",
        "description": "Tor Project - Addresses of running Tor relays",
        "refresh_hours": 6,
        "max_age_hours": 7 * 24,
        "parser": "onionoo",
        "background": True,
    },
    "threatfox": {
        # abuse.ch's indicators of compromise: C2 addresses with their ports,
        # domains, URLs and file hashes, the last few days' worth. Needs the free
        # Auth-Key, for not-for-profit use (abuse.ch terms 3.1). Listed after the
        # address feeds, so an address one of them lists on every port keeps
        # that listing; ThreatFox's are matched on their port only.
        "url": "https://threatfox-api.abuse.ch/v2/files/exports/{auth_key}/recent.json",
        "needs_auth_key": True,
        "type": "mixed",
        "category": "Malware C2 / Delivery",
        "description": "ThreatFox - Malware C2 addresses, domains and URLs",
        "refresh_hours": 6,
        "parser": "threatfox_json",
        "hash_export": True,
        "background": True,
    },
    "malwarebazaar_recent": {
        # SHA-256 of samples from the last 48 hours, for file scans. Written to
        # the hash lists folder (src/hash_feed.py), never parsed here.
        "url": "https://mb-api.abuse.ch/v2/files/exports/{auth_key}/sha256_recent.txt",
        "needs_auth_key": True,
        "type": "sha256",
        "category": "Malware",
        "description": "MalwareBazaar - Malware file hashes, last 48 hours",
        "refresh_hours": 6,
        "store": "hash_lists",
        "background": True,
    },
    "malwarebazaar_full": {
        # Every sample's SHA-256, about 1.2 million: a 39 MB zip, so weekly.
        "url": "https://mb-api.abuse.ch/v2/files/exports/{auth_key}/sha256_full.txt.zip",
        "needs_auth_key": True,
        "type": "sha256",
        "category": "Malware",
        "description": "MalwareBazaar - Malware file hashes, all",
        "refresh_hours": 168,
        "store": "hash_lists",
        "zip": True,
        "background": True,
    },
    "sslbl_ja3": {
        # abuse.ch stopped adding to this list in August 2021, and it says itself
        # that the fingerprints were not tested against good traffic; the site was
        # also not answering when this was written. Off unless
        # threat_intel.ja3_feed is set. Matches are reported at MEDIUM.
        "url": "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
        "optional": "ja3_feed",
        "type": "ja3",
        "category": "Malicious TLS Client",
        "description": "SSL Blacklist - JA3 fingerprints of malware TLS clients",
        "refresh_hours": 168,
        "max_age_hours": 24 * 90,
        "parser": "ja3_csv",
        "background": True,
    },
}

# A cached feed older than this is no longer used: addresses get reassigned, so a
# list nobody has refreshed in a week accuses whoever has them now.
DEFAULT_MAX_FEED_AGE_HOURS = 7 * 24

# Status codes that will not fix themselves by retrying. The feed is left alone
# for a week after one, and the reason logged once.
PERMANENT_HTTP_ERRORS = (401, 403, 404, 410)
PERMANENT_RETRY_SEC = 7 * 86400
TRANSIENT_RETRY_SEC = 3600

# Newly registered domains: WhoisDS publishes yesterday's registrations as a
# free daily zip ("may be reused, including for commercial purposes, without a
# license and without any payment"). The file name is the date, base64-encoded.
NRD_URL = "https://www.whoisds.com//whois-database/newly-registered-domains/{token}/nrd"
NRD_MAX_DAYS = 30

# Known suspicious/malicious domains (built-in, no download needed)
BUILTIN_SUSPICIOUS_DOMAINS = {
    # Common dynamic DNS used by malware
    "no-ip.com", "no-ip.org", "no-ip.biz", "ddns.net",
    "duckdns.org", "freedns.afraid.org", "changeip.com",
    "hopto.org", "zapto.org", "sytes.net", "serveftp.com",
    # Known malicious TLDs (high abuse rate)
    # (checked by suffix, not exact match)
}

# Stored WITHOUT a leading dot and matched against the final DNS label only.
# Suffix-matching the raw string instead (`domain.endswith('rest')`) also matches
# 'forest', 'webcam', 'network', 'uplink' and 'homework' — all of which appear as
# single-label LLMNR/NetBIOS lookups on Windows networks.
SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "tk", "ml", "ga", "cf", "gq",
    "work", "click", "link", "icu", "monster", "rest",
    "cam", "surf", "ooo", "sbs", "cyou",
}


# URL feeds list malware *links*, and a great many of those are hosted on
# platforms everyone uses. A bad file on github.com says nothing about
# github.com, so these hosts never become malicious domains; the full URL is
# still matched exactly.
#
# Only hosts where the uploader lives in the *path* belong here. On hosting where
# the uploader picks the *subdomain* (evil.pages.dev, evil.herokuapp.com — see
# net_detect.CLOUD_HOSTING_DOMAINS), that subdomain is theirs and is a fair
# indicator, so those are not listed and their tenants can be flagged.
SHARED_HOSTING = (
    # Code hosting
    'github.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org',
    'gitee.com', 'codeberg.org', 'sourceforge.net',
    # Big-provider storage and documents
    'google.com', 'googleusercontent.com', 'googleapis.com', 'goo.gl',
    'dropbox.com', 'dropboxusercontent.com', 'onedrive.live.com', 'live.com', '1drv.ms',
    'sharepoint.com', 'microsoft.com', 'windows.net', 'azureedge.net', 'office.com',
    'amazonaws.com', 'cloudfront.net', 'icloud.com', 'box.com',
    'yandex.ru', 'yadi.sk',
    # Chat attachments
    'discord.com', 'discordapp.com', 'discordapp.net', 't.me', 'telegram.org',
    # File hosts and paste sites
    'mediafire.com', 'archive.org', 'pastebin.com', 'paste.ee', 'mega.nz',
    'wetransfer.com', 'we.tl', 'transfer.sh', 'catbox.moe', 'gofile.io',
    'pixeldrain.com', 'imgur.com', 'sendspace.com', 'file.io', 'filebin.net',
    'temp.sh', '0x0.st', 'uguu.se', 'anonfiles.com', 'ufile.io',
    # IPFS gateways: the content address is in the path
    'ipfs.io', 'dweb.link', 'cloudflare-ipfs.com', 'gateway.pinata.cloud',
    'w3s.link', 'nftstorage.link',
    # URL shorteners: the link is in the path, and the shortener is everyone's
    'bit.ly', 'tinyurl.com', 'is.gd', 'v.gd', 'cutt.ly', 'rb.gy', 't.ly',
    'shorturl.at', 'ow.ly', 'buff.ly', 'rebrand.ly', 'tiny.cc', 'goo.su',
    's.id', 'qrco.de', 'bl.ink', 'short.io', 'bitly.com', 'lnkd.in', 'shorturl.com',
)

_SHARED_HOSTING_SET = frozenset(SHARED_HOSTING)


def _suffix_in(host, suffixes):
    """True if `host` is, or is under, any domain in `suffixes`."""
    if host in suffixes:
        return True
    idx = host.find('.')
    while idx != -1:
        if host[idx + 1:] in suffixes:
            return True
        idx = host.find('.', idx + 1)
    return False


def is_shared_hosting(host):
    """
    A host whose name says nothing about what it serves: shared file and code
    hosting, plus the first-party services in net_detect.KNOWN_CLOUD_DOMAINS.
    The two lists used to disagree, so a host one exempted the other flagged.
    """
    host = (host or '').lower().rstrip('.')
    if not host:
        return False
    if _suffix_in(host, _SHARED_HOSTING_SET):
        return True
    from src.net_detect import KNOWN_CLOUD_DOMAINS
    return _suffix_in(host, KNOWN_CLOUD_DOMAINS)


def is_dynamic_dns(domain):
    """
    The dynamic-DNS provider `domain` is under, or None. On a label boundary:
    a bare endswith() made myfooddns.net a "ddns.net" host.
    """
    domain = (domain or '').lower().rstrip('.')
    for dyn in BUILTIN_SUSPICIOUS_DOMAINS:
        if domain == dyn or domain.endswith('.' + dyn):
            return dyn
    return None


def normalize_url(url):
    """
    A URL in the form feeds and observed requests are compared in: scheme and
    host lowercased, a default port dropped, no fragment. The path and query
    keep their case — on most servers they are case-sensitive.
    """
    if not url:
        return ''
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return ''
    scheme = parts.scheme.lower()
    if scheme not in ('http', 'https'):
        return ''
    host = (parts.hostname or '').lower().rstrip('.')
    if not host:
        return ''
    try:
        port = parts.port
    except ValueError:
        return ''
    if ':' in host:
        host = f'[{host}]'
    netloc = host if port in (None, 80 if scheme == 'http' else 443) else f'{host}:{port}'
    return urlunsplit((scheme, netloc, parts.path or '/', parts.query, ''))


def tld_of(domain):
    """Return the final DNS label, lowercased. Empty for single-label names."""
    if not domain:
        return ''
    domain = domain.rstrip('.').lower()
    return domain.rsplit('.', 1)[-1] if '.' in domain else ''

# Suspicious user-agent patterns
SUSPICIOUS_USER_AGENTS = [
    "python-requests", "go-http-client", "curl/", "wget/",
    "powershell", "certutil", "mshta", "wscript", "cscript",
]


class _NetworkIndex:
    """
    Listed networks, found by bisection. A linear scan was fine for DShield's
    twenty /24s and not for Spamhaus DROP's thousands of blocks, checked for
    every new address. Networks can overlap, so each entry keeps the furthest
    end of any network starting at or before it, and the search walks back
    only while that end still covers the address.
    """

    def __init__(self, networks=()):
        self._by_version = {}
        for version in (4, 6):
            rows = sorted(((int(n.network_address), int(n.broadcast_address), n, info)
                           for n, info in networks if n.version == version),
                          key=lambda r: (r[0], -r[1]))
            reach, furthest = [], -1
            for row in rows:
                furthest = max(furthest, row[1])
                reach.append(furthest)
            self._by_version[version] = ([r[0] for r in rows], rows, reach)
        self.count = sum(len(v[1]) for v in self._by_version.values())

    def __len__(self):
        return self.count

    def lookup(self, addr):
        """(network, info) of the most specific listed network holding addr."""
        starts, rows, reach = self._by_version.get(addr.version, ((), (), ()))
        value = int(addr)
        best = None
        i = bisect.bisect_right(starts, value) - 1
        while i >= 0 and reach[i] >= value:
            start, end, network, info = rows[i]
            if start <= value <= end and (best is None or network.prefixlen > best[0].prefixlen):
                best = (network, info)
            i -= 1
        return best


def _domain_hash(domain):
    return int.from_bytes(hashlib.blake2b(domain.encode('utf-8', 'ignore'),
                                          digest_size=8).digest(), 'big')


class ThreatIntelEngine:
    """
    Manages threat intelligence feeds and provides lookup capabilities.
    Downloads, caches, and periodically refreshes threat data.
    """

    def __init__(self, config):
        from src.config import DB_DIR
        self.config = config
        self.cache_dir = os.path.join(DB_DIR, "threat_intel")
        os.makedirs(self.cache_dir, exist_ok=True)

        self.enabled = config.get('threat_intel', 'enabled', default=True)
        self.auto_update = config.get('threat_intel', 'auto_update', default=True)
        self.nrd_enabled = config.get('threat_intel', 'newly_registered_domains', default=True)
        self.nrd_days = max(1, min(NRD_MAX_DAYS, int(
            config.get('threat_intel', 'nrd_days', default=7) or 7)))
        # A free key from https://auth.abuse.ch/ — URLhaus exports need one now.
        # A secret: it goes in the request URL, never in a log line.
        self.abuse_ch_auth_key = str(
            config.get('threat_intel', 'abuse_ch_auth_key', default='') or '').strip()
        self.optional_feeds = {
            'ja3_feed': bool(config.get('threat_intel', 'ja3_feed', default=False)),
        }
        self._reported = set()      # (feed, reason) already logged this run

        # Lookup tables. Rebuilt whole on every load and swapped in under the
        # lock, so an indicator a feed has dropped stops matching.
        self._malicious_ips = {}       # {ip: {feed, category, description}}
        self._malicious_domains = {}   # {domain: {feed, category, description}}
        self._malicious_urls = set()
        self._ip_networks = _NetworkIndex()   # listed networks, for CIDR matching
        self._feed_counts = {}         # {feed: indicators in its last load}
        self._tor_endpoints = frozenset()   # {(ip, port)}: running relays' OR ports
        self._tor_ips = frozenset()
        self._malicious_ja3 = {}       # {md5: {feed, category, description, malware}}
        self._nrd_hashes = array.array('Q')   # sorted blake2b-64 of registrable domains
        self._nrd_dates = []

        # Stats
        self.stats = {
            'total_ips': 0,
            'total_domains': 0,
            'total_urls': 0,
            'total_networks': 0,
            'total_ja3': 0,
            'newly_registered_domains': 0,
            'feeds_loaded': 0,
            'feeds_failed': 0,
            'last_update': None,
            'lookups_performed': 0,
            'threats_found': 0,
        }

        # Feed metadata (last update times)
        self._meta_path = os.path.join(self.cache_dir, "feed_meta.json")
        self._feed_meta = self._load_meta()

        self._lock = threading.Lock()

        # Initial load from cache
        self._load_all_feeds(initial=True)
        self._load_nrd()

        # Background updater
        if self.enabled and self.auto_update:
            self._updater_thread = threading.Thread(
                target=self._update_loop, daemon=True, name="ThreatIntelUpdate"
            )
            self._updater_thread.start()

        logger.info(
            "Threat Intel initialized: %d IPs, %d domains, %d URLs from %d feeds",
            self.stats['total_ips'], self.stats['total_domains'],
            self.stats['total_urls'], self.stats['feeds_loaded']
        )

    def check_ip(self, ip):
        """
        Check if an IP is in any threat feed.

        Returns:
            dict or None: {feed, category, description, attacker_feed} if listed
        """
        if not self.enabled or not ip:
            return None

        self.stats['lookups_performed'] += 1

        # Skip private/local IPs
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return None
        except ValueError:
            return None

        # Direct IP match
        with self._lock:
            if ip in self._malicious_ips:
                self.stats['threats_found'] += 1
                return self._malicious_ips[ip].copy()

            hit = self._ip_networks.lookup(addr)
            if hit:
                network, feed_info = hit
                self.stats['threats_found'] += 1
                result = feed_info.copy()
                result['matched_network'] = str(network)
                return result

        return None

    def check_domain(self, domain):
        """
        Check if a domain is in any threat feed or matches suspicious patterns.

        Returns:
            dict or None: {feed, category, description, confidence} if suspicious
        """
        if not self.enabled or not domain:
            return None

        self.stats['lookups_performed'] += 1
        domain = domain.lower().strip('.')

        with self._lock:
            # Exact domain match
            if domain in self._malicious_domains:
                self.stats['threats_found'] += 1
                result = self._malicious_domains[domain].copy()
                result['confidence'] = 'HIGH'
                result['match_type'] = 'exact'
                return result

            # Parent domain match (e.g., if evil.com is listed, sub.evil.com matches)
            parts = domain.split('.')
            for i in range(1, len(parts) - 1):
                parent = '.'.join(parts[i:])
                if parent in self._malicious_domains:
                    self.stats['threats_found'] += 1
                    result = self._malicious_domains[parent].copy()
                    result['confidence'] = 'MEDIUM'
                    result['match_type'] = 'parent_domain'
                    result['matched_domain'] = parent
                    return result

        # Dynamic DNS check
        dyn_domain = is_dynamic_dns(domain)
        if dyn_domain:
            return {
                'feed': 'builtin',
                'category': 'Dynamic DNS',
                'description': f'Domain uses dynamic DNS service ({dyn_domain})',
                'confidence': 'LOW',
                'match_type': 'dynamic_dns',
            }

        # Suspicious TLD check
        tld = tld_of(domain)
        if tld in SUSPICIOUS_TLDS:
            return {
                'feed': 'builtin',
                'category': 'Suspicious TLD',
                'description': f'Domain uses high-abuse TLD (.{tld})',
                'confidence': 'LOW',
                'match_type': 'suspicious_tld',
            }

        return None

    def check_url(self, url):
        """Check if a URL matches known malicious URLs (compared normalised)."""
        if not self.enabled or not url:
            return None
        self.stats['lookups_performed'] += 1
        normalised = normalize_url(url)
        if not normalised:
            return None
        with self._lock:
            if normalised in self._malicious_urls:
                self.stats['threats_found'] += 1
                return {
                    'feed': 'urlhaus_domains',
                    'category': 'Malware Distribution',
                    'description': 'URL found in URLhaus malware database',
                    'confidence': 'HIGH',
                    'matched_url': normalised,
                }
        return None

    def check_ja3(self, ja3):
        """A JA3 client fingerprint on the downloaded blocklist, or None."""
        if not self.enabled or not ja3:
            return None
        with self._lock:
            hit = self._malicious_ja3.get(ja3.lower())
        if hit:
            self.stats['threats_found'] += 1
            return dict(hit)
        return None

    def is_tor_relay(self, ip, port=None):
        """Whether ip (and port, when given) is a running Tor relay's OR address."""
        if not self.enabled or not ip:
            return False
        if port is None:
            return ip in self._tor_ips
        return (ip, int(port)) in self._tor_endpoints

    def check_new_domain(self, domain):
        """
        The registrable domain if it appears in the recent newly-registered
        lists, else None. Matched on the registrable part, since the lists hold
        registrations, not hostnames.
        """
        if not self.enabled or not self.nrd_enabled or not domain:
            return None
        from src.public_suffix import registrable_domain
        base = registrable_domain(domain)
        if not base:
            return None
        h = _domain_hash(base)
        with self._lock:
            hashes = self._nrd_hashes
            idx = bisect.bisect_left(hashes, h)
            found = idx < len(hashes) and hashes[idx] == h
            days = list(self._nrd_dates)
        if not found:
            return None
        return {
            'feed': 'whoisds_nrd',
            'category': 'Newly Registered Domain',
            'registered_domain': base,
            'lists_checked': f"{days[0]} to {days[-1]}" if days else '',
            'description': (f'{base} was registered within the last '
                            f'{len(days) or self.nrd_days} days.'),
        }

    # ─── Feed Management ─────────────────────────────────────────────────

    def _http_get(self, url, limit=MAX_FEED_BYTES):
        """One bounded HTTPS download. Tests replace this."""
        req = urllib.request.Request(url, headers={
            'User-Agent': 'NetSentinel/1.0 ThreatIntel'
        })
        with urllib.request.urlopen(req, timeout=30) as response:
            if not response.geturl().lower().startswith('https://'):
                raise ValueError(f"feed redirected off HTTPS: {response.geturl()}")
            # Bounded read: response.read() with no limit lets a compromised or
            # misconfigured feed return an arbitrarily large body.
            raw = response.read(limit + 1)
        if len(raw) > limit:
            raise ValueError(f"feed exceeded {limit // (1024 * 1024)} MB limit")
        return raw

    def _log_once(self, feed_name, reason, message, *args, level=logging.WARNING):
        if (feed_name, reason) not in self._reported:
            self._reported.add((feed_name, reason))
            logger.log(level, message, *args)

    def _feed_url(self, feed_config):
        """The download URL, or None when it needs a key that is not configured."""
        url = feed_config['url']
        if feed_config.get('needs_auth_key'):
            if not self.abuse_ch_auth_key:
                return None
            url = url.replace('{auth_key}', quote(self.abuse_ch_auth_key, safe=''))
        return url

    def _cache_path(self, feed_name, feed_config):
        """Where a feed is kept: hash lists go straight to the folder file scans
        read (src/hash_feed.py); everything else to this engine's cache."""
        if feed_config.get('store') == 'hash_lists':
            from src.hash_feed import default_folder
            return os.path.join(default_folder(), f"{feed_name}.txt")
        return os.path.join(self.cache_dir, f"{feed_name}.txt")

    def _download_feed(self, feed_name, feed_config):
        """Download a single threat feed."""
        url = self._feed_url(feed_config)
        cache_file = self._cache_path(feed_name, feed_config)
        if url is None:
            return None

        try:
            logger.info("Downloading threat feed: %s", feed_name)
            raw = self._http_get(url)
            if feed_config.get('zip'):
                raw = _first_zip_member(raw)
            stored = feed_config.get('store') == 'hash_lists'
            # A stored list is written as it came, a million lines not decoded
            # and split in memory; file scans read it themselves.
            data = None if stored else raw.decode('utf-8', errors='ignore')

            # Cache to disk
            os.makedirs(os.path.dirname(cache_file), exist_ok=True)
            tmp = cache_file + '.tmp'
            if stored:
                with open(tmp, 'wb') as f:
                    f.write(raw)
            else:
                with open(tmp, 'w', encoding='utf-8') as f:
                    f.write(data)
            os.replace(tmp, cache_file)
            if feed_config.get('hash_export'):
                self._export_hashes(feed_name, data)

            # Update metadata (a success clears any recorded failure)
            self._feed_meta[feed_name] = {
                'last_download': time.time(),
                'size_bytes': len(raw),
                'lines': raw.count(b'\n'),
            }
            if stored:
                self._feed_meta[feed_name]['entries'] = sum(
                    1 for _ in _SHA256_LINE.finditer(raw))
            self._save_meta()

            logger.info("Downloaded %s: %d bytes", feed_name, len(raw))
            return data if data is not None else ''

        except Exception as e:
            code = getattr(e, 'code', None)
            if code in PERMANENT_HTTP_ERRORS:
                # Gone, moved behind a login, or refused: retrying every few hours
                # cannot help. Say so once and leave it for a week.
                meta = self._feed_meta.setdefault(feed_name, {})
                meta['failed_permanently'] = {'status': code, 'at': time.time()}
                self._save_meta()
                self._log_once(feed_name, f'http{code}',
                               "Threat feed %s answered HTTP %s; not retrying for a week.",
                               feed_name, code)
            else:
                # Back off for an hour: a host that timed out was retried at every
                # start, holding startup up by the full timeout each time.
                self._feed_meta.setdefault(feed_name, {})['last_failure'] = time.time()
                self._save_meta()
                # The exception text, never the URL: some URLs carry a key.
                logger.warning("Failed to download %s: %s", feed_name,
                               type(e).__name__ if feed_config.get('needs_auth_key') else e)
            return self._read_cache(feed_name, feed_config)

    def _export_hashes(self, feed_name, data):
        """A feed's SHA-256 indicators, as a list file scans read (hash_feed)."""
        try:
            hashes = _threatfox_hashes(data)
            from src.hash_feed import default_folder
            folder = default_folder()
            os.makedirs(folder, exist_ok=True)
            path = os.path.join(folder, f"{feed_name}_sha256.txt")
            tmp = path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(f"# {feed_name}: SHA-256 indicators, {len(hashes)}\n")
                f.write('\n'.join(sorted(hashes)))
            os.replace(tmp, path)
        except Exception as e:
            logger.debug("Hash export from %s failed: %s", feed_name, e)

    def _read_cache(self, feed_name, feed_config):
        """The cached copy of a feed, unless it is too old to trust."""
        cache_file = self._cache_path(feed_name, feed_config)
        if not os.path.exists(cache_file):
            return None
        max_age = feed_config.get('max_age_hours', DEFAULT_MAX_FEED_AGE_HOURS) * 3600
        try:
            age = time.time() - os.path.getmtime(cache_file)
        except OSError:
            return None
        if age > max_age:
            self._log_once(feed_name, 'stale',
                           "Cached threat feed %s is %d days old; not using it.",
                           feed_name, int(age // 86400))
            return None
        with open(cache_file, encoding='utf-8') as f:
            return f.read()

    def _parse_feed(self, feed_name, feed_config, data):
        """Parse a feed's raw text into IPs/domains/URLs (and networks, JA3)."""
        ips, domains, urls, _networks, _ja3 = self._parse_feed_full(
            feed_name, feed_config, data)
        return ips, domains, urls

    def _parse_feed_full(self, feed_name, feed_config, data):
        if not data:
            return [], [], [], [], []

        ips = []
        domains = []
        urls = []
        networks = []
        ja3 = []
        parser = feed_config.get('parser', 'plain_ips')
        category = feed_config.get('category', 'Unknown')
        description = feed_config.get('description', '')

        feed_info = {
            'feed': feed_name,
            'category': category,
            'description': description,
            'attacker_feed': bool(feed_config.get('attacker')),
        }

        if parser == 'comment_lines':
            # Lines that are IPs, skip comments (#) and empty lines
            for line in data.strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('#') or line.startswith(';'):
                    continue
                # Might have additional columns
                ip = line.split()[0] if line.split() else ''
                if self._is_valid_ip(ip):
                    ips.append((ip, feed_info))

        elif parser == 'plain_ips':
            for line in data.strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('#') or line.startswith(';'):
                    continue
                ip = line.split()[0] if line.split() else ''
                if self._is_valid_ip(ip):
                    ips.append((ip, feed_info))

        elif parser == 'url_lines':
            # One URL per line (the old text export), or the CSV export:
            # "id","dateadded","url","url_status","last_online","threat",...
            for line in data.strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('"'):
                    try:
                        row = next(csv.reader([line]))
                    except (csv.Error, StopIteration):
                        continue
                    if len(row) < 3:
                        continue
                    if len(row) > 3 and row[3].strip().lower() == 'offline':
                        continue
                    line = row[2].strip()
                    if not line.lower().startswith(('http://', 'https://')):
                        continue
                urls.append(line)
                # Extract domain from URL
                try:
                    host = (urlsplit(line).hostname or '').lower()
                    if not host:
                        continue
                    if self._is_valid_ip(host):
                        # A bare address serving malware is an IP indicator; filed
                        # as a "domain" it could never match anything.
                        ips.append((host, feed_info))
                    elif not is_shared_hosting(host):
                        domains.append((host, feed_info))
                except Exception:
                    pass

        elif parser == 'dshield':
            # Tab-separated: start of block, end of block, prefix length, attacks,
            # name, country, email. The first column alone is a network address
            # (x.y.z.0) that no packet ever comes from, so the old exact-IP entry
            # never matched anything; each line is a /24 and is matched as one.
            for line in data.strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('#') or not line[0].isdigit():
                    continue
                parts = line.split('\t')
                if len(parts) < 3:
                    parts = line.split()
                start = parts[0].strip() if parts else ''
                if not self._is_valid_ip(start):
                    continue
                try:
                    bits = int(parts[2].strip()) if len(parts) >= 3 else 24
                    network = ipaddress.ip_network(f"{start}/{bits}", strict=False)
                except ValueError:
                    continue
                if network.prefixlen < 8:
                    continue            # a broken line must not condemn a /0
                networks.append((network, feed_info))

        elif parser == 'ja3_csv':
            # ja3_md5,Firstseen,Lastseen,Listingreason
            for line in data.strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                cols = [c.strip() for c in line.split(',')]
                md5 = cols[0].lower() if cols else ''
                if len(md5) == 32 and all(c in '0123456789abcdef' for c in md5):
                    entry = dict(feed_info)
                    entry['malware'] = cols[3][:80] if len(cols) > 3 else ''
                    entry['last_seen'] = cols[2][:20] if len(cols) > 2 else ''
                    ja3.append((md5, entry))

        elif parser == 'spamhaus_ndjson':
            # One JSON object a line, {"cidr": ..., "sblid": ...}; the last line
            # is the metadata (timestamp, copyright) the terms say stays with it.
            for line in data.splitlines():
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                cidr = record.get('cidr') if isinstance(record, dict) else None
                if not cidr:
                    continue
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                if network.prefixlen < 8:
                    continue
                entry = dict(feed_info)
                entry['sbl'] = str(record.get('sblid', ''))[:20]
                networks.append((network, entry))

        elif parser == 'threatfox_json':
            # {"<id>": [{"ioc_value", "ioc_type", "threat_type", "malware_printable",
            # "confidence_level", ...}], ...}. An ip:port is matched on its port.
            for record in _threatfox_records(data):
                value = str(record.get('ioc_value', '')).strip()
                kind = record.get('ioc_type', '')
                entry = dict(feed_info)
                entry['malware'] = str(record.get('malware_printable', ''))[:80]
                entry['threat_type'] = str(record.get('threat_type', ''))[:40]
                if kind == 'ip:port':
                    ip, _, port = value.rpartition(':')
                    ip = ip.strip('[]')
                    if self._is_valid_ip(ip) and port.isdigit():
                        entry['ports'] = {int(port)}
                        ips.append((ip, entry))
                elif kind == 'domain':
                    host = value.lower().rstrip('.')
                    if host and not is_shared_hosting(host):
                        domains.append((host, entry))
                elif kind == 'url' and value.lower().startswith(('http://', 'https://')):
                    urls.append(value)

        return ips, domains, urls, networks, ja3

    def _refresh_stored(self, feed_name, feed_config, initial=False):
        """
        Bring a feed kept as a file (hash lists) up to date without reading it.
        True if a copy is there to use. Hash lists do not go stale the way
        addresses do: a file that was malware still is.
        """
        if self._feed_skipped(feed_config):
            return False
        path = self._cache_path(feed_name, feed_config)
        if self._refresh_due(feed_name, feed_config, initial):
            self._download_feed(feed_name, feed_config)
        return os.path.exists(path)

    def _refresh_due(self, feed_name, feed_config, initial=False):
        """Whether a feed should be downloaded now: due, not backing off, allowed."""
        meta = self._feed_meta.get(feed_name, {})
        now = time.time()
        refresh_sec = feed_config.get('refresh_hours', 12) * 3600
        if now - meta.get('last_download', 0) <= refresh_sec:
            return False
        failed = meta.get('failed_permanently') or {}
        if failed and now - failed.get('at', 0) < PERMANENT_RETRY_SEC:
            return False
        if now - meta.get('last_failure', 0) < TRANSIENT_RETRY_SEC:
            return False
        # With auto_update off nothing is downloaded — not even while the engine
        # is being built, which used to fetch every feed regardless (and made
        # tests reach the internet).
        return bool(URLLIB_AVAILABLE and self.auto_update
                    and not (initial and feed_config.get('background')))

    def _feed_skipped(self, feed_config):
        """Off by configuration: an optional feed not enabled, or no key for one."""
        optional = feed_config.get('optional')
        if optional and not self.optional_feeds.get(optional):
            return True
        return bool(feed_config.get('needs_auth_key')) and not self.abuse_ch_auth_key

    def _feed_text(self, feed_name, feed_config, initial=False):
        optional = feed_config.get('optional')
        if optional and not self.optional_feeds.get(optional):
            return None
        if feed_config.get('needs_auth_key') and not self.abuse_ch_auth_key:
            self._log_once(feed_name, 'nokey',
                           "Threat feed %s needs a free abuse.ch Auth-Key "
                           "(threat_intel.abuse_ch_auth_key); skipping it.", feed_name,
                           level=logging.INFO)
            return None

        if self._refresh_due(feed_name, feed_config, initial):
            return self._download_feed(feed_name, feed_config)
        return self._read_cache(feed_name, feed_config)

    def _load_all_feeds(self, initial=False):
        """Load all feeds from cache (or download if needed) and swap them in."""
        new_ips, new_domains, new_urls = {}, {}, set()
        new_networks, new_ja3 = [], {}
        new_tor = None
        counts = {}
        loaded = failed = skipped = 0
        for feed_name, feed_config in THREAT_FEEDS.items():
            try:
                if feed_config.get('store') == 'hash_lists':
                    # Read by file scans from their folder, never parsed here:
                    # the full list is a million lines.
                    if self._refresh_stored(feed_name, feed_config, initial):
                        counts[feed_name] = self._feed_meta.get(feed_name, {}).get('entries', 0)
                        loaded += 1
                    elif self._feed_skipped(feed_config):
                        skipped += 1
                    else:
                        failed += 1
                    continue
                data = self._feed_text(feed_name, feed_config, initial=initial)
                if not data:
                    if self._feed_skipped(feed_config):
                        skipped += 1
                    else:
                        failed += 1
                    continue
                if feed_config.get('parser') == 'onionoo':
                    new_tor = _parse_onionoo(data)
                    counts[feed_name] = len(new_tor[0])
                    loaded += 1
                    continue
                ips, domains, urls, networks, ja3 = self._parse_feed_full(
                    feed_name, feed_config, data)
                counts[feed_name] = len(ips) + len(domains) + len(urls) + len(networks) + len(ja3)
                for ip, info in ips:
                    ports = info.get('ports')
                    if ports:
                        known = new_ips.get(ip)
                        if known is not None and not known.get('ports'):
                            continue        # listed on every port already
                        if known is not None:
                            info = dict(known, ports=known['ports'] | ports)
                    new_ips[ip] = info
                for domain, info in domains:
                    new_domains[domain] = info
                new_urls.update(u for u in (normalize_url(u) for u in urls) if u)
                new_networks.extend(networks)
                for md5, info in ja3:
                    new_ja3[md5] = info
                loaded += 1
                logger.debug("Loaded feed %s: %d IPs, %d domains, %d networks",
                             feed_name, len(ips), len(domains), len(networks))
            except Exception as e:
                logger.warning("Error loading feed %s: %s", feed_name, e)
                failed += 1

        with self._lock:
            self._malicious_ips = new_ips
            self._malicious_domains = new_domains
            self._malicious_urls = new_urls
            self._ip_networks = _NetworkIndex(new_networks)
            self._malicious_ja3 = new_ja3
            self._feed_counts = counts
            self._tor_endpoints, self._tor_ips = new_tor or (frozenset(), frozenset())

        # Counts reflect this load, not every load since startup.
        self.stats['feeds_loaded'] = loaded
        self.stats['feeds_failed'] = failed
        self.stats['feeds_skipped'] = skipped
        self.stats['total_ips'] = len(new_ips)
        self.stats['total_domains'] = len(new_domains)
        self.stats['total_urls'] = len(new_urls)
        self.stats['total_networks'] = len(new_networks)
        self.stats['total_ja3'] = len(new_ja3)
        self.stats['last_update'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # ─── Newly registered domains ────────────────────────────────────────

    def _nrd_dir(self):
        return os.path.join(self.cache_dir, 'nrd')

    def _nrd_wanted_days(self, today=None):
        today = today or datetime.now(timezone.utc).date()
        # The list for a date is published the day after.
        return [(today - timedelta(days=i)).isoformat() for i in range(1, self.nrd_days + 1)]

    def _update_nrd(self, today=None):
        """Fetch any of the last nrd_days daily lists not already cached."""
        if not self.nrd_enabled:
            return 0
        directory = self._nrd_dir()
        os.makedirs(directory, exist_ok=True)
        fetched = 0
        for day in self._nrd_wanted_days(today):
            path = os.path.join(directory, f'{day}.txt')
            if os.path.exists(path):
                continue
            token = base64.b64encode(f'{day}.zip'.encode()).decode()
            try:
                blob = self._http_get(NRD_URL.format(token=token), limit=64 * 1024 * 1024)
                domains = _read_nrd_zip(blob)
            except Exception as e:
                logger.info("Newly registered domains for %s not fetched: %s", day, e)
                continue
            tmp = path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write('\n'.join(domains))
            os.replace(tmp, path)
            fetched += 1
        # Lists older than the window are no longer wanted.
        keep = set(self._nrd_wanted_days(today))
        for name in os.listdir(directory):
            if name.endswith('.txt') and name[:-4] not in keep:
                try:
                    os.remove(os.path.join(directory, name))
                except OSError:
                    pass
        return fetched

    def _load_nrd(self, today=None):
        """Build the sorted hash table from the cached daily lists."""
        if not self.nrd_enabled:
            return
        directory = self._nrd_dir()
        if not os.path.isdir(directory):
            return
        wanted = set(self._nrd_wanted_days(today))
        hashes, days = set(), []
        for name in sorted(os.listdir(directory)):
            if not name.endswith('.txt') or name[:-4] not in wanted:
                continue
            try:
                with open(os.path.join(directory, name), encoding='utf-8') as f:
                    for line in f:
                        line = line.strip().lower().rstrip('.')
                        if line and '.' in line:
                            hashes.add(_domain_hash(line))
                days.append(name[:-4])
            except OSError as e:
                logger.debug("NRD list %s unreadable: %s", name, e)
        table = array.array('Q', sorted(hashes))
        with self._lock:
            self._nrd_hashes = table
            self._nrd_dates = days
        self.stats['newly_registered_domains'] = len(table)

    def _update_loop(self):
        """Periodically refresh threat feeds in the background."""
        # Wait 60 seconds before first refresh attempt
        time.sleep(60)
        while True:
            try:
                self._load_all_feeds()
            except Exception as e:
                logger.error("Feed update error: %s", e)
            try:
                if self._update_nrd():
                    self._load_nrd()
                elif not len(self._nrd_hashes):
                    self._load_nrd()
            except Exception as e:
                logger.error("Newly registered domain update error: %s", e)
            # Check every 30 minutes
            time.sleep(1800)

    # ─── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _is_valid_ip(s):
        """Check if string is a valid IPv4/IPv6 address."""
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    def _load_meta(self):
        """Load feed metadata from disk."""
        if os.path.exists(self._meta_path):
            try:
                with open(self._meta_path, encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_meta(self):
        """Save feed metadata to disk."""
        try:
            from src.config import atomic_write_json
            atomic_write_json(self._meta_path, self._feed_meta, secure=False, indent=1)
        except Exception:
            pass

    def _spamhaus_credit(self, name, cfg):
        """Spamhaus's terms: credit, with the list's date and copyright."""
        credit = 'The Spamhaus Project'
        try:
            with open(self._cache_path(name, cfg), encoding='utf-8') as f:
                for line in f:
                    if '"metadata"' not in line:
                        continue
                    meta = json.loads(line)
                    stamp = datetime.fromtimestamp(int(meta.get('timestamp', 0)))
                    credit = (f"{meta.get('copyright') or credit}, "
                              f"list of {stamp:%Y-%m-%d %H:%M}")
        except (OSError, ValueError, OverflowError):
            pass
        return f'Data: {credit}.'

    def get_stats(self):
        """Return threat intel statistics."""
        return {
            **self.stats,
            'enabled': self.enabled,
            'feeds_available': len(THREAT_FEEDS),
        }

    def feed_status(self, now=None):
        """
        Each feed's state for the Threat data page: in use or not, and why not.
        URLhaus went unused for six months (no key, then too old to trust) and
        nothing said so.
        """
        now = now or time.time()
        rows = []
        for name, cfg in THREAT_FEEDS.items():
            meta = self._feed_meta.get(name, {})
            stored = cfg.get('store') == 'hash_lists'
            try:
                updated = os.path.getmtime(self._cache_path(name, cfg))
            except OSError:
                updated = None
            age = now - updated if updated else None
            max_age = (float('inf') if stored else
                       cfg.get('max_age_hours', DEFAULT_MAX_FEED_AGE_HOURS) * 3600)
            failed = meta.get('failed_permanently') or {}
            optional = cfg.get('optional')
            if not self.enabled:
                state, note = 'off', 'Threat feeds are off (threat_intel.enabled).'
            elif optional and not self.optional_feeds.get(optional):
                state, note = 'off', f'Off in settings (threat_intel.{optional}).'
            elif cfg.get('needs_auth_key') and not self.abuse_ch_auth_key:
                state, note = 'needs key', ('Needs a free abuse.ch Auth-Key: '
                                            'Settings → Threat data.')
            elif failed and now - failed.get('at', 0) < PERMANENT_RETRY_SEC:
                state, note = 'failed', (f"The source answered HTTP {failed.get('status')}; "
                                         'tried again weekly.')
            elif updated is None:
                state, note = 'waiting', 'Not downloaded yet.'
            elif age > max_age:
                state, note = 'stale', (f'{int(age // 86400)} days old, so not used. '
                                        + ('Downloads are off (threat_intel.auto_update).'
                                           if not self.auto_update else
                                           'The last downloads failed.'))
            else:
                state, note = 'ok', ''
            if state == 'ok' and cfg.get('parser') == 'spamhaus_ndjson':
                note = self._spamhaus_credit(name, cfg)
            elif state == 'ok' and stored:
                note = 'For file scans.'
            elif state == 'ok' and name == 'tor_relays':
                note = 'Not malicious: marks a connection as Tor. CC0, Tor Project.'
            entries = self._feed_counts.get(name, 0)
            if stored:
                entries = meta.get('entries', 0)
            rows.append({
                'name': name,
                'description': cfg.get('description', ''),
                'category': cfg.get('category', ''),
                'state': state,
                'note': note,
                'updated': updated,
                'entries': entries if state == 'ok' else 0,
                'refresh_hours': cfg.get('refresh_hours', 12),
            })
        rows.append({
            'name': 'ja4db',
            'description': 'FoxIO JA4DB - TLS client fingerprints',
            'category': 'Malicious TLS Client',
            'state': 'off',
            'note': ('Not used: since 2026 it needs an enterprise sign-up, and its '
                     'terms forbid copying it.'),
            'updated': None, 'entries': 0, 'refresh_hours': None,
        })
        nrd_days = list(self._nrd_dates)
        rows.append({
            'name': 'whoisds_nrd',
            'description': 'WhoisDS - Newly registered domains (daily lists)',
            'category': 'Newly Registered Domain',
            'state': ('off' if not (self.enabled and self.nrd_enabled) else
                      'ok' if nrd_days else 'waiting'),
            'note': (f'{nrd_days[0]} to {nrd_days[-1]}' if nrd_days else
                     'Off in settings (threat_intel.newly_registered_domains).'
                     if not self.nrd_enabled else 'Not downloaded yet.'),
            'updated': None,
            'entries': len(self._nrd_hashes),
            'refresh_hours': 24,
        })
        return rows


def _first_zip_member(blob, limit=256 * 1024 * 1024):
    """The first file in a zip, refusing one that inflates past limit."""
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for member in zf.infolist():
            if member.is_dir():
                continue
            if member.file_size > limit:
                raise ValueError('zip member larger than expected')
            with zf.open(member) as f:
                data = f.read(limit + 1)
            if len(data) > limit:
                raise ValueError('zip member larger than expected')
            return data
    raise ValueError('empty zip')


# One SHA-256 a line, as MalwareBazaar's lists hold them.
_SHA256_LINE = re.compile(rb'(?m)^[0-9A-Fa-f]{64}\s*$')


# ThreatFox's own confidence, 0-100; below this a listing is a guess.
THREATFOX_MIN_CONFIDENCE = 50


def _threatfox_records(data):
    """ThreatFox export records with enough confidence to act on."""
    try:
        doc = json.loads(data)
    except ValueError:
        return []
    groups = doc.values() if isinstance(doc, dict) else doc if isinstance(doc, list) else ()
    out = []
    for group in groups:
        for record in (group if isinstance(group, list) else [group]):
            if not isinstance(record, dict):
                continue
            try:
                confidence = int(record.get('confidence_level') or 0)
            except (TypeError, ValueError):
                confidence = 0
            if confidence >= THREATFOX_MIN_CONFIDENCE:
                out.append(record)
    return out


def _threatfox_hashes(data):
    return {str(r.get('ioc_value', '')).strip().lower() for r in _threatfox_records(data)
            if r.get('ioc_type') == 'sha256_hash'
            and len(str(r.get('ioc_value', '')).strip()) == 64}


def _parse_onionoo(data):
    """({(ip, or_port)}, {ip}) of running relays from an Onionoo details document."""
    endpoints, addresses = set(), set()
    try:
        relays = json.loads(data).get('relays') or ()
    except (ValueError, AttributeError):
        return frozenset(), frozenset()
    for relay in relays:
        for entry in relay.get('or_addresses') or ():
            host, _, port = str(entry).rpartition(':')
            host = host.strip('[]')
            try:
                ip = str(ipaddress.ip_address(host))
            except ValueError:
                continue
            if port.isdigit():
                endpoints.add((ip, int(port)))
                addresses.add(ip)
    return frozenset(endpoints), frozenset(addresses)


def _read_nrd_zip(blob, limit=128 * 1024 * 1024):
    """Domain names from a WhoisDS daily zip: one text member, one name per line."""
    domains = []
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for member in zf.infolist()[:4]:
            if member.file_size > limit or member.is_dir():
                continue
            with zf.open(member) as f:
                text = f.read(limit + 1)
            if len(text) > limit:
                continue
            for line in text.decode('utf-8', 'ignore').splitlines():
                name = line.strip().lower().rstrip('.')
                if name and '.' in name and len(name) <= 253 and ' ' not in name:
                    domains.append(name)
    return domains
