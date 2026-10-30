"""
Threat Intelligence Engine
===========================
Downloads and caches free, public threat intelligence feeds.
Checks IPs and domains against known malicious indicators.
Auto-refreshes feeds periodically.

Every lookup is local: feeds are downloaded as whole lists and matched here, so
nothing about this machine's traffic is sent anywhere.

Sources (all free, no API key needed):
- abuse.ch Feodo Tracker (botnet C2 IPs)
- abuse.ch SSL Blacklist (malicious SSL IPs, and JA3 client fingerprints)
- abuse.ch URLhaus (malicious URLs/domains)
- Emerging Threats compromised IPs
- DShield top attacking /24 blocks
- blocklist.de brute-force and scanner IPs
- WhoisDS newly registered domains (daily list, opt-out via config)
"""

import os
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
        self._ip_networks = []         # List of (network, feed_info) for CIDR matching
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

            # CIDR network match. `addr` is already parsed above — re-parsing it
            # inside the loop cost one ip_address() construction per network.
            for network, feed_info in self._ip_networks:
                if addr.version == network.version and addr in network:
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

    def _download_feed(self, feed_name, feed_config):
        """Download a single threat feed."""
        url = self._feed_url(feed_config)
        cache_file = os.path.join(self.cache_dir, f"{feed_name}.txt")
        if url is None:
            return None

        try:
            logger.info("Downloading threat feed: %s", feed_name)
            data = self._http_get(url).decode('utf-8', errors='ignore')

            # Cache to disk
            tmp = cache_file + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(data)
            os.replace(tmp, cache_file)

            # Update metadata (a success clears any recorded failure)
            self._feed_meta[feed_name] = {
                'last_download': time.time(),
                'size_bytes': len(data),
                'lines': data.count('\n'),
            }
            self._save_meta()

            logger.info("Downloaded %s: %d bytes", feed_name, len(data))
            return data

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

    def _read_cache(self, feed_name, feed_config):
        """The cached copy of a feed, unless it is too old to trust."""
        cache_file = os.path.join(self.cache_dir, f"{feed_name}.txt")
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

        return ips, domains, urls, networks, ja3

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

        meta = self._feed_meta.get(feed_name, {})
        now = time.time()
        last_dl = meta.get('last_download', 0)
        refresh_sec = feed_config.get('refresh_hours', 12) * 3600
        needs_refresh = (now - last_dl) > refresh_sec
        failed = meta.get('failed_permanently') or {}
        if failed and now - failed.get('at', 0) < PERMANENT_RETRY_SEC:
            needs_refresh = False
        if now - meta.get('last_failure', 0) < TRANSIENT_RETRY_SEC:
            needs_refresh = False
        # With auto_update off nothing is downloaded — not even while the engine
        # is being built, which used to fetch every feed regardless (and made
        # tests reach the internet).
        allowed_now = self.auto_update and not (initial and feed_config.get('background'))

        if needs_refresh and URLLIB_AVAILABLE and allowed_now:
            return self._download_feed(feed_name, feed_config)
        return self._read_cache(feed_name, feed_config)

    def _load_all_feeds(self, initial=False):
        """Load all feeds from cache (or download if needed) and swap them in."""
        new_ips, new_domains, new_urls = {}, {}, set()
        new_networks, new_ja3 = [], {}
        loaded = failed = skipped = 0
        for feed_name, feed_config in THREAT_FEEDS.items():
            try:
                data = self._feed_text(feed_name, feed_config, initial=initial)
                if not data:
                    if self._feed_skipped(feed_config):
                        skipped += 1
                    else:
                        failed += 1
                    continue
                ips, domains, urls, networks, ja3 = self._parse_feed_full(
                    feed_name, feed_config, data)
                for ip, info in ips:
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
            self._ip_networks = new_networks
            self._malicious_ja3 = new_ja3

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

    def get_stats(self):
        """Return threat intel statistics."""
        return {
            **self.stats,
            'enabled': self.enabled,
            'feeds_available': len(THREAT_FEEDS),
        }


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
