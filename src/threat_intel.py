"""
Threat Intelligence Engine
===========================
Downloads and caches free, public threat intelligence feeds.
Checks IPs and domains against known malicious indicators.
Auto-refreshes feeds periodically.

Sources (all free, no API key needed):
- abuse.ch Feodo Tracker (botnet C2 IPs)
- abuse.ch SSL Blacklist (malicious SSL IPs)
- abuse.ch URLhaus (malicious URLs/domains)
- Emerging Threats compromised IPs
- Spamhaus DROP (hijacked IP blocks)
- Cisco Umbrella/OpenDNS popular suspicious domains
- DShield top attacking IPs
"""

import os
import re
import csv
import time
import json
import logging
import threading
import ipaddress
from io import StringIO
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger("NetSentinel.ThreatIntel")

try:
    import urllib.request
    URLLIB_AVAILABLE = True
except ImportError:
    URLLIB_AVAILABLE = False

# ─── Feed Definitions ───────────────────────────────────────────────────────

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
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
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
    },
    "dshield_top": {
        "url": "https://feeds.dshield.org/block.txt",
        "type": "ip",
        "category": "Active Attacker",
        "description": "DShield - Top attacking /24 subnets (last 3 days)",
        "refresh_hours": 4,
        "parser": "dshield",
    },
    "blocklist_de": {
        "url": "https://lists.blocklist.de/lists/all.txt",
        "type": "ip",
        "category": "Brute Force / Scanner",
        "description": "blocklist.de - Brute force and scanner IPs",
        "refresh_hours": 12,
        "parser": "plain_ips",
    },
}

# Known suspicious/malicious domains (built-in, no download needed)
BUILTIN_SUSPICIOUS_DOMAINS = {
    # Common dynamic DNS used by malware
    "no-ip.com", "no-ip.org", "no-ip.biz", "ddns.net",
    "duckdns.org", "freedns.afraid.org", "changeip.com",
    "hopto.org", "zapto.org", "sytes.net", "serveftp.com",
    # Known malicious TLDs (high abuse rate)
    # (checked by suffix, not exact match)
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".buzz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".work", ".click", ".link", ".icu", ".monster", ".rest",
    ".cam", ".surf", ".ooo", ".sbs", ".cyou",
}

# Suspicious user-agent patterns
SUSPICIOUS_USER_AGENTS = [
    "python-requests", "go-http-client", "curl/", "wget/",
    "powershell", "certutil", "mshta", "wscript", "cscript",
]


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

        # Lookup tables
        self._malicious_ips = {}       # {ip: {feed, category, description}}
        self._malicious_domains = {}   # {domain: {feed, category, description}}
        self._malicious_urls = set()
        self._ip_networks = []         # List of (network, feed_info) for CIDR matching

        # Stats
        self.stats = {
            'total_ips': 0,
            'total_domains': 0,
            'total_urls': 0,
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
        self._load_all_feeds()

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
            dict or None: {feed, category, description} if malicious, None if clean
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

            # CIDR network match
            for network, feed_info in self._ip_networks:
                try:
                    if ipaddress.ip_address(ip) in network:
                        self.stats['threats_found'] += 1
                        return feed_info.copy()
                except ValueError:
                    continue

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
        for dyn_domain in BUILTIN_SUSPICIOUS_DOMAINS:
            if domain.endswith(dyn_domain):
                return {
                    'feed': 'builtin',
                    'category': 'Dynamic DNS',
                    'description': f'Domain uses dynamic DNS service ({dyn_domain})',
                    'confidence': 'LOW',
                    'match_type': 'dynamic_dns',
                }

        # Suspicious TLD check
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld.lstrip('.')):
                return {
                    'feed': 'builtin',
                    'category': 'Suspicious TLD',
                    'description': f'Domain uses high-abuse TLD ({tld})',
                    'confidence': 'LOW',
                    'match_type': 'suspicious_tld',
                }

        return None

    def check_url(self, url):
        """Check if a URL matches known malicious URLs."""
        if not self.enabled or not url:
            return None
        self.stats['lookups_performed'] += 1
        with self._lock:
            if url in self._malicious_urls:
                self.stats['threats_found'] += 1
                return {
                    'feed': 'urlhaus',
                    'category': 'Malware Distribution',
                    'description': 'URL found in URLhaus malware database',
                    'confidence': 'HIGH',
                }
        return None

    # ─── Feed Management ─────────────────────────────────────────────────

    def _download_feed(self, feed_name, feed_config):
        """Download a single threat feed."""
        url = feed_config['url']
        cache_file = os.path.join(self.cache_dir, f"{feed_name}.txt")

        try:
            logger.info("Downloading threat feed: %s", feed_name)
            req = urllib.request.Request(url, headers={
                'User-Agent': 'NetSentinel/1.0 ThreatIntel'
            })
            with urllib.request.urlopen(req, timeout=30) as response:
                data = response.read().decode('utf-8', errors='ignore')

            # Cache to disk
            with open(cache_file, 'w', encoding='utf-8') as f:
                f.write(data)

            # Update metadata
            self._feed_meta[feed_name] = {
                'last_download': time.time(),
                'size_bytes': len(data),
                'lines': data.count('\n'),
            }
            self._save_meta()

            logger.info("Downloaded %s: %d bytes", feed_name, len(data))
            return data

        except Exception as e:
            logger.warning("Failed to download %s: %s", feed_name, e)
            # Try loading from cache
            if os.path.exists(cache_file):
                logger.info("Using cached version of %s", feed_name)
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return f.read()
            return None

    def _parse_feed(self, feed_name, feed_config, data):
        """Parse a feed's raw text into IPs/domains."""
        if not data:
            return [], [], []

        ips = []
        domains = []
        urls = []
        parser = feed_config.get('parser', 'plain_ips')
        category = feed_config.get('category', 'Unknown')
        description = feed_config.get('description', '')

        feed_info = {
            'feed': feed_name,
            'category': category,
            'description': description,
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
            for line in data.strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                urls.append(line)
                # Extract domain from URL
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(line)
                    if parsed.hostname:
                        domains.append((parsed.hostname, feed_info))
                except Exception:
                    pass

        elif parser == 'dshield':
            for line in data.strip().split('\n'):
                line = line.strip()
                if not line or line.startswith('#') or not line[0].isdigit():
                    continue
                parts = line.split('\t')
                if parts:
                    ip = parts[0].strip()
                    if self._is_valid_ip(ip):
                        ips.append((ip, feed_info))

        return ips, domains, urls

    def _load_all_feeds(self):
        """Load all feeds from cache (or download if needed)."""
        for feed_name, feed_config in THREAT_FEEDS.items():
            try:
                cache_file = os.path.join(self.cache_dir, f"{feed_name}.txt")
                data = None

                # Check if we need to download
                meta = self._feed_meta.get(feed_name, {})
                last_dl = meta.get('last_download', 0)
                refresh_sec = feed_config.get('refresh_hours', 12) * 3600
                needs_refresh = (time.time() - last_dl) > refresh_sec

                if needs_refresh and URLLIB_AVAILABLE:
                    data = self._download_feed(feed_name, feed_config)
                elif os.path.exists(cache_file):
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        data = f.read()

                if data:
                    ips, domains, urls = self._parse_feed(feed_name, feed_config, data)

                    with self._lock:
                        for ip, info in ips:
                            self._malicious_ips[ip] = info
                        for domain, info in domains:
                            self._malicious_domains[domain] = info
                        self._malicious_urls.update(urls)

                    self.stats['feeds_loaded'] += 1
                    logger.debug(
                        "Loaded feed %s: %d IPs, %d domains",
                        feed_name, len(ips), len(domains)
                    )
                else:
                    self.stats['feeds_failed'] += 1

            except Exception as e:
                logger.warning("Error loading feed %s: %s", feed_name, e)
                self.stats['feeds_failed'] += 1

        # Update totals
        self.stats['total_ips'] = len(self._malicious_ips)
        self.stats['total_domains'] = len(self._malicious_domains)
        self.stats['total_urls'] = len(self._malicious_urls)
        self.stats['last_update'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def _update_loop(self):
        """Periodically refresh threat feeds in the background."""
        # Wait 60 seconds before first refresh attempt
        time.sleep(60)
        while True:
            try:
                self._load_all_feeds()
            except Exception as e:
                logger.error("Feed update error: %s", e)
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
                with open(self._meta_path, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_meta(self):
        """Save feed metadata to disk."""
        try:
            with open(self._meta_path, 'w') as f:
                json.dump(self._feed_meta, f, indent=1)
        except Exception:
            pass

    def get_stats(self):
        """Return threat intel statistics."""
        return {
            **self.stats,
            'enabled': self.enabled,
            'feeds_available': len(THREAT_FEEDS),
        }
