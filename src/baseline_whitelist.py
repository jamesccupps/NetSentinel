"""
Baseline Whitelist Learner
============================
Automatically learns which domains, IPs, and traffic patterns are normal
for THIS specific network during the ML baseline learning period.

The key insight: instead of hardcoding known-good domains (which makes
the tool network-specific), we LEARN them. During the initial baseline
period (configurable, default 2 hours), every domain queried, every IP
contacted, and every port used is recorded as "normal for this network."

After baseline completes, these learned patterns are used to:
- Suppress DGA false positives for domains seen during baseline
- Reduce alert severity for IPs that were contacted during baseline
- Skip beaconing detection for devices with learned periodic patterns
- Auto-whitelist internal infrastructure discovered during baseline

The whitelist is saved to disk and grows over time. Domains/IPs that
haven't been seen in 30 days are pruned.

Network-agnostic: works identically on a home network, office, or data center.
"""

import os
import json
import time
import logging
import threading
from collections import Counter, defaultdict
from datetime import datetime

logger = logging.getLogger("NetSentinel.BaselineWL")


class BaselineWhitelist:
    """
    Learns and maintains a whitelist of normal network behavior.
    No hardcoded values — everything is learned from observed traffic.
    """

    def __init__(self, config):
        self.config = config

        # Baseline learning duration (seconds)
        self.learning_hours = config.get('ml', 'baseline_learning_hours', default=2)
        self.learning_duration = self.learning_hours * 3600

        # Learning state
        self.learning_start = time.time()
        self.is_learning = True

        # Learned data
        self._domains = {}          # {domain: {first_seen, last_seen, count, source_ips}}
        self._ips = {}              # {ip: {first_seen, last_seen, count, ports, domains}}
        self._port_patterns = Counter()  # {port: count during baseline}
        self._dns_pairs = set()     # {(src_ip, domain)} - known DNS query pairs
        self._periodic_ips = {}     # {(src, dst): avg_interval} - learned beacons

        # Config-driven exclusions (user can add via config, but starts empty)
        user_dga_suffixes = config.get('whitelists', 'dga_whitelist_suffixes', default=[])
        user_dga_exact = config.get('whitelists', 'dga_whitelist_exact', default=[])
        self._user_dga_suffixes = set(user_dga_suffixes)
        self._user_dga_exact = set(user_dga_exact)

        self._lock = threading.Lock()

        # Persistence
        from src.config import DB_DIR
        self._db_path = os.path.join(DB_DIR, "baseline_whitelist.json")
        self._load()

        # If we have existing data, check if learning is complete
        if self._domains:
            elapsed = time.time() - self.learning_start
            if elapsed > self.learning_duration:
                self.is_learning = False

        logger.info(
            "Baseline whitelist: %d domains, %d IPs learned. Learning: %s",
            len(self._domains), len(self._ips), self.is_learning
        )

    def observe_dns(self, src_ip, domain, timestamp=None):
        """Record a DNS query observed on the network."""
        if not domain:
            return
        ts = timestamp or time.time()
        domain = domain.lower().strip('.')

        # Extract base domain (last 2 labels for standard, 3 for co.uk etc.)
        base = self._base_domain(domain)

        with self._lock:
            if base not in self._domains:
                self._domains[base] = {
                    'first_seen': ts,
                    'last_seen': ts,
                    'count': 0,
                    'source_ips': set(),
                    'full_domains': set(),
                }
            entry = self._domains[base]
            entry['last_seen'] = ts
            entry['count'] += 1
            entry['source_ips'].add(src_ip)
            if len(entry['full_domains']) < 50:
                entry['full_domains'].add(domain)

            self._dns_pairs.add((src_ip, base))
            # Cap to prevent unbounded memory growth
            if len(self._dns_pairs) > 50000:
                # Evict oldest half (sets aren't ordered, but this is a pragmatic cap)
                self._dns_pairs = set(list(self._dns_pairs)[-25000:])

    def observe_connection(self, src_ip, dst_ip, dst_port, timestamp=None):
        """Record a connection observed on the network."""
        if not dst_ip:
            return
        ts = timestamp or time.time()

        with self._lock:
            if dst_ip not in self._ips:
                self._ips[dst_ip] = {
                    'first_seen': ts,
                    'last_seen': ts,
                    'count': 0,
                    'ports': Counter(),
                    'source_ips': set(),
                }
            entry = self._ips[dst_ip]
            entry['last_seen'] = ts
            entry['count'] += 1
            entry['ports'][str(dst_port)] += 1
            entry['source_ips'].add(src_ip)

            if dst_port:
                self._port_patterns[dst_port] += 1

    def observe_beacon(self, src_ip, dst_ip, avg_interval):
        """Record a learned periodic pattern (not necessarily malicious)."""
        with self._lock:
            self._periodic_ips[(src_ip, dst_ip)] = avg_interval

    def check_learning_complete(self):
        """Check if baseline learning period has elapsed."""
        if self.is_learning:
            elapsed = time.time() - self.learning_start
            if elapsed > self.learning_duration:
                self.is_learning = False
                self.save()
                logger.info(
                    "Baseline learning complete. Learned %d domains, %d IPs, %d port patterns",
                    len(self._domains), len(self._ips), len(self._port_patterns)
                )
        return not self.is_learning

    def is_learned_domain(self, domain):
        """Check if this domain was seen during baseline (normal traffic)."""
        if not domain:
            return False
        domain = domain.lower().strip('.')
        base = self._base_domain(domain)

        # Check user-configured exact matches
        if domain in self._user_dga_exact or base in self._user_dga_exact:
            return True

        # Check user-configured suffix matches
        for suffix in self._user_dga_suffixes:
            if domain.endswith(suffix) or base.endswith(suffix):
                return True

        with self._lock:
            entry = self._domains.get(base)
            if entry and entry['count'] >= 3:
                return True

        return False

    def is_learned_ip(self, ip):
        """Check if this IP was contacted during baseline."""
        with self._lock:
            entry = self._ips.get(ip)
            return entry is not None and entry['count'] >= 3

    def is_learned_beacon(self, src_ip, dst_ip):
        """Check if this src→dst pair had a regular pattern during baseline."""
        with self._lock:
            return (src_ip, dst_ip) in self._periodic_ips

    def is_learned_port(self, port):
        """Check if this port was commonly used during baseline."""
        with self._lock:
            return self._port_patterns.get(port, 0) >= 5

    def get_domain_confidence(self, domain):
        """
        Return confidence (0-1) that this domain is normal for this network.
        Higher = more likely normal. 0 = never seen.
        """
        if not domain:
            return 0.0
        base = self._base_domain(domain)

        with self._lock:
            entry = self._domains.get(base)
            if not entry:
                return 0.0
            # More source IPs querying = more confidence it's legitimate
            src_count = len(entry['source_ips']) if isinstance(entry['source_ips'], set) else entry.get('source_ip_count', 1)
            query_count = entry['count']

            # Score based on how many devices query this and how often
            score = min(1.0, (src_count / 3.0) * 0.5 + (query_count / 50.0) * 0.5)
            return score

    def get_stats(self):
        """Return whitelist statistics for dashboard."""
        with self._lock:
            return {
                'is_learning': self.is_learning,
                'learning_hours': self.learning_hours,
                'learned_domains': len(self._domains),
                'learned_ips': len(self._ips),
                'learned_port_patterns': len(self._port_patterns),
                'learned_beacons': len(self._periodic_ips),
                'learning_elapsed_min': int((time.time() - self.learning_start) / 60),
                'learning_remaining_min': max(0, int(
                    (self.learning_duration - (time.time() - self.learning_start)) / 60
                )) if self.is_learning else 0,
            }

    @staticmethod
    def _base_domain(domain):
        """Extract the base domain (registrable domain) from a full domain."""
        parts = domain.lower().strip('.').split('.')
        if len(parts) <= 2:
            return domain.lower().strip('.')
        # Handle common multi-part TLDs
        multi_tlds = {'co.uk', 'co.jp', 'com.au', 'co.nz', 'co.in', 'com.br'}
        if len(parts) >= 3:
            last_two = f"{parts[-2]}.{parts[-1]}"
            if last_two in multi_tlds:
                return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])

    def save(self):
        """Persist whitelist to disk."""
        with self._lock:
            data = {
                'learning_start': self.learning_start,
                'is_learning': self.is_learning,
                'domains': {
                    k: {
                        'first_seen': v['first_seen'],
                        'last_seen': v['last_seen'],
                        'count': v['count'],
                        'source_ip_count': len(v['source_ips']) if isinstance(v['source_ips'], set) else v.get('source_ip_count', 0),
                        'sample_domains': list(v['full_domains'])[:10] if isinstance(v.get('full_domains'), set) else v.get('sample_domains', []),
                    }
                    for k, v in self._domains.items()
                },
                'ips': {
                    k: {
                        'first_seen': v['first_seen'],
                        'last_seen': v['last_seen'],
                        'count': v['count'],
                        'ports': dict(v['ports']) if isinstance(v['ports'], Counter) else v.get('ports', {}),
                        'source_ip_count': len(v['source_ips']) if isinstance(v['source_ips'], set) else v.get('source_ip_count', 0),
                    }
                    for k, v in self._ips.items()
                },
                'port_patterns': dict(self._port_patterns),
                'periodic_ips': {
                    f"{k[0]}>{k[1]}": v for k, v in self._periodic_ips.items()
                },
            }
        try:
            with open(self._db_path, 'w') as f:
                json.dump(data, f, indent=1, default=str)
            logger.info("Saved baseline whitelist (%d domains, %d IPs)",
                       len(data['domains']), len(data['ips']))
        except Exception as e:
            logger.error("Failed to save baseline whitelist: %s", e)

    def _load(self):
        """Load previously learned whitelist."""
        if not os.path.exists(self._db_path):
            return
        try:
            with open(self._db_path, 'r') as f:
                data = json.load(f)

            self.learning_start = data.get('learning_start', time.time())

            # Restore domains
            for k, v in data.get('domains', {}).items():
                self._domains[k] = {
                    'first_seen': v['first_seen'],
                    'last_seen': v['last_seen'],
                    'count': v['count'],
                    'source_ips': set(),  # Can't fully restore, but that's OK
                    'full_domains': set(v.get('sample_domains', [])),
                }

            # Restore IPs
            for k, v in data.get('ips', {}).items():
                self._ips[k] = {
                    'first_seen': v['first_seen'],
                    'last_seen': v['last_seen'],
                    'count': v['count'],
                    'ports': Counter(v.get('ports', {})),
                    'source_ips': set(),
                }

            self._port_patterns = Counter(data.get('port_patterns', {}))

            for k, v in data.get('periodic_ips', {}).items():
                parts = k.split('>')
                if len(parts) == 2:
                    self._periodic_ips[(parts[0], parts[1])] = v

            logger.info("Loaded baseline whitelist: %d domains, %d IPs",
                       len(self._domains), len(self._ips))
        except Exception as e:
            logger.error("Failed to load baseline whitelist: %s", e)

    def prune_stale(self, max_age_days=30):
        """Remove entries not seen in max_age_days."""
        cutoff = time.time() - (max_age_days * 86400)
        with self._lock:
            stale_d = [k for k, v in self._domains.items() if v['last_seen'] < cutoff]
            for k in stale_d:
                del self._domains[k]
            stale_i = [k for k, v in self._ips.items() if v['last_seen'] < cutoff]
            for k in stale_i:
                del self._ips[k]
            if stale_d or stale_i:
                logger.info("Pruned %d stale domains, %d stale IPs from whitelist",
                           len(stale_d), len(stale_i))
