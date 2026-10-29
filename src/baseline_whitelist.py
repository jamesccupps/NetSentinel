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
from collections import Counter

from src.public_suffix import registrable_domain

logger = logging.getLogger("NetSentinel.BaselineWL")


def _field(alert, name):
    """Read a field from an Alert or from its to_dict() form."""
    if isinstance(alert, dict):
        return alert.get(name)
    return getattr(alert, name, None)


def alert_subjects(alert):
    """
    What an alert is about, most specific first: (kind, value) pairs.

    Domains come only from what the traffic itself said (SNI, the DNS query), not
    from destination_domains, which is a guess from recent lookups and can name an
    unrelated site.
    """
    evidence = _field(alert, 'evidence') or {}
    subjects = []
    for key in ('tls_sni', 'dns_query', 'query', 'domain'):
        name = evidence.get(key) if isinstance(evidence, dict) else None
        if isinstance(name, str) and '.' in name:
            name = name.lower().strip('.')
            subjects.append(('domain', registrable_domain(name) or name))
            break
    for kind in ('dst_ip', 'src_ip'):
        ip = _field(alert, kind)
        if ip and not _is_group_address(ip):
            subjects.append((kind, ip))
    return subjects


def _is_group_address(ip):
    """
    Multicast and broadcast are not hosts. A verdict on an mDNS alert was tied to
    224.0.0.251 and would have silenced that rule for every device on the network.
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(str(ip).split('%')[0])
    except ValueError:
        return False
    return addr.is_multicast or addr.is_unspecified or str(addr) == '255.255.255.255'


class ConfirmedFalsePositives:
    """
    Alerts a person marked as false positives, by rule and subject.

    Unlike learned entries these never expire: someone decided. Kept in their own
    file and re-read when it changes, so a verdict recorded from the command line
    reaches a running NetSentinel without a restart, and the running app's saves
    cannot overwrite it.
    """

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._entries = {}
        self._mtime = None
        self._reload()

    @staticmethod
    def key(rule_id, kind, value):
        return f"{rule_id}|{kind}|{value}"

    def add(self, alert, note='', review_id=''):
        """Confirm an alert as a false positive. None if it names nothing to match."""
        subjects = alert_subjects(alert)
        if not subjects:
            return None
        kind, value = subjects[0]
        rule_id = _field(alert, 'rule_id') or ''
        entry = {'rule_id': rule_id, 'kind': kind, 'value': value,
                 'note': str(note or '')[:500], 'review_id': review_id,
                 'added': time.time()}
        with self._lock:
            self._reload()
            self._entries[self.key(rule_id, kind, value)] = entry
            self._save()
        logger.info("Confirmed false positive: %s for %s %s", rule_id, kind, value)
        return entry

    def remove(self, key):
        with self._lock:
            self._reload()
            if self._entries.pop(key, None) is None:
                return False
            self._save()
            return True

    def entries(self):
        with self._lock:
            self._reload()
            return sorted(self._entries.values(), key=lambda e: e['added'])

    def matches(self, alert):
        """The entry that suppresses this alert, or None."""
        with self._lock:
            self._reload()
            if not self._entries:
                return None
            rule_id = _field(alert, 'rule_id') or ''
            for kind, value in alert_subjects(alert):
                entry = self._entries.get(self.key(rule_id, kind, value))
                if entry is not None:
                    return entry
        return None

    def _reload(self):
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError:
            return
        if mtime == self._mtime:
            return
        try:
            with open(self.path, encoding='utf-8') as f:
                data = json.load(f)
            self._entries = {self.key(e['rule_id'], e['kind'], e['value']): e
                             for e in data if isinstance(e, dict) and 'rule_id' in e}
            self._mtime = mtime
        except (OSError, ValueError, KeyError) as e:
            logger.error("Could not read confirmed false positives: %s", e)

    def _save(self):
        from src.config import atomic_write_json
        atomic_write_json(self.path, list(self._entries.values()), indent=1)
        try:
            self._mtime = os.stat(self.path).st_mtime
        except OSError:
            pass


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
        self.confirmed = ConfirmedFalsePositives(
            os.path.join(DB_DIR, "confirmed_false_positives.json"))

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

        # Check user-configured suffix matches, on a label boundary: a bare
        # endswith let "ample.com" vouch for "example.com".
        for suffix in self._user_dga_suffixes:
            suffix = suffix.lower().strip('.')
            if suffix and (domain == suffix or domain.endswith('.' + suffix)):
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

    def confirm_false_positive(self, alert, note='', review_id=''):
        """Never alert on this rule for this alert's subject again. See ConfirmedFalsePositives."""
        return self.confirmed.add(alert, note=note, review_id=review_id)

    def suppresses(self, alert):
        """The confirmed false positive matching this alert, or None."""
        return self.confirmed.matches(alert)

    @staticmethod
    def _base_domain(domain):
        """
        The registrable domain: what one owner controls.

        It was the last two labels, with six two-part suffixes special-cased, so
        learning one site under .co.za, or one tenant of github.io or duckdns.org,
        whitelisted every other one.
        """
        domain = domain.lower().strip('.')
        return registrable_domain(domain) or domain

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
            from src.config import atomic_write_json
            atomic_write_json(self._db_path, data, indent=1, default=str)
            logger.info("Saved baseline whitelist (%d domains, %d IPs)",
                       len(data['domains']), len(data['ips']))
        except Exception as e:
            logger.error("Failed to save baseline whitelist: %s", e)

    def _load(self):
        """Load previously learned whitelist."""
        if not os.path.exists(self._db_path):
            return
        try:
            with open(self._db_path, encoding='utf-8') as f:
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
