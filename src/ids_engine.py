"""
Signature-Based Intrusion Detection System (IDS)
=================================================
Rule-based detection for known attack patterns, port scans,
brute force attempts, suspicious payloads, and protocol anomalies.
"""

import os
import sys
import json
import time
import logging
import itertools
from collections import Counter, defaultdict, deque
from datetime import datetime

from src.dns_analysis import DnsResponseMonitor
from src.ipcache import is_private

logger = logging.getLogger("NetSentinel.IDS")


class Severity:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    _order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    @classmethod
    def gte(cls, a, b):
        return cls._order.get(a, 0) >= cls._order.get(b, 0)


# ─── Hot-path constants (evaluated once at import, not per-packet) ────────────
# Ports where a source sending FROM them is a service response, not a scan
_COMMON_SERVICE_PORTS = frozenset({
    21, 22, 25, 53, 67, 68, 80, 110, 123, 143, 161, 443, 445,
    993, 995, 1883, 3306, 5060, 5353, 5432, 8008, 8009, 8080,
    8443, 8888, 9090, 27017,
})

# Standard outbound ports where local machines legitimately open many connections
_STANDARD_OUTBOUND_PORTS = frozenset({80, 443, 8080, 8443, 27015, 27016, 27017, 27018})

# Known malware/backdoor port names for alert descriptions
_BUILTIN_PORT_NAMES = {
    4444: 'Metasploit/Meterpreter', 5555: 'Android ADB/Trojan',
    6666: 'IRC Backdoor', 1337: 'Common Backdoor',
    31337: 'Back Orifice', 12345: 'NetBus Trojan',
    65535: 'Backdoor', 6667: 'IRC Botnet C2',
}

# TLDs with a high rate of abuse. Stored WITHOUT the leading dot and compared
# against the final label only — `query.endswith('top')` also matches 'laptop',
# 'desktop' and 'rooftop', which single-label LLMNR/NetBIOS lookups produce
# constantly on Windows networks.
_BUILTIN_HIGH_ABUSE_TLDS = frozenset({'xyz', 'top', 'buzz', 'tk', 'ml', 'ga', 'cf', 'gq'})


def load_rule_pack():
    """
    Load rules/default_rules.json, shipped alongside the source (and bundled by
    PyInstaller). It was previously packaged and documented but never read, so the
    ports and TLDs in it had quietly drifted away from the hardcoded values.

    A user copy at ~/.netsentinel/rules/default_rules.json overrides the bundled one.
    Returns (bad_ports: dict[int, str], tlds: set[str]).
    """
    candidates = []
    try:
        from src.config import RULES_DIR
        candidates.append(os.path.join(RULES_DIR, 'default_rules.json'))
    except Exception:
        pass
    base = getattr(sys, '_MEIPASS', None) or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.append(os.path.join(base, 'rules', 'default_rules.json'))

    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
            ports = {}
            for port_str, name in data.get('known_bad_ports', {}).get('ports', {}).items():
                try:
                    ports[int(port_str)] = str(name)
                except (TypeError, ValueError):
                    logger.warning("Ignoring non-numeric port %r in %s", port_str, path)
            tlds = {str(t).lstrip('.').lower() for t in data.get('suspicious_tlds', [])}
            logger.info("Loaded rule pack from %s: %d ports, %d TLDs",
                        path, len(ports), len(tlds))
            return ports, tlds
        except Exception as e:
            logger.error("Could not load rule pack %s: %s", path, e)
    return {}, set()


_RULE_PACK_PORTS, _RULE_PACK_TLDS = load_rule_pack()

# Rule-pack entries merge on top of the built-ins, so editing the JSON has an effect.
_PORT_NAMES = {**_BUILTIN_PORT_NAMES, **_RULE_PACK_PORTS}
_HIGH_ABUSE_TLDS = frozenset(_BUILTIN_HIGH_ABUSE_TLDS | _RULE_PACK_TLDS)


def _domain_matches(domain, domain_set):
    """Match a domain against a set of suffixes, walking up the label hierarchy."""
    if not domain or not domain_set:
        return False
    domain = domain.lower().rstrip('.')
    if domain in domain_set:
        return True
    idx = 0
    while True:
        idx = domain.find('.', idx)
        if idx == -1:
            return False
        idx += 1
        if domain[idx:] in domain_set:
            return True


def _tld_of(domain):
    """Return the final DNS label, lowercased. Empty for single-label names."""
    if not domain:
        return ''
    domain = domain.rstrip('.').lower()
    return domain.rsplit('.', 1)[-1] if '.' in domain else ''


# Service names for brute force alert descriptions
_SERVICE_NAMES = {
    22: 'SSH', 3389: 'RDP', 21: 'FTP', 23: 'Telnet',
    445: 'SMB', 1433: 'MSSQL', 3306: 'MySQL', 5432: 'PostgreSQL',
}


class SlidingPortWindow:
    """
    Distinct destination ports seen from one source within a time window.

    The port-scan rule needs the distinct-port count on *every* packet. Rebuilding
    a set from the history each time is O(window) per packet — the profiler recorded
    ~1000 set operations per packet against a 500-entry history.

    Instead, keep the history in arrival order alongside a Counter of live ports.
    Each entry is appended once and evicted once, so maintaining the count is
    amortised O(1) and `unique_ports` is a plain len().
    """

    __slots__ = ('_events', '_port_counts', '_window', '_max_events')

    def __init__(self, window_sec, max_events=2000):
        self._events = deque()          # (timestamp, port, dst_ip), oldest first
        self._port_counts = Counter()   # port -> occurrences still inside the window
        self._window = window_sec
        self._max_events = max_events

    def add(self, timestamp, port, dst_ip):
        self._events.append((timestamp, port, dst_ip))
        self._port_counts[port] += 1
        self._evict(timestamp)

    def _evict(self, now):
        cutoff = now - self._window
        events = self._events
        # Time-based eviction, then a hard cap so a burst cannot grow this without
        # bound before the window advances.
        while events and (events[0][0] < cutoff or len(events) > self._max_events):
            _, port, _ = events.popleft()
            if self._port_counts[port] <= 1:
                del self._port_counts[port]
            else:
                self._port_counts[port] -= 1

    @property
    def unique_ports(self):
        return len(self._port_counts)

    def ports(self):
        """Sorted distinct ports. Only called when an alert actually fires."""
        return sorted(self._port_counts)

    def destinations(self):
        """Distinct destinations in the window. Only called when an alert fires."""
        return {dst for _, _, dst in self._events if dst}

    @property
    def last_seen(self):
        return self._events[-1][0] if self._events else 0

    def __len__(self):
        return len(self._events)


class Alert:
    """Represents a security alert."""
    _id_gen = itertools.count(1)

    def __init__(self, rule_id, severity, title, description,
                 src_ip="", dst_ip="", src_port=0, dst_port=0,
                 protocol="", evidence=None, category=""):
        self.id = next(Alert._id_gen)
        self.timestamp = time.time()
        self.rule_id = rule_id
        self.severity = severity
        self.title = title
        self.description = description
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.evidence = evidence or {}
        self.category = category
        self.acknowledged = False

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'time_str': datetime.fromtimestamp(self.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
            'rule_id': self.rule_id,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'evidence': self.evidence,
            'category': self.category,
            'acknowledged': self.acknowledged,
        }

    def __repr__(self):
        return f"<Alert [{self.severity}] {self.title} from {self.src_ip}>"


class IDSEngine:
    """
    Rule-based Intrusion Detection System.
    Detects: port scans, brute force, suspicious ports, protocol anomalies,
    data exfiltration, ARP spoofing, and more.
    """

    def __init__(self, config, alert_callback=None, threat_intel=None, net_env=None):
        self.config = config
        self.alert_callback = alert_callback
        self.threat_intel = threat_intel
        self.net_env = net_env
        self.enabled = config.get('ids', 'enabled', default=True)
        self.baseline_whitelist = None  # Set by app after init

        # Alert dedup / cooldown
        self._alert_cooldowns = {}  # {rule_id+ip: last_alert_time}
        self.cooldown_sec = config.get('alerts', 'cooldown_sec', default=30)

        # Suppressions measured in hours rather than seconds, kept separate so the
        # short-cooldown pruner cannot discard them.
        self._long_suppressions = {}

        # Escalating per-destination exfil thresholds, in MB.
        self._exfil_thresholds = {}

        # Whitelists/Blacklists
        self.whitelist_ips = set(config.get('whitelists', 'ips', default=[]))
        self.whitelist_ports = set(config.get('whitelists', 'ports', default=[]))
        self.blacklist_ips = set(config.get('blacklists', 'ips', default=[]))
        self.blacklist_ports = set(config.get('blacklists', 'ports', default=[]))
        # Domain and process lists existed in DEFAULT_CONFIG but were never consulted,
        # so entering one appeared to work and silently did nothing.
        self.whitelist_domains = {d.lower().lstrip('.')
                                  for d in config.get('whitelists', 'domains', default=[])}
        self.whitelist_processes = {p.lower()
                                    for p in config.get('whitelists', 'processes', default=[])}
        self.blacklist_domains = {d.lower().lstrip('.')
                                  for d in config.get('blacklists', 'domains', default=[])}
        self.known_bad_ports = set(config.get('ids', 'known_bad_ports', default=[]))
        self.blocked_ja3 = {f.lower() for f in config.get('ids', 'blocked_ja3', default=[])}
        self.blocked_ja4 = {f.lower() for f in config.get('ids', 'blocked_ja4', default=[])}

        # Thresholds
        self.port_scan_threshold = config.get('ids', 'port_scan_threshold', default=15)
        self.port_scan_window = config.get('ids', 'port_scan_window_sec', default=60)
        self.brute_force_threshold = config.get('ids', 'brute_force_threshold', default=10)
        self.brute_force_window = config.get('ids', 'brute_force_window_sec', default=30)
        self.large_upload_mb = config.get('ids', 'large_upload_mb', default=100)

        # State tracking
        self._port_access = defaultdict(
            lambda: SlidingPortWindow(self.port_scan_window))  # {src_ip: SlidingPortWindow}
        self._conn_failures = defaultdict(lambda: deque(maxlen=500))  # {src_ip: [time]}
        self._arp_table = {}  # {ip: mac}
        self._data_transfer = defaultdict(float)  # {dst_ip: bytes}
        self._active_transfer_ips = set()  # IPs seen this cleanup cycle
        self._dns_queries_by_ip = defaultdict(lambda: deque(maxlen=200))
        self._icmp_flood_tracker = defaultdict(lambda: deque(maxlen=200))

        # DNS resolution tracking: maps IPs to domains and vice versa
        # When we see DNS query "docs.google.com" followed by a connection to 142.x.x.x,
        # we know that IP was resolved from docs.google.com
        self._dns_to_ip = {}        # {domain: (ip, timestamp)} - from DNS responses
        self._ip_to_domains = defaultdict(set)  # {ip: {domain1, domain2}} - reverse mapping
        self._latest_dns_by_ip = {}  # {src_ip: (domain, timestamp)} - O(1) lookup for inference
        self._ip_to_domains_max = 20  # Max domains to track per IP

        # Distinct JA4 fingerprints observed, for the dashboard and for spotting a
        # client stack that has never been seen on this network before.
        self._ja4_seen = {}

        # DNS response analysis: NXDOMAIN bursts (DGA) and fast-flux hosting.
        # Queries alone cannot see either — both live in the answer section.
        self.dns_monitor = DnsResponseMonitor(config)

        # Statistics
        self.alerts_generated = 0
        self.total_packets_inspected = 0
        self.threat_intel_hits = 0

        # Threat intel lookup cache: avoid checking the same IP/domain repeatedly
        # {ip_or_domain: (result_or_None, timestamp)}
        self._ti_cache = {}
        self._ti_cache_ttl = 300  # Cache results for 5 minutes
        self._ti_cache_max = 10000

        # Periodic state cleanup
        self._last_cleanup = time.time()
        self._cleanup_interval = 60  # Prune stale state every 60 seconds
        self._packets_since_cleanup = 0

        logger.info("IDS Engine initialized. Rules active. Threat intel: %s",
                     "enabled" if threat_intel else "disabled")

    def _periodic_cleanup(self, force=False):
        """Prune stale entries from all state-tracking dicts to prevent memory leaks."""
        # Only check time every 1000 packets to avoid time.time() overhead
        if not force:
            self._packets_since_cleanup += 1
            if self._packets_since_cleanup < 1000:
                return
            self._packets_since_cleanup = 0

        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now

        # Prune alert cooldowns older than 5x the cooldown window
        max_cooldown_age = self.cooldown_sec * 5
        stale_keys = [k for k, t in self._alert_cooldowns.items()
                      if now - t > max_cooldown_age]
        for k in stale_keys:
            del self._alert_cooldowns[k]

        # Prune data transfer tracking — remove entries not updated in 10 minutes
        # (these accumulate one entry per unique dst_ip seen, forever)
        stale_transfers = [ip for ip, _ in self._data_transfer.items()
                           if ip not in self._active_transfer_ips]
        for ip in stale_transfers:
            del self._data_transfer[ip]
        self._active_transfer_ips = set()

        # Prune dns_to_ip cache — remove entries older than 10 minutes
        stale_dns = [d for d, (ip, ts) in self._dns_to_ip.items()
                     if now - ts > 600]
        for d in stale_dns:
            del self._dns_to_ip[d]

        # Prune _latest_dns_by_ip — remove entries older than 60 seconds
        stale_latest = [ip for ip, (_, ts) in self._latest_dns_by_ip.items()
                        if now - ts > 60]
        for ip in stale_latest:
            del self._latest_dns_by_ip[ip]

        # Cap ip_to_domains — remove IPs with oldest inferred associations
        max_ip_entries = 5000
        if len(self._ip_to_domains) > max_ip_entries:
            # Keep only the most recently active IPs (heuristic: smaller sets first)
            sorted_ips = sorted(self._ip_to_domains.keys(),
                                key=lambda ip: len(self._ip_to_domains[ip]))
            for ip in sorted_ips[:len(sorted_ips) // 4]:
                del self._ip_to_domains[ip]

        # Prune port_access / conn_failures / dns_queries / icmp trackers
        # — remove IPs not seen in 5 minutes
        stale_sources = [ip for ip, w in self._port_access.items()
                         if len(w) and now - w.last_seen > 300]
        for ip in stale_sources:
            del self._port_access[ip]

        for tracker in (self._conn_failures, self._dns_queries_by_ip,
                        self._icmp_flood_tracker):
            stale = [k for k, dq in tracker.items()
                     if dq and (now - (dq[-1][0] if isinstance(dq[-1], tuple) else dq[-1])) > 300]
            for k in stale:
                del tracker[k]

        # Prune long-lived suppressions once their window has fully elapsed
        stale_long = [k for k, t in self._long_suppressions.items() if now - t > 7200]
        for k in stale_long:
            del self._long_suppressions[k]

        # Prune escalating exfil thresholds for destinations no longer being tracked
        stale_exfil = [ip for ip in self._exfil_thresholds if ip not in self._data_transfer]
        for ip in stale_exfil:
            del self._exfil_thresholds[ip]

        # Cap the ARP table. Bounded by LAN size in normal use, but an ARP flood
        # from a hostile host would otherwise grow it without limit.
        if len(self._arp_table) > 4096:
            for k in list(self._arp_table)[:len(self._arp_table) // 2]:
                del self._arp_table[k]

    def inspect_packet(self, pkt_info):
        """
        Run all detection rules against a single packet.
        Returns list of Alert objects generated.
        """
        if not self.enabled:
            return []

        self.total_packets_inspected += 1
        self._periodic_cleanup()
        alerts = []

        # ─── TLS SNI: the destination name for encrypted traffic ──────
        # The ClientHello is plaintext even under TLS 1.3, so this is a direct
        # IP -> name mapping that does not depend on observing the DNS lookup.
        # It is also the only one that survives DNS-over-HTTPS.
        if pkt_info.tls_ja4:
            entry = self._ja4_seen.get(pkt_info.tls_ja4)
            if entry is None:
                if len(self._ja4_seen) < 5000:
                    self._ja4_seen[pkt_info.tls_ja4] = [time.time(), 1]
            else:
                entry[0] = time.time()
                entry[1] += 1

        if pkt_info.tls_sni and pkt_info.dst_ip:
            known = self._ip_to_domains.get(pkt_info.dst_ip)
            if known is None or len(known) < self._ip_to_domains_max:
                self._ip_to_domains[pkt_info.dst_ip].add(pkt_info.tls_sni)

        # ─── DNS Resolution Tracking (always runs, lightweight) ────────
        # Track every DNS query so we can map IPs to domains later
        if pkt_info.dns_query:
            now = time.time()
            # O(1) index: remember most recent DNS query per source IP
            self._latest_dns_by_ip[pkt_info.src_ip] = (pkt_info.dns_query, now)
            # When we see a DNS response, map the domain to the destination
            if pkt_info.dns_response:
                self._dns_to_ip[pkt_info.dns_query] = (pkt_info.dns_response, now)
                resp_ip = pkt_info.dns_response
                if len(self._ip_to_domains.get(resp_ip, set())) < self._ip_to_domains_max:
                    self._ip_to_domains[resp_ip].add(pkt_info.dns_query)

        # Also infer domain from recent DNS queries:
        # If we just saw a DNS query for "docs.google.com" and now see a TCP connection
        # to an IP, that IP likely resolved from that domain.
        # Uses O(1) index lookup instead of scanning the full recent_dns deque.
        if pkt_info.dst_ip and pkt_info.protocol in ('TCP', 'UDP') and not pkt_info.dns_query:
            entry = self._latest_dns_by_ip.get(pkt_info.src_ip)
            if entry:
                domain, ts = entry
                if time.time() - ts < 30:
                    if len(self._ip_to_domains.get(pkt_info.dst_ip, set())) < self._ip_to_domains_max:
                        self._ip_to_domains[pkt_info.dst_ip].add(domain)

        # Manual whitelist = skip everything entirely
        if pkt_info.src_ip in self.whitelist_ips or pkt_info.dst_ip in self.whitelist_ips:
            return []
        if self.whitelist_processes and pkt_info.process_name and \
                pkt_info.process_name.lower() in self.whitelist_processes:
            return []
        if self.whitelist_domains and self._matches_domain_list(
                pkt_info, self.whitelist_domains):
            return []

        # Explicitly blacklisted domain
        blacklist_target = pkt_info.dns_query or pkt_info.tls_sni
        if self.blacklist_domains and blacklist_target and \
                _domain_matches(blacklist_target, self.blacklist_domains):
            alerts.append(self._create_alert(
                "BL-DOMAIN", Severity.HIGH,
                "Blacklisted Domain",
                f"Connection to blacklisted domain: {blacklist_target}",
                pkt_info,
                evidence={
                    'queried_domain': blacklist_target,
                    'requesting_ip': pkt_info.src_ip,
                    'process': pkt_info.process_name or 'Unknown',
                    'recommendation': 'This domain is on your configured blacklist. '
                        'Identify the process that requested it.',
                },
                category="Blacklist"
            ))

        # Smart auto-whitelist: skip HEURISTIC rules for known infrastructure
        skip_heuristics = False
        if self.net_env:
            skip_heuristics = self.net_env.should_skip_ids(
                pkt_info.src_ip, pkt_info.dst_ip,
                pkt_info.dst_port, pkt_info.protocol
            )

        # === Rule 1: Threat Intel - IP Reputation (cloud-aware) ===
        if self.threat_intel:
            for ip_field, direction in [(pkt_info.src_ip, 'inbound'), (pkt_info.dst_ip, 'outbound')]:
                result = self._cached_ti_check('ip', ip_field)
                if result:
                    self.threat_intel_hits += 1

                    # Get all domains associated with this IP
                    associated_domains = self._get_domains_for_ip(ip_field)

                    # Cloud-aware severity: check if this IP is serving known
                    # legitimate cloud services
                    is_cloud_service = False
                    cloud_domains = []
                    non_cloud_domains = []
                    if self.net_env and associated_domains:
                        for d in associated_domains:
                            if self.net_env.is_known_cloud_domain(d):
                                is_cloud_service = True
                                cloud_domains.append(d)
                            else:
                                non_cloud_domains.append(d)

                    # Determine severity based on cloud context
                    if is_cloud_service and not non_cloud_domains:
                        # All associated domains are known cloud services
                        # This is almost certainly shared infrastructure (e.g., GCP IP
                        # serving docs.google.com but also flagged for hosting something bad)
                        sev = Severity.LOW
                        title = f"Shared Cloud IP in Threat Feed ({result['category']})"
                        desc = (f"IP {ip_field} appears in threat feed but is associated with "
                                f"known cloud service: {', '.join(cloud_domains[:3])}. "
                                f"Likely shared infrastructure — probably a false positive.")
                        recommendation = (
                            'This IP is in a threat feed, but your traffic is going to a '
                            'recognized cloud service (e.g., Google, Microsoft, AWS). '
                            'Shared cloud IPs often get flagged because other customers '
                            'on the same infrastructure run malicious services. '
                            'If the domain shown is one you recognize and use, this is '
                            'almost certainly safe. If you see an unfamiliar domain here, '
                            'investigate further.'
                        )
                    elif is_cloud_service and non_cloud_domains:
                        # Mix of cloud and unknown domains — moderate concern
                        sev = Severity.MEDIUM
                        title = f"Suspicious Cloud IP ({result['category']})"
                        desc = (f"IP {ip_field} hosts both known services ({', '.join(cloud_domains[:2])}) "
                                f"and unknown domains ({', '.join(non_cloud_domains[:2])})")
                        recommendation = (
                            'This cloud IP serves both legitimate and unrecognized domains. '
                            'Check which domain YOUR connection is going to. If it\'s a '
                            'known service you use, it\'s likely fine. If it\'s an '
                            'unfamiliar domain on cloud infrastructure, it could be '
                            'malicious content hosted on a legitimate cloud platform.'
                        )
                    else:
                        # No cloud association — standard threat intel alert
                        sev = Severity.CRITICAL if result['category'] in ('Botnet C2', 'Malicious SSL') \
                            else Severity.HIGH
                        title = f"Known Malicious IP ({result['category']})"
                        desc = (f"{direction.title()} traffic "
                                f"{'from' if direction == 'inbound' else 'to'} "
                                f"known malicious IP {ip_field}")
                        if associated_domains:
                            desc += f" (domain: {', '.join(list(associated_domains)[:3])})"
                        recommendation = (
                            'This IP was found in a threat intelligence feed with NO '
                            'association to known cloud services. This is a strong indicator '
                            'of malicious activity. Investigate which process made this '
                            'connection and consider blocking this IP in your firewall.'
                        )

                    alerts.append(self._create_alert(
                        "THREAT-INTEL-IP", sev, title, desc, pkt_info,
                        evidence={
                            'matched_ip': ip_field,
                            'direction': direction,
                            'threat_feed': result['feed'],
                            'threat_category': result['category'],
                            'feed_description': result['description'],
                            'associated_domains': list(associated_domains)[:10] if associated_domains else ['No domain resolved — direct IP connection'],
                            'cloud_domains': cloud_domains[:5] if cloud_domains else [],
                            'unknown_domains': non_cloud_domains[:5] if non_cloud_domains else [],
                            'is_shared_cloud_ip': is_cloud_service,
                            'connection': f"{pkt_info.src_ip}:{pkt_info.src_port} → {pkt_info.dst_ip}:{pkt_info.dst_port} ({pkt_info.protocol})",
                            'dst_port': pkt_info.dst_port,
                            'protocol': pkt_info.protocol,
                            'process': pkt_info.process_name or 'Unknown',
                            'recommendation': recommendation,
                        },
                        category="Threat Intelligence"
                    ))

        # === Rule 2: Threat Intel - Domain Reputation ===
        # observed_domain is the DNS query when we saw one, otherwise the TLS SNI.
        # Before SNI was parsed, this rule could not fire at all on HTTPS traffic.
        observed_domain = pkt_info.dns_query or pkt_info.tls_sni
        if self.threat_intel and observed_domain:
            # FIRST: Check if this is a first-party cloud domain (docs.google.com,
            # outlook.office365.com, etc.). These appear in feeds like URLhaus
            # because users share malware THROUGH the service, but the domain
            # itself is legitimate. Skip entirely.
            is_first_party_cloud = False
            is_cloud_hosting = False
            if self.net_env:
                if self.net_env.is_known_cloud_domain(observed_domain):
                    is_first_party_cloud = True
                elif self.net_env.is_cloud_hosting_domain(observed_domain):
                    is_cloud_hosting = True

            if not is_first_party_cloud:
                result = self._cached_ti_check('domain', observed_domain)
                if result and result.get('confidence') in ('HIGH', 'MEDIUM'):
                    self.threat_intel_hits += 1

                    if is_cloud_hosting:
                        # Cloud hosting domain (appspot.com, herokuapp.com, etc.)
                        # Anyone can deploy here — flag but note context
                        sev = Severity.HIGH
                        desc_extra = ('This domain is on a cloud hosting platform where '
                                      'anyone can deploy sites. Both legitimate and malicious '
                                      'content exists on these platforms.')
                    else:
                        # Not cloud at all — standard threat
                        sev = Severity.CRITICAL if result['confidence'] == 'HIGH' else Severity.HIGH
                        desc_extra = 'The domain itself is the concern, not the IP.'

                    alerts.append(self._create_alert(
                        "THREAT-INTEL-DOMAIN", sev,
                        f"Malicious Domain ({result['category']})",
                        (f"DNS lookup for known malicious domain: {observed_domain}"
                         if pkt_info.dns_query else
                         f"TLS connection to known malicious domain: {observed_domain}"),
                        pkt_info,
                        evidence={
                            'queried_domain': observed_domain,
                            'observed_via': 'DNS query' if pkt_info.dns_query else 'TLS SNI',
                            'threat_feed': result['feed'],
                            'threat_category': result['category'],
                            'feed_description': result['description'],
                            'confidence': result['confidence'],
                            'match_type': result.get('match_type', 'exact'),
                            'matched_domain': result.get('matched_domain', observed_domain),
                            'hosted_on_cloud': is_cloud_hosting,
                            'connection': f"{pkt_info.src_ip}:{pkt_info.src_port} → "
                                          f"{pkt_info.dst_ip}:{pkt_info.dst_port}",
                            'requesting_ip': pkt_info.src_ip,
                            'process': pkt_info.process_name or 'Unknown',
                            'description': (
                                f'This domain appeared in a malware/threat database. '
                                f'{desc_extra}'
                            ),
                            'recommendation': (
                                'Identify which application made this DNS request. '
                                'If you don\'t recognize this domain, it may indicate '
                                'malware, a phishing attempt, or unwanted software. '
                                'Check your browser history and running processes.'
                            ),
                        },
                        category="Threat Intelligence"
                    ))

        # If this is auto-whitelisted infrastructure traffic (gateway, DNS, broadcast, etc.)
        # emit any threat intel alerts found above but skip all heuristic rules below
        if skip_heuristics:
            valid_alerts = [a for a in alerts if a is not None]
            for alert in valid_alerts:
                if self.alert_callback:
                    self.alert_callback(alert)
            self.alerts_generated += len(valid_alerts)
            return valid_alerts

        # === Rule 2b: Known-bad TLS client fingerprint ===
        # JA3/JA4 identify the client *stack*, not the site, so this matches malware
        # using a distinctive TLS library even when everything it sends is encrypted
        # and the destination is one nobody has reported yet.
        if self.blocked_ja3 or self.blocked_ja4:
            matched = None
            if pkt_info.tls_ja3 and pkt_info.tls_ja3.lower() in self.blocked_ja3:
                matched = ('JA3', pkt_info.tls_ja3)
            elif pkt_info.tls_ja4 and pkt_info.tls_ja4.lower() in self.blocked_ja4:
                matched = ('JA4', pkt_info.tls_ja4)
            if matched:
                kind, value = matched
                alerts.append(self._create_alert(
                    "TLS-FINGERPRINT", Severity.HIGH,
                    f"Known Malicious TLS Client ({kind})",
                    f"TLS client fingerprint {value} is on the blocklist",
                    pkt_info,
                    evidence={
                        'fingerprint_type': kind,
                        'fingerprint': value,
                        'server_name': pkt_info.tls_sni or 'none (direct IP)',
                        'tls_version': pkt_info.tls_version,
                        'process': pkt_info.process_name or 'Unknown',
                        'description': (
                            'This fingerprint is a hash of the TLS options the client '
                            'offered. It identifies the software making the connection, '
                            'not the site it is visiting, so it still works when the '
                            'traffic itself is encrypted.'),
                        'recommendation': (
                            'Identify the process making this connection. A fingerprint '
                            'that matches no browser or tool you installed is a strong '
                            'indicator of malware using its own TLS stack.'),
                    },
                    category="Threat Intelligence"
                ))

        # === Rule 2c: DNS response analysis (DGA bursts, fast-flux) ===
        if pkt_info.dns_rcode >= 0 and pkt_info.dns_query:
            for finding in self.dns_monitor.observe_response(
                    pkt_info.dst_ip or pkt_info.src_ip,
                    pkt_info.dns_query,
                    pkt_info.dns_rcode,
                    pkt_info.dns_answers,
                    pkt_info.dns_ttl,
                    pkt_info.timestamp):
                alerts.append(self._alert_from_dns_finding(finding, pkt_info))

        # === Rule 3: Blacklisted IP ===
        if pkt_info.src_ip in self.blacklist_ips:
            alerts.append(self._create_alert(
                "BL-IP-SRC", Severity.HIGH,
                "Blacklisted Source IP",
                f"Traffic from blacklisted IP: {pkt_info.src_ip}",
                pkt_info,
                evidence={
                    'blacklisted_ip': pkt_info.src_ip,
                    'direction': 'inbound',
                    'destination': f"{pkt_info.dst_ip}:{pkt_info.dst_port}",
                    'protocol': pkt_info.protocol,
                    'process': pkt_info.process_name or 'Unknown',
                },
                category="Blacklist"
            ))
        if pkt_info.dst_ip in self.blacklist_ips:
            alerts.append(self._create_alert(
                "BL-IP-DST", Severity.HIGH,
                "Blacklisted Destination IP",
                f"Traffic to blacklisted IP: {pkt_info.dst_ip}",
                pkt_info,
                evidence={
                    'blacklisted_ip': pkt_info.dst_ip,
                    'direction': 'outbound',
                    'source': f"{pkt_info.src_ip}:{pkt_info.src_port}",
                    'protocol': pkt_info.protocol,
                    'process': pkt_info.process_name or 'Unknown',
                },
                category="Blacklist"
            ))

        # === Rule 4: Suspicious Ports ===
        if pkt_info.dst_port in self.known_bad_ports:
            alerts.append(self._create_alert(
                "BAD-PORT", Severity.HIGH,
                "Known Malicious Port",
                f"Connection to known bad port {pkt_info.dst_port} "
                f"({_PORT_NAMES.get(pkt_info.dst_port, 'Suspicious')})",
                pkt_info,
                evidence={
                    'port': pkt_info.dst_port,
                    'known_usage': _PORT_NAMES.get(pkt_info.dst_port, 'Unknown malicious service'),
                    'source': f"{pkt_info.src_ip}:{pkt_info.src_port}",
                    'destination': f"{pkt_info.dst_ip}:{pkt_info.dst_port}",
                    'protocol': pkt_info.protocol,
                    'process': pkt_info.process_name or 'Unknown',
                    'recommendation': 'This port is commonly used by malware. Investigate the '
                        'process making this connection.',
                },
                category="Suspicious Port"
            ))

        # === Rule 5: Port Scan Detection (with full port list) ===
        # A port scan probes many SERVICE ports on a target to find open services.
        # Key exclusions to avoid false positives:
        #   - Server response traffic: a DNS server (src_port 53) sending replies to
        #     many ephemeral dst_ports is NOT a scan — it's answering queries.
        #   - Ephemeral-only: if ALL "scanned" ports are >= 1024, the source is a
        #     server responding to client connections, not probing for services.
        #   - Single-service fan-out: a device responding on one service port (8008,
        #     8009, 80, 443) to many clients' ephemeral ports is normal.
        if pkt_info.src_ip and pkt_info.dst_port:
            now = time.time()

            # Don't track as "scanning" if src is sending FROM a well-known service
            # port — that's response traffic, not reconnaissance
            src_is_service_response = pkt_info.src_port in _COMMON_SERVICE_PORTS

            if not src_is_service_response:
                window = self._port_access[pkt_info.src_ip]
                window.add(now, pkt_info.dst_port, pkt_info.dst_ip)
                unique_ports = window.unique_ports

                if unique_ports >= self.port_scan_threshold:
                    # Only materialised when an alert fires, not on every packet.
                    scanned_ports = window.ports()
                    dst_ips_hit = window.destinations()
                    # Check if ALL scanned ports are ephemeral (>= 1024)
                    # If so, this is a server responding to many clients, not a scan
                    has_low_ports = scanned_ports[0] < 1024

                    if has_low_ports:
                        alerts.append(self._create_alert(
                            "PORT-SCAN", Severity.HIGH,
                            "Port Scan Detected",
                            f"{pkt_info.src_ip} scanned {unique_ports} ports in {self.port_scan_window}s",
                            pkt_info,
                            evidence={
                                'scanner_ip': pkt_info.src_ip,
                                'unique_port_count': unique_ports,
                                'ports_scanned': scanned_ports[:50],
                                'window_seconds': self.port_scan_window,
                                'target_ips': list(dst_ips_hit)[:10],
                                'scan_rate': f"{unique_ports / self.port_scan_window:.1f} ports/sec",
                                'process': pkt_info.process_name or 'Unknown',
                                'recommendation': 'A port scan probes for open services. This may indicate '
                                    'reconnaissance before an attack. If source is external, block it.',
                            },
                            category="Reconnaissance"
                        ))

        # === Rule 6: Brute Force / Failed Connections ===
        if pkt_info.flags and 'R' in pkt_info.flags:
            now = time.time()
            key = f"{pkt_info.src_ip}->{pkt_info.dst_ip}:{pkt_info.dst_port}"
            self._conn_failures[key].append(now)
            recent = [t for t in self._conn_failures[key]
                       if now - t < self.brute_force_window]
            if len(recent) >= self.brute_force_threshold:
                service = _SERVICE_NAMES.get(pkt_info.dst_port, f'port {pkt_info.dst_port}')
                alerts.append(self._create_alert(
                    "BRUTE-FORCE", Severity.HIGH,
                    f"Potential Brute Force ({service})",
                    f"{len(recent)} failed connections to {service} in {self.brute_force_window}s",
                    pkt_info,
                    evidence={
                        'attacker_ip': pkt_info.src_ip,
                        'target': f"{pkt_info.dst_ip}:{pkt_info.dst_port}",
                        'target_service': service,
                        'failed_attempts': len(recent),
                        'window_seconds': self.brute_force_window,
                        'rate': f"{len(recent) / self.brute_force_window:.1f} attempts/sec",
                        'recommendation': 'Multiple failed connections suggest credential '
                            'guessing. Consider blocking the source IP and checking '
                            'authentication logs.',
                    },
                    category="Brute Force"
                ))

        # === Rule 7: SYN Flood Detection ===
        # A real SYN flood hammers ONE target with many SYNs to exhaust its
        # connection table. Normal browsing fans SYNs out to MANY different
        # destinations — that's parallel connection setup, not an attack.
        #
        # Fix: track SYNs per (src → dst) pair. Only alert when one source
        # sends many SYNs to ONE destination. Also apply higher thresholds
        # for local machines making outbound connections to standard ports.
        if pkt_info.protocol == "TCP" and pkt_info.flags:
            if 'S' in pkt_info.flags and 'A' not in pkt_info.flags:
                now = time.time()

                # Track per (src, dst) pair — this is the key change
                pair_key = f"syn-{pkt_info.src_ip}->{pkt_info.dst_ip}"
                if pair_key not in self._conn_failures:
                    self._conn_failures[pair_key] = deque(maxlen=500)
                self._conn_failures[pair_key].append(now)
                recent = [t for t in self._conn_failures[pair_key] if now - t < 10]

                # Determine if this is local outbound (browsing) vs external inbound (attack)
                src_is_local = self._is_local_ip(pkt_info.src_ip)

                # Higher threshold for local outbound to standard service ports
                # (browser opening many tabs = dozens of SYNs to one CDN IP)
                is_outbound_to_service = (
                    src_is_local and pkt_info.dst_port in _STANDARD_OUTBOUND_PORTS
                )

                if is_outbound_to_service:
                    threshold = 200  # Local machine → CDN, much higher bar
                else:
                    threshold = 50   # External → internal, or non-standard ports

                if len(recent) > threshold:
                    # Final check: skip if destination is a known gateway or whitelisted
                    skip = False
                    if self.net_env and hasattr(self.net_env, 'gateways'):
                        if pkt_info.dst_ip in (self.net_env.gateways or []):
                            skip = True
                    if pkt_info.dst_ip in self.whitelist_ips:
                        skip = True

                    if not skip:
                        alerts.append(self._create_alert(
                            "SYN-FLOOD", Severity.CRITICAL,
                            "SYN Flood Attack",
                            f"{len(recent)} SYN packets from {pkt_info.src_ip} "
                            f"to {pkt_info.dst_ip} in 10 seconds",
                            pkt_info,
                            evidence={
                                'attacker_ip': pkt_info.src_ip,
                                'target_ip': pkt_info.dst_ip,
                                'syn_count': len(recent),
                                'rate': f"{len(recent) / 10:.0f} SYNs/sec",
                                'target': pkt_info.dst_ip,
                                'threshold_used': threshold,
                                'is_local_outbound': is_outbound_to_service,
                                'description': 'SYN flood exhausts server resources by sending '
                                    'many connection requests without completing the handshake.',
                                'recommendation': 'This is a denial-of-service attack. Block the '
                                    'source IP immediately.' if not src_is_local else
                                    'High volume outbound SYN traffic from local machine. '
                                    'Check for malware or runaway application.',
                            },
                            category="DoS"
                        ))

        # === Rule 8: ICMP Flood ===
        if pkt_info.protocol == "ICMP":
            now = time.time()
            self._icmp_flood_tracker[pkt_info.src_ip].append(now)
            recent = [t for t in self._icmp_flood_tracker[pkt_info.src_ip]
                       if now - t < 10]
            if len(recent) > 30:
                alerts.append(self._create_alert(
                    "ICMP-FLOOD", Severity.HIGH,
                    "ICMP Flood Detected",
                    f"{len(recent)} ICMP packets from {pkt_info.src_ip} in 10 seconds",
                    pkt_info,
                    evidence={
                        'source_ip': pkt_info.src_ip,
                        'icmp_count': len(recent),
                        'rate': f"{len(recent) / 10:.0f} pings/sec",
                        'description': 'High volume of ICMP traffic can indicate a ping flood '
                            'DoS attack or network scanning.',
                        'recommendation': 'Block ICMP from this source if not expected.',
                    },
                    category="DoS"
                ))

        # === Rule 9: Suspicious DNS (with full detail) ===
        # Runs on the TLS SNI as well: a connection to a high-abuse TLD is the same
        # signal whether the name came from a DNS query or the handshake.
        if pkt_info.dns_query or pkt_info.tls_sni:
            query = pkt_info.dns_query or pkt_info.tls_sni
            if pkt_info.dns_query:
                self._dns_queries_by_ip[pkt_info.src_ip].append((time.time(), query))
            query_parts = query.split('.')
            subdomain = query_parts[0] if query_parts else ''

            # Skip DNS heuristics for known cloud/CDN domains
            is_known_cloud = False
            if self.net_env and self.net_env.is_known_cloud_domain(query):
                is_known_cloud = True

            # Skip DNS heuristics for domains learned during baseline period
            is_learned = False
            if self.baseline_whitelist and self.baseline_whitelist.is_learned_domain(query):
                is_learned = True

            # Long subdomain (possible DNS tunneling) — skip for known/learned domains
            if len(query) > 60 and not is_known_cloud and not is_learned:
                # Calculate entropy of subdomain
                from collections import Counter
                import math
                char_freq = Counter(subdomain)
                ent = -sum((c/len(subdomain)) * math.log2(c/len(subdomain))
                           for c in char_freq.values()) if subdomain else 0

                alerts.append(self._create_alert(
                    "DNS-TUNNEL", Severity.HIGH,
                    "Possible DNS Tunneling",
                    f"Unusually long DNS query ({len(query)} chars) with high entropy",
                    pkt_info,
                    evidence={
                        'full_query': query,
                        'query_length': len(query),
                        'subdomain': subdomain[:80],
                        'subdomain_length': len(subdomain),
                        'subdomain_entropy': round(ent, 2),
                        'domain_levels': len(query_parts),
                        'requesting_ip': pkt_info.src_ip,
                        'process': pkt_info.process_name or 'Unknown',
                        'description': 'DNS tunneling encodes data in DNS queries to '
                            'exfiltrate information or establish covert communication channels. '
                            'High entropy subdomains are a strong indicator.',
                        'recommendation': 'Identify the process making these queries. '
                            'Legitimate software rarely uses subdomains this long.',
                    },
                    category="Exfiltration"
                ))

            # Suspicious TLD check — skip for known cloud or learned domains
            tld = _tld_of(query)
            if not is_known_cloud and not is_learned and tld in _HIGH_ABUSE_TLDS:
                recent_same_tld = [
                    q for _, q in self._dns_queries_by_ip[pkt_info.src_ip]
                    if _tld_of(q) == tld
                ]
                alerts.append(self._create_alert(
                    "DNS-BAD-TLD", Severity.MEDIUM,
                    f"Suspicious TLD Query (.{tld})",
                    f"DNS query to high-abuse TLD: {query}",
                    pkt_info,
                    evidence={
                        'full_query': query,
                        'suspicious_tld': f'.{tld}',
                        'recent_queries_same_tld': recent_same_tld[-10:],
                        'total_queries_this_tld': len(recent_same_tld),
                        'requesting_ip': pkt_info.src_ip,
                        'process': pkt_info.process_name or 'Unknown',
                        'description': f'The .{tld} TLD has a high rate of abuse and is '
                            'frequently used for phishing, malware distribution, and C2.',
                    },
                    category="Suspicious DNS"
                ))

            # High DNS query rate from single source
            now = time.time()
            recent_dns = [t for t, _ in self._dns_queries_by_ip[pkt_info.src_ip]
                          if now - t < 10]
            if len(recent_dns) > 50:  # 50+ DNS queries in 10 seconds
                recent_domains = [q for t, q in self._dns_queries_by_ip[pkt_info.src_ip]
                                  if now - t < 10]
                unique_domains = list(set(recent_domains))
                alerts.append(self._create_alert(
                    "DNS-FLOOD", Severity.MEDIUM,
                    "Excessive DNS Queries",
                    f"{len(recent_dns)} DNS queries in 10s from {pkt_info.src_ip}",
                    pkt_info,
                    evidence={
                        'query_count': len(recent_dns),
                        'unique_domains': len(unique_domains),
                        'sample_domains': unique_domains[:20],
                        'rate': f"{len(recent_dns) / 10:.0f} queries/sec",
                        'requesting_ip': pkt_info.src_ip,
                        'process': pkt_info.process_name or 'Unknown',
                        'description': 'Extremely high DNS query rates can indicate DNS '
                            'tunneling, DGA malware (domain generation algorithms), or '
                            'DNS-based data exfiltration.',
                    },
                    category="Suspicious DNS"
                ))

        # === Rule 10: ARP Spoofing ===
        if pkt_info.protocol == "ARP" and pkt_info.src_ip and pkt_info.src_mac:
            if pkt_info.src_ip in self._arp_table:
                if self._arp_table[pkt_info.src_ip] != pkt_info.src_mac:
                    alerts.append(self._create_alert(
                        "ARP-SPOOF", Severity.CRITICAL,
                        "ARP Spoofing Detected",
                        f"IP {pkt_info.src_ip} changed MAC address",
                        pkt_info,
                        evidence={
                            'ip_address': pkt_info.src_ip,
                            'previous_mac': self._arp_table[pkt_info.src_ip],
                            'new_mac': pkt_info.src_mac,
                            'description': 'ARP spoofing is a man-in-the-middle attack where '
                                'an attacker sends fake ARP messages to associate their MAC '
                                'address with a legitimate IP, allowing traffic interception.',
                            'recommendation': 'Verify your gateway MAC address. Someone on your '
                                'local network may be intercepting traffic.',
                        },
                        category="MITM"
                    ))
            self._arp_table[pkt_info.src_ip] = pkt_info.src_mac

        # === Rule 11: Large Data Transfer (potential exfil, escalating) ===
        # Only outbound counts. Accumulating against dst_ip unconditionally meant every
        # large download was reported as data "sent to" the user's own machine.
        if pkt_info.payload_size > 0 and self._is_outbound(pkt_info):
            self._data_transfer[pkt_info.dst_ip] += pkt_info.payload_size
            self._active_transfer_ips.add(pkt_info.dst_ip)
            mb_sent = self._data_transfer[pkt_info.dst_ip] / (1024 * 1024)

            # Per-IP escalating threshold: first alert at configured MB,
            # then doubles each time (100 → 200 → 400 → ...)
            ip_threshold = self._exfil_thresholds.get(
                pkt_info.dst_ip, self.large_upload_mb)

            if mb_sent > ip_threshold:
                # Skip if this IP was contacted during baseline learning (normal transfer target)
                is_learned = False
                if self.baseline_whitelist and self.baseline_whitelist.is_learned_ip(pkt_info.dst_ip):
                    is_learned = True

                sev = Severity.MEDIUM if is_learned else Severity.HIGH
                title_suffix = " (to known destination)" if is_learned else ""

                alerts.append(self._create_alert(
                    "DATA-EXFIL", sev,
                    f"Large Data Transfer{title_suffix}",
                    f"{mb_sent:.1f} MB sent to {pkt_info.dst_ip}",
                    pkt_info,
                    evidence={
                        'destination_ip': pkt_info.dst_ip,
                        'megabytes_transferred': round(mb_sent, 2),
                        'threshold_mb': ip_threshold,
                        'next_alert_at_mb': ip_threshold * 2,
                        'destination_port': pkt_info.dst_port,
                        'protocol': pkt_info.protocol,
                        'process': pkt_info.process_name or 'Unknown',
                        'known_destination': is_learned,
                        'description': 'An unusually large volume of data was sent to a '
                            'single destination, which could indicate data exfiltration.'
                            + (' This destination was seen during baseline learning, so '
                               'it may be a normal transfer target (cloud backup, update server).'
                               if is_learned else ''),
                        'recommendation': 'Verify this transfer was intentional. Check what '
                            'application sent this data and whether the destination is trusted.',
                    },
                    category="Exfiltration"
                ))
                # Escalate threshold — next alert at double the current
                self._exfil_thresholds[pkt_info.dst_ip] = ip_threshold * 2

        # === Rule 12: Unusual time-of-day activity ===
        # Only alert once per source IP per hour window (not per packet)
        hour = datetime.now().hour
        if hour >= 2 and hour <= 5:
            if pkt_info.payload_size > 50000:  # 50KB minimum, not 10KB
                # Custom cooldown: source IP + hour, so max 1 alert per IP per hour
                odd_key = f"ODD-HOURS:{pkt_info.src_ip}:h{hour}"
                now = time.time()
                # Kept out of _alert_cooldowns: that dict is pruned at cooldown_sec*5
                # (150s by default), which silently reduced this to ~24 alerts/hour.
                if now - self._long_suppressions.get(odd_key, 0) > 3600:
                    self._long_suppressions[odd_key] = now
                    alerts.append(self._create_alert(
                        "ODD-HOURS", Severity.LOW,
                        "Unusual Off-Hours Network Activity",
                        f"Significant traffic from {pkt_info.src_ip} at {hour}:00",
                        pkt_info,
                        evidence={
                            'hour': hour,
                            'payload_bytes': pkt_info.payload_size,
                            'source': f"{pkt_info.src_ip}:{pkt_info.src_port}",
                            'destination': f"{pkt_info.dst_ip}:{pkt_info.dst_port}",
                            'process': pkt_info.process_name or 'Unknown',
                            'description': 'Network activity between 2-5 AM is unusual for '
                                'most users and may indicate unauthorized access or malware.',
                        },
                        category="Anomaly"
                    ))

        # Filter and emit
        valid_alerts = [a for a in alerts if a is not None]
        for alert in valid_alerts:
            if self.alert_callback:
                self.alert_callback(alert)

        self.alerts_generated += len(valid_alerts)
        return valid_alerts

    def _matches_domain_list(self, pkt_info, domain_set):
        """True if the query, or any domain known for either endpoint, is in the set."""
        if pkt_info.dns_query and _domain_matches(pkt_info.dns_query, domain_set):
            return True
        for ip in (pkt_info.dst_ip, pkt_info.src_ip):
            for domain in self._get_domains_for_ip(ip):
                if _domain_matches(domain, domain_set):
                    return True
        return False

    def _is_local_ip(self, ip):
        """Is this address one of ours, or on a private network?"""
        if not ip:
            return False
        if self.net_env:
            if ip in getattr(self.net_env, 'local_ips', ()) or \
               ip in getattr(self.net_env, 'auto_whitelist_ips', ()):
                return True
        return is_private(ip)

    def _is_outbound(self, pkt_info):
        """True when traffic leaves a local host for an external destination."""
        return self._is_local_ip(pkt_info.src_ip) and not self._is_local_ip(pkt_info.dst_ip)

    def _alert_from_dns_finding(self, finding, pkt_info):
        """Turn a DnsResponseMonitor finding into an alert."""
        if finding['type'] == 'nxdomain_burst':
            return self._create_alert(
                "DNS-NXDOMAIN-BURST", finding['severity'],
                "Burst of Failed DNS Lookups (possible DGA)",
                finding['description'], pkt_info,
                evidence={
                    'requesting_ip': finding['src_ip'],
                    'failed_lookups': finding['failure_count'],
                    'window_seconds': finding['window_sec'],
                    'distinct_domains': finding['distinct_domains'],
                    'machine_generated_ratio': finding['algorithmic_ratio'],
                    'mean_name_entropy': finding['mean_entropy'],
                    'sample_domains': finding['sample_domains'],
                    'process': pkt_info.process_name or 'Unknown',
                    'description': finding['description'],
                    'recommendation': finding['recommendation'],
                },
                category="Suspicious DNS")

        if finding['type'] == 'fast_flux':
            return self._create_alert(
                "DNS-FAST-FLUX", finding['severity'],
                "Fast-Flux Hosting Detected",
                finding['description'], pkt_info,
                evidence={
                    'domain': finding['domain'],
                    'distinct_addresses': finding['address_count'],
                    'minimum_ttl_seconds': finding['min_ttl'],
                    'window_seconds': finding['window_sec'],
                    'sample_addresses': finding['sample_addresses'],
                    'process': pkt_info.process_name or 'Unknown',
                    'description': finding['description'],
                    'recommendation': finding['recommendation'],
                },
                category="Suspicious DNS")
        return None

    def _get_domains_for_ip(self, ip):
        """Look up what domains have been associated with an IP via DNS."""
        return self._ip_to_domains.get(ip, set())

    def _get_connection_context(self, pkt_info):
        """Build a rich context dict for any alert, including domain info."""
        dst_domains = self._get_domains_for_ip(pkt_info.dst_ip)
        src_domains = self._get_domains_for_ip(pkt_info.src_ip)
        return {
            'connection': f"{pkt_info.src_ip}:{pkt_info.src_port} → "
                          f"{pkt_info.dst_ip}:{pkt_info.dst_port} ({pkt_info.protocol})",
            'destination_domains': list(dst_domains)[:5] if dst_domains else ['No domain — direct IP'],
            'source_domains': list(src_domains)[:5] if src_domains else [],
            'protocol': pkt_info.protocol,
            'flags': pkt_info.flags or 'none',
            'packet_size': f"{pkt_info.length} bytes",
            'payload_size': f"{pkt_info.payload_size} bytes",
            'encrypted': 'Yes (TLS/SSL)' if pkt_info.is_encrypted else 'No',
            'process': pkt_info.process_name or 'Unknown',
            'dns_query': pkt_info.dns_query if pkt_info.dns_query else None,
            'tls_sni': pkt_info.tls_sni or None,
            'tls_version': pkt_info.tls_version or None,
            'tls_ja4': pkt_info.tls_ja4 or None,
        }

    def _cached_ti_check(self, check_type, value):
        """
        Cached threat intel lookup. Avoids hitting the threat intel
        engine for the same IP/domain on every single packet.
        """
        if not value or not self.threat_intel:
            return None

        now = time.time()
        cache_key = f"{check_type}:{value}"

        # Check cache first
        if cache_key in self._ti_cache:
            result, cached_at = self._ti_cache[cache_key]
            if now - cached_at < self._ti_cache_ttl:
                return result  # Cache hit (may be None = known clean)

        # Cache miss — do the actual lookup
        if check_type == 'ip':
            result = self.threat_intel.check_ip(value)
        elif check_type == 'domain':
            result = self.threat_intel.check_domain(value)
        else:
            result = None

        # Store in cache (including None results = "this IP is clean")
        if len(self._ti_cache) >= self._ti_cache_max:
            # Evict oldest 20%
            sorted_keys = sorted(self._ti_cache, key=lambda k: self._ti_cache[k][1])
            for k in sorted_keys[:len(sorted_keys)//5]:
                del self._ti_cache[k]

        self._ti_cache[cache_key] = (result, now)
        return result

    def _create_alert(self, rule_id, severity, title, description,
                      pkt_info, evidence=None, category=""):
        """Create an alert with cooldown deduplication and auto-enriched context."""
        # Cooldown check
        cooldown_key = f"{rule_id}:{pkt_info.src_ip}:{pkt_info.dst_ip}"
        now = time.time()
        if cooldown_key in self._alert_cooldowns:
            if now - self._alert_cooldowns[cooldown_key] < self.cooldown_sec:
                return None  # Suppress duplicate
        self._alert_cooldowns[cooldown_key] = now

        # Auto-enrich evidence with connection context
        # This gives every alert domain info, packet details, etc.
        context = self._get_connection_context(pkt_info)
        if evidence is None:
            evidence = {}

        # Merge context under the evidence — rule-specific fields take priority
        enriched = {}
        # Add context fields first (lower priority)
        for k, v in context.items():
            if v is not None:  # Skip None values
                enriched[k] = v
        # Add rule-specific evidence on top (higher priority)
        for k, v in evidence.items():
            enriched[k] = v

        return Alert(
            rule_id=rule_id,
            severity=severity,
            title=title,
            description=description,
            src_ip=pkt_info.src_ip,
            dst_ip=pkt_info.dst_ip,
            src_port=pkt_info.src_port,
            dst_port=pkt_info.dst_port,
            protocol=pkt_info.protocol,
            evidence=enriched,
            category=category,
        )

    def get_stats(self):
        stats = {
            'enabled': self.enabled,
            'alerts_generated': self.alerts_generated,
            'packets_inspected': self.total_packets_inspected,
            'tracked_sources': len(self._port_access),
            'arp_entries': len(self._arp_table),
            'threat_intel_hits': self.threat_intel_hits,
            'tls_fingerprints_seen': len(self._ja4_seen),
            'dns': self.dns_monitor.get_stats(),
        }
        if self.threat_intel:
            stats['threat_intel'] = self.threat_intel.get_stats()
        return stats
