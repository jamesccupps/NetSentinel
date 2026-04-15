"""
Passive Device Learner
========================
Automatically discovers and profiles devices on the network by observing
traffic patterns. No hardcoded IPs, MACs, or network-specific info.

Learns from:
- ARP announcements → MAC-to-IP mappings
- DHCP traffic → hostnames, vendor class
- mDNS announcements → service names
- DNS query patterns → device behavioral fingerprint
- Traffic profiles → what ports/protocols a device uses

Devices are classified by behavior:
- Gateway (high fan-out, ARP responses for many IPs)
- DNS server (receives port 53 queries)
- IoT device (limited port set, periodic beaconing to cloud)
- Workstation (diverse ports, HTTP/HTTPS heavy)
- Server (listens on fixed ports, responds to many clients)
- Printer (ports 515, 631, 9100)
- Camera (RTSP port 554, constant upload)

The learned device inventory is persisted to disk and loaded on restart.
Learned profiles feed into the IDS to suppress false positives for
known-normal device behavior WITHOUT any manual configuration.
"""

import os
import json
import time
import logging
import threading
from collections import defaultdict, Counter
from datetime import datetime

logger = logging.getLogger("NetSentinel.DeviceLearner")

# Behavioral classification rules (port-based heuristics)
_DEVICE_SIGNATURES = {
    'printer':    {'listen_ports': {515, 631, 9100}, 'min_match': 1},
    'camera':     {'listen_ports': {554, 8554}, 'min_match': 1},
    'dns_server': {'listen_ports': {53}, 'min_match': 1},
    'iot_hub':    {'listen_ports': {1883, 8883, 8123}, 'min_match': 1},
    'web_server': {'listen_ports': {80, 443, 8080, 8443}, 'min_match': 2},
    'database':   {'listen_ports': {3306, 5432, 1433, 6379, 27017}, 'min_match': 1},
}


class DeviceProfile:
    """Profile for a single observed device."""

    __slots__ = [
        'ip', 'mac', 'hostname', 'vendor_class', 'first_seen', 'last_seen',
        'device_type', 'services_seen', 'dst_ports_used', 'protocols_used',
        'dns_domains', 'packet_count', 'byte_count', 'mdns_services',
        'src_ports_served', 'confidence', 'is_gateway',
    ]

    def __init__(self, ip, mac=""):
        self.ip = ip
        self.mac = mac.lower() if mac else ""
        self.hostname = ""
        self.vendor_class = ""
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.device_type = "unknown"
        self.services_seen = set()       # Ports this device listens on
        self.dst_ports_used = Counter()  # Ports this device connects TO
        self.protocols_used = Counter()  # Protocol frequency
        self.dns_domains = Counter()     # Top DNS domains queried
        self.packet_count = 0
        self.byte_count = 0
        self.mdns_services = set()       # mDNS service types advertised
        self.src_ports_served = set()    # Ports this device serves FROM
        self.confidence = 0.0
        self.is_gateway = False

    def to_dict(self):
        return {
            'ip': self.ip,
            'mac': self.mac,
            'hostname': self.hostname,
            'vendor_class': self.vendor_class,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'device_type': self.device_type,
            'services_seen': list(self.services_seen),
            'dst_ports_top': dict(self.dst_ports_used.most_common(20)),
            'protocols': dict(self.protocols_used),
            'dns_top_domains': dict(self.dns_domains.most_common(20)),
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'mdns_services': list(self.mdns_services),
            'confidence': self.confidence,
            'is_gateway': self.is_gateway,
        }

    @classmethod
    def from_dict(cls, data):
        dev = cls(data['ip'], data.get('mac', ''))
        dev.hostname = data.get('hostname', '')
        dev.vendor_class = data.get('vendor_class', '')
        dev.first_seen = data.get('first_seen', time.time())
        dev.last_seen = data.get('last_seen', time.time())
        dev.device_type = data.get('device_type', 'unknown')
        dev.services_seen = set(data.get('services_seen', []))
        dev.dst_ports_used = Counter(data.get('dst_ports_top', {}))
        dev.protocols_used = Counter(data.get('protocols', {}))
        dev.dns_domains = Counter(data.get('dns_top_domains', {}))
        dev.packet_count = data.get('packet_count', 0)
        dev.byte_count = data.get('byte_count', 0)
        dev.mdns_services = set(data.get('mdns_services', []))
        dev.confidence = data.get('confidence', 0.0)
        dev.is_gateway = data.get('is_gateway', False)
        return dev


class DeviceLearner:
    """
    Passively learns about all devices on the network from observed traffic.
    No configuration required — works on any network.
    """

    def __init__(self, config, net_env=None):
        self.config = config
        self.net_env = net_env

        # Device inventory: {ip: DeviceProfile}
        self.devices = {}
        # MAC → IP mapping (from ARP)
        self._mac_to_ip = {}
        # Track which IPs respond to ARP for many targets (gateway detection)
        self._arp_response_targets = defaultdict(set)
        # Lock for thread safety
        self._lock = threading.Lock()

        # Persistence
        from src.config import DB_DIR
        self._db_path = os.path.join(DB_DIR, "learned_devices.json")
        self._load()

        # Periodic classification
        self._last_classify = 0
        self._classify_interval = 60  # Re-classify every 60 seconds

        logger.info("Device learner initialized with %d known devices", len(self.devices))

    def observe_packet(self, pkt_info):
        """Feed a packet to the learner. Called from the worker thread."""
        now = time.time()

        with self._lock:
            # Track source device
            if pkt_info.src_ip and not pkt_info.src_ip.startswith('255.'):
                dev = self._get_or_create(pkt_info.src_ip)
                dev.last_seen = now
                dev.packet_count += 1
                dev.byte_count += pkt_info.length
                dev.protocols_used[pkt_info.protocol] += 1

                if pkt_info.src_mac and not dev.mac:
                    dev.mac = pkt_info.src_mac.lower()
                    self._mac_to_ip[dev.mac] = pkt_info.src_ip

                # If this device is sending FROM a low port, it's serving that port
                if pkt_info.src_port and pkt_info.src_port < 1024:
                    dev.src_ports_served.add(pkt_info.src_port)
                    dev.services_seen.add(pkt_info.src_port)

                # Track outbound port usage
                if pkt_info.dst_port:
                    dev.dst_ports_used[pkt_info.dst_port] += 1

                # DNS queries reveal device behavior
                if pkt_info.dns_query:
                    # Store the base domain (last 2 labels)
                    parts = pkt_info.dns_query.split('.')
                    if len(parts) >= 2:
                        base = '.'.join(parts[-2:])
                        dev.dns_domains[base] += 1

                # ARP tracking for gateway detection
                if pkt_info.protocol == "ARP" and pkt_info.dst_ip:
                    self._arp_response_targets[pkt_info.src_ip].add(pkt_info.dst_ip)

                # mDNS service advertisements
                if pkt_info.dns_query and pkt_info.dst_port == 5353:
                    if '_tcp.local' in pkt_info.dns_query or '_udp.local' in pkt_info.dns_query:
                        dev.mdns_services.add(pkt_info.dns_query)

            # Track destination device (lighter — just note it exists)
            if pkt_info.dst_ip and not pkt_info.dst_ip.startswith('255.'):
                dev = self._get_or_create(pkt_info.dst_ip)
                # If something is connecting TO this device on a low port, it's a service
                if pkt_info.dst_port and pkt_info.dst_port < 1024:
                    dev.services_seen.add(pkt_info.dst_port)

        # Periodic classification (outside lock)
        if now - self._last_classify > self._classify_interval:
            self._last_classify = now
            self._classify_all()

    def observe_dhcp(self, mac, ip, hostname="", vendor_class=""):
        """Called when DHCP traffic reveals device info."""
        with self._lock:
            dev = self._get_or_create(ip)
            if mac:
                dev.mac = mac.lower()
                self._mac_to_ip[mac.lower()] = ip
            if hostname:
                dev.hostname = hostname
            if vendor_class:
                dev.vendor_class = vendor_class

    def _get_or_create(self, ip):
        """Get or create a device profile. Must be called under lock."""
        if ip not in self.devices:
            self.devices[ip] = DeviceProfile(ip)
        return self.devices[ip]

    def _classify_all(self):
        """Classify all devices and trim unbounded counters."""
        with self._lock:
            for ip, dev in self.devices.items():
                self._classify_device(dev)
                # Trim Counters to prevent unbounded memory growth
                # Keep only top-100 entries for long-lived devices
                if len(dev.dst_ports_used) > 200:
                    dev.dst_ports_used = Counter(dict(dev.dst_ports_used.most_common(100)))
                if len(dev.dns_domains) > 200:
                    dev.dns_domains = Counter(dict(dev.dns_domains.most_common(100)))
                if len(dev.protocols_used) > 50:
                    dev.protocols_used = Counter(dict(dev.protocols_used.most_common(20)))

    def _classify_device(self, dev):
        """Classify a single device based on its behavioral profile."""
        # Gateway detection: responds to ARP for many different IPs
        arp_targets = len(self._arp_response_targets.get(dev.ip, set()))
        if arp_targets > 10:
            dev.device_type = "gateway"
            dev.is_gateway = True
            dev.confidence = min(0.5 + arp_targets / 100.0, 1.0)
            return

        # Also mark as gateway if net_env detected it
        if self.net_env and dev.ip in getattr(self.net_env, 'gateways', []):
            dev.device_type = "gateway"
            dev.is_gateway = True
            dev.confidence = 0.95
            return

        # Signature-based classification
        for dev_type, sig in _DEVICE_SIGNATURES.items():
            matches = dev.services_seen & sig['listen_ports']
            if len(matches) >= sig['min_match']:
                dev.device_type = dev_type
                dev.confidence = 0.7 + (len(matches) / 10.0)
                return

        # Behavioral classification
        total_dst_ports = len(dev.dst_ports_used)
        top_ports = dev.dst_ports_used.most_common(5)

        # IoT device: few unique ports, mostly cloud services
        if total_dst_ports < 10 and dev.packet_count > 100:
            cloud_ports = sum(1 for p, _ in top_ports if p in {443, 8883, 1883, 8443})
            if cloud_ports >= 1:
                dev.device_type = "iot_device"
                dev.confidence = 0.6
                return

        # Workstation: diverse port usage, HTTP/HTTPS heavy
        if total_dst_ports > 20:
            https_ratio = dev.dst_ports_used.get(443, 0) / max(dev.packet_count, 1)
            if https_ratio > 0.1:
                dev.device_type = "workstation"
                dev.confidence = 0.65
                return

        # Server: many packets, serves on fixed ports
        if len(dev.src_ports_served) > 0 and dev.packet_count > 500:
            dev.device_type = "server"
            dev.confidence = 0.6
            return

        dev.device_type = "unknown"
        dev.confidence = 0.0

    def get_device(self, ip=None, mac=None):
        """Look up a device by IP or MAC."""
        with self._lock:
            if ip and ip in self.devices:
                return self.devices[ip]
            if mac:
                ip = self._mac_to_ip.get(mac.lower())
                if ip and ip in self.devices:
                    return self.devices[ip]
        return None

    def get_all_devices(self):
        """Return a snapshot of all known devices."""
        with self._lock:
            return {ip: dev.to_dict() for ip, dev in self.devices.items()}

    def get_device_expected_ports(self, ip):
        """Return the set of ports this device normally uses (learned behavior)."""
        with self._lock:
            dev = self.devices.get(ip)
            if not dev:
                return set()
            # Top ports by frequency (the device's normal behavior)
            normal_ports = set()
            for port, count in dev.dst_ports_used.most_common(30):
                if count >= 3:  # Seen at least 3 times
                    normal_ports.add(port)
            normal_ports |= dev.services_seen
            return normal_ports

    def is_known_device(self, ip):
        """Check if this IP is a device we've profiled."""
        with self._lock:
            dev = self.devices.get(ip)
            return dev is not None and dev.packet_count > 50

    def is_learned_gateway(self, ip):
        """Check if we've learned this IP is a gateway."""
        with self._lock:
            dev = self.devices.get(ip)
            return dev is not None and dev.is_gateway

    def get_summary(self):
        """Return summary for dashboard display."""
        with self._lock:
            by_type = Counter(d.device_type for d in self.devices.values())
            active_1h = sum(1 for d in self.devices.values()
                          if time.time() - d.last_seen < 3600)
            return {
                'total_devices': len(self.devices),
                'active_last_hour': active_1h,
                'by_type': dict(by_type),
                'devices': [
                    {
                        'ip': d.ip,
                        'mac': d.mac,
                        'hostname': d.hostname or '—',
                        'type': d.device_type,
                        'confidence': f"{d.confidence:.0%}",
                        'packets': d.packet_count,
                        'last_seen': datetime.fromtimestamp(d.last_seen).strftime('%H:%M:%S'),
                        'services': sorted(d.services_seen)[:10],
                    }
                    for d in sorted(self.devices.values(),
                                   key=lambda d: d.last_seen, reverse=True)[:100]
                ],
            }

    def save(self):
        """Persist learned devices to disk."""
        with self._lock:
            data = {ip: dev.to_dict() for ip, dev in self.devices.items()}
        try:
            with open(self._db_path, 'w') as f:
                json.dump(data, f, indent=1, default=str)
            logger.info("Saved %d learned device profiles", len(data))
        except Exception as e:
            logger.error("Failed to save device learner data: %s", e)

    def _load(self):
        """Load previously learned devices from disk."""
        if not os.path.exists(self._db_path):
            return
        try:
            with open(self._db_path, 'r') as f:
                data = json.load(f)
            for ip, dev_data in data.items():
                self.devices[ip] = DeviceProfile.from_dict(dev_data)
                if dev_data.get('mac'):
                    self._mac_to_ip[dev_data['mac'].lower()] = ip
            logger.info("Loaded %d learned device profiles from disk", len(self.devices))
        except Exception as e:
            logger.error("Failed to load device learner data: %s", e)

    def prune_stale(self, max_age_days=30):
        """Remove devices not seen in max_age_days."""
        cutoff = time.time() - (max_age_days * 86400)
        with self._lock:
            stale = [ip for ip, d in self.devices.items()
                     if d.last_seen < cutoff and d.packet_count < 100]
            for ip in stale:
                del self.devices[ip]
            if stale:
                logger.info("Pruned %d stale device profiles", len(stale))
