"""
Network packet capture engine using Scapy.
Captures packets, extracts metadata, and feeds them to the analysis pipeline.
"""

import inspect
import threading
import time
import logging
from collections import defaultdict, deque

from src.tls_inspect import looks_like_tls_handshake, parse_client_hello

logger = logging.getLogger("NetSentinel.Capture")

try:
    from scapy.all import (
        sniff, conf, get_if_list, get_if_addr,
        IP, IPv6, TCP, UDP, ICMP, DNS, ARP, Raw, Ether
    )
    from scapy.packet import NoPayload
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    NoPayload = ()
    logger.warning("Scapy not available. Install with: pip install scapy")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class PacketInfo:
    """Structured packet metadata extracted from raw capture."""
    __slots__ = [
        'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
        'protocol', 'length', 'flags', 'payload_size', 'ttl',
        'dns_query', 'dns_response', 'is_encrypted', 'raw_summary',
        'src_mac', 'dst_mac', 'process_name', 'process_pid',
        'tls_sni', 'tls_ja3', 'tls_ja4', 'tls_version',
        'dns_rcode', 'dns_ttl', 'dns_answers',
        '_raw_payload',
    ]

    def __init__(self):
        self.timestamp = time.time()
        self.src_ip = ""
        self.dst_ip = ""
        self.src_port = 0
        self.dst_port = 0
        self.protocol = ""
        self.length = 0
        self.flags = ""
        self.payload_size = 0
        self.ttl = 0
        self.dns_query = ""
        self.dns_response = ""
        self.is_encrypted = False
        self.raw_summary = ""
        self.src_mac = ""
        self.dst_mac = ""
        self.process_name = ""
        self.process_pid = 0
        # Recovered from the (plaintext) TLS ClientHello. For encrypted traffic this
        # is the only destination name and client identity available.
        self.tls_sni = ""
        self.tls_ja3 = ""
        self.tls_ja4 = ""
        self.tls_version = ""
        # DNS response detail. Responses previously carried only a single rdata
        # string and no question name, so nothing could correlate an answer with
        # what was asked or notice that it failed.
        self.dns_rcode = -1        # -1 = not a response; 0 = NOERROR, 3 = NXDOMAIN
        self.dns_ttl = -1          # Lowest TTL across the answers
        self.dns_answers = ()      # Every rdata in the answer section
        self._raw_payload = None

    def to_dict(self):
        return {attr: getattr(self, attr) for attr in self.__slots__ if not attr.startswith('_')}

    @property
    def domain(self):
        """Best available destination name: the TLS SNI, else the DNS query."""
        return self.tls_sni or self.dns_query

    @property
    def flow_key(self):
        """Bidirectional flow key."""
        ips = tuple(sorted([self.src_ip, self.dst_ip]))
        ports = tuple(sorted([self.src_port, self.dst_port]))
        return (ips[0], ips[1], ports[0], ports[1], self.protocol)

    def __repr__(self):
        return (f"<Packet {self.protocol} {self.src_ip}:{self.src_port} -> "
                f"{self.dst_ip}:{self.dst_port} len={self.length}>")


class NetworkFlow:
    """Tracks a bidirectional network conversation."""

    def __init__(self, flow_key):
        self.flow_key = flow_key
        self.start_time = time.time()
        self.last_seen = self.start_time
        self.packet_count = 0
        self.byte_count = 0
        self.payload_bytes = 0
        self.src_packets = 0
        self.dst_packets = 0
        self.flags_seen = set()
        self.inter_arrival_times = deque(maxlen=500)
        self._last_packet_time = self.start_time
        self.dns_queries = []
        self.is_established = False
        self.syn_count = 0
        self.rst_count = 0
        self.fin_count = 0

    def add_packet(self, pkt_info: PacketInfo):
        now = time.time()
        self.last_seen = now
        self.packet_count += 1
        self.byte_count += pkt_info.length
        self.payload_bytes += pkt_info.payload_size

        iat = now - self._last_packet_time
        if iat > 0:
            self.inter_arrival_times.append(iat)
        self._last_packet_time = now

        if pkt_info.flags:
            self.flags_seen.add(pkt_info.flags)
            if 'S' in pkt_info.flags and 'A' not in pkt_info.flags:
                self.syn_count += 1
            if 'R' in pkt_info.flags:
                self.rst_count += 1
            if 'F' in pkt_info.flags:
                self.fin_count += 1
            if 'SA' in pkt_info.flags or ('S' in pkt_info.flags and 'A' in pkt_info.flags):
                self.is_established = True

        if pkt_info.src_ip == self.flow_key[0]:
            self.src_packets += 1
        else:
            self.dst_packets += 1

        if pkt_info.dns_query:
            self.dns_queries.append(pkt_info.dns_query)

    @property
    def duration(self):
        return max(self.last_seen - self.start_time, 0.001)

    @property
    def bytes_per_sec(self):
        return self.byte_count / self.duration

    @property
    def packets_per_sec(self):
        return self.packet_count / self.duration

    @property
    def avg_packet_size(self):
        return self.byte_count / max(self.packet_count, 1)

    @property
    def direction_ratio(self):
        total = self.src_packets + self.dst_packets
        return self.src_packets / max(total, 1)


# Map port numbers to process (Windows)
_port_process_cache = {}
_port_cache_time = 0
_PORT_CACHE_TTL = 2  # seconds between full psutil enumerations


def _refresh_port_process_map(force=False):
    """Build a map of local ports to process names using psutil."""
    global _port_process_cache, _port_cache_time
    if not PSUTIL_AVAILABLE:
        return
    now = time.time()
    if not force and now - _port_cache_time < _PORT_CACHE_TTL:
        return
    try:
        new_map = {}
        for conn in psutil.net_connections(kind='inet'):
            if conn.laddr and conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    new_map[conn.laddr.port] = (proc.name(), conn.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        _port_process_cache = new_map
        _port_cache_time = now
    except Exception:
        pass


def _get_process_for_port(port):
    """Look up which process owns a given local port. Pure dict read — no syscalls."""
    return _port_process_cache.get(port, ("", 0))


def _process_map_refresher(should_run):
    """
    Keep the port->process map warm from a background thread.

    psutil.net_connections() takes tens of milliseconds and used to run inline in the
    capture callback, stalling packet capture every couple of seconds.
    """
    while should_run():
        try:
            _refresh_port_process_map(force=True)
        except Exception as e:
            logger.debug("Process map refresh error: %s", e)
        time.sleep(_PORT_CACHE_TTL)


# Ports where raw payloads are extracted for credential scanning.
# Defined at module level to avoid rebuilding the set on every packet.
_CREDENTIAL_PORTS = frozenset({
    # Classic insecure protocols
    21, 23, 25, 69, 80, 110, 143, 161, 162, 389,
    445, 513, 514, 587,
    # Network discovery (DHCP, mDNS, LLMNR)
    67, 68, 5353, 5355,
    # Databases (often no TLS)
    1433, 1521, 3306, 5432, 6379, 9042, 27017,
    # Search / cache / message (no auth by default)
    9200, 11211, 5672, 15672,
    # VoIP / streaming / IoT
    554, 1883, 5060, 5061,
    # Remote access
    5900, 5901, 5800,
    # File sharing / sync
    873, 2049,
    # HTTP alternatives (dev servers, admin panels)
    3000, 4200, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9090,
    # Network services
    1812, 1813,
    # Industrial / SCADA
    502, 47808,
    # Parking systems (cleartext XML on control channels)
    31769,
    # Printers
    515, 631, 9100,
    # IRC / chat
    6667, 6668, 6669,
    # CouchDB
    5984,
})


# Ports where a TLS handshake is expected. The ClientHello on these is parsed for
# SNI and JA3/JA4 — the payload itself stays opaque, but the handshake is not.
_TLS_PORTS = frozenset({
    443, 465, 563, 636, 853, 989, 990, 993, 995,
    1443, 2083, 2087, 2096, 4443, 5061, 5986,
    8443, 8883, 9443, 10443,
})


def _iter_dns_records(section, count):
    """
    Yield the records in a DNS section.

    Scapy changed the representation: 2.7 exposes an iterable list, while older
    releases chain records through .payload. Supporting only the chain silently
    returned just the first answer on 2.7 — enough to look like it worked.
    """
    if section is None:
        return

    # Scapy 2.7 wraps the section in a list subclass that ALSO proxies attribute
    # access to its first element, so `hasattr(section, 'rdata')` is true either
    # way and cannot be used to tell the two representations apart. isinstance
    # against list can.
    if isinstance(section, list):
        yield from section
        return

    record = section
    for _ in range(max(int(count or 0), 1)):
        if record is None or type(record).__name__ == 'NoPayload':
            return
        yield record
        record = getattr(record, 'payload', None)


class CaptureEngine:
    """
    Core packet capture engine.
    Uses a queue-based architecture to decouple capture from processing.
    Capture thread → Queue → Worker thread(s) → Callbacks
    
    This prevents heavy processing (IDS, threat intel) from blocking
    the kernel capture buffer, which causes network lag and drops.
    """

    def __init__(self, config, packet_callback=None, raw_packet_callback=None):
        self.config = config
        self.packet_callback = packet_callback
        self.raw_packet_callback = raw_packet_callback  # For PCAP writer
        self._running = False
        self._thread = None
        self._lock = threading.Lock()
        self._stats_lock = threading.Lock()  # Lightweight lock for rate calculations

        # Queue-based processing: capture thread enqueues, worker dequeues
        import queue
        self._packet_queue = queue.Queue(maxsize=2000)
        self._dropped_packets = 0

        # Sampling: under load, only process 1 in N packets for IDS
        # (stats always count everything)
        self._sample_rate = 1  # 1 = process all, 2 = every other, etc.
        self._sample_counter = 0
        self._load_check_interval = 2  # seconds
        self._last_load_check = 0

        # Flow tracking
        self.flows = {}
        self.flow_timeout = config.get('analysis', 'flow_timeout_sec', default=120)
        self.max_flows = config.get('analysis', 'max_flows_tracked', default=50000)

        # Statistics
        self.stats = {
            'packets_captured': 0,
            'bytes_captured': 0,
            'flows_active': 0,
            'packets_per_sec': 0,
            'bytes_per_sec': 0,
            'start_time': 0,
            'protocols': defaultdict(int),
            'top_talkers': defaultdict(int),
            'dns_queries': deque(maxlen=1000),
            'packets_dropped': 0,
            'sample_rate': 1,
        }
        self._pps_counter = 0
        self._bps_counter = 0
        self._last_rate_calc = 0
        # Atomic counters for capture thread (avoid lock contention)
        self._atomic_packets = 0
        self._atomic_bytes = 0

        # Interface
        self.interface = config.get('capture', 'interface', default='auto')

        # Hard PPS cap: never enqueue more than this many packets per second
        # Prevents CPU saturation during heavy traffic (browsing, streaming)
        self._max_pps = config.get('capture', 'max_pps', default=500)
        self._pps_window_count = 0
        self._pps_window_start = 0

        # Watchdog: auto-restart capture if it dies
        self._restart_count = 0
        self._max_restarts = 10

        # Set when capture failed for a reason restarting cannot fix.
        self._fatal_capture_error = False

        # Declared up front so the watchdog can never touch an undefined attribute.
        self._worker_thread = None
        self._cleanup_thread = None
        self._watchdog_thread = None
        self._procmap_thread = None

    def _select_interface(self):
        """Auto-detect the best network interface."""
        if not SCAPY_AVAILABLE:
            return None
        if self.interface != 'auto':
            return self.interface
        try:
            iface = conf.iface
            logger.info("Auto-selected interface: %s", iface)
            return iface
        except Exception as e:
            logger.error("Could not auto-detect interface: %s", e)
            return None

    @staticmethod
    def _extract_dns(dns, info):
        """
        Pull the question and, for responses, the full answer detail.

        The question name is recorded for responses too. Without it an answer
        cannot be tied to what was asked, which is what NXDOMAIN-burst and
        fast-flux analysis need.
        """
        try:
            if dns.qd is not None:
                qname = getattr(dns.qd, 'qname', b'')
                if qname:
                    info.dns_query = qname.decode('utf-8', errors='ignore').rstrip('.').lower()

            if dns.qr != 1:
                return

            info.dns_rcode = int(dns.rcode)

            answers = []
            ttls = []
            for record in _iter_dns_records(dns.an, getattr(dns, 'ancount', 0)):
                rdata = getattr(record, 'rdata', None)
                if rdata is not None:
                    answers.append(rdata.decode('utf-8', errors='ignore').rstrip('.')
                                   if isinstance(rdata, bytes) else str(rdata))
                ttl = getattr(record, 'ttl', None)
                if ttl is not None:
                    ttls.append(int(ttl))

            info.dns_answers = tuple(answers)
            if answers:
                info.dns_response = answers[0]
            if ttls:
                info.dns_ttl = min(ttls)
        except Exception as e:
            logger.debug("DNS extraction error: %s", e)

    @staticmethod
    def _transport_payload(packet):
        """
        The bytes carried above TCP/UDP, however Scapy chose to dissect them.

        `packet.haslayer(Raw)` is only true when Scapy had no dissector for the
        payload. With scapy.layers.tls loaded — which `from scapy.all import *`
        does — port-443 traffic dissects into a TLS layer instead, and DNS, and
        anything else Scapy recognises. Keying off Raw therefore silently reported
        payload_size = 0 for every one of those, which is most of a real capture.
        """
        transport = packet.getlayer(TCP) or packet.getlayer(UDP)
        if transport is None:
            return b''
        payload = transport.payload
        if payload is None or isinstance(payload, NoPayload):
            return b''
        original = getattr(payload, 'original', None)
        return original if original else bytes(payload)

    @staticmethod
    def _raw_bytes(packet):
        """
        The packet's wire bytes, without asking Scapy to rebuild it.

        A packet dissected from the wire keeps its original buffer in `.original`.
        `len(packet)` and `bytes(packet)` both go through build(), which re-serialises
        every layer — the dominant cost in this function, and it runs per packet.
        """
        original = getattr(packet, 'original', None)
        return original if original else bytes(packet)

    def _extract_packet_info(self, packet) -> PacketInfo:
        """Extract structured metadata from a Scapy packet."""
        info = PacketInfo()
        info.timestamp = time.time()
        raw = self._raw_bytes(packet)
        info.length = len(raw)
        payload = b''

        # Ethernet layer
        if packet.haslayer(Ether):
            info.src_mac = packet[Ether].src
            info.dst_mac = packet[Ether].dst

        # IP layer
        if packet.haslayer(IP):
            info.src_ip = packet[IP].src
            info.dst_ip = packet[IP].dst
            info.ttl = packet[IP].ttl

            if packet.haslayer(TCP):
                info.protocol = "TCP"
                info.src_port = packet[TCP].sport
                info.dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                info.flags = str(flags)
                payload = self._transport_payload(packet)
                info.payload_size = len(payload)
                if info.dst_port == 443 or info.src_port == 443:
                    info.is_encrypted = True

            elif packet.haslayer(UDP):
                info.protocol = "UDP"
                info.src_port = packet[UDP].sport
                info.dst_port = packet[UDP].dport
                payload = self._transport_payload(packet)
                info.payload_size = len(payload)

            elif packet.haslayer(ICMP):
                info.protocol = "ICMP"
            else:
                info.protocol = "IP/Other"

        elif packet.haslayer(IPv6):
            info.src_ip = packet[IPv6].src
            info.dst_ip = packet[IPv6].dst

            # IPv6 carries TCP/UDP the same way as IPv4
            if packet.haslayer(TCP):
                info.protocol = "TCP"
                info.src_port = packet[TCP].sport
                info.dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                info.flags = str(flags)
                payload = self._transport_payload(packet)
                info.payload_size = len(payload)
                if info.dst_port == 443 or info.src_port == 443:
                    info.is_encrypted = True
            elif packet.haslayer(UDP):
                info.protocol = "UDP"
                info.src_port = packet[UDP].sport
                info.dst_port = packet[UDP].dport
                payload = self._transport_payload(packet)
                info.payload_size = len(payload)
            elif packet.haslayer(ICMP):
                info.protocol = "ICMPv6"
            else:
                info.protocol = "IPv6/Other"

        elif packet.haslayer(ARP):
            info.protocol = "ARP"
            info.src_ip = packet[ARP].psrc
            info.dst_ip = packet[ARP].pdst

        else:
            info.protocol = "Other"

        # DNS layer
        if packet.haslayer(DNS):
            self._extract_dns(packet[DNS], info)

        # Process attribution. The expensive part (enumerating sockets) happens on a
        # background thread; this is a dict lookup, so every packet can be attributed
        # instead of roughly one per refresh interval.
        proc_name, proc_pid = _get_process_for_port(info.src_port)
        if not proc_name:
            proc_name, proc_pid = _get_process_for_port(info.dst_port)
        info.process_name = proc_name
        info.process_pid = proc_pid

        # Extract raw payload ONLY for unencrypted protocols where we need
        # to scan for credentials. This is a tiny fraction of traffic.
        if (info.payload_size > 0 and
            (info.dst_port in _CREDENTIAL_PORTS or info.src_port in _CREDENTIAL_PORTS)):
            info._raw_payload = payload

        # TLS handshake inspection. Only the first packets of a connection carry a
        # ClientHello, and looks_like_tls_handshake() rejects everything else in four
        # byte comparisons, so this costs almost nothing on established connections.
        elif (info.payload_size > 0 and info.protocol == 'TCP'
                and (info.dst_port in _TLS_PORTS or info.src_port in _TLS_PORTS)
                and looks_like_tls_handshake(payload)):
            hello = parse_client_hello(payload)
            if hello:
                info.tls_sni = hello['sni'] or ''
                info.tls_ja3 = hello['ja3']
                info.tls_ja4 = hello['ja4']
                info.tls_version = hello['version']

        # QUIC rides UDP/443 and would otherwise be indistinguishable from any other
        # UDP traffic — no flags, and is_encrypted left False.
        if (info.protocol == 'UDP' and not info.is_encrypted
                and (info.dst_port == 443 or info.src_port == 443)):
            info.is_encrypted = True
            info.tls_version = 'QUIC'

        return info

    def _capture_callback(self, packet):
        """
        Called by Scapy for each captured packet.
        This runs in the capture thread — must be FAST.
        Only extracts minimal info and enqueues for processing.
        """
        try:
            pkt_info = self._extract_packet_info(packet)

            # Buffer raw bytes for PCAP writer (before PPS cap for complete captures)
            if self.raw_packet_callback:
                try:
                    self.raw_packet_callback(bytes(packet))
                except Exception:
                    pass

            # Lightweight counter updates (single-writer from capture thread,
            # read-only from GUI — CPython GIL makes simple int assignment safe)
            self._atomic_packets += 1
            self._atomic_bytes += pkt_info.length
            self._pps_counter += 1
            self._bps_counter += pkt_info.length

            # Rate calculation — sync atomic counters to stats dict under lock
            now = time.time()
            elapsed = now - self._last_rate_calc
            if elapsed >= 1.0:
                with self._stats_lock:
                    self.stats['packets_captured'] = self._atomic_packets
                    self.stats['bytes_captured'] = self._atomic_bytes
                    self.stats['packets_per_sec'] = self._pps_counter / elapsed
                    self.stats['bytes_per_sec'] = self._bps_counter / elapsed
                    self._pps_counter = 0
                    self._bps_counter = 0
                    self._last_rate_calc = now

            # Enqueue for deep processing (IDS, threat intel, ML)
            # Hard PPS cap: skip enqueueing if we're over budget this second
            now2 = time.time()
            if now2 - self._pps_window_start >= 1.0:
                self._pps_window_start = now2
                self._pps_window_count = 0
            self._pps_window_count += 1

            if self._pps_window_count > self._max_pps:
                self._dropped_packets += 1
                return  # Skip this packet entirely — stats already counted

            # If queue is full, drop the packet (better than blocking capture)
            try:
                self._packet_queue.put_nowait(pkt_info)
            except Exception:
                self._dropped_packets += 1

        except Exception as e:
            logger.debug("Capture callback error: %s", e)

    def _worker_loop(self):
        """
        Worker thread that processes packets from the queue.
        Handles IDS inspection, flow tracking, and ML callbacks.
        Runs separately from the capture thread so processing
        never blocks packet capture.
        """
        import queue
        logger.info("Packet processing worker started.")
        batch = []
        batch_size = 10  # Process up to 10 packets at a time

        while self._running:
            try:
                # Collect a batch of packets (with timeout so we can check _running)
                try:
                    pkt = self._packet_queue.get(timeout=0.5)
                    batch.append(pkt)
                except queue.Empty:
                    pass

                # Drain more if available (up to batch_size)
                while len(batch) < batch_size:
                    try:
                        pkt = self._packet_queue.get_nowait()
                        batch.append(pkt)
                    except queue.Empty:
                        break

                if not batch:
                    continue

                # Adaptive sampling: if queue is backing up, increase sample rate
                qsize = self._packet_queue.qsize()
                if qsize > 1000:
                    self._sample_rate = 4  # Process 1 in 4
                elif qsize > 500:
                    self._sample_rate = 2  # Process 1 in 2
                else:
                    self._sample_rate = 1  # Process all
                self.stats['sample_rate'] = self._sample_rate
                self.stats['packets_dropped'] = self._dropped_packets

                for pkt_info in batch:
                    try:
                        # Flow tracking (always, lightweight)
                        with self._lock:
                            self.stats['protocols'][pkt_info.protocol] += 1
                            if pkt_info.src_ip:
                                self.stats['top_talkers'][pkt_info.src_ip] += pkt_info.length
                            if pkt_info.dns_query:
                                self.stats['dns_queries'].append(
                                    (pkt_info.timestamp, pkt_info.dns_query))

                            if pkt_info.src_ip and pkt_info.dst_ip:
                                key = pkt_info.flow_key
                                if key not in self.flows:
                                    if len(self.flows) < self.max_flows:
                                        self.flows[key] = NetworkFlow(key)
                                if key in self.flows:
                                    self.flows[key].add_packet(pkt_info)
                            self.stats['flows_active'] = len(self.flows)

                        # IDS / ML callback (sampling under load)
                        self._sample_counter += 1
                        if self._sample_counter >= self._sample_rate:
                            self._sample_counter = 0
                            if self.packet_callback:
                                self.packet_callback(pkt_info)

                    except Exception as e:
                        logger.debug("Worker packet error: %s", e)

                batch.clear()

            except Exception as e:
                logger.debug("Worker loop error: %s", e)
                batch.clear()

        logger.info("Packet processing worker stopped.")

    def _cleanup_flows(self):
        """Remove expired flows and prune stats periodically."""
        while self._running:
            time.sleep(30)
            now = time.time()
            with self._lock:
                expired = [
                    k for k, f in self.flows.items()
                    if now - f.last_seen > self.flow_timeout
                ]
                for k in expired:
                    del self.flows[k]
                if expired:
                    logger.debug("Cleaned up %d expired flows", len(expired))

                # Prune top_talkers to prevent unbounded growth
                # Keep only the top 500 by bytes
                tt = self.stats['top_talkers']
                if len(tt) > 1000:
                    top_keys = sorted(tt, key=tt.get, reverse=True)[:500]
                    pruned = defaultdict(int, {k: tt[k] for k in top_keys})
                    self.stats['top_talkers'] = pruned

    def _watchdog_loop(self):
        """
        Monitors the capture thread and restarts it if it dies.
        Also monitors the worker thread.
        """
        while self._running:
            time.sleep(5)

            # Check capture thread
            if self._fatal_capture_error:
                logger.error("Capture cannot start with the current configuration. "
                             "Watchdog standing down.")
                return
            if self._thread and not self._thread.is_alive():
                if self._restart_count < self._max_restarts:
                    self._restart_count += 1
                    logger.warning(
                        "Capture thread died. Restarting (attempt %d/%d)...",
                        self._restart_count, self._max_restarts
                    )
                    self._start_capture_thread()
                else:
                    logger.error("Capture thread exceeded max restarts (%d). Giving up.",
                                 self._max_restarts)

            # Check worker thread
            if self._worker_thread and not self._worker_thread.is_alive():
                logger.warning("Worker thread died. Restarting...")
                self._worker_thread = threading.Thread(
                    target=self._worker_loop, daemon=True, name="PacketWorker")
                self._worker_thread.start()

    def _supported_sniff_kwargs(self, desired):
        """
        Keep only the options this Scapy build's listen socket accepts.

        sniff() takes **kwargs and forwards anything it does not recognise
        straight to the socket constructor, where an unsupported name raises
        TypeError and kills the capture thread. The accepted set varies by Scapy
        version and by platform — Linux PF_PACKET takes `promisc`, and no Linux
        socket takes `snaplen` at all — so ask rather than assume.
        """
        try:
            listener = getattr(conf, 'L2listen', None)
            accepted = set(inspect.signature(listener.__init__).parameters)
        except (AttributeError, TypeError, ValueError) as e:
            logger.debug("Could not introspect the listen socket (%s); "
                         "passing no extra options.", e)
            return {}

        supported, skipped = {}, []
        for name, value in desired.items():
            if name in accepted:
                supported[name] = value
            else:
                skipped.append(name)
        if skipped:
            logger.info("Capture options not supported by this Scapy build, "
                        "ignoring: %s", ', '.join(sorted(skipped)))
        return supported

    def _start_capture_thread(self):
        """Start (or restart) the Scapy capture thread."""
        iface = self._select_interface()
        bpf = self.config.get('capture', 'bpf_filter', default='')
        sniff_options = self._supported_sniff_kwargs({
            'promisc': self.config.get('capture', 'promiscuous', default=True),
            'snaplen': self.config.get('capture', 'snap_length', default=65535),
        })

        def _capture_loop():
            logger.info("Capture started on interface: %s", iface)
            try:
                sniff(
                    iface=iface,
                    prn=self._capture_callback,
                    store=False,
                    stop_filter=lambda _: not self._running,
                    filter=bpf if bpf else None,
                    **sniff_options,
                )
            except PermissionError:
                logger.error("Permission denied. Run as Administrator (Windows) or "
                             "as root / with CAP_NET_RAW (Linux) for packet capture.")
            except TypeError as e:
                # An option this Scapy build rejects. Restarting cannot help, and
                # the watchdog would otherwise retry it ten times.
                logger.error("Capture rejected an option (%s). Not retrying.", e)
                self._fatal_capture_error = True
            except Exception as e:
                logger.error("Capture error: %s", e)
            finally:
                logger.info("Capture thread exited.")

        self._thread = threading.Thread(
            target=_capture_loop, daemon=True, name="CaptureThread")
        self._thread.start()

    def start(self):
        """Start the capture engine with worker threads and watchdog."""
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start capture: Scapy is not installed.")
            return False

        if self._running:
            return True

        self._running = True
        self.stats['start_time'] = time.time()
        self._last_rate_calc = time.time()
        self._restart_count = 0

        # Start capture thread
        self._start_capture_thread()

        # Start worker thread (processes packets from queue)
        self._worker_thread = threading.Thread(
            target=self._worker_loop, daemon=True, name="PacketWorker")
        self._worker_thread.start()

        # Start flow cleanup
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_flows, daemon=True, name="FlowCleanup")
        self._cleanup_thread.start()

        # Start watchdog (auto-restarts crashed threads)
        self._watchdog_thread = threading.Thread(
            target=self._watchdog_loop, daemon=True, name="Watchdog")
        self._watchdog_thread.start()

        # Keep the port->process map warm without blocking the capture thread
        if PSUTIL_AVAILABLE:
            self._procmap_thread = threading.Thread(
                target=_process_map_refresher, args=(lambda: self._running,),
                daemon=True, name="ProcMapRefresh")
            self._procmap_thread.start()

        logger.info("Capture engine started with queue-based processing.")
        return True

    def stop(self):
        """Stop the capture engine and wait for its threads to wind down."""
        self._running = False
        # The capture thread is the one that can outlive this: Scapy only evaluates
        # stop_filter when a packet arrives, so on a quiet interface it stays blocked.
        # It is a daemon thread, so that does not prevent process exit.
        for t in (self._worker_thread, self._thread):
            if t is not None and t.is_alive():
                t.join(timeout=5)
        logger.info("Capture engine stopped. Dropped packets: %d", self._dropped_packets)

    def get_flows_snapshot(self):
        """Return a snapshot of current flows for analysis."""
        with self._lock:
            return {k: v for k, v in self.flows.items()}

    def get_stats(self):
        """
        Return a real snapshot of current statistics.

        dict(self.stats) is shallow, so callers used to receive the live protocols and
        top_talkers dicts and the dns_queries deque, which the worker thread keeps
        mutating — iterating the deque raises RuntimeError, and nothing was actually
        isolated despite the lock.
        """
        with self._stats_lock:
            with self._lock:
                snap = dict(self.stats)
                snap['protocols'] = dict(self.stats['protocols'])
                snap['top_talkers'] = dict(self.stats['top_talkers'])
                snap['dns_queries'] = list(self.stats['dns_queries'])
                return snap

    @property
    def is_running(self):
        return self._running
