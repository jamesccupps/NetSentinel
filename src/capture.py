"""
Network packet capture engine using Scapy.
Captures packets, extracts metadata, and feeds them to the analysis pipeline.
"""

import threading
import time
import logging
import socket
import struct
from collections import defaultdict, deque
from datetime import datetime

logger = logging.getLogger("NetSentinel.Capture")

try:
    from scapy.all import (
        sniff, conf, get_if_list, get_if_addr,
        IP, IPv6, TCP, UDP, ICMP, DNS, ARP, Raw, Ether
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
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
        self._raw_payload = None

    def to_dict(self):
        return {attr: getattr(self, attr) for attr in self.__slots__ if not attr.startswith('_')}

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


def _refresh_port_process_map():
    """Build a map of local ports to process names using psutil."""
    global _port_process_cache, _port_cache_time
    if not PSUTIL_AVAILABLE:
        return
    now = time.time()
    if now - _port_cache_time < 2:  # Cache for 2 seconds
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
    """Look up which process owns a given local port."""
    _refresh_port_process_map()
    return _port_process_cache.get(port, ("", 0))


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

        # Process lookup throttling (psutil is expensive)
        self._process_lookup_interval = 5  # Only look up processes every N seconds
        self._last_process_lookup = 0

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

    def _extract_packet_info(self, packet) -> PacketInfo:
        """Extract structured metadata from a Scapy packet."""
        info = PacketInfo()
        info.timestamp = time.time()
        info.length = len(packet)

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
                if packet.haslayer(Raw):
                    info.payload_size = len(packet[Raw].load)
                if info.dst_port == 443 or info.src_port == 443:
                    info.is_encrypted = True

            elif packet.haslayer(UDP):
                info.protocol = "UDP"
                info.src_port = packet[UDP].sport
                info.dst_port = packet[UDP].dport
                if packet.haslayer(Raw):
                    info.payload_size = len(packet[Raw].load)

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
                if packet.haslayer(Raw):
                    info.payload_size = len(packet[Raw].load)
                if info.dst_port == 443 or info.src_port == 443:
                    info.is_encrypted = True
            elif packet.haslayer(UDP):
                info.protocol = "UDP"
                info.src_port = packet[UDP].sport
                info.dst_port = packet[UDP].dport
                if packet.haslayer(Raw):
                    info.payload_size = len(packet[Raw].load)
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
            try:
                dns = packet[DNS]
                if dns.qr == 0 and dns.qd:
                    info.dns_query = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                elif dns.qr == 1 and dns.an:
                    info.dns_response = str(dns.an.rdata) if hasattr(dns.an, 'rdata') else ""
            except Exception:
                pass

        # Process lookup (throttled — only every N seconds to save CPU)
        now = time.time()
        if now - self._last_process_lookup >= self._process_lookup_interval:
            self._last_process_lookup = now
            proc_name, proc_pid = _get_process_for_port(info.src_port)
            if not proc_name:
                proc_name, proc_pid = _get_process_for_port(info.dst_port)
            info.process_name = proc_name
            info.process_pid = proc_pid

        # Extract raw payload ONLY for unencrypted protocols where we need
        # to scan for credentials. This is a tiny fraction of traffic.
        if (info.payload_size > 0 and
            (info.dst_port in _CREDENTIAL_PORTS or info.src_port in _CREDENTIAL_PORTS)):
            try:
                if packet.haslayer(Raw):
                    info._raw_payload = bytes(packet[Raw].load)
            except Exception:
                pass

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

    def _start_capture_thread(self):
        """Start (or restart) the Scapy capture thread."""
        iface = self._select_interface()
        bpf = self.config.get('capture', 'bpf_filter', default='')

        def _capture_loop():
            logger.info("Capture started on interface: %s", iface)
            try:
                sniff(
                    iface=iface,
                    prn=self._capture_callback,
                    store=False,
                    stop_filter=lambda _: not self._running,
                    filter=bpf if bpf else None,
                )
            except PermissionError:
                logger.error("Permission denied. Run as Administrator for full capture.")
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

        logger.info("Capture engine started with queue-based processing.")
        return True

    def stop(self):
        """Stop the capture engine."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Capture engine stopped. Dropped packets: %d", self._dropped_packets)

    def get_flows_snapshot(self):
        """Return a snapshot of current flows for analysis."""
        with self._lock:
            return {k: v for k, v in self.flows.items()}

    def get_stats(self):
        """Return current statistics (thread-safe snapshot)."""
        with self._stats_lock:
            with self._lock:
                return dict(self.stats)

    @property
    def is_running(self):
        return self._running
