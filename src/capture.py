"""
Network packet capture engine using Scapy.
Captures packets, extracts metadata, and feeds them to the analysis pipeline.
"""

import inspect
import threading
import time
import logging
from collections import defaultdict, deque

from src.tls_inspect import (
    ClientHelloReassembler, QuicHelloReassembler, looks_like_quic,
)
from src.tls_certs import ServerHandshakeReassembler

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
    # Separate from the import above so a stub scapy (tests) still loads the rest.
    from scapy.all import AsyncSniffer
except ImportError:
    AsyncSniffer = None

# Cap on the per-flow list of names looked up, which used to grow without limit
# for a long-lived DNS flow (every query to the resolver shares one flow).
MAX_FLOW_DNS_QUERIES = 64

_HTTP_METHODS = (b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS ',
                 b'PATCH ')
_HTTP_HEADER_LIMIT = 4096


def parse_http_request(payload):
    """
    (method, host, path) from the start of a plaintext HTTP request, or None.

    Only the request line and Host header, read from the first few KB. Values are
    reduced to printable ASCII so a crafted request cannot carry control
    characters into alerts.
    """
    if not payload or not payload.startswith(_HTTP_METHODS):
        return None
    head = payload[:_HTTP_HEADER_LIMIT]
    line_end = head.find(b'\r\n')
    if line_end < 0:
        line_end = head.find(b'\n')
    if line_end < 0:
        return None
    parts = head[:line_end].split(b' ')
    if len(parts) < 3 or not parts[2].startswith(b'HTTP/'):
        return None
    method = parts[0].decode('ascii', 'replace')
    target = parts[1][:2048]
    host = b''
    lower = head.lower()
    idx = lower.find(b'\nhost:')
    if idx >= 0:
        end = head.find(b'\n', idx + 1)
        host = head[idx + 6:end if end >= 0 else len(head)].strip()
    if target.startswith((b'http://', b'https://')):
        # Absolute form, as sent to a proxy: the host is in the target.
        rest = target.split(b'://', 1)[1]
        slash = rest.find(b'/')
        host = host or (rest[:slash] if slash >= 0 else rest)
        target = rest[slash:] if slash >= 0 else b'/'

    def _clean(value, limit):
        text = value.decode('ascii', 'replace')[:limit]
        return ''.join(c for c in text if 32 < ord(c) < 127)

    host = _clean(host, 253).lower()
    path = _clean(target, 2048)
    if not path.startswith('/'):
        return None
    return method, host, path


def _looks_like_stratum(payload):
    """Plaintext Stratum (mining pool JSON-RPC): cheap enough for the packet path."""
    if not payload or payload[:1] != b'{':
        return False
    head = payload[:512]
    return (b'"mining.' in head or
            (b'"method"' in head and b'"login"' in head and b'"agent"' in head))

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
        'dns_rcode', 'dns_ttl', 'dns_answers', 'dns_qtype',
        'arp_op', 'arp_hwsrc', 'icmp_type',
        'http_method', 'http_host', 'http_path', 'app_protocol',
        'sample_weight',
        '_raw_payload', '_tls_certs',
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
        self.dns_qtype = 0         # Question type: 1 = A, 16 = TXT, 28 = AAAA ...
        # ARP sender detail from the ARP payload itself. The Ethernet source is
        # the frame's sender, which a proxy or a spoofing tool can make differ.
        self.arp_op = 0            # 1 = who-has (request), 2 = is-at (reply)
        self.arp_hwsrc = ""
        self.icmp_type = -1        # ICMP or ICMPv6 type (134 = router advertisement)
        # Plaintext HTTP request line, for exact-URL threat matching.
        self.http_method = ""
        self.http_host = ""
        self.http_path = ""
        self.app_protocol = ""     # 'http' or 'stratum' when recognised in the payload
        # How many packets this one stands for: under adaptive sampling only one in
        # N reaches the rules, so byte-counting rules scale by this.
        self.sample_weight = 1
        self._raw_payload = None
        self._tls_certs = ()       # DER certificates from a TLS <= 1.2 server flight

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
        self.dns_queries = deque(maxlen=MAX_FLOW_DNS_QUERIES)
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


def _process_map_refresher(stop):
    """
    Keep the port->process map warm from a background thread.

    psutil.net_connections() takes tens of milliseconds and used to run inline in the
    capture callback, stalling packet capture every couple of seconds.

    `stop` is the run's threading.Event, so the thread exits as soon as that run
    ends instead of after its next sleep — or, after a quick restart, never.
    """
    while not stop.is_set():
        try:
            _refresh_port_process_map(force=True)
        except Exception as e:
            logger.debug("Process map refresh error: %s", e)
        stop.wait(_PORT_CACHE_TTL)


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
    # NetBIOS name service and IPv6 DHCP, for the LAN-attack checks
    137, 546, 547,
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
        # Each run gets its own stop event, and every thread of that run waits on
        # it. One shared flag let a quick stop()+start() revive the old run's
        # threads beside the new ones.
        self._stop_event = threading.Event()
        self._stop_event.set()
        self._lifecycle_lock = threading.Lock()
        self._sniffer = None
        self._thread = None
        self._lock = threading.Lock()

        # Handshakes that span packets, joined per flow (bounded; see each class).
        self._hello_reassembler = ClientHelloReassembler()
        self._quic_reassembler = QuicHelloReassembler()
        self._cert_reassembler = ServerHandshakeReassembler()
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
            # Packets adaptive sampling kept from the rules. Counted apart from
            # drops: they were captured and tracked, just not inspected.
            'packets_sampled_out': 0,
            'sample_rate': 1,
        }
        self._sampled_out = 0
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
            question = dns.qd
            if isinstance(question, list):
                # Scapy 2.7+: a list (which also proxies to its first element,
                # with a deprecation warning on every packet).
                question = question[0] if len(question) else None
            if question is not None:
                qname = getattr(question, 'qname', b'')
                if qname:
                    info.dns_query = qname.decode('utf-8', errors='ignore').rstrip('.').lower()
                try:
                    info.dns_qtype = int(getattr(question, 'qtype', 0) or 0)
                except (TypeError, ValueError):
                    info.dns_qtype = 0

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

    def _extract_packet_info(self, packet, offline=False, raw=None) -> PacketInfo:
        """
        Extract structured metadata from a Scapy packet.

        `offline` is for reading a capture file: the timestamp comes from the
        packet rather than the clock, and there is no process lookup (the
        processes that sent it are long gone, and the ports now belong to others).
        This is the one parser for live capture and file analysis, so a file
        gets the same SNI, DNS and IPv6 detail as the live view.
        """
        info = PacketInfo()
        if offline:
            try:
                info.timestamp = float(packet.time)
            except (AttributeError, TypeError, ValueError):
                info.timestamp = time.time()
        else:
            info.timestamp = time.time()
        if raw is None:
            raw = self._raw_bytes(packet)
        info.length = len(raw)
        payload = b''
        tcp_seq = None

        # Ethernet layer
        if packet.haslayer(Ether):
            info.src_mac = packet[Ether].src
            info.dst_mac = packet[Ether].dst

        # IP layer
        ip_layer = None
        is_v6 = False
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            info.src_ip = ip_layer.src
            info.dst_ip = ip_layer.dst
            info.ttl = ip_layer.ttl
        elif packet.haslayer(IPv6):
            ip_layer = packet[IPv6]
            is_v6 = True
            info.src_ip = ip_layer.src
            info.dst_ip = ip_layer.dst
            info.ttl = ip_layer.hlim

        if ip_layer is not None:
            # IPv6 carries TCP/UDP the same way as IPv4
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                info.protocol = "TCP"
                info.src_port = tcp.sport
                info.dst_port = tcp.dport
                info.flags = str(tcp.flags)
                tcp_seq = tcp.seq
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
            elif is_v6 and ip_layer.nh == 58:
                # ICMPv6 dissects into a class per message type, none of them ICMP,
                # so it used to fall through to "IPv6/Other" and lose the type that
                # tells a router advertisement from an echo.
                info.protocol = "ICMPv6"
                body = ip_layer.payload
                first = getattr(body, 'type', None)
                if first is None:
                    load = getattr(body, 'load', b'')
                    first = load[0] if load else None
                info.icmp_type = int(first) if first is not None else -1
            elif packet.haslayer(ICMP):
                info.protocol = "ICMPv6" if is_v6 else "ICMP"
                info.icmp_type = int(packet[ICMP].type)
            else:
                info.protocol = "IPv6/Other" if is_v6 else "IP/Other"

        elif packet.haslayer(ARP):
            arp = packet[ARP]
            info.protocol = "ARP"
            info.src_ip = arp.psrc
            info.dst_ip = arp.pdst
            info.arp_op = int(arp.op)
            info.arp_hwsrc = str(arp.hwsrc or '').lower()

        else:
            info.protocol = "Other"

        # DNS layer
        if packet.haslayer(DNS):
            self._extract_dns(packet[DNS], info)

        # Process attribution. The expensive part (enumerating sockets) happens on a
        # background thread; this is a dict lookup, so every packet can be attributed
        # instead of roughly one per refresh interval.
        if not offline:
            proc_name, proc_pid = _get_process_for_port(info.src_port)
            if not proc_name:
                proc_name, proc_pid = _get_process_for_port(info.dst_port)
            info.process_name = proc_name
            info.process_pid = proc_pid

        if info.payload_size > 0:
            self._inspect_payload(info, payload, tcp_seq)

        return info

    def _inspect_payload(self, info, payload, tcp_seq):
        """What can be read from the transport payload: kept bytes for the
        credential scanners, TLS and QUIC handshakes, and plaintext requests."""
        # Raw payload ONLY for unencrypted protocols where we scan for credentials.
        # This is a tiny fraction of traffic.
        if info.dst_port in _CREDENTIAL_PORTS or info.src_port in _CREDENTIAL_PORTS:
            info._raw_payload = payload

        if info.protocol == 'TCP':
            # TLS handshakes. A separate test from the one above, not an elif: 8443
            # and 5061 are on both lists, so their handshakes were never parsed.
            # The reassemblers reject anything that is not a handshake start in a
            # few byte comparisons, so established connections cost almost nothing.
            if info.dst_port in _TLS_PORTS or info.src_port in _TLS_PORTS:
                key = (info.src_ip, info.src_port, info.dst_ip, info.dst_port)
                hello = self._hello_reassembler.feed(key, payload, tcp_seq, info.timestamp)
                if hello:
                    info.tls_sni = hello['sni'] or ''
                    info.tls_ja3 = hello['ja3']
                    info.tls_ja4 = hello['ja4']
                    info.tls_version = hello['version']
                elif info.src_port in _TLS_PORTS:
                    certs = self._cert_reassembler.feed(
                        key, payload, tcp_seq, info.timestamp)
                    if certs:
                        info._tls_certs = certs

            if payload[:1] in (b'G', b'P', b'H', b'D', b'O'):
                request = parse_http_request(payload)
                if request:
                    info.http_method, info.http_host, info.http_path = request
                    info.app_protocol = 'http'
            elif _looks_like_stratum(payload):
                info.app_protocol = 'stratum'

        elif info.protocol == 'UDP' and (info.dst_port == 443 or info.src_port == 443):
            # QUIC rides UDP/443 and would otherwise be indistinguishable from any
            # other UDP traffic — no flags, and is_encrypted left False.
            info.is_encrypted = True
            info.tls_version = 'QUIC'
            if info.dst_port == 443 and looks_like_quic(payload):
                hello = self._quic_reassembler.feed(payload, info.timestamp)
                if hello:
                    info.tls_sni = hello['sni'] or ''
                    info.tls_ja3 = hello['ja3']
                    info.tls_ja4 = hello['ja4']

    def _capture_callback(self, packet):
        """
        Called by Scapy for each captured packet.
        This runs in the capture thread — must be FAST.
        Only extracts minimal info and enqueues for processing.
        """
        try:
            raw = self._raw_bytes(packet)
            pkt_info = self._extract_packet_info(packet, raw=raw)

            # Buffer raw bytes for PCAP writer (before PPS cap for complete captures).
            # The wire bytes as captured: bytes(packet) re-serialised every layer,
            # once more per packet on this thread, and could differ from the wire.
            if self.raw_packet_callback:
                try:
                    self.raw_packet_callback(raw)
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

    def _worker_loop(self, stop=None):
        """
        Worker thread that processes packets from the queue.
        Handles IDS inspection, flow tracking, and ML callbacks.
        Runs separately from the capture thread so processing
        never blocks packet capture.
        """
        import queue
        stop = stop or self._stop_event
        logger.info("Packet processing worker started.")
        batch = []
        batch_size = 10  # Process up to 10 packets at a time

        while not stop.is_set():
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
                self.stats['packets_sampled_out'] = self._sampled_out

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

                        # IDS / ML callback (sampling under load). A skipped packet
                        # is counted, and the one that goes through carries the
                        # rate, so volume rules can scale what they see.
                        self._sample_counter += 1
                        if self._sample_counter >= self._sample_rate:
                            self._sample_counter = 0
                            pkt_info.sample_weight = self._sample_rate
                            if self.packet_callback:
                                self.packet_callback(pkt_info)
                        else:
                            self._sampled_out += 1

                    except Exception as e:
                        logger.debug("Worker packet error: %s", e)

                batch.clear()

            except Exception as e:
                logger.debug("Worker loop error: %s", e)
                batch.clear()

        logger.info("Packet processing worker stopped.")

    def _cleanup_flows(self, stop=None):
        """Remove expired flows and prune stats periodically."""
        stop = stop or self._stop_event
        while not stop.wait(30):
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

    def _watchdog_loop(self, stop=None):
        """
        Monitors the capture thread and restarts it if it dies.
        Also monitors the worker thread.
        """
        stop = stop or self._stop_event
        while not stop.wait(5):
            # Check capture thread
            self._note_sniffer_failure()
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
                    self._start_capture_thread(stop)
                else:
                    logger.error("Capture thread exceeded max restarts (%d). Giving up.",
                                 self._max_restarts)

            # Check worker thread
            if self._worker_thread and not self._worker_thread.is_alive() \
                    and not stop.is_set():
                logger.warning("Worker thread died. Restarting...")
                self._worker_thread = threading.Thread(
                    target=self._worker_loop, args=(stop,), daemon=True,
                    name="PacketWorker")
                self._worker_thread.start()

    def _note_sniffer_failure(self):
        """
        Log why a sniffer thread ended, once. AsyncSniffer catches the exception
        its thread raised and keeps it; a TypeError means an option this Scapy
        build rejects, which restarting cannot fix.
        """
        sniffer = self._sniffer
        error = getattr(sniffer, 'exception', None) if sniffer is not None else None
        if error is None or getattr(sniffer, '_ns_reported', False):
            return
        sniffer._ns_reported = True
        if isinstance(error, PermissionError):
            logger.error("Permission denied. Run as Administrator (Windows) or "
                         "as root / with CAP_NET_RAW (Linux) for packet capture.")
        elif isinstance(error, TypeError):
            logger.error("Capture rejected an option (%s). Not retrying.", error)
            self._fatal_capture_error = True
        else:
            logger.error("Capture error: %s", error)

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

    def _start_capture_thread(self, stop=None):
        """
        Start (or restart) the capture for the run that owns `stop`.

        AsyncSniffer, because plain sniff() checks stop_filter only when a packet
        arrives: on a quiet interface a stopped capture stayed blocked, and after
        a quick restart the old sniffer kept capturing beside the new one.
        AsyncSniffer.stop() wakes its loop directly. `_thread` is the sniffer's
        thread, which the app joins before it starts a new run.
        """
        stop = stop or self._stop_event
        if stop.is_set() or stop is not self._stop_event:
            return      # a late restart from a run that has already been stopped
        iface = self._select_interface()
        bpf = self.config.get('capture', 'bpf_filter', default='')
        sniff_options = self._supported_sniff_kwargs({
            'promisc': self.config.get('capture', 'promiscuous', default=True),
            'snaplen': self.config.get('capture', 'snap_length', default=65535),
        })
        logger.info("Capture starting on interface: %s", iface)

        if AsyncSniffer is not None:
            sniffer = AsyncSniffer(
                iface=iface,
                prn=self._capture_callback,
                store=False,
                stop_filter=lambda _: stop.is_set(),
                filter=bpf if bpf else None,
                **sniff_options,
            )
            sniffer.start()
            self._sniffer = sniffer
            self._thread = sniffer.thread
            if stop.is_set():           # stopped while this was starting
                self._stop_sniffer(sniffer)
            return

        # A Scapy too old for AsyncSniffer: sniff in one-second slices, so the
        # loop notices the stop event even when nothing arrives.
        def _capture_loop():
            try:
                while not stop.is_set():
                    sniff(iface=iface, prn=self._capture_callback, store=False,
                          stop_filter=lambda _: stop.is_set(), timeout=1,
                          filter=bpf if bpf else None, **sniff_options)
            except PermissionError:
                logger.error("Permission denied. Run as Administrator (Windows) or "
                             "as root / with CAP_NET_RAW (Linux) for packet capture.")
            except TypeError as e:
                logger.error("Capture rejected an option (%s). Not retrying.", e)
                self._fatal_capture_error = True
            except Exception as e:
                logger.error("Capture error: %s", e)
            finally:
                logger.info("Capture thread exited.")

        self._sniffer = None
        self._thread = threading.Thread(
            target=_capture_loop, daemon=True, name="CaptureThread")
        self._thread.start()

    @staticmethod
    def _stop_sniffer(sniffer, wait=1.0):
        """
        Stop an AsyncSniffer. Its stop() refuses until the thread has marked
        itself running, which a stop straight after a start can beat, so allow
        it a moment to get there rather than leave it capturing.
        """
        deadline = time.time() + wait
        while True:
            thread = getattr(sniffer, 'thread', None)
            if getattr(sniffer, 'running', False):
                try:
                    sniffer.stop(join=False)
                except Exception as e:
                    logger.debug("Sniffer stop: %s", e)
                return
            if thread is None or not thread.is_alive() or time.time() >= deadline:
                return
            time.sleep(0.02)

    def start(self):
        """Start the capture engine with worker threads and watchdog."""
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start capture: Scapy is not installed.")
            return False

        with self._lifecycle_lock:
            if self._running:
                return True

            stop = self._stop_event = threading.Event()
            self._running = True
            self._fatal_capture_error = False
            self.stats['start_time'] = time.time()
            self._last_rate_calc = time.time()
            self._restart_count = 0

            # Start capture thread
            try:
                self._start_capture_thread(stop)
            except Exception as e:
                logger.error("Capture could not start: %s", e)
                stop.set()
                self._running = False
                return False

            # Start worker thread (processes packets from queue)
            self._worker_thread = threading.Thread(
                target=self._worker_loop, args=(stop,), daemon=True, name="PacketWorker")
            self._worker_thread.start()

            # Start flow cleanup
            self._cleanup_thread = threading.Thread(
                target=self._cleanup_flows, args=(stop,), daemon=True, name="FlowCleanup")
            self._cleanup_thread.start()

            # Start watchdog (auto-restarts crashed threads)
            self._watchdog_thread = threading.Thread(
                target=self._watchdog_loop, args=(stop,), daemon=True, name="Watchdog")
            self._watchdog_thread.start()

            # Keep the port->process map warm without blocking the capture thread
            if PSUTIL_AVAILABLE:
                self._procmap_thread = threading.Thread(
                    target=_process_map_refresher, args=(stop,),
                    daemon=True, name="ProcMapRefresh")
                self._procmap_thread.start()

            logger.info("Capture engine started with queue-based processing.")
            return True

    def stop(self):
        """Stop the capture engine and wait for its threads to wind down."""
        with self._lifecycle_lock:
            self._running = False
            self._stop_event.set()
            if self._sniffer is not None:
                self._stop_sniffer(self._sniffer)
            # Every thread of this run waits on the event, so these return promptly.
            for t in (self._thread, self._worker_thread, self._watchdog_thread,
                      self._cleanup_thread, self._procmap_thread):
                if t is not None and t.is_alive() and t is not threading.current_thread():
                    t.join(timeout=5)
            logger.info("Capture engine stopped. Dropped packets: %d, sampled out: %d",
                        self._dropped_packets, self._sampled_out)

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
