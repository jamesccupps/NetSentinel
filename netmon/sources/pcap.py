"""
Packet capture as an event source.
===================================
Reads a capture file or a live mirror port and turns packets into Events. This
is what makes the protocol-aware rules work: BACnet commands, TLS server names,
DNS and name-resolution queries, DHCP — none of which appear in a flow export.

    from netmon.sources.pcap import read_pcap
    for event in read_pcap('capture.pcapng', profile):
        ...

What it extracts, and what it refuses to
----------------------------------------
Derived facts only: a server name, a query, a BACnet service and object, a
credential *type*. Never the bytes themselves. Nothing here attaches a payload
to an event, so there is nothing for a later stage to leak.

On a segment the profile marks `store_payload: false`, it goes further and does
not parse above the transport header at all. The rules would have discarded the
result, but not looking is a stronger guarantee than looking and discarding, and
it is the one the site asked for. Those segments still produce flow events —
who talked to whom, when, how much — which is the whole point of metadata-only.

Trunk mirrors count each routed packet twice
--------------------------------------------
A routed packet crosses the mirror twice: once arriving from the sender on the
source VLAN, once leaving the router on the destination VLAN. In a measured
seven-second sample, 3,178 packets appeared on both sides. Counting both doubles
every byte total and attributes half the traffic to the router.

Set `router_macs` in the profile and the relayed copy is dropped: a frame whose
source MAC is the router, but whose source *address* is not the router, is the
second appearance of a packet already counted. Traffic the router itself
originates is kept, and so is same-VLAN traffic, which a simpler "only count
frames sent to the router" rule would discard.
"""

from __future__ import annotations

import logging
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from netmon.events import Event                                   # noqa: E402
from netmon.protocols import bacnet, site                         # noqa: E402

logger = logging.getLogger("netmon.sources.pcap")

__all__ = ['read_pcap', 'packet_to_events', 'PcapError', 'CLEARTEXT_PORTS']


class PcapError(ValueError):
    """The capture could not be read."""


def _scapy():
    """
    Import Scapy lazily and loudly.

    Importing it costs a second or two and pulls in a great deal; the rest of
    netmon works without it, and a UniFi-export user should not pay for a
    dependency they never touch.
    """
    try:
        from scapy.all import (ARP, DNS, DNSQR, DNSRR, UDP, TCP, IP, IPv6,  # noqa
                               Dot1Q, Ether, NoPayload, PcapReader, sniff)
    except ImportError as e:                                   # pragma: no cover
        raise PcapError(
            'scapy is needed to read captures: pip install scapy') from e
    import scapy.all as scapy_all
    return scapy_all


#: Ports where credentials cross in the clear. The rule reports the *type* and
#: the endpoints; the value is never read, logged or carried.
CLEARTEXT_PORTS = {
    21: 'ftp', 23: 'telnet', 80: 'http', 110: 'pop3', 143: 'imap',
    389: 'ldap-simple-bind', 161: 'snmp-community', 5060: 'sip-register',
    1433: 'mssql-tds', 3306: 'mysql', 23389: 'rdp-cleartext',
}

_NAME_PORTS = {5355: 'llmnr', 5353: 'mdns', 137: 'nbns', 53: 'dns'}


def _first(packet, layer):
    try:
        return packet.getlayer(layer)
    except Exception:                                          # pragma: no cover
        return None


def _vlan_of(packet, scapy):
    """The outermost 802.1Q tag, or None for an untagged frame."""
    tag = _first(packet, scapy.Dot1Q)
    return int(tag.vlan) if tag is not None else None


def _transport_payload(packet, scapy):
    """
    The bytes above TCP/UDP, however Scapy chose to dissect them.

    `haslayer(Raw)` is only true when Scapy had no dissector. With the TLS and
    DNS layers loaded, port 443 and port 53 dissect into those instead, so
    keying off Raw silently returns nothing for most of a real capture.
    """
    transport = _first(packet, scapy.TCP) or _first(packet, scapy.UDP)
    if transport is None:
        return b''
    payload = transport.payload
    if payload is None or isinstance(payload, scapy.NoPayload):
        return b''
    original = getattr(payload, 'original', None)
    if original:
        return original
    try:
        return bytes(payload)
    except Exception:                                          # pragma: no cover
        return b''


# ─── Packet to events ────────────────────────────────────────────────────────

def packet_to_events(packet, profile=None, scapy=None):
    """
    Turn one packet into zero or more Events.

    Usually one. A DNS response carrying several answers produces one event per
    answer, because a rule about fast-flux counts addresses.
    """
    scapy = scapy or _scapy()

    ether = _first(packet, scapy.Ether)
    ip = _first(packet, scapy.IP) or _first(packet, scapy.IPv6)
    arp = _first(packet, scapy.ARP)
    vlan = _vlan_of(packet, scapy)

    if ip is None and arp is None:
        return []

    timestamp = float(getattr(packet, 'time', 0) or 0)
    src_mac = (ether.src if ether is not None else '') or ''
    dst_mac = (ether.dst if ether is not None else '') or ''

    if arp is not None:
        return [_arp_event(arp, src_mac, dst_mac, vlan, timestamp)]

    transport = _first(packet, scapy.TCP) or _first(packet, scapy.UDP)
    protocol = 'tcp' if _first(packet, scapy.TCP) is not None else \
        ('udp' if _first(packet, scapy.UDP) is not None else '')
    src_port = int(transport.sport) if transport is not None else None
    dst_port = int(transport.dport) if transport is not None else None

    base = dict(
        ts=timestamp, src_ip=str(ip.src), dst_ip=str(ip.dst),
        src_mac=src_mac.lower(), dst_mac=dst_mac.lower(),
        src_port=src_port, dst_port=dst_port, protocol=protocol, vlan=vlan,
        bytes_to_dst=len(packet), packets=1, source='pcap')

    # The prohibition, applied before anything is parsed rather than after.
    # Not looking is a stronger guarantee than looking and discarding.
    if profile is not None and not profile.may_store_payload(vlan):
        event = Event(kind='flow', **base)
        event.fields['metadata_only'] = True
        return [event]

    payload = _transport_payload(packet, scapy)
    specific = _protocol_events(packet, base, payload, src_port, dst_port,
                                protocol, scapy)
    events = specific or [Event(kind='flow', **base)]
    for event in events:
        _name_the_service(event, payload, profile)
    return events


def _name_the_service(event, payload, profile):
    """
    Say which system this is, where that can be established.

    A finding that says "TCP 7000" is one nobody acts on; one that says "Otis
    elevator control" can go to the lift contractor. The site's own additions
    come from the profile, because the next building runs a different lift.
    """
    service = site.identify(
        src_port=event.src_port, dst_port=event.dst_port,
        protocol=event.protocol, payload=payload,
        name=event.fields.get('sni') or event.fields.get('query') or '',
        extra_services=getattr(profile, 'services', ()) if profile else ())
    if service is None:
        return

    event.fields['service_name'] = service.name
    event.fields['service_description'] = service.description
    if service.category:
        event.fields['service_category'] = service.category
    event.fields['service_encrypted'] = service.encrypted

    # The three protocols worth reading further. Each adds fields a rule can
    # match on; none of them reads more of the message than it needs.
    if service.name == 'parking-kiosk':
        # Metadata only, always: these carry cardholder data, and the profile's
        # payload policy is not the mechanism here — the parser is.
        details = site.parse_kiosk_command(payload)
        if details:
            event.fields.update({f'kiosk_{k}': v for k, v in details.items()})
    elif service.name == 'siemens-p2':
        details = site.parse_p2(payload, event.src_port, event.dst_port)
        if details:
            event.fields.update(details)
    elif service.name == 'otis':
        details = site.parse_otis(payload)
        if details:
            event.fields.update(details)


def _arp_event(arp, src_mac, dst_mac, vlan, timestamp):
    """
    ARP, which is how an address conflict or a decommissioned host shows up.

    `psrc`/`pdst` rather than the IP header, because an ARP frame has none.
    """
    event = Event(kind='arp', ts=timestamp, src_ip=str(arp.psrc),
                  dst_ip=str(arp.pdst), src_mac=(src_mac or arp.hwsrc).lower(),
                  dst_mac=dst_mac.lower(), vlan=vlan, packets=1, source='pcap')
    event.fields['arp_operation'] = 'reply' if int(arp.op) == 2 else 'request'
    event.fields['is_answer'] = int(arp.op) == 2
    return event


def _protocol_events(packet, base, payload, src_port, dst_port, protocol, scapy):
    """Dispatch on the ports involved, returning [] when nothing matched."""
    ports = {p for p in (src_port, dst_port) if p}

    if protocol == 'udp' and any(bacnet.is_bacnet_port(p) for p in ports):
        return _bacnet_events(base, payload)

    name_kind = next((_NAME_PORTS[p] for p in ports if p in _NAME_PORTS), '')
    if name_kind:
        return _name_events(packet, base, name_kind, scapy)

    if 67 in ports or 68 in ports:
        return _dhcp_events(packet, base, scapy)

    if protocol == 'tcp' and payload:
        events = _tls_events(base, payload)
        if events:
            return events

    if protocol == 'udp' and 443 in ports and payload:
        from src.tls_inspect import looks_like_quic
        if looks_like_quic(payload):
            event = Event(kind='quic', **base)
            return [event]

    if protocol == 'tcp' and 80 in ports and payload:
        agent = _user_agent(payload)
        if agent:
            details = site.parse_eset_user_agent(agent)
            if details:
                event = Event(kind='http', **base)
                event.fields.update(details)
                # The User-Agent itself is not carried: the OS build is the
                # finding, and the rest of the string is a fingerprint nobody
                # asked this monitor to keep.
                return [event]

    credential = _cleartext_kind(ports, payload)
    if credential:
        event = Event(kind='cleartext', **base)
        # The type and the endpoints. Never the value: this string is written
        # to logs, sent in alerts and included in AI prompts.
        event.fields['credential_type'] = credential
        return [event]

    return []


def _bacnet_events(base, payload):
    message = bacnet.parse(payload)
    if message is None:
        return []
    event = Event(kind='bacnet', **base)
    event.fields.update(message.as_fields())
    return [event]


def _name_events(packet, base, kind, scapy):
    """
    DNS and its unauthenticated cousins: LLMNR, mDNS, NBNS.

    The cousins matter more than DNS here. None of them authenticates anything:
    whoever answers first wins, so a name nobody owns is a standing invitation.
    """
    dns = _first(packet, scapy.DNS)
    if dns is None:
        return [Event(kind=kind, **base)]

    is_answer = bool(int(getattr(dns, 'qr', 0)))
    query = ''
    question = getattr(dns, 'qd', None)
    if question is not None:
        name = getattr(question, 'qname', b'')
        if isinstance(name, (bytes, bytearray)):
            name = name.decode('utf-8', 'replace')
        query = str(name).rstrip('.').lower()

    events = []
    answers = _answer_records(dns)
    if is_answer and answers:
        for value, record_type, ttl in answers:
            event = Event(kind=kind, **base)
            event.fields.update({'query': query, 'is_answer': True,
                                 'answer': value, 'record_type': record_type,
                                 'ttl': ttl,
                                 'rcode': int(getattr(dns, 'rcode', 0))})
            events.append(event)
        return events

    event = Event(kind=kind, **base)
    event.fields.update({'query': query, 'is_answer': is_answer,
                         'rcode': int(getattr(dns, 'rcode', 0))})
    if is_answer and int(getattr(dns, 'rcode', 0)) == 3:
        event.fields['nxdomain'] = True
    return [event]


def _answer_records(dns):
    """
    Every answer, whatever shape this Scapy version uses for the section.

    Scapy 2.7 returns a list subclass that also proxies `rdata` through to its
    first element, so testing for that attribute finds one answer and misses the
    rest. Testing for a list is what distinguishes them.
    """
    section = getattr(dns, 'an', None)
    if section is None:
        return []
    records = list(section) if isinstance(section, list) else [section]

    out = []
    for record in records:
        if record is None:
            continue
        value = getattr(record, 'rdata', None)
        if value is None:
            continue
        if isinstance(value, (bytes, bytearray)):
            value = value.decode('utf-8', 'replace')
        out.append((str(value).rstrip('.'),
                    int(getattr(record, 'type', 0)),
                    int(getattr(record, 'ttl', 0))))
    return out


#: DHCP message types, by the value of option 53.
_DHCP_TYPES = {1: 'discover', 2: 'offer', 3: 'request', 4: 'decline',
               5: 'ack', 6: 'nak', 7: 'release', 8: 'inform'}


def _dhcp_events(packet, base, scapy):
    """
    DHCP, where the two findings are a device that never gets an answer and an
    answer from something that is not the gateway.
    """
    event = Event(kind='dhcp', **base)
    options = None
    try:
        layer = packet.getlayer(scapy.DHCP)
        options = getattr(layer, 'options', None) if layer is not None else None
    except (AttributeError, IndexError):
        options = None

    message_type = None
    hostname = ''
    for option in (options or []):
        if not isinstance(option, tuple) or len(option) < 2:
            continue
        name, value = option[0], option[1]
        if name == 'message-type':
            message_type = _DHCP_TYPES.get(int(value), str(value))
        elif name == 'hostname':
            hostname = value.decode('utf-8', 'replace') \
                if isinstance(value, (bytes, bytearray)) else str(value)

    event.fields['message'] = message_type or ''
    if hostname:
        event.fields['hostname'] = hostname

    # The client MAC is in the BOOTP header, which is where an offer addressed
    # to a broadcast still names who it is for.
    try:
        bootp = packet.getlayer(scapy.BOOTP)
        if bootp is not None and getattr(bootp, 'chaddr', None):
            raw = bytes(bootp.chaddr)[:6]
            event.fields['client_mac'] = ':'.join(f'{b:02x}' for b in raw)
    except (AttributeError, IndexError):
        pass
    return [event]


def _tls_events(base, payload):
    """A TLS ClientHello, for the server name and the client fingerprints."""
    from src.tls_inspect import looks_like_tls_handshake, parse_client_hello
    if not looks_like_tls_handshake(payload):
        return []
    hello = parse_client_hello(payload)
    if not hello:
        return []
    event = Event(kind='tls', **base)
    for key in ('sni', 'ja3', 'ja4', 'alpn', 'version'):
        value = hello.get(key)
        if value:
            event.fields[key] = value
    return [event]


_USER_AGENT = re.compile(rb'\r\nUser-Agent:\s*([^\r\n]{1,300})\r\n', re.I)


def _user_agent(payload):
    """The User-Agent header, if this looks like an HTTP request."""
    found = _USER_AGENT.search(payload[:2048])
    return found.group(1).decode('latin-1', 'replace') if found else ''


def _cleartext_kind(ports, payload):
    """
    Whether this looks like credentials in the clear, and of what kind.

    Deliberately shallow. It looks at the port and, for HTTP, at whether an
    Authorization header is present — not at what is in it. The finding is
    "a credential crossed here in the clear"; the value is the one thing that
    must not be recorded.
    """
    for port in ports:
        kind = CLEARTEXT_PORTS.get(port)
        if kind is None:
            continue
        if kind == 'http':
            if not payload:
                return None
            head = payload[:512].lower()
            if b'authorization:' in head or b'proxy-authorization:' in head:
                return 'http-authorization'
            if b'cookie:' in head and b'session' in head:
                return 'http-session-cookie'
            return None
        if kind == 'snmp-community' and not payload:
            return None
        return kind
    return None


# ─── Reading ─────────────────────────────────────────────────────────────────

#: The first four bytes of each capture format, in both byte orders.
_PCAP_MAGIC = (
    b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',      # pcap
    b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d',      # pcap, nanosecond
    b'\x0a\x0d\x0d\x0a',                              # pcapng
)


def _check_magic(path):
    """
    Confirm the file is a capture before handing it to Scapy.

    Scapy opens the file and then fails on the magic, leaving the handle for the
    garbage collector; more usefully, "this is not a capture file" is a better
    answer than whatever its internals say when a text file is fed to them.
    """
    try:
        with open(path, 'rb') as handle:
            magic = handle.read(4)
    except OSError as e:
        raise PcapError(f'{path}: {e}') from e
    if magic not in _PCAP_MAGIC:
        if magic[:2] == b'\x1f\x8b':
            raise PcapError(f'{path} is gzipped; decompress it first')
        raise PcapError(f'{path} is not a capture file '
                        f'(it starts {magic!r}, not a pcap or pcapng magic)')


class _RouterDedup:
    """
    Drops the second appearance of a routed packet on a trunk mirror.

    A frame relayed by the router has the router's source MAC but not the
    router's source address; the original, already counted, had the sender's
    MAC. Frames the router itself originates keep their own address and are
    kept, as is all same-VLAN traffic.
    """

    def __init__(self, router_macs=(), router_ips=()):
        self.router_macs = {m.lower() for m in router_macs if m}
        self.router_ips = set(router_ips or ())
        self.dropped = 0

    def should_drop(self, event):
        if not self.router_macs:
            return False
        if event.src_mac not in self.router_macs:
            return False
        if event.src_ip and event.src_ip in self.router_ips:
            return False                      # the router speaking for itself
        self.dropped += 1
        return True


def read_pcap(path, profile=None, limit=None, bpf=None, dedup_router=True):
    """
    Read a capture file, yielding Events.

    Args:
        path: a .pcap or .pcapng.
        profile: used for the payload prohibition and for router deduplication.
        limit: stop after this many events.
        bpf: a capture filter applied while reading. Build it with netmon.bpf
            rather than by hand; the module docstring there explains why.
        dedup_router: drop the relayed copy of routed packets. See the class
            above.

    A generator: a day of mirrored traffic does not fit in memory, and a caller
    that wants a list can ask for one knowingly.
    """
    scapy = _scapy()
    if not os.path.exists(path):
        raise PcapError(f'capture not found: {path}')

    dedup = _RouterDedup(
        getattr(profile, 'router_macs', ()) if dedup_router else (),
        {v.gateway for v in getattr(profile, 'vlans', {}).values() if v.gateway}
        if profile is not None else ())

    _check_magic(path)

    emitted = skipped = 0
    try:
        reader = scapy.PcapReader(path)
    except Exception as e:
        raise PcapError(f'{path}: {e}') from e

    try:
        for packet in reader:
            try:
                events = packet_to_events(packet, profile, scapy)
            except Exception:
                # One malformed packet must not end the capture. The parsers
                # are bounds-checked, so this is for whatever Scapy does with a
                # frame it cannot dissect.
                logger.debug('could not read a packet', exc_info=True)
                skipped += 1
                continue
            for event in events:
                if dedup.should_drop(event):
                    continue
                yield event
                emitted += 1
                if limit and emitted >= limit:
                    return
    finally:
        reader.close()
        if skipped:
            logger.warning('%s: skipped %d unreadable packets of %d',
                           os.path.basename(path), skipped, skipped + emitted)
        if dedup.dropped:
            logger.info('%s: dropped %d router-relayed duplicates',
                        os.path.basename(path), dedup.dropped)


def read_live(interface, profile=None, bpf=None, count=0, timeout=None,
              dedup_router=True):
    """
    Read from an interface. Needs privileges, and a mirror port to be useful.

    The capture interface should have no address and no protocol bindings: one
    left configured puts DHCP, NBNS, LLMNR, mDNS, SSDP and EAPOL onto the
    mirrored VLAN, which contaminates every baseline built from it. List its MAC
    under `sensor_macs` in the profile and the sensor_chatter rule will say so
    if it ever transmits.
    """
    scapy = _scapy()
    dedup = _RouterDedup(
        getattr(profile, 'router_macs', ()) if dedup_router else (),
        {v.gateway for v in getattr(profile, 'vlans', {}).values() if v.gateway}
        if profile is not None else ())

    collected = []

    def handle(packet):
        try:
            for event in packet_to_events(packet, profile, scapy):
                if not dedup.should_drop(event):
                    collected.append(event)
        except Exception:
            logger.debug('could not read a packet', exc_info=True)

    scapy.sniff(iface=interface, filter=bpf or None, prn=handle,
                count=count, timeout=timeout, store=False)
    return collected
