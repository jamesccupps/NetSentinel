"""
Attacks on the local network.
=============================
The ways another machine on the same LAN takes over traffic, and the signs of an
intruder moving across it. All passive: nothing here sends a packet.

- **ARP spoofing.** A host claiming another's IP address (the gateway's, above
  all) so traffic flows through it. The sender's MAC and the opcode come from the
  ARP payload, not the Ethernet header, which a relaying or spoofing host can
  make differ. The gateway's MAC is pinned and kept across restarts.
- **Rogue DHCP, router advertisements and DHCPv6.** Whoever answers DHCP decides
  a client's gateway and DNS server; an unknown server is a classic redirect, and
  on IPv6 the same is done with router advertisements or DHCPv6 (mitm6).
- **LLMNR / NBT-NS / mDNS poisoning.** Responder answers every name lookup on
  the segment with its own address and harvests the credentials that follow.
  The tell is one host answering for many names that are not its own.
- **Lateral movement.** One LAN host reaching many others over SMB, RDP,
  WinRM or RPC in a few minutes.
- **Uploads.** A host sending far more to the internet than it normally does.
- **New devices.** A MAC address first seen after the learning period.

Note that a PC sees other hosts' unicast traffic only through a SPAN/mirror port
or a hub; without one, lateral movement and most LAN detections here can only
see what touches this machine (and broadcasts, which is how ARP, DHCP and the
name protocols work, so those still see the whole segment).

Each monitor returns finding dicts; IDSEngine turns them into alerts, which is
where cooldowns apply.
"""

import ipaddress
import logging
import os
import struct
import threading
import time
from collections import OrderedDict, deque

from src.ipcache import classify

logger = logging.getLogger("NetSentinel.LAN")

__all__ = ['LanThreatMonitor', 'is_randomized_mac', 'is_failover_mac',
           'parse_dns_wire', 'vendor_for_mac']

STATE_FILE = 'lan_state.json'

# ─── MAC helpers ─────────────────────────────────────────────────────────────

# Virtual MACs that move between routers by design (RFC 5798 VRRP, Cisco HSRP
# and GLBP, CARP uses VRRP's). A gateway IP moving to one of these, or between
# them, is a failover, not an attack.
_FAILOVER_PREFIXES = ('00:00:5e:00:01:', '00:00:5e:00:02:', '00:00:0c:07:ac:',
                      '00:00:0c:9f:f', '00:07:b4:')


def _norm_mac(mac):
    return (mac or '').lower().replace('-', ':')


def is_multicast_mac(mac):
    try:
        return bool(int(_norm_mac(mac)[:2], 16) & 0x01)
    except ValueError:
        return True


def is_randomized_mac(mac):
    """Locally administered: phones and laptops pick these per network."""
    try:
        return bool(int(_norm_mac(mac)[:2], 16) & 0x02)
    except ValueError:
        return False


def is_failover_mac(mac):
    return _norm_mac(mac).startswith(_FAILOVER_PREFIXES)


def _usable_mac(mac):
    mac = _norm_mac(mac)
    return bool(mac) and mac != '00:00:00:00:00:00' and not is_multicast_mac(mac)


def _arp_sender_mac(mac):
    """
    A sender address worth tracking in ARP. Unlike a device identity, a group
    address here is kept: no real host sends ARP from one, so a binding to it
    is itself a sign of tampering.
    """
    mac = _norm_mac(mac)
    return bool(mac) and mac not in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff')


def vendor_for_mac(mac):
    """The OUI vendor from Scapy's manufacturer database, or ''."""
    mac = _norm_mac(mac)
    if not mac or is_randomized_mac(mac):
        return ''
    try:
        from scapy.all import conf
        db = getattr(conf, 'manufdb', None)
        if db is None:
            return ''
        name = db._get_manuf(mac)
    except Exception:
        return ''
    if not name or _norm_mac(name) == mac:
        return ''
    return str(name)[:80]


def _is_lan(ip):
    if not ip:
        return False
    valid, private, multicast, link_local, loopback = classify(ip)
    return valid and (private or link_local) and not multicast and not loopback


# ─── DNS wire format (LLMNR, mDNS and NetBIOS name service share it) ──────────

def _read_name(buf, pos, depth=0):
    labels = []
    jumped_to = None
    for _ in range(128):
        if pos >= len(buf):
            raise ValueError('name past end')
        length = buf[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xc0 == 0xc0:
            if pos + 1 >= len(buf) or depth > 8:
                raise ValueError('bad pointer')
            target = ((length & 0x3f) << 8) | buf[pos + 1]
            if jumped_to is None:
                jumped_to = pos + 2
            pos = target
            depth += 1
            continue
        if length > 63 or pos + 1 + length > len(buf):
            raise ValueError('bad label')
        labels.append(buf[pos + 1:pos + 1 + length])
        pos += 1 + length
    return labels, (jumped_to if jumped_to is not None else pos)


def _decode_netbios(label):
    """First-level NetBIOS name encoding: 32 letters A-P for 16 bytes."""
    if len(label) != 32:
        return None
    try:
        raw = bytes(((label[i] - 0x41) << 4) | (label[i + 1] - 0x41)
                    for i in range(0, 32, 2))
    except ValueError:
        return None
    return raw[:15].decode('ascii', 'replace').rstrip(' \x00')


def parse_dns_wire(payload, netbios=False):
    """
    (is_response, [(name, address)]) for the address records in a DNS-format
    message, or None if it does not parse. Names are lowercased; NetBIOS names
    are decoded. Bounded and strict: every byte here is attacker-supplied.
    """
    try:
        if len(payload) < 12:
            return None
        flags, qd, an, ns, ar = struct.unpack('>HHHHH', payload[2:12])
        is_response = bool(flags & 0x8000)
        pos = 12
        for _ in range(min(qd, 16)):
            _, pos = _read_name(payload, pos)
            pos += 4
        answers = []
        for _ in range(min(an + ns + ar, 64)):
            labels, pos = _read_name(payload, pos)
            if pos + 10 > len(payload):
                break
            rtype, _rclass, _ttl, rdlen = struct.unpack('>HHIH', payload[pos:pos + 10])
            pos += 10
            rdata = payload[pos:pos + rdlen]
            pos += rdlen
            if len(rdata) != rdlen:
                break
            if netbios:
                if rtype == 0x20 and labels and rdlen >= 6:
                    name = _decode_netbios(labels[0])
                    if name:
                        answers.append((name.lower(), str(ipaddress.IPv4Address(rdata[2:6]))))
                continue
            name = b'.'.join(labels).decode('utf-8', 'replace').lower()
            if rtype == 1 and rdlen == 4:
                answers.append((name, str(ipaddress.IPv4Address(rdata))))
            elif rtype == 28 and rdlen == 16:
                answers.append((name, str(ipaddress.IPv6Address(rdata))))
        return is_response, answers
    except (ValueError, struct.error, IndexError):
        return None


def _short_name(name):
    name = name.lower().rstrip('.')
    return name[:-6] if name.endswith('.local') else name


# ─── The monitor ─────────────────────────────────────────────────────────────

class LanThreatMonitor:
    """
    One object, several checks, one small persisted state file (the pinned
    gateway MAC, DHCP servers and routers learned, MACs already seen).
    `offline` (PCAP analysis) neither reads nor writes that file, and skips
    the checks that only mean something against this network's own history.
    """

    def __init__(self, config=None, net_env=None, state_path=None, offline=False):
        self.net_env = net_env
        self.offline = offline
        get = (lambda *keys, default=None: default) if config is None else config.get
        self.baseline_hours = float(get('ids', 'lan_baseline_hours', default=24))
        self.arp_max_ips_per_mac = int(get('ids', 'arp_max_ips_per_mac', default=5))
        self.lateral_threshold = int(get('ids', 'lateral_fanout_hosts', default=10))
        self.upload_floor_mb = float(get('ids', 'upload_spike_min_mb', default=50))
        self.new_device_alerts = bool(get('ids', 'new_device_alerts', default=True))

        if state_path is None and not offline and config is not None:
            try:
                from src.config import DB_DIR
                state_path = os.path.join(DB_DIR, STATE_FILE)
            except Exception:
                state_path = None
        self.state_path = None if offline else state_path
        self._lock = threading.Lock()
        self._dirty = False
        self._last_save = 0.0
        self.state = {'created': time.time(), 'gateway_macs': {}, 'dhcp_servers': [],
                      'routers': [], 'dhcpv6_servers': [], 'known_macs': {}}
        self._load()

        # ARP
        self._started = time.time()
        self._gw_heard = {}               # gateway ip -> last time its pinned MAC spoke
        self._arp = {}                    # ip -> {'mac', 'last', 'history': [mac...]}
        self._mac_ips = {}                # mac -> {ip: last}
        self._garp = {}                   # mac -> deque[timestamps]
        # Name poisoning: responder -> {'names': {name: last}, 'ips': set}
        self._responders = OrderedDict()
        self._name_owners = {}            # name -> {responder ids}
        # Lateral movement: src -> {dst: last}
        self._fanout = {}
        # Uploads: src -> state
        self._uploads = {}
        self.stats = {'arp_seen': 0, 'dhcp_server_messages': 0, 'router_adverts': 0,
                      'name_responses': 0, 'new_devices': 0}

    # ─── State ──────────────────────────────────────────────────────────────

    def _load(self):
        if not self.state_path or not os.path.exists(self.state_path):
            return
        try:
            import json
            with open(self.state_path, encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict):
                for key, value in data.items():
                    if key in self.state and isinstance(value, type(self.state[key])):
                        self.state[key] = value
        except Exception as e:
            logger.warning("LAN state %s unreadable, starting fresh: %s", self.state_path, e)

    def save(self, force=False):
        if not self.state_path:
            return
        now = time.time()
        if not force and (not self._dirty or now - self._last_save < 60):
            return
        with self._lock:
            known = self.state['known_macs']
            if len(known) > 10000:
                for mac in sorted(known, key=known.get)[:len(known) - 10000]:
                    del known[mac]
            snapshot = {k: (dict(v) if isinstance(v, dict) else list(v) if isinstance(v, list) else v)
                        for k, v in self.state.items()}
            self._dirty = False
            self._last_save = now
        try:
            from src.config import atomic_write_json
            atomic_write_json(self.state_path, snapshot, indent=1)
        except Exception as e:
            logger.debug("LAN state save failed: %s", e)

    def in_baseline(self, now):
        if self.offline:
            return False
        return now - self.state.get('created', now) < self.baseline_hours * 3600

    def _gateways(self):
        return list(getattr(self.net_env, 'gateways', None) or [])

    # ─── Entry point ────────────────────────────────────────────────────────

    def observe(self, pkt, now, outbound=False):
        """All checks for one packet. Returns a list of finding dicts."""
        findings = []
        proto = pkt.protocol
        if proto == 'ARP':
            findings.extend(self._observe_arp(pkt, now))
        elif proto == 'UDP':
            if pkt.src_port == 67 and pkt.dst_port == 68:
                findings.extend(self._observe_dhcp(pkt, now))
            elif pkt.src_port == 547 and pkt.dst_port == 546:
                findings.extend(self._observe_dhcpv6(pkt, now))
            elif pkt.src_port in (5355, 5353, 137) and pkt._raw_payload:
                findings.extend(self._observe_name_response(pkt, now))
        elif proto == 'ICMPv6' and pkt.icmp_type == 134:
            findings.extend(self._observe_router_advert(pkt, now))

        if proto == 'TCP' and pkt.dst_port in LATERAL_PORTS:
            findings.extend(self._observe_lateral(pkt, now))
        if outbound and pkt.payload_size > 0:
            findings.extend(self._observe_upload(pkt, now))
        if self.new_device_alerts and not self.offline:
            findings.extend(self._observe_device(pkt, now))

        if self._dirty:
            self.save()
        return findings

    # ─── ARP ────────────────────────────────────────────────────────────────

    def _observe_arp(self, pkt, now):
        mac = _norm_mac(pkt.arp_hwsrc or pkt.src_mac)
        ip = pkt.src_ip
        if not ip or ip == '0.0.0.0' or not _arp_sender_mac(mac):
            return []          # RFC 5227 probes come from 0.0.0.0
        self.stats['arp_seen'] += 1
        findings = []

        gratuitous = bool(pkt.dst_ip) and pkt.dst_ip == ip
        if gratuitous:
            burst = self._garp.setdefault(mac, deque(maxlen=64))
            burst.append(now)
            recent = sum(1 for t in burst if now - t <= 60)
            if recent >= 20:
                findings.append(self._finding(
                    'ARP-GRATUITOUS-BURST', 'MEDIUM', 'Burst of Gratuitous ARP',
                    f"{mac} sent {recent} gratuitous ARP announcements in 60 seconds",
                    {'mac': mac, 'ip_claimed': ip, 'announcements_60s': recent,
                     'vendor': vendor_for_mac(mac),
                     'description': ('Gratuitous ARP tells every host to update its '
                                     'cache. A failover sends a few; a steady stream is '
                                     'what ARP-poisoning tools send to keep caches '
                                     'pointed at them.'),
                     'recommendation': 'Find the device with this MAC on your switch '
                                       'or router and confirm what it is.'},
                    'MITM', key=f"ARP-GRATUITOUS-BURST:{mac}", hold=600))

        # The gateway's pinned MAC.
        if ip in self._gateways():
            findings.extend(self._check_gateway(ip, mac, now))

        entry = self._arp.get(ip)
        if entry is None:
            self._arp[ip] = {'mac': mac, 'last': now, 'history': [mac]}
        elif entry['mac'] != mac:
            previous, prev_last = entry['mac'], entry['last']
            history = entry['history']
            flapping = mac in history[:-1]
            entry.update(mac=mac, last=now)
            history.append(mac)
            del history[:-6]
            failover = is_failover_mac(mac) or is_failover_mac(previous)
            recent = now - prev_last <= 600
            if not failover and ip not in self._gateways() and (recent or flapping):
                both_random = is_randomized_mac(mac) and is_randomized_mac(previous)
                severity = 'CRITICAL' if flapping else ('MEDIUM' if both_random else 'HIGH')
                findings.append(self._finding(
                    'ARP-SPOOF', severity, 'ARP Spoofing Detected',
                    f"IP {ip} changed MAC address",
                    {'ip_address': ip, 'previous_mac': previous, 'new_mac': mac,
                     'previous_vendor': vendor_for_mac(previous),
                     'new_vendor': vendor_for_mac(mac),
                     'seconds_since_previous_claim': round(now - prev_last, 1),
                     'flapping': flapping,
                     'arp_operation': {1: 'request', 2: 'reply'}.get(pkt.arp_op, 'unknown'),
                     'description': ('ARP spoofing is a man-in-the-middle attack where '
                                     'an attacker sends fake ARP messages to associate '
                                     'their MAC address with a legitimate IP, allowing '
                                     'traffic interception.'
                                     + (' The address is switching back and forth between '
                                        'MACs, which is two hosts fighting over it.'
                                        if flapping else '')
                                     + (' Both MACs are randomised, which can also be one '
                                        'phone or laptop changing its private address.'
                                        if both_random else '')),
                     'recommendation': 'Verify your gateway MAC address. Someone on your '
                                       'local network may be intercepting traffic.'},
                    'MITM'))
        else:
            entry['last'] = now

        # One MAC claiming many IPs.
        claims = self._mac_ips.setdefault(mac, {})
        claims[ip] = now
        if len(claims) > self.arp_max_ips_per_mac:
            for stale in [a for a, t in claims.items() if now - t > 600]:
                del claims[stale]
            if len(claims) > self.arp_max_ips_per_mac and not is_failover_mac(mac):
                findings.append(self._finding(
                    'ARP-MAC-MULTI-IP', 'HIGH', 'One MAC Claiming Many IP Addresses',
                    f"{mac} claimed {len(claims)} IP addresses in 10 minutes",
                    {'mac': mac, 'vendor': vendor_for_mac(mac),
                     'ip_addresses': sorted(claims)[:20], 'count': len(claims),
                     'description': ('Poisoning a whole subnet means claiming every '
                                     'victim\'s address at the gateway. A Wi-Fi range '
                                     'extender in MAC-translation mode also does this, '
                                     'legitimately.'),
                     'recommendation': 'If this MAC is not a range extender or router you '
                                       'own, find it on your network.'},
                    'MITM', key=f"ARP-MAC-MULTI-IP:{mac}", hold=1800))

        if len(self._arp) > 4096:
            for k in list(self._arp)[:2048]:
                del self._arp[k]
        if len(self._mac_ips) > 4096:
            for k in list(self._mac_ips)[:2048]:
                del self._mac_ips[k]
        if len(self._garp) > 1024:
            for k in list(self._garp)[:512]:
                del self._garp[k]
        return findings

    def _check_gateway(self, ip, mac, now):
        pins = self.state['gateway_macs']
        pin = pins.get(ip)
        if pin is None:
            # Pinned on first sight, and kept across restarts (offline analysis
            # keeps it only for the file being read).
            with self._lock:
                pins[ip] = {'mac': mac, 'pinned_at': now, 'last_seen': now}
                self._dirty = True
            self._gw_heard[ip] = now
            return []
        if pin['mac'] == mac:
            self._gw_heard[ip] = now
            if now - pin.get('last_seen', 0) > 3600:
                pin['last_seen'] = now
                self._dirty = True
            return []
        if is_failover_mac(mac) or is_failover_mac(pin['mac']):
            return []
        # The router really was replaced: the pinned MAC has not been heard for a
        # whole day of this run while another answers. Re-pin, and say so once at
        # a lower level. Counted from this run's start, so a restart after a long
        # break does not hand the pin to whoever answers first.
        if now - self._gw_heard.get(ip, self._started) > 86400:
            with self._lock:
                old = pin['mac']
                pins[ip] = {'mac': mac, 'pinned_at': now, 'last_seen': now}
                self._dirty = True
            self._gw_heard[ip] = now
            return [self._finding(
                'ARP-GATEWAY-CHANGED', 'MEDIUM', 'Gateway MAC Address Changed',
                f"Gateway {ip} now answers from {mac} (was {old}, not seen for a day)",
                {'gateway_ip': ip, 'previous_mac': old, 'new_mac': mac,
                 'new_vendor': vendor_for_mac(mac),
                 'description': 'The router was probably replaced. The new MAC is now '
                                'the one expected.',
                 'recommendation': 'If you did not change your router, check what owns '
                                   'this MAC.'},
                'MITM')]
        return [self._finding(
            'ARP-SPOOF', 'CRITICAL', 'Gateway Impersonation (ARP Spoofing)',
            f"Gateway {ip} claimed by {mac}; it has always been {pin['mac']}",
            {'ip_address': ip, 'gateway': True, 'expected_mac': pin['mac'],
             'previous_mac': pin['mac'], 'new_mac': mac,
             'expected_vendor': vendor_for_mac(pin['mac']), 'new_vendor': vendor_for_mac(mac),
             'pinned_since': time.strftime('%Y-%m-%d %H:%M', time.localtime(pin['pinned_at'])),
             'description': ('Another device is answering for your gateway. Traffic to '
                             'the internet from hosts that believe it passes through '
                             'that device first.'),
             'recommendation': 'Treat this network as hostile until the device with '
                               'this MAC is found. Check the gateway\'s real MAC on '
                               'its label or admin page.'},
            'MITM', key=f"ARP-SPOOF-GW:{ip}:{mac}")]

    # ─── DHCP, router advertisements, DHCPv6 ──────────────────────────────

    def _known(self, configured, learned_key):
        return set(configured) | set(self.state[learned_key])

    def _learn(self, learned_key, value):
        with self._lock:
            if value not in self.state[learned_key]:
                self.state[learned_key].append(value)
                del self.state[learned_key][:-32]
                self._dirty = True

    def _observe_dhcp(self, pkt, now):
        self.stats['dhcp_server_messages'] += 1
        msg_type, server_id = _dhcp_fields(pkt._raw_payload)
        if msg_type not in (None, 2, 5, 6):        # OFFER, ACK, NAK
            return []
        server = server_id or pkt.src_ip
        configured = list(getattr(self.net_env, 'dhcp_servers', None) or [])
        known = self._known(configured, 'dhcp_servers')
        if not configured:
            known |= set(self._gateways())
        if server in known or pkt.src_ip in known:
            return []
        if not configured and (self.in_baseline(now) or not self.state['dhcp_servers']):
            if not self.offline:
                self._learn('dhcp_servers', server)
            return []
        name = {2: 'OFFER', 5: 'ACK', 6: 'NAK'}.get(msg_type, 'server message')
        return [self._finding(
            'ROGUE-DHCP', 'HIGH', 'Unknown DHCP Server',
            f"DHCP {name} from {server}, which is not a known DHCP server",
            {'dhcp_server': server, 'source_ip': pkt.src_ip, 'source_mac': pkt.src_mac,
             'vendor': vendor_for_mac(pkt.src_mac), 'message': name,
             'known_servers': sorted(known)[:10],
             'description': ('Whoever answers DHCP tells clients which gateway and DNS '
                             'server to use. A second server, by mistake or on purpose, '
                             'redirects every client that listens to it.'),
             'recommendation': 'Find the device at this address. A travel router, a '
                               'misconfigured access point or an attack tool are the '
                               'usual causes.'},
            'MITM', key=f"ROGUE-DHCP:{server}", hold=3600)]

    def _observe_router_advert(self, pkt, now):
        self.stats['router_adverts'] += 1
        ident = _norm_mac(pkt.src_mac) or pkt.src_ip
        known = set(self.state['routers'])
        pinned = {p['mac'] for p in self.state['gateway_macs'].values()}
        if ident in known or ident in pinned or pkt.src_ip in known:
            return []
        if self.in_baseline(now) or not known:
            if not self.offline:
                self._learn('routers', ident)
            return []
        return [self._finding(
            'ROGUE-RA', 'HIGH', 'Unknown IPv6 Router Advertisement',
            f"{pkt.src_ip} ({pkt.src_mac or 'unknown MAC'}) is advertising itself as an "
            f"IPv6 router",
            {'router_ip': pkt.src_ip, 'router_mac': pkt.src_mac,
             'vendor': vendor_for_mac(pkt.src_mac), 'known_routers': sorted(known)[:10],
             'description': ('Hosts accept IPv6 router advertisements by default, even on '
                             'IPv4-only networks, so an unknown router can take over '
                             'their IPv6 routing and DNS.'),
             'recommendation': 'Identify the device. If IPv6 is not used here, consider '
                               'RA Guard on the switch.'},
            'MITM', key=f"ROGUE-RA:{ident}", hold=3600)]

    def _observe_dhcpv6(self, pkt, now):
        payload = pkt._raw_payload or b''
        msg_type = payload[0] if payload else None
        if msg_type not in (None, 2, 7):           # ADVERTISE, REPLY
            return []
        ident = _norm_mac(pkt.src_mac) or pkt.src_ip
        known = set(self.state['dhcpv6_servers'])
        if ident in known or pkt.src_ip in known:
            return []
        if self.in_baseline(now) or not known:
            if not self.offline:
                self._learn('dhcpv6_servers', ident)
            return []
        return [self._finding(
            'ROGUE-DHCPV6', 'HIGH', 'Unknown DHCPv6 Server',
            f"DHCPv6 {'REPLY' if msg_type == 7 else 'ADVERTISE'} from {pkt.src_ip}, "
            f"not a known DHCPv6 server",
            {'server_ip': pkt.src_ip, 'server_mac': pkt.src_mac,
             'vendor': vendor_for_mac(pkt.src_mac), 'known_servers': sorted(known)[:10],
             'description': ('Windows asks for DHCPv6 even on IPv4 networks, and an '
                             'answer can set its DNS server. That is how mitm6 takes '
                             'over name resolution.'),
             'recommendation': 'Identify the device answering. Disable IPv6 on hosts '
                               'that do not need it, or filter DHCPv6 at the switch.'},
            'MITM', key=f"ROGUE-DHCPV6:{ident}", hold=3600)]

    # ─── Name poisoning ─────────────────────────────────────────────────────

    def _observe_name_response(self, pkt, now):
        protocol = {5355: 'LLMNR', 5353: 'mDNS', 137: 'NBT-NS'}[pkt.src_port]
        parsed = parse_dns_wire(pkt._raw_payload, netbios=(protocol == 'NBT-NS'))
        if not parsed or not parsed[0] or not parsed[1]:
            return []
        self.stats['name_responses'] += 1
        # One identity per host: its MAC when the frame has one, so the answers it
        # sends over IPv4 and over IPv6 are one responder, not two.
        responder = _norm_mac(pkt.src_mac) or pkt.src_ip
        entry = self._responders.get(responder)
        if entry is None:
            entry = self._responders[responder] = {'names': {}, 'ips': set(), 'protocols': set()}
            while len(self._responders) > 1024:
                self._responders.popitem(last=False)
        entry['ips'].add(pkt.src_ip)
        entry['protocols'].add(protocol)
        for name, _address in parsed[1]:
            short = _short_name(name)
            if not short:
                continue
            entry['names'][short] = now
            owners = self._name_owners.setdefault(short, set())
            owners.add(responder)
        for stale in [n for n, t in entry['names'].items() if now - t > 600]:
            del entry['names'][stale]
        if len(self._name_owners) > 8192:
            self._name_owners.clear()

        names = entry['names']
        if len(names) < 4:
            return []
        conflicts = {n: sorted(self._name_owners.get(n, ()))[:5] for n in names
                     if len(self._name_owners.get(n, ())) > 1}
        return [self._finding(
            'NAME-POISONING', 'HIGH', 'Name Poisoning (Responder Pattern)',
            f"{responder} answered {protocol} lookups for {len(names)} different names",
            {'responder': responder, 'responder_ips': sorted(entry['ips'])[:5],
             'protocols': sorted(entry['protocols']),
             'names_answered': sorted(names)[:20],
             'names_also_answered_by_others': conflicts,
             'vendor': vendor_for_mac(responder) if ':' in responder and
             len(responder) == 17 else '',
             'description': ('A host normally answers name lookups only for its own name. '
                             'Answering for many is what Responder and similar tools do, '
                             'to collect the password hashes clients then send. (An Apple '
                             'Bonjour sleep proxy answers for sleeping Macs, and can '
                             'look similar.)'),
             'recommendation': 'Find this host. Disable LLMNR and NetBIOS over TCP/IP '
                               'by group policy where they are not needed.'},
            'MITM', key=f"NAME-POISONING:{responder}", hold=1800)]

    # ─── Lateral movement ───────────────────────────────────────────────────

    def _observe_lateral(self, pkt, now):
        if not (_is_lan(pkt.src_ip) and _is_lan(pkt.dst_ip)):
            return []
        if pkt.flags and not ('S' in pkt.flags and 'A' not in pkt.flags):
            return []          # count connection attempts, not every segment
        targets = self._fanout.setdefault(pkt.src_ip, {})
        targets[pkt.dst_ip] = (now, pkt.dst_port)
        for stale in [d for d, (t, _) in targets.items() if now - t > 300]:
            del targets[stale]
        if len(self._fanout) > 4096:
            for k in list(self._fanout)[:2048]:
                del self._fanout[k]
        if len(targets) < self.lateral_threshold:
            return []
        ports = sorted({p for _, p in targets.values()})
        return [self._finding(
            'LATERAL-MOVEMENT', 'HIGH', 'Possible Lateral Movement',
            f"{pkt.src_ip} connected to {len(targets)} LAN hosts over "
            f"{', '.join(LATERAL_PORTS[p] for p in ports)} in 5 minutes",
            {'source_ip': pkt.src_ip, 'targets': sorted(targets)[:25],
             'target_count': len(targets), 'ports': ports, 'window_seconds': 300,
             'description': ('Reaching many machines over SMB, RDP, WinRM or RPC in a short '
                             'time is how ransomware and intruders spread. Backup servers, '
                             'management tools and network scanners also do it.'),
             'recommendation': 'If this host is not a server or admin tool that is '
                               'expected to do this, isolate it and check it.'},
            'Lateral Movement', key=f"LATERAL-MOVEMENT:{pkt.src_ip}", hold=1800)]

    # ─── Uploads ────────────────────────────────────────────────────────────

    def _observe_upload(self, pkt, now):
        src = pkt.src_ip
        state = self._uploads.get(src)
        if state is None:
            if len(self._uploads) >= 1024:
                del self._uploads[next(iter(self._uploads))]
            state = self._uploads[src] = {'start': now, 'bytes': 0.0, 'windows': 0,
                                          'mean': 0.0, 'var': 0.0, 'alerted': False,
                                          'dests': {}}
        elapsed = now - state['start']
        if elapsed >= UPLOAD_WINDOW_SEC:
            # Close the window, plus any idle ones since: a host idle for an hour
            # has an hour of zero windows, which belong in its baseline.
            closed = min(int(elapsed // UPLOAD_WINDOW_SEC), 288)
            for i in range(closed):
                self._update_baseline(state, state['bytes'] if i == 0 else 0.0)
            state['start'] += closed * UPLOAD_WINDOW_SEC
            if now - state['start'] >= UPLOAD_WINDOW_SEC:
                state['start'] = now
            state['bytes'] = 0.0
            state['alerted'] = False
            state['dests'] = {}
        weight = max(1, int(getattr(pkt, 'sample_weight', 1) or 1))
        size = pkt.payload_size * weight
        state['bytes'] += size
        dests = state['dests']
        if pkt.dst_ip in dests or len(dests) < 64:
            dests[pkt.dst_ip] = dests.get(pkt.dst_ip, 0) + size

        if state['alerted'] or state['windows'] < UPLOAD_MIN_WINDOWS:
            return []
        mb = state['bytes'] / (1024 * 1024)
        mean_mb = state['mean'] / (1024 * 1024)
        std_mb = (state['var'] ** 0.5) / (1024 * 1024)
        limit = max(self.upload_floor_mb, mean_mb + 4 * std_mb, mean_mb * 4)
        if mb <= limit:
            return []
        state['alerted'] = True
        top = sorted(dests.items(), key=lambda kv: kv[1], reverse=True)[:5]
        return [self._finding(
            'UPLOAD-SPIKE', 'MEDIUM', 'Unusual Upload Volume',
            f"{src} sent {mb:.0f} MB to the internet in {UPLOAD_WINDOW_SEC // 60} minutes "
            f"(normally about {mean_mb:.1f} MB)",
            {'source_ip': src, 'megabytes_this_window': round(mb, 1),
             'window_seconds': UPLOAD_WINDOW_SEC,
             'baseline_mean_mb': round(mean_mb, 2), 'baseline_std_mb': round(std_mb, 2),
             'baseline_windows': state['windows'], 'threshold_mb': round(limit, 1),
             'top_destinations': [{'ip': ip, 'mb': round(b / (1024 * 1024), 1)} for ip, b in top],
             'sampling_compensated': weight > 1,
             'description': ('This host is uploading far more than its own normal. Cloud '
                             'backups, video calls and large shares do this; so does data '
                             'theft.'),
             'recommendation': 'Check which process is sending, and to where.'},
            'Exfiltration', key=f"UPLOAD-SPIKE:{src}", hold=UPLOAD_WINDOW_SEC)]

    @staticmethod
    def _update_baseline(state, value):
        if state['windows'] == 0:
            state['mean'], state['var'] = value, 0.0
        else:
            diff = value - state['mean']
            state['mean'] += UPLOAD_ALPHA * diff
            state['var'] = (1 - UPLOAD_ALPHA) * (state['var'] + UPLOAD_ALPHA * diff * diff)
        state['windows'] += 1

    # ─── New devices ────────────────────────────────────────────────────────

    def _observe_device(self, pkt, now):
        if pkt.protocol == 'ARP':
            mac, ip = _norm_mac(pkt.arp_hwsrc or pkt.src_mac), pkt.src_ip
        else:
            mac, ip = _norm_mac(pkt.src_mac), pkt.src_ip
        if not _usable_mac(mac) or not _is_lan(ip) or ip == '0.0.0.0':
            return []
        known = self.state['known_macs']
        if mac in known:
            return []
        with self._lock:
            known[mac] = now
            self._dirty = True
        if is_randomized_mac(mac) or self.in_baseline(now):
            # Randomised MACs are per-network and may rotate: alerting on each
            # would report the same phone again and again.
            return []
        if ip in (getattr(self.net_env, 'local_ips', None) or ()):
            return []
        self.stats['new_devices'] += 1
        vendor = vendor_for_mac(mac)
        return [self._finding(
            'NEW-DEVICE', 'LOW', 'New Device on the Network',
            f"First sighting of {mac}{' (' + vendor + ')' if vendor else ''} at {ip}",
            {'mac': mac, 'ip_address': ip, 'vendor': vendor or 'unknown',
             'first_seen': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now)),
             'description': 'A device this network has not seen before, after the '
                            'learning period.',
             'recommendation': 'If you do not recognise it, find it on your router\'s '
                               'client list.'},
            'Inventory', key=f"NEW-DEVICE:{mac}")]

    # ─── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _finding(rule_id, severity, title, description, evidence, category,
                 key=None, hold=None):
        return {'rule_id': rule_id, 'severity': severity, 'title': title,
                'description': description, 'evidence': evidence,
                'category': category, 'cooldown_key': key, 'hold_sec': hold}

    def get_stats(self):
        return dict(self.stats,
                    gateway_pins=dict((ip, p['mac']) for ip, p in
                                      self.state['gateway_macs'].items()),
                    known_devices=len(self.state['known_macs']),
                    in_baseline=self.in_baseline(time.time()))


LATERAL_PORTS = {445: 'SMB', 3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM/TLS', 135: 'RPC'}

UPLOAD_WINDOW_SEC = 300
UPLOAD_MIN_WINDOWS = 12          # an hour of history before judging
UPLOAD_ALPHA = 0.1


def _dhcp_fields(payload):
    """(message type, server identifier) from a BOOTP/DHCP payload, if present."""
    if not payload or len(payload) < 240 or payload[236:240] != b'\x63\x82\x53\x63':
        return None, None
    msg_type = server = None
    pos = 240
    while pos < len(payload):
        code = payload[pos]
        if code == 255:
            break
        if code == 0:
            pos += 1
            continue
        if pos + 1 >= len(payload):
            break
        length = payload[pos + 1]
        value = payload[pos + 2:pos + 2 + length]
        if code == 53 and length == 1 and value:
            msg_type = value[0]
        elif code == 54 and length == 4 and len(value) == 4:
            server = str(ipaddress.IPv4Address(value))
        pos += 2 + length
    return msg_type, server
