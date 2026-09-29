"""
Identifying the systems on a site network.
===========================================
A finding that says "TCP 7000" is one nobody acts on. A finding that says
"Otis elevator control" is one someone can take to the lift contractor.

This maps what is on the wire to what it is: port numbers, frame magic and, for
three protocols, enough parsing to name the operation. It is identification, not
dissection — the goal is a label an operator recognises.

Everything here is a default. A site puts its own additions in the profile under
`services:`, because the next building will run a different lift.

The kiosk parser is metadata only
---------------------------------
Parking kiosks broadcast UTF-16 XML that contains cardholder and credential
data. The parser reads the command name and nothing else — not by filtering the
fields afterwards, but by never walking past the one element it wants. Its test
fixture is synthetic and its values are invented, because a real one is exactly
the file that must not be in a repository.
"""

from __future__ import annotations

import re

__all__ = ['identify', 'SERVICES', 'parse_kiosk_command', 'parse_p2',
           'parse_otis', 'parse_eset_user_agent', 'Service']


class Service:
    """One recognisable system: how to spot it, and what to call it."""

    __slots__ = ('name', 'description', 'ports', 'protocol', 'magic',
                 'names', 'category', 'encrypted')

    def __init__(self, name, description='', ports=(), protocol='',
                 magic=None, names=(), category='', encrypted=False):
        self.name = name
        self.description = description
        self.ports = frozenset(ports)
        self.protocol = protocol
        self.magic = magic                 # bytes the payload starts with
        self.names = tuple(n.lower() for n in names)
        self.category = category
        self.encrypted = encrypted

    def __repr__(self):
        return f'<Service {self.name}>'


#: The systems the site survey catalogued, plus the ones any building has.
#:
#: `encrypted` records whether the protocol protects itself. It is not a
#: judgement — BACnet has no encryption by design and is not going to grow any —
#: but it decides whether "this crossed a segment boundary" is interesting or
#: alarming.
SERVICES = [
    # ─── Building automation ─────────────────────────────────────────────
    Service('bacnet', 'BACnet/IP building automation', ports=range(47808, 47824),
            protocol='udp', category='building-automation'),
    Service('siemens-p2', 'Siemens P2 building automation',
            ports=(5033, 5034), protocol='tcp', category='building-automation'),

    # ─── Access control and life safety ──────────────────────────────────
    Service('gallagher', 'Gallagher access control (controller to command centre)',
            ports=(1072,), protocol='tcp', category='access-control',
            encrypted=True),
    Service('otis', 'Otis elevator control', ports=(7000,), protocol='tcp',
            magic=b'\xa5\x5a', category='elevator'),

    # ─── Video ───────────────────────────────────────────────────────────
    Service('exacq', 'Exacq video', ports=(22609,), protocol='tcp',
            category='video'),
    Service('unifi-protect', 'UniFi Protect camera to console',
            ports=(7444, 7552, 6666), protocol='tcp', category='video'),
    Service('rtsp', 'RTSP video stream', ports=(554, 8554), protocol='tcp',
            category='video'),

    # ─── Payment ─────────────────────────────────────────────────────────
    Service('parking-kiosk', 'Parking kiosk broadcast', ports=(31769,),
            protocol='udp', category='payment'),

    # ─── Infrastructure ──────────────────────────────────────────────────
    Service('unifi-discovery', 'UniFi device discovery', ports=(10001,),
            protocol='udp', category='network'),
    Service('unifi-syslog', 'UniFi device logging to the gateway', ports=(5514,),
            protocol='udp', category='network'),
    Service('weatherflow', 'WeatherFlow weather station broadcast',
            ports=(50222,), protocol='udp', category='sensor'),
    Service('sentinel-licensing', 'Sentinel licence manager broadcast',
            ports=(1947,), category='licensing'),

    # ─── Remote access and tunnels ───────────────────────────────────────
    Service('anydesk', 'AnyDesk remote access',
            names=('net.anydesk.com',), category='remote-access', encrypted=True),
    Service('teamviewer', 'TeamViewer remote access',
            names=('teamviewer.com',), category='remote-access', encrypted=True),
    Service('screenconnect', 'ScreenConnect remote access',
            names=('screenconnect.com',), category='remote-access', encrypted=True),
    Service('splashtop', 'Splashtop remote access',
            names=('splashtop.com',), category='remote-access', encrypted=True),
    Service('rustdesk', 'RustDesk remote access',
            names=('rustdesk.com',), category='remote-access', encrypted=True),
    Service('chrome-remote-desktop', 'Chrome Remote Desktop',
            names=('remotedesktop-pa.googleapis.com',),
            category='remote-access', encrypted=True),
    Service('tailscale', 'Tailscale mesh VPN', ports=(41641, 3478),
            protocol='udp', names=('tailscale.com', '100.100.100.100'),
            category='vpn', encrypted=True),
    Service('wireguard', 'WireGuard VPN', ports=(51820,), protocol='udp',
            category='vpn', encrypted=True),
    Service('openvpn', 'OpenVPN', ports=(1194,), category='vpn', encrypted=True),

    # ─── Software that phones home ───────────────────────────────────────
    Service('eset', 'ESET endpoint protection', ports=(8883,),
            names=('update.eset.com', 'eset.com'), category='endpoint'),

    # ─── Cleartext services worth naming ─────────────────────────────────
    Service('telnet', 'Telnet', ports=(23,), protocol='tcp', category='cleartext'),
    Service('ftp', 'FTP', ports=(21,), protocol='tcp', category='cleartext'),
    Service('snmp', 'SNMP', ports=(161, 162), protocol='udp',
            category='cleartext'),
    Service('sip', 'SIP telephony', ports=(5060,), category='cleartext'),
    Service('modbus', 'Modbus/TCP', ports=(502,), protocol='tcp',
            category='building-automation'),
]

_BY_PORT = {}
for _service in SERVICES:
    for _port in _service.ports:
        _BY_PORT.setdefault((_service.protocol, _port), _service)
        if not _service.protocol:
            _BY_PORT.setdefault(('tcp', _port), _service)
            _BY_PORT.setdefault(('udp', _port), _service)


def identify(src_port=None, dst_port=None, protocol='', payload=b'', name='',
             extra_services=()):
    """
    Name the system this traffic belongs to, or None.

    Checked in order of how much the answer is worth: a magic number is proof,
    a hostname is strong, a port is a guess that is usually right. A site's own
    additions from the profile are checked first, because they know their
    building better than this list does.
    """
    services = list(extra_services) + SERVICES
    protocol = (protocol or '').lower()
    ports = [p for p in (dst_port, src_port) if p]

    if payload:
        for service in services:
            if service.magic and payload.startswith(service.magic):
                return service

    if name:
        lowered = str(name).lower()
        for service in services:
            if any(candidate in lowered for candidate in service.names):
                return service

    for port in ports:
        for service in services:
            if port in service.ports and (not service.protocol
                                          or service.protocol == protocol):
                return service
    return None


# ─── Parking kiosks: metadata only ───────────────────────────────────────────

#: The command element, and nothing else. Deliberately not an XML parse: a
#: parser walks the whole document, and every other element in these messages
#: may hold cardholder or credential data. This reads one element by name and
#: never sees the rest.
_KIOSK_COMMAND = re.compile(rb'<\s*Command\s*>\s*([A-Za-z0-9_.-]{1,64})\s*<',
                            re.IGNORECASE)
_KIOSK_TYPE = re.compile(rb'xsi:type\s*=\s*["\']([A-Za-z0-9_.-]{1,64})["\']',
                         re.IGNORECASE)


def parse_kiosk_command(payload):
    """
    The command name from a parking-kiosk broadcast, and nothing else.

    These messages are UTF-16 XML carrying cardholder and credential data. The
    command name is operationally useful — it says what the kiosk is doing — and
    nothing else in the message is anyone's business here.

    The restriction is structural, not a filter applied afterwards: this matches
    two named elements by regular expression and never walks the document, so
    there is no path by which another field could be read. Returns a dict with
    at most `command` and `message_type`, or None.
    """
    if not payload:
        return None

    # UTF-16 with a BOM, UTF-16 without one, or UTF-8. Decoding is avoided —
    # the patterns run against both the raw bytes and a NUL-stripped copy, which
    # covers UTF-16LE without needing to know the encoding or handle a partial
    # code unit at a snap-length boundary.
    candidates = [payload]
    if b'\x00' in payload[:64]:
        candidates.append(payload.replace(b'\x00', b''))

    for data in candidates:
        command = _KIOSK_COMMAND.search(data)
        kind = _KIOSK_TYPE.search(data)
        if command or kind:
            out = {}
            if command:
                out['command'] = command.group(1).decode('ascii', 'replace')
            if kind:
                out['message_type'] = kind.group(1).decode('ascii', 'replace')
            return out
    return None


# ─── Siemens P2 ──────────────────────────────────────────────────────────────

#: Node names in a P2 roster, advertised as `NAME|PORT`. Bounded so a crafted
#: packet cannot produce an enormous name, and restricted to the characters a
#: hostname uses so it cannot smuggle control characters into an alert.
_P2_NODE = re.compile(rb'([A-Za-z0-9][A-Za-z0-9._-]{0,62})\|(\d{1,5})')


def parse_p2(payload, src_port=None, dst_port=None):
    """
    What a Siemens P2 session is advertising.

    The useful fact is the roster: which node names are announcing themselves,
    and on which port. A name that was not there last week is a new panel, or
    something pretending to be one.

    Port 5034 runs panels to the supervisory server; 5033 runs both directions.
    """
    ports = {p for p in (src_port, dst_port) if p}
    if not ports & {5033, 5034}:
        return None

    out = {'p2_direction': 'panel-to-server' if 5034 in ports else 'bidirectional'}
    nodes = []
    for match in _P2_NODE.finditer(payload or b''):
        name = match.group(1).decode('ascii', 'replace')
        port = int(match.group(2))
        if 0 < port <= 65535 and (name, port) not in nodes:
            nodes.append((name, port))
        if len(nodes) >= 16:
            break
    if nodes:
        out['p2_nodes'] = [f'{name}|{port}' for name, port in nodes]
    return out


# ─── Otis ────────────────────────────────────────────────────────────────────

def parse_otis(payload):
    """
    An Otis elevator frame, identified by its `a5 5a` header.

    Only the header and length are read. The rest is a vendor protocol with no
    public specification, and guessing at its fields would produce findings
    nobody could verify — which is worse than none.
    """
    if not payload or len(payload) < 4 or not payload.startswith(b'\xa5\x5a'):
        return None
    return {'otis_frame': True,
            'otis_type': f'0x{payload[2]:02x}',
            'otis_length': len(payload)}


# ─── ESET ────────────────────────────────────────────────────────────────────

#: The OS build out of an ESET update User-Agent, which is how an unsupported
#: Windows build becomes visible without touching the endpoint.
_ESET_OS = re.compile(r'OS:\s*(\d+\.\d+\.(\d+))(?:\s+UBR\s+(\d+))?', re.I)


def parse_eset_user_agent(user_agent):
    """
    The Windows build an endpoint reports to its own update service.

    Useful because it is the only place on the wire that says which build a
    machine is running, and an out-of-support build is a finding nobody can see
    from the network any other way.
    """
    if not user_agent:
        return None
    found = _ESET_OS.search(str(user_agent))
    if not found:
        return None
    out = {'os_version': found.group(1), 'os_build': int(found.group(2))}
    if found.group(3):
        out['os_ubr'] = int(found.group(3))
    return out
