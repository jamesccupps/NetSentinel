"""
Active subnet audit
===================
Everything else in NetSentinel is passive. The audit will be the one exception,
an opt-in scan of the owner's own networks, so before any of it exists this
module settles the part that matters most: which networks it may touch.

A network qualifies only if it is RFC 1918, IPv4 link-local or IPv6 ULA, no
larger than a /16, not loopback, and overlaps an interface of this computer that
is up (read here with psutil, not from net_detect). Its network and broadcast
addresses, and those of any local subnet it overlaps, are never probed.
"""

import ipaddress
import logging
import re
import socket

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a hard dependency of the app
    psutil = None

logger = logging.getLogger("NetSentinel.Audit")

__all__ = ['AuditError', 'ScopeError', 'local_networks', 'validate_network',
           'validate_networks', 'parse_ports']

# A /16. Past this a sweep stops being an audit of "my network" and starts being
# a survey; for IPv6 it means nothing shorter than a /112.
MAX_ADDRESSES = 65536
# A typo in a port list must not turn into tens of thousands of probes per host.
MAX_PORTS = 1024

_ALLOWED_RANGES = (
    (ipaddress.ip_network('10.0.0.0/8'), 'rfc1918'),
    (ipaddress.ip_network('172.16.0.0/12'), 'rfc1918'),
    (ipaddress.ip_network('192.168.0.0/16'), 'rfc1918'),
    (ipaddress.ip_network('169.254.0.0/16'), 'link-local'),
    (ipaddress.ip_network('fc00::/7'), 'ula'),
)
_LOOPBACK = (ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('::1/128'))
_V6_LINK_LOCAL = ipaddress.ip_network('fe80::/10')


# ─── Errors ──────────────────────────────────────────────────────────────────
class AuditError(Exception):
    """Base class for an audit that cannot start."""


class ScopeError(AuditError, ValueError):
    """A network, address or port list the audit refuses to touch."""

    def __init__(self, message, reason='invalid'):
        super().__init__(message)
        self.reason = reason


# ─── Interfaces and scope ────────────────────────────────────────────────────
def _v6_prefix(mask):
    # Windows reports no IPv6 netmask at all. /64 is what nearly every IPv6 LAN uses,
    # and the size limit refuses anything that big anyway, so the guess only decides
    # whether a small ULA range sits on this interface.
    if not mask:
        return 64
    try:
        return int(mask)
    except (TypeError, ValueError):
        pass
    try:
        return bin(int(ipaddress.IPv6Address(str(mask).split('/')[0]))).count('1')
    except ValueError:
        return 64


def _interface_addresses():
    """[(interface name, ipaddress interface)] for every interface that is up."""
    if psutil is None:
        return []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception as exc:
        logger.warning("Could not list network interfaces: %s", exc)
        return []
    out = []
    for name, entries in addrs.items():
        st = stats.get(name)
        # A down adapter keeps its APIPA address; scanning "its" network would send
        # packets out of whatever interface is up instead.
        if st is not None and not st.isup:
            continue
        for entry in entries:
            if entry.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            addr = str(entry.address).split('%')[0]
            try:
                if entry.family == socket.AF_INET6:
                    iface = ipaddress.ip_interface(f'{addr}/{_v6_prefix(entry.netmask)}')
                elif entry.netmask:
                    iface = ipaddress.ip_interface(f'{addr}/{entry.netmask}')
                else:
                    iface = ipaddress.ip_interface(f'{addr}/32')
            except ValueError:
                continue
            out.append((name, iface))
    return out


def _normalise_interfaces(entries):
    out = []
    for entry in entries:
        name, iface = entry[0], entry[1]
        if not isinstance(iface, (ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
            iface = ipaddress.ip_interface(str(iface))
        out.append((str(name), iface))
    return out


def _range_kind(net):
    for allowed, kind in _ALLOWED_RANGES:
        if net.version == allowed.version and net.subnet_of(allowed):
            return kind
    return None


def validate_network(text, interfaces=None):
    """
    Return the ipaddress network for `text`, or raise ScopeError saying why not.

    Host bits are allowed and dropped ("192.168.1.7/24" is 192.168.1.0/24), and a
    bare address is a /32. `interfaces` is for tests; normally this machine's own
    interfaces are read with psutil.
    """
    if isinstance(text, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        net = text
    else:
        raw = str(text if text is not None else '').strip()
        if not raw:
            raise ScopeError('No network given.', 'invalid')
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ScopeError(f'"{raw[:60]}" is not a network; use CIDR, like 192.168.1.0/24.',
                             'invalid') from None
    if any(net.version == lb.version and net.subnet_of(lb) for lb in _LOOPBACK):
        raise ScopeError(f'{net} is loopback; the audit only scans real networks.', 'loopback')
    if net.version == 6 and net.subnet_of(_V6_LINK_LOCAL):
        # Connecting to fe80:: needs an interface scope, which Windows does not
        # report; audit the IPv4 network on that interface instead.
        raise ScopeError(f'{net} is IPv6 link-local, which the audit does not scan; '
                         'audit the IPv4 network on that interface instead.', 'link-local-v6')
    kind = _range_kind(net)
    if kind is None:
        raise ScopeError(f'{net} is not a private network (RFC 1918, IPv4 link-local or '
                         'IPv6 ULA); the audit never scans public or reserved addresses.',
                         'public')
    if net.num_addresses > MAX_ADDRESSES:
        limit = '/16' if net.version == 4 else '/112'
        raise ScopeError(f'{net} has {net.num_addresses:,} addresses; the audit scans no more '
                         f'than a {limit} ({MAX_ADDRESSES:,}) at a time.', 'too-large')
    if interfaces is None:
        interfaces = _interface_addresses()
    local = [iface for _, iface in _normalise_interfaces(interfaces)
             if iface.version == net.version and not iface.ip.is_loopback
             and iface.network.overlaps(net)]
    if not local:
        raise ScopeError(f'{net} is not on any network interface of this computer that is '
                         'up; the audit only scans local networks.', 'not-local')
    return net


def validate_networks(networks, interfaces=None):
    """Validate every network, all or nothing; overlapping choices are refused so no
    host is scanned twice in one run."""
    if isinstance(networks, (str, ipaddress.IPv4Network, ipaddress.IPv6Network)):
        networks = [networks]
    networks = list(networks or [])
    if not networks:
        raise ScopeError('Choose at least one network to audit.', 'empty')
    if interfaces is None:
        interfaces = _interface_addresses()
    nets = []
    for text in networks:
        net = validate_network(text, interfaces)
        for other in nets:
            if net.version == other.version and net.overlaps(other):
                raise ScopeError(f'{net} overlaps {other}; choose one of them.', 'overlap')
        nets.append(net)
    return nets


def _targets(net, interfaces):
    """Addresses to probe: the network without its network and broadcast addresses,
    or those of any local subnet it overlaps (a /23 chosen over a /24 interface
    would otherwise include that /24's broadcast)."""
    skip = set()
    for _, iface in interfaces:
        inet = iface.network
        if inet.version == 4 and net.version == 4 and inet.overlaps(net) and inet.prefixlen < 31:
            skip.add(inet.network_address)
            skip.add(inet.broadcast_address)
    if net.version == 4:
        # /31 point-to-point links and /32 single hosts have no network or broadcast
        # address; spelled out because hosts() on these changed between versions.
        hosts = net.hosts() if net.prefixlen < 31 else iter(net)
    else:
        hosts = net.hosts() if net.prefixlen < 127 else iter(net)
    return [a for a in hosts if a not in skip]


_VIRTUAL_RE = re.compile(
    r'vethernet|wsl|hyper-v|virtualbox|vmware|vmnet|docker|^br-|^veth|virbr|tailscale|'
    r'zerotier|wireguard|openvpn|tap-|loopback', re.I)


def local_networks(interfaces=None):
    """
    The private networks of this computer's interfaces that the audit can scan: the
    choices to offer the owner. Each is a dict with network, interface, address,
    kind (rfc1918, link-local, ula), addresses (how many get probed), virtual (a
    Hyper-V, WSL, VPN or container adapter) and narrowed_from (set when the
    interface's own network is larger than a /16 and its /24 is offered instead).
    """
    if interfaces is None:
        interfaces = _interface_addresses()
    interfaces = _normalise_interfaces(interfaces)
    seen = {}
    for name, iface in interfaces:
        if iface.ip.is_loopback:
            continue
        net, narrowed = iface.network, None
        if net.num_addresses > MAX_ADDRESSES and net.version == 4:
            narrowed = str(net)
            net = ipaddress.ip_network(f'{iface.ip}/24', strict=False)
        if (net.version == 4 and net.prefixlen >= 32) or (net.version == 6 and net.prefixlen >= 128):
            continue  # a point-to-point address: nothing to audit but itself
        try:
            validate_network(net, interfaces)
        except ScopeError:
            continue
        key = str(net)
        if key in seen:
            seen[key]['interface'] += f', {name}'
            continue
        seen[key] = {
            'network': key,
            'interface': name,
            'address': str(iface.ip),
            'kind': _range_kind(net),
            'addresses': len(_targets(net, interfaces)),
            'virtual': bool(_VIRTUAL_RE.search(name)),
            'narrowed_from': narrowed,
        }
    return sorted(seen.values(), key=lambda n: (n['virtual'], ipaddress.ip_network(n['network'])))


def parse_ports(spec):
    """'22,80,8000-8010' -> sorted unique ports. Raises ScopeError for bad input."""
    if isinstance(spec, (list, tuple, set, frozenset)):
        items = [str(p) for p in spec]
    else:
        items = [p for p in re.split(r'[\s,]+', str(spec or '').strip()) if p]
    ports = set()
    for item in items:
        lo, sep, hi = item.partition('-')
        try:
            lo_n = int(lo)
            hi_n = int(hi) if sep else lo_n
        except ValueError:
            raise ScopeError(f'"{item[:20]}" is not a port or a range like 8000-8010.',
                             'ports') from None
        if not (1 <= lo_n <= 65535 and 1 <= hi_n <= 65535) or hi_n < lo_n:
            raise ScopeError(f'"{item[:20]}" is outside 1-65535.', 'ports')
        if hi_n - lo_n + 1 + len(ports) > MAX_PORTS:
            raise ScopeError(f'More than {MAX_PORTS} ports; an audit is for top ports, '
                             'not a full sweep.', 'ports')
        ports.update(range(lo_n, hi_n + 1))
    if not ports:
        raise ScopeError('No ports given.', 'ports')
    return sorted(ports)
