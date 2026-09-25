"""
Events and findings.
====================
One event type, several sources. A live capture, a pcap replay and a UniFi flow
export describe the same things in different vocabularies; normalising them here
means a rule written once works against all three, and against whatever source
gets added next.

An `Event` carries the fields every source can supply as attributes, and
anything source- or protocol-specific in `fields`. `get()` reads either, so a
rule refers to `src_ip` and `sni` the same way without caring which is which.

Enrichment
----------
`enrich()` resolves everything the profile knows — names, roles, zones, whether
the flow is expected, whether a BACnet write is allowed — and writes the answers
onto the event before any rule sees it. Two reasons:

    Rules stay declarative. A rule is field comparisons and nothing else, so it
    can live in YAML and be edited by whoever runs the site rather than by
    whoever wrote the engine.

    Profile lookups happen once per event instead of once per rule. With thirty
    rules that is the difference between one subnet walk and thirty.

Findings
--------
A rule that matches produces a `Finding`. Findings deduplicate on
(rule, device, key) within a window, because the alternative is 1,017 NAT-PMP
alerts from one laptop in an afternoon — an observed number, not a hypothetical.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field

__all__ = ['Event', 'Finding', 'Severity', 'Tier', 'enrich', 'Deduplicator']


class Severity:
    """Ordered so rules can compare, and named so YAML can spell them."""
    INFO = 'info'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

    ORDER = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}

    @classmethod
    def rank(cls, value):
        return cls.ORDER.get(str(value).lower(), 0)

    @classmethod
    def normalise(cls, value):
        text = str(value).lower().strip()
        return text if text in cls.ORDER else cls.MEDIUM


class Tier:
    """
    How a finding is delivered. The site's own vocabulary, kept deliberately.

    PUSH is an immediate notification; DIGEST goes into the daily report. A rule
    may have different tiers depending on where it fired — the same remote-access
    tool is a push on a building VLAN and a digest entry on the staff network.
    """
    PUSH = 'push'
    DIGEST = 'digest'
    WEEKLY = 'weekly'


@dataclass
class Event:
    """
    One observation, from any source.

    Only `kind` and `ts` are required. A UniFi flow row fills in the byte and
    packet counts and leaves the protocol detail empty; a parsed BACnet packet
    does the reverse. Rules cope by testing for what they need.
    """

    kind: str                      # flow, dns, tls, bacnet, dhcp, arp, device...
    ts: float = 0.0

    src_ip: str = ''
    dst_ip: str = ''
    src_mac: str = ''
    dst_mac: str = ''
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = ''             # tcp, udp, icmp...
    vlan: int | None = None

    # Byte and packet counts are named by direction relative to the source,
    # because "sent" and "received" are ambiguous enough that one widely used
    # export gets them the other way round from what the labels suggest.
    bytes_to_dst: int = 0
    bytes_to_src: int = 0
    packets: int = 0

    source: str = ''               # which importer produced this
    fields: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.ts:
            self.ts = time.time()

    def get(self, name, default=None):
        """Read an attribute or a kind-specific field, attributes winning."""
        if hasattr(self, name):
            value = getattr(self, name)
            if value not in (None, '', 0) or name in _ZERO_IS_MEANINGFUL:
                return value
            return self.fields.get(name, value)
        return self.fields.get(name, default)

    def set(self, name, value):
        if hasattr(self, name):
            setattr(self, name, value)
        else:
            self.fields[name] = value

    def as_dict(self):
        data = {k: v for k, v in self.__dict__.items() if k != 'fields'}
        data.update(self.fields)
        return data

    # ─── Convenience used by several rules ───────────────────────────────

    @property
    def total_bytes(self):
        return (self.bytes_to_dst or 0) + (self.bytes_to_src or 0)

    def endpoint_pair(self):
        return (self.src_ip, self.dst_ip)


#: Fields where 0 is a real answer rather than "unset", so `get` must not fall
#: through to `fields` and find a stale value.
_ZERO_IS_MEANINGFUL = frozenset({'bytes_to_dst', 'bytes_to_src', 'packets',
                                 'src_port', 'dst_port', 'vlan', 'ts'})


@dataclass
class Finding:
    """What a rule produces. Advisory: nothing in this system acts on one."""

    rule_id: str
    title: str
    severity: str = Severity.MEDIUM
    tier: str = Tier.DIGEST
    description: str = ''
    ts: float = 0.0
    device: str = ''               # the device the finding is about
    key: str = ''                  # what makes this instance distinct
    next_check: str = ''           # a command to run, written by the rule
    event: Event | None = None
    count: int = 1
    evidence: dict = field(default_factory=dict)

    def __post_init__(self):
        self.severity = Severity.normalise(self.severity)
        if not self.ts:
            self.ts = self.event.ts if self.event else time.time()

    def dedup_key(self):
        return (self.rule_id, self.device, self.key)

    def as_dict(self, include_event=False):
        data = {
            'rule_id': self.rule_id, 'title': self.title,
            'severity': self.severity, 'tier': self.tier,
            'description': self.description, 'ts': self.ts,
            'device': self.device, 'key': self.key,
            'next_check': self.next_check, 'count': self.count,
            'evidence': dict(self.evidence),
        }
        if include_event and self.event is not None:
            data['event'] = self.event.as_dict()
        return data


# ─── Enrichment ──────────────────────────────────────────────────────────────

def _is_link_local(ip):
    """169.254/16 or fe80::/10 — an address handed out by nothing."""
    try:
        return ipaddress.ip_address(ip).is_link_local
    except ValueError:
        return False


#: Address space that is inside a site, or is not an address of anywhere.
#:
#: Written out rather than using `is_private`, which answers a different
#: question. `is_private` is true for the documentation ranges (192.0.2.0/24,
#: 198.51.100.0/24, 203.0.113.0/24) — a device talking to one of those is
#: talking off-site by any useful definition — and false for carrier NAT
#: (100.64/10), which is not the internet at all. Both answers are wrong for
#: "did this leave the building", which is the only question asked of it here.
_SITE_LOCAL = tuple(ipaddress.ip_network(cidr) for cidr in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',      # RFC 1918
    '100.64.0.0/10',                                       # carrier NAT
    '127.0.0.0/8', '169.254.0.0/16', '0.0.0.0/8',
    '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
    'fc00::/7', 'fe80::/10', '::1/128', '::/128', 'ff00::/8',
))


def _is_public(ip):
    """Whether this address is outside the site."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(address in network for network in _SITE_LOCAL
                   if network.version == address.version)


def enrich(event, profile, now=None):
    """
    Resolve everything the profile knows and write it onto the event.

    Called once per event, before any rule runs. Rules then read `src_role` and
    `flow_expected` as plain fields, which is what lets them live in YAML.

    Returns the same event, mutated, so it can be used in a comprehension.
    """
    src = profile.identify(mac=event.src_mac, ip=event.src_ip)
    dst = profile.identify(mac=event.dst_mac, ip=event.dst_ip)

    event.fields.setdefault('src_name', src.name)
    event.fields.setdefault('dst_name', dst.name)
    event.fields['src_role'] = src.role
    event.fields['dst_role'] = dst.role
    event.fields['src_known'] = src.mac in profile.devices
    event.fields['dst_known'] = dst.mac in profile.devices

    src_vlan = profile.vlan_for_ip(event.src_ip)
    dst_vlan = profile.vlan_for_ip(event.dst_ip)
    event.fields['src_vlan'] = src_vlan.id if src_vlan else None
    event.fields['dst_vlan'] = dst_vlan.id if dst_vlan else None
    event.fields['src_zone'] = src_vlan.zone if src_vlan else ''
    event.fields['dst_zone'] = dst_vlan.zone if dst_vlan else ''

    # The tag actually on the wire, kept before the fallback below overwrites
    # it — an address that disagrees with the tag it arrived under is the whole
    # point of the bad_address rule, and inferring the tag from the address
    # would make that check always pass.
    observed = event.vlan
    event.fields['observed_vlan'] = observed
    tagged_vlan = profile.vlans.get(int(observed)) if observed is not None else None
    event.fields['address_matches_vlan'] = (
        tagged_vlan.contains(event.src_ip)
        if tagged_vlan is not None and tagged_vlan.subnet and event.src_ip
        else True)
    event.fields['link_local'] = any(
        _is_link_local(ip) for ip in (event.src_ip, event.dst_ip) if ip)

    gateways = {v.gateway for v in profile.vlans.values() if v.gateway}
    event.fields['src_is_gateway'] = event.src_ip in gateways
    event.fields['dst_is_gateway'] = event.dst_ip in gateways

    if event.vlan is None and src_vlan is not None:
        event.vlan = src_vlan.id

    # Direction, from the site's point of view rather than the packet's.
    src_public, dst_public = _is_public(event.src_ip), _is_public(event.dst_ip)
    if dst_public and not src_public:
        event.fields['direction'] = 'outbound'
    elif src_public and not dst_public:
        event.fields['direction'] = 'inbound'
    elif src_public and dst_public:
        event.fields['direction'] = 'transit'
    else:
        event.fields['direction'] = 'internal'
    event.fields['internet'] = dst_public or src_public

    crosses = (event.fields['src_vlan'] is not None
               and event.fields['dst_vlan'] is not None
               and event.fields['src_vlan'] != event.fields['dst_vlan'])
    event.fields['cross_vlan'] = crosses
    event.fields['flow_expected'] = profile.is_expected_flow(
        event.src_ip, event.dst_ip, event.dst_port, event.protocol)

    event.fields['bacnet_write_allowed'] = profile.bacnet_write_allowed(
        event.src_ip, event.dst_ip, event.fields.get('object'))
    event.fields['muted_reference'] = profile.is_known_dead_reference(
        event.src_ip, event.dst_ip, event.protocol)

    # `store_payload: false` is a prohibition, so it is resolved here and any
    # payload already attached is dropped rather than left for a rule to
    # remember not to read.
    event.fields['may_store_payload'] = (
        profile.may_store_payload(event.fields['src_vlan'])
        and profile.may_store_payload(event.fields['dst_vlan'])
        and profile.may_store_payload(event.vlan))
    if not event.fields['may_store_payload']:
        event.fields.pop('payload', None)

    hour = time.localtime(event.ts).tm_hour if now is None else now
    event.fields['hour'] = hour
    event.fields['quiet_hours'] = profile.in_quiet_hours(hour)

    sensor_macs = getattr(profile, 'sensor_macs', set())
    event.fields['is_sensor_mac'] = bool(sensor_macs) and event.src_mac in sensor_macs

    watched = _matched_watched_name(event, profile.watched_names)
    event.fields['watched_name'] = watched

    # A separate list, because these are two different things that both happen
    # to be called names. `watched_names` are destinations nobody should be
    # reaching — remote-access relays, file drops. `poisonable_names` are local
    # names that must only ever be answered by the host that owns them: WPAD, a
    # decommissioned server, a typo that half the site still asks for. Conflating
    # them means the poisoning rule silently never fires, because a site's list
    # of bad destinations never contains its own hostnames.
    event.fields['poisonable_name'] = _matched_name(
        str(event.fields.get('query') or event.fields.get('name') or ''),
        getattr(profile, 'poisonable_names', ()))
    event.fields['approved_remote_access'] = _is_approved_remote_access(
        event, getattr(profile, 'remote_access_allowed', ()))
    return event


def _is_approved_remote_access(event, approved):
    """
    Whether this destination is sanctioned remote-access tooling.

    Matched on the domain rather than the address, because these services
    change relay IPs constantly — that is how they get through firewalls — so an
    address allowlist would be stale within the week.
    """
    if not approved:
        return False
    haystack = ' '.join(str(event.fields.get(key, ''))
                        for key in ('sni', 'query', 'domain', 'url',
                                    'server_name')).lower()
    if not haystack.strip():
        return False
    for entry in approved:
        for domain in (entry.get('domains') or []):
            if domain and str(domain).lower() in haystack:
                return True
    return False


def _matched_watched_name(event, watched_names):
    """The first watched destination appearing in any name-bearing field."""
    haystack = ' '.join(str(event.fields.get(key, ''))
                        for key in ('sni', 'query', 'domain', 'hostname',
                                    'url', 'server_name'))
    return _matched_name(haystack, watched_names)


def _matched_name(haystack, names):
    """The first of `names` appearing in `haystack`, case-insensitively."""
    if not names or not haystack:
        return ''
    lowered = haystack.lower()
    for name in names:
        if name and str(name).lower() in lowered:
            return str(name).lower()
    return ''


# ─── Deduplication ───────────────────────────────────────────────────────────

class Deduplicator:
    """
    Collapse repeats of the same finding within a window.

    One laptop produced 1,017 NAT-PMP requests in an afternoon at the site this
    was written for. Without this, that is 1,017 notifications and the monitor
    gets muted, which is the only failure mode that matters.

    Repeats are counted, not discarded: the finding that is eventually delivered
    says how many there were.
    """

    def __init__(self, window_sec=3600, clock=time.time):
        self.window_sec = window_sec
        self._clock = clock
        self._seen = {}            # key -> [first_ts, last_ts, count, finding]
        self._snoozed = {}         # key -> until_ts

    def admit(self, finding):
        """
        Return the finding if it should be delivered now, else None.

        The first occurrence in a window goes out immediately; later ones update
        its count so the digest can report the true number.
        """
        key = finding.dedup_key()
        now = self._clock()

        until = self._snoozed.get(key)
        if until is not None:
            if now < until:
                return None
            del self._snoozed[key]

        entry = self._seen.get(key)
        if entry is None or now - entry[0] > self.window_sec:
            self._seen[key] = [now, now, 1, finding]
            return finding

        entry[1] = now
        entry[2] += 1
        entry[3].count = entry[2]
        return None

    def snooze(self, rule_id, device='', key='', seconds=86400):
        """Silence one finding identity — acknowledged, or under maintenance."""
        self._snoozed[(rule_id, device, key)] = self._clock() + seconds

    def suppressed_counts(self):
        """What was collapsed, for the digest."""
        return {key: entry[2] for key, entry in self._seen.items() if entry[2] > 1}

    def reset(self):
        self._seen.clear()
        self._snoozed.clear()
