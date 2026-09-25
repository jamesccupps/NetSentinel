"""
Site profile.
=============
Everything site-specific lives here, in YAML, and nowhere else. No IP, MAC, VLAN
number or device name belongs in the code — a rule says "traffic into the
management zone from a device whose role is not `security_viewer`", and the
profile decides what that means for one building.

That separation is what makes the same tool useful at a second site: point it at
a different profile and the rules still mean something.

What a profile holds
--------------------
    site        name, timezone, quiet hours
    vlans       id -> name, subnet, zone, whether payload may be stored
    devices     MAC -> name, role, expected addresses
    roles       role -> what that kind of device is allowed to do
    flows       cross-VLAN traffic that is expected (anything else is notable)
    allowlists  BACnet writes, approved remote-access tools
    muted       known-broken things, so they stop producing alerts until fixed

Keep your real profile out of version control. It is a map of your network:
VLANs, device inventory, which systems are unencrypted, what is exposed. That is
the document an attacker would most like to have. `profiles/example-site.yaml`
is a fictional site showing the schema; put yours somewhere else and pass its
path.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field

import yaml

logger = logging.getLogger("netmon.profile")

__all__ = ['SiteProfile', 'Device', 'Vlan', 'ProfileError', 'load_profile']

_MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')


class ProfileError(ValueError):
    """The profile is malformed. Raised with a message naming the offending key."""


def normalise_mac(value):
    """Lowercase colon-separated form, accepting the usual separators."""
    if value is None or value == '':
        return ''
    if isinstance(value, int):
        value = _mac_from_yaml_int(value)
    cleaned = re.sub(r'[^0-9a-fA-F]', '', str(value)).lower()
    if len(cleaned) != 12:
        return str(value).strip().lower()
    return ':'.join(cleaned[i:i + 2] for i in range(0, 12, 2))


def _mac_from_yaml_int(value):
    """
    Undo YAML 1.1's sexagesimal integer parsing of an unquoted MAC.

    `10:11:22:33:44:55` is, to a YAML 1.1 parser, a base-60 number, so PyYAML
    hands back 7923433495 and the device silently vanishes from the profile.
    `aa:bb:...` is safe (letters) and so is anything starting `00:` (the resolver
    wants a non-zero first digit), which is why this bites only some sites and
    looks like magic when it does.

    Exactly one text shape can be misparsed: a leading group of 10-99 followed by
    five groups of 00-59, because the resolver is `[1-9][0-9_]*(:[0-5]?[0-9])+`
    and a MAC octet is always two characters. Anything outside that range was
    never a MAC, so it is returned unchanged for the validator to reject by name
    rather than quietly reconstructed into a plausible-looking address.
    """
    if not isinstance(value, int) or value <= 0:
        return str(value)
    groups = []
    remaining = value
    for _ in range(5):
        groups.append(remaining % 60)
        remaining //= 60
    if not 10 <= remaining <= 99:
        return str(value)
    groups.append(remaining)
    return ':'.join(f'{g:02d}' for g in reversed(groups))


@dataclass
class Vlan:
    id: int
    name: str = ''
    subnet: str = ''
    zone: str = ''
    gateway: str = ''
    # When false, no payload from this VLAN may be written to disk or sent
    # anywhere. Used for segments carrying regulated data.
    store_payload: bool = True
    notes: str = ''

    def contains(self, ip):
        if not self.subnet or not ip:
            return False
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(self.subnet, strict=False)
        except ValueError:
            return False


@dataclass
class Device:
    mac: str
    name: str = ''
    role: str = 'unknown'
    ips: list = field(default_factory=list)
    vlan: int | None = None
    switch_port: str = ''
    notes: str = ''

    def __post_init__(self):
        self.mac = normalise_mac(self.mac)
        self.ips = [str(i) for i in (self.ips or [])]


@dataclass
class Role:
    name: str
    description: str = ''
    # Internet destinations this kind of device is expected to reach. Empty means
    # "no expectation recorded", which is not the same as "nothing allowed" — the
    # rule decides how to treat that.
    allowed_domains: list = field(default_factory=list)
    allowed_asns: list = field(default_factory=list)
    internet_expected: bool = True
    remote_access_expected: bool = False


@dataclass
class ExpectedFlow:
    """One cross-VLAN conversation the site knows about and accepts."""
    src: str = ''            # IP, CIDR, role name, or '*'
    dst: str = ''
    ports: list = field(default_factory=list)
    protocol: str = ''
    note: str = ''

    def matches(self, src_ip, dst_ip, port=None, protocol='', resolver=None):
        if not _endpoint_matches(self.src, src_ip, resolver):
            return False
        if not _endpoint_matches(self.dst, dst_ip, resolver):
            return False
        if self.ports and port is not None and int(port) not in [int(p) for p in self.ports]:
            return False
        if self.protocol and protocol and self.protocol.lower() != protocol.lower():
            return False
        return True


def _endpoint_matches(spec, ip, resolver=None):
    """An endpoint spec is '*', an IP, a CIDR, or a role name."""
    if not spec or spec == '*':
        return True
    if not ip:
        return False
    spec = str(spec)
    if spec == ip:
        return True
    if '/' in spec:
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(spec, strict=False)
        except ValueError:
            return False
    if resolver is not None:
        device = resolver(ip)
        if device is not None and device.role == spec:
            return True
    return False


class SiteProfile:
    """Loaded, validated site profile with lookup helpers."""

    def __init__(self, data=None, path=''):
        data = data or {}
        self.path = path
        self.raw = data

        site = data.get('site') or {}
        self.name = site.get('name', 'unnamed site')
        self.timezone = site.get('timezone', 'UTC')
        self.quiet_hours = tuple(site.get('quiet_hours', (22, 6)))

        self.vlans = {}
        for vid, spec in (data.get('vlans') or {}).items():
            spec = spec or {}
            try:
                vid_int = int(vid)
            except (TypeError, ValueError):
                raise ProfileError(f"vlans: '{vid}' is not a VLAN id")
            self.vlans[vid_int] = Vlan(
                id=vid_int, name=spec.get('name', ''), subnet=spec.get('subnet', ''),
                zone=spec.get('zone', ''), gateway=spec.get('gateway', ''),
                store_payload=bool(spec.get('store_payload', True)),
                notes=spec.get('notes', ''))

        self.roles = {}
        for rname, spec in (data.get('roles') or {}).items():
            spec = spec or {}
            self.roles[rname] = Role(
                name=rname, description=spec.get('description', ''),
                allowed_domains=list(spec.get('allowed_domains', [])),
                allowed_asns=list(spec.get('allowed_asns', [])),
                internet_expected=bool(spec.get('internet_expected', True)),
                remote_access_expected=bool(spec.get('remote_access_expected', False)))

        self.devices = {}
        self._by_ip = {}
        for mac, spec in (data.get('devices') or {}).items():
            spec = spec or {}
            if isinstance(mac, int):
                logger.warning(
                    "devices: %r was read as a number, not a MAC address — YAML "
                    "treats it as base-60. Recovered as %s; quote it in the "
                    "profile to be safe.", mac, normalise_mac(mac))
            device = Device(mac=mac, name=spec.get('name', ''),
                            role=spec.get('role', 'unknown'),
                            ips=spec.get('ips', []), vlan=spec.get('vlan'),
                            switch_port=spec.get('switch_port', ''),
                            notes=spec.get('notes', ''))
            if device.role != 'unknown' and device.role not in self.roles:
                logger.warning("device %s has role %r which is not defined under roles",
                               device.name or device.mac, device.role)
            self.devices[device.mac] = device
            for ip in device.ips:
                self._by_ip.setdefault(ip, device)

        self.expected_flows = [
            ExpectedFlow(src=f.get('src', ''), dst=f.get('dst', ''),
                         ports=list(f.get('ports', [])),
                         protocol=f.get('protocol', ''), note=f.get('note', ''))
            for f in (data.get('expected_flows') or [])
        ]

        self.bacnet_write_allowlist = list(data.get('bacnet_write_allowlist') or [])
        self.known_dead_references = list(data.get('known_dead_references') or [])
        self.remote_access_allowed = list(data.get('remote_access_allowed') or [])
        self.watched_names = [n.lower() for n in (data.get('watched_names') or [])]

        # Local names that must only ever be answered by their owner. Different
        # from watched_names, which are destinations nobody should reach. WPAD
        # is the canonical example: nothing owns it, so whoever answers first
        # becomes everyone's proxy.
        self.poisonable_names = [n.lower()
                                 for n in (data.get('poisonable_names') or [])]

        # The monitor's own capture interfaces. They are supposed to be silent:
        # no address, no protocol bindings. If one ever transmits, the monitor
        # has started polluting the segment it is meant to be observing, and
        # every baseline it has built is contaminated.
        self.sensor_macs = {normalise_mac(m)
                            for m in (data.get('sensor_macs') or []) if m}

        self.metadata_only_vlans = {
            int(v) for v in (data.get('metadata_only_vlans') or [])
        } | {v.id for v in self.vlans.values() if not v.store_payload}

        self.validate()

    # ─── Lookup ──────────────────────────────────────────────────────────

    def device_for_mac(self, mac):
        return self.devices.get(normalise_mac(mac))

    def device_for_ip(self, ip):
        return self._by_ip.get(ip)

    def identify(self, mac=None, ip=None):
        """Best available identity. Never returns None — callers always get a label."""
        device = self.device_for_mac(mac) if mac else None
        if device is None and ip:
            device = self.device_for_ip(ip)
        if device is not None:
            return device
        return Device(mac=normalise_mac(mac) if mac else '',
                      name=ip or normalise_mac(mac) or 'unknown',
                      role='unknown', ips=[ip] if ip else [])

    def vlan_for_ip(self, ip):
        for vlan in self.vlans.values():
            if vlan.contains(ip):
                return vlan
        return None

    def role_of(self, mac=None, ip=None):
        return self.identify(mac=mac, ip=ip).role

    def may_store_payload(self, vlan_id):
        """False for segments whose payload must never be written or transmitted."""
        if vlan_id is None:
            return True
        return int(vlan_id) not in self.metadata_only_vlans

    def is_expected_flow(self, src_ip, dst_ip, port=None, protocol=''):
        return any(f.matches(src_ip, dst_ip, port, protocol, resolver=self.device_for_ip)
                   for f in self.expected_flows)

    def is_known_dead_reference(self, src_ip, target_ip, protocol=''):
        """Muted until remediated — a broken reference already on the fix list."""
        for entry in self.known_dead_references:
            targets = entry.get('target')
            targets = [targets] if isinstance(targets, str) else list(targets or [])
            if target_ip not in targets:
                continue
            if entry.get('src_any'):
                return True
            src = entry.get('src')
            srcs = [src] if isinstance(src, str) else list(src or [])
            if srcs and src_ip not in srcs:
                continue
            proto = entry.get('proto', '')
            if proto and protocol and proto.lower() not in protocol.lower():
                continue
            return True
        return False

    def bacnet_write_allowed(self, src_ip, dst_ip, obj=None):
        for entry in self.bacnet_write_allowlist:
            if entry.get('src') and entry['src'] != src_ip:
                continue
            dsts = entry.get('dst')
            dsts = [dsts] if isinstance(dsts, str) else list(dsts or [])
            if dsts and dst_ip not in dsts:
                continue
            objects = entry.get('objects')
            if objects:
                # The entry authorises specific objects. A message that names
                # none cannot be checked against that scope, so it is not
                # covered — otherwise an exception written for one setpoint
                # would authorise every unparsed write from that source.
                if obj is None or obj not in objects:
                    continue
            return True
        return False

    def in_quiet_hours(self, hour):
        start, end = self.quiet_hours
        if start == end:
            return False
        if start < end:
            return start <= hour < end
        return hour >= start or hour < end     # window wraps midnight

    # ─── Validation ──────────────────────────────────────────────────────

    def validate(self):
        """Raise ProfileError on anything that would make rules behave oddly."""
        problems = []

        for mac in self.devices:
            if not _MAC_RE.match(mac):
                problems.append(f"devices: '{mac}' is not a MAC address")

        for mac in self.sensor_macs:
            if not _MAC_RE.match(mac):
                problems.append(f"sensor_macs: '{mac}' is not a MAC address")

        for vlan in self.vlans.values():
            if vlan.subnet:
                try:
                    ipaddress.ip_network(vlan.subnet, strict=False)
                except ValueError:
                    problems.append(
                        f"vlans.{vlan.id}.subnet: '{vlan.subnet}' is not a network")

        seen_ips = {}
        for device in self.devices.values():
            for ip in device.ips:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    problems.append(
                        f"devices.{device.mac}.ips: '{ip}' is not an address")
                    continue
                if ip in seen_ips and seen_ips[ip] != device.mac:
                    # Worth surfacing rather than silently picking one: it is
                    # either a profile mistake or a genuine address collision.
                    problems.append(
                        f"address {ip} is claimed by both {seen_ips[ip]} and {device.mac}")
                seen_ips[ip] = device.mac

        start, end = self.quiet_hours
        if not (0 <= int(start) <= 23 and 0 <= int(end) <= 23):
            problems.append(f"site.quiet_hours: {self.quiet_hours} outside 0-23")

        if problems:
            raise ProfileError("; ".join(problems))
        return True

    # ─── Reporting ───────────────────────────────────────────────────────

    def summary(self):
        by_role = {}
        for device in self.devices.values():
            by_role[device.role] = by_role.get(device.role, 0) + 1
        return {
            'site': self.name,
            'vlans': len(self.vlans),
            'devices': len(self.devices),
            'roles': len(self.roles),
            'devices_by_role': dict(sorted(by_role.items())),
            'expected_flows': len(self.expected_flows),
            'metadata_only_vlans': sorted(self.metadata_only_vlans),
            'muted_references': len(self.known_dead_references),
            'watched_names': len(self.watched_names),
            'poisonable_names': len(self.poisonable_names),
            'sensor_macs': len(self.sensor_macs),
        }


def load_profile(path):
    """Load and validate a profile from disk."""
    if not os.path.exists(path):
        raise ProfileError(f"profile not found: {path}")
    with open(path, encoding='utf-8') as f:
        try:
            data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ProfileError(f"{path}: {e}") from e
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ProfileError(f"{path}: top level must be a mapping")
    return SiteProfile(data, path=path)


def _main(argv=None):
    """`python -m netmon.profile <path>` — validate a profile and describe it."""
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog='python -m netmon.profile',
        description='Validate a site profile and print what it contains.')
    parser.add_argument('path', help='path to the profile YAML')
    parser.add_argument('--json', action='store_true',
                        help='machine-readable summary')
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
    try:
        profile = load_profile(args.path)
    except ProfileError as e:
        print(f'invalid: {e}')
        return 1

    summary = profile.summary()
    if args.json:
        print(json.dumps(summary, indent=2))
        return 0

    print(f"{summary['site']}  ({args.path})")
    print(f"  {summary['vlans']} VLANs, {summary['devices']} devices, "
          f"{summary['roles']} roles")
    for role, count in summary['devices_by_role'].items():
        print(f"    {count:>3}  {role}")
    print(f"  {summary['expected_flows']} expected flows, "
          f"{summary['muted_references']} muted references, "
          f"{summary['watched_names']} watched names")
    restricted = summary['metadata_only_vlans']
    if restricted:
        names = ', '.join(
            f"{v} ({profile.vlans[v].name})" if v in profile.vlans else str(v)
            for v in restricted)
        print(f"  metadata only, no payload stored: {names}")
    else:
        print("  no VLAN is marked metadata-only — intended?")
    print('valid')
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(_main())
