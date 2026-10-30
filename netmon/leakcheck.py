"""
Restricted segments, on the wire and on disk.
=============================================
The capture filter keeps metadata-only segments off the disk; this checks that
it did, and finds the traffic a tag-based filter cannot see.

Two questions, asked of every frame read:

**Is a restricted segment on disk?** The rolling capture is written under a
filter that excludes the metadata-only VLANs by tag and their subnets by
address. A frame from one of them in a rotated file means that filter is not
the one running, or this capture stack does not honour it — and that payload
the site said must never be stored is sitting in the ring buffer. That is the
`restricted_capture_leak` finding, critical, and it is raised for files from
the rolling capture (the service, `analyze --from-ring`) and for an extract
that had to leave such frames out.

**Is restricted traffic outside its VLAN?** A door controller's address seen
untagged (the trunk's native VLAN is the restricted one), under another VLAN's
tag (a port in the wrong VLAN), or inside a QinQ frame, is reachable by any
filter that tests the outer tag and nothing else. That is
`restricted_outside_vlan`, raised wherever it is seen. A router's relayed copy
is routing, not a mistake, so frames to or from a listed router are left out;
and where no routers are listed, only frames carrying the restricted device's
own MAC are judged, because without the router's MAC the two cannot be told
apart.

A sample taken for `netmon bpf --verify` is unfiltered on purpose, so its
restricted frames are expected: `analyze --pcap` reads them as metadata only,
says how many there were, and reports only the outside-its-VLAN finding.

Frames are read as bytes, not through Scapy's dissection: Scapy files an
802.1ad frame's inner tag as the first Dot1Q layer and does not dissect 0x9100
at all, so asking it for "the VLAN" gives the wrong one for exactly the frames
this exists to catch.
"""

from __future__ import annotations

import ipaddress

from netmon.events import Finding, Severity, Tier

__all__ = ['frame_layout', 'Restricted', 'LeakCounter', 'extraction_finding',
           'STACK_TPIDS']

#: 802.1Q, 802.1ad (QinQ's service tag), and the pre-standard 0x9100.
STACK_TPIDS = (0x8100, 0x88a8, 0x9100)


def frame_layout(raw):
    """
    The tags and addresses of an Ethernet frame, from its bytes.

    {'tpids': [...], 'tags': [...], 'src_mac', 'dst_mac', 'src_ip', 'dst_ip'}
    with the addresses '' when the frame carries no IP header.
    """
    data = bytes(raw or b'')
    out = {'tpids': [], 'tags': [], 'src_mac': '', 'dst_mac': '',
           'src_ip': '', 'dst_ip': ''}
    if len(data) < 14:
        return out
    out['dst_mac'] = ':'.join(f'{b:02x}' for b in data[0:6])
    out['src_mac'] = ':'.join(f'{b:02x}' for b in data[6:12])
    offset = 12
    ethertype = int.from_bytes(data[12:14], 'big')
    while ethertype in STACK_TPIDS and offset + 6 <= len(data) \
            and len(out['tags']) < 4:
        out['tpids'].append(ethertype)
        out['tags'].append(int.from_bytes(data[offset + 2:offset + 4], 'big') & 0x0fff)
        offset += 4
        ethertype = int.from_bytes(data[offset:offset + 2], 'big')
    header = offset + 2
    try:
        if ethertype == 0x0800 and len(data) >= header + 20:
            out['src_ip'] = str(ipaddress.IPv4Address(data[header + 12:header + 16]))
            out['dst_ip'] = str(ipaddress.IPv4Address(data[header + 16:header + 20]))
        elif ethertype == 0x86dd and len(data) >= header + 40:
            out['src_ip'] = str(ipaddress.IPv6Address(data[header + 8:header + 24]))
            out['dst_ip'] = str(ipaddress.IPv6Address(data[header + 24:header + 40]))
    except ipaddress.AddressValueError:
        pass
    return out


class Restricted:
    """What identifies the profile's metadata-only segments on the wire."""

    def __init__(self, profile):
        self.profile = profile
        self.vlans = set(getattr(profile, 'metadata_only_vlans', set()) or set())
        vlans = getattr(profile, 'vlans', {}) or {}
        self.networks = []
        for vlan in vlans.values():
            if vlan.id in self.vlans and vlan.subnet:
                try:
                    self.networks.append(
                        (ipaddress.ip_network(vlan.subnet, strict=False), vlan))
                except ValueError:
                    continue
        self.router_macs = set(getattr(profile, 'router_macs', set()) or set())
        devices = getattr(profile, 'devices', {}) or {}
        self.device_macs = {mac for mac, device in devices.items()
                            if device.vlan is not None and int(device.vlan) in self.vlans}

    def __bool__(self):
        return bool(self.vlans)

    def segment_of(self, ip):
        """The restricted VLAN an address belongs to, or None."""
        if not ip:
            return None
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for network, vlan in self.networks:
            if network.version == address.version and address in network:
                return vlan
        return None

    def is_restricted(self, layout):
        """Whether a frame belongs to a restricted segment by any measure."""
        return (any(tag in self.vlans for tag in layout['tags'])
                or self.segment_of(layout['src_ip']) is not None
                or self.segment_of(layout['dst_ip']) is not None)

    def outside(self, layout):
        """
        Restricted addresses in this frame that are not where they belong:
        [(address, vlan, how)] where how is 'untagged', 'tag N' or 'qinq'.
        """
        found = []
        tags = layout['tags']
        stacked = len(tags) > 1 or any(t != 0x8100 for t in layout['tpids'])
        for side in ('src', 'dst'):
            ip = layout[f'{side}_ip']
            vlan = self.segment_of(ip)
            if vlan is None:
                continue
            mac = layout[f'{side}_mac']
            if mac in self.router_macs:
                continue                           # the router's relayed copy
            if not self.router_macs and mac not in self.device_macs:
                continue                           # cannot tell routing apart
            if stacked:
                found.append((ip, vlan, 'qinq'))
            elif not tags:
                found.append((ip, vlan, 'untagged'))
            elif tags[0] != vlan.id:
                found.append((ip, vlan, f'tag {tags[0]}'))
        if stacked and any(t in self.vlans for t in tags) and not found:
            # A restricted tag inside a stacked frame: any filter reading only
            # the outer tag lets it through, whatever its addresses.
            vlan_id = next(t for t in tags if t in self.vlans)
            vlan = (getattr(self.profile, 'vlans', {}) or {}).get(vlan_id)
            if vlan is not None:
                found.append((layout['src_ip'] or layout['src_mac'], vlan, 'qinq'))
        return found


class LeakCounter:
    """
    Counts restricted frames while a capture is read, and turns them into
    findings at the end.

    `on_disk` says the file came from the rolling capture, where any
    restricted frame at all is a leak.
    """

    #: Distinct out-of-place addresses kept per file; the count goes on.
    max_addresses = 64

    def __init__(self, profile, on_disk=False, source=''):
        self.restricted = Restricted(profile)
        self.on_disk = bool(on_disk)
        self.source = source
        self.frames = 0
        self.by_kind = {'tagged': 0, 'untagged': 0, 'other_tag': 0, 'qinq': 0}
        self.restricted_tags = set()
        self.outside = {}         # (address, vlan id, how) -> [count, first ts, vlan]
        self.first_ts = None

    @property
    def restricted_frames(self):
        return self.frames

    def observe(self, raw, ts=0.0, layout=None):
        if not self.restricted:
            return
        layout = layout or frame_layout(raw)
        if not self.restricted.is_restricted(layout):
            return
        self.frames += 1
        if self.first_ts is None:
            self.first_ts = float(ts or 0) or None
        tags = layout['tags']
        hit = [t for t in tags if t in self.restricted.vlans]
        if len(tags) > 1 or any(t != 0x8100 for t in layout['tpids']):
            self.by_kind['qinq'] += 1
        if hit:
            self.by_kind['tagged'] += 1
            self.restricted_tags.update(hit)
        elif not tags:
            self.by_kind['untagged'] += 1
        else:
            self.by_kind['other_tag'] += 1

        for address, vlan, how in self.restricted.outside(layout):
            key = (address, vlan.id, how)
            entry = self.outside.get(key)
            if entry is None:
                if len(self.outside) >= self.max_addresses:
                    continue
                self.outside[key] = [1, float(ts or 0), vlan]
            else:
                entry[0] += 1

    def summary(self):
        return {'restricted_frames': self.frames, 'by_kind': dict(self.by_kind),
                'restricted_tags': sorted(self.restricted_tags),
                'outside_their_vlan': len(self.outside)}

    def findings(self):
        out = []
        if self.on_disk and self.frames:
            out.append(self._leak())
        for (address, _, how), (count, ts, vlan) in sorted(
                self.outside.items(), key=lambda kv: -kv[1][0]):
            out.append(self._outside(address, vlan, how, count, ts))
        return out

    def _breakdown(self):
        parts = []
        if self.by_kind['tagged']:
            parts.append(f"{self.by_kind['tagged']} tagged VLAN "
                         + ', '.join(str(v) for v in sorted(self.restricted_tags)))
        if self.by_kind['untagged']:
            parts.append(f"{self.by_kind['untagged']} untagged")
        if self.by_kind['other_tag']:
            parts.append(f"{self.by_kind['other_tag']} under another VLAN's tag")
        if self.by_kind['qinq']:
            parts.append(f"{self.by_kind['qinq']} in stacked (QinQ) frames")
        return '; '.join(parts)

    def _leak(self):
        name = self.source or 'a capture file'
        vlans = sorted(self.restricted_tags | {
            vlan.id for (_, _, _), (_, _, vlan) in self.outside.items()})
        if not vlans:
            vlans = sorted(self.restricted.vlans)
        return Finding(
            'restricted_capture_leak',
            'Traffic from a metadata-only segment was written to disk',
            severity=Severity.CRITICAL, tier=Tier.PUSH,
            description=(f'{self.frames} frames from metadata-only segments are '
                         f'on disk in {name} ({self._breakdown()}). The capture '
                         f'filter is not keeping them out, so payload the site '
                         f'said must never be stored has been.'),
            ts=self.first_ts or 0.0, device='rolling capture', key=name,
            evidence={'count': self.frames, 'vlans': vlans, 'name': name,
                      'reason': self._breakdown()},
            next_check=('Delete the file. Compare the running tcpdump filter with '
                        'what `netmon capture --command` prints, restart the '
                        'capture unit with it, and run `netmon bpf --profile ... '
                        '--verify` on an unfiltered sample taken on this sensor.'))

    def _outside(self, address, vlan, how, count, ts):
        identify = getattr(self.restricted.profile, 'identify', None)
        device = identify(ip=address) if identify is not None and address else None
        label = device.name if device is not None and device.name != address \
            else address
        where = {'untagged': 'untagged', 'qinq': 'inside a stacked (QinQ) frame'}.get(
            how, f'tagged VLAN {how[4:]}' if how.startswith('tag ') else how)
        observed = int(how[4:]) if how.startswith('tag ') else None
        return Finding(
            'restricted_outside_vlan',
            'A metadata-only segment\'s traffic seen outside its VLAN',
            severity=Severity.HIGH, tier=Tier.PUSH,
            description=(f'{label} ({address}), on the {vlan.name or "restricted"} '
                         f'segment (VLAN {vlan.id}), was seen {where}: {count} '
                         f'frames. A capture filter that excludes VLAN {vlan.id} '
                         f'by its tag does not exclude these.'),
            ts=ts or 0.0, device=label, key=f'{address}/{how}',
            evidence={'ip': address, 'vlan': vlan.id, 'observed_vlan': observed,
                      'count': count, 'reason': where},
            next_check=('Check the switch port and the mirror: a native VLAN set '
                        'to the restricted one, a port in the wrong VLAN, or QinQ '
                        'on the mirror would each do this. If it is routed '
                        'traffic, list the router under router_macs.'))


def extraction_finding(result, profile=None):
    """The finding for an extract that had to leave restricted frames out."""
    count = int(result.get('excluded_restricted') or 0)
    if not count:
        return None
    files = ', '.join(result.get('from_files') or []) or 'the rolling capture'
    restricted = sorted(getattr(profile, 'metadata_only_vlans', set()) or set())
    return Finding(
        'restricted_capture_leak',
        'Traffic from a metadata-only segment was written to disk',
        severity=Severity.CRITICAL, tier=Tier.PUSH,
        description=(f'Extracting packets for an alert found {count} frames from '
                     f'metadata-only segments in {files}, and left them out. '
                     f'They should never have been captured.'),
        device='rolling capture', key=files,
        evidence={'count': count, 'vlans': restricted, 'name': files},
        next_check=('Delete those files. Compare the running tcpdump filter with '
                    'what `netmon capture --command` prints, and run `netmon bpf '
                    '--profile ... --verify` on an unfiltered sample.'))
