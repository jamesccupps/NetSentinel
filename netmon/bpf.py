"""
VLAN-aware BPF filter construction.
====================================
Capturing from a trunk mirror means most frames carry an 802.1Q tag, and BPF
handles tags badly enough that hand-written filters are usually wrong in ways
that fail silently — they capture less than you think and you find out later.

Every rule below is verified against tcpdump in netmon_tests/test_bpf.py using
synthetic tagged frames, because "it compiles" says nothing about what it matches.

The traps
---------
**`vlan N` shifts every offset after it.** The keyword tells BPF the next 4 bytes
are a tag, so terms written before it use unshifted offsets and terms after it
use shifted ones. A filter must therefore be written as
`<untagged form> or (vlan and <same form>)` to match both.

**`vlan 5 or vlan 6` does not do what it reads like.** The second `vlan` applies
a second offset shift on top of the first, so it tests the wrong bytes. Verified:
that filter matches a VLAN 5 frame and silently misses VLAN 6. Use one `vlan`
keyword and compare the tag field directly:

    vlan and (ether[14:2] & 0x0fff == 5 or ether[14:2] & 0x0fff == 6)

**Mixing tagged and untagged selection is where this really bites.** Both of the
obvious forms are wrong, and verified so against tcpdump:

    not vlan or (vlan and (tag == 5 or tag == 6))   -> matches ONLY untagged
    (vlan and (tag == 5 or tag == 6)) or not vlan   -> matches EVERYTHING

The second is the dangerous one. `vlan` shifts offsets for everything after it in
the expression, including across `or`, so the trailing `not vlan` ends up testing
the *encapsulated* ethertype — true for every tagged frame. A filter written to
capture two HVAC VLANs would quietly capture VLAN 12 as well, whose payload this
system is required never to store.

The builder therefore never emits the `vlan` keyword for mixed selection. It tests
the tag field explicitly on both branches, so no offset shifting happens anywhere:

    (ether[12:2] != 0x8100) or (ether[12:2] == 0x8100 and (tag == 5 or tag == 6))

**Verify on your own capture setup.** The spec this was built from reports that
`ether[12:2] != 0x8100` did not exclude tagged frames under Npcap on Windows,
where it does under libpcap on Linux. That matters because the mixed form above
has no alternative: `not vlan` cannot appear beside a tagged branch without
shifting its offsets, so the ethertype test is the only way to write "untagged or
these VLANs" in one expression.

Untagged-*only* selection has no such constraint and uses `not vlan`, which is
reported to work on both stacks.

`diagnose_untagged()` runs both forms over a sample capture and says which one
your stack honours; `verify_filter()` does the same for any candidate filter. Take
a short unfiltered capture on the machine that will run the sensor and settle it
there rather than arguing from documentation.

**MAC terms need no `vlan` keyword.** `ether host`, `ether broadcast` and friends
match tagged and untagged frames alike, because they read bytes before the tag.

**One `vlan` keyword per filter, at the end.** The shift applies to everything
after the keyword, `and` as much as `or`. So two both-forms terms in a row —
drop a host, then drop a port — leave the second one's untagged branch reading
shifted bytes: verified, the example profile's filter dropped RTSP on VLAN 20
and kept it untagged. Every term that needs the keyword is folded into one
block, last: `(untagged and X) or (vlan and X)`.

**Restricted segments are excluded by tag and by address.** By tag, at both
positions of a stacked frame: a QinQ frame starts 0x88a8, and a filter that only
knows 0x8100 reads it as untagged. By address, with `not net` written out by
offset for each tag layout: the access-control subnet's traffic also arrives
untagged (a native VLAN), under another VLAN's tag (a routed copy, a port in
the wrong VLAN), or inside QinQ, and none of those carries the tag the first
exclusion looks for. Both come first and use no `vlan` keyword, so nothing
before them can shift them and they shift nothing after.
"""

from __future__ import annotations

import os
import re

__all__ = [
    'vlan_filter', 'exclude_vlans', 'exclude_networks', 'protocol_filter',
    'host_filter', 'exclude_hosts', 'exclude_ports', 'build_capture_filter',
    'tag_field_expr', 'combine', 'verify_filter', 'diagnose_untagged',
    'from_profile', 'restricted_networks',
]

_MAC_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')


def tag_field_expr(vlan_id):
    """Test one VLAN id by reading the tag field directly (offset-shift safe)."""
    return f'ether[14:2] & 0x0fff == {int(vlan_id)}'


#: Frames carrying an 802.1Q tag have this ethertype at offset 12.
DOT1Q = '0x8100'


def vlan_filter(vlan_ids, include_untagged=False):
    """
    Match the given VLAN ids, optionally alongside untagged frames.

    Never emits `vlan A or vlan B` (matches only A), nor either mixed form using
    the `vlan` keyword (one matches nothing tagged, the other matches everything).
    See the module docstring.
    """
    ids = sorted({int(v) for v in (vlan_ids or [])})

    if not ids:
        # No VLAN selection: keep untagged only, or everything.
        #
        # `not vlan` rather than the ethertype test, because there is no tagged
        # branch here for it to shift offsets in, and the ethertype test is the
        # form reported not to exclude tagged frames under Npcap. Where both
        # work, they are equivalent; where only one works, this is it.
        return 'not vlan' if include_untagged else ''

    inner = ' or '.join(tag_field_expr(v) for v in ids)
    tagged = f'(ether[12:2] == {DOT1Q} and ({inner}))' if len(ids) > 1 \
        else f'(ether[12:2] == {DOT1Q} and {inner})'

    if include_untagged:
        return f'(ether[12:2] != {DOT1Q} or {tagged})'
    return tagged


#: The tag protocol identifiers a frame can be stacked with: 802.1Q, 802.1ad
#: (QinQ's service tag) and the older pre-standard 0x9100. A filter that knows
#: only 0x8100 reads a QinQ frame as untagged.
STACK_TPIDS = ('0x8100', '0x88a8', '0x9100')


def _tpid_at(offset):
    return '(' + ' or '.join(f'ether[{offset}:2] == {t}' for t in STACK_TPIDS) + ')'


def _not_tpid_at(offset):
    return ' and '.join(f'ether[{offset}:2] != {t}' for t in STACK_TPIDS)


def exclude_vlans(vlan_ids):
    """
    Everything except these VLANs — untagged frames included.

    The complement of `vlan_filter`, and the one that carries a different kind
    of weight: this is what keeps a segment's payload off the disk. A capture
    written with a selection filter that happens to omit VLAN 40 is one
    misconfiguration away from including it; a capture written with an exclusion
    filter names what must never be there.

    Written without the `vlan` keyword for the same reason as the mixed form
    above: the keyword shifts offsets across `or`, and the failure is silent.

    Stacked tags are tested at both positions. A QinQ frame starts 0x88a8, not
    0x8100, so a filter that only knew 0x8100 read it as untagged and let it
    through whatever VLAN it carried — the outer tag or the inner.
    """
    ids = sorted({int(v) for v in (vlan_ids or [])})
    if not ids:
        return ''

    def restricted_at(offset):
        terms = ' or '.join(f'ether[{offset}:2] & 0x0fff == {v}' for v in ids)
        return f'({terms})' if len(ids) > 1 else terms

    # Untagged frames carry no tag to match, so they pass; a singly tagged one
    # passes if its tag is not in the list; a doubly tagged one only if
    # neither of its tags is.
    untagged = _not_tpid_at(12)
    single = (f'{_tpid_at(12)} and {_not_tpid_at(16)} '
              f'and not {restricted_at(14)}')
    stacked = (f'{_tpid_at(12)} and {_tpid_at(16)} '
               f'and not {restricted_at(14)} and not {restricted_at(18)}')
    return f'(({untagged}) or ({single}) or ({stacked}))'


def _network_test(network, base):
    """
    One network at either address of an IP header starting at `base`, by
    explicit offsets: the header's own fields, no `vlan` keyword, so nothing is
    shifted for whatever comes after it in the expression.
    """
    import ipaddress
    net = ipaddress.ip_network(str(network), strict=False)
    if net.prefixlen == 0:
        raise ValueError(f'{network} covers every address; that excludes '
                         f'everything')
    packed, bits = net.network_address.packed, net.prefixlen
    if net.version == 4:
        ethertype, fields = '0x0800', (base + 12, base + 16)
    else:
        ethertype, fields = '0x86dd', (base + 8, base + 24)

    def matches(at):
        words = []
        for index in range(0, (bits + 31) // 32):
            covered = min(32, bits - index * 32)
            mask = (0xffffffff << (32 - covered)) & 0xffffffff
            value = int.from_bytes(packed[index * 4:index * 4 + 4], 'big') & mask
            load = f'ether[{at + index * 4}:4]'
            words.append(f'{load} == 0x{value:08x}' if mask == 0xffffffff
                         else f'{load} & 0x{mask:08x} == 0x{value:08x}')
        return ' and '.join(words) if len(words) == 1 else \
            '(' + ' and '.join(words) + ')'

    return (f'(ether[{base - 2}:2] == {ethertype} and '
            f'({matches(fields[0])} or {matches(fields[1])}))')


def exclude_networks(networks):
    """
    Everything except traffic to or from these networks, however it is tagged.

    The address-side half of keeping a restricted segment off the disk. A tag
    exclusion cannot see the access-control subnet's traffic when it arrives
    untagged (the trunk's native VLAN), under another VLAN's tag (a routed copy,
    or a port in the wrong VLAN), or inside a QinQ frame. `not net` catches all
    of those, written out by offset for the untagged, single-tagged and
    double-tagged layouts, so it needs no `vlan` keyword and shifts nothing.
    """
    nets = [n for n in (networks or []) if str(n).strip()]
    if not nets:
        return ''
    terms = []
    for network in nets:
        terms.append(f'({_not_tpid_at(12)} and {_network_test(network, 14)})')
        terms.append(f'({_tpid_at(12)} and {_network_test(network, 18)})')
        terms.append(f'({_tpid_at(12)} and {_tpid_at(16)} and '
                     f'{_network_test(network, 22)})')
    return 'not (' + ' or '.join(terms) + ')'


def _both_forms(term):
    """
    A term that must match whether or not the frame is tagged.

    The untagged form comes first because `vlan` shifts offsets for everything
    after it; writing it the other way round silently breaks the untagged case.

    Each side is parenthesised rather than left to BPF's precedence rules. They
    happen to give the right answer for `tcp and port 554`, but a module whose
    reason for existing is that BPF does surprising things should not be leaning
    on them.
    """
    return f'(({term}) or (vlan and ({term})))'


#: Protocols with no port field. Asking for a port on one of these produces a
#: filter libpcap rejects outright ("expression rejects all packets"), which
#: would stop the capture starting rather than merely matching nothing.
PORTLESS_PROTOCOLS = frozenset({'icmp', 'icmp6', 'arp', 'rarp'})

KNOWN_PROTOCOLS = frozenset({'tcp', 'udp', 'icmp', 'icmp6', 'arp', 'rarp',
                             'ip', 'ip6'})


def protocol_filter(protocol=None, ports=None, direction='either'):
    """
    Build a protocol/port term that works on tagged and untagged frames.

    direction: 'src', 'dst' or 'either'.

    Raises ValueError for a port on a protocol that has none. The alternative —
    emitting it and letting libpcap refuse — turns a profile typo into a capture
    that will not start, discovered on the mirror port rather than here.
    """
    term = _protocol_term(protocol, ports, direction)
    return _both_forms(term) if term else ''


def _protocol_term(protocol=None, ports=None, direction='either'):
    """The protocol/port test in one form, before the both-forms treatment."""
    parts = []
    proto = (protocol or '').lower().strip()
    if ports and proto in PORTLESS_PROTOCOLS:
        raise ValueError(
            f'{proto} has no ports; drop the port list or change the protocol')
    if proto in KNOWN_PROTOCOLS:
        parts.append(proto)

    if ports:
        keyword = {'src': 'src port', 'dst': 'dst port'}.get(direction, 'port')
        port_list = [int(p) for p in ports]
        if len(port_list) == 1:
            parts.append(f'{keyword} {port_list[0]}')
        else:
            joined = ' or '.join(f'{keyword} {p}' for p in sorted(set(port_list)))
            parts.append(f'({joined})')

    if not parts:
        return ''
    return ' and '.join(parts)


def host_filter(hosts, direction='either'):
    """
    Match hosts by IP, CIDR or MAC.

    MAC terms are emitted without the `vlan` dance — they read bytes before the
    tag, so they already match both forms.
    """
    return _host_terms(hosts, direction, _both_forms)


def _host_terms(hosts, direction='either', wrap=None):
    """Host terms, with the address ones passed through `wrap` if given."""
    if not hosts:
        return ''

    macs = [h for h in hosts if _MAC_RE.match(str(h))]
    addrs = [h for h in hosts if not _MAC_RE.match(str(h))]
    terms = []

    for mac in macs:
        keyword = {'src': 'ether src', 'dst': 'ether dst'}.get(direction, 'ether host')
        terms.append(f'{keyword} {mac.lower()}')

    if addrs:
        # A bare address takes `host`/`src`/`dst`; a CIDR takes `net`, and
        # undirected it is `net X` with no `host` — `host net X` is a syntax
        # error that would stop the whole capture filter compiling.
        bare = {'src': 'src', 'dst': 'dst'}.get(direction, 'host')
        cidr = {'src': 'src net', 'dst': 'dst net'}.get(direction, 'net')
        addr_terms = [f'{cidr} {addr}' if '/' in str(addr) else f'{bare} {addr}'
                      for addr in addrs]
        joined = ' or '.join(addr_terms)
        joined = f'({joined})' if len(addr_terms) > 1 else joined
        terms.append(wrap(joined) if wrap is not None else joined)

    if len(terms) == 1:
        return terms[0]
    return '(' + ' or '.join(terms) + ')'


def exclude_hosts(hosts):
    """Negated host term, for dropping high-volume sources such as video."""
    term = host_filter(hosts)
    return f'not {term}' if term else ''


def exclude_ports(ports, protocol=None):
    """Negated port term, for dropping known bulk streams."""
    term = protocol_filter(protocol=protocol, ports=ports)
    return f'not {term}' if term else ''


def combine(*terms, op='and'):
    """Join non-empty terms, parenthesising so precedence cannot surprise."""
    live = [t for t in terms if t and t.strip()]
    if not live:
        return ''
    if len(live) == 1:
        return live[0]
    return f' {op} '.join(t if t.startswith('(') or ' ' not in t else f'({t})'
                          for t in live)


def _keyword_block(drop_hosts=None, drop_ports=None, drop_port_protocol='tcp',
                   extra=None):
    """
    Every term that needs the `vlan` keyword, as one block with the keyword once.

    `(untagged and X) or (vlan and X)`: the untagged branch is read before the
    keyword shifts anything, and guarded by the tag test so that a negation in
    X (drop this host) cannot make it true for every tagged frame.
    """
    dropped = [t for t in (_host_terms(drop_hosts),
                           _protocol_term(drop_port_protocol, drop_ports)
                           if drop_ports else '') if t]
    inner = []
    if dropped:
        # Each parenthesised: BPF gives `and` and `or` the same precedence, so
        # `host X or tcp and port 554` would read as `(host X or tcp) and ...`.
        inner.append('not (' + ' or '.join(f'({t})' for t in dropped) + ')')
    if extra:
        inner.append(f'({extra})')
    if not inner:
        return ''
    body = ' and '.join(inner)
    return f'(({_not_tpid_at(12)} and {body}) or (vlan and {body}))'


def build_capture_filter(vlans=None, include_untagged=True,
                         drop_hosts=None, drop_ports=None,
                         drop_port_protocol='tcp', extra=None,
                         never_vlans=None, never_networks=None):
    """
    Assemble a capture filter for one mirror input.

    Args:
        vlans: VLAN ids to keep. Empty or None keeps every VLAN.
        include_untagged: keep untagged frames (management traffic usually is).
        drop_hosts: hosts to exclude — typically camera streams.
        drop_ports: ports to exclude — typically video.
        drop_port_protocol: protocol for drop_ports.
        never_vlans: VLANs that must not appear in the output at all. Use this
            rather than relying on `vlans` to omit them: a selection filter that
            happens to leave one out is one edit away from including it, where
            an exclusion names what must never be there. Applied first, at
            both tag positions of a stacked frame.
        never_networks: subnets whose traffic must not appear, however it is
            tagged — untagged, under another VLAN's tag, inside QinQ. The
            address-side half of never_vlans; applied second.
        extra: a BPF fragment appended with `and`. Given the both-forms
            treatment so a plain term like `udp` matches tagged frames too —
            without it, `extra='udp'` matches nothing on a trunk mirror, which
            is the trap this module exists to prevent. A fragment that already
            mentions `vlan` is passed through untouched, last, on the basis
            that whoever wrote it is handling tags deliberately. Not validated
            otherwise; a syntax error surfaces when libpcap compiles it.

    The result is empty when nothing is being filtered, which libpcap reads as
    "capture everything" — the correct meaning, and safer than emitting a term
    that might not match.
    """
    parts = []

    # The exclusions first, so they are the first thing read and a later term
    # can only ever narrow them. Neither uses the `vlan` keyword, so nothing
    # can shift them.
    if never_vlans:
        parts.append(exclude_vlans(never_vlans))
    if never_networks:
        parts.append(exclude_networks(never_networks))

    if vlans:
        parts.append(vlan_filter(vlans, include_untagged=include_untagged))
    elif not include_untagged:
        # Tagged frames only, by the tag test rather than the bare keyword,
        # which would shift every offset after it.
        parts.append(_tpid_at(12))

    keyword_extra = extra if extra and 'vlan' in extra else None
    parts.append(_keyword_block(drop_hosts, drop_ports, drop_port_protocol,
                                None if keyword_extra else extra))
    if keyword_extra:
        parts.append(f'({keyword_extra})')

    return combine(*parts)


def verify_filter(bpf, pcap_path, tcpdump='tcpdump', restricted_vlans=(),
                  restricted_nets=()):
    """
    Run a filter over a capture and report what it actually matched, per VLAN.

    The point is to settle capture-setup questions empirically. BPF tag handling
    differs between libpcap and Npcap, so a filter that is correct here may not be
    correct on the machine that will run it. Take a short capture with no filter,
    then check the candidate against it:

        >>> verify_filter(build_capture_filter(vlans=[5, 6]), 'sample.pcap')
        {'total': 5000, 'matched': 1840, 'by_vlan': {5: 1200, 6: 640},
         'untagged_matched': 0, ...}

    With `restricted_vlans` and `restricted_nets`, it also counts what the
    filter kept from those segments — any tag in a stacked frame, any address
    in the subnets — under `restricted_kept`. That is the number that must be
    zero, and `netmon bpf --verify` exits non-zero when it is not.

    Returns a dict, or one with an 'error' key if tcpdump is unavailable or the
    filter does not compile — never raises, so a UI can call it freely.
    """
    import ipaddress
    import shutil
    import subprocess

    if not shutil.which(tcpdump):
        return {'error': f'{tcpdump} not found on PATH'}
    if not os.path.exists(pcap_path):
        return {'error': f'capture not found: {pcap_path}'}

    def run(expr):
        cmd = [tcpdump, '-r', pcap_path, '-nn', '-e', '-c', '200000']
        if expr:
            cmd.append(expr)
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            return None, proc.stderr.strip().splitlines()[-1:] or ['unknown error']
        return proc.stdout.splitlines(), None

    baseline, err = run('')
    if err:
        return {'error': f'could not read capture: {err[0]}'}

    matched, err = run(bpf)
    if err:
        return {'error': f'filter did not compile: {err[0]}', 'filter': bpf}

    # tcpdump -e prints "vlan N," for tagged frames.
    vlan_re = re.compile(r'vlan (\d+)')
    address_re = re.compile(r'(?<![\w.:])(\d{1,3}(?:\.\d{1,3}){3})(?:\.\d+)?(?=[ :,>])')
    restricted_vlans = {int(v) for v in (restricted_vlans or ())}
    nets = []
    for net in restricted_nets or ():
        try:
            nets.append(ipaddress.ip_network(str(net), strict=False))
        except ValueError:
            continue

    def restricted(line):
        if any(int(v) in restricted_vlans for v in vlan_re.findall(line)):
            return 'vlan'
        for text in address_re.findall(line):
            try:
                address = ipaddress.ip_address(text)
            except ValueError:
                continue
            if any(address in net for net in nets if net.version == address.version):
                return 'address'
        return None

    def tally(lines):
        by_vlan, untagged = {}, 0
        for line in lines:
            found = vlan_re.search(line)
            if found:
                vid = int(found.group(1))
                by_vlan[vid] = by_vlan.get(vid, 0) + 1
            else:
                untagged += 1
        return by_vlan, untagged

    seen_vlans, seen_untagged = tally(baseline)
    hit_vlans, hit_untagged = tally(matched)

    kept = {'vlan': 0, 'address': 0}
    present = {'vlan': 0, 'address': 0}
    if restricted_vlans or nets:
        for lines, counts in ((matched, kept), (baseline, present)):
            for line in lines:
                found = restricted(line)
                if found:
                    counts[found] += 1

    return {
        'filter': bpf,
        'total': len(baseline),
        'matched': len(matched),
        'by_vlan': dict(sorted(hit_vlans.items())),
        'untagged_matched': hit_untagged,
        'vlans_present': dict(sorted(seen_vlans.items())),
        'untagged_present': seen_untagged,
        'vlans_dropped': sorted(set(seen_vlans) - set(hit_vlans)),
        'restricted_present': present,
        'restricted_kept': kept,
    }


def display_filter(vlans=None, hosts=None, ports=None, protocol=None):
    """
    The Wireshark equivalent, which needs none of the above care.

    Wireshark's dissector walks the tag, so `vlan.id == 5` and `ip.addr == ...`
    behave as written. Provided so the UI can offer both without anyone assuming
    the BPF rules apply here too.
    """
    parts = []
    if vlans:
        ids = sorted({int(v) for v in vlans})
        parts.append(f'vlan.id == {ids[0]}' if len(ids) == 1
                     else '(' + ' or '.join(f'vlan.id == {v}' for v in ids) + ')')
    if hosts:
        addrs = [h for h in hosts if not _MAC_RE.match(str(h))]
        macs = [h for h in hosts if _MAC_RE.match(str(h))]
        host_terms = [f'ip.addr == {a}' for a in addrs] + \
                     [f'eth.addr == {m.lower()}' for m in macs]
        if host_terms:
            parts.append(host_terms[0] if len(host_terms) == 1
                         else '(' + ' or '.join(host_terms) + ')')
    if protocol:
        parts.append(protocol.lower())
    if ports:
        proto = (protocol or 'tcp').lower()
        port_terms = [f'{proto}.port == {int(p)}' for p in ports]
        parts.append(port_terms[0] if len(port_terms) == 1
                     else '(' + ' or '.join(port_terms) + ')')
    return ' and '.join(parts)


def from_profile(profile):
    """Build the capture filter described by a profile's `capture:` section."""
    capture = (getattr(profile, 'raw', {}) or {}).get('capture') or {}
    # Segments the profile marks metadata-only are excluded from the filter
    # itself, not merely left out of the selection. Whatever a `capture:`
    # section says, their payload does not reach the disk.
    never = sorted(getattr(profile, 'metadata_only_vlans', set()) or set())
    return build_capture_filter(
        vlans=capture.get('vlans'),
        include_untagged=capture.get('include_untagged', True),
        drop_hosts=capture.get('drop_hosts'),
        drop_ports=capture.get('drop_ports'),
        drop_port_protocol=capture.get('drop_port_protocol', 'tcp'),
        extra=capture.get('extra'),
        never_vlans=never,
        never_networks=restricted_networks(profile))


def restricted_networks(profile):
    """The subnets of the profile's metadata-only VLANs."""
    restricted = set(getattr(profile, 'metadata_only_vlans', set()) or set())
    vlans = getattr(profile, 'vlans', {}) or {}
    return sorted({v.subnet for v in vlans.values()
                   if v.id in restricted and v.subnet})


def diagnose_untagged(pcap_path, tcpdump='tcpdump'):
    """
    Work out which untagged-selection form this capture stack honours.

    The spec this was built from reports `ether[12:2] != 0x8100` failing to
    exclude tagged frames under Npcap, where it works under libpcap. Rather than
    take either report on faith, run both over a capture that contains tagged and
    untagged frames and see.

    Returns a dict per form with what it matched, plus `recommended` naming a form
    that selected untagged frames and nothing else — or None if neither did, which
    would mean the mixed-VLAN filters in this module cannot be trusted on this
    stack and the capture should be split into two.
    """
    forms = {
        'ethertype': f'ether[12:2] != {DOT1Q}',
        'not-vlan': 'not vlan',
    }
    baseline = verify_filter('', pcap_path, tcpdump=tcpdump)
    if 'error' in baseline:
        return baseline
    if not baseline['vlans_present']:
        return {'error': 'sample contains no tagged frames, so it cannot '
                         'distinguish the two forms'}
    if not baseline['untagged_present']:
        return {'error': 'sample contains no untagged frames, so it cannot '
                         'confirm either form keeps them'}

    results, recommended = {}, None
    for name, expr in forms.items():
        report = verify_filter(expr, pcap_path, tcpdump=tcpdump)
        correct = ('error' not in report
                   and not report.get('by_vlan')
                   and report.get('untagged_matched') == baseline['untagged_present'])
        results[name] = {
            'filter': expr,
            'untagged_kept': report.get('untagged_matched'),
            'tagged_leaked': sum((report.get('by_vlan') or {}).values()),
            'correct': correct,
            'error': report.get('error'),
        }
        if correct and recommended is None:
            recommended = name

    results['recommended'] = recommended
    results['mixed_form_trustworthy'] = results['ethertype']['correct']
    return results


#: Exit codes for `netmon bpf`, so a deployment check can be a script.
EXIT_OK, EXIT_ERROR, EXIT_RESTRICTED_KEPT, EXIT_NO_TRUSTWORTHY_FORM = 0, 1, 3, 4


def _main(argv=None):
    """
    `python -m netmon.bpf` — show the filter a profile produces, and optionally
    prove what it matches against a sample capture.

    The proof step matters more than it looks. BPF VLAN handling differs between
    libpcap and Npcap, so a filter verified here may behave differently on the
    machine that will run it. Take a short unfiltered capture there and check.

    `--verify` exits 3 if the filter kept anything from a metadata-only
    segment — a tag or an address — so it can gate a deployment.
    `--diagnose-untagged` exits 4 if neither untagged form is trustworthy on
    this stack.
    """
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog='python -m netmon.bpf',
        description='Build and verify a VLAN-aware capture filter.')
    parser.add_argument('--profile', help='site profile to read capture: from')
    parser.add_argument('--vlans', help='comma-separated VLAN ids (overrides profile)')
    parser.add_argument('--no-untagged', action='store_true',
                        help='exclude untagged frames')
    parser.add_argument('--drop-hosts', help='comma-separated hosts to exclude')
    parser.add_argument('--drop-ports', help='comma-separated ports to exclude')
    parser.add_argument('--verify', metavar='PCAP',
                        help='run the filter over this capture and report what '
                             'it matched, per VLAN. Exits 3 if anything from a '
                             'metadata-only segment got through')
    parser.add_argument('--diagnose-untagged', metavar='PCAP',
                        help='run both untagged-selection forms over an '
                             'unfiltered sample with tagged and untagged frames, '
                             'and say which this capture stack honours')
    parser.add_argument('--wireshark', action='store_true',
                        help='also print the Wireshark display filter')
    args = parser.parse_args(argv)

    if args.diagnose_untagged:
        report = diagnose_untagged(args.diagnose_untagged)
        print(json.dumps(report, indent=2))
        if 'error' in report:
            return EXIT_ERROR
        if not report.get('recommended'):
            print()
            print('Neither form selects untagged frames alone on this stack, so the '
                  'mixed tagged-and-untagged filters cannot be trusted here. Capture '
                  'tagged and untagged traffic separately.')
            return EXIT_NO_TRUSTWORTHY_FORM
        if not report.get('mixed_form_trustworthy'):
            print()
            print('The ethertype test does not exclude tagged frames here, and '
                  'the mixed filters rely on it. Capture tagged and untagged '
                  'traffic separately.')
            return EXIT_NO_TRUSTWORTHY_FORM
        return EXIT_OK

    vlans = None
    if args.vlans:
        vlans = [int(v) for v in args.vlans.split(',') if v.strip()]

    profile = None
    if args.profile:
        from netmon.profile import ProfileError, load_profile
        try:
            profile = load_profile(args.profile)
        except ProfileError as e:
            print(f'invalid profile: {e}')
            return EXIT_ERROR

    if profile is not None and vlans is None and not args.drop_hosts \
            and not args.drop_ports:
        bpf_filter = from_profile(profile)
    else:
        bpf_filter = build_capture_filter(
            vlans=vlans,
            include_untagged=not args.no_untagged,
            drop_hosts=(args.drop_hosts or '').split(',') if args.drop_hosts else None,
            drop_ports=[int(p) for p in args.drop_ports.split(',')]
            if args.drop_ports else None,
            never_vlans=sorted(profile.metadata_only_vlans) if profile else None,
            never_networks=restricted_networks(profile) if profile else None)

    print(bpf_filter or '(empty — captures everything)')

    if args.wireshark:
        print()
        print('Wireshark:', display_filter(vlans=vlans) or '(none)')

    if args.verify:
        print()
        restricted = sorted(getattr(profile, 'metadata_only_vlans', set()) or set())
        report = verify_filter(bpf_filter, args.verify,
                               restricted_vlans=restricted,
                               restricted_nets=restricted_networks(profile)
                               if profile else ())
        if 'error' in report:
            print(f"could not verify: {report['error']}")
            return EXIT_ERROR
        print(json.dumps({k: v for k, v in report.items() if k != 'filter'},
                         indent=2))
        if report['vlans_dropped']:
            print()
            print('dropped entirely: VLAN ' +
                  ', '.join(str(v) for v in report['vlans_dropped']))
        kept = report.get('restricted_kept') or {}
        if any(kept.values()):
            print()
            print(f"RESTRICTED TRAFFIC KEPT: {kept.get('vlan', 0)} frames tagged "
                  f"with a metadata-only VLAN and {kept.get('address', 0)} with a "
                  f"metadata-only address got through this filter. Its payload "
                  f"would reach the disk. Do not deploy it.")
            return EXIT_RESTRICTED_KEPT
        if not profile:
            print()
            print('No --profile, so nothing was checked against the metadata-only '
                  'segments.')
    return EXIT_OK


if __name__ == '__main__':
    import sys
    sys.exit(_main())
