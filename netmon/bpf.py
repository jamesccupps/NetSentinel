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
where it does under libpcap on Linux. `verify_filter()` runs a candidate filter
over a sample capture and reports what it matched per VLAN, so the question can be
settled on the hardware that will run it rather than argued from documentation.

**MAC terms need no `vlan` keyword.** `ether host`, `ether broadcast` and friends
match tagged and untagged frames alike, because they read bytes before the tag.
"""

from __future__ import annotations

import os
import re

__all__ = [
    'vlan_filter', 'protocol_filter', 'host_filter', 'exclude_hosts',
    'exclude_ports', 'build_capture_filter', 'tag_field_expr', 'combine',
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
        return f'ether[12:2] != {DOT1Q}' if include_untagged else ''

    inner = ' or '.join(tag_field_expr(v) for v in ids)
    tagged = f'(ether[12:2] == {DOT1Q} and ({inner}))' if len(ids) > 1 \
        else f'(ether[12:2] == {DOT1Q} and {inner})'

    if include_untagged:
        return f'(ether[12:2] != {DOT1Q} or {tagged})'
    return tagged


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
    return _both_forms(' and '.join(parts))


def host_filter(hosts, direction='either'):
    """
    Match hosts by IP, CIDR or MAC.

    MAC terms are emitted without the `vlan` dance — they read bytes before the
    tag, so they already match both forms.
    """
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
        terms.append(_both_forms(f'({joined})' if len(addr_terms) > 1 else joined))

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


def build_capture_filter(vlans=None, include_untagged=True,
                         drop_hosts=None, drop_ports=None,
                         drop_port_protocol='tcp', extra=None):
    """
    Assemble a capture filter for one mirror input.

    Args:
        vlans: VLAN ids to keep. Empty or None keeps every VLAN.
        include_untagged: keep untagged frames (management traffic usually is).
        drop_hosts: hosts to exclude — typically camera streams.
        drop_ports: ports to exclude — typically video.
        drop_port_protocol: protocol for drop_ports.
        extra: a BPF fragment appended with `and`. Given the both-forms
            treatment so a plain term like `udp` matches tagged frames too —
            without it, `extra='udp'` matches nothing on a trunk mirror, which
            is the trap this module exists to prevent. A fragment that already
            mentions `vlan` is passed through untouched, on the basis that
            whoever wrote it is handling tags deliberately. Not validated
            otherwise; a syntax error surfaces when libpcap compiles it.

    The result is empty when nothing is being filtered, which libpcap reads as
    "capture everything" — the correct meaning, and safer than emitting a term
    that might not match.
    """
    parts = []

    if vlans:
        parts.append(vlan_filter(vlans, include_untagged=include_untagged))
    elif not include_untagged:
        parts.append('vlan')

    if drop_hosts:
        parts.append(exclude_hosts(drop_hosts))
    if drop_ports:
        parts.append(exclude_ports(drop_ports, protocol=drop_port_protocol))
    if extra:
        parts.append(f'({extra})' if 'vlan' in extra else _both_forms(extra))

    return combine(*parts)


def verify_filter(bpf, pcap_path, tcpdump='tcpdump'):
    """
    Run a filter over a capture and report what it actually matched, per VLAN.

    The point is to settle capture-setup questions empirically. BPF tag handling
    differs between libpcap and Npcap, so a filter that is correct here may not be
    correct on the machine that will run it. Take a short capture with no filter,
    then check the candidate against it:

        >>> verify_filter(build_capture_filter(vlans=[5, 6]), 'sample.pcap')
        {'total': 5000, 'matched': 1840, 'by_vlan': {5: 1200, 6: 640},
         'untagged_matched': 0, ...}

    Returns a dict, or one with an 'error' key if tcpdump is unavailable or the
    filter does not compile — never raises, so a UI can call it freely.
    """
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

    return {
        'filter': bpf,
        'total': len(baseline),
        'matched': len(matched),
        'by_vlan': dict(sorted(hit_vlans.items())),
        'untagged_matched': hit_untagged,
        'vlans_present': dict(sorted(seen_vlans.items())),
        'untagged_present': seen_untagged,
        'vlans_dropped': sorted(set(seen_vlans) - set(hit_vlans)),
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
    return build_capture_filter(
        vlans=capture.get('vlans'),
        include_untagged=capture.get('include_untagged', True),
        drop_hosts=capture.get('drop_hosts'),
        drop_ports=capture.get('drop_ports'),
        drop_port_protocol=capture.get('drop_port_protocol', 'tcp'),
        extra=capture.get('extra'))


def _main(argv=None):
    """
    `python -m netmon.bpf` — show the filter a profile produces, and optionally
    prove what it matches against a sample capture.

    The proof step matters more than it looks. BPF VLAN handling differs between
    libpcap and Npcap, so a filter verified here may behave differently on the
    machine that will run it. Take a short unfiltered capture there and check.
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
                             'it matched, per VLAN')
    parser.add_argument('--wireshark', action='store_true',
                        help='also print the Wireshark display filter')
    args = parser.parse_args(argv)

    vlans = None
    if args.vlans:
        vlans = [int(v) for v in args.vlans.split(',') if v.strip()]

    if args.profile and vlans is None and not args.drop_hosts and not args.drop_ports:
        from netmon.profile import ProfileError, load_profile
        try:
            bpf_filter = from_profile(load_profile(args.profile))
        except ProfileError as e:
            print(f'invalid profile: {e}')
            return 1
    else:
        bpf_filter = build_capture_filter(
            vlans=vlans,
            include_untagged=not args.no_untagged,
            drop_hosts=(args.drop_hosts or '').split(',') if args.drop_hosts else None,
            drop_ports=[int(p) for p in args.drop_ports.split(',')]
            if args.drop_ports else None)

    print(bpf_filter or '(empty — captures everything)')

    if args.wireshark:
        print()
        print('Wireshark:', display_filter(vlans=vlans) or '(none)')

    if args.verify:
        print()
        report = verify_filter(bpf_filter, args.verify)
        if 'error' in report:
            print(f"could not verify: {report['error']}")
            return 1
        print(json.dumps({k: v for k, v in report.items() if k != 'filter'},
                         indent=2))
        if report['vlans_dropped']:
            print()
            print('dropped entirely: VLAN ' +
                  ', '.join(str(v) for v in report['vlans_dropped']))
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(_main())
