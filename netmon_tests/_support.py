"""
Shared fixtures for the netmon tests.

The BPF tests are only meaningful if they run a real filter over real frames, so
this builds a small synthetic capture with known VLAN tags and checks what
tcpdump actually matches. Nothing here touches a live interface.
"""

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HAVE_TCPDUMP = shutil.which('tcpdump') is not None

try:
    from scapy.all import Dot1Q, Ether, IP, TCP, UDP, wrpcap
    HAVE_SCAPY = True
except Exception:                                    # pragma: no cover
    HAVE_SCAPY = False


#: (vlan id or None, count, dst port) for the synthetic capture.
SAMPLE_LAYOUT = [
    (5, 30, 47808),      # HVAC controller chatter
    (6, 15, 47808),      # second HVAC segment
    (12, 20, 443),       # the segment that must never be captured by accident
    (14, 10, 554),       # video
    (None, 6, 22),       # untagged management
]


def build_sample_pcap(path):
    """Write a capture containing every VLAN in SAMPLE_LAYOUT plus untagged frames."""
    packets = []
    for index, (vlan, count, port) in enumerate(SAMPLE_LAYOUT):
        for n in range(count):
            frame = Ether(src=f'00:11:22:33:44:{index:02x}',
                          dst='00:aa:bb:cc:dd:ee')
            if vlan is not None:
                frame /= Dot1Q(vlan=vlan)
            octet = vlan if vlan is not None else 1
            frame /= IP(src=f'10.0.{octet}.{n % 200 + 1}', dst=f'10.0.{octet}.250')
            frame /= (UDP(dport=port) if port == 47808 else TCP(dport=port))
            packets.append(frame)
    wrpcap(path, packets)
    return path


class PcapFixture:
    """Builds the sample capture once and reuses it across a test class."""

    _dir = None
    _path = None

    @classmethod
    def path(cls):
        if cls._path is None:
            cls._dir = tempfile.mkdtemp(prefix='netmon-bpf-')
            cls._path = build_sample_pcap(os.path.join(cls._dir, 'sample.pcap'))
        return cls._path

    @classmethod
    def cleanup(cls):
        if cls._dir:
            shutil.rmtree(cls._dir, ignore_errors=True)
            cls._dir = cls._path = None


def matched_vlans(bpf, pcap_path):
    """
    Run a filter over the capture and report which VLANs survived it.

    Returns (counts_by_vlan, untagged_count). A VLAN absent from the dict was
    filtered out — which is the assertion that matters, since the failure mode
    being guarded against is capturing a segment that should have been excluded.
    """
    import re
    cmd = ['tcpdump', '-r', pcap_path, '-nn', '-e']
    if bpf:
        cmd.append(bpf)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise AssertionError(
            f'tcpdump rejected {bpf!r}: {proc.stderr.strip().splitlines()[-1:]}')
    by_vlan, untagged = {}, 0
    tag = re.compile(r'vlan (\d+)')
    for line in proc.stdout.splitlines():
        found = tag.search(line)
        if found:
            vid = int(found.group(1))
            by_vlan[vid] = by_vlan.get(vid, 0) + 1
        else:
            untagged += 1
    return by_vlan, untagged
