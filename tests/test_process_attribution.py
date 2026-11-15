"""
A packet is put down to a program by this PC's own end of it.
=============================================================
The outside review of 2026-11-14 (N9): capture named a packet's program by
its source port, else its destination port, whoever's ports they were. On a
mirror port or in promiscuous mode, traffic between two other hosts whose
port matched a local program's was blamed on that program; the IOC scanner
could then raise IOC-SUSPICIOUS-PROC, and uploads were counted against it.
The owner's alert review of 11-13 had two ad servers' alerts naming
tailscaled.exe, whose UDP port a browser's TCP connection had reused.
Addresses are made-up LAN or documentation ones.
"""

import collections
import os
import socket
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401

PC, NAS, TV, SITE = '192.168.10.32', '192.168.10.21', '192.168.10.50', '198.51.100.40'


def info(src, sport, dst, dport, protocol='TCP'):
    return SimpleNamespace(src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
                           protocol=protocol)


class _Maps(unittest.TestCase):

    def setUp(self):
        from src import capture
        self.capture = capture
        names = ('_local_addresses', '_recent_connections', '_port_process_cache',
                 '_port_process_by_proto')
        saved = {n: getattr(capture, n) for n in names}
        self.addCleanup(lambda: [setattr(capture, n, v) for n, v in saved.items()])
        capture._local_addresses = frozenset({PC})
        capture._recent_connections = {}
        capture._port_process_cache = {41641: ('tailscaled.exe', 7), 50000: ('chrome.exe', 9)}
        capture._port_process_by_proto = {(41641, 'UDP'): ('tailscaled.exe', 7),
                                          (50000, 'TCP'): ('chrome.exe', 9)}


class TestWhichEnd(_Maps):

    def test_traffic_between_two_other_hosts_is_no_programs(self):
        """A TV and the NAS on the mirror port, one of them using 50000."""
        self.assertEqual(self.capture._process_for_packet(info(TV, 50000, NAS, 445)), ('', 0))
        self.assertEqual(self.capture._process_for_packet(info(NAS, 445, TV, 50000)), ('', 0))

    def test_this_pcs_end_names_the_program_either_way(self):
        self.assertEqual(self.capture._process_for_packet(info(PC, 50000, SITE, 443)),
                         ('chrome.exe', 9))
        self.assertEqual(self.capture._process_for_packet(info(SITE, 443, PC, 50000)),
                         ('chrome.exe', 9))

    def test_the_remote_port_is_never_looked_up(self):
        """This PC's port 51000 is nobody's; the server's 50000 is not this PC's."""
        self.assertEqual(self.capture._process_for_packet(info(PC, 51000, SITE, 50000)), ('', 0))

    def test_a_tcp_connection_is_not_the_udp_program_on_that_port(self):
        self.capture._port_process_cache[41641] = ('tailscaled.exe', 7)
        self.capture._port_process_by_proto[(41641, 'TCP')] = ('msedge.exe', 11)
        self.assertEqual(self.capture._process_for_packet(info(PC, 41641, SITE, 443)),
                         ('msedge.exe', 11))
        self.assertEqual(self.capture._process_for_packet(info(PC, 41641, SITE, 3478, 'UDP')),
                         ('tailscaled.exe', 7))

    def test_the_exact_connection_wins(self):
        self.capture._recent_connections[(50000, SITE)] = ('ssh.exe', 4, 0)
        self.assertEqual(self.capture._process_for_packet(info(SITE, 443, PC, 50000)),
                         ('ssh.exe', 4))

    def test_before_the_first_refresh_nothing_is_named(self):
        self.capture._local_addresses = frozenset()
        self.assertEqual(self.capture._process_for_packet(info(PC, 50000, SITE, 443)), ('', 0))


class TestThroughTheCapture(_Maps):

    def test_a_mirrored_packet_between_two_other_hosts_names_no_program(self):
        from _test_support import SCAPY_REAL, reset_config
        if not SCAPY_REAL:
            self.skipTest('real scapy unavailable')
        from scapy.all import IP, TCP, Ether
        from src.capture import CaptureEngine
        engine = CaptureEngine(reset_config())
        wire = bytes(Ether(src='00:00:5e:00:53:50', dst='00:00:5e:00:53:21')
                     / IP(src=TV, dst=NAS) / TCP(sport=50000, dport=445, flags='PA'))
        got = engine._extract_packet_info(Ether(wire))
        self.assertEqual((got.process_name, got.process_pid), ('', 0))
        mine = bytes(Ether(src='00:00:5e:00:53:32', dst='00:00:5e:00:53:01')
                     / IP(src=PC, dst=SITE) / TCP(sport=50000, dport=443, flags='PA'))
        self.assertEqual(engine._extract_packet_info(Ether(mine)).process_name, 'chrome.exe')


class TestTheRefreshKeepsTheProtocol(_Maps):

    def test_tcp_and_udp_on_one_port_are_two_programs(self):
        capture = self.capture
        Conn = collections.namedtuple('Conn', 'laddr raddr status pid type')
        Addr = collections.namedtuple('Addr', 'ip port')
        conns = [Conn(Addr(PC, 41641), None, 'NONE', 7, socket.SOCK_DGRAM),
                 Conn(Addr(PC, 41641), Addr(SITE, 443), 'ESTABLISHED', 11, socket.SOCK_STREAM)]
        names = {7: 'tailscaled.exe', 11: 'msedge.exe'}
        saved = (getattr(capture, 'psutil', None), capture.PSUTIL_AVAILABLE)

        def restore():
            if saved[0] is not None:
                capture.psutil = saved[0]
            capture.PSUTIL_AVAILABLE = saved[1]
        self.addCleanup(restore)
        capture.psutil = SimpleNamespace(
            CONN_LISTEN='LISTEN', NoSuchProcess=LookupError, AccessDenied=PermissionError,
            net_connections=lambda kind='inet': conns,
            net_if_addrs=lambda: {'eth': [SimpleNamespace(family=socket.AF_INET, address=PC)]},
            Process=lambda pid: SimpleNamespace(name=lambda: names[pid]))
        capture.PSUTIL_AVAILABLE = True
        capture._refresh_port_process_map(force=True)
        self.assertEqual(capture._port_process_by_proto[(41641, 'UDP')], ('tailscaled.exe', 7))
        self.assertEqual(capture._port_process_by_proto[(41641, 'TCP')], ('msedge.exe', 11))
        self.assertEqual(capture._process_for_packet(info(PC, 41641, '203.0.113.7', 3478, 'UDP')),
                         ('tailscaled.exe', 7))


if __name__ == '__main__':
    unittest.main()
