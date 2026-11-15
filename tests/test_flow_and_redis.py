"""
A flow's two directions, and an open Redis.
===========================================
The outside review of 2026-11-14 (N9):

- forensics set a flow's src_ip from each packet just before testing whether
  the packet came from src_ip, so dst_packets stayed 0, every flow was
  one-way, and the classifier's direction ratios (streaming, file transfer)
  never matched. The flow was also keyed by the packet's destination port,
  so the replies were a second flow keyed by the client's port.
- "Redis No Auth", CRITICAL, was any command packet without AUTH in it. AUTH
  is sent once per connection, so every session with a password counted.

Addresses are made-up LAN ones.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401

from test_third_review import T0, tcp, udp  # noqa: E402

PC, NAS, CACHE = '192.168.10.32', '192.168.10.21', '192.168.10.80'
GET = b'*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n'


def forensics():
    from src.forensics import NetworkForensics
    return NetworkForensics()


def redis_findings(f):
    return [d for d in f.sensitive_data if d['data_type'] == 'Redis No Auth']


class TestAFlowHasTwoDirections(unittest.TestCase):

    def download(self, f, server_port=21, client_port=50000, chunks=40):
        f.analyze_packet(tcp(PC, client_port, NAS, server_port, b'RETR big.iso\r\n',
                             server=server_port))
        for i in range(chunks):
            f.analyze_packet(tcp(NAS, server_port, PC, client_port, b'x' * 1400,
                                 server=server_port, ts=T0 + i * 0.01))

    def test_the_replies_are_counted_to_the_same_flow(self):
        f = forensics()
        self.download(f)
        [flow] = f.flows.values()
        self.assertEqual((flow['src_ip'], flow['dst_ip'], flow['dst_port']), (PC, NAS, 21))
        self.assertEqual((flow['src_packets'], flow['dst_packets']), (1, 40))

    def test_a_download_is_classified_by_its_direction(self):
        f = forensics()
        self.download(f)
        report = f.finalize()
        kinds = {c['classification'] for c in report['flow_classifications'].values()}
        self.assertIn('file_transfer', kinds)

    def test_without_the_servers_port_the_lower_port_is_the_service(self):
        """UDP has no handshake: both directions share the lower port."""
        f = forensics()
        f.analyze_packet(udp(PC, 53000, NAS, 53, b'q' * 30))
        f.analyze_packet(udp(NAS, 53, PC, 53000, b'a' * 60, ts=T0 + 0.01))
        [flow] = f.flows.values()
        self.assertEqual((flow['src_ip'], flow['dst_port']), (PC, 53))
        self.assertEqual((flow['src_packets'], flow['dst_packets']), (1, 1))


class TestRedis(unittest.TestCase):

    def test_a_session_that_authenticated_is_not_open(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 50000, CACHE, 6379,
                             b'*2\r\n$4\r\nAUTH\r\n$8\r\nexample1\r\n', server=6379))
        f.analyze_packet(tcp(CACHE, 6379, PC, 50000, b'+OK\r\n', server=6379))
        for i in range(5):
            f.analyze_packet(tcp(PC, 50000, CACHE, 6379, GET, server=6379, ts=T0 + i))
            f.analyze_packet(tcp(CACHE, 6379, PC, 50000, b'$5\r\nvalue\r\n', server=6379,
                                 ts=T0 + i + 0.01))
        self.assertEqual(redis_findings(f), [])

    def test_resp3_hello_with_auth_counts(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 50000, CACHE, 6379,
                             b'*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$4\r\nuser\r\n'
                             b'$8\r\nexample1\r\n', server=6379))
        f.analyze_packet(tcp(PC, 50000, CACHE, 6379, GET, server=6379, ts=T0 + 1))
        f.analyze_packet(tcp(CACHE, 6379, PC, 50000, b'$5\r\nvalue\r\n', server=6379,
                             ts=T0 + 1.01))
        self.assertEqual(redis_findings(f), [])

    def test_a_server_that_wants_a_password_is_not_open(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 50000, CACHE, 6379, GET, server=6379))
        f.analyze_packet(tcp(CACHE, 6379, PC, 50000,
                             b'-NOAUTH Authentication required.\r\n', server=6379))
        f.analyze_packet(tcp(PC, 50001, CACHE, 6379, GET, server=6379, ts=T0 + 1))
        self.assertEqual(redis_findings(f), [])

    def test_a_command_answered_without_a_password_is_open(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 50000, CACHE, 6379, GET, server=6379))
        self.assertEqual(redis_findings(f), [], 'not before the server answers')
        f.analyze_packet(tcp(CACHE, 6379, PC, 50000, b'$5\r\nvalue\r\n', server=6379))
        [finding] = redis_findings(f)
        self.assertEqual((finding['source_ip'], finding['destination_ip'], finding['port'],
                          finding['risk']), (PC, CACHE, 6379, 'CRITICAL'))


if __name__ == '__main__':
    unittest.main()
