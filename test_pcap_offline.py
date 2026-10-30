"""
Capture files through the live parser, on packet time.
=======================================================
H5: the analyser had its own older parser: no SNI, no DNS answers or response
codes, IPv6 with no ports. And every rule's window ran on the wall clock, so a
ten-minute capture replayed in a second looked like a ten-minute flood in a
second. H6: exact URL matching was never called, live or here.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import SCAPY_REAL, reset_config  # noqa: E402

if SCAPY_REAL:
    from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, Raw, DNS, DNSQR, wrpcap  # noqa: E402


@unittest.skipUnless(SCAPY_REAL, 'real scapy unavailable')
class TestPcapAnalysis(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='ns_pcap_')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def analyse(self, frames, intel=None, start=1_700_000_000.0, step=0.01):
        for i, frame in enumerate(frames):
            if not getattr(frame, '_timed', False):
                frame.time = start + i * step
        path = os.path.join(self.tmp, 'cap.pcap')
        wrpcap(path, frames)
        from src.pcap_analyzer import PcapAnalyzer
        analyzer = PcapAnalyzer(reset_config(), threat_intel=intel)
        return analyzer.analyze_file(path)

    @staticmethod
    def rules(result):
        return [a['rule_id'] for a in result['alerts']]

    def test_sni_from_a_hello_split_over_two_segments(self):
        from test_handshakes import big_hello
        record = big_hello(b'c2panel.xyz')
        frames = [Ether() / IP(src='192.168.1.5', dst='45.155.205.20') /
                  TCP(sport=50000, dport=443, seq=1000 + off, flags='PA') /
                  Raw(load=record[off:off + 1000]) for off in (0, 1000)]
        result = self.analyse(frames)
        self.assertIn('DNS-BAD-TLD', self.rules(result))

    def test_ipv6_ports_are_read(self):
        frames = [Ether(src='02:00:00:00:00:05', dst='02:00:00:00:00:09') /
                  IPv6(src='2001:db8::5', dst='2001:db8::9') /
                  TCP(sport=50000, dport=2222, flags='S')]
        result = self.analyse(frames)
        self.assertEqual(result['stats']['unique_dst_ports'], 1)
        self.assertEqual(result['stats']['protocols'].get('TCP'), 1)

    def test_dns_response_codes_reach_the_rules(self):
        frames = []
        for i in range(20):
            frames.append(Ether() / IP(src='192.168.1.1', dst='192.168.1.5') /
                          UDP(sport=53, dport=50000 + i) /
                          DNS(id=i, qr=1, rcode=3, qd=DNSQR(qname=f'xk{i}q.dga{i % 7}.example')))
        result = self.analyse(frames)
        self.assertIn('DNS-NXDOMAIN-BURST', self.rules(result))

    def test_windows_run_on_packet_time(self):
        frames = [Ether() / IP(src='45.155.205.30', dst='192.168.1.5') / ICMP()
                  for _ in range(60)]
        result = self.analyse(frames, step=10.0)          # one ping every ten seconds
        self.assertNotIn('ICMP-FLOOD', self.rules(result))
        self.assertEqual(result['stats']['capture_duration'], '590.0 seconds')

    def test_alerts_carry_the_packet_time(self):
        frames = [Ether() / IP(src='192.168.1.5', dst='10.0.0.9') /
                  TCP(sport=50000, dport=4444, flags='S')]
        result = self.analyse(frames, start=1_600_000_000.0)
        hit = [a for a in result['alerts'] if a['rule_id'] == 'BAD-PORT']
        self.assertTrue(hit)
        self.assertEqual(hit[0]['timestamp'], 1_600_000_000.0)

    def test_a_malware_url_in_the_capture(self):
        from test_live_detection import FakeIntel
        url = 'http://bad.example/payload.exe'
        intel = FakeIntel(urls={url: {'feed': 'urlhaus_domains', 'category': 'Malware',
                                      'description': 'x', 'confidence': 'HIGH'}})
        request = b'GET /payload.exe HTTP/1.1\r\nHost: bad.example\r\n\r\n'
        frames = [Ether() / IP(src='192.168.1.5', dst='45.155.205.40') /
                  TCP(sport=50000, dport=80, flags='PA') / Raw(load=request)]
        result = self.analyse(frames, intel=intel)
        self.assertIn('THREAT-INTEL-URL', self.rules(result))


if __name__ == '__main__':
    unittest.main()
