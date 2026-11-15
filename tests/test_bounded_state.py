"""
State that grew for as long as NetSentinel ran.
===============================================
The outside review of 2026-11-14 (N10):

- the app walked every insecure service not yet alerted on, on every packet,
  and those under 5 packets never left that list;
- forensics' dedup sets and per-server notes were never bounded;
- the vault was re-encrypted and rewritten whole for every new finding;
- the device learner's ARP targets were never pruned;
- a capture file's DNS queries were all kept in a list;
- the GeoIP download was inflated whole before its size was checked;
- NVD's totalResults set how many pages were asked for.
Addresses are made up.
"""

import gzip
import json
import os
import shutil
import sys
import time
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_detection_corpus import _Pipeline  # noqa: E402
from test_third_review import T0, tcp  # noqa: E402

PC = '192.168.10.32'


class TestInsecureServices(unittest.TestCase):

    def test_only_changed_services_are_looked_at(self):
        pipeline = _Pipeline()
        for i in range(300):                         # 300 servers, one packet each
            pipeline.forensics.analyze_packet(
                tcp(PC, 50000, f'192.168.10.{i % 250}', 23 if i < 250 else 21,
                    b'x' * 20, server=23 if i < 250 else 21))
        pipeline.app._check_forensics_alerts()
        services = pipeline.forensics.insecure_services
        self.assertGreater(len(services), 200)
        looked = []
        real = pipeline.app._insecure_service_named_today
        pipeline.app._insecure_service_named_today = lambda svc: looked.append(svc) or real(svc)
        pipeline.feed(*(tcp(PC, 50000, '192.168.10.7', 23, b'x' * 20, server=23,
                            ts=T0 + i) for i in range(1, 6)))
        self.assertEqual([s['ip'] for s in looked], ['192.168.10.7'])
        self.assertEqual(pipeline.forensics.services_touched, set())

    def test_a_service_still_alerts_at_five_packets(self):
        raised = _Pipeline().feed(*(tcp(PC, 50000, '192.168.10.7', 23, b'x' * 20, server=23,
                                        ts=T0 + i) for i in range(5)))
        self.assertIn('FORENSICS-INSECURE-SVC', [a.rule_id for a in raised])

    def test_services_and_dedup_sets_are_capped(self):
        from src import forensics as fx
        f = fx.NetworkForensics()
        with mock.patch.object(fx, 'MAX_SERVICES', 50), mock.patch.object(fx, 'MAX_CONTEXT_IPS', 50):
            for i in range(120):
                f.insecure_services[('10.9.0.%d' % i, 23)] = {
                    'packet_count': 1, 'first_seen': i}
                f._http_ua_alerted.add(('10.9.0.%d' % i, 'curl'))
            f._bound_context()
        self.assertEqual(len(f.insecure_services), 50)
        self.assertEqual(f._http_ua_alerted, set())


class TestTheVault(unittest.TestCase):

    def setUp(self):
        from src.config import DB_DIR
        shutil.rmtree(os.path.join(DB_DIR, 'forensics'), ignore_errors=True)
        self.addCleanup(shutil.rmtree, os.path.join(DB_DIR, 'forensics'), True)
        from src.forensics_db import ForensicsDB
        self.db = ForensicsDB(reset_config(**{'forensics.save_credentials': True,
                                              'forensics.vault_passphrase': ''}))

    def writes(self, n):
        calls = []
        real = self.db._save_encrypted
        self.db._save_encrypted = lambda path, data: calls.append(path) or real(path, data)
        for i in range(n):
            self.db.store_credential('ParkingCloud/GETEIP', 'heartbeat_token', '',
                                     f'token {i}', PC, '203.0.113.5', 9000, time.time())
        return calls

    def test_a_finding_a_minute_does_not_rewrite_the_vault_each_time(self):
        calls = self.writes(50)
        self.assertEqual(len(calls), 1)               # the first, then batched
        self.db.save_pending()
        from src.forensics_db import ForensicsDB
        self.assertEqual(len(ForensicsDB(reset_config()).search_credentials()), 50)

    def test_shutdown_writes_what_is_pending(self):
        self.writes(5)
        self.db.flush()
        from src.forensics_db import ForensicsDB
        self.assertEqual(len(ForensicsDB(reset_config()).search_credentials()), 5)


class TestSmallerThings(unittest.TestCase):

    def test_arp_targets_are_capped(self):
        from src.device_learner import ARP_TARGETS_KEPT, DeviceLearner
        learner = DeviceLearner(reset_config(), net_env=SimpleNamespace(
            local_ips=[PC], gateways=[], local_subnet='192.168.10.0/24'))
        learner.max_devices = 20
        for src in range(60):
            for dst in range(60):
                learner.observe_packet(SimpleNamespace(
                    src_ip=f'192.168.10.{src + 1}', dst_ip=f'192.168.10.{dst + 100}',
                    src_mac=f'00:00:5e:00:53:{src:02x}', dst_mac='', protocol='ARP',
                    src_port=0, dst_port=0, length=42, payload_size=0, timestamp=T0,
                    dns_query='', process_name='', ttl=64, tls_sni='', flags=''))
        self.assertLessEqual(len(learner._arp_response_targets), 20)
        self.assertTrue(all(len(t) <= ARP_TARGETS_KEPT
                            for t in learner._arp_response_targets.values()))

    def test_a_small_download_cannot_inflate_without_limit(self):
        from src import geoip
        bomb = gzip.compress(b'\0' * (5 * 1024 * 1024))
        with self.assertRaises(ValueError):
            geoip._gunzip(bomb, 1024 * 1024)
        self.assertEqual(geoip._gunzip(gzip.compress(b'abc'), 10), b'abc')

    def test_a_captures_dns_names_are_counted_not_kept(self):
        from _test_support import SCAPY_REAL
        if not SCAPY_REAL:
            self.skipTest('real scapy unavailable')
        import tempfile
        from scapy.all import DNS, DNSQR, IP, UDP, Ether, wrpcap
        from src import pcap_analyzer
        tmp = tempfile.mkdtemp(prefix='ns_dns_names_')
        self.addCleanup(shutil.rmtree, tmp, True)
        names = ['a.example', 'b.example', 'a.example', 'c.example', 'a.example', 'd.example']
        cap = os.path.join(tmp, 'dns.pcap')
        wrpcap(cap, [Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')
                     / IP(src=PC, dst='192.168.10.1') / UDP(sport=50000 + i, dport=53)
                     / DNS(rd=1, qd=DNSQR(qname=name)) for i, name in enumerate(names)])
        with mock.patch.object(pcap_analyzer, 'MAX_DNS_NAMES', 3):
            stats = pcap_analyzer.PcapAnalyzer(reset_config()).analyze_file(cap)['stats']
        self.assertEqual(stats['unique_dns_queries'], 3)              # d.example was past the cap
        self.assertEqual(stats['top_dns_queries'][0][1], 3)
        self.assertTrue(stats['dns_names_capped'])

    def test_nvd_cannot_ask_for_endless_pages(self):
        from src import vulns
        catalog = vulns.Catalog.__new__(vulns.Catalog)
        pages = []
        catalog._sleep = lambda s: None

        def fetch(url, limit):
            pages.append(url)
            if len(pages) > 3:              # the old loop went on for 500,000 pages
                raise AssertionError('kept asking for pages')
            return json.dumps({'totalResults': 10 ** 9,
                               'vulnerabilities': [{}] * 2000}).encode()
        catalog._fetch = fetch
        with self.assertRaises(ValueError):
            catalog._nvd_items()
        self.assertEqual(len(pages), 1)


if __name__ == '__main__':
    unittest.main()
