"""
Bounds and noise outside the engine: forensics, the device table, the IOC
scanner and the alert verifier.
=========================================================================
Live, these run as long as the app does. Forensics kept every flow, timeline
event, credential and finding forever; the device table grew by IP; the DGA
counter never reset. And a few findings were rated or filed wrongly.
"""

import os
import sys
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from src.capture import PacketInfo  # noqa: E402


def pkt(**kw):
    p = PacketInfo()
    for k, v in kw.items():
        setattr(p, k, v)
    return p


def http(ua, src='192.168.1.10', dst='93.184.216.34'):
    payload = f'GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: {ua}\r\n\r\n'.encode()
    return pkt(src_ip=src, dst_ip=dst, src_port=50000, dst_port=80, protocol='TCP',
               payload_size=len(payload), _raw_payload=payload)


class TestForensics(unittest.TestCase):

    def setUp(self):
        from src.forensics import NetworkForensics
        self.f = NetworkForensics()

    def test_curl_and_okhttp_are_not_attack_tools(self):
        """curl.exe ships with Windows; okhttp is Android's HTTP stack."""
        for ua in ('curl/8.4.0', 'okhttp/4.12.0'):
            self.f.analyze_packet(http(ua))
        risks = {d['value'].split('"')[1].split('/')[0]: d['risk'] for d in self.f.sensitive_data}
        self.assertEqual(risks, {'curl': 'LOW', 'okhttp': 'LOW'})
        self.assertFalse([s for s in self.f.security_findings
                          if s['type'] == 'malicious_user_agent'])

    def test_real_attack_tools_stay_critical(self):
        self.f.analyze_packet(http('Mozilla/5.0 (compatible; Nikto/2.5.0)'))
        self.assertEqual([d['risk'] for d in self.f.sensitive_data], ['CRITICAL'])

    def test_a_payload_is_scanned_once(self):
        """analyze_packet_with_payload scanned the same bytes twice."""
        payload = b'PASS hunter2secret\r\n'
        p = pkt(src_ip='192.168.1.10', dst_ip='198.51.100.5', src_port=40000, dst_port=21,
                protocol='TCP', payload_size=len(payload), _raw_payload=payload)
        self.f.analyze_packet_with_payload(p, payload)
        self.assertEqual(len(self.f.credentials_found), 1)

    def test_findings_are_capped_and_a_cursor_still_works(self):
        from src.forensics import MAX_CREDENTIALS
        cursor = 0
        seen = 0
        with self.assertLogs('NetSentinel.Forensics', level='WARNING'):
            for i in range(MAX_CREDENTIALS + 300):
                self.f._add_credential('FTP', 'password', '***', '10.0.0.1', '10.0.0.2', 21,
                                       time.time())
                new = self.f.credentials_found[cursor:]
                seen += len(new)
                cursor = len(self.f.credentials_found)
        self.assertEqual(seen, MAX_CREDENTIALS + 300, "an app cursor missed findings")
        self.assertEqual(len(list(self.f.credentials_found)), MAX_CREDENTIALS)

    def test_flows_and_timeline_are_capped(self):
        from src.forensics import MAX_FLOWS, MAX_TIMELINE
        for i in range(MAX_FLOWS + 500):
            self.f.analyze_packet(pkt(src_ip='10.0.0.1', dst_ip=f'10.{i // 65536}.{i // 256 % 256}.{i % 256}',
                                      dst_port=443, protocol='TCP', length=60, timestamp=i))
        self.assertLessEqual(len(self.f.flows), MAX_FLOWS)
        for i in range(MAX_TIMELINE + 50):
            self.f._add_timeline_event(time.time(), 'x', f'event {i}')
        self.assertEqual(len(list(self.f.timeline)), MAX_TIMELINE)

    def _name_answer(self, port, src_ip, mac):
        import struct
        name = b'\x0bfileserver1\x00'
        payload = struct.pack('>HHHHHH', 1, 0x8000, 0, 1, 0, 0) + name + \
            struct.pack('>HHIH', 1, 1, 30, 4) + bytes([192, 168, 1, 9])
        return pkt(src_ip=src_ip, dst_ip='192.168.1.10', src_port=port, dst_port=50000,
                   protocol='UDP', src_mac=mac, payload_size=len(payload),
                   _raw_payload=payload)

    def test_llmnr_is_not_filed_as_sensitive_data(self):
        self.f.analyze_packet(self._name_answer(5355, '192.168.1.9', '00:1b:21:00:00:09'))
        self.f.analyze_packet(self._name_answer(5355, '192.168.1.66', '00:1b:21:00:00:66'))
        self.assertFalse([d for d in self.f.sensitive_data if 'LLMNR' in d['data_type']])
        self.assertTrue([s for s in self.f.security_findings if s['type'] == 'name_poisoning'])

    def test_one_host_over_v4_and_v6_is_one_responder(self):
        self.f.analyze_packet(self._name_answer(5355, '192.168.1.9', '00:1b:21:00:00:09'))
        self.f.analyze_packet(self._name_answer(5355, 'fe80::9', '00:1b:21:00:00:09'))
        self.assertFalse([s for s in self.f.security_findings if s['type'] == 'name_poisoning'])
        self.assertFalse([d for d in self.f.sensitive_data if 'LLMNR' in d['data_type']],
                         "one host's IPv4 and IPv6 answers were two responders")

    def test_smbv1_is_an_insecure_service(self):
        payload = b'\x00\x00\x00\x2f\xffSMB\x72' + b'\x00' * 40
        for _ in range(6):
            self.f.analyze_packet(pkt(src_ip='192.168.1.10', dst_ip='192.168.1.20',
                                      src_port=50000, dst_port=445, protocol='TCP',
                                      payload_size=len(payload), _raw_payload=payload))
        self.assertFalse([d for d in self.f.sensitive_data if d['data_type'] == 'SMBv1'])
        svc = self.f.insecure_services.get(('192.168.1.20', 445, 'smbv1'))
        self.assertIsNotNone(svc)
        self.assertEqual((svc['service'], svc['risk']), ('SMBv1', 'CRITICAL'))
        self.assertGreaterEqual(svc['packet_count'], 5, "the app alerts from five packets")


class TestDeviceTable(unittest.TestCase):

    def test_a_device_that_changes_address_is_one_device(self):
        from src.device_learner import DeviceLearner
        dl = DeviceLearner(reset_config())
        dl.devices.clear()
        mac = '00:1b:21:aa:00:01'
        for ip in ('192.168.1.40', '192.168.1.41'):
            dl.observe_packet(pkt(src_ip=ip, dst_ip='8.8.8.8', src_mac=mac,
                                  protocol='UDP', dst_port=53, length=80))
        self.assertEqual(len(dl.devices), 1)
        dev = dl.get_device('192.168.1.41')
        self.assertEqual(dev.mac, mac)
        self.assertEqual(dev.packet_count, 2)
        self.assertIsNone(dl.get_device('192.168.1.40'))

    def test_the_table_is_capped(self):
        from src.device_learner import DeviceLearner
        cfg = reset_config(**{'analysis.max_devices': 50})
        try:
            dl = DeviceLearner(cfg)
            dl.devices.clear()
            for i in range(400):
                dl.observe_packet(pkt(src_ip=f'10.0.{i // 250}.{i % 250 + 1}', dst_ip='8.8.8.8',
                                      src_mac=f'00:1b:21:00:{i // 256:02x}:{i % 256:02x}',
                                      protocol='UDP', dst_port=53, length=80))
            self.assertLessEqual(len(dl.devices), 50)
        finally:
            reset_config(**{'analysis.max_devices': 2000})

    def test_a_router_mac_does_not_merge_routed_hosts(self):
        from src.device_learner import DeviceLearner
        dl = DeviceLearner(reset_config())
        dl.devices.clear()
        for i in range(10):
            dl.observe_packet(pkt(src_ip=f'10.9.0.{i + 1}', dst_ip='8.8.8.8',
                                  src_mac='00:1b:21:ff:ff:01', protocol='UDP', dst_port=53))
        self.assertGreaterEqual(len(dl.devices), 7)


class TestIocScanner(unittest.TestCase):

    def scanner(self, net_env=None):
        from src.ioc_scanner import IOCScanner
        return IOCScanner(reset_config(), net_env=net_env) if net_env else \
            IOCScanner(reset_config())

    DGA = ['xkqzvbnmtrwplh.com', 'qwrtzpsdfghjkl.net', 'zxcvbnmlkjhgfd.org',
           'mnbvcxzlkjhgfr.info', 'plkmnjuhbvgytf.biz', 'rtyuiopqwertzx.com']

    def test_dga_counts_a_burst_not_a_lifetime(self):
        s = self.scanner()
        t = 1_000_000.0
        for i, name in enumerate(self.DGA[:5]):
            found = s.check_packet_ioc(pkt(src_ip='10.0.0.5', dns_query=name, timestamp=t + i * 3600))
            self.assertFalse([f for f in found if f['rule_id'] == 'IOC-DGA'],
                             "five names over five hours are not a DGA burst")

    def test_dga_burst_alerts_once_then_resets(self):
        s = self.scanner()
        hits = []
        for i, name in enumerate(self.DGA):
            hits += [f for f in s.check_packet_ioc(pkt(src_ip='10.0.0.6', dns_query=name,
                                                       timestamp=2_000_000.0 + i))
                     if f['rule_id'] == 'IOC-DGA']
        self.assertEqual(len(hits), 1)

    def test_doh_and_tor_alert_once_per_connection(self):
        s = self.scanner()
        doh = tor = 0
        for i in range(20):
            found = s.check_packet_ioc(pkt(src_ip='10.0.0.7', dst_ip='1.1.1.1', dst_port=443,
                                           timestamp=3_000_000.0 + i))
            doh += sum(1 for f in found if f['rule_id'] == 'IOC-DOH-BYPASS')
            found = s.check_packet_ioc(pkt(src_ip='10.0.0.7', dst_ip='45.155.205.9',
                                           dst_port=9050, timestamp=3_000_000.0 + i))
            tor += sum(1 for f in found if f['rule_id'] == 'IOC-TOR')
        self.assertEqual((doh, tor), (1, 1))

    def test_port_9001_alone_is_not_tor(self):
        s = self.scanner()
        found = s.check_packet_ioc(pkt(src_ip='10.0.0.8', dst_ip='45.155.205.9', dst_port=9001))
        self.assertFalse([f for f in found if f['rule_id'] == 'IOC-TOR'])

    def test_the_configured_resolver_is_not_a_dns_bypass(self):
        env = SimpleNamespace(is_configured_resolver=lambda ip: ip == '1.1.1.1')
        found = self.scanner(env).check_packet_ioc(
            pkt(src_ip='10.0.0.9', dst_ip='1.1.1.1', dst_port=443))
        self.assertFalse([f for f in found if f['rule_id'] == 'IOC-DOH-BYPASS'])


class TestVerifierCdnPatterns(unittest.TestCase):

    def verdict(self, query, entropy=4.0):
        from src.alert_verify import AlertVerifier
        from src.ids_engine import Alert
        from src.net_detect import NetworkEnvironment
        env = NetworkEnvironment()
        env._cloud_domain_set = {'cloudfront.net'}
        v = AlertVerifier(reset_config(), net_env=env)
        alert = Alert('DNS-TUNNEL', 'HIGH', 't', 'd', evidence={
            'full_query': query, 'subdomain_entropy': entropy, 'query_length': len(query)})
        return v._verify_dns_tunnel(alert, alert.evidence)

    def test_a_hex_tunnel_is_not_exonerated_as_a_cdn(self):
        info = self.verdict('6f75726461746167656f6573686572656576657279626f6479.tunnel-domain.example')
        self.assertFalse([r for r in info['reasoning'] if 'CDN' in r])

    def test_cdn_words_count_only_as_whole_labels(self):
        info = self.verdict('mzlbxq2tkcdnr7vwe3pa5oqedgeu4yj.tunnel-domain.example')
        self.assertFalse([r for r in info['reasoning'] if 'CDN' in r])
        info = self.verdict('cdn-03.assets.example')
        self.assertTrue([r for r in info['reasoning'] if 'CDN' in r])

    def test_hashes_under_a_known_cdn_still_count(self):
        info = self.verdict('d3f4a8b9c0e1f2a3b4c5d6e7f8a9b0c1.cloudfront.net')
        self.assertTrue([r for r in info['reasoning'] if 'CDN' in r])


if __name__ == '__main__':
    unittest.main()
