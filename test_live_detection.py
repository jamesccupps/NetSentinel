"""
The IDS engine on this machine's own traffic.
==============================================
H1: should_skip_ids skipped every heuristic rule for this PC's own addresses, its
gateway, its DHCP servers and every DNS server including 8.8.8.8 and 1.1.1.1. The
unit tests built IDSEngine without a NetworkEnvironment, which is why none of
them noticed: the first class here uses a real one, detected on this machine.

The rest pin the feed-noise fixes (one alert per connection, the cloud-range
exemption, no guessed domains), the rule fixes that inspecting this machine's own
traffic made necessary, packet time, and the new rules the engine raises.
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from src.capture import PacketInfo  # noqa: E402
from src.ids_engine import IDSEngine  # noqa: E402

ENCODED = 'nbswy3dpeb3w64tmmqqgc3tjnzzsa5dimvzgkidjomqgcidtmvrxezlu'   # base32, 56 chars


def pkt(ts=None, **kw):
    p = PacketInfo()
    if ts is not None:
        p.timestamp = ts
    for k, v in kw.items():
        setattr(p, k, v)
    return p


def rules(alerts):
    return [a.rule_id for a in alerts]


class FakeIntel:
    """A threat-intel stand-in: answers from dicts, never touches a feed."""

    def __init__(self, ips=None, domains=None, urls=None, ja3=None, new=None):
        self.ips, self.domains = ips or {}, domains or {}
        self.urls, self.ja3, self.new = urls or {}, ja3 or {}, new or {}

    def check_ip(self, ip):
        return self.ips.get(ip)

    def check_domain(self, domain):
        return self.domains.get(domain)

    def check_url(self, url):
        return self.urls.get(url)

    def check_ja3(self, ja3):
        return self.ja3.get(ja3)

    def check_new_domain(self, domain):
        return self.new.get(domain)


def _engine(net_env=None, intel=None, **kw):
    alerts = []
    ids = IDSEngine(reset_config(), alert_callback=alerts.append, threat_intel=intel,
                    net_env=net_env, **kw)
    if getattr(ids, 'lan', None) is not None:
        ids.lan.state_path = None       # never write the shared test HOME's state
        ids.lan.state['gateway_macs'] = {}
    return ids, alerts


class TestOwnTrafficIsInspected(unittest.TestCase):
    """With the real NetworkEnvironment and this machine's own address."""

    @classmethod
    def setUpClass(cls):
        from src.net_detect import NetworkEnvironment
        cls.env = NetworkEnvironment().detect()
        cls.own = next((ip for ip in cls.env.local_ips
                        if ':' not in ip and not ip.startswith(('127.', '169.254.'))), None)

    def setUp(self):
        if not self.own:
            self.skipTest('this machine has no IPv4 address')

    def test_port_scan_from_this_machine(self):
        ids, alerts = _engine(self.env)
        for port in range(20, 45):
            ids.inspect_packet(pkt(src_ip=self.own, dst_ip='93.184.216.34', src_port=40000,
                                   dst_port=port, protocol='TCP', flags='S'))
        self.assertIn('PORT-SCAN', rules(alerts))

    def test_dns_tunnel_through_a_public_resolver(self):
        ids, alerts = _engine(self.env)
        ids.inspect_packet(pkt(src_ip=self.own, dst_ip='8.8.8.8', src_port=53000, dst_port=53,
                               protocol='UDP', dns_query=f'{ENCODED}.t.badtunnel.example'))
        self.assertIn('DNS-TUNNEL', rules(alerts))

    def test_large_upload_from_this_machine(self):
        ids, alerts = _engine(self.env)
        for _ in range(1100):
            ids.inspect_packet(pkt(src_ip=self.own, dst_ip='93.184.216.34', src_port=50000,
                                   dst_port=443, protocol='TCP', payload_size=100_000))
        self.assertIn('DATA-EXFIL', rules(alerts))

    def test_gateway_impersonation_is_seen(self):
        gateway = next((g for g in self.env.gateways if ':' not in g), None)
        if not gateway:
            self.skipTest('no IPv4 gateway detected')
        ids, alerts = _engine(self.env)
        for mac in ('00:11:22:33:44:55', '00:66:77:88:99:aa'):
            ids.inspect_packet(pkt(src_ip=gateway, dst_ip=self.own, protocol='ARP',
                                   arp_op=2, arp_hwsrc=mac, src_mac=mac))
        spoof = [a for a in alerts if a.rule_id == 'ARP-SPOOF']
        self.assertTrue(spoof)
        self.assertEqual(spoof[0].severity, 'CRITICAL')

    def test_dns_volume_to_the_own_resolver_is_exempt_but_not_elsewhere(self):
        ids, alerts = _engine(self.env)
        saved = list(self.env.configured_dns_servers)
        self.env.configured_dns_servers = ['192.168.1.1']
        try:
            for i in range(60):
                ids.inspect_packet(pkt(src_ip=self.own, dst_ip='192.168.1.1', dst_port=53,
                                       protocol='UDP', dns_query=f'site{i}.example.com'))
            self.assertNotIn('DNS-FLOOD', rules(alerts))
            for i in range(60):
                ids.inspect_packet(pkt(src_ip=self.own, dst_ip='9.9.9.9', dst_port=53,
                                       protocol='UDP', dns_query=f'other{i}.example.com'))
            self.assertIn('DNS-FLOOD', rules(alerts))
        finally:
            self.env.configured_dns_servers = saved


class TestThreatIntelNoise(unittest.TestCase):

    LISTED = '185.220.101.5'

    def test_one_alert_per_connection_not_per_direction(self):
        intel = FakeIntel(ips={self.LISTED: {'feed': 'feodo_c2', 'category': 'Botnet C2',
                                             'description': 'x'}})
        ids, alerts = _engine(intel=intel)
        ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip=self.LISTED, src_port=51000,
                               dst_port=443, protocol='TCP', flags='S'))
        ids.inspect_packet(pkt(src_ip=self.LISTED, dst_ip='192.168.1.5', src_port=443,
                               dst_port=51000, protocol='TCP', flags='SA'))
        hits = [a for a in alerts if a.rule_id == 'THREAT-INTEL-IP']
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].evidence['direction'], 'outbound')

    def test_attacker_feeds_spare_cloud_addresses_this_machine_connects_to(self):
        from src.cloud_ranges import CloudRanges
        cloud_ip = '52.95.110.1'
        attacker = {'feed': 'blocklist_de', 'category': 'Brute Force / Scanner',
                    'description': 'x', 'attacker_feed': True}
        ids, alerts = _engine(intel=FakeIntel(ips={cloud_ip: attacker}))
        ids.cloud_ranges = CloudRanges(
            {'providers': {'aws': {'kind': 'cloud', 'v4': ['52.95.0.0/16']}}})
        ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip=cloud_ip, src_port=51000,
                               dst_port=443, protocol='TCP', flags='S'))
        self.assertNotIn('THREAT-INTEL-IP', rules(alerts))
        self.assertEqual(ids.cloud_exempted, 1)
        # The same address scanning in is exactly what the feed is about.
        ids.inspect_packet(pkt(src_ip=cloud_ip, dst_ip='192.168.1.5', src_port=51515,
                               dst_port=22, protocol='TCP', flags='S'))
        self.assertIn('THREAT-INTEL-IP', rules(alerts))

    def test_c2_feeds_are_not_exempted_in_the_cloud(self):
        from src.cloud_ranges import CloudRanges
        c2 = {'feed': 'feodo_c2', 'category': 'Botnet C2', 'description': 'x'}
        ids, alerts = _engine(intel=FakeIntel(ips={'52.95.110.2': c2}))
        ids.cloud_ranges = CloudRanges(
            {'providers': {'aws': {'kind': 'cloud', 'v4': ['52.95.0.0/16']}}})
        ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip='52.95.110.2', src_port=51000,
                               dst_port=443, protocol='TCP', flags='S'))
        self.assertIn('THREAT-INTEL-IP', rules(alerts))

    def test_a_listed_address_is_not_given_the_last_name_looked_up(self):
        """How github.com came to be named in alerts about unrelated addresses."""
        intel = FakeIntel(ips={self.LISTED: {'feed': 'x', 'category': 'Botnet C2',
                                             'description': 'x'}})
        ids, alerts = _engine(intel=intel)
        ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip='192.168.1.1', dst_port=53,
                               protocol='UDP', dns_query='github.com'))
        ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip=self.LISTED, src_port=51000,
                               dst_port=443, protocol='TCP', flags='S'))
        hit = next(a for a in alerts if a.rule_id == 'THREAT-INTEL-IP')
        self.assertNotIn('github.com', hit.evidence['associated_domains'])
        self.assertNotIn('github.com', hit.description)

    def test_a_dns_response_does_not_repeat_the_domain_alert(self):
        bad = {'feed': 'urlhaus', 'category': 'Malware', 'description': 'x',
               'confidence': 'HIGH'}
        ids, alerts = _engine(intel=FakeIntel(domains={'evil.example': bad}))
        ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip='192.168.1.1', src_port=50000,
                               dst_port=53, protocol='UDP', dns_query='evil.example'))
        ids.inspect_packet(pkt(src_ip='192.168.1.1', dst_ip='192.168.1.5', src_port=53,
                               dst_port=50000, protocol='UDP', dns_query='evil.example',
                               dns_rcode=0, dns_answers=('203.0.113.9',)))
        self.assertEqual(rules(alerts).count('THREAT-INTEL-DOMAIN'), 1)

    def test_malware_url_is_matched_exactly(self):
        url = 'http://bad.example:8080/bins/x86'
        intel = FakeIntel(urls={url: {'feed': 'urlhaus_domains', 'category': 'Malware',
                                      'description': 'x', 'confidence': 'HIGH'}})
        ids, alerts = _engine(intel=intel)
        ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip='203.0.113.50', src_port=50000,
                               dst_port=8080, protocol='TCP', http_method='GET',
                               http_host='bad.example:8080', http_path='/bins/x86'))
        self.assertIn('THREAT-INTEL-URL', rules(alerts))

    def test_newly_registered_domain_is_a_low_note_once_a_day(self):
        fresh = {'registered_domain': 'fresh-login.example', 'description': 'new',
                 'lists_checked': '2026-10-27 to 2026-10-28'}
        ids, alerts = _engine(intel=FakeIntel(new={'www.fresh-login.example': fresh}))
        for _ in range(3):
            ids._alert_cooldowns.clear()
            ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip='192.168.1.1', dst_port=53,
                                   protocol='UDP', dns_query='www.fresh-login.example'))
        hits = [a for a in alerts if a.rule_id == 'NEWLY-REGISTERED-DOMAIN']
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].severity, 'LOW')

    def test_ja3_feed_match(self):
        listed = {'feed': 'sslbl_ja3', 'malware': 'Trickbot', 'last_seen': '2019'}
        ids, alerts = _engine(intel=FakeIntel(ja3={'abc123': listed}))
        ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip='203.0.113.60', src_port=50000,
                               dst_port=443, protocol='TCP', tls_ja3='abc123',
                               tls_sni='odd.example'))
        hit = [a for a in alerts if a.rule_id == 'TLS-FINGERPRINT-FEED']
        self.assertTrue(hit)
        self.assertEqual(hit[0].severity, 'MEDIUM')


class TestRulesOnOwnTraffic(unittest.TestCase):

    def test_peer_to_peer_fan_out_is_not_a_port_scan(self):
        ids, alerts = _engine()
        ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip='151.101.1.1', src_port=50000,
                               dst_port=443, protocol='TCP', flags='S'))
        for i in range(30):
            ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip=f'84.10.{i}.7', src_port=50001,
                                   dst_port=40000 + i * 97, protocol='UDP'))
        self.assertNotIn('PORT-SCAN', rules(alerts))

    def test_resets_to_a_web_server_are_not_brute_force(self):
        ids, alerts = _engine()
        for i in range(20):
            ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip='151.101.1.1',
                                   src_port=50000 + i, dst_port=443, protocol='TCP', flags='R'))
        self.assertNotIn('BRUTE-FORCE', rules(alerts))

    def test_an_ssh_server_refusing_one_client_is_brute_force(self):
        ids, alerts = _engine()
        for i in range(12):
            ids.inspect_packet(pkt(src_ip='192.168.1.20', dst_ip='203.0.113.66', src_port=22,
                                   dst_port=40000 + i, protocol='TCP', flags='R'))
        hit = [a for a in alerts if a.rule_id == 'BRUTE-FORCE']
        self.assertTrue(hit)
        self.assertEqual(hit[0].evidence['attacker_ip'], '203.0.113.66')


class TestPacketTime(unittest.TestCase):

    def test_windows_run_on_packet_time(self):
        """Sixty pings ten seconds apart are not a flood, however fast they are read."""
        ids, alerts = _engine()
        base = 1_700_000_000.0
        for i in range(60):
            ids.inspect_packet(pkt(ts=base + i * 10, src_ip='203.0.113.70',
                                   dst_ip='192.168.1.5', protocol='ICMP'))
        self.assertNotIn('ICMP-FLOOD', rules(alerts))
        for i in range(40):
            ids.inspect_packet(pkt(ts=base + 1000 + i * 0.1, src_ip='203.0.113.70',
                                   dst_ip='192.168.1.5', protocol='ICMP'))
        self.assertIn('ICMP-FLOOD', rules(alerts))

    def test_offline_alerts_carry_the_packet_time(self):
        ids, alerts = _engine(offline=True)
        ids.inspect_packet(pkt(ts=1_600_000_000.0, src_ip='192.168.1.5', dst_ip='10.0.0.9',
                               dst_port=4444, protocol='TCP', flags='S'))
        self.assertEqual(alerts[0].timestamp, 1_600_000_000.0)


class TestNewRules(unittest.TestCase):

    def test_mining_pool_lookup(self):
        ids, alerts = _engine()
        ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip='192.168.1.1', dst_port=53,
                               protocol='UDP', dns_query='gulf.moneroocean.stream'))
        self.assertIn('MINING-POOL', rules(alerts))

    def test_port_4444_to_a_pool_is_mining_not_metasploit(self):
        ids, alerts = _engine()
        ids.inspect_packet(pkt(src_ip='192.168.1.1', dst_ip='192.168.1.5', src_port=53,
                               dst_port=50000, protocol='UDP', dns_query='xmr.2miners.com',
                               dns_rcode=0, dns_answers=('198.18.0.40',)))
        ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip='198.18.0.40', src_port=50001,
                               dst_port=4444, protocol='TCP', flags='S'))
        self.assertNotIn('BAD-PORT', rules(alerts))
        self.assertIn('MINING-POOL', rules(alerts))

    def test_stratum_protocol(self):
        ids, alerts = _engine()
        ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip='198.18.0.41', src_port=50002,
                               dst_port=3333, protocol='TCP', app_protocol='stratum'))
        self.assertIn('MINING-STRATUM', rules(alerts))

    def test_untrusted_certificate_from_an_internet_server(self):
        from test_handshakes import make_cert
        ids, alerts = _engine()
        cert = make_cert(self_signed=True, expired=True)
        ids.inspect_packet(pkt(src_ip='45.155.205.80', dst_ip='192.168.1.5', src_port=443,
                               dst_port=50000, protocol='TCP', _tls_certs=(cert,)))
        hit = [a for a in alerts if a.rule_id == 'TLS-CERT-SELF-SIGNED']
        self.assertTrue(hit)
        self.assertIn('expired', hit[0].title)
        # A printer's self-signed certificate on the LAN is not news.
        ids.inspect_packet(pkt(src_ip='192.168.1.30', dst_ip='192.168.1.5', src_port=443,
                               dst_port=50001, protocol='TCP', _tls_certs=(cert,)))
        self.assertEqual(len([a for a in alerts if a.rule_id.startswith('TLS-CERT')]), 1)

    def test_geoip_fields_reach_the_evidence(self):
        class FakeGeo:
            def annotate(self, ip, prefix):
                return {f'{prefix}_country': 'DE', f'{prefix}_asn': 3320} \
                    if ip == '203.0.113.90' else {}

        ids, alerts = _engine()
        ids.geoip = FakeGeo()
        ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip='203.0.113.90', src_port=50000,
                               dst_port=4444, protocol='TCP', flags='S'))
        self.assertEqual(alerts[0].evidence['dst_country'], 'DE')
        self.assertNotIn('src_country', alerts[0].evidence)


if __name__ == '__main__':
    unittest.main()
