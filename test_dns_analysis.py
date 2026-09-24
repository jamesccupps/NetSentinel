"""
DNS response analysis.
======================
Like test_beaconing.py, these double as the calibration record. The benign cases
matter more than the malicious ones: NXDOMAIN and short TTLs are both completely
normal, and a detector that fires on them is worse than no detector.
"""

import os
import random
import string
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import SCAPY_REAL  # noqa: E402

from src.capture import PacketInfo  # noqa: E402
from src.config import Config  # noqa: E402
from src.dns_analysis import (  # noqa: E402
    DnsResponseMonitor, RCODE_NXDOMAIN, domain_entropy, looks_algorithmic,
)

T0 = 1_000_000.0


def rng():
    return random.Random(20260924)


def dga_name(r, length=15, tld='net'):
    return ''.join(r.choices(string.ascii_lowercase, k=length)) + '.' + tld


class TestDomainEntropy(unittest.TestCase):

    def test_repeated_characters_have_no_entropy(self):
        self.assertEqual(domain_entropy('aaaaaa'), 0.0)

    def test_varied_characters_have_more(self):
        self.assertGreater(domain_entropy('qwzxjvbnkm'), domain_entropy('aaabbbccc'))

    def test_empty_is_zero(self):
        self.assertEqual(domain_entropy(''), 0.0)


class TestAlgorithmicNameHeuristic(unittest.TestCase):
    """
    One input to a decision, never the decision. Optimised for a low false
    positive rate, because it is applied to every failing lookup on the network.
    """

    REAL_NAMES = [
        'google.com', 'cdn.cloudflare.net', 'outlook.office365.com',
        'my-company-intranet.local', 'a1b2c3d4e5f6.cdn.example.com',
        'wikipedia.org', 'stackoverflow.com', 'news.ycombinator.com',
        'login.microsoftonline.com', 's3.eu-west-1.amazonaws.com',
        'fonts.gstatic.com', 'dev-api-staging.internal',
        'build-agent-07.ci.example.com', 'pkg-cache.example.net',
        'telemetry.mozilla.org', 'ocsp.digicert.com',
        'safebrowsing.googleapis.com', 'mail.corp.local',
        'db-primary.prod.example.com', 'grafana.monitoring.svc',
    ]

    def test_no_false_positives_on_realistic_names(self):
        flagged = [n for n in self.REAL_NAMES if looks_algorithmic(n)]
        self.assertEqual(flagged, [], f"false positives: {flagged}")

    def test_catches_a_useful_share_of_generated_names(self):
        r = rng()
        names = [dga_name(r, r.randint(12, 18)) for _ in range(100)]
        caught = sum(1 for n in names if looks_algorithmic(n))
        self.assertGreater(caught / len(names), 0.5,
                           "should flag most machine-generated names")

    def test_short_names_are_never_flagged(self):
        for name in ('bbc.co.uk', 'x.com', 'abc.io'):
            self.assertFalse(looks_algorithmic(name))

    def test_hex_hashes_are_not_treated_as_generated(self):
        """CDN cache keys are long and high-entropy but not DGA output."""
        self.assertFalse(looks_algorithmic('deadbeefcafe1234567890ab.cdn.example.com'))

    def test_hyphenated_names_are_human(self):
        self.assertFalse(looks_algorithmic('my-company-intranet.local'))
        self.assertFalse(looks_algorithmic('zzxkq-vvbnm-jjhgf.example.com'))

    def test_handles_empty_and_odd_input(self):
        for name in ('', '.', '...', 'a'):
            self.assertIsInstance(looks_algorithmic(name), bool)


class TestNxdomainBursts(unittest.TestCase):

    def setUp(self):
        self.m = DnsResponseMonitor()
        self.r = rng()

    def _fail(self, name, src='192.168.1.50', ts=T0):
        return self.m.observe_response(src, name, RCODE_NXDOMAIN, timestamp=ts)

    def test_chrome_startup_probe_does_not_fire(self):
        """Chrome issues 3 random lookups at startup to detect ISP hijacking."""
        findings = []
        for i in range(3):
            findings += self._fail(dga_name(self.r, 10, 'com'), ts=T0 + i)
        self.assertEqual(findings, [])

    def test_windows_suffix_search_does_not_fire(self):
        """One failed name multiplied by several configured search suffixes."""
        findings = []
        for i in range(12):
            findings += self._fail(f'printer.corp{i % 3}.local', ts=T0 + i)
        self.assertEqual(findings, [])

    def test_repeated_failures_against_one_domain_do_not_fire(self):
        """A broken service, not a DGA."""
        findings = []
        for i in range(40):
            findings += self._fail('api.broken-service.com', ts=T0 + i * 0.5)
        self.assertEqual(findings, [])

    def test_dga_burst_fires(self):
        findings = []
        for i in range(40):
            findings += self._fail(dga_name(self.r), ts=T0 + i * 0.5)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f['type'], 'nxdomain_burst')
        self.assertEqual(f['severity'], 'HIGH')
        self.assertGreater(f['algorithmic_ratio'], 0.5)
        self.assertEqual(f['src_ip'], '192.168.1.50')

    def test_non_algorithmic_burst_is_only_medium(self):
        """
        Many failures over ordinary-looking names across DIFFERENT domains is odd
        but not alarming — a stale config or a dead partner integration.
        """
        findings = []
        words = ['mail', 'intranet', 'printer', 'backup', 'wiki', 'vpn', 'jira',
                 'sharepoint', 'confluence', 'jenkins', 'nexus', 'gitlab',
                 'sonar', 'redmine', 'bamboo', 'artifactory', 'phabricator',
                 'teamcity', 'octopus', 'rundeck']
        for i, word in enumerate(words):
            findings += self._fail(f'{word}.old-company-{i}.com', ts=T0 + i * 0.5)
        self.assertTrue(findings, "a burst across distinct domains should report")
        self.assertEqual(findings[0]['severity'], 'MEDIUM',
                         "ordinary-looking names are not DGA-grade evidence")

    def test_failures_spread_over_time_do_not_fire(self):
        """The window is what makes it a burst."""
        findings = []
        for i in range(40):
            findings += self._fail(dga_name(self.r), ts=T0 + i * 30)
        self.assertEqual(findings, [])

    def test_only_reports_once_per_cooldown(self):
        for i in range(40):
            self._fail(dga_name(self.r), ts=T0 + i * 0.5)
        later = []
        for i in range(40):
            later += self._fail(dga_name(self.r), ts=T0 + 20 + i * 0.5)
        self.assertEqual(later, [], "should not re-report inside the cooldown")

    def test_separate_hosts_are_tracked_separately(self):
        findings = []
        for i in range(20):
            findings += self._fail(dga_name(self.r), src='192.168.1.60', ts=T0 + i * 0.5)
            findings += self._fail(dga_name(self.r), src='192.168.1.61', ts=T0 + i * 0.5)
        self.assertEqual(len({f['src_ip'] for f in findings}), 2)


class TestFastFlux(unittest.TestCase):

    def setUp(self):
        self.m = DnsResponseMonitor()

    def _resolve(self, name, addresses, ttl, ts):
        return self.m.observe_response('192.168.1.50', name, 0, addresses, ttl, ts)

    def test_cdn_short_ttl_stable_addresses_does_not_fire(self):
        """Cloudflare and Akamai answer with 60s TTLs by design."""
        findings = []
        for i in range(30):
            findings += self._resolve('cdn.example.com', ['104.16.1.1', '104.16.1.2'],
                                      60, T0 + i * 10)
        self.assertEqual(findings, [])

    def test_load_balancer_many_addresses_long_ttl_does_not_fire(self):
        findings = []
        for i in range(30):
            findings += self._resolve('lb.example.org', [f'93.184.{i}.{i}'],
                                      86400, T0 + i * 10)
        self.assertEqual(findings, [])

    def test_many_addresses_and_short_ttl_fires(self):
        findings = []
        for i in range(20):
            findings += self._resolve('flux.example.net', [f'93.184.{i}.{i}'],
                                      60, T0 + i * 10)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f['type'], 'fast_flux')
        self.assertEqual(f['domain'], 'flux.example.net')
        self.assertGreaterEqual(f['address_count'], 8)
        self.assertLessEqual(f['min_ttl'], 300)

    def test_addresses_outside_the_window_are_forgotten(self):
        findings = []
        for i in range(20):
            findings += self._resolve('slow.example.net', [f'93.184.{i}.{i}'],
                                      60, T0 + i * 3600)
        self.assertEqual(findings, [])

    def test_cname_answers_are_not_counted_as_addresses(self):
        findings = []
        for i in range(20):
            findings += self._resolve('alias.example.com', [f'target{i}.example.com'],
                                      60, T0 + i * 10)
        self.assertEqual(findings, [])

    def test_ipv6_answers_count(self):
        findings = []
        for i in range(20):
            findings += self._resolve('flux6.example.net', [f'2001:db8::{i}'],
                                      60, T0 + i * 10)
        self.assertTrue(findings)


class TestMonitorHousekeeping(unittest.TestCase):

    def test_stats_report_what_was_seen(self):
        m = DnsResponseMonitor()
        m.observe_response('192.168.1.50', 'a.com', 0, ['1.2.3.4'], 300, T0)
        m.observe_response('192.168.1.50', 'b.com', RCODE_NXDOMAIN, timestamp=T0)
        stats = m.get_stats()
        self.assertEqual(stats['responses_seen'], 2)
        self.assertEqual(stats['nxdomain_seen'], 1)
        self.assertAlmostEqual(stats['nxdomain_ratio'], 0.5)

    def test_address_to_domain_mapping(self):
        m = DnsResponseMonitor()
        m.observe_response('192.168.1.50', 'a.example.com', 0, ['1.2.3.4'], 300, T0)
        m.observe_response('192.168.1.50', 'b.example.org', 0, ['1.2.3.4'], 300, T0)
        self.assertEqual(m.domains_for_address('1.2.3.4'),
                         {'example.com', 'example.org'})

    def test_queries_and_malformed_input_are_ignored(self):
        m = DnsResponseMonitor()
        self.assertEqual(m.observe_response('1.2.3.4', 'a.com', -1), [])
        self.assertEqual(m.observe_response('1.2.3.4', '', 0), [])
        self.assertEqual(m.observe_response('1.2.3.4', None, 3), [])

    def test_state_does_not_grow_without_bound(self):
        m = DnsResponseMonitor()
        r = rng()
        for i in range(3000):
            m.observe_response('192.168.1.50', dga_name(r), 0,
                               [f'93.{i % 256}.{i % 251}.1'], 300, T0 + i)
        self.assertLess(len(m._resolutions), 3000,
                        "resolutions should be pruned as the window moves")


class TestIdsIntegration(unittest.TestCase):

    def setUp(self):
        from src.ids_engine import IDSEngine
        cfg = Config().load()
        cfg.set('threat_intel', 'auto_update', False)
        self.alerts = []
        self.ids = IDSEngine(cfg, alert_callback=self.alerts.append)
        self.r = rng()

    def _response(self, query, rcode=0, answers=(), ttl=-1, ts=T0):
        p = PacketInfo()
        p.src_ip, p.dst_ip = '192.168.1.1', '192.168.1.50'
        p.src_port, p.dst_port, p.protocol = 53, 51000, 'UDP'
        p.dns_query, p.dns_rcode = query, rcode
        p.dns_answers, p.dns_ttl, p.timestamp, p.length = tuple(answers), ttl, ts, 90
        return p

    def _rules(self):
        return [a.rule_id for a in self.alerts]

    def test_dga_burst_raises_an_alert(self):
        for i in range(40):
            self.ids.inspect_packet(self._response(dga_name(self.r), 3, ts=T0 + i * 0.5))
        self.assertIn('DNS-NXDOMAIN-BURST', self._rules())

    def test_fast_flux_raises_an_alert(self):
        for i in range(20):
            self.ids.inspect_packet(self._response(
                'flux.example.net', 0, [f'93.184.{i}.{i}'], 60, T0 + i * 10))
        self.assertIn('DNS-FAST-FLUX', self._rules())

    def test_normal_dns_traffic_raises_nothing(self):
        for i in range(30):
            self.ids.inspect_packet(self._response(
                'cdn.cloudflare.net', 0, ['104.16.1.1', '104.16.1.2'], 60, T0 + i * 10))
        for i in range(3):
            self.ids.inspect_packet(self._response(dga_name(self.r, 10, 'com'), 3, ts=T0 + i))
        self.assertEqual([r for r in self._rules() if r.startswith('DNS-')], [])

    def test_alert_evidence_is_actionable(self):
        for i in range(40):
            self.ids.inspect_packet(self._response(dga_name(self.r), 3, ts=T0 + i * 0.5))
        alert = next(a for a in self.alerts if a.rule_id == 'DNS-NXDOMAIN-BURST')
        for key in ('failed_lookups', 'distinct_domains', 'sample_domains',
                    'machine_generated_ratio', 'recommendation'):
            self.assertIn(key, alert.evidence)

    def test_dns_stats_surface_on_the_engine(self):
        self.ids.inspect_packet(self._response('a.com', 0, ['1.2.3.4'], 300))
        self.assertIn('dns', self.ids.get_stats())


@unittest.skipUnless(SCAPY_REAL, 'real scapy unavailable')
class TestResponseExtraction(unittest.TestCase):
    """Capture must surface rcode, TTL and every answer, not just the first."""

    def setUp(self):
        from src.capture import CaptureEngine
        cfg = Config().load()
        cfg.set('threat_intel', 'auto_update', False)
        self.engine = CaptureEngine(cfg)

    def _dissect(self, pkt):
        from scapy.all import Ether
        return Ether(bytes(pkt))

    def test_all_answers_and_the_lowest_ttl(self):
        from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR
        answers = (DNSRR(rrname='example.com', type='A', ttl=300, rdata='93.184.216.34') /
                   DNSRR(rrname='example.com', type='A', ttl=60, rdata='93.184.216.35') /
                   DNSRR(rrname='example.com', type='A', ttl=120, rdata='93.184.216.36'))
        pkt = (Ether() / IP() / UDP(sport=53, dport=51000) /
               DNS(qr=1, qd=DNSQR(qname='example.com'), an=answers, ancount=3))
        info = self.engine._extract_packet_info(self._dissect(pkt))
        self.assertEqual(len(info.dns_answers), 3)
        self.assertEqual(info.dns_ttl, 60)
        self.assertEqual(info.dns_rcode, 0)

    def test_nxdomain_carries_its_question(self):
        """Responses had no question name, so an answer could not be correlated."""
        from scapy.all import Ether, IP, UDP, DNS, DNSQR
        pkt = (Ether() / IP() / UDP(sport=53, dport=51000) /
               DNS(qr=1, rcode=3, qd=DNSQR(qname='nope.example.com')))
        info = self.engine._extract_packet_info(self._dissect(pkt))
        self.assertEqual(info.dns_query, 'nope.example.com')
        self.assertEqual(info.dns_rcode, 3)
        self.assertEqual(info.dns_answers, ())

    def test_a_query_is_not_mistaken_for_a_response(self):
        from scapy.all import Ether, IP, UDP, DNS, DNSQR
        pkt = (Ether() / IP() / UDP(sport=51000, dport=53) /
               DNS(rd=1, qd=DNSQR(qname='ask.example.com')))
        info = self.engine._extract_packet_info(self._dissect(pkt))
        self.assertEqual(info.dns_query, 'ask.example.com')
        self.assertEqual(info.dns_rcode, -1)

    def test_cname_targets_are_decoded(self):
        from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR
        pkt = (Ether() / IP() / UDP(sport=53, dport=51000) /
               DNS(qr=1, qd=DNSQR(qname='www.example.com'),
                   an=DNSRR(rrname='www.example.com', type='CNAME', ttl=3600,
                            rdata='example.com'), ancount=1))
        info = self.engine._extract_packet_info(self._dissect(pkt))
        self.assertEqual(info.dns_answers, ('example.com',))


if __name__ == '__main__':
    unittest.main(verbosity=2)
