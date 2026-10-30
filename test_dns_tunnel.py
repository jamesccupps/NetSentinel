"""
DNS tunnelling, fast-flux next to CDNs, and the ML DNS rate.
=============================================================
The old DNS-TUNNEL rule was "query longer than 60 characters", whatever was in
it, and ignored ids.dns_tunnel_max_subdomain_len. Tunnels that kept each name
short, or carried data back in TXT records, were never seen.
"""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from src.capture import PacketInfo  # noqa: E402
from src.dns_analysis import DnsTunnelMonitor, DnsResponseMonitor  # noqa: E402


def encoded(n, seed=0):
    """Base32 of pseudo-random bytes, lowercase, as a tunnel sends it."""
    data = bytes((i * 131 + seed * 17 + 7) % 256 for i in range(n))
    return base64.b32encode(data).decode().rstrip('=').lower()


def query(src, name, qtype=1, ts=None):
    p = PacketInfo()
    p.src_ip, p.dst_ip, p.protocol, p.src_port, p.dst_port = src, '192.168.1.1', 'UDP', 53000, 53
    p.dns_query, p.dns_qtype = name, qtype
    if ts is not None:
        p.timestamp = ts
    return p


class TestTunnelMonitor(unittest.TestCase):

    def setUp(self):
        self.mon = DnsTunnelMonitor(reset_config())

    def kinds(self, findings):
        return [f['type'] for f in findings]

    def test_a_long_encoded_name(self):
        name = f'{encoded(40)}.t.tunnel-domain.example'
        self.assertIn('long_name', self.kinds(self.mon.observe_query('10.0.0.5', name, 1, 1.0)))

    def test_a_long_repetitive_name_is_not_a_tunnel(self):
        name = ('a' * 30) + '.' + ('b' * 30) + '.example.com'
        self.assertEqual(self.mon.observe_query('10.0.0.5', name, 1, 1.0), [])

    def test_the_configured_length_is_used(self):
        cfg = reset_config(**{'ids.dns_tunnel_max_subdomain_len': 20})
        try:
            mon = DnsTunnelMonitor(cfg)
            name = f'{encoded(16)}.short.example'          # 26 encoded characters
            self.assertIn('long_name', self.kinds(mon.observe_query('10.0.0.5', name, 1, 1.0)))
            self.assertEqual(self.mon.observe_query('10.0.0.5', name, 1, 1.0), [])
        finally:
            reset_config(**{'ids.dns_tunnel_max_subdomain_len': 50})

    def test_many_short_names_under_one_domain(self):
        found = []
        for i in range(120):
            found += self.mon.observe_query('10.0.0.6', f'{encoded(10, i)}.data.exfil.example',
                                            1, 100.0 + i)
        self.assertIn('volume', self.kinds(found))

    def test_a_txt_heavy_rate(self):
        found = []
        for i in range(30):
            found += self.mon.observe_query('10.0.0.7', f'c{i}.cmd.c2-domain.example', 16,
                                            200.0 + i)
        self.assertIn('rate', self.kinds(found))

    def test_reputation_lookups_and_service_records_are_left_alone(self):
        for name in (f'{encoded(40)}.avqs.mcafee.com', f'{encoded(40)}.sophosxl.net',
                     f'sel1._domainkey.{encoded(40)}.example.com', 'x.y.local'):
            with self.subTest(name=name[:30]):
                self.assertEqual(self.mon.observe_query('10.0.0.8', name, 16, 1.0), [])

    def test_bounded(self):
        for i in range(5000):
            self.mon.observe_query(f'10.1.{i // 250}.{i % 250}', f'h{i}.d{i}.example', 1, 1.0)
        self.assertLessEqual(len(self.mon._pairs), 2048)


class TestEngineRaisesTunnelAlerts(unittest.TestCase):

    def test_engine_alerts_and_keeps_the_verifier_fields(self):
        from src.ids_engine import IDSEngine
        alerts = []
        ids = IDSEngine(reset_config(), alert_callback=alerts.append)
        ids.inspect_packet(query('10.0.0.9', f'{encoded(40)}.t.tunnel-domain.example'))
        hit = [a for a in alerts if a.rule_id == 'DNS-TUNNEL']
        self.assertTrue(hit)
        for field in ('full_query', 'query_length', 'subdomain_entropy'):
            self.assertIn(field, hit[0].evidence)
        self.assertGreater(hit[0].evidence['subdomain_entropy'], 3.3)

    def test_a_long_readable_name_does_not_alert(self):
        """Over 60 characters used to be enough."""
        from src.ids_engine import IDSEngine
        alerts = []
        ids = IDSEngine(reset_config(), alert_callback=alerts.append)
        ids.inspect_packet(query('10.0.0.9', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
                                             '.example.com'))
        self.assertNotIn('DNS-TUNNEL', [a.rule_id for a in alerts])


class TestFastFluxBesideCdns(unittest.TestCase):

    def _flux(self, mon, name, addresses):
        out = []
        for i, addr in enumerate(addresses):
            out += mon.observe_response('10.0.0.5', name, 0, (addr,), 30, 1000.0 + i)
        return [f for f in out if f['type'] == 'fast_flux']

    def test_cdn_names_and_cdn_addresses_are_not_fast_flux(self):
        mon = DnsResponseMonitor(reset_config())
        self.assertEqual(self._flux(mon, 'e1234.a.akamaiedge.net',
                                    [f'23.{i}.1.1' for i in range(12)]), [])
        # Cloudflare's own published range, under a name nobody knows.
        self.assertEqual(self._flux(mon, 'shop.unknown-brand.example',
                                    [f'104.16.{i}.1' for i in range(12)]), [])

    def test_residential_churn_still_is(self):
        mon = DnsResponseMonitor(reset_config())
        self.assertTrue(self._flux(mon, 'pharma.flux-domain.example',
                                   [f'{80 + i}.{30 + i}.5.{9 + i}' for i in range(12)]))


class TestMlDnsRate(unittest.TestCase):

    def test_rate_is_per_second_of_the_window_given(self):
        """The analysis window is 5 s, but the rate divided by 60."""
        from src.ml_engine import AnomalyDetector
        det = AnomalyDetector(reset_config())
        packets = []
        for i in range(300):                    # 60 queries a second for 5 seconds
            p = query('10.0.0.5', f'n{i}.example.com', ts=1000.0 + i / 60)
            packets.append(p)
        self.assertGreater(det._check_dns_anomalies(packets), 0.0)


if __name__ == '__main__':
    unittest.main()
