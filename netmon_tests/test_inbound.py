"""
Inbound HTTPS from outside Cloudflare, and the frames it arrives in.
====================================================================
Two pieces. Router deduplication dropped every inbound internet frame: on a
trunk mirror they carry the router's MAC and a source address that is not the
router's, which is what a relayed duplicate looks like — but they have no
first copy, so nothing about inbound traffic survived. And with them back, a
site that publishes through Cloudflare can be told when its origin is being
reached around it, well above the background of scanners.

Addresses: documentation ranges, the example profile's internal ones, and two
inside Cloudflare's published ranges.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.events import Event, enrich  # noqa: E402
from netmon.handlers import inbound_volume  # noqa: E402
from netmon.profile import CLOUDFLARE_RANGES, ProfileError, SiteProfile, load_profile  # noqa: E402
from netmon.redact import redact_finding  # noqa: E402
from netmon.rules_engine import load_rules  # noqa: E402
from netmon.sources.pcap import _RouterDedup  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')
RULES = os.path.join(ROOT, 'netmon', 'rules')

ROUTER = '00:11:22:00:00:50'
CLOUDFLARE_IP = '104.16.1.1'
SCANNER = '203.0.113.9'
DAY = 86400.0 * 20_000


def profile(**cloudflare):
    import yaml
    with open(EXAMPLE, encoding='utf-8') as handle:
        data = yaml.safe_load(handle)
    data['cloudflare'] = cloudflare or {'origins': ['bas-server']}
    return SiteProfile(data)


# ─── The frames ──────────────────────────────────────────────────────────────

class TestRouterDedup(unittest.TestCase):

    def setUp(self):
        self.dedup = _RouterDedup([ROUTER], {'10.10.20.1'})

    def event(self, src_ip, src_mac=ROUTER, dst_ip='10.10.20.10'):
        return Event(kind='flow', src_ip=src_ip, dst_ip=dst_ip, src_mac=src_mac)

    def test_an_inbound_internet_frame_is_kept(self):
        """The only copy there is."""
        self.assertFalse(self.dedup.should_drop(self.event(SCANNER)))
        self.assertFalse(self.dedup.should_drop(self.event('2001:db8::5')))
        self.assertEqual(self.dedup.kept_from_internet, 2)

    def test_the_relayed_copy_of_internal_traffic_is_still_dropped(self):
        self.assertTrue(self.dedup.should_drop(self.event('10.10.60.50')))
        self.assertEqual(self.dedup.dropped, 1)

    def test_the_router_speaking_for_itself_is_kept(self):
        self.assertFalse(self.dedup.should_drop(self.event('10.10.20.1')))

    def test_other_senders_are_untouched(self):
        self.assertFalse(self.dedup.should_drop(
            self.event(SCANNER, src_mac='00:11:22:00:00:01')))


try:
    from scapy.all import Ether, IP, TCP, Dot1Q, wrpcap
    HAVE_SCAPY = True
except Exception:                                              # pragma: no cover
    HAVE_SCAPY = False


@unittest.skipUnless(HAVE_SCAPY, 'needs scapy to write a capture')
class TestThroughACapture(unittest.TestCase):

    def test_inbound_frames_reach_the_rules(self):
        from netmon.sources.pcap import read_pcap
        scratch = tempfile.mkdtemp(prefix='netmon-inbound-')
        self.addCleanup(shutil.rmtree, scratch, True)
        path = os.path.join(scratch, 'in.pcap')
        wrpcap(path, [
            # Arriving from the internet, relayed onto VLAN 20 by the router.
            Ether(src=ROUTER, dst='00:11:22:00:00:01') / Dot1Q(vlan=20)
            / IP(src=SCANNER, dst='10.10.20.10') / TCP(sport=40000, dport=443),
            # A routed internal frame's second appearance.
            Ether(src=ROUTER, dst='00:11:22:00:00:01') / Dot1Q(vlan=20)
            / IP(src='10.10.60.50', dst='10.10.20.10') / TCP(dport=443),
        ])
        events = list(read_pcap(path, load_profile(EXAMPLE)))
        self.assertEqual([e.src_ip for e in events], [SCANNER])


# ─── Cloudflare's ranges ─────────────────────────────────────────────────────

class TestRanges(unittest.TestCase):

    def test_the_shipped_list_is_dated_and_parses(self):
        with open(CLOUDFLARE_RANGES, encoding='utf-8') as handle:
            text = handle.read()
        self.assertIn('Recorded: ', text)
        self.assertIn('cloudflare.com/ips-v4', text)
        self.assertGreaterEqual(len(load_profile(EXAMPLE).cloudflare_ranges), 20)

    def test_membership(self):
        site = load_profile(EXAMPLE)
        self.assertTrue(site.is_cloudflare(CLOUDFLARE_IP))
        self.assertTrue(site.is_cloudflare('2606:4700::1'))
        self.assertFalse(site.is_cloudflare(SCANNER))
        self.assertFalse(site.is_cloudflare('not an address'))

    def test_the_profile_can_replace_the_list(self):
        site = profile(origins=['bas-server'], ranges=['192.0.2.0/24'])
        self.assertTrue(site.is_cloudflare('192.0.2.7'))
        self.assertFalse(site.is_cloudflare(CLOUDFLARE_IP))

    def test_a_bad_range_is_refused_by_name(self):
        with self.assertRaises(ProfileError) as ctx:
            profile(origins=['x'], ranges=['not-a-network'])
        self.assertIn('cloudflare.ranges', str(ctx.exception))

    def test_the_data_file_is_not_read_as_rules(self):
        self.assertTrue(all(not r.id.startswith('1') for r in load_rules(RULES)))


class TestEnrichment(unittest.TestCase):

    def test_the_flags(self):
        site = profile()
        inbound = enrich(Event(kind='flow', src_ip=CLOUDFLARE_IP,
                               dst_ip='10.10.20.10', dst_port=443), site)
        self.assertTrue(inbound.get('src_is_cloudflare'))
        self.assertTrue(inbound.get('dst_cloudflare_origin'))
        other = enrich(Event(kind='flow', src_ip=SCANNER, dst_ip='10.10.20.21',
                             dst_port=443), site)
        self.assertFalse(other.get('src_is_cloudflare'))
        self.assertFalse(other.get('dst_cloudflare_origin'))

    def test_origins_by_role_and_by_network(self):
        for spec, ip in (('automation_server', '10.10.20.10'),
                         ('10.10.30.0/24', '10.10.30.10'), ('10.10.60.50', '10.10.60.50')):
            with self.subTest(spec=spec):
                self.assertTrue(profile(origins=[spec]).is_cloudflare_origin(ip))

    def test_no_origins_means_none(self):
        self.assertFalse(load_profile(EXAMPLE).is_cloudflare_origin('10.10.20.10'))


# ─── The handler ─────────────────────────────────────────────────────────────

class _Rule:
    id = 'inbound_https_bypass'
    title = 'Inbound HTTPS from outside Cloudflare'
    severity = 'high'
    tier = 'push'
    next_check = ''

    def __init__(self, **params):
        self.params = dict({'ports': [443], 'min_bytes': 1_000_000, 'multiple': 4,
                            'min_days': 1}, **params)


class TestTheHandler(unittest.TestCase):

    def setUp(self):
        self.site = profile()
        self.rule = _Rule()
        self.state = {}

    def hit(self, src, size, day=0, dst='10.10.20.10', port=443):
        event = enrich(Event(kind='flow', ts=DAY + day * 86400 + 3600, src_ip=src,
                             dst_ip=dst, dst_port=port, protocol='tcp',
                             bytes_to_dst=size), self.site)
        return inbound_volume(event, self.rule, self.state)

    def test_the_first_day_is_learning(self):
        self.assertIsNone(self.hit(SCANNER, 50_000_000))

    def test_a_day_well_above_the_usual_is_reported(self):
        self.hit(SCANNER, 200_000)                      # yesterday's scanners
        found = self.hit('198.51.100.7', 5_000_000, day=1)
        self.assertIsNotNone(found)
        self.assertIn('bas-server', found.description)
        self.assertIn('outside Cloudflare', found.description)
        self.assertEqual(found.evidence['source_count'], 1)
        self.assertEqual(found.evidence['median_bytes'], 200_000)

    def test_an_origin_that_usually_hears_only_from_cloudflare(self):
        """Its usual level is nothing, which is a baseline, not a missing one."""
        self.hit(CLOUDFLARE_IP, 80_000_000)
        found = self.hit(SCANNER, 2_000_000, day=1)
        self.assertIsNotNone(found)
        self.assertIn('nothing on a usual day', found.description)

    def test_cloudflare_traffic_never_counts(self):
        self.hit(SCANNER, 200_000)
        self.assertIsNone(self.hit(CLOUDFLARE_IP, 500_000_000, day=1))

    def test_below_the_floor_or_the_multiple_is_quiet(self):
        self.hit(SCANNER, 2_000_000)
        self.assertIsNone(self.hit(SCANNER, 500_000, day=1))         # floor
        self.assertIsNone(self.hit(SCANNER, 5_000_000, day=1))       # < 4x

    def test_reported_once_a_day(self):
        self.hit(SCANNER, 100_000)
        self.assertIsNotNone(self.hit(SCANNER, 5_000_000, day=1))
        self.assertIsNone(self.hit(SCANNER, 5_000_000, day=1))

    def test_hosts_that_are_not_origins_are_ignored(self):
        self.hit(SCANNER, 100_000, dst='10.10.20.21')
        self.assertIsNone(self.hit(SCANNER, 50_000_000, day=1, dst='10.10.20.21'))

    def test_other_ports_are_ignored_unless_listed(self):
        self.hit(SCANNER, 100_000, port=8443)
        self.assertIsNone(self.hit(SCANNER, 50_000_000, day=1, port=8443))
        self.rule = _Rule(ports=[8443])
        self.state = {}
        self.hit(SCANNER, 100_000, port=8443)
        self.assertIsNotNone(self.hit(SCANNER, 50_000_000, day=1, port=8443))

    def test_sources_are_bounded(self):
        for n in range(500):
            self.hit(f'198.51.100.{n % 250}' if n < 250 else f'203.0.113.{n % 250}',
                     10)
        self.assertLessEqual(len(self.state['days']['10.10.20.10'][int(
            (DAY + 3600) // 86400)][1]), 200)

    def test_old_days_are_forgotten(self):
        for day in range(40):
            self.hit(SCANNER, 10, day=day)
        self.assertLessEqual(len(self.state['days']['10.10.20.10']), 32)


class TestTheShippedRule(unittest.TestCase):

    def test_end_to_end_and_through_redaction(self):
        site = profile()
        rules = load_rules(RULES)
        found = []
        for day, src, size in ((0, SCANNER, 100_000), (1, '198.51.100.7', 9_000_000)):
            event = enrich(Event(kind='flow', ts=DAY + day * 86400, src_ip=src,
                                 dst_ip='10.10.20.10', dst_port=443, protocol='tcp',
                                 bytes_to_dst=size), site)
            found += [f for f in rules.evaluate(event)
                      if f.rule_id == 'inbound_https_bypass']
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].tier, 'push')
        record = redact_finding(found[0], site)
        self.assertEqual(record['evidence']['sources'], ['198.51.100.7'])

    def test_inert_without_origins(self):
        site = load_profile(EXAMPLE)
        rules = load_rules(RULES)
        for day in (0, 1):
            event = enrich(Event(kind='flow', ts=DAY + day * 86400, src_ip=SCANNER,
                                 dst_ip='10.10.20.10', dst_port=443, protocol='tcp',
                                 bytes_to_dst=10 ** 8 * (day + 1)), site)
            self.assertFalse([f for f in rules.evaluate(event)
                              if f.rule_id == 'inbound_https_bypass'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
