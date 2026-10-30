"""
The packet-side VLAN leak check.
================================
Metadata-only segments are kept off the disk by the capture filter. What was
missing:

- nothing noticed when restricted frames were on disk anyway — in a rotated
  capture, or when an extract had to leave some out;
- nothing looked for restricted traffic outside its VLAN: untagged, under
  another tag, or inside QinQ, all invisible to a filter that tests the tag;
- the filter excluded by tag only, and read a QinQ (0x88a8) frame as untagged;
- the parser decided "restricted" from the outer 802.1Q tag Scapy reported,
  which for 802.1ad is the *inner* one, and never from the addresses — so a
  routed copy of a door controller's traffic was parsed above the transport
  header;
- `bpf --verify` exited 0 whatever it found, and `diagnose_untagged()` was
  unreachable from the command line (and defined after `__main__` ran).

The example profile's restricted VLANs are 40 (10.10.40.0/24) and 50
(10.10.50.0/24); its router is 00:11:22:00:00:50.
"""

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import _test_support  # noqa: E402,F401

from netmon import bpf  # noqa: E402
from netmon.leakcheck import LeakCounter, Restricted, frame_layout  # noqa: E402
from netmon.profile import load_profile  # noqa: E402
from netmon.redact import AI, redact_finding  # noqa: E402
from netmon_tests._support import HAVE_TCPDUMP, matched_vlans  # noqa: E402

try:
    from scapy.all import DNS, DNSQR, Dot1Q, Ether, IP, IPv6, TCP, UDP, wrpcap
    from scapy.layers.l2 import Dot1AD
    import scapy.all as scapy_all
    HAVE_SCAPY = hasattr(scapy_all, 'PcapReader')
except Exception:                                              # pragma: no cover
    HAVE_SCAPY = False

requires_scapy = unittest.skipUnless(HAVE_SCAPY, 'needs scapy to build frames')
requires_tools = unittest.skipUnless(HAVE_SCAPY and HAVE_TCPDUMP,
                                     'needs scapy and tcpdump')

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')
PROFILE = load_profile(EXAMPLE)

ROUTER = '00:11:22:00:00:50'
DOOR = '00:11:22:00:00:20'          # door-panel-north, 10.10.40.10, VLAN 40
OTHER = '00:11:22:33:44:55'


def frame(tags=(), src='10.10.20.21', dst='10.10.20.10', src_mac=OTHER,
          dst_mac='00:aa:bb:cc:dd:ee', stag=False, dns=False, dport=443):
    packet = Ether(src=src_mac, dst=dst_mac)
    for index, tag in enumerate(tags):
        packet /= Dot1AD(vlan=tag) if (stag and index == 0) else Dot1Q(vlan=tag)
    packet /= IP(src=src, dst=dst)
    if dns:
        packet /= UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname='secret.example.test'))
    else:
        packet /= TCP(dport=dport)
    return Ether(bytes(packet))


# ─── Reading frames as bytes ─────────────────────────────────────────────────

@requires_scapy
class TestFrameLayout(unittest.TestCase):

    def test_untagged(self):
        layout = frame_layout(bytes(frame()))
        self.assertEqual(layout['tags'], [])
        self.assertEqual((layout['src_ip'], layout['dst_ip']),
                         ('10.10.20.21', '10.10.20.10'))

    def test_single_and_stacked_tags(self):
        self.assertEqual(frame_layout(bytes(frame([20])))['tags'], [20])
        layout = frame_layout(bytes(frame([40, 20], stag=True)))
        self.assertEqual(layout['tags'], [40, 20])
        self.assertEqual(layout['tpids'], [0x88a8, 0x8100])
        self.assertEqual(layout['src_ip'], '10.10.20.21')

    def test_0x9100_which_scapy_does_not_dissect(self):
        raw = bytes(Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02', type=0x9100) / Dot1Q(vlan=40) / Dot1Q(vlan=20)
                    / IP(src='10.10.40.10', dst='10.10.20.10') / TCP())
        layout = frame_layout(raw)
        self.assertEqual(layout['tags'], [40, 20])
        self.assertEqual(layout['src_ip'], '10.10.40.10')

    def test_ipv6(self):
        raw = bytes(Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / Dot1Q(vlan=20) / IPv6(src='2001:db8::1',
                                                     dst='2001:db8::2') / TCP())
        self.assertEqual(frame_layout(raw)['dst_ip'], '2001:db8::2')

    def test_a_runt_does_not_raise(self):
        self.assertEqual(frame_layout(b'\x00' * 10)['tags'], [])


# ─── The parser's payload prohibition ────────────────────────────────────────

@requires_scapy
class TestThePayloadProhibition(unittest.TestCase):
    """Nothing above the transport header from a restricted segment, by any
    measure — tag anywhere in the stack, or address."""

    def events(self, packet):
        from netmon.sources.pcap import packet_to_events
        return packet_to_events(packet, PROFILE, scapy_all)

    def assertMetadataOnly(self, packet):
        events = self.events(packet)
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0].fields.get('metadata_only'))
        self.assertNotIn('query', events[0].fields)
        return events[0]

    def test_an_ordinary_segment_is_parsed(self):
        events = self.events(frame([20], dns=True))
        self.assertEqual(events[0].fields.get('query'), 'secret.example.test')

    def test_the_restricted_tag_inside_qinq(self):
        """Scapy reported the inner tag (20) as the frame's VLAN."""
        event = self.assertMetadataOnly(frame([40, 20], stag=True, dns=True))
        self.assertEqual(event.vlan, 40)
        self.assertEqual(event.fields['vlan_stack'], [40, 20])

    def test_the_restricted_tag_as_the_inner_of_two(self):
        self.assertMetadataOnly(frame([20, 40], dns=True))

    def test_a_routed_copy_with_a_restricted_address(self):
        self.assertMetadataOnly(frame([20], src='10.10.40.10', src_mac=ROUTER,
                                      dns=True))

    def test_a_restricted_address_untagged(self):
        self.assertMetadataOnly(frame([], dst='10.10.50.20', dns=True))


# ─── Restricted traffic outside its VLAN ─────────────────────────────────────

@requires_scapy
class TestOutsideItsVlan(unittest.TestCase):

    def counter(self, on_disk=False, profile=PROFILE):
        return LeakCounter(profile, on_disk=on_disk, source='netmon-1.pcap')

    def feed(self, counter, *packets):
        for packet in packets:
            counter.observe(bytes(packet), 1000.0)
        return counter.findings()

    def test_the_restricted_vlan_untagged(self):
        found = self.feed(self.counter(), frame([], src='10.10.40.10', src_mac=DOOR))
        self.assertEqual([f.rule_id for f in found], ['restricted_outside_vlan'])
        self.assertIn('door-panel-north', found[0].description)
        self.assertIn('untagged', found[0].description)

    def test_under_another_vlans_tag(self):
        found = self.feed(self.counter(), frame([20], src='10.10.40.10', src_mac=DOOR))
        self.assertIn('tagged VLAN 20', found[0].description)
        self.assertEqual(found[0].evidence['observed_vlan'], 20)

    def test_inside_qinq(self):
        found = self.feed(self.counter(), frame([30, 40], stag=True))
        self.assertEqual([f.rule_id for f in found], ['restricted_outside_vlan'])
        self.assertIn('QinQ', found[0].description)

    def test_a_routed_copy_is_routing_not_a_mistake(self):
        self.assertEqual(self.feed(self.counter(), frame(
            [20], src='10.10.40.10', src_mac=ROUTER)), [])
        self.assertEqual(self.feed(self.counter(), frame(
            [20], dst='10.10.40.10', dst_mac=ROUTER)), [])

    def test_without_routers_only_the_devices_own_mac_is_judged(self):
        import yaml
        from netmon.profile import SiteProfile
        with open(EXAMPLE, encoding='utf-8') as handle:
            data = yaml.safe_load(handle)
        data['router_macs'] = []
        no_routers = SiteProfile(data)
        self.assertEqual(self.feed(self.counter(profile=no_routers), frame(
            [20], src='10.10.40.10', src_mac=OTHER)), [])
        self.assertEqual(len(self.feed(self.counter(profile=no_routers), frame(
            [20], src='10.10.40.10', src_mac=DOOR))), 1)

    def test_its_own_vlan_is_fine(self):
        counter = self.counter()
        self.assertEqual(self.feed(counter, frame([40], src='10.10.40.10',
                                                  src_mac=DOOR)), [])
        self.assertEqual(counter.restricted_frames, 1)

    def test_repeats_are_counted_in_one_finding(self):
        packet = frame([], src='10.10.40.10', src_mac=DOOR)
        found = self.feed(self.counter(), *([packet] * 25))
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].evidence['count'], 25)

    def test_never_sent_to_a_model(self):
        found = self.feed(self.counter(on_disk=True),
                          frame([], src='10.10.40.10', src_mac=DOOR))
        for finding in found:
            with self.subTest(rule=finding.rule_id):
                self.assertIsNone(redact_finding(finding, PROFILE, audience=AI))


@requires_scapy
class TestOnDisk(unittest.TestCase):

    def test_any_restricted_frame_in_a_rotated_capture_is_a_leak(self):
        counter = LeakCounter(PROFILE, on_disk=True, source='netmon-1.pcap')
        for packet in (frame([40], src='10.10.40.10', src_mac=DOOR),
                       frame([40], src='10.10.40.10', src_mac=DOOR),
                       frame([20], src='10.10.40.10', src_mac=ROUTER),
                       frame([20])):
            counter.observe(bytes(packet), 1000.0)
        leaks = [f for f in counter.findings()
                 if f.rule_id == 'restricted_capture_leak']
        self.assertEqual(len(leaks), 1)
        self.assertEqual(leaks[0].severity, 'critical')
        self.assertEqual(leaks[0].tier, 'push')
        self.assertEqual(leaks[0].evidence['count'], 3)
        self.assertIn('netmon-1.pcap', leaks[0].description)
        self.assertIn('2 tagged VLAN 40', leaks[0].description)

    def test_a_sample_is_not_a_leak(self):
        """An unfiltered sample has them on purpose."""
        counter = LeakCounter(PROFILE, on_disk=False)
        counter.observe(bytes(frame([40], src='10.10.40.10', src_mac=DOOR)))
        self.assertEqual(counter.findings(), [])
        self.assertEqual(counter.restricted_frames, 1)

    def test_a_profile_with_no_restricted_segment_counts_nothing(self):
        from netmon.profile import SiteProfile
        counter = LeakCounter(SiteProfile({}), on_disk=True)
        counter.observe(bytes(frame([40])))
        self.assertEqual(counter.findings(), [])


def _capture(directory, name, packets):
    path = os.path.join(directory, name)
    wrpcap(path, packets)
    return path


@requires_scapy
class TestTheServiceAndTheCommand(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-leak-')
        self.addCleanup(shutil.rmtree, self.scratch, True)

    def test_the_service_reports_a_leaking_ring(self):
        from netmon.service import Service, ServiceConfig
        ring = os.path.join(self.scratch, 'ring')
        os.makedirs(ring)
        now = time.time()
        for when in (now - 3600, now):
            _capture(ring, time.strftime('netmon-%Y%m%d-%H%M%S.pcap',
                                         time.localtime(when)),
                     [frame([40], src='10.10.40.10', src_mac=DOOR), frame([20])])
        config = ServiceConfig(profile_path=EXAMPLE, ring_dir=ring,
                               state_dir=os.path.join(self.scratch, 'state'),
                               notify=False)
        config.web_port = None
        found = Service(config).analyse_new_captures()
        self.assertIn('restricted_capture_leak', [f.rule_id for f in found])

    def run_analyze(self, *extra):
        from netmon.analyze import _main
        path = _capture(self.scratch, 'sample.pcap',
                        [frame([40], src='10.10.40.10', src_mac=DOOR), frame([20])])
        out = io.StringIO()
        with redirect_stdout(out):
            _main(['--profile', EXAMPLE, '--pcap', path, *extra])
        return out.getvalue()

    def test_analyze_treats_a_capture_as_a_sample_by_default(self):
        text = self.run_analyze()
        self.assertNotIn('restricted_capture_leak', text)
        self.assertIn('1 frames from metadata-only segments, read as metadata only',
                      text)

    def test_from_ring_reports_the_leak(self):
        data = json.loads(self.run_analyze('--from-ring', '--json'))
        self.assertIn('restricted_capture_leak',
                      [f['rule_id'] for f in data['findings']])


@requires_scapy
class TestExtraction(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-extract-')
        self.addCleanup(shutil.rmtree, self.scratch, True)

    def test_restricted_frames_are_left_out_by_address_and_stacked_tag(self):
        from netmon.ringbuffer import RingBuffer
        when = time.time() - 600
        packets = [frame([20]), frame([40], src='10.10.40.10'),
                   frame([20], src='10.10.40.10', src_mac=ROUTER),
                   frame([30, 40], stag=True), frame([], dst='10.10.50.20')]
        for packet in packets:
            packet.time = when
        _capture(self.scratch, time.strftime('netmon-%Y%m%d-%H%M%S.pcap',
                                             time.localtime(when - 60)), packets)
        result = RingBuffer(self.scratch, PROFILE).extract(when, seconds=60)
        self.assertEqual(result['packets'], 1)
        self.assertEqual(result['excluded_restricted'], 4)

    def test_an_extract_that_left_some_out_pushes_a_leak_once(self):
        from netmon.alerting import Notifier, NotifierConfig
        from netmon.events import Event, Finding

        class _Ring:
            def extract_for_finding(self, finding, seconds=30):
                return {'path': '/x.pcap', 'packets': 3, 'excluded_restricted': 7,
                        'from_files': ['netmon-20261029-030000.pcap']}

        notifier = Notifier(NotifierConfig(server='https://ntfy.example.test',
                                           topic='t', dry_run=True),
                            PROFILE, ring=_Ring())
        alert = Finding('bacnet_control', 't', severity='critical', tier='push',
                        description='a write', event=Event(kind='bacnet',
                                                           src_ip='10.10.60.50'))
        sent, _ = notifier.send([alert])
        self.assertEqual([f.rule_id for f in sent],
                         ['bacnet_control', 'restricted_capture_leak'])
        sent, _ = notifier.send([alert])
        self.assertEqual([f.rule_id for f in sent], ['bacnet_control'])


# ─── The capture filter ──────────────────────────────────────────────────────

class TestTheFilterText(unittest.TestCase):

    def test_the_profile_filter_names_the_restricted_subnets(self):
        filt = bpf.from_profile(PROFILE)
        self.assertIn('0x0a0a2800', filt)                       # 10.10.40.0
        self.assertIn('0x0a0a3200', filt)                       # 10.10.50.0
        self.assertIn('0x88a8', filt)

    def test_the_exclusions_use_no_vlan_keyword(self):
        for filt in (bpf.exclude_networks(['10.10.40.0/24', '2001:db8:40::/48']),
                     bpf.exclude_vlans([40, 50])):
            with self.subTest(filt=filt[:40]):
                self.assertEqual(re.findall(r'(?<![\w\[])vlan\b', filt), [])

    def test_at_most_one_vlan_keyword_in_anything_built(self):
        """Two in a row shift the second's untagged branch."""
        filt = bpf.build_capture_filter(vlans=[20], drop_hosts=['10.0.30.10'],
                                        drop_ports=[554], extra='udp',
                                        never_vlans=[40],
                                        never_networks=['10.10.40.0/24'])
        self.assertEqual(len(re.findall(r'(?<![\w\[])vlan\b', filt)), 1)

    def test_tagged_only_does_not_use_the_bare_keyword(self):
        filt = bpf.build_capture_filter(include_untagged=False, drop_ports=[554])
        self.assertEqual(len(re.findall(r'(?<![\w\[])vlan\b', filt)), 1)

    def test_a_whole_address_space_is_refused(self):
        with self.assertRaises(ValueError):
            bpf.exclude_networks(['0.0.0.0/0'])

    def test_ipv6_prefixes_compare_whole_words(self):
        filt = bpf.exclude_networks(['2001:db8:40::/48'])
        self.assertIn('0x86dd', filt)
        self.assertIn('== 0x20010db8', filt)
        self.assertIn('& 0xffff0000 == 0x00400000', filt)

    def test_the_restricted_subnets_helper(self):
        self.assertEqual(bpf.restricted_networks(PROFILE),
                         ['10.10.40.0/24', '10.10.50.0/24'])


@requires_tools
class TestTheFilterAgainstFrames(unittest.TestCase):
    """What actually survives, by tcpdump."""

    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.mkdtemp(prefix='netmon-leakfilter-')
        cls.frames = [
            ('ordinary', frame([20])),
            ('mgmt', frame([], src='10.10.1.2', dst='10.10.1.1', dport=22)),
            ('v40 tagged', frame([40], src='10.10.40.10')),
            ('v40 untagged', frame([], src='10.10.40.10')),
            ('v40 routed onto 20', frame([20], src='10.10.40.10', src_mac=ROUTER)),
            ('to a kiosk under 60', frame([60], src='10.10.60.50', dst='10.10.50.20')),
            ('qinq s40', frame([40, 20], stag=True)),
            ('double, 40 inner', frame([20, 40])),
            ('qinq, kiosk inside', frame([20, 30], src='10.10.50.20', stag=True)),
        ]
        cls.path = _capture(cls.scratch, 'mixed.pcap', [f for _, f in cls.frames])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.scratch, ignore_errors=True)

    def kept(self, filt):
        result = subprocess.run(['tcpdump', '-r', self.path, '-nn', '-e', filt],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return len(result.stdout.splitlines())

    def test_only_the_ordinary_frames_survive_the_profile_filter(self):
        self.assertEqual(self.kept(bpf.from_profile(PROFILE)), 2)

    def test_verify_counts_what_it_let_through_from_restricted_segments(self):
        report = bpf.verify_filter('', self.path, restricted_vlans=[40, 50],
                                   restricted_nets=['10.10.40.0/24',
                                                    '10.10.50.0/24'])
        self.assertEqual(sum(report['restricted_kept'].values()), 7)
        clean = bpf.verify_filter(bpf.from_profile(PROFILE), self.path,
                                  restricted_vlans=[40, 50],
                                  restricted_nets=['10.10.40.0/24',
                                                   '10.10.50.0/24'])
        self.assertEqual(clean['restricted_kept'], {'vlan': 0, 'address': 0})

    def test_dropping_a_host_and_a_port_drops_both_untagged(self):
        """
        Two both-forms terms in a row: the second's untagged branch read
        shifted bytes, so untagged RTSP survived a filter dropping port 554.
        """
        scratch = tempfile.mkdtemp(prefix='netmon-rtsp-')
        self.addCleanup(shutil.rmtree, scratch, True)
        path = _capture(scratch, 'rtsp.pcap', [
            frame([], dport=554), frame([20], dport=554),
            frame([], src='10.0.30.10'), frame([30], src='10.0.30.10'),
            frame([]), frame([20])])
        filt = bpf.build_capture_filter(drop_hosts=['10.0.30.10'],
                                        drop_ports=[554])
        self.assertEqual(matched_vlans(filt, path), ({20: 1}, 1))


class TestTheCommand(unittest.TestCase):

    def run_main(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = bpf._main(list(argv))
        return code, out.getvalue()

    def test_verify_exits_non_zero_when_restricted_traffic_gets_through(self):
        leaky = {'filter': '', 'total': 10, 'matched': 10, 'by_vlan': {40: 3},
                 'untagged_matched': 7, 'vlans_present': {40: 3},
                 'untagged_present': 7, 'vlans_dropped': [],
                 'restricted_present': {'vlan': 3, 'address': 1},
                 'restricted_kept': {'vlan': 3, 'address': 1}}
        with mock.patch.object(bpf, 'verify_filter', return_value=leaky) as called:
            code, text = self.run_main('--profile', EXAMPLE, '--verify', 's.pcap')
        self.assertEqual(code, bpf.EXIT_RESTRICTED_KEPT)
        self.assertIn('RESTRICTED TRAFFIC KEPT', text)
        self.assertEqual(called.call_args.kwargs['restricted_vlans'], [40, 50])

    def test_and_zero_when_nothing_does(self):
        clean = {'filter': '', 'total': 1, 'matched': 1, 'by_vlan': {},
                 'untagged_matched': 1, 'vlans_present': {}, 'untagged_present': 1,
                 'vlans_dropped': [], 'restricted_present': {'vlan': 0, 'address': 0},
                 'restricted_kept': {'vlan': 0, 'address': 0}}
        with mock.patch.object(bpf, 'verify_filter', return_value=clean):
            code, _ = self.run_main('--profile', EXAMPLE, '--verify', 's.pcap')
        self.assertEqual(code, bpf.EXIT_OK)

    def test_an_unverifiable_capture_is_an_error(self):
        with mock.patch.object(bpf, 'verify_filter',
                               return_value={'error': 'tcpdump not found'}):
            code, _ = self.run_main('--profile', EXAMPLE, '--verify', 's.pcap')
        self.assertEqual(code, bpf.EXIT_ERROR)

    def test_diagnose_untagged_is_a_flag(self):
        good = {'ethertype': {'correct': True}, 'not-vlan': {'correct': True},
                'recommended': 'ethertype', 'mixed_form_trustworthy': True}
        with mock.patch.object(bpf, 'diagnose_untagged', return_value=good):
            code, text = self.run_main('--diagnose-untagged', 's.pcap')
        self.assertEqual(code, bpf.EXIT_OK)
        self.assertIn('"recommended": "ethertype"', text)

    def test_an_untrustworthy_stack_exits_non_zero(self):
        bad = {'ethertype': {'correct': False}, 'not-vlan': {'correct': True},
               'recommended': 'not-vlan', 'mixed_form_trustworthy': False}
        with mock.patch.object(bpf, 'diagnose_untagged', return_value=bad):
            code, text = self.run_main('--diagnose-untagged', 's.pcap')
        self.assertEqual(code, bpf.EXIT_NO_TRUSTWORTHY_FORM)
        self.assertIn('separately', text)

    def test_it_works_as_a_module(self):
        """diagnose_untagged was defined after `if __name__ == '__main__'`, so
        running the module reached _main before the function existed."""
        env = dict(os.environ, PYTHONIOENCODING='utf-8')
        result = subprocess.run(
            [sys.executable, '-m', 'netmon.bpf', '--diagnose-untagged',
             os.path.join(tempfile.gettempdir(), 'no-such-sample.pcap')],
            cwd=ROOT, capture_output=True, text=True, env=env, timeout=60)
        self.assertNotIn('NameError', result.stderr)
        self.assertEqual(result.returncode, bpf.EXIT_ERROR, result.stderr)


@requires_tools
class TestDiagnoseAgainstASample(unittest.TestCase):

    def test_it_recommends_a_form_on_this_stack(self):
        from netmon_tests._support import PcapFixture
        self.addCleanup(PcapFixture.cleanup)
        report = bpf.diagnose_untagged(PcapFixture.path())
        self.assertIn(report['recommended'], ('ethertype', 'not-vlan'))


class TestRestrictedIndex(unittest.TestCase):

    def test_segment_lookup(self):
        index = Restricted(PROFILE)
        self.assertEqual(index.segment_of('10.10.40.99').id, 40)
        self.assertIsNone(index.segment_of('10.10.20.10'))
        self.assertIsNone(index.segment_of('not-an-ip'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
