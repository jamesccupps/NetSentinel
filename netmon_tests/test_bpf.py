"""
BPF filter construction, checked against tcpdump.
==================================================
These tests do not assert on filter *text*. A BPF filter that compiles and reads
correctly can still match the wrong frames — that is the entire problem with
802.1Q in BPF — so every test here runs the generated filter over a synthetic
capture and asserts on which VLANs came out the other side.

The two tests that matter most are the ones proving the obvious hand-written
forms are wrong: `TestTheWrongFormsAreWrong` documents, by running them, why the
builder refuses to emit the `vlan` keyword for mixed tagged/untagged selection.
"""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon_tests._support import (HAVE_SCAPY, HAVE_TCPDUMP, PcapFixture,  # noqa: E402
                                   matched_vlans)
from netmon import bpf  # noqa: E402

requires_tools = unittest.skipUnless(
    HAVE_SCAPY and HAVE_TCPDUMP,
    'needs scapy to build frames and tcpdump to match them')


# ─── Text-level checks (cheap, no tools needed) ──────────────────────────────

class TestConstruction(unittest.TestCase):

    def test_tag_field_is_masked_to_twelve_bits(self):
        """The upper 4 bits of the tag field are PCP and DEI, not the VLAN id."""
        self.assertEqual(bpf.tag_field_expr(5), 'ether[14:2] & 0x0fff == 5')

    def test_never_emits_a_second_vlan_keyword(self):
        """`vlan 5 or vlan 6` shifts offsets twice and silently misses VLAN 6."""
        filt = bpf.vlan_filter([5, 6])
        self.assertNotIn('vlan 5', filt)
        self.assertNotIn('vlan 6', filt)
        self.assertEqual(filt.count('ether[14:2]'), 2)

    def test_mixed_selection_avoids_the_vlan_keyword_entirely(self):
        """Because `vlan` shifts offsets across `or`. See the module docstring."""
        filt = bpf.vlan_filter([5, 6], include_untagged=True)
        self.assertNotIn('vlan', filt.replace('ether', ''))

    def test_no_vlans_and_no_untagged_means_no_filter(self):
        """Empty reads as 'capture everything', which is the honest answer."""
        self.assertEqual(bpf.vlan_filter([]), '')

    def test_untagged_only(self):
        self.assertEqual(bpf.vlan_filter([], include_untagged=True),
                         'ether[12:2] != 0x8100')

    def test_ids_are_deduplicated_and_ordered(self):
        """Same selection, same filter text — so it can be compared and cached."""
        self.assertEqual(bpf.vlan_filter([6, 5, 6]), bpf.vlan_filter([5, 6]))

    def test_mac_terms_carry_no_vlan_dance(self):
        """`ether host` reads bytes before the tag, so it needs no both-forms."""
        filt = bpf.host_filter(['00:11:22:33:44:55'])
        self.assertNotIn('vlan', filt)

    def test_ip_terms_do_carry_it(self):
        """IP offsets shift, so the term must appear in both forms."""
        self.assertEqual(bpf.host_filter(['10.0.5.1']).count('10.0.5.1'), 2)

    def test_untagged_form_is_written_first(self):
        """
        `vlan` shifts offsets for everything after it, so `(vlan and X) or X`
        would leave the second X testing shifted bytes.
        """
        filt = bpf.host_filter(['10.0.5.1'])
        self.assertLess(filt.index('10.0.5.1'), filt.index('vlan'))

    def test_combine_drops_empties(self):
        self.assertEqual(bpf.combine('', 'tcp', '', None), 'tcp')

    def test_combine_parenthesises_multiword_terms(self):
        self.assertEqual(bpf.combine('tcp port 80', 'udp'), '(tcp port 80) and udp')


class TestDisplayFilter(unittest.TestCase):
    """Wireshark needs none of the care above; provided so nobody assumes it does."""

    def test_vlan_ids_are_plain(self):
        self.assertEqual(bpf.display_filter(vlans=[5]), 'vlan.id == 5')

    def test_multiple_vlans_read_as_written(self):
        self.assertEqual(bpf.display_filter(vlans=[5, 6]),
                         '(vlan.id == 5 or vlan.id == 6)')

    def test_combines_dimensions(self):
        got = bpf.display_filter(vlans=[5], hosts=['10.0.5.1'],
                                 ports=[47808], protocol='udp')
        self.assertEqual(got, 'vlan.id == 5 and ip.addr == 10.0.5.1 and udp '
                              'and udp.port == 47808')


# ─── Behavioural checks against tcpdump ──────────────────────────────────────

@requires_tools
class TestAgainstTcpdump(unittest.TestCase):

    @classmethod
    def tearDownClass(cls):
        PcapFixture.cleanup()

    def match(self, filt):
        return matched_vlans(filt, PcapFixture.path())

    def test_the_sample_contains_what_we_think(self):
        by_vlan, untagged = self.match('')
        self.assertEqual(by_vlan, {5: 30, 6: 15, 12: 20, 14: 10})
        self.assertEqual(untagged, 6)

    def test_single_vlan(self):
        by_vlan, untagged = self.match(bpf.vlan_filter([5]))
        self.assertEqual(by_vlan, {5: 30})
        self.assertEqual(untagged, 0)

    def test_two_vlans_both_arrive(self):
        """The `vlan 5 or vlan 6` bug drops VLAN 6 here. The builder must not."""
        by_vlan, _ = self.match(bpf.vlan_filter([5, 6]))
        self.assertEqual(by_vlan, {5: 30, 6: 15})

    def test_two_vlans_exclude_everything_else(self):
        by_vlan, untagged = self.match(bpf.vlan_filter([5, 6]))
        self.assertNotIn(12, by_vlan)
        self.assertNotIn(14, by_vlan)
        self.assertEqual(untagged, 0)

    def test_mixed_tagged_and_untagged(self):
        by_vlan, untagged = self.match(bpf.vlan_filter([5, 6], include_untagged=True))
        self.assertEqual(by_vlan, {5: 30, 6: 15})
        self.assertEqual(untagged, 6)

    def test_mixed_selection_still_excludes_the_restricted_vlan(self):
        """
        The regression this whole module exists for. One of the two obvious
        hand-written forms captures VLAN 12 as well, whose payload the site
        profile forbids storing — a filter bug becomes a data-handling breach.
        """
        by_vlan, _ = self.match(bpf.vlan_filter([5, 6], include_untagged=True))
        self.assertNotIn(12, by_vlan)

    def test_untagged_only(self):
        by_vlan, untagged = self.match(bpf.vlan_filter([], include_untagged=True))
        self.assertEqual(by_vlan, {})
        self.assertEqual(untagged, 6)

    def test_port_term_matches_across_tagged_and_untagged(self):
        """47808 appears on VLANs 5 and 6 only; nothing untagged uses it."""
        by_vlan, untagged = self.match(bpf.protocol_filter('udp', [47808]))
        self.assertEqual(by_vlan, {5: 30, 6: 15})
        self.assertEqual(untagged, 0)

    def test_ssh_is_only_untagged_in_the_sample(self):
        by_vlan, untagged = self.match(bpf.protocol_filter('tcp', [22]))
        self.assertEqual(by_vlan, {})
        self.assertEqual(untagged, 6)

    def test_dropping_a_port_keeps_everything_else(self):
        by_vlan, untagged = self.match(bpf.exclude_ports([554], protocol='tcp'))
        self.assertEqual(by_vlan, {5: 30, 6: 15, 12: 20})
        self.assertEqual(untagged, 6)

    def test_dropping_a_host_works_on_tagged_frames(self):
        by_vlan, _ = self.match(bpf.exclude_hosts(['10.0.14.250']))
        self.assertNotIn(14, by_vlan)
        self.assertEqual(by_vlan[5], 30)

    def test_dropping_a_mac_needs_no_vlan_handling(self):
        """Source MAC 00:11:22:33:44:03 is the VLAN 14 generator."""
        by_vlan, _ = self.match(bpf.exclude_hosts(['00:11:22:33:44:03']))
        self.assertNotIn(14, by_vlan)


@requires_tools
class TestBuildCaptureFilter(unittest.TestCase):
    """The assembled filter, exercised the way a profile would drive it."""

    @classmethod
    def tearDownClass(cls):
        PcapFixture.cleanup()

    def match(self, **kw):
        return matched_vlans(bpf.build_capture_filter(**kw), PcapFixture.path())

    def test_hvac_only_no_untagged(self):
        self.assertEqual(self.match(vlans=[5, 6], include_untagged=False),
                         ({5: 30, 6: 15}, 0))

    def test_hvac_plus_management(self):
        self.assertEqual(self.match(vlans=[5, 6], include_untagged=True),
                         ({5: 30, 6: 15}, 6))

    def test_everything_except_video_port(self):
        by_vlan, untagged = self.match(drop_ports=[554])
        self.assertEqual(by_vlan, {5: 30, 6: 15, 12: 20})
        self.assertEqual(untagged, 6)

    def test_selection_and_exclusion_together(self):
        by_vlan, untagged = self.match(vlans=[5, 6], include_untagged=True,
                                       drop_ports=[554])
        self.assertEqual(by_vlan, {5: 30, 6: 15})
        self.assertEqual(untagged, 6)

    def test_no_arguments_captures_everything(self):
        self.assertEqual(bpf.build_capture_filter(), '')

    def test_tagged_only_with_no_vlan_selection(self):
        by_vlan, untagged = self.match(include_untagged=False)
        self.assertEqual(sorted(by_vlan), [5, 6, 12, 14])
        self.assertEqual(untagged, 0)

    def test_extra_fragment_gets_the_both_forms_treatment(self):
        """
        A plain `udp` appended raw matches nothing on a trunk mirror. Users
        reach for `extra` precisely when they are not thinking about tags, so
        the builder handles it for them.
        """
        by_vlan, _ = self.match(vlans=[5, 6], extra='udp')
        self.assertEqual(by_vlan, {5: 30, 6: 15})

    def test_extra_fragment_narrows_as_intended(self):
        """VLAN 5 and 6 carry UDP only, so `tcp` must leave nothing."""
        by_vlan, _ = self.match(vlans=[5, 6], extra='tcp')
        self.assertEqual(by_vlan, {})

    def test_extra_fragment_mentioning_vlan_is_left_alone(self):
        """Whoever wrote `vlan` into it is handling offsets deliberately."""
        filt = bpf.build_capture_filter(extra='vlan 5')
        self.assertIn('(vlan 5)', filt)
        by_vlan, untagged = matched_vlans(filt, PcapFixture.path())
        self.assertEqual(by_vlan, {5: 30})
        self.assertEqual(untagged, 0)


@requires_tools
class TestTheWrongFormsAreWrong(unittest.TestCase):
    """
    Executable documentation. Each of these is a filter someone would reasonably
    write by hand; each is wrong; the test proves it by running it.

    If a future libpcap changes this behaviour these tests will fail, which is
    the correct outcome — the builder's contortions could then be simplified.
    """

    @classmethod
    def tearDownClass(cls):
        PcapFixture.cleanup()

    def match(self, filt):
        return matched_vlans(filt, PcapFixture.path())

    def test_or_of_vlan_keywords_silently_drops_the_second(self):
        by_vlan, _ = self.match('vlan 5 or vlan 6')
        self.assertEqual(by_vlan.get(5), 30)
        self.assertNotIn(6, by_vlan)

    def test_not_vlan_first_matches_only_untagged(self):
        by_vlan, untagged = self.match(
            'not vlan or (vlan and (ether[14:2] & 0x0fff == 5 '
            'or ether[14:2] & 0x0fff == 6))')
        self.assertEqual(by_vlan, {})
        self.assertEqual(untagged, 6)

    def test_not_vlan_last_matches_everything_including_the_restricted_vlan(self):
        """
        The dangerous one. `vlan` shifts offsets for everything after it, so the
        trailing `not vlan` tests the encapsulated ethertype — true for every
        tagged frame. A filter written to capture two HVAC VLANs captures the
        access-control VLAN too, and nothing about the filter text says so.
        """
        by_vlan, untagged = self.match(
            '(vlan and (ether[14:2] & 0x0fff == 5 '
            'or ether[14:2] & 0x0fff == 6)) or not vlan')
        self.assertEqual(by_vlan, {5: 30, 6: 15, 12: 20, 14: 10})
        self.assertEqual(untagged, 6)

    def test_the_builder_gets_the_same_intent_right(self):
        """Same intent as the two above, expressed by the builder."""
        by_vlan, untagged = self.match(
            bpf.vlan_filter([5, 6], include_untagged=True))
        self.assertEqual(by_vlan, {5: 30, 6: 15})
        self.assertEqual(untagged, 6)

    def test_a_bare_ip_term_misses_tagged_frames(self):
        """Why protocol_filter emits both forms rather than the term alone."""
        by_vlan, untagged = self.match('udp port 47808')
        self.assertEqual(by_vlan, {})
        self.assertEqual(untagged, 0)


@unittest.skipUnless(HAVE_TCPDUMP, 'needs tcpdump to compile filters')
class TestEverythingItEmitsCompiles(unittest.TestCase):
    """
    The structural guard. A filter that does not compile takes the whole capture
    down, and the failure arrives at 3am on a mirror port rather than in a test.

    This caught `host net 10.0.5.0/24` — a syntax error the builder emitted for
    any profile listing a subnet under `drop_hosts`, which is the natural way to
    exclude a video VLAN.
    """

    def assertCompiles(self, filt):
        if not filt:
            return
        result = subprocess.run(['tcpdump', '-d', filt],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0,
                         f'{filt!r} -> {result.stderr.strip()}')

    def test_vlan_selections(self):
        for vlans in ([], [5], [5, 6], [1, 20, 40, 50, 60]):
            for untagged in (True, False):
                with self.subTest(vlans=vlans, untagged=untagged):
                    self.assertCompiles(bpf.vlan_filter(vlans, untagged))

    def test_host_terms_in_every_shape(self):
        shapes = [['10.0.5.1'], ['10.0.5.0/24'], ['00:11:22:33:44:55'],
                  ['10.0.5.1', '10.0.6.1'], ['10.0.5.0/24', '10.0.6.0/24'],
                  ['10.0.5.0/24', '10.0.6.1', '00:11:22:33:44:55'],
                  ['2001:db8::1'], ['2001:db8::/32']]
        for hosts in shapes:
            for direction in ('either', 'src', 'dst'):
                with self.subTest(hosts=hosts, direction=direction):
                    self.assertCompiles(bpf.host_filter(hosts, direction))
                    self.assertCompiles(bpf.exclude_hosts(hosts))

    def test_protocol_terms_in_every_shape(self):
        for proto in (None, 'tcp', 'udp', 'icmp', 'arp', 'ip', 'ip6'):
            for ports in (None, [80], [80, 443, 47808]):
                if ports and proto in bpf.PORTLESS_PROTOCOLS:
                    continue                    # refused at build time instead
                for direction in ('either', 'src', 'dst'):
                    with self.subTest(proto=proto, ports=ports, direction=direction):
                        self.assertCompiles(
                            bpf.protocol_filter(proto, ports, direction))

    def test_a_port_on_a_portless_protocol_is_refused_not_emitted(self):
        """
        libpcap rejects `arp and port 80` outright, so emitting it would turn a
        profile typo into a capture that will not start.
        """
        for proto in ('arp', 'icmp'):
            with self.subTest(proto=proto):
                with self.assertRaises(ValueError) as ctx:
                    bpf.protocol_filter(proto, [80])
                self.assertIn('no ports', str(ctx.exception))

    def test_the_portless_protocols_alone_are_fine(self):
        for proto in ('arp', 'icmp'):
            with self.subTest(proto=proto):
                self.assertCompiles(bpf.protocol_filter(proto))

    def test_assembled_filters(self):
        cases = [
            {},
            {'vlans': [5, 6]},
            {'vlans': [5, 6], 'include_untagged': False},
            {'drop_hosts': ['10.0.30.10']},
            {'drop_hosts': ['10.0.30.0/24']},
            {'drop_ports': [554], 'drop_port_protocol': 'tcp'},
            {'vlans': [5], 'drop_hosts': ['10.0.30.0/24'], 'drop_ports': [554, 8554]},
            {'vlans': [5], 'extra': 'udp'},
            {'extra': 'vlan 5'},
        ]
        for kwargs in cases:
            with self.subTest(**kwargs):
                self.assertCompiles(bpf.build_capture_filter(**kwargs))

    def test_the_shipped_example_profile_compiles(self):
        """
        The example is what a new user copies. If its capture section produces a
        filter libpcap rejects, their first run fails and the tool looks broken.
        """
        from netmon.profile import load_profile
        example = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), 'netmon', 'profiles', 'example-site.yaml')
        self.assertCompiles(bpf.from_profile(load_profile(example)))

    def test_a_subnet_under_drop_hosts_compiles(self):
        """The exact regression: `host net X` is a syntax error, `net X` is not."""
        filt = bpf.build_capture_filter(vlans=[5], drop_hosts=['10.0.30.0/24'])
        self.assertNotIn('host net', filt)
        self.assertCompiles(filt)


@requires_tools
class TestVerifyFilter(unittest.TestCase):
    """The empirical check offered to users who capture on other stacks."""

    @classmethod
    def tearDownClass(cls):
        PcapFixture.cleanup()

    def test_reports_what_was_kept_and_dropped(self):
        report = bpf.verify_filter(bpf.vlan_filter([5, 6]), PcapFixture.path())
        self.assertEqual(report['total'], 81)
        self.assertEqual(report['matched'], 45)
        self.assertEqual(report['by_vlan'], {5: 30, 6: 15})
        self.assertEqual(report['vlans_dropped'], [12, 14])

    def test_reports_what_the_capture_contained(self):
        report = bpf.verify_filter(bpf.vlan_filter([5]), PcapFixture.path())
        self.assertEqual(report['vlans_present'], {5: 30, 6: 15, 12: 20, 14: 10})
        self.assertEqual(report['untagged_present'], 6)

    def test_a_bad_filter_is_reported_not_raised(self):
        """A UI calls this on every keystroke; it must never throw."""
        report = bpf.verify_filter('not a filter', PcapFixture.path())
        self.assertIn('error', report)
        self.assertIn('did not compile', report['error'])

    def test_a_missing_capture_is_reported_not_raised(self):
        report = bpf.verify_filter('tcp', '/nonexistent/sample.pcap')
        self.assertIn('error', report)

    def test_missing_tcpdump_is_reported_not_raised(self):
        report = bpf.verify_filter('tcp', PcapFixture.path(),
                                   tcpdump='tcpdump-that-is-not-installed')
        self.assertIn('not found', report['error'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
