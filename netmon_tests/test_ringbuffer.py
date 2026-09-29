"""
The rolling capture.
====================
Two things this file is really about.

The first is that a segment marked metadata-only must not reach the disk, and
must not come back off it either. The capture filter excludes it by name — not
merely by failing to select it — and extraction applies the same exclusion
again, because a file written last week predates this week's profile. Both are
tested against real frames.

The second is retention. A ring buffer that deletes the file being written, or
that prunes by mtime when the newest file's mtime is always now, fails in ways
you find out about a day later when the window you wanted is gone.
"""

import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import _test_support  # noqa: E402,F401

from netmon.events import Event, Finding  # noqa: E402
from netmon.profile import SiteProfile  # noqa: E402
from netmon.ringbuffer import RingBuffer, RingBufferError  # noqa: E402

try:
    from scapy.all import Dot1Q, Ether, IP, TCP, wrpcap
    import scapy.all as scapy
    HAVE_SCAPY = hasattr(scapy, 'PcapReader')
except Exception:                                              # pragma: no cover
    HAVE_SCAPY = False

requires_scapy = unittest.skipUnless(HAVE_SCAPY, 'needs a real scapy')


def profile(**overrides):
    data = {
        'site': {'name': 'test'},
        'vlans': {
            20: {'name': 'ot', 'subnet': '10.10.20.0/24', 'zone': 'ot'},
            40: {'name': 'restricted', 'subnet': '10.10.40.0/24',
                 'store_payload': False},
            60: {'name': 'staff', 'subnet': '10.10.60.0/24'},
        },
        'capture': {'interface': 'mirror0', 'vlans': [20, 40, 60],
                    'include_untagged': True},
    }
    data.update(overrides)
    return SiteProfile(data)


class _RingCase(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-ring-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.ring = RingBuffer(self.scratch, profile())

    def write_capture(self, name, packets=None, when=None):
        """A capture file named as tcpdump's rotation would name it."""
        path = os.path.join(self.scratch, name)
        if packets is None:
            packets = [Ether() / IP(src='10.10.20.1', dst='10.10.20.2') / TCP()]
        wrpcap(path, packets)
        if when is not None:
            os.utime(path, (when, when))
        return path

    def name_for(self, when):
        return time.strftime('netmon-%Y%m%d-%H%M%S.pcap', time.localtime(when))


# ─── The capture command ─────────────────────────────────────────────────────

class TestCaptureCommand(_RingCase):

    def test_it_names_the_interface_and_the_directory(self):
        command = self.ring.capture_command()
        self.assertIn('mirror0', command)
        self.assertTrue(any(self.scratch in part for part in command))

    def test_it_rotates_and_sets_a_snap_length(self):
        command = self.ring.capture_command()
        self.assertIn('-G', command)
        self.assertIn('-s', command)

    def test_it_drops_privileges(self):
        """Capture needs root to open the socket and nothing after that."""
        command = self.ring.capture_command()
        self.assertIn('-Z', command)

    def test_it_does_not_resolve_names_from_the_sensor(self):
        self.assertIn('-n', self.ring.capture_command())

    def test_no_interface_is_an_error_that_says_what_to_set(self):
        ring = RingBuffer(self.scratch, SiteProfile({}))
        with self.assertRaises(RingBufferError) as ctx:
            ring.capture_command()
        self.assertIn('capture.interface', str(ctx.exception))

    def test_the_restricted_vlans_are_excluded_by_name(self):
        """
        Not merely absent from the selection: a capture that happens not to
        select VLAN 40 is one edit away from selecting it.
        """
        expression = self.ring.capture_command()[-1]
        self.assertIn('not', expression)
        self.assertIn('0x0fff == 40', expression)

    def test_the_description_says_what_is_excluded(self):
        description = self.ring.describe()
        self.assertIn('VLAN 40', description)
        self.assertIn('metadata only', description)

    def test_a_profile_with_no_restricted_segment_says_so(self):
        ring = RingBuffer(self.scratch, SiteProfile({
            'vlans': {20: {'name': 'ot'}},
            'capture': {'interface': 'eth1'}}))
        self.assertIn('no VLAN is marked', ring.describe())


@unittest.skipUnless(shutil.which('tcpdump'), 'needs tcpdump')
class TestTheFilterActuallyExcludes(_RingCase):
    """
    The property the whole design rests on, checked against real frames rather
    than against the filter text.
    """

    def capture_with_every_vlan(self):
        packets = []
        for vlan, count in ((20, 10), (40, 8), (60, 6)):
            for n in range(count):
                packets.append(
                    Ether(src=f'00:11:22:33:44:{vlan:02x}', dst='00:aa:bb:cc:dd:ee')
                    / Dot1Q(vlan=vlan)
                    / IP(src=f'10.10.{vlan}.{n + 1}', dst=f'10.10.{vlan}.250')
                    / TCP(dport=443))
        path = os.path.join(self.scratch, 'all.pcap')
        wrpcap(path, packets)
        return path

    def test_the_restricted_vlan_does_not_survive_the_filter(self):
        from netmon_tests._support import matched_vlans
        by_vlan, _ = matched_vlans(self.ring.filter_expression(),
                                   self.capture_with_every_vlan())
        self.assertNotIn(40, by_vlan)

    def test_even_though_the_capture_section_selects_it(self):
        """
        The example the exclusion exists for: `capture.vlans` lists 40, and it
        is still excluded. The two mechanisms disagree and the safe one wins.
        """
        self.assertIn(40, self.ring.profile.raw['capture']['vlans'])
        from netmon_tests._support import matched_vlans
        by_vlan, _ = matched_vlans(self.ring.filter_expression(),
                                   self.capture_with_every_vlan())
        self.assertNotIn(40, by_vlan)

    def test_everything_else_still_arrives(self):
        from netmon_tests._support import matched_vlans
        by_vlan, _ = matched_vlans(self.ring.filter_expression(),
                                   self.capture_with_every_vlan())
        self.assertEqual(by_vlan, {20: 10, 60: 6})


# ─── The directory ───────────────────────────────────────────────────────────

@requires_scapy
class TestDirectory(_RingCase):

    def test_it_is_created_owner_only(self):
        """It holds packet payload."""
        target = os.path.join(self.scratch, 'new')
        ring = RingBuffer(target, profile())
        ring.ensure_directory()
        self.assertEqual(os.stat(target).st_mode & 0o077, 0)

    def test_files_are_listed_oldest_first(self):
        now = time.time()
        for offset in (0, -3600, -7200):
            self.write_capture(self.name_for(now + offset))
        files = self.ring.files()
        self.assertEqual(len(files), 3)
        self.assertEqual([f['started'] for f in files],
                         sorted(f['started'] for f in files))

    def test_the_start_time_comes_from_the_name_not_the_mtime(self):
        """
        A file still being written has an mtime of now and a name from an hour
        ago. Pruning by mtime would keep exactly the wrong ones.
        """
        when = time.time() - 7200
        path = self.write_capture(self.name_for(when))
        os.utime(path, (time.time(), time.time()))
        self.assertAlmostEqual(self.ring.files()[0]['started'], when, delta=60)

    def test_an_unrelated_file_is_ignored(self):
        with open(os.path.join(self.scratch, 'notes.txt'), 'w') as handle:
            handle.write('hello')
        self.write_capture(self.name_for(time.time()))
        self.assertEqual(len(self.ring.files()), 1)

    def test_a_capture_with_another_name_falls_back_to_its_mtime(self):
        when = time.time() - 3600
        self.write_capture('somethingelse.pcap', when=when)
        files = self.ring.files()
        self.assertEqual(len(files), 1)
        self.assertAlmostEqual(files[0]['started'], when, delta=2)

    def test_an_empty_directory_is_not_an_error(self):
        self.assertEqual(self.ring.files(), [])
        self.assertEqual(self.ring.status()['files'], 0)

    def test_a_missing_directory_is_not_an_error(self):
        ring = RingBuffer(os.path.join(self.scratch, 'nope'), profile())
        self.assertEqual(ring.files(), [])


@requires_scapy
class TestRetention(_RingCase):

    def fill(self, hours_back):
        now = time.time()
        for hours in hours_back:
            self.write_capture(self.name_for(now - hours * 3600))
        return now

    def test_files_past_the_window_are_removed(self):
        self.ring.hours = 24
        self.fill([1, 5, 30, 50])
        result = self.ring.prune()
        self.assertEqual(len(result['removed']), 2)
        self.assertEqual(result['remaining'], 2)

    def test_nothing_inside_the_window_is_touched(self):
        self.ring.hours = 48
        self.fill([1, 5, 30])
        self.assertEqual(self.ring.prune()['removed'], [])

    def test_the_newest_file_is_never_removed(self):
        """
        It is the one being written. Removing it leaves the capture writing to
        a deleted inode, with no error anywhere.
        """
        self.ring.hours = 0.0001
        self.fill([10, 20, 30])
        self.ring.prune()
        self.assertEqual(len(self.ring.files()), 1)

    def test_the_size_budget_removes_oldest_first(self):
        now = time.time()
        packets = [Ether() / IP() / TCP()] * 200
        for hours in (3, 2, 1):
            self.write_capture(self.name_for(now - hours * 3600), packets)
        total = sum(f['size'] for f in self.ring.files())
        self.ring.max_bytes = total // 2
        result = self.ring.prune()
        self.assertTrue(result['removed'])
        remaining = {f['name'] for f in self.ring.files()}
        self.assertIn(self.name_for(now - 3600), remaining)

    def test_a_dry_run_removes_nothing(self):
        self.ring.hours = 0.0001
        self.fill([10, 20, 30])
        result = self.ring.prune(dry_run=True)
        self.assertTrue(result['removed'])
        self.assertEqual(len(self.ring.files()), 3)

    def test_status_reports_whether_it_is_within_bounds(self):
        self.ring.hours = 24
        self.fill([1, 2])
        status = self.ring.status()
        self.assertTrue(status['within_retention'])
        self.assertTrue(status['within_size'])
        self.assertEqual(status['files'], 2)

    def test_status_says_when_it_is_over(self):
        self.ring.hours = 1
        self.fill([0.1, 10])
        self.assertFalse(self.ring.status()['within_retention'])

    def test_pruning_an_empty_directory_is_harmless(self):
        self.assertEqual(self.ring.prune()['removed'], [])


# ─── Getting a window back out ───────────────────────────────────────────────

@requires_scapy
class TestExtraction(_RingCase):

    def setUp(self):
        super().setUp()
        self.base = 1790000000.0
        self.write_window()

    def write_window(self):
        """Three files, fifteen minutes apart, each a minute of traffic."""
        for index, offset in enumerate((0, 900, 1800)):
            packets = []
            for second in range(60):
                stamp = self.base + offset + second
                for vlan, src, dst in ((20, '10.10.20.21', '10.10.20.10'),
                                       (40, '10.10.40.10', '10.10.40.11'),
                                       (60, '10.10.60.50', '10.10.20.10')):
                    packet = (Ether(src='00:11:22:33:44:55',
                                    dst='00:aa:bb:cc:dd:ee')
                              / Dot1Q(vlan=vlan) / IP(src=src, dst=dst)
                              / TCP(dport=443))
                    packet.time = stamp
                    packets.append(packet)
            self.write_capture(self.name_for(self.base + offset), packets)

    def test_a_window_is_extracted(self):
        result = self.ring.extract(self.base + 30, seconds=10)
        self.assertTrue(os.path.exists(result['path']))
        self.assertGreater(result['packets'], 0)

    def test_only_the_window_comes_out(self):
        from scapy.all import rdpcap
        result = self.ring.extract(self.base + 30, seconds=10)
        stamps = [float(p.time) for p in rdpcap(result['path'])]
        self.assertGreaterEqual(min(stamps), self.base + 25)
        self.assertLessEqual(max(stamps), self.base + 35)

    def test_the_restricted_vlan_never_comes_back_out(self):
        """
        Applied again on extraction: a file on disk was written under whatever
        profile was current then, and a segment marked metadata-only since must
        not come back.
        """
        from scapy.all import Dot1Q as Tag, rdpcap
        result = self.ring.extract(self.base + 30, seconds=10)
        vlans = {int(p.getlayer(Tag).vlan) for p in rdpcap(result['path'])
                 if p.getlayer(Tag) is not None}
        self.assertNotIn(40, vlans)
        self.assertGreater(result['excluded_restricted'], 0)

    def test_narrowing_to_the_endpoints_involved(self):
        """
        Usually turns a hundred thousand packets into the few dozen someone
        will actually read.
        """
        from scapy.all import IP as Net, rdpcap
        result = self.ring.extract(self.base + 30, seconds=10,
                                   endpoints={'10.10.60.50'})
        addresses = set()
        for packet in rdpcap(result['path']):
            layer = packet.getlayer(Net)
            addresses |= {layer.src, layer.dst}
        self.assertIn('10.10.60.50', addresses)
        self.assertNotIn('10.10.20.21', addresses)

    def test_a_window_spanning_two_files(self):
        result = self.ring.extract(self.base + 890, seconds=60)
        self.assertGreaterEqual(len(result['from_files']), 1)
        self.assertGreater(result['packets'], 0)

    def test_the_extract_is_written_owner_only(self):
        result = self.ring.extract(self.base + 30, seconds=10)
        self.assertEqual(os.stat(result['path']).st_mode & 0o077, 0)

    def test_a_time_with_nothing_on_disk_says_so(self):
        with self.assertRaises(RingBufferError) as ctx:
            self.ring.extract(self.base - 100_000, seconds=10)
        self.assertIn('nothing on disk', str(ctx.exception))

    def test_an_empty_window_says_so_rather_than_writing_an_empty_file(self):
        with self.assertRaises(RingBufferError) as ctx:
            self.ring.extract(self.base + 300, seconds=2)
        self.assertIn('nothing matched', str(ctx.exception))

    def test_a_host_that_was_never_there_says_so(self):
        with self.assertRaises(RingBufferError) as ctx:
            self.ring.extract(self.base + 30, seconds=10,
                              endpoints={'203.0.113.99'})
        self.assertIn('203.0.113.99', str(ctx.exception))

    def test_a_damaged_file_does_not_stop_the_extraction(self):
        with open(os.path.join(self.scratch,
                               self.name_for(self.base + 450)), 'wb') as handle:
            handle.write(b'not a capture')
        result = self.ring.extract(self.base + 30, seconds=10)
        self.assertGreater(result['packets'], 0)


@requires_scapy
class TestExtractingForAFinding(_RingCase):
    """What an alert links to."""

    def setUp(self):
        super().setUp()
        self.base = 1790000000.0
        packets = []
        for second in range(120):
            for src, dst in (('10.10.60.50', '10.10.20.21'),
                             ('10.10.20.10', '10.10.20.22')):
                packet = (Ether() / Dot1Q(vlan=20) / IP(src=src, dst=dst)
                          / TCP(dport=47808))
                packet.time = self.base + second
                packets.append(packet)
        self.write_capture(self.name_for(self.base), packets)

    def finding(self):
        event = Event(kind='bacnet', src_ip='10.10.60.50', dst_ip='10.10.20.21',
                      ts=self.base + 60, vlan=20)
        return Finding('bacnet_control', 'A write', severity='critical',
                       device='ahu-controller-1', event=event,
                       ts=self.base + 60)

    def test_the_window_around_the_finding(self):
        result = self.ring.extract_for_finding(self.finding(), seconds=20)
        self.assertGreater(result['packets'], 0)

    def test_it_is_narrowed_to_the_devices_involved(self):
        from scapy.all import IP as Net, rdpcap
        result = self.ring.extract_for_finding(self.finding(), seconds=20)
        for packet in rdpcap(result['path']):
            layer = packet.getlayer(Net)
            self.assertIn('10.10.60.50', {layer.src, layer.dst})

    def test_a_finding_with_no_packet_behind_it_says_so(self):
        """A digest entry has no window to extract."""
        finding = Finding('digest', 'Summary', ts=self.base)
        with self.assertRaises(RingBufferError) as ctx:
            self.ring.extract_for_finding(finding)
        self.assertIn('no packet', str(ctx.exception))


if __name__ == '__main__':
    unittest.main(verbosity=2)
