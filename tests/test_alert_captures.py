"""
Alert captures are kept for good.
=================================
The traffic behind an alert was pruned: outside review mode only the newest 50
captures were kept, and review mode's snippets were cut back to a 500 MB budget,
oldest first. An alert from last week could come up for review with nothing
behind it. Now neither is ever deleted. Outside review mode they live in their
own folder, apart from the recordings that rotate, and a nearly full disk skips
new captures rather than deleting old ones.
Addresses here are documentation ranges.
"""

import os
import shutil
import struct
import sys
import tempfile
import unittest
from collections import namedtuple
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401

from src.ids_engine import Alert, Severity  # noqa: E402
from src.pcap_writer import PcapWriter  # noqa: E402
from src.review import ReviewRecorder  # noqa: E402
from test_review import bare_app  # noqa: E402


class _Settings:
    """Config stand-in: the given (section, key) values, defaults for the rest."""

    def __init__(self, **values):
        self.values = {tuple(k.split('__')): v for k, v in values.items()}

    def get(self, *keys, default=None):
        return self.values.get(keys, default)


def frame(src, dst, size=60):
    """An Ethernet + IPv4 frame between two hosts, padded to size bytes."""
    eth = b'\x02\x00\x00\x00\x00\x02' + b'\x02\x00\x00\x00\x00\x01' + b'\x08\x00'
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, size - 14, 0, 0, 64, 6, 0,
                     bytes(int(o) for o in src.split('.')),
                     bytes(int(o) for o in dst.split('.')))
    return (eth + ip).ljust(size, b'\x00')


def an_alert(rule='PORT-SCAN', severity=Severity.HIGH):
    return Alert(rule, severity, 't', 'd', src_ip='192.0.2.10', dst_ip='198.51.100.7')


DiskUsage = namedtuple('DiskUsage', 'total used free')


class _Case(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='ns_alertcaps_')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def writer(self, settings=None, frames=40, size=60):
        writer = PcapWriter(settings or _Settings(), output_dir=self.tmp)
        for _ in range(frames):
            writer.buffer_packet(frame('192.0.2.10', '198.51.100.7', size))
        return writer


class TestNothingDeletesThem(_Case):

    def test_outside_review_mode_every_capture_is_kept_in_its_own_folder(self):
        # 1.10.0 honoured this and deleted all but the newest three.
        writer = self.writer(_Settings(capture__pcap_max_alert_files=3))
        paths = [writer.export_for_alert(an_alert(f'RULE{i}')) for i in range(8)]
        alert_dir = os.path.join(self.tmp, 'alerts')
        self.assertEqual({os.path.dirname(p) for p in paths}, {alert_dir})
        self.assertEqual(len([f for f in os.listdir(alert_dir) if f.endswith('.pcap')]), 8)

    def test_review_snippets_outlive_the_old_budget(self):
        # Three snippets of about 1.2 MB each against the old 1 MB budget.
        settings = _Settings(review__snippet_budget_mb=1)
        writer = self.writer(settings, frames=800, size=1514)
        recorder = ReviewRecorder(os.path.join(self.tmp, 'review'), writer, settings)
        paths = [recorder.snippet(an_alert(f'RULE{i}')) for i in range(3)]
        self.assertTrue(all(paths))
        for path in paths:
            self.assertTrue(os.path.exists(path), path)
            self.assertEqual(os.path.dirname(path), recorder.snippet_dir)

    def test_the_captures_list_shows_alert_captures_too(self):
        writer = self.writer()
        writer.export_for_alert(an_alert())
        writer.export_buffer()
        names = [f['filename'] for f in writer.get_capture_files()]
        self.assertEqual(len(names), 2)
        self.assertTrue(any(n.startswith('alerts/alert_PORT-SCAN_') for n in names), names)


class TestAFullDisk(_Case):

    def test_a_nearly_full_disk_skips_the_capture_and_deletes_nothing(self):
        writer = self.writer()
        kept = writer.export_for_alert(an_alert('FIRST'))
        alert = an_alert('SECOND')
        with mock.patch('src.pcap_writer.shutil.disk_usage',
                        return_value=DiskUsage(10 << 30, (10 << 30) - (10 << 20), 10 << 20)):
            self.assertIsNone(writer.export_for_alert(alert))
        self.assertTrue(os.path.exists(kept))
        note = alert.evidence['packet_capture_note']
        self.assertIn('1024 MB', note)
        self.assertIn('never deleted', note)

    def test_the_floor_is_a_setting(self):
        writer = self.writer(_Settings(capture__alert_min_free_mb=5))
        with mock.patch('src.pcap_writer.shutil.disk_usage',
                        return_value=DiskUsage(10 << 30, (10 << 30) - (10 << 20), 10 << 20)):
            self.assertIsNotNone(writer.export_for_alert(an_alert()))

    def test_a_disk_that_cannot_be_read_still_gets_the_capture(self):
        writer = self.writer()
        with mock.patch('src.pcap_writer.shutil.disk_usage', side_effect=OSError('no')):
            self.assertIsNotNone(writer.export_for_alert(an_alert()))


class TestRepeatsShareOneCapture(_Case):

    def test_outside_review_mode_a_repeat_points_at_the_first_capture(self):
        # 1.10.0 shared only in review mode, because it pruned the rest; a repeat
        # inside the cooldown got nothing.
        app = bare_app()
        app.pcap_writer = self.writer()
        app._pcap_on_alert = True
        first, second = an_alert(severity=Severity.CRITICAL), an_alert(severity=Severity.CRITICAL)
        app._capture_alert_evidence(first)
        app._capture_alert_evidence(second)
        self.assertTrue(os.path.exists(first.evidence['packet_capture']))
        self.assertEqual(second.evidence.get('packet_capture'),
                         first.evidence['packet_capture'])


if __name__ == '__main__':
    unittest.main()
