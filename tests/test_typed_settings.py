"""
Numbers in config.json, typed by hand.
======================================
Most of NetSentinel read its numeric settings as they came. The outside review
of 2026-11-14 (N3) found that alerts.max_stored as "5000" stopped the start,
and capture.max_pps as "2000" raised on every packet: the capture callback
logged that at DEBUG, nothing reached the IDS, and nothing said so. Config.load
now makes every number a number before any reader sees it.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import SCAPY_REAL, reset_config  # noqa: E402

from src import config  # noqa: E402


def numeric_settings():
    for section, defaults in config.DEFAULT_CONFIG.items():
        for key, default in (defaults.items() if isinstance(defaults, dict) else ()):
            if isinstance(default, (int, float)) and not isinstance(default, bool):
                yield section, key, default


class _ConfigFile(unittest.TestCase):

    def setUp(self):
        folder = tempfile.mkdtemp(prefix='ns_typed_')
        self.path = os.path.join(folder, 'config.json')
        patcher = mock.patch.object(config, 'CONFIG_FILE', self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(reset_config)          # the real file again, for the next test

    def load(self, change):
        data = json.loads(json.dumps(config.DEFAULT_CONFIG))
        change(data)
        with open(self.path, 'w', encoding='utf-8') as f:
            json.dump(data, f)
        return config.Config().load()


class TestEveryNumberAsText(_ConfigFile):

    def test_each_comes_back_a_number_of_its_defaults_kind(self):
        def as_text(data):
            for section, key, default in numeric_settings():
                data[section][key] = f' {default} '
        cfg = self.load(as_text)
        for section, key, default in numeric_settings():
            with self.subTest(setting=f'{section}.{key}'):
                value = cfg.get(section, key)
                self.assertEqual(value, default)
                self.assertIsInstance(value, type(default) if isinstance(default, float)
                                      or (section, key) not in config.FRACTIONAL_SETTINGS
                                      else (int, float))

    def test_the_two_the_review_found_now_start_and_analyse(self):
        def quoted(data):
            data['alerts']['max_stored'] = '5000'
            data['capture']['max_pps'] = '2000'
        cfg = self.load(quoted)
        from src.alerts import AlertManager
        self.assertEqual(AlertManager(cfg).max_stored, 5000)
        from src.capture import CaptureEngine
        self.assertEqual(CaptureEngine(cfg)._max_pps, 2000)

    def test_not_a_number_is_the_default_with_a_warning(self):
        def typo(data):
            data['alerts']['max_stored'] = '50OO'
            data['ml']['contamination'] = 'lots'
            data['gui']['refresh_rate_ms'] = None
        with self.assertLogs('NetSentinel.Config', level='WARNING') as logs:
            cfg = self.load(typo)
        self.assertEqual(cfg.get('alerts', 'max_stored'), 5000)
        self.assertEqual(cfg.get('ml', 'contamination'), 0.25)
        self.assertEqual(cfg.get('gui', 'refresh_rate_ms'), 1000)
        self.assertTrue(any('alerts.max_stored' in line for line in logs.output))

    def test_out_of_range_is_clamped(self):
        def wild(data):
            data['alerts']['max_stored'] = -5          # deque(maxlen=-5) raised
            data['ml']['contamination'] = 0.9          # scikit-learn refuses > 0.5
            data['syslog']['port'] = 70000
            data['ids']['port_scan_threshold'] = -1
        cfg = self.load(wild)
        self.assertEqual(cfg.get('alerts', 'max_stored'), 1)
        self.assertEqual(cfg.get('ml', 'contamination'), 0.5)
        self.assertEqual(cfg.get('syslog', 'port'), 65535)
        self.assertEqual(cfg.get('ids', 'port_scan_threshold'), 0)

    def test_durations_may_be_fractions_counts_may_not(self):
        def halves(data):
            data['ml']['baseline_learning_hours'] = 0.5
            data['alerts']['max_stored'] = 2500.5
        cfg = self.load(halves)
        self.assertEqual(cfg.get('ml', 'baseline_learning_hours'), 0.5)
        self.assertEqual(cfg.get('alerts', 'max_stored'), 5000)

    def test_the_old_threshold_name_is_a_number_or_nothing(self):
        def legacy(data):
            data['ml']['anomaly_threshold'] = '0.3'
        self.assertEqual(self.load(legacy).get('ml', 'anomaly_threshold'), 0.3)

        def broken(data):
            data['ml']['anomaly_threshold'] = 'high'
        self.assertIsNone(self.load(broken).get('ml', 'anomaly_threshold'))

    def test_a_section_that_is_not_a_section_is_the_defaults(self):
        def flat(data):
            data['alerts'] = 5
        self.assertEqual(self.load(flat).get('alerts', 'max_stored'), 5000)

    def test_text_and_lists_are_left_alone(self):
        def keep(data):
            data['capture']['interface'] = 'Ethernet 2'
            data['ids']['known_bad_ports'] = [4444]
        cfg = self.load(keep)
        self.assertEqual(cfg.get('capture', 'interface'), 'Ethernet 2')
        self.assertEqual(cfg.get('ids', 'known_bad_ports'), [4444])


class TestACaptureErrorIsSaid(unittest.TestCase):

    @unittest.skipUnless(SCAPY_REAL, 'real scapy unavailable')
    def test_an_error_on_every_packet_is_a_warning_once(self):
        """It was DEBUG only: analysis stopped and the log said nothing."""
        from scapy.all import IP, TCP, Ether
        from src.capture import CaptureEngine
        engine = CaptureEngine(reset_config())
        engine._max_pps = 'broken'               # what a quoted max_pps used to be
        packet = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / \
            IP(src='192.0.2.1', dst='192.0.2.2') / TCP(sport=1, dport=80)
        with self.assertLogs('NetSentinel', level='WARNING') as logs:
            for _ in range(5):
                engine._capture_callback(packet)
        warnings = [line for line in logs.output if 'not being analysed' in line]
        self.assertEqual(len(warnings), 1)


if __name__ == '__main__':
    unittest.main()
