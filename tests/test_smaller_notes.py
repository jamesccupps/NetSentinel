"""
The outside review's smaller notes on NetSentinel (2026-11-14).
===============================================================
Each is small; each has a case here. Addresses are made up.
"""

import csv
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + os.sep + 'tests')

import _test_support  # noqa: E402,F401
from _test_support import SCAPY_REAL, reset_config  # noqa: E402

FORMULA = '=HYPERLINK("http://evil.example","open")'


def alert(**kw):
    from src.ids_engine import Alert
    return Alert('DNS-BAD-TLD', 'MEDIUM', FORMULA, '+cmd|calc', src_ip='192.168.10.32',
                 dst_ip='198.51.100.9', evidence=dict({'dns_query': '@evil.example'}, **kw))


class _Folder(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='ns_notes_')
        self.addCleanup(shutil.rmtree, self.dir, True)

    def cells(self, path):
        with open(path, encoding='utf-8', newline='') as f:
            return [cell for row in csv.reader(f) for cell in row]


class TestSpreadsheetExports(_Folder):
    """A cell starting with = + - or @ runs as a formula in Excel; the dashboard
    guarded its export, the desktop app's two did not."""

    def test_the_alert_export(self):
        from src.alerts import AlertManager
        manager = AlertManager(reset_config())
        manager.clear_alerts()
        manager.add_alert(alert())
        path = os.path.join(self.dir, 'alerts.csv')
        manager.export_alerts(path, format='csv')
        cells = self.cells(path)
        self.assertIn("'" + FORMULA, cells)
        self.assertIn("'@evil.example", cells)
        self.assertFalse([c for c in cells if c[:1] in ('=', '+', '@')])

    def test_the_capture_analysis_export(self):
        from src.pcap_analyzer import PcapAnalyzer
        analyzer = PcapAnalyzer(reset_config())
        analyzer.alerts = [alert()]
        path = os.path.join(self.dir, 'capture.csv')
        analyzer.export_results(path, format='csv')
        cells = self.cells(path)
        self.assertIn("'" + FORMULA, cells)
        self.assertFalse([c for c in cells if c[:1] in ('=', '+', '@')])

    def test_numbers_are_left_alone(self):
        from src.presentation import spreadsheet_safe
        self.assertEqual(spreadsheet_safe(-5), -5)
        self.assertEqual(spreadsheet_safe('-5 dB'), "'-5 dB")
        self.assertEqual(spreadsheet_safe('plain'), 'plain')


class TestReviewBundles(_Folder):

    @unittest.skipUnless(SCAPY_REAL, 'real scapy unavailable')
    def test_a_non_ip_frame_is_redacted_too(self):
        """Its summary names MAC addresses, which pseudonymised bundles replace."""
        from scapy.all import Ether, Raw
        from src.review import Pseudonymiser, _packet_line, _Redactor
        frame = Ether(src='00:00:5e:00:53:31', dst='00:00:5e:00:53:01', type=0x88cc) / Raw(b'x')
        frame.time = 1_790_000_000
        line = _packet_line(frame, _Redactor(Pseudonymiser()), include_payloads=False)
        self.assertNotIn('00:00:5e:00:53:31', line)

    def test_out_will_not_empty_a_folder_that_is_not_a_bundle(self):
        from src.review import build_bundle
        from test_review import record, write_jsonl
        write_jsonl(self.dir, [record('PORT-SCAN', '192.168.10.66', '192.168.10.32')])
        precious = os.path.join(self.dir, 'Documents')
        os.makedirs(precious)
        with open(os.path.join(precious, 'thesis.docx'), 'wb') as f:
            f.write(b'years of work')
        with self.assertRaises(FileExistsError):
            build_bundle(self.dir, out_dir=precious)
        self.assertTrue(os.path.exists(os.path.join(precious, 'thesis.docx')))
        again = build_bundle(self.dir, out_dir=os.path.join(self.dir, 'bundle'))
        build_bundle(self.dir, out_dir=again['folder'])          # a bundle may be replaced


class TestSettings(unittest.TestCase):

    def test_settings_can_be_set_without_a_write_each(self):
        from src import config
        cfg = reset_config()
        self.addCleanup(reset_config)
        with mock.patch.object(config.Config, 'save') as save:
            cfg.set('alerts', 'cooldown_sec', 31, save=False)
            cfg.set('alerts', 'max_stored', 4000, save=False)
            save.assert_not_called()
            cfg.set('alerts', 'cooldown_sec', 32)
            save.assert_called_once()


class TestElevation(unittest.TestCase):

    @unittest.skipUnless(sys.platform == 'win32', 'elevation is Windows')
    def test_the_exe_is_not_passed_to_itself(self):
        import main
        calls = []
        shell = mock.Mock(ShellExecuteW=lambda *a: calls.append(a) or 42)
        with mock.patch.object(main.ctypes, 'windll', mock.Mock(shell32=shell)), \
                mock.patch.object(sys, 'frozen', True, create=True), \
                mock.patch.object(sys, 'argv', [r'C:\Tools\NetSentinel.exe', '--monitor']), \
                mock.patch.object(sys, 'exit'):
            main.request_admin()
        self.assertEqual(calls[0][3], '--monitor')


if __name__ == '__main__':
    unittest.main()
