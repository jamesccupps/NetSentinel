"""
Presentation logic.
===================
This logic used to live inside gui.py methods, interleaved with widget calls, so
none of it could be tested — 1,772 statements at 0% coverage. Extracted into pure
functions, it is testable on a headless machine and reusable outside tkinter.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src import presentation as p  # noqa: E402
from src.ids_engine import Alert, Severity  # noqa: E402


class TestByteFormatting(unittest.TestCase):

    def test_scales_through_the_units(self):
        cases = [(0, '0.0 B'), (512, '512.0 B'), (1024, '1.0 KB'),
                 (1536, '1.5 KB'), (1024 ** 2, '1.0 MB'), (1024 ** 3, '1.0 GB'),
                 (1024 ** 4, '1.0 TB'), (1024 ** 5, '1.0 PB')]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(p.format_bytes(value), expected)

    def test_negatives_keep_their_sign(self):
        self.assertEqual(p.format_bytes(-1536), '-1.5 KB')

    def test_garbage_does_not_raise(self):
        for value in (None, 'abc', [], {}):
            self.assertEqual(p.format_bytes(value), '—')

    def test_absurd_values_still_format(self):
        self.assertTrue(p.format_bytes(1024 ** 8).endswith('PB'))


class TestNumberFormatting(unittest.TestCase):

    def test_compacts_large_counts(self):
        cases = [(0, '0'), (999, '999'), (1000, '1.0K'), (15234, '15.2K'),
                 (1_000_000, '1.0M'), (2_500_000, '2.5M'), (3_000_000_000, '3.0B')]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(p.format_number(value), expected)

    def test_negatives_and_garbage(self):
        self.assertEqual(p.format_number(-1500), '-1.5K')
        self.assertEqual(p.format_number(None), '—')


class TestDurationFormatting(unittest.TestCase):

    def test_picks_the_right_granularity(self):
        self.assertEqual(p.format_duration(0), '0m')
        self.assertEqual(p.format_duration(59), '0m')
        self.assertEqual(p.format_duration(3600), '1h 0m')
        self.assertEqual(p.format_duration(3660), '1h 1m')
        self.assertEqual(p.format_duration(93784), '1d 2h 3m')

    def test_negative_clamps_to_zero(self):
        self.assertEqual(p.format_duration(-5), '0m')

    def test_garbage_does_not_raise(self):
        self.assertEqual(p.format_duration(None), '—')


class TestTimestampFormatting(unittest.TestCase):

    def test_formats_and_survives_garbage(self):
        self.assertRegex(p.format_timestamp(1700000000), r'\d{2}:\d{2}:\d{2}')
        for bad in (None, 'x', float('nan'), 1e30):
            self.assertIsInstance(p.format_timestamp(bad), str)


class TestTruncateMiddle(unittest.TestCase):

    def test_short_text_is_untouched(self):
        self.assertEqual(p.truncate_middle('short', 40), 'short')

    def test_long_text_keeps_both_ends(self):
        out = p.truncate_middle('a' * 30 + 'MIDDLE' + 'b' * 30, 20)
        self.assertLessEqual(len(out), 20)
        self.assertTrue(out.startswith('a'))
        self.assertTrue(out.endswith('b'))
        self.assertIn('…', out)


class TestThreatLevel(unittest.TestCase):

    def test_thresholds(self):
        cases = [(0.0, 'SAFE'), (0.1, 'SAFE'), (0.2, 'SAFE'), (0.21, 'GUARDED'),
                 (0.4, 'GUARDED'), (0.41, 'ELEVATED'), (0.7, 'ELEVATED'),
                 (0.71, 'CRITICAL'), (1.0, 'CRITICAL')]
        for score, expected in cases:
            with self.subTest(score=score):
                self.assertEqual(p.threat_level(score)[0], expected)

    def test_returns_a_colour_key(self):
        self.assertEqual(p.threat_level(0.9), ('CRITICAL', 'red'))
        self.assertEqual(p.threat_level(0.0), ('SAFE', 'green'))

    def test_garbage_is_safe(self):
        self.assertEqual(p.threat_level(None)[0], 'SAFE')
        self.assertEqual(p.threat_level('x')[0], 'SAFE')


class TestSeverityHelpers(unittest.TestCase):

    def test_ordering(self):
        self.assertLess(p.severity_rank('LOW'), p.severity_rank('MEDIUM'))
        self.assertLess(p.severity_rank('MEDIUM'), p.severity_rank('HIGH'))
        self.assertLess(p.severity_rank('HIGH'), p.severity_rank('CRITICAL'))

    def test_unknown_severity_sorts_lowest(self):
        self.assertEqual(p.severity_rank('BOGUS'), 0)
        self.assertEqual(p.severity_rank(None), 0)

    def test_case_insensitive(self):
        self.assertEqual(p.severity_rank('critical'), p.severity_rank('CRITICAL'))

    def test_threshold_comparison(self):
        self.assertTrue(p.severity_at_least('CRITICAL', 'HIGH'))
        self.assertTrue(p.severity_at_least('HIGH', 'HIGH'))
        self.assertFalse(p.severity_at_least('MEDIUM', 'HIGH'))


class TestProtocolBreakdown(unittest.TestCase):

    def test_orders_by_count_and_computes_fractions(self):
        out = p.protocol_breakdown({'TCP': 70, 'UDP': 20, 'ICMP': 10})
        self.assertEqual([name for name, _, _ in out], ['TCP', 'UDP', 'ICMP'])
        self.assertAlmostEqual(out[0][2], 0.7)
        self.assertAlmostEqual(sum(frac for _, _, frac in out), 1.0)

    def test_fractions_use_the_full_total_not_the_truncated_one(self):
        """A top-N bar chart must not overstate each slice."""
        protocols = {f'P{i}': 10 for i in range(20)}
        out = p.protocol_breakdown(protocols, limit=5)
        self.assertEqual(len(out), 5)
        self.assertAlmostEqual(out[0][2], 10 / 200)
        self.assertLess(sum(frac for _, _, frac in out), 1.0)

    def test_empty_and_zero_inputs(self):
        self.assertEqual(p.protocol_breakdown({}), [])
        self.assertEqual(p.protocol_breakdown(None), [])
        self.assertEqual(p.protocol_breakdown({'TCP': 0}), [])

    def test_ties_break_deterministically(self):
        a = p.protocol_breakdown({'B': 5, 'A': 5, 'C': 5})
        b = p.protocol_breakdown({'C': 5, 'A': 5, 'B': 5})
        self.assertEqual(a, b, "identical counts must produce a stable order")


class TestTopTalkers(unittest.TestCase):

    def test_largest_first_and_limited(self):
        talkers = {f'10.0.0.{i}': i * 100 for i in range(1, 21)}
        out = p.top_talkers(talkers, limit=5)
        self.assertEqual(len(out), 5)
        self.assertEqual(out[0][0], '10.0.0.20')
        self.assertGreater(out[0][1], out[-1][1])

    def test_empty(self):
        self.assertEqual(p.top_talkers({}), [])
        self.assertEqual(p.top_talkers(None), [])


class TestAlertFiltering(unittest.TestCase):

    def setUp(self):
        self.alerts = [
            Alert('PORT-SCAN', Severity.HIGH, 'Port Scan', 'd',
                  src_ip='203.0.113.9', category='Reconnaissance'),
            Alert('ODD-HOURS', Severity.LOW, 'Odd hours', 'd',
                  src_ip='192.168.1.5', category='Anomaly'),
            Alert('SYN-FLOOD', Severity.CRITICAL, 'SYN Flood', 'd',
                  src_ip='203.0.113.9', category='DoS'),
        ]
        for i, a in enumerate(self.alerts):
            a.timestamp = 1000 + i
        self.alerts[1].acknowledged = True

    def test_filter_by_severity(self):
        out = p.filter_alerts(self.alerts, severity='CRITICAL')
        self.assertEqual([a.rule_id for a in out], ['SYN-FLOOD'])

    def test_all_is_a_passthrough(self):
        self.assertEqual(len(p.filter_alerts(self.alerts, severity='ALL')), 3)
        self.assertEqual(len(p.filter_alerts(self.alerts)), 3)

    def test_filter_by_category_and_time(self):
        self.assertEqual(len(p.filter_alerts(self.alerts, category='DoS')), 1)
        self.assertEqual(len(p.filter_alerts(self.alerts, since=1001)), 2)

    def test_filter_by_acknowledged(self):
        self.assertEqual(len(p.filter_alerts(self.alerts, acknowledged=True)), 1)
        self.assertEqual(len(p.filter_alerts(self.alerts, acknowledged=False)), 2)

    def test_search_spans_the_useful_fields(self):
        self.assertEqual(len(p.filter_alerts(self.alerts, search='203.0.113.9')), 2)
        self.assertEqual(len(p.filter_alerts(self.alerts, search='flood')), 1)
        self.assertEqual(len(p.filter_alerts(self.alerts, search='nothing')), 0)

    def test_works_on_dicts_as_well_as_objects(self):
        as_dicts = [a.to_dict() for a in self.alerts]
        self.assertEqual(len(p.filter_alerts(as_dicts, severity='CRITICAL')), 1)
        self.assertEqual(len(p.filter_alerts(as_dicts, search='port scan')), 1)

    def test_filters_combine(self):
        out = p.filter_alerts(self.alerts, severity='HIGH', category='Reconnaissance')
        self.assertEqual(len(out), 1)

    def test_input_is_not_mutated(self):
        p.filter_alerts(self.alerts, severity='CRITICAL')
        self.assertEqual(len(self.alerts), 3)


class TestAlertSorting(unittest.TestCase):

    def setUp(self):
        self.alerts = []
        for i, sev in enumerate([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]):
            a = Alert(f'R{i}', sev, f'alert-{i}', 'd')
            a.timestamp = 1000 + i
            self.alerts.append(a)

    def test_by_time_newest_first(self):
        out = p.sort_alerts(self.alerts)
        self.assertEqual([a.title for a in out], ['alert-2', 'alert-1', 'alert-0'])

    def test_by_time_oldest_first(self):
        out = p.sort_alerts(self.alerts, newest_first=False)
        self.assertEqual([a.title for a in out], ['alert-0', 'alert-1', 'alert-2'])

    def test_by_severity(self):
        out = p.sort_alerts(self.alerts, key='severity')
        self.assertEqual([a.severity for a in out], ['CRITICAL', 'MEDIUM', 'LOW'])

    def test_severity_ties_break_on_recency(self):
        extra = Alert('R9', Severity.CRITICAL, 'newer-critical', 'd')
        extra.timestamp = 9999
        out = p.sort_alerts(self.alerts + [extra], key='severity')
        self.assertEqual(out[0].title, 'newer-critical')


class TestAlertSummary(unittest.TestCase):

    def test_counts_every_level_even_when_absent(self):
        alerts = [Alert('R', Severity.HIGH, 't', 'd') for _ in range(3)]
        counts = p.summarise_alert_counts(alerts)
        self.assertEqual(counts['HIGH'], 3)
        self.assertEqual(counts['LOW'], 0)
        self.assertEqual(counts['CRITICAL'], 0)
        self.assertEqual(counts['TOTAL'], 3)

    def test_empty_input_has_a_stable_shape(self):
        counts = p.summarise_alert_counts([])
        self.assertEqual(set(counts), {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'TOTAL'})
        self.assertEqual(counts['TOTAL'], 0)

    def test_unknown_severity_is_ignored_not_crashed_on(self):
        counts = p.summarise_alert_counts([Alert('R', 'WEIRD', 't', 'd')])
        self.assertEqual(counts['TOTAL'], 1)
        self.assertEqual(sum(counts[k] for k in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')), 0)


class TestGuiUsesTheSharedLogic(unittest.TestCase):
    """Guard against the extracted logic being duplicated back into gui.py."""

    def test_gui_delegates_rather_than_reimplementing(self):
        root = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(root, 'src', 'gui.py')) as f:
            source = f.read()
        self.assertIn('from src import presentation', source)
        self.assertIn('presentation.threat_level', source)
        self.assertIn('presentation.protocol_breakdown', source)
        self.assertIn('presentation.format_duration', source)
        # The old inline threshold ladder must be gone.
        self.assertNotIn('threat, color = "ELEVATED"', source)

    def test_presentation_module_imports_no_gui_toolkit(self):
        root = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(root, 'src', 'presentation.py')) as f:
            source = f.read()
        self.assertNotIn('import tkinter', source)
        self.assertNotIn('from tkinter', source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
