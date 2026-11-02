"""
The dashboard's charts and wording.
====================================
The charts drew only what the page had seen since it opened, with no axes and
no readout: a fresh page showed one line. The server now keeps a day of traffic
rates (src/metrics_history.py) and the page asks for a range. Incidents also
read "1 alerts ... within 0s".
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src.metrics_history import MetricsHistory  # noqa: E402
from test_headless import _ApiTestCase  # noqa: E402

T0 = 1_790_000_000.0


class Counters:
    """A capture's running totals, moved on by hand."""

    def __init__(self):
        self.value = {'packets': 0, 'bytes': 0, 'alerts': 0, 'dropped': 0}
        self.running = True

    def __call__(self):
        return dict(self.value) if self.running else None

    def add(self, packets=0, bytes_=0, alerts=0):
        self.value['packets'] += packets
        self.value['bytes'] += bytes_
        self.value['alerts'] += alerts


class TestHistory(unittest.TestCase):

    def setUp(self):
        self.counters = Counters()
        self.history = MetricsHistory(self.counters, interval=5)
        self.history.sample(now=T0)

    def test_rates_are_the_change_over_the_interval(self):
        self.counters.add(packets=500, bytes_=50_000, alerts=2)
        t, pps, bps, alerts, dropped = self.history.sample(now=T0 + 5)
        self.assertEqual((pps, bps, alerts, dropped), (100.0, 10_000.0, 2, 0))

    def test_a_restarted_capture_is_a_gap_not_a_negative_rate(self):
        self.counters.add(packets=500)
        self.history.sample(now=T0 + 5)
        self.counters.value['packets'] = 10          # a new capture engine
        self.assertIsNone(self.history.sample(now=T0 + 10))
        self.counters.add(packets=50)
        self.assertEqual(self.history.sample(now=T0 + 15)[1], 10.0)

    def test_stopped_monitoring_and_a_long_pause_are_gaps(self):
        self.counters.running = False
        self.assertIsNone(self.history.sample(now=T0 + 5))
        self.counters.running = True
        self.assertIsNone(self.history.sample(now=T0 + 10))   # first reading back
        self.assertIsNone(self.history.sample(now=T0 + 60))   # 50 s since the last
        self.assertEqual(self.history.series(minutes=5, now=T0 + 60)['points'], [])

    def test_a_long_range_is_bucketed_with_average_and_peak(self):
        start = (T0 // 120 + 1) * 120                 # buckets sit on whole periods
        self.history = MetricsHistory(self.counters, interval=5)
        self.history.sample(now=start)
        for i in range(1, 24):                        # one bucket's samples
            self.counters.add(packets=50 if i != 7 else 5000)
            self.history.sample(now=start + 5 * i)
        series = self.history.series(minutes=60, max_points=30, now=start + 119)
        self.assertEqual(series['bucket_sec'], 120)
        [point] = series['points']
        fields = dict(zip(series['fields'], point, strict=True))
        self.assertEqual(fields['pps_peak'], 1000.0)
        self.assertAlmostEqual(fields['pps'], (22 * 10 + 1000) / 23, places=1)

    def test_only_the_asked_for_range_is_returned(self):
        for i in range(1, 200):
            self.counters.add(packets=5)
            self.history.sample(now=T0 + 5 * i)
        series = self.history.series(minutes=1, now=T0 + 5 * 199)
        self.assertEqual(len(series['points']), 12)
        self.assertTrue(all(p[0] >= T0 + 5 * 199 - 60 for p in series['points']))


class TestHistoryRoute(_ApiTestCase):

    def test_the_route_serves_the_apps_history(self):
        counters = Counters()
        self.app.metrics_history = MetricsHistory(counters, interval=5)
        self.app.metrics_history.sample()
        counters.add(packets=10)
        import time
        self.app.metrics_history.sample(now=time.time() + 5)
        data = self.get_json('/api/history?minutes=15')
        self.assertEqual(data['fields'][:3], ['t', 'pps', 'pps_peak'])
        self.assertEqual(len(data['points']), 1)

    def test_without_history_the_route_answers_empty(self):
        self.assertEqual(self.get_json('/api/history')['points'], [])

    def test_the_page_has_the_range_picker(self):
        page = self.get('/')[2]
        self.assertIn('id="ranges"', page)
        self.assertIn('id="pps-summary"', page)


class TestIncidentWording(unittest.TestCase):

    def incident(self, count, span):
        from src.alert_correlator import Incident
        from src.ids_engine import Alert
        incident = Incident()
        for _ in range(count):
            incident.add_alert(Alert('FORENSICS-INSECURE-SVC', 'LOW', 't', 'd',
                                     src_ip='192.168.1.50', category='Insecure Service'))
        incident.created, incident.updated = T0, T0 + span    # it keeps wall-clock times
        incident._update_narrative()
        return incident

    def test_one_alert_reads_as_one(self):
        incident = self.incident(1, 0)
        self.assertEqual(incident.title, 'Insecure Service (1 alert)')
        self.assertEqual(incident.narrative, '1 Insecure Service alert from 192.168.1.50.')

    def test_several_give_the_span(self):
        incident = self.incident(3, 200)
        self.assertEqual(incident.narrative,
                         '3 Insecure Service alerts from 192.168.1.50 over 3 minutes.')


if __name__ == '__main__':
    unittest.main()
