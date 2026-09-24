"""
Beaconing detection.
====================
These tests double as the calibration record for the scoring thresholds. If a
weight or cutoff in src/beaconing.py changes, the traffic-shape cases below say
whether it still separates C2 check-ins from ordinary traffic.

Synthetic traffic is generated from a seeded RNG so the numbers are reproducible.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src.beaconing import (  # noqa: E402
    MIN_OBSERVATIONS, bowley_skewness, is_expected_periodic, mad_ratio, score_beacon,
)
from src.capture import PacketInfo  # noqa: E402
from src.config import Config  # noqa: E402

# Below this a destination is not reported. Mirrors ids.beaconing_score_threshold.
THRESHOLD = 0.75


def _rng():
    return random.Random(20260924)


def beacon(interval, jitter, n=40, size=120, size_jitter=0.02, rng=None):
    """Arrival times and payload sizes for a C2-style check-in."""
    rng = rng or _rng()
    t, times, sizes = 1_000_000.0, [], []
    for _ in range(n):
        t += interval * (1 + rng.uniform(-jitter, jitter))
        times.append(t)
        sizes.append(max(1, int(size * (1 + rng.uniform(-size_jitter, size_jitter)))))
    return times, sizes


def poisson(mean_gap, n=40, rng=None):
    """Random arrivals — what ordinary uncoordinated traffic looks like."""
    rng = rng or _rng()
    t, times, sizes = 1_000_000.0, [], []
    for _ in range(n):
        t += rng.expovariate(1.0 / mean_gap)
        times.append(t)
        sizes.append(rng.randint(60, 1460))
    return times, sizes


def browsing(n=40, rng=None):
    """Bursts of requests separated by idle reading time."""
    rng = rng or _rng()
    t, times, sizes = 1_000_000.0, [], []
    while len(times) < n:
        t += rng.uniform(15, 120)
        for _ in range(rng.randint(3, 8)):
            t += rng.uniform(0.02, 0.4)
            times.append(t)
            sizes.append(rng.randint(200, 1460))
            if len(times) >= n:
                break
    return times, sizes


class TestStatistics(unittest.TestCase):

    def test_bowley_is_zero_for_symmetric_data(self):
        self.assertAlmostEqual(bowley_skewness([1, 2, 3, 4, 5, 6, 7, 8, 9]), 0.0, places=6)

    def test_bowley_detects_right_skew(self):
        """Idle gaps with bursts inside them — the shape of human traffic."""
        self.assertGreater(bowley_skewness([1, 1, 1, 1, 1, 2, 3, 20, 100]), 0.3)

    def test_bowley_is_bounded(self):
        for values in ([1] * 20, list(range(50)), [1, 1, 1, 999]):
            self.assertLessEqual(abs(bowley_skewness(values)), 1.0)

    def test_bowley_handles_degenerate_input(self):
        self.assertEqual(bowley_skewness([5, 5, 5, 5]), 0.0)
        self.assertEqual(bowley_skewness([]), 0.0)

    def test_mad_ratio_is_zero_for_constant_data(self):
        self.assertEqual(mad_ratio([10] * 20), 0.0)

    def test_mad_ratio_grows_with_spread(self):
        tight = mad_ratio([100, 101, 99, 100, 102, 98])
        loose = mad_ratio([100, 180, 40, 130, 60, 200])
        self.assertLess(tight, loose)

    def test_mad_ratio_is_robust_to_one_outlier(self):
        """A single missed check-in must not destroy the measurement."""
        clean = mad_ratio([60] * 20)
        with_gap = mad_ratio([60] * 19 + [3600])
        self.assertLess(with_gap - clean, 0.1)


class TestBeaconScoringCalibration(unittest.TestCase):
    """
    The central claim: this survives jitter, and the old CV < 0.05 rule did not.
    """

    def _score(self, times, sizes):
        return score_beacon(times, sizes)['score']

    def test_detects_c2_at_every_realistic_jitter(self):
        for jitter, label in [(0.00, 'no jitter'),
                              (0.10, "Cobalt Strike's default"),
                              (0.20, 'Sliver / Mythic typical'),
                              (0.35, 'heavy'),
                              (0.50, 'aggressive evasion')]:
            with self.subTest(jitter=jitter, label=label):
                score = self._score(*beacon(60, jitter))
                self.assertGreaterEqual(
                    score, THRESHOLD,
                    f"{label} ({jitter:.0%}) scored {score:.3f}, below {THRESHOLD}")

    def test_the_old_cv_rule_would_have_missed_these(self):
        """Documents what was actually wrong, so the fix is not undone later."""
        import statistics
        for jitter in (0.10, 0.20, 0.35, 0.50):
            times, sizes = beacon(60, jitter)
            intervals = [b - a for a, b in zip(times, times[1:])]
            cv = statistics.pstdev(intervals) / statistics.fmean(intervals)
            with self.subTest(jitter=jitter):
                self.assertGreater(cv, 0.05, "precondition: CV rule would not fire")
                self.assertGreaterEqual(self._score(times, sizes), THRESHOLD)

    def test_slow_beacons_are_caught(self):
        for interval in (60, 300, 900, 1800):
            with self.subTest(interval=interval):
                self.assertGreaterEqual(self._score(*beacon(interval, 0.15)), THRESHOLD)

    def test_random_traffic_scores_low(self):
        self.assertLess(self._score(*poisson(45)), THRESHOLD)

    def test_browsing_bursts_score_low(self):
        self.assertLess(self._score(*browsing()), THRESHOLD)

    def test_varying_payload_sizes_weaken_the_score(self):
        """Volume consistency is what separates a beacon from a polling app."""
        rng = _rng()
        steady = score_beacon(*beacon(60, 0.15, rng=rng))['score']
        times, _ = beacon(60, 0.15, rng=_rng())
        noisy_sizes = [rng.randint(100, 20000) for _ in times]
        noisy = score_beacon(times, noisy_sizes)['score']
        self.assertGreater(steady, noisy)


class TestBeaconQualification(unittest.TestCase):

    def test_too_few_observations_is_not_scored(self):
        times, sizes = beacon(60, 0.0, n=MIN_OBSERVATIONS - 1)
        result = score_beacon(times, sizes)
        self.assertFalse(result['qualified'])
        self.assertEqual(result['score'], 0.0)
        self.assertIn('insufficient', result['reason'])

    def test_sub_second_intervals_are_rejected(self):
        """Streaming and websockets are regular but not beacons."""
        result = score_beacon(*beacon(0.05, 0.1, n=60))
        self.assertFalse(result['qualified'])
        self.assertIn('too short', result['reason'])

    def test_very_long_intervals_are_out_of_range(self):
        result = score_beacon(*beacon(7200, 0.05, n=20))
        self.assertFalse(result['qualified'])

    def test_empty_and_degenerate_input(self):
        for times in ([], [1.0], [1.0] * 40):
            result = score_beacon(times)
            self.assertFalse(result['qualified'])
            self.assertEqual(result['score'], 0.0)

    def test_unsorted_input_is_handled(self):
        times, sizes = beacon(60, 0.05)
        shuffled = list(times)
        _rng().shuffle(shuffled)
        self.assertAlmostEqual(score_beacon(shuffled, sizes)['score'],
                               score_beacon(times, sizes)['score'], places=6)

    def test_missing_sizes_are_neutral_not_penalised(self):
        times, sizes = beacon(60, 0.10)
        self.assertEqual(score_beacon(times)['volume'], 0.5)
        self.assertGreater(score_beacon(times, sizes)['volume'], 0.5)

    def test_reason_describes_the_pattern(self):
        result = score_beacon(*beacon(300, 0.10))
        self.assertIn('min', result['reason'])
        self.assertIn('check-ins', result['reason'])


class TestExpectedPeriodicServices(unittest.TestCase):
    """
    NTP scores ~0.90 and should: it is a beacon. Timing cannot separate it from
    C2, so the port does.
    """

    def test_ntp_traffic_is_structurally_a_beacon(self):
        score = score_beacon(*beacon(64, 0.02, size=90))['score']
        self.assertGreaterEqual(score, THRESHOLD,
                                "NTP genuinely looks like a beacon — that is the point")

    def test_known_polling_services_are_excluded(self):
        for port in (123, 53, 67, 68, 161, 514, 5353, 1900):
            with self.subTest(port=port):
                self.assertTrue(is_expected_periodic(dst_port=port))

    def test_ordinary_ports_are_not_excluded(self):
        for port in (443, 80, 8080, 4444, 22):
            with self.subTest(port=port):
                self.assertFalse(is_expected_periodic(dst_port=port))

    def test_source_port_is_considered_too(self):
        self.assertTrue(is_expected_periodic(src_port=123))


class TestEngineIntegration(unittest.TestCase):
    """The eligibility rules around the scorer, in AnomalyDetector."""

    def setUp(self):
        from src.ml_engine import AnomalyDetector
        cfg = Config().load()
        cfg.set('threat_intel', 'auto_update', False)
        self.det = AnomalyDetector(cfg)
        self.det.baseline_whitelist = None

    def _packets(self, dst, interval, jitter, n=40, port=443, size=120):
        rng = _rng()
        t, out = 1_000_000.0, []
        for _ in range(n):
            t += interval * (1 + rng.uniform(-jitter, jitter))
            p = PacketInfo()
            p.src_ip, p.dst_ip, p.dst_port = '192.168.1.50', dst, port
            p.timestamp = t
            p.payload_size = int(size * (1 + rng.uniform(-0.02, 0.02)))
            p.length = p.payload_size + 54
            p.protocol = 'TCP'
            out.append(p)
        return out

    def test_external_c2_is_reported_with_detail(self):
        score = self.det._check_beaconing(self._packets('93.184.1.8', 60, 0.20))
        self.assertGreaterEqual(score, THRESHOLD)
        self.assertIsNotNone(self.det.last_beacon)
        self.assertEqual(self.det.last_beacon['destination'], '93.184.1.8')
        self.assertIn('192.168.1.50', self.det.last_beacon['sources'])

    def test_private_destinations_are_skipped(self):
        """IoT devices legitimately beacon to local hubs."""
        self.assertEqual(self.det._check_beaconing(
            self._packets('192.168.1.99', 60, 0.05)), 0.0)

    def test_ntp_port_is_skipped_even_though_it_scores_high(self):
        self.assertEqual(self.det._check_beaconing(
            self._packets('93.184.1.11', 64, 0.02, port=123, size=90)), 0.0)

    def test_random_traffic_returns_zero(self):
        rng = _rng()
        t, pkts = 1_000_000.0, []
        for _ in range(40):
            t += rng.expovariate(1 / 45)
            p = PacketInfo()
            p.src_ip, p.dst_ip, p.dst_port = '192.168.1.50', '93.184.1.12', 443
            p.timestamp = t
            p.payload_size = rng.randint(60, 1400)
            p.length = p.payload_size + 54
            pkts.append(p)
        self.assertEqual(self.det._check_beaconing(pkts), 0.0)

    def test_score_below_threshold_is_reported_as_zero(self):
        """Merely regular traffic must not leak into the combined anomaly score."""
        score = self.det._check_beaconing(self._packets('93.184.1.20', 60, 0.9))
        self.assertIn(score, (0.0,))

    def test_learned_beacons_are_suppressed(self):
        from src.baseline_whitelist import BaselineWhitelist
        import time
        bl = BaselineWhitelist(Config().load())
        bl.learning_start = time.time() - 10 * 3600
        bl.check_learning_complete()
        bl.observe_beacon('192.168.1.50', '93.184.1.30', 60.0)
        self.det.baseline_whitelist = bl
        self.assertEqual(self.det._check_beaconing(
            self._packets('93.184.1.30', 60, 0.1)), 0.0)

    def test_learning_mode_records_instead_of_alerting(self):
        from src.baseline_whitelist import BaselineWhitelist
        bl = BaselineWhitelist(Config().load())
        bl.is_learning = True
        self.det.baseline_whitelist = bl
        self.assertEqual(self.det._check_beaconing(
            self._packets('93.184.1.40', 60, 0.1)), 0.0)
        self.assertTrue(bl.is_learned_beacon('192.168.1.50', '93.184.1.40'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
