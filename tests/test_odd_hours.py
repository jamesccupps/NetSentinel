"""
Off-hours activity is added up.
===============================
The outside review of 2026-11-14 (N9): ODD-HOURS needed one packet with more
than 50,000 bytes of payload, which only segmentation offload produces, so a
device sending gigabytes at 3 a.m. in ordinary packets never raised it. Now
what each device on this network sends in the hour is added up.
"""

import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_third_review import tcp  # noqa: E402

PC = '192.168.10.32'
# Public: Python counts the documentation ranges as private, and so local.
SITE = '93.184.216.34'
THREE_AM = datetime(2026, 11, 14, 3, 10).timestamp()
NOON = datetime(2026, 11, 14, 12, 10).timestamp()


def engine():
    from src.ids_engine import IDSEngine
    alerts = []
    return IDSEngine(reset_config(), alert_callback=alerts.append, offline=True), alerts


def send(ids, total_mb, start, src=PC, dst=SITE, size=1400):
    for i in range(int(total_mb * 1024 * 1024 / size) + 1):
        ids.inspect_packet(tcp(src, 50000, dst, 443, b'x' * size, server=443,
                               ts=start + i * 0.001))


def odd(alerts):
    return [a for a in alerts if a.rule_id == 'ODD-HOURS']


class TestOddHours(unittest.TestCase):

    def test_ordinary_packets_add_up(self):
        ids, alerts = engine()
        send(ids, 60, THREE_AM)
        [alert] = odd(alerts)
        self.assertGreaterEqual(alert.evidence['bytes_this_hour'], 50 * 1024 * 1024)
        self.assertIn('MB sent by 192.168.10.32', alert.description)

    def test_a_little_at_night_is_quiet(self):
        ids, alerts = engine()
        send(ids, 5, THREE_AM)
        self.assertEqual(odd(alerts), [])

    def test_the_same_at_noon_is_quiet(self):
        ids, alerts = engine()
        send(ids, 60, NOON)
        self.assertEqual(odd(alerts), [])

    def test_a_download_from_a_server_is_not_the_servers_activity(self):
        ids, alerts = engine()
        send(ids, 60, THREE_AM, src=SITE, dst=PC)
        self.assertEqual(odd(alerts), [])


if __name__ == '__main__':
    unittest.main()
