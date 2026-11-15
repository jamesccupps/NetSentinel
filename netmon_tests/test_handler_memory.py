"""
The stateful rules forget by age.
=================================
The outside review of 2026-11-14 (N10): beaconing kept up to 512 times for
every (source, destination) pair ever seen; new_destination, upload_volume,
unanswered_name and overlapping_ip kept everything, and upload_volume read its
whole map on every event over the floor. Fine for a day's export; `netmon
serve` runs for months. Addresses and names are made up.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.events import Event  # noqa: E402
from netmon.handlers import (beaconing, dhcp_loop, new_destination, overlapping_ip,  # noqa: E402
                             unanswered_name, upload_volume)

DAY = 86400
T0 = 1_800_000_000


class _Rule:
    id = 'test_rule'
    title = 'Test rule'
    severity = 'medium'
    tier = 'digest'
    next_check = ''

    def __init__(self, **params):
        self.params = params


def flow(ts, src='10.10.20.10', dst='198.51.100.7', **kw):
    return Event(kind='flow', ts=ts, src_ip=src, dst_ip=dst, dst_port=8443,
                 protocol='tcp', **kw)


class TestTheyForget(unittest.TestCase):

    def test_beaconing_drops_pairs_that_went_quiet(self):
        rule, state = _Rule(max_interval_sec=3600), {}
        for i in range(2000):                       # a new destination every 10 minutes
            beaconing(flow(T0 + i * 600, dst=f'198.51.{i // 250}.{i % 250}'), rule, state)
        self.assertLess(len(state['series']), 20)

    def test_unanswered_names_past_their_window_are_dropped(self):
        rule, state = _Rule(window_sec=3600), {}
        for i in range(2000):
            unanswered_name(Event(kind='dns', ts=T0 + i * 600, src_ip='10.10.20.10',
                                  fields={'query': f'host{i}.corp.example'}), rule, state)
        self.assertLess(len(state['counts']), 20)

    def test_dhcp_counts_past_their_window_are_dropped(self):
        rule, state = _Rule(window_sec=600), {}
        for i in range(2000):
            dhcp_loop(Event(kind='dhcp', ts=T0 + i * 600, src_mac=f'00:00:5e:00:{i // 250:02x}:'
                                                               f'{i % 250:02x}',
                            fields={'message': 'discover'}), rule, state)
        self.assertLess(len(state['counts']), 10)

    def test_a_destination_unseen_for_long_enough_is_new_again(self):
        rule, state = _Rule(learn_sec=0, forget_sec=30 * DAY), {}
        self.assertIsNotNone(new_destination(flow(T0), rule, state))
        self.assertIsNone(new_destination(flow(T0 + DAY), rule, state))
        for i in range(1, 100):                     # other traffic, every day for 100 days
            new_destination(flow(T0 + i * DAY, dst='198.51.100.8'), rule, state)
        self.assertNotIn('198.51.100.7', state['known']['10.10.20.10'])
        self.assertIsNotNone(new_destination(flow(T0 + 100 * DAY), rule, state))

    def test_upload_history_keeps_its_days_per_device(self):
        rule, state = _Rule(min_bytes=1, history_days=30), {}
        for i in range(200):
            upload_volume(flow(T0 + i * DAY, bytes_to_dst=1000), rule, state)
        self.assertLessEqual(len(state['days']['10.10.20.10']), 32)

    def test_an_upload_spike_is_still_found(self):
        rule, state = _Rule(min_bytes=1000, multiple=4), {}
        for i in range(10):
            self.assertIsNone(upload_volume(flow(T0 + i * DAY, bytes_to_dst=10_000), rule, state))
        self.assertIsNotNone(upload_volume(flow(T0 + 10 * DAY, bytes_to_dst=100_000), rule, state))

    def test_an_address_whose_owner_left_can_be_someone_elses(self):
        """DHCP gives a departed device's address to another: not a conflict."""
        rule, state = _Rule(forget_sec=7 * DAY), {}
        self.assertEqual(overlapping_ip(flow(T0, src_mac='00:00:5e:00:53:01'), rule, state), [])
        later = flow(T0 + 10 * DAY, src_mac='00:00:5e:00:53:02')
        self.assertEqual(overlapping_ip(later, rule, state), [])
        clash = flow(T0 + 10 * DAY + 60, src_mac='00:00:5e:00:53:03')
        self.assertEqual(len(overlapping_ip(clash, rule, state)), 1)


if __name__ == '__main__':
    unittest.main()
