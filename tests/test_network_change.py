"""
A change of network is noticed.
===============================
The outside review of 2026-11-14 (N9): the network was detected once, at
start. After moving to another network or a VPN coming up, this PC's
addresses, gateway and subnet stayed the first network's, so its own traffic
on the new one looked like another host's. Now the addresses are compared
once a minute, and a change runs detection again. Addresses are made up.
"""

import os
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401

HOME = ['127.0.0.1', '192.168.10.32']
CAFE = ['127.0.0.1', '10.88.4.17']


class _Detect:
    """net_detect's probes, faked: one network, then another."""

    def __init__(self):
        self.addresses = list(HOME)
        self.runs = 0

    def patches(self):
        from src import net_detect

        def gateway():
            self.runs += 1
            return ['192.168.10.1'] if self.addresses == HOME else ['10.88.4.1']
        return [mock.patch.object(net_detect, 'detect_local_ips', lambda: list(self.addresses)),
                mock.patch.object(net_detect, 'detect_default_gateway', gateway),
                mock.patch.object(net_detect, 'detect_configured_dns_servers', lambda: []),
                mock.patch.object(net_detect, 'detect_dhcp_server', lambda: []),
                mock.patch.object(net_detect, 'get_local_subnet',
                                  lambda: '192.168.10.0/24' if self.addresses == HOME
                                  else '10.88.4.0/24')]


class TestTheEnvironment(unittest.TestCase):

    def setUp(self):
        self.fake = _Detect()
        for p in self.fake.patches():
            p.start()
            self.addCleanup(p.stop)
        from src.net_detect import NetworkEnvironment
        self.env = NetworkEnvironment().detect()

    def test_nothing_changed_runs_nothing(self):
        self.assertFalse(self.env.refresh_if_changed())
        self.assertEqual(self.fake.runs, 1)

    def test_a_new_network_is_detected_again(self):
        self.fake.addresses = list(CAFE)
        self.assertTrue(self.env.refresh_if_changed())
        self.assertEqual((self.env.gateways, self.env.local_subnet),
                         (['10.88.4.1'], '10.88.4.0/24'))
        self.assertIn('10.88.4.17', self.env.local_ips)
        self.assertNotIn('192.168.10.32', self.env.auto_whitelist_ips)
        self.assertFalse(self.env.refresh_if_changed())


class TestTheApp(unittest.TestCase):

    def test_it_looks_once_a_minute_while_monitoring(self):
        from src.app import NETWORK_CHECK_SEC, NetSentinelApp
        app = NetSentinelApp.__new__(NetSentinelApp)
        checks = []
        app.net_env = SimpleNamespace(refresh_if_changed=lambda: checks.append(1) or True)
        self.assertTrue(app._check_network_change(now=1000.0))
        self.assertFalse(app._check_network_change(now=1000.0 + NETWORK_CHECK_SEC - 1))
        self.assertTrue(app._check_network_change(now=1000.0 + NETWORK_CHECK_SEC))
        self.assertEqual(len(checks), 2)

    def test_a_failure_is_not_the_loops_problem(self):
        from src.app import NetSentinelApp
        app = NetSentinelApp.__new__(NetSentinelApp)

        def broken():
            raise OSError('no adapters')
        app.net_env = SimpleNamespace(refresh_if_changed=broken)
        self.assertFalse(app._check_network_change(now=5000.0))


if __name__ == '__main__':
    unittest.main()
