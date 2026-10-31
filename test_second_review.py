"""
What the second review of real alerts found.
============================================
A day of 1.9.0 on the owner's network raised 263 alerts. The first looked at was
a CRITICAL "ARP Spoofing": two smart-home devices that each remembered an old
address, 192.168.1.80, from the network they were set up on, and announced it
once whenever they rejoined Wi-Fi, hours apart. Addresses and MACs here are
made up.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import SCAPY_REAL  # noqa: E402

from test_lan_threats import _Lan, arp  # noqa: E402

STALE = '192.168.1.80'
PLUG, LIGHT = '00:1b:21:00:00:a1', '00:1b:21:00:00:b2'
HOUR = 3600.0


class TestStaleAddressAnnouncements(_Lan):

    def spoof_alerts(self, alerts):
        return [a for a in alerts if a.rule_id == 'ARP-SPOOF']

    def test_devices_announcing_an_old_address_hours_apart_are_not_spoofing(self):
        """The CRITICAL that started this review: once each, hours apart."""
        ids, alerts = self.engine(env=False)
        for n, mac in enumerate((LIGHT, PLUG, LIGHT, PLUG, LIGHT)):
            ids._alert_cooldowns.clear()
            ids.inspect_packet(arp(STALE, mac, ts=1_000_000.0 + n * 5.7 * HOUR, target=STALE))
        self.assertEqual(self.spoof_alerts(alerts), [])

    def test_a_back_and_forth_hours_apart_is_not_two_hosts_fighting(self):
        """Flapping counted however far apart the changes were."""
        ids, alerts = self.engine(env=False)
        for n, mac in enumerate((LIGHT, PLUG, LIGHT)):
            ids._alert_cooldowns.clear()
            for repeat in range(2):
                ids.inspect_packet(arp(STALE, mac, ts=1_000_000.0 + n * 5 * HOUR + repeat))
        self.assertEqual(self.spoof_alerts(alerts), [])

    def test_a_spoofer_contesting_an_address_is_still_caught(self):
        ids, alerts = self.engine(env=False)
        t = 1_000_000.0
        ids.inspect_packet(arp('192.168.1.30', PLUG, ts=t))
        for i in range(2):
            ids.inspect_packet(arp('192.168.1.30', '00:1b:21:66:66:66', ts=t + 5 + i))
        ids._alert_cooldowns.clear()
        for i in range(2):                  # the owner answers back
            ids.inspect_packet(arp('192.168.1.30', PLUG, ts=t + 9 + i))
        found = self.spoof_alerts(alerts)
        self.assertEqual([a.severity for a in found], ['HIGH', 'CRITICAL'])
        self.assertNotIn('gateway', found[0].evidence['recommendation'].lower(),
                         'it told you to check the gateway for a device that is not one')


class TestStaleGatewayPin(unittest.TestCase):

    def test_this_computer_is_no_longer_pinned_as_a_gateway(self):
        """Pinned before the route-table fix, and kept across restarts after it."""
        from src.lan_threats import LanThreatMonitor
        tmp = tempfile.mkdtemp(prefix='ns_pin_')
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, 'lan_state.json')
        pins = {'192.168.8.1': {'mac': '00:11:22:33:44:55', 'pinned_at': 1, 'last_seen': 1},
                '192.168.8.32': {'mac': '00:1b:21:00:00:32', 'pinned_at': 1, 'last_seen': 1}}
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({'gateway_macs': pins}, f)
        env = SimpleNamespace(gateways=['192.168.8.1'], local_ips=['192.168.8.32', '127.0.0.1'])
        lan = LanThreatMonitor(None, net_env=env, state_path=path)
        self.assertEqual(sorted(lan.state['gateway_macs']), ['192.168.8.1'])


@unittest.skipUnless(SCAPY_REAL, 'needs scapy')
class TestArpCaptures(unittest.TestCase):

    def test_an_arp_alert_saves_its_arp(self):
        """The capture said "no packet named the alert's hosts": ARP was never read."""
        from scapy.all import ARP, Dot1Q, Ether
        from src.pcap_writer import _frame_involves
        announce = (Ether(src=LIGHT, dst='ff:ff:ff:ff:ff:ff') / Dot1Q(vlan=3)
                    / ARP(op=1, hwsrc=LIGHT, psrc=STALE, pdst=STALE))
        self.assertTrue(_frame_involves(bytes(announce), {STALE}))
        asking = Ether(src=PLUG, dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, hwsrc=PLUG,
                                                                psrc='192.168.12.169',
                                                                pdst=STALE)
        self.assertTrue(_frame_involves(bytes(asking), {STALE}))
        self.assertFalse(_frame_involves(bytes(asking), {'192.168.12.1'}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
