"""
The adapter the capture listens on.
====================================
A docked laptop, on its dock's cable and its Wi-Fi at once, monitored for over
an hour and counted no packets: Scapy's conf.iface, worked out once when Scapy
loads, was the Wi-Fi, and Stop and Start kept it. The capture now asks the OS
which address it sends from and listens on that adapter, follows it when it
changes, never asks a Wi-Fi adapter for promiscuous mode (some drivers then
deliver nothing), and says so on the dashboards when monitoring sees nothing.
Addresses are made up.
"""

import os
import sys
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

WIFI_IP, CABLE_IP = '10.88.4.21', '10.88.4.22'


def adapter(name, ip, flags='UP+RUNNING+OK', description=''):
    return SimpleNamespace(name=name, description=description or name, flags=flags,
                           ips={4: [ip]}, ip=ip, guid='{%s}' % name)


WIFI = adapter('Wi-Fi', WIFI_IP, 'UP+RUNNING+WIRELESS+OK', 'Example Wi-Fi 6E Adapter')
CABLE = adapter('Ethernet 3', CABLE_IP, description='Example USB-C Dock Ethernet')
UNPLUGGED = adapter('Ethernet', CABLE_IP, 'UP+RUNNING+DISCONNECTED')


class _Ifaces(dict):
    def __init__(self, items, later=()):
        super().__init__((a.guid, a) for a in items)
        self.later = list(later)

    def reload(self):
        for a in self.later:
            self[a.guid] = a


class _Sniffer:
    made = []

    def __init__(self, iface=None, **options):
        self.iface, self.options = iface, options
        self.running = False
        self.thread = SimpleNamespace(is_alive=lambda: self.running)
        _Sniffer.made.append(self)

    def start(self):
        self.running = True

    def stop(self, join=True):
        self.running = False


class _EngineCase(unittest.TestCase):

    def engine(self, ifaces, scapy_choice, route, interface='auto'):
        from src import capture
        self.addCleanup(reset_config)
        cfg = reset_config(**{'capture.interface': interface})
        engine = capture.CaptureEngine(cfg)
        engine._supported_sniff_kwargs = lambda options: dict(options)
        for name, value in (('SCAPY_AVAILABLE', True), ('AsyncSniffer', _Sniffer),
                            ('conf', SimpleNamespace(iface=scapy_choice, ifaces=ifaces))):
            patcher = mock.patch.object(capture, name, value, create=True)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.route = [route]
        patcher = mock.patch.object(capture, 'routed_source_address', create=True,
                                    side_effect=lambda *a: self.route[0])
        patcher.start()
        self.addCleanup(patcher.stop)
        _Sniffer.made = []
        return engine

    def run_capture(self, engine):
        engine._stop_event = threading.Event()
        engine._running = True
        engine._start_capture_thread(engine._stop_event)
        return _Sniffer.made[-1]


class TestWhichAdapter(_EngineCase):

    def test_the_adapter_the_os_sends_from_not_scapys_first_guess(self):
        engine = self.engine(_Ifaces([WIFI, CABLE]), scapy_choice=WIFI, route=CABLE_IP)
        self.assertIs(engine._select_interface(), CABLE)
        self.assertIs(self.run_capture(engine).iface, CABLE)

    def test_an_adapter_connected_since_scapy_loaded_is_found(self):
        engine = self.engine(_Ifaces([WIFI], later=[CABLE]), scapy_choice=WIFI, route=CABLE_IP)
        self.assertIs(engine._select_interface(), CABLE)

    def test_a_disconnected_adapter_is_never_chosen(self):
        engine = self.engine(_Ifaces([WIFI, UNPLUGGED]), scapy_choice=WIFI, route=CABLE_IP)
        self.assertIs(engine._select_interface(), WIFI)

    def test_with_no_route_scapys_choice_stands(self):
        engine = self.engine(_Ifaces([WIFI, CABLE]), scapy_choice=WIFI, route='')
        self.assertIs(engine._select_interface(), WIFI)

    def test_an_adapter_named_in_the_config_is_kept(self):
        engine = self.engine(_Ifaces([WIFI, CABLE]), scapy_choice=WIFI, route=CABLE_IP,
                             interface='Wi-Fi')
        self.assertEqual(engine._select_interface(), 'Wi-Fi')
        self.run_capture(engine)
        self.assertFalse(engine.follow_routed_adapter())

    def test_the_dashboards_name_the_adapter_in_use(self):
        engine = self.engine(_Ifaces([WIFI, CABLE]), scapy_choice=WIFI, route=CABLE_IP)
        self.assertEqual(engine.interface_info()['name'], 'Ethernet 3')


class TestPromiscuousMode(_EngineCase):

    def test_wifi_is_captured_without_it(self):
        engine = self.engine(_Ifaces([WIFI]), scapy_choice=WIFI, route=WIFI_IP)
        self.assertIs(self.run_capture(engine).options['promisc'], False)

    def test_a_cable_still_gets_it(self):
        engine = self.engine(_Ifaces([CABLE]), scapy_choice=CABLE, route=CABLE_IP)
        self.assertIs(self.run_capture(engine).options['promisc'], True)

    def test_wifi_named_in_the_config_is_recognised(self):
        engine = self.engine(_Ifaces([WIFI, CABLE]), scapy_choice=CABLE, route=CABLE_IP,
                             interface='Wi-Fi')
        self.assertIs(self.run_capture(engine).options['promisc'], False)


class TestFollowingTheTraffic(_EngineCase):

    def test_docking_moves_the_capture_to_the_cable(self):
        engine = self.engine(_Ifaces([WIFI, CABLE]), scapy_choice=WIFI, route=WIFI_IP)
        first = self.run_capture(engine)
        self.assertIs(first.iface, WIFI)
        self.assertFalse(engine.follow_routed_adapter())
        self.route[0] = CABLE_IP
        with self.assertLogs('NetSentinel.Capture', level='WARNING') as logs:
            self.assertTrue(engine.follow_routed_adapter())
        self.assertIn('moving the capture', logs.output[0])
        self.assertFalse(first.running)
        self.assertIs(_Sniffer.made[-1].iface, CABLE)
        self.assertTrue(_Sniffer.made[-1].running)
        self.assertEqual(sum(1 for s in _Sniffer.made if s.running), 1)
        self.assertFalse(engine.follow_routed_adapter())

    def test_the_app_looks_each_minute(self):
        from src.app import NETWORK_CHECK_SEC, NetSentinelApp
        app = NetSentinelApp.__new__(NetSentinelApp)
        follows = []
        app.capture_engine = SimpleNamespace(follow_routed_adapter=lambda: follows.append(1))
        app.net_env = SimpleNamespace(refresh_if_changed=lambda: False)
        app._check_network_change(now=1000.0)
        app._check_network_change(now=1000.0 + NETWORK_CHECK_SEC - 1)
        app._check_network_change(now=1000.0 + NETWORK_CHECK_SEC)
        self.assertEqual(len(follows), 2)


class TestNothingCaptured(_EngineCase):

    def test_monitoring_with_no_packets_says_so(self):
        from src import presentation
        from src.capture import NO_PACKETS_WARN_SEC
        engine = self.engine(_Ifaces([WIFI]), scapy_choice=WIFI, route=WIFI_IP)
        self.run_capture(engine)
        self.assertEqual(engine.capture_problem(), '')
        later = engine._sniffer_started + NO_PACKETS_WARN_SEC + 180
        self.assertEqual(engine.capture_problem(now=later), 'No packets on Wi-Fi in 5 minutes')
        with mock.patch.object(time, 'time', return_value=later):
            info = engine.interface_info()
        rows = dict(presentation.network_rows(
            {'detected': True, 'local_ips': [WIFI_IP]}, info))
        self.assertEqual(rows['Capture'], 'No packets on Wi-Fi in 5 minutes')
        engine._atomic_packets += 1
        self.assertEqual(engine.capture_problem(now=later), '')

    def test_the_log_says_it_once(self):
        from src.capture import NO_PACKETS_WARN_SEC
        engine = self.engine(_Ifaces([WIFI]), scapy_choice=WIFI, route=WIFI_IP)
        self.run_capture(engine)
        engine._sniffer_started -= NO_PACKETS_WARN_SEC + 1
        stop = engine._stop_event
        waits = iter([False, False, True])
        stop.wait = lambda timeout=None: next(waits)
        with self.assertLogs('NetSentinel.Capture', level='WARNING') as logs:
            engine._watchdog_loop(stop)
        self.assertEqual(sum('No packets on Wi-Fi' in line for line in logs.output), 1)


if __name__ == '__main__':
    unittest.main()
