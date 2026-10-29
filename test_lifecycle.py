"""
Starting and stopping monitoring.
==================================
The browser dashboard can now start and stop monitoring as well as the desktop
window, from another thread, so a start that ran twice or a restart that left the
last run's threads behind stopped being a corner case.

The app is built without its __init__, which detects the network and loads threat
feeds, and given fakes for everything start and stop touch.
"""

import os
import sys
import threading
import time
import unittest
from collections import deque
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src import app as app_module  # noqa: E402
from src.app import NetSentinelApp  # noqa: E402
from src.config import Config  # noqa: E402
from src.feature_store import FeatureStore  # noqa: E402


class _Capture:
    def __init__(self, starts=True):
        self.starts = starts
        self.start_calls = 0
        self.is_running = False
        self._thread = None
        self._watchdog_thread = None

    def start(self):
        self.start_calls += 1
        self.is_running = self.starts
        return self.starts

    def stop(self):
        self.is_running = False

    def get_flows_snapshot(self):
        return {}


class _Recorder:
    """Accepts any method call and counts it."""

    def __init__(self, **returns):
        self.calls = {}
        self._returns = returns

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)

        def method(*args, **kwargs):
            self.calls[name] = self.calls.get(name, 0) + 1
            return self._returns.get(name)
        return method


def make_app(capture=None, interval=0.05):
    app = NetSentinelApp.__new__(NetSentinelApp)
    app.config = Config().load()
    app.capture_engine = capture or _Capture()
    app.ioc_scanner = _Recorder(run_startup_scan=[], check_packet_ioc=[])
    app.device_learner = _Recorder()
    app.baseline_whitelist = _Recorder()
    app.baseline_whitelist.is_learning = False
    app.alert_manager = _Recorder()
    app.ml_engine = SimpleNamespace(baseline=_Recorder(), is_trained=False)
    app.alert_correlator = _Recorder()
    app.pcap_writer = _Recorder()
    app.forensics_db = _Recorder()
    app.feature_store = _Recorder()
    app.ids_engine = _Recorder()
    app.forensics_enabled = False
    app.net_env = SimpleNamespace(local_ips=set())
    app._packet_window = deque(maxlen=100)
    app._analysis_interval = interval
    app._alert_cooldown = 30
    app._alert_cooldowns = {}
    import queue
    app._verify_queue = queue.Queue()
    app.review = None
    app._running = False
    app._lifecycle_lock = threading.Lock()
    app._stop_event = threading.Event()
    app._stop_event.set()
    app.last_start_error = ''
    return app


class TestStart(unittest.TestCase):

    def tearDown(self):
        if getattr(self, 'app', None) is not None:
            self.app.stop_monitoring()

    def test_a_second_start_does_nothing(self):
        """It reran the startup IOC scan and started a second analysis loop."""
        self.app = make_app()
        self.assertTrue(self.app.start_monitoring())
        first = self.app._analysis_thread
        self.assertTrue(self.app.start_monitoring())
        self.assertIs(self.app._analysis_thread, first)
        self.assertEqual(self.app.ioc_scanner.calls['run_startup_scan'], 1)
        self.assertEqual(self.app.capture_engine.start_calls, 1)

    def test_a_quick_restart_leaves_one_set_of_loops(self):
        """
        The old loops slept, woke, found the shared flag set again by the new run,
        and carried on beside it.
        """
        self.app = make_app(interval=0.2)
        self.app.start_monitoring()
        old_analysis, old_verify = self.app._analysis_thread, self.app._verify_thread
        self.app.stop_monitoring()
        self.app.start_monitoring()
        old_analysis.join(1)
        old_verify.join(1)
        self.assertFalse(old_analysis.is_alive())
        self.assertFalse(old_verify.is_alive())
        self.assertTrue(self.app._analysis_thread.is_alive())

    def test_a_failed_capture_says_why_and_is_not_running(self):
        """It used to stay 'running' with no capture, which the UI could not tell."""
        self.app = make_app(capture=_Capture(starts=False))
        self.assertFalse(self.app.start_monitoring())
        self.assertIn('Npcap', self.app.last_start_error)
        self.assertFalse(self.app.is_monitoring)
        self.assertFalse(self.app._running)

    def test_a_restart_waits_for_the_last_capture_thread(self):
        """Two capture threads on one interface would double every packet."""
        capture = _Capture()
        blocked = threading.Event()
        capture._thread = threading.Thread(target=blocked.wait, daemon=True)
        capture._thread.start()
        self.addCleanup(blocked.set)
        self.app = make_app(capture=capture)
        with mock.patch.object(app_module, 'CAPTURE_EXIT_WAIT', 0.1):
            self.assertFalse(self.app.start_monitoring())
        self.assertIn('still shutting down', self.app.last_start_error)
        self.assertEqual(capture.start_calls, 0)

        blocked.set()
        capture._thread.join(1)
        self.assertTrue(self.app.start_monitoring())

    def test_stop_saves_even_when_start_failed(self):
        """Closing the window after a failed start must still keep the alerts."""
        self.app = make_app(capture=_Capture(starts=False))
        self.app.start_monitoring()
        self.app.stop_monitoring()
        self.assertEqual(self.app.alert_manager.calls['save_alerts'], 1)

    def test_alerts_are_saved_while_running(self):
        """They reached disk only on a clean stop, so a crash lost the session."""
        self.app = make_app(interval=0.02)
        self.app.start_monitoring()
        deadline = time.time() + 2
        while not self.app.alert_manager.calls.get('maybe_autosave') \
                and time.time() < deadline:
            time.sleep(0.02)
        self.assertGreater(self.app.alert_manager.calls.get('maybe_autosave', 0), 0)

    def test_start_and_stop_from_two_threads_at_once(self):
        self.app = make_app()
        threads = [threading.Thread(target=self.app.start_monitoring)
                   for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        self.assertEqual(self.app.capture_engine.start_calls, 1)


class TestCooldownOutsideTheEngine(unittest.TestCase):

    def test_an_ioc_matching_every_packet_alerts_once(self):
        """IOC-DOH-BYPASS and IOC-TOR alerted on every packet of a connection."""
        app = make_app()
        finding = {'rule_id': 'IOC-DOH-BYPASS', 'severity': 'MEDIUM',
                   'title': 'DoH', 'description': 'd'}
        app.ioc_scanner = _Recorder(check_packet_ioc=[finding])
        raised = []
        app._alert_gateway = raised.append
        pkt = SimpleNamespace(src_ip='192.168.1.5', dst_ip='1.1.1.1', src_port=50000,
                              dst_port=443, protocol='TCP', domain='', timestamp=time.time())
        for _ in range(5):
            app._on_packet(pkt)
        self.assertEqual(len(raised), 1)

        other = SimpleNamespace(**dict(vars(pkt), dst_ip='8.8.8.8'))
        app._on_packet(other)
        self.assertEqual(len(raised), 2)


class _Widget:
    def __init__(self):
        self.options = {}

    def config(self, **options):
        self.options.update(options)


class TestTheWindowFollowsTheEngine(unittest.TestCase):

    def setUp(self):
        try:
            from src.gui import NetSentinelGUI
        except ImportError:
            self.skipTest('tkinter is not installed')
        self.gui = NetSentinelGUI.__new__(NetSentinelGUI)
        self.gui.app = SimpleNamespace(is_monitoring=False, last_start_error='')
        self.gui._monitoring = False
        self.gui._lifecycle_thread = None
        self.gui._lifecycle_was_start = False
        for name in ('_start_btn', '_status_label', '_status_dot', '_statusbar_text'):
            setattr(self.gui, name, _Widget())

    def test_a_start_from_the_browser_shows_in_the_window(self):
        self.gui.app.is_monitoring = True
        self.gui._sync_monitoring()
        self.assertTrue(self.gui._monitoring)
        self.assertIn('STOP', self.gui._start_btn.options['text'])

    def test_a_failed_start_does_not_claim_to_be_monitoring(self):
        """The window used to say MONITORING whatever start_monitoring returned."""
        self.gui.app.last_start_error = 'Packet capture failed to start.'
        self.gui._lifecycle_was_start = True
        self.gui._lifecycle_thread = threading.Thread(target=lambda: None)
        self.gui._lifecycle_thread.start()
        self.gui._lifecycle_thread.join()
        with mock.patch('src.gui.messagebox') as box:
            self.gui._sync_monitoring()
        self.assertFalse(self.gui._monitoring)
        self.assertEqual(self.gui._status_label.options['text'], 'STOPPED')
        self.assertEqual(self.gui._statusbar_text.options['text'],
                         'Packet capture failed to start.')
        self.assertEqual(self.gui._start_btn.options['state'], 'normal')
        box.showwarning.assert_called_once()


class TestFeatureStoreRestart(unittest.TestCase):

    def test_it_flushes_again_after_a_restart(self):
        """
        Stopping monitoring shut the flush thread down for good, so after a restart
        rows piled up in the 100-row buffer and the oldest were dropped.
        """
        store = FeatureStore(Config().load())
        self.addCleanup(store.shutdown)
        first = store._flush_thread
        store.shutdown()
        store.start()
        first.join(1)
        self.assertFalse(first.is_alive(), "the last run's flush thread must exit")
        self.assertTrue(store._flush_thread.is_alive())
        self.assertIsNot(store._flush_thread, first)


if __name__ == '__main__':
    unittest.main(verbosity=2)
