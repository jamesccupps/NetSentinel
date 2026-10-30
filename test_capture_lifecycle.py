"""
Capture threads: one run, one set of threads, and a stop that stops.
=====================================================================
Every CaptureEngine thread polled one shared `_running` flag, and Scapy's sniff()
checks its stop_filter only when a packet arrives. So on a quiet interface a
stopped capture kept its sniffer, and after stop() then a quick start() the old
watchdog and cleanup threads woke up to a True flag and carried on beside the new
ones. The sniffer here is a fake that, like the real one on a quiet interface,
never sees a packet.
"""

import os
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import SCAPY_REAL, reset_config  # noqa: E402


class QuietAsyncSniffer:
    """AsyncSniffer on an interface where nothing ever arrives."""

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.running = False
        self.exception = None
        self._stop = threading.Event()
        self.thread = None

    def start(self):
        def run():
            self.running = True
            self._stop.wait()
            self.running = False
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def stop(self, join=True):
        if not self.running:
            raise RuntimeError("Not running")
        self._stop.set()
        if join:
            self.thread.join()


def quiet_sniff(*args, **kwargs):
    """Plain sniff() on a quiet interface: stop_filter is never consulted."""
    time.sleep(kwargs.get('timeout') or 30)


@unittest.skipUnless(SCAPY_REAL, 'real scapy unavailable')
class TestCaptureLifecycle(unittest.TestCase):

    def setUp(self):
        from src import capture
        self.capture_module = capture
        patches = [mock.patch.object(capture, 'AsyncSniffer', QuietAsyncSniffer, create=True),
                   mock.patch.object(capture, 'sniff', quiet_sniff),
                   mock.patch.object(capture, 'PSUTIL_AVAILABLE', False)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.engine = capture.CaptureEngine(reset_config())
        self.addCleanup(self.engine.stop)

    def test_stop_ends_the_sniffer_on_a_quiet_interface(self):
        self.assertTrue(self.engine.start())
        sniffer_thread = self.engine._thread
        self.assertTrue(sniffer_thread.is_alive())
        self.engine.stop()
        sniffer_thread.join(2)
        self.assertFalse(sniffer_thread.is_alive(), "the sniffer outlived stop()")

    def test_a_quick_restart_leaves_no_old_threads(self):
        self.engine.start()
        old = {name: getattr(self.engine, name) for name in
               ('_thread', '_worker_thread', '_watchdog_thread', '_cleanup_thread')}
        self.engine.stop()
        self.engine.start()
        for name, thread in old.items():
            thread.join(1.5)
            with self.subTest(thread=name):
                self.assertFalse(thread.is_alive(), f"old {name} still running after restart")
        self.assertIsNot(self.engine._watchdog_thread, old['_watchdog_thread'])
        self.assertTrue(self.engine._watchdog_thread.is_alive())

    def test_start_twice_is_one_run(self):
        self.engine.start()
        first = self.engine._worker_thread
        self.assertTrue(self.engine.start())
        self.assertIs(self.engine._worker_thread, first)

    def test_stop_straight_after_start_still_stops(self):
        """AsyncSniffer.stop() refuses until its thread is running."""
        self.engine.start()
        self.engine.stop()
        self.engine._thread.join(2)
        self.assertFalse(self.engine._thread.is_alive())


class TestSamplingAndBuffers(unittest.TestCase):

    def test_packets_skipped_by_sampling_are_counted(self):
        from src.capture import CaptureEngine, PacketInfo
        engine = CaptureEngine(reset_config())
        delivered = []
        engine.packet_callback = delivered.append
        for _ in range(1500):                    # backlog > 1000 -> 1 in 4
            p = PacketInfo()
            p.src_ip, p.dst_ip, p.protocol, p.length = '10.0.0.1', '10.0.0.2', 'TCP', 60
            engine._packet_queue.put_nowait(p)
        stop = threading.Event()
        worker = threading.Thread(target=engine._worker_loop, args=(stop,), daemon=True)
        worker.start()
        deadline = time.time() + 10
        while not engine._packet_queue.empty() and time.time() < deadline:
            time.sleep(0.05)
        time.sleep(0.6)
        stop.set()
        worker.join(2)
        sampled = engine.stats['packets_sampled_out']
        self.assertGreater(sampled, 0)
        self.assertEqual(sampled + len(delivered), 1500)
        self.assertTrue(any(p.sample_weight > 1 for p in delivered))

    def test_flow_dns_query_list_is_capped(self):
        from src.capture import NetworkFlow, PacketInfo, MAX_FLOW_DNS_QUERIES
        flow = NetworkFlow(('10.0.0.1', '10.0.0.53', 53, 40000, 'UDP'))
        for i in range(MAX_FLOW_DNS_QUERIES * 5):
            p = PacketInfo()
            p.src_ip, p.dns_query = '10.0.0.1', f'n{i}.example'
            flow.add_packet(p)
        self.assertEqual(len(flow.dns_queries), MAX_FLOW_DNS_QUERIES)

    @unittest.skipUnless(SCAPY_REAL, 'real scapy unavailable')
    def test_ring_buffer_gets_the_wire_bytes_without_a_rebuild(self):
        from scapy.all import Ether, IP, TCP, Raw
        from src.capture import CaptureEngine
        got = []
        engine = CaptureEngine(reset_config(), raw_packet_callback=got.append)
        wire = bytes(Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src='1.2.3.4', dst='5.6.7.8') /
                     TCP(sport=1, dport=8000, flags='PA') / Raw(load=b'x' * 200))
        packet = Ether(wire)
        calls = []
        original = type(packet).build

        def counting_build(self, *a, **kw):
            calls.append(1)
            return original(self, *a, **kw)

        type(packet).build = counting_build
        try:
            engine._capture_callback(packet)
        finally:
            type(packet).build = original
        self.assertEqual(got, [wire])
        self.assertEqual(calls, [], "bytes(packet) rebuilt the packet for the ring buffer")


if __name__ == '__main__':
    unittest.main()
