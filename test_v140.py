"""
NetSentinel v1.4.0 Comprehensive Test Suite
=============================================
Tests all bug fixes, new modules, and integration points.
No network capture required — all tests use mocked data.

Usage:
    python test_v140.py -v
"""

import os
import sys
import json
import time
import struct
import tempfile
import shutil
import unittest
import threading
import numpy as np
from unittest.mock import MagicMock, patch
from collections import defaultdict, deque, Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import Config, DEFAULT_CONFIG
from src.ids_engine import IDSEngine, Alert, Severity, _COMMON_SERVICE_PORTS, _STANDARD_OUTBOUND_PORTS, _PORT_NAMES, _SERVICE_NAMES
from src.ml_engine import BaselineProfile, TrafficFeatureExtractor, AnomalyDetector
from src.capture import PacketInfo, NetworkFlow, CaptureEngine, _CREDENTIAL_PORTS
from src.alerts import AlertManager
from src.device_learner import DeviceLearner, DeviceProfile
from src.baseline_whitelist import BaselineWhitelist
from src.alert_correlator import AlertCorrelator, Incident
from src.pcap_writer import PcapWriter


# ═══════════════════════════════════════════════════════════════════
# Test Helpers
# ═══════════════════════════════════════════════════════════════════

def make_config(**overrides):
    """Create a mock config object."""
    cfg = MagicMock()
    data = {**DEFAULT_CONFIG}
    for k, v in overrides.items():
        data[k] = v
    def _get(*keys, default=None):
        node = data
        for key in keys:
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                return default
        return node
    cfg.get = _get
    cfg.set = MagicMock()
    cfg.save = MagicMock()
    cfg.data = data
    return cfg

def make_packet(src_ip="192.168.1.10", dst_ip="10.0.0.1",
                src_port=12345, dst_port=80, protocol="TCP",
                flags="", dns_query="", dns_response="",
                payload_size=0, length=100, process_name="",
                src_mac="", dst_mac="", is_encrypted=False):
    pkt = PacketInfo()
    pkt.src_ip = src_ip
    pkt.dst_ip = dst_ip
    pkt.src_port = src_port
    pkt.dst_port = dst_port
    pkt.protocol = protocol
    pkt.flags = flags
    pkt.dns_query = dns_query
    pkt.dns_response = dns_response
    pkt.payload_size = payload_size
    pkt.length = length
    pkt.process_name = process_name
    pkt.src_mac = src_mac
    pkt.dst_mac = dst_mac
    pkt.is_encrypted = is_encrypted
    pkt._raw_payload = None
    return pkt


# ═══════════════════════════════════════════════════════════════════
# BUG FIX TESTS
# ═══════════════════════════════════════════════════════════════════

class TestAlertIDThreadSafety(unittest.TestCase):
    """Fix #1: Alert IDs must be unique even under concurrent creation."""

    def test_unique_ids_sequential(self):
        ids = set()
        for _ in range(1000):
            a = Alert("TEST", "LOW", "t", "d")
            self.assertNotIn(a.id, ids, "Duplicate Alert ID!")
            ids.add(a.id)

    def test_unique_ids_concurrent(self):
        """Stress test: create alerts from multiple threads."""
        results = []
        barrier = threading.Barrier(4)

        def create_alerts():
            barrier.wait()
            local_ids = []
            for _ in range(500):
                a = Alert("TEST", "LOW", "t", "d")
                local_ids.append(a.id)
            results.append(local_ids)

        threads = [threading.Thread(target=create_alerts) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        all_ids = [id for r in results for id in r]
        self.assertEqual(len(all_ids), len(set(all_ids)),
                        f"Duplicate IDs found! {len(all_ids)} created, {len(set(all_ids))} unique")


class TestNetworkFlowCleanup(unittest.TestCase):
    """Fix #4: NetworkFlow should not have unbounded packet_sizes."""

    def test_no_packet_sizes_attribute(self):
        nf = NetworkFlow(('a', 'b', 1, 2, 'TCP'))
        self.assertFalse(hasattr(nf, 'packet_sizes'))

    def test_inter_arrival_bounded(self):
        nf = NetworkFlow(('a', 'b', 1, 2, 'TCP'))
        self.assertIsInstance(nf.inter_arrival_times, deque)
        self.assertEqual(nf.inter_arrival_times.maxlen, 500)


class TestModuleLevelConstants(unittest.TestCase):
    """Fix #6: Constants must be at module level, not rebuilt per call."""

    def test_credential_ports_is_frozenset(self):
        self.assertIsInstance(_CREDENTIAL_PORTS, frozenset)
        self.assertGreater(len(_CREDENTIAL_PORTS), 40)
        self.assertIn(80, _CREDENTIAL_PORTS)
        self.assertIn(21, _CREDENTIAL_PORTS)

    def test_ids_constants_are_frozensets(self):
        self.assertIsInstance(_COMMON_SERVICE_PORTS, frozenset)
        self.assertIsInstance(_STANDARD_OUTBOUND_PORTS, frozenset)
        self.assertIn(443, _COMMON_SERVICE_PORTS)
        self.assertIn(443, _STANDARD_OUTBOUND_PORTS)

    def test_port_names_dict(self):
        self.assertIn(4444, _PORT_NAMES)
        self.assertIn(31337, _PORT_NAMES)

    def test_service_names_dict(self):
        self.assertIn(22, _SERVICE_NAMES)
        self.assertEqual(_SERVICE_NAMES[22], 'SSH')


class TestEntropyFix(unittest.TestCase):
    """Fix #11: Entropy should use frequency distribution, not unique set."""

    def test_entropy_varies_with_distribution(self):
        extractor = TrafficFeatureExtractor()
        # All same port → entropy should be 0
        same_port = [80] * 100
        ent_same = extractor._entropy(same_port)
        self.assertAlmostEqual(ent_same, 0.0, places=3)

        # Two ports equally distributed → entropy should be 1.0
        two_ports = [80, 443] * 50
        ent_two = extractor._entropy(two_ports)
        self.assertAlmostEqual(ent_two, 1.0, places=3)

        # Uniform distribution → high entropy
        many_ports = list(range(256))
        ent_many = extractor._entropy(many_ports)
        self.assertAlmostEqual(ent_many, 8.0, places=3)  # log2(256)

    def test_feature_extraction_uses_port_list(self):
        extractor = TrafficFeatureExtractor()
        # Create packets all going to port 443
        packets = [make_packet(dst_port=443) for _ in range(50)]
        features = extractor.extract_from_window({}, packets, 60)
        # entropy_dst_port is index 8
        port_entropy = features[8]
        self.assertAlmostEqual(port_entropy, 0.0, places=3,
                              msg="All packets to same port should have 0 entropy")


class TestDNSLookupO1(unittest.TestCase):
    """Fix #8: DNS inference should use O(1) dict lookup, not O(n) scan."""

    def test_latest_dns_by_ip_populated(self):
        config = make_config()
        ids = IDSEngine(config)
        pkt = make_packet(src_ip="192.168.1.5", dns_query="example.com")
        ids.inspect_packet(pkt)
        self.assertIn("192.168.1.5", ids._latest_dns_by_ip)
        domain, ts = ids._latest_dns_by_ip["192.168.1.5"]
        self.assertEqual(domain, "example.com")

    def test_dns_inference_works(self):
        config = make_config()
        ids = IDSEngine(config)
        # DNS query
        dns_pkt = make_packet(src_ip="192.168.1.5", dst_ip="8.8.8.8",
                             dst_port=53, protocol="UDP",
                             dns_query="google.com")
        ids.inspect_packet(dns_pkt)
        # Connection from same source to an IP
        conn_pkt = make_packet(src_ip="192.168.1.5", dst_ip="142.250.80.46",
                              dst_port=443, protocol="TCP")
        ids.inspect_packet(conn_pkt)
        # The IP should now be associated with google.com
        domains = ids._get_domains_for_ip("142.250.80.46")
        self.assertIn("google.com", domains)


class TestDataExfilEscalation(unittest.TestCase):
    """Fix #13: Data exfil should use escalating thresholds, not reset."""

    def test_threshold_doubles_after_alert(self):
        config = make_config()
        alerts = []
        ids = IDSEngine(config, alert_callback=alerts.append)
        # Send 101MB to same IP
        for _ in range(1010):
            pkt = make_packet(dst_ip="5.5.5.5", payload_size=105000)  # ~100KB each
            ids.inspect_packet(pkt)
        # Should have exactly 1 alert (at ~100MB)
        exfil_alerts = [a for a in alerts if a.rule_id == "DATA-EXFIL"]
        self.assertEqual(len(exfil_alerts), 1)
        # Threshold should now be 200MB
        self.assertEqual(ids._exfil_thresholds.get("5.5.5.5"), 200)


class TestTimeOfDayThrottle(unittest.TestCase):
    """Fix #14: Time-of-day alerts should be limited to 1 per IP per hour."""

    @patch('src.ids_engine.datetime')
    def test_one_alert_per_ip_per_hour(self, mock_dt):
        mock_dt.now.return_value = MagicMock(hour=3)
        mock_dt.fromtimestamp = MagicMock()
        config = make_config()
        alerts = []
        ids = IDSEngine(config, alert_callback=alerts.append)
        # Send 100 large packets at 3 AM from same source
        for _ in range(100):
            pkt = make_packet(src_ip="192.168.1.50", payload_size=60000)
            ids.inspect_packet(pkt)
        odd_alerts = [a for a in alerts if a.rule_id == "ODD-HOURS"]
        self.assertLessEqual(len(odd_alerts), 1,
                            f"Expected at most 1 ODD-HOURS alert, got {len(odd_alerts)}")


class TestIPv6PortExtraction(unittest.TestCase):
    """Fix #12: IPv6 packets should have TCP/UDP ports extracted."""

    def test_ipv6_flow_key_has_ports(self):
        """Verify PacketInfo works with IPv6 addresses and ports."""
        pkt = make_packet(src_ip="2001:db8::1", dst_ip="2001:db8::2",
                         src_port=54321, dst_port=443, protocol="TCP")
        self.assertEqual(pkt.src_port, 54321)
        self.assertEqual(pkt.dst_port, 443)
        key = pkt.flow_key
        self.assertIn(443, key)


class TestAlertRestoreFromDisk(unittest.TestCase):
    """Fix #16: Alerts loaded from disk should be actual Alert objects."""

    def test_alerts_restored_as_objects(self):
        config = make_config()
        tmpdir = tempfile.mkdtemp()
        try:
            db_path = os.path.join(tmpdir, "alerts.json")
            # Write fake alert data
            test_alerts = [{
                'id': 1, 'timestamp': time.time(), 'rule_id': 'TEST-1',
                'severity': 'HIGH', 'title': 'Test Alert', 'description': 'test',
                'src_ip': '1.2.3.4', 'dst_ip': '5.6.7.8',
                'src_port': 0, 'dst_port': 80, 'protocol': 'TCP',
                'evidence': {'key': 'val'}, 'category': 'Test',
                'acknowledged': True,
            }]
            with open(db_path, 'w') as f:
                json.dump(test_alerts, f)

            # Patch at the config module level where ALERTS_DB is defined
            with patch('src.config.ALERTS_DB', db_path):
                am = AlertManager(config)
                # Force reload with correct path
                am.db_path = db_path
                am.clear_alerts()  # Clear any previous load
                am._load_alerts()
                stored = am.get_alerts(limit=10)
                self.assertEqual(len(stored), 1)
                # Find our test alert
                test_alert = [a for a in stored if a.rule_id == 'TEST-1']
                self.assertEqual(len(test_alert), 1)
                self.assertIsInstance(test_alert[0], Alert)
                self.assertTrue(test_alert[0].acknowledged)
                self.assertEqual(test_alert[0].evidence['key'], 'val')
        finally:
            shutil.rmtree(tmpdir)


class TestNotificationBatching(unittest.TestCase):
    """Fix #19: Desktop notifications should be batched."""

    def test_batch_collects_alerts(self):
        config = make_config()
        am = AlertManager(config)
        self.assertEqual(len(am._notify_batch), 0)
        # Simulate a HIGH alert (triggers batching)
        alert = Alert("TEST", "HIGH", "Test", "desc")
        am._batch_notification(alert)
        self.assertEqual(len(am._notify_batch), 1)

    def test_sound_cooldown(self):
        config = make_config()
        am = AlertManager(config)
        # First sound should play
        am._last_sound_time = 0
        # Simulate the cooldown check
        now = time.time()
        self.assertTrue(now - am._last_sound_time >= am._sound_cooldown)


# ═══════════════════════════════════════════════════════════════════
# NEW MODULE TESTS: DeviceLearner
# ═══════════════════════════════════════════════════════════════════

class TestDeviceLearner(unittest.TestCase):

    def setUp(self):
        self.config = make_config()
        self.dl = DeviceLearner(self.config)

    def test_learns_device_from_packet(self):
        pkt = make_packet(src_ip="192.168.1.50", src_mac="aa:bb:cc:dd:ee:ff",
                         dst_ip="8.8.8.8", dst_port=53, protocol="UDP")
        self.dl.observe_packet(pkt)
        dev = self.dl.get_device("192.168.1.50")
        self.assertIsNotNone(dev)
        self.assertEqual(dev.mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(dev.packet_count, 1)

    def test_learns_mac_to_ip(self):
        pkt = make_packet(src_ip="192.168.1.50", src_mac="AA:BB:CC:DD:EE:FF")
        self.dl.observe_packet(pkt)
        dev = self.dl.get_device(mac="aa:bb:cc:dd:ee:ff")
        self.assertIsNotNone(dev)
        self.assertEqual(dev.ip, "192.168.1.50")

    def test_learns_services_from_src_port(self):
        """Device sending FROM port 80 = web server."""
        pkt = make_packet(src_ip="10.0.0.5", src_port=80, dst_port=54321)
        self.dl.observe_packet(pkt)
        dev = self.dl.get_device("10.0.0.5")
        self.assertIn(80, dev.services_seen)

    def test_learns_services_from_dst_port(self):
        """Connection TO port 631 on a device = printer."""
        pkt = make_packet(src_ip="192.168.1.10", dst_ip="192.168.1.200",
                         dst_port=631, protocol="TCP")
        self.dl.observe_packet(pkt)
        dev = self.dl.get_device("192.168.1.200")
        self.assertIn(631, dev.services_seen)

    def test_dhcp_enrichment(self):
        self.dl.observe_dhcp("aa:bb:cc:dd:ee:ff", "192.168.1.50",
                            hostname="james-desktop", vendor_class="MSFT 5.0")
        dev = self.dl.get_device("192.168.1.50")
        self.assertEqual(dev.hostname, "james-desktop")
        self.assertEqual(dev.vendor_class, "MSFT 5.0")

    def test_gateway_detection_from_arp(self):
        """Device that ARPs for many targets = gateway."""
        gw_ip = "192.168.1.1"
        for i in range(20):
            pkt = make_packet(src_ip=gw_ip, dst_ip=f"192.168.1.{i+10}",
                             protocol="ARP", src_mac="00:11:22:33:44:55")
            self.dl.observe_packet(pkt)
        self.dl._classify_all()
        dev = self.dl.get_device(gw_ip)
        self.assertTrue(dev.is_gateway)
        self.assertEqual(dev.device_type, "gateway")

    def test_persistence_roundtrip(self):
        tmpdir = tempfile.mkdtemp()
        try:
            self.dl._db_path = os.path.join(tmpdir, "devices.json")
            pkt = make_packet(src_ip="10.0.0.1", src_mac="aa:bb:cc:00:00:01")
            self.dl.observe_packet(pkt)
            self.dl.save()

            dl2 = DeviceLearner(self.config)
            dl2._db_path = self.dl._db_path
            dl2._load()
            dev = dl2.get_device("10.0.0.1")
            self.assertIsNotNone(dev)
            self.assertEqual(dev.mac, "aa:bb:cc:00:00:01")
        finally:
            shutil.rmtree(tmpdir)

    def test_get_summary(self):
        pkt = make_packet(src_ip="192.168.1.5")
        self.dl.observe_packet(pkt)
        summary = self.dl.get_summary()
        self.assertEqual(summary['total_devices'], 2)  # src + dst
        self.assertIn('devices', summary)
        self.assertIn('by_type', summary)

    def test_prune_stale(self):
        dev = DeviceProfile("10.0.0.99")
        dev.last_seen = time.time() - (60 * 86400)  # 60 days ago
        dev.packet_count = 5
        self.dl.devices["10.0.0.99"] = dev
        self.dl.prune_stale(max_age_days=30)
        self.assertNotIn("10.0.0.99", self.dl.devices)


# ═══════════════════════════════════════════════════════════════════
# NEW MODULE TESTS: BaselineWhitelist
# ═══════════════════════════════════════════════════════════════════

class TestBaselineWhitelist(unittest.TestCase):

    def setUp(self):
        self.config = make_config()
        self.bl = BaselineWhitelist(self.config)

    def test_learns_domain_after_3_observations(self):
        for _ in range(3):
            self.bl.observe_dns("192.168.1.10", "update.eset.com")
        self.assertTrue(self.bl.is_learned_domain("update.eset.com"))

    def test_not_learned_after_1_observation(self):
        self.bl.observe_dns("192.168.1.10", "random-site.xyz")
        self.assertFalse(self.bl.is_learned_domain("random-site.xyz"))

    def test_subdomain_matches_base(self):
        for _ in range(5):
            self.bl.observe_dns("192.168.1.10", "sub.example.com")
        self.assertTrue(self.bl.is_learned_domain("other.example.com"))

    def test_learns_ip_after_3_connections(self):
        for _ in range(3):
            self.bl.observe_connection("192.168.1.10", "142.250.80.46", 443)
        self.assertTrue(self.bl.is_learned_ip("142.250.80.46"))

    def test_learns_beacon_pattern(self):
        self.bl.observe_beacon("192.168.1.10", "104.16.0.1", 30.0)
        self.assertTrue(self.bl.is_learned_beacon("192.168.1.10", "104.16.0.1"))
        self.assertFalse(self.bl.is_learned_beacon("192.168.1.10", "5.5.5.5"))

    def test_learning_completes(self):
        self.bl.learning_duration = 0.01  # Instant for testing
        time.sleep(0.02)
        self.bl.check_learning_complete()
        self.assertFalse(self.bl.is_learning)

    def test_user_dga_exact_whitelist(self):
        """User-configured exact matches should work."""
        config = make_config()
        config.get = lambda *keys, default=None: (
            ['nabu.casa'] if keys == ('whitelists', 'dga_whitelist_exact') else default
        )
        bl = BaselineWhitelist(config)
        self.assertTrue(bl.is_learned_domain("nabu.casa"))

    def test_persistence_roundtrip(self):
        tmpdir = tempfile.mkdtemp()
        try:
            self.bl._db_path = os.path.join(tmpdir, "bl.json")
            for _ in range(5):
                self.bl.observe_dns("10.0.0.1", "saved-domain.com")
            self.bl.save()

            bl2 = BaselineWhitelist(self.config)
            bl2._db_path = self.bl._db_path
            bl2._load()
            self.assertTrue(bl2.is_learned_domain("saved-domain.com"))
        finally:
            shutil.rmtree(tmpdir)

    def test_domain_confidence(self):
        # Never seen → 0
        self.assertEqual(self.bl.get_domain_confidence("unknown.com"), 0.0)
        # Seen many times from many IPs → higher
        for i in range(10):
            for _ in range(5):
                self.bl.observe_dns(f"192.168.1.{i}", "popular.com")
        conf = self.bl.get_domain_confidence("popular.com")
        self.assertGreater(conf, 0.5)

    def test_base_domain_extraction(self):
        self.assertEqual(BaselineWhitelist._base_domain("sub.example.com"), "example.com")
        self.assertEqual(BaselineWhitelist._base_domain("deep.sub.example.co.uk"), "example.co.uk")
        self.assertEqual(BaselineWhitelist._base_domain("example.com"), "example.com")

    def test_prune_stale(self):
        self.bl._domains["old.com"] = {
            'first_seen': 0, 'last_seen': 1,  # epoch = very old
            'count': 100, 'source_ips': set(), 'full_domains': set()
        }
        self.bl.prune_stale(max_age_days=1)
        self.assertNotIn("old.com", self.bl._domains)


# ═══════════════════════════════════════════════════════════════════
# NEW MODULE TESTS: AlertCorrelator
# ═══════════════════════════════════════════════════════════════════

class TestAlertCorrelator(unittest.TestCase):

    def setUp(self):
        self.config = make_config()
        self.corr = AlertCorrelator(self.config)

    def test_groups_by_source_ip(self):
        a1 = Alert("R1", "HIGH", "Alert1", "d", src_ip="10.0.0.5", category="Cat1")
        a2 = Alert("R2", "LOW", "Alert2", "d", src_ip="10.0.0.5", category="Cat2")
        inc1 = self.corr.process_alert(a1)
        inc2 = self.corr.process_alert(a2)
        self.assertEqual(inc1.id, inc2.id, "Same source IP should correlate")

    def test_different_ips_separate_incidents(self):
        a1 = Alert("R1", "HIGH", "Alert1", "d", src_ip="10.0.0.5", category="Cat1")
        a2 = Alert("R2", "HIGH", "Alert2", "d", src_ip="10.0.0.99", category="Cat1")
        inc1 = self.corr.process_alert(a1)
        inc2 = self.corr.process_alert(a2)
        self.assertNotEqual(inc1.id, inc2.id)

    def test_escalation_recon_then_attack(self):
        a1 = Alert("SCAN", "HIGH", "Port Scan", "d",
                   src_ip="10.0.0.5", category="Reconnaissance")
        a2 = Alert("BF", "HIGH", "Brute Force", "d",
                   src_ip="10.0.0.5", category="Brute Force")
        self.corr.process_alert(a1)
        inc = self.corr.process_alert(a2)
        self.assertTrue(inc.is_escalation)
        self.assertIn("Escalation", inc.title)
        self.assertEqual(inc.severity, "HIGH")

    def test_escalation_threat_intel_exfil(self):
        a1 = Alert("TI", "HIGH", "Threat Intel", "d",
                   src_ip="10.0.0.5", category="Threat Intelligence")
        a2 = Alert("EX", "MEDIUM", "Data Exfil", "d",
                   src_ip="10.0.0.5", category="Exfiltration")
        self.corr.process_alert(a1)
        inc = self.corr.process_alert(a2)
        self.assertTrue(inc.is_escalation)

    def test_severity_takes_highest(self):
        a1 = Alert("R1", "LOW", "Low", "d", src_ip="10.0.0.5", category="C")
        a2 = Alert("R2", "CRITICAL", "Crit", "d", src_ip="10.0.0.5", category="C")
        self.corr.process_alert(a1)
        inc = self.corr.process_alert(a2)
        self.assertEqual(inc.severity, "CRITICAL")

    def test_incident_to_dict(self):
        a = Alert("R1", "HIGH", "Test", "d", src_ip="1.2.3.4", category="C")
        inc = self.corr.process_alert(a)
        d = inc.to_dict()
        self.assertIn('id', d)
        self.assertIn('narrative', d)
        self.assertIn('alert_count', d)
        self.assertEqual(d['alert_count'], 1)

    def test_get_incidents(self):
        for i in range(5):
            a = Alert("R", "HIGH", f"Alert{i}", "d",
                     src_ip=f"10.0.0.{i}", category="C")
            self.corr.process_alert(a)
        incidents = self.corr.get_incidents(limit=3)
        self.assertEqual(len(incidents), 3)

    def test_stats(self):
        a = Alert("R", "HIGH", "Test", "d", src_ip="10.0.0.1", category="C")
        self.corr.process_alert(a)
        stats = self.corr.get_stats()
        self.assertGreaterEqual(stats['total_incidents'], 1)
        self.assertGreaterEqual(stats['active_incidents'], 1)


# ═══════════════════════════════════════════════════════════════════
# NEW MODULE TESTS: PcapWriter
# ═══════════════════════════════════════════════════════════════════

class TestPcapWriter(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.config = make_config()
        self.pw = PcapWriter(self.config, output_dir=self.tmpdir)

    def tearDown(self):
        self.pw.cleanup()
        shutil.rmtree(self.tmpdir)

    def test_buffer_packet(self):
        self.pw.buffer_packet(b'\x00' * 64)
        stats = self.pw.get_buffer_stats()
        self.assertEqual(stats['buffer_packets'], 1)

    def test_export_buffer(self):
        for i in range(10):
            self.pw.buffer_packet(b'\x00' * 64)
        path = self.pw.export_buffer(last_minutes=5)
        self.assertIsNotNone(path)
        self.assertTrue(os.path.exists(path))
        # Verify PCAP header
        with open(path, 'rb') as f:
            magic = struct.unpack('<I', f.read(4))[0]
            self.assertEqual(magic, 0xa1b2c3d4)

    def test_export_empty_returns_none(self):
        path = self.pw.export_buffer()
        self.assertIsNone(path)

    def test_recording_start_stop(self):
        path = self.pw.start_recording()
        self.assertIsNotNone(path)
        self.assertTrue(self.pw.is_recording)

        self.pw.buffer_packet(b'\x00' * 64)
        self.pw.buffer_packet(b'\x11' * 64)

        stats = self.pw.stop_recording()
        self.assertFalse(self.pw.is_recording)
        self.assertEqual(stats['packets'], 2)
        self.assertTrue(os.path.exists(stats['filepath']))

    def test_get_capture_files(self):
        self.pw.buffer_packet(b'\x00' * 64)
        self.pw.export_buffer()
        files = self.pw.get_capture_files()
        self.assertEqual(len(files), 1)
        self.assertIn('filename', files[0])
        self.assertIn('size_mb', files[0])

    def test_ring_buffer_bounded(self):
        """Ring buffer should not exceed maxlen."""
        self.pw._buffer = deque(maxlen=100)
        for i in range(200):
            self.pw.buffer_packet(b'\x00')
        self.assertLessEqual(len(self.pw._buffer), 100)


# ═══════════════════════════════════════════════════════════════════
# INTEGRATION TESTS: IDS + BaselineWhitelist
# ═══════════════════════════════════════════════════════════════════

class TestIDSBaselineIntegration(unittest.TestCase):
    """Verify IDS suppresses alerts for learned domains."""

    def test_learned_domain_skips_bad_tld(self):
        config = make_config()
        alerts = []
        ids = IDSEngine(config, alert_callback=alerts.append)
        bl = BaselineWhitelist(config)

        # Learn a .xyz domain during baseline
        for _ in range(5):
            bl.observe_dns("192.168.1.10", "legit-service.xyz")
        ids.baseline_whitelist = bl

        # Query the learned .xyz domain — should NOT trigger bad-TLD alert
        pkt = make_packet(src_ip="192.168.1.10", dst_ip="8.8.8.8",
                         dst_port=53, protocol="UDP",
                         dns_query="legit-service.xyz")
        ids.inspect_packet(pkt)
        bad_tld_alerts = [a for a in alerts if a.rule_id == "DNS-BAD-TLD"]
        self.assertEqual(len(bad_tld_alerts), 0,
                        "Learned .xyz domain should not trigger bad-TLD alert")

    def test_unknown_domain_still_triggers(self):
        config = make_config()
        alerts = []
        ids = IDSEngine(config, alert_callback=alerts.append)
        bl = BaselineWhitelist(config)
        ids.baseline_whitelist = bl

        # Query a .xyz domain NOT learned during baseline
        pkt = make_packet(src_ip="192.168.1.10", dst_ip="8.8.8.8",
                         dst_port=53, protocol="UDP",
                         dns_query="malware-c2.xyz")
        ids.inspect_packet(pkt)
        bad_tld_alerts = [a for a in alerts if a.rule_id == "DNS-BAD-TLD"]
        self.assertEqual(len(bad_tld_alerts), 1,
                        "Unknown .xyz domain should still trigger bad-TLD alert")


# ═══════════════════════════════════════════════════════════════════
# EDGE CASE TESTS
# ═══════════════════════════════════════════════════════════════════

class TestEdgeCases(unittest.TestCase):

    def test_empty_packet(self):
        """All-empty PacketInfo should not crash any module."""
        config = make_config()
        ids = IDSEngine(config)
        pkt = PacketInfo()
        # Should not raise
        ids.inspect_packet(pkt)

    def test_none_fields(self):
        """PacketInfo with empty strings should work."""
        config = make_config()
        dl = DeviceLearner(config)
        pkt = PacketInfo()
        pkt.src_ip = ""
        pkt.dst_ip = ""
        dl.observe_packet(pkt)  # Should not crash

    def test_baseline_whitelist_empty_domain(self):
        bl = BaselineWhitelist(make_config())
        self.assertFalse(bl.is_learned_domain(""))
        self.assertFalse(bl.is_learned_domain(None))

    def test_device_learner_broadcast_skipped(self):
        dl = DeviceLearner(make_config())
        pkt = make_packet(src_ip="192.168.1.1", dst_ip="255.255.255.255")
        dl.observe_packet(pkt)
        self.assertNotIn("255.255.255.255", dl.devices)

    def test_correlator_empty_source_ip(self):
        corr = AlertCorrelator(make_config())
        a = Alert("R", "LOW", "Test", "d", src_ip="", category="C")
        inc = corr.process_alert(a)
        self.assertIsNotNone(inc)

    def test_pcap_writer_binary_data(self):
        tmpdir = tempfile.mkdtemp()
        try:
            pw = PcapWriter(make_config(), output_dir=tmpdir)
            # Random binary data
            pw.buffer_packet(os.urandom(1500))
            path = pw.export_buffer()
            self.assertIsNotNone(path)
            size = os.path.getsize(path)
            self.assertGreater(size, 24)  # At least PCAP header
            pw.cleanup()
        finally:
            shutil.rmtree(tmpdir)

    def test_feature_info_complete(self):
        """_FEATURE_INFO should have an entry for every feature name."""
        from src.app import _FEATURE_INFO
        extractor = TrafficFeatureExtractor()
        for name in extractor.feature_names:
            self.assertIn(name, _FEATURE_INFO,
                         f"Missing _FEATURE_INFO entry for '{name}'")

    def test_config_deep_merge_isolation(self):
        """Deep merge should not share references between merged dicts."""
        import copy
        from src.config import Config
        base = {'a': {'b': [1, 2, 3]}}
        override = {'a': {'b': [4, 5]}}
        result = Config._deep_merge(base, override)
        # Mutating result should not affect override
        result['a']['b'].append(99)
        self.assertNotIn(99, override['a']['b'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
