"""
NetSentinel Unit Tests
=======================
Tests core logic in isolation — no network capture, no GUI, no admin required.
Validates bug fixes, optimizations, and new features.

Usage:
    python test_unit.py                 # Run all tests
    python test_unit.py TestIDS         # Run one test class
    python -m pytest test_unit.py -v    # With pytest
"""

import os
import sys
import json
import time
import unittest
import tempfile
import shutil
import numpy as np
from unittest.mock import MagicMock, patch
from collections import defaultdict, deque

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import Config, DEFAULT_CONFIG
from src.ids_engine import IDSEngine, Alert, Severity
from src.ml_engine import BaselineProfile, TrafficFeatureExtractor, AnomalyDetector
from src.net_detect import NetworkEnvironment, KNOWN_CLOUD_DOMAINS, CLOUD_HOSTING_DOMAINS
from src.ioc_scanner import IOCScanner, DGA_WHITELIST_SUFFIXES
from src.alerts import AlertManager
from src.capture import PacketInfo


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════

def make_packet(src_ip="192.168.1.10", dst_ip="10.0.0.1",
                src_port=12345, dst_port=80, protocol="TCP",
                flags="", dns_query="", dns_response="",
                payload_size=0, length=100, process_name="",
                src_mac="", dst_mac="", is_encrypted=False):
    """Create a PacketInfo for testing."""
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
    return pkt


def make_config():
    """Create a Config for testing (in-memory, no disk IO)."""
    import copy
    config = Config.__new__(Config)
    config._data = copy.deepcopy(DEFAULT_CONFIG)
    return config


# ═══════════════════════════════════════════════════════════════════
# FIX 1: Memory leak — IDS state dict pruning
# ═══════════════════════════════════════════════════════════════════

class TestIDSMemoryCleanup(unittest.TestCase):

    def setUp(self):
        self.config = make_config()
        self.alerts = []
        self.ids = IDSEngine(self.config, alert_callback=self.alerts.append)

    def test_alert_cooldown_pruning(self):
        """Alert cooldowns should be pruned after 5x the cooldown window."""
        # Inject stale cooldowns
        old_time = time.time() - 600  # 10 minutes ago
        for i in range(100):
            self.ids._alert_cooldowns[f"RULE:{i}:1.2.3.4"] = old_time
        self.assertEqual(len(self.ids._alert_cooldowns), 100)

        # Force cleanup
        self.ids._last_cleanup = 0
        self.ids._periodic_cleanup(force=True)

        # All stale entries should be gone
        self.assertEqual(len(self.ids._alert_cooldowns), 0)

    def test_data_transfer_pruning(self):
        """Data transfer tracker should prune IPs not seen this cycle."""
        self.ids._data_transfer["10.0.0.1"] = 50000
        self.ids._data_transfer["10.0.0.2"] = 80000
        self.ids._active_transfer_ips = {"10.0.0.1"}  # Only .1 was active

        self.ids._last_cleanup = 0
        self.ids._periodic_cleanup(force=True)

        self.assertIn("10.0.0.1", self.ids._data_transfer)
        self.assertNotIn("10.0.0.2", self.ids._data_transfer)

    def test_dns_to_ip_pruning(self):
        """DNS-to-IP cache should prune entries older than 10 minutes."""
        old = time.time() - 700
        recent = time.time()
        self.ids._dns_to_ip["old.example.com"] = ("1.2.3.4", old)
        self.ids._dns_to_ip["new.example.com"] = ("5.6.7.8", recent)

        self.ids._last_cleanup = 0
        self.ids._periodic_cleanup(force=True)

        self.assertNotIn("old.example.com", self.ids._dns_to_ip)
        self.assertIn("new.example.com", self.ids._dns_to_ip)


# ═══════════════════════════════════════════════════════════════════
# FIX 2: DGA whitelist — config-driven
# ═══════════════════════════════════════════════════════════════════

class TestDGAWhitelist(unittest.TestCase):

    def test_builtin_whitelist_covers_known_fps(self):
        """Built-in DGA whitelist should cover .local, nabu.casa, eset, chromecast."""
        must_whitelist = [
            '.local', '.nabu.casa', '.eset.com',
            '._googlecast._tcp.local', '.ui.nabu.casa',
        ]
        for suffix in must_whitelist:
            self.assertIn(suffix, DGA_WHITELIST_SUFFIXES,
                          f"Missing DGA whitelist suffix: {suffix}")

    def test_config_driven_whitelist_merges(self):
        """Extra suffixes from config should merge with built-in whitelist."""
        config = make_config()
        config.set('whitelists', 'dga_whitelist_suffixes',
                    ['.mycompany.local', '.custom-iot.internal'])
        scanner = IOCScanner(config)

        # Built-in should still be present
        self.assertIn('.local', scanner._dga_whitelist_suffixes)
        self.assertIn('.nabu.casa', scanner._dga_whitelist_suffixes)
        # Custom should also be present
        self.assertIn('.mycompany.local', scanner._dga_whitelist_suffixes)
        self.assertIn('.custom-iot.internal', scanner._dga_whitelist_suffixes)

    def test_whitelisted_domain_not_flagged_as_dga(self):
        """Domains matching DGA whitelist should not produce IOC-DGA findings."""
        config = make_config()
        scanner = IOCScanner(config)

        # High-entropy mDNS name that looks like DGA but isn't
        test_domains = [
            "a3f7b2c8d9e1f0ab._googlecast._tcp.local",
            "xz9k4m7p2q8r._tcp.local",
            "randomhash12345678.nabu.casa",
            "ecaserver-node-x9f2.eset.com",
            "device-uuid-abc123def456.local",
        ]
        for domain in test_domains:
            pkt = make_packet(dns_query=domain)
            findings = scanner.check_packet_ioc(pkt)
            dga_findings = [f for f in findings if f['rule_id'] == 'IOC-DGA']
            self.assertEqual(len(dga_findings), 0,
                             f"False DGA positive on whitelisted domain: {domain}")


# ═══════════════════════════════════════════════════════════════════
# FIX 3: Welford's algorithm for baseline
# ═══════════════════════════════════════════════════════════════════

class TestWelfordBaseline(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "baseline.json")

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_welford_matches_numpy(self):
        """Welford's online stats should match numpy batch computation."""
        baseline = BaselineProfile(self.db_path)
        np.random.seed(42)

        samples = [np.random.randn(18) * 10 + 50 for _ in range(200)]
        for s in samples:
            baseline.add_sample(s)

        # Compare against numpy
        batch = np.array(samples)
        np_mean = np.mean(batch, axis=0)
        np_std = np.std(batch, axis=0, ddof=1) + 1e-8  # sample std

        np.testing.assert_allclose(baseline.global_mean, np_mean, rtol=1e-10,
                                    err_msg="Welford mean diverged from numpy")
        np.testing.assert_allclose(baseline.global_std, np_std, rtol=1e-5,
                                    err_msg="Welford std diverged from numpy")

    def test_welford_persists_across_restart(self):
        """Welford state should survive save/load cycle."""
        baseline = BaselineProfile(self.db_path)
        np.random.seed(123)
        for _ in range(50):
            baseline.add_sample(np.random.randn(18))
        baseline.save()

        mean_before = baseline.global_mean.copy()
        n_before = baseline._welford_n

        # Reload
        baseline2 = BaselineProfile(self.db_path)
        np.testing.assert_array_almost_equal(baseline2.global_mean, mean_before)
        self.assertEqual(baseline2._welford_n, n_before)

    def test_deviation_score_returns_float(self):
        """Deviation score should work after enough samples."""
        baseline = BaselineProfile(self.db_path)
        np.random.seed(99)
        normal = np.ones(18) * 10
        for _ in range(20):
            baseline.add_sample(normal + np.random.randn(18) * 0.1)

        score = baseline.get_deviation_score(normal)
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

        # An outlier should score higher
        outlier = np.ones(18) * 1000
        outlier_score = baseline.get_deviation_score(outlier)
        self.assertGreater(outlier_score, score)


# ═══════════════════════════════════════════════════════════════════
# FIX 4: Port scan dst_ips_hit bug
# ═══════════════════════════════════════════════════════════════════

class TestPortScanTargetTracking(unittest.TestCase):

    def test_port_scan_tracks_multiple_dst_ips(self):
        """Port scan should report all distinct destination IPs in evidence."""
        config = make_config()
        config.set('ids', 'port_scan_threshold', 5)
        config.set('ids', 'port_scan_window_sec', 60)
        alerts = []
        ids = IDSEngine(config, alert_callback=alerts.append)

        # Scan 5 different ports across 3 different destination IPs
        target_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
        for i in range(5):
            dst = target_ips[i % 3]
            pkt = make_packet(src_ip="192.168.1.100", dst_ip=dst,
                              dst_port=1000 + i)
            ids.inspect_packet(pkt)

        scan_alerts = [a for a in alerts if a.rule_id == "PORT-SCAN"]
        self.assertGreaterEqual(len(scan_alerts), 1, "Port scan should have fired")

        target_ips_in_evidence = scan_alerts[0].evidence.get('target_ips', [])
        self.assertGreater(len(target_ips_in_evidence), 1,
                           "Port scan should report multiple target IPs, not just one")


# ═══════════════════════════════════════════════════════════════════
# FIX 5: Config deep copy
# ═══════════════════════════════════════════════════════════════════

class TestConfigDeepCopy(unittest.TestCase):

    def test_config_mutations_dont_corrupt_defaults(self):
        """Mutating config lists should not affect DEFAULT_CONFIG."""
        import copy
        original_whitelist_ips = copy.deepcopy(DEFAULT_CONFIG['whitelists']['ips'])

        config = make_config()
        wl = config.get('whitelists', 'ips')
        wl.append("INJECTED-IP")

        # DEFAULT_CONFIG should be untouched
        self.assertEqual(DEFAULT_CONFIG['whitelists']['ips'], original_whitelist_ips,
                         "Config mutation leaked into DEFAULT_CONFIG — shallow copy bug")


# ═══════════════════════════════════════════════════════════════════
# FIX 6: Cloud domain lookup optimization
# ═══════════════════════════════════════════════════════════════════

class TestCloudDomainLookup(unittest.TestCase):

    def setUp(self):
        self.env = NetworkEnvironment()
        self.env.detect()

    def test_known_cloud_domains_match(self):
        """Known cloud domains and subdomains should match."""
        self.assertTrue(self.env.is_known_cloud_domain("google.com"))
        self.assertTrue(self.env.is_known_cloud_domain("docs.google.com"))
        self.assertTrue(self.env.is_known_cloud_domain("sub.sub.amazonaws.com"))
        self.assertTrue(self.env.is_known_cloud_domain("cdn.cloudflare.com"))

    def test_unknown_domains_dont_match(self):
        """Random domains should not match cloud list."""
        self.assertFalse(self.env.is_known_cloud_domain("evil-hacker.xyz"))
        self.assertFalse(self.env.is_known_cloud_domain("notgoogle.com"))
        self.assertFalse(self.env.is_known_cloud_domain(""))

    def test_hosting_domains_match(self):
        """Cloud hosting domains should match."""
        self.assertTrue(self.env.is_cloud_hosting_domain("myapp.herokuapp.com"))
        self.assertTrue(self.env.is_cloud_hosting_domain("test.netlify.app"))
        self.assertTrue(self.env.is_cloud_hosting_domain("s3.amazonaws.com"))

    def test_suffix_walk_performance(self):
        """Suffix-based lookup should be faster than linear scan."""
        import timeit
        domain = "deeply.nested.subdomain.of.googleapis.com"

        # Time the optimized method
        t = timeit.timeit(lambda: self.env.is_known_cloud_domain(domain), number=10000)
        # Should complete 10k lookups well under 1 second
        self.assertLess(t, 1.0, f"Cloud domain lookup too slow: {t:.3f}s for 10k calls")


# ═══════════════════════════════════════════════════════════════════
# FIX 7: acknowledge_all bug
# ═══════════════════════════════════════════════════════════════════

class TestAlertManager(unittest.TestCase):

    def setUp(self):
        self.config = make_config()
        with patch('src.alerts.AlertManager._load_alerts'):
            self.mgr = AlertManager(self.config)

    def test_acknowledge_all_actually_acknowledges(self):
        """acknowledge_all should set all alerts to acknowledged=True."""
        for i in range(5):
            alert = Alert("TEST", "MEDIUM", f"Test {i}", "desc")
            self.mgr.add_alert(alert)

        self.mgr.acknowledge_all()
        with self.mgr._lock:
            for a in self.mgr._alerts:
                self.assertTrue(a.acknowledged,
                                f"Alert {a.id} not acknowledged after acknowledge_all")

    def test_export_json(self):
        """JSON export should produce valid JSON with all alerts."""
        for i in range(3):
            alert = Alert("TEST", "HIGH", f"Alert {i}", "description",
                          evidence={'key': 'value', 'nested': [1, 2, 3]})
            self.mgr.add_alert(alert)

        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, "alerts.json")
            count = self.mgr.export_alerts(path, format='json')
            self.assertEqual(count, 3)

            with open(path) as f:
                data = json.load(f)
            self.assertEqual(len(data), 3)
        finally:
            shutil.rmtree(tmpdir)

    def test_export_csv(self):
        """CSV export should flatten evidence and produce valid CSV."""
        alert = Alert("TEST", "HIGH", "Test Alert", "desc",
                      evidence={'reason': 'testing', 'ports': [80, 443]})
        self.mgr.add_alert(alert)

        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, "alerts.csv")
            count = self.mgr.export_alerts(path, format='csv')
            self.assertEqual(count, 1)

            import csv
            with open(path, newline='') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            self.assertEqual(len(rows), 1)
            # Evidence should be flattened with evidence_ prefix
            self.assertIn('evidence_reason', rows[0])
        finally:
            shutil.rmtree(tmpdir)

    def test_alert_rate_tracking(self):
        """Alert rate should be tracked per 10-second buckets."""
        # Fast-forward bucket start
        self.mgr._rate_bucket_start = time.time() - 11
        for i in range(5):
            alert = Alert("TEST", "LOW", f"Rate test {i}", "desc")
            self.mgr.add_alert(alert)

        stats = self.mgr.get_stats()
        self.assertIn('alerts_per_minute', stats)
        self.assertIn('rate_history', stats)


# ═══════════════════════════════════════════════════════════════════
# FEATURE: Known device registry
# ═══════════════════════════════════════════════════════════════════

class TestKnownDevices(unittest.TestCase):

    def test_known_device_loaded_and_queryable(self):
        """Known devices from config should be loadable and queryable."""
        env = NetworkEnvironment()
        env.detect()
        env.load_known_devices([
            {"name": "Home Assistant", "ip": "192.168.2.100",
             "mac": "dc:a6:32:xx:xx:xx", "type": "hub"},
            {"name": "Shelly Plug", "ip": "192.168.2.50",
             "type": "iot"},
        ])

        self.assertEqual(env.get_device_name(ip="192.168.2.100"), "Home Assistant")
        self.assertEqual(env.get_device_name(ip="192.168.2.50"), "Shelly Plug")
        self.assertIsNone(env.get_device_name(ip="10.0.0.99"))

    def test_known_device_ips_auto_whitelisted(self):
        """Known device IPs should be added to auto-whitelist."""
        env = NetworkEnvironment()
        env.detect()
        env.load_known_devices([
            {"name": "Home Assistant", "ip": "192.168.2.100"},
        ])

        self.assertIn("192.168.2.100", env.auto_whitelist_ips)

    def test_known_device_in_summary(self):
        """Known devices should appear in get_summary output."""
        env = NetworkEnvironment()
        env.detect()
        env.load_known_devices([
            {"name": "Test Device", "ip": "10.0.0.5", "type": "sensor"},
        ])

        summary = env.get_summary()
        self.assertIn('known_devices', summary)
        self.assertEqual(len(summary['known_devices']), 1)
        self.assertEqual(summary['known_devices'][0]['name'], "Test Device")


# ═══════════════════════════════════════════════════════════════════
# FEATURE: Feature extractor
# ═══════════════════════════════════════════════════════════════════

class TestFeatureExtraction(unittest.TestCase):

    def test_extract_from_empty_window(self):
        """Empty packet window should return zero vector."""
        extractor = TrafficFeatureExtractor()
        features = extractor.extract_from_window({}, [], 60)
        self.assertEqual(features.shape, (18,))
        np.testing.assert_array_equal(features, np.zeros(18))

    def test_extract_produces_correct_shape(self):
        """Feature extraction should produce 18-dim vector."""
        extractor = TrafficFeatureExtractor()
        packets = [make_packet(dst_port=80 + i, flags="S") for i in range(10)]
        features = extractor.extract_from_window({}, packets, 60)
        self.assertEqual(features.shape, (18,))
        # bytes_per_sec should be > 0
        self.assertGreater(features[0], 0)

    def test_entropy_calculation(self):
        """Entropy should be 0 for uniform and >0 for diverse."""
        self.assertAlmostEqual(TrafficFeatureExtractor._entropy([1, 1, 1]), 0.0)
        self.assertGreater(TrafficFeatureExtractor._entropy([1, 2, 3, 4, 5]), 0)


# ═══════════════════════════════════════════════════════════════════
# IDS: Core detection rules
# ═══════════════════════════════════════════════════════════════════

class TestIDSRules(unittest.TestCase):

    def setUp(self):
        self.config = make_config()
        self.alerts = []
        self.ids = IDSEngine(self.config, alert_callback=self.alerts.append)

    def test_suspicious_port_detection(self):
        """Connections to known malware ports should trigger alerts."""
        pkt = make_packet(dst_port=4444, dst_ip="10.0.0.1")
        self.ids.inspect_packet(pkt)
        bad_port = [a for a in self.alerts if a.rule_id == "BAD-PORT"]
        self.assertGreater(len(bad_port), 0, "Should detect known bad port 4444")

    def test_arp_spoofing_detection(self):
        """MAC address change for same IP should trigger ARP spoof alert."""
        pkt1 = make_packet(src_ip="192.168.1.1", src_mac="aa:bb:cc:dd:ee:01",
                           protocol="ARP")
        pkt2 = make_packet(src_ip="192.168.1.1", src_mac="aa:bb:cc:dd:ee:02",
                           protocol="ARP")
        self.ids.inspect_packet(pkt1)
        self.ids.inspect_packet(pkt2)
        spoof = [a for a in self.alerts if a.rule_id == "ARP-SPOOF"]
        self.assertGreater(len(spoof), 0, "Should detect ARP spoofing")

    def test_whitelist_skips_ids(self):
        """Whitelisted IPs should not trigger heuristic rules."""
        self.ids.whitelist_ips.add("192.168.1.100")
        pkt = make_packet(src_ip="192.168.1.100", dst_port=4444)
        result = self.ids.inspect_packet(pkt)
        self.assertEqual(len(result), 0, "Whitelisted IP should not trigger alerts")

    def test_alert_cooldown_dedup(self):
        """Same alert for same src/dst should be suppressed within cooldown."""
        self.ids.cooldown_sec = 30
        pkt = make_packet(dst_port=4444)
        self.ids.inspect_packet(pkt)
        count_1 = len(self.alerts)

        self.ids.inspect_packet(pkt)
        count_2 = len(self.alerts)

        self.assertEqual(count_1, count_2,
                         "Duplicate alert within cooldown should be suppressed")

    def test_data_exfil_tracks_active_ips(self):
        """Data exfil rule should mark active transfer IPs."""
        pkt = make_packet(dst_ip="10.0.0.5", payload_size=1000)
        self.ids.inspect_packet(pkt)
        self.assertIn("10.0.0.5", self.ids._active_transfer_ips)

    def test_dns_resolution_tracking(self):
        """DNS queries should create IP-to-domain mappings."""
        pkt = make_packet(dns_query="example.com", dns_response="93.184.216.34",
                          protocol="UDP", dst_port=53)
        self.ids.inspect_packet(pkt)

        domains = self.ids._get_domains_for_ip("93.184.216.34")
        self.assertIn("example.com", domains)


# ═══════════════════════════════════════════════════════════════════
# IOC Scanner
# ═══════════════════════════════════════════════════════════════════

class TestIOCScanner(unittest.TestCase):

    def test_tor_port_detection(self):
        """Connections to TOR ports should fire IOC-TOR."""
        config = make_config()
        scanner = IOCScanner(config)
        pkt = make_packet(dst_port=9050, dst_ip="10.0.0.1")
        findings = scanner.check_packet_ioc(pkt)
        tor = [f for f in findings if f['rule_id'] == 'IOC-TOR']
        self.assertGreater(len(tor), 0)

    def test_doh_detection(self):
        """HTTPS to known DoH providers should fire IOC-DOH-BYPASS."""
        config = make_config()
        scanner = IOCScanner(config)
        pkt = make_packet(dst_port=443, dst_ip="1.1.1.1")
        findings = scanner.check_packet_ioc(pkt)
        doh = [f for f in findings if f['rule_id'] == 'IOC-DOH-BYPASS']
        self.assertGreater(len(doh), 0)

    def test_suspicious_process_detection(self):
        """Known malware process names should fire IOC alerts."""
        config = make_config()
        scanner = IOCScanner(config)
        pkt = make_packet(process_name="mimikatz.exe", dst_port=443)
        findings = scanner.check_packet_ioc(pkt)
        proc = [f for f in findings if f['rule_id'] == 'IOC-SUSPICIOUS-PROC']
        self.assertGreater(len(proc), 0)

    def test_safe_process_not_flagged(self):
        """Known safe Windows processes should not trigger IOC alerts."""
        config = make_config()
        scanner = IOCScanner(config)
        pkt = make_packet(process_name="chrome.exe", dst_port=443)
        findings = scanner.check_packet_ioc(pkt)
        proc = [f for f in findings if f['rule_id'] == 'IOC-SUSPICIOUS-PROC']
        self.assertEqual(len(proc), 0, "chrome.exe should not be flagged")


# ═══════════════════════════════════════════════════════════════════
# Network Environment
# ═══════════════════════════════════════════════════════════════════

class TestNetworkEnvironment(unittest.TestCase):

    def test_special_addresses_skipped(self):
        """Broadcast/multicast should be skipped by IDS."""
        env = NetworkEnvironment()
        env.detect()
        self.assertTrue(env.should_skip_ids("255.255.255.255", "192.168.1.1"))
        self.assertTrue(env.should_skip_ids("192.168.1.1", "224.0.0.1"))

    def test_malware_ports_not_skipped_even_for_gateway(self):
        """Known malware ports should not be skipped even for whitelisted IPs."""
        env = NetworkEnvironment()
        env.detect()
        env.auto_whitelist_ips.add("192.168.1.1")
        # Normal port → skip
        self.assertTrue(env.should_skip_ids("192.168.1.1", "10.0.0.1", dst_port=80))
        # Malware port → don't skip
        self.assertFalse(env.should_skip_ids("192.168.1.1", "10.0.0.1", dst_port=4444))


# ═══════════════════════════════════════════════════════════════════
# Severity
# ═══════════════════════════════════════════════════════════════════

class TestSeverity(unittest.TestCase):

    def test_severity_ordering(self):
        self.assertTrue(Severity.gte("CRITICAL", "LOW"))
        self.assertTrue(Severity.gte("HIGH", "MEDIUM"))
        self.assertTrue(Severity.gte("LOW", "LOW"))
        self.assertFalse(Severity.gte("LOW", "HIGH"))


# ═══════════════════════════════════════════════════════════════════
# Run
# ═══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    unittest.main(verbosity=2)
