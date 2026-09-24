"""
Tests for modules the original suite never touched.
====================================================
Coverage before this file: feature_store 0%, forensics 10%, alert_verify 12%.

These are the modules where a silent failure is most expensive — the feature
store feeds every ML decision, the forensics scanner is the largest detection
surface in the codebase, and the verifier decides what severity the user sees.
"""

import os
import sys
import csv
import time
import types
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Isolated HOME + real Scapy where available. Must precede any src import.
import _test_support  # noqa: E402,F401
from _test_support import SCAPY_REAL  # noqa: E402

import numpy as np  # noqa: E402

from src.capture import PacketInfo  # noqa: E402
from src.config import Config  # noqa: E402
from src.feature_store import FeatureStore, FEATURE_COLUMNS  # noqa: E402
from src.forensics import NetworkForensics  # noqa: E402
from src.forensics_db import ForensicsDB  # noqa: E402
from src.alert_verify import AlertVerifier, AlertVerdict  # noqa: E402
from src.ids_engine import Alert, Severity  # noqa: E402
from src.alert_correlator import AlertCorrelator  # noqa: E402


def cfg():
    c = Config().load()
    c.set('threat_intel', 'auto_update', False)
    return c


def pkt(**kw):
    p = PacketInfo()
    for k, v in kw.items():
        setattr(p, k, v)
    return p


# ══════════════════════════════════════════════════════════════════════
# FeatureStore — 0% covered before this
# ══════════════════════════════════════════════════════════════════════
class TestFeatureStore(unittest.TestCase):
    """
    Every ML decision is trained on what this writes. It runs a background flush
    thread, rotates daily CSVs and enforces retention, none of which was tested.
    """

    def setUp(self):
        self.store = FeatureStore(cfg())
        # Start from a clean directory so retention/rotation assertions are exact.
        for f in os.listdir(self.store.store_dir):
            os.remove(os.path.join(self.store.store_dir, f))

    def tearDown(self):
        self.store.shutdown()

    def _record(self, n=5, score=0.4):
        for i in range(n):
            features = np.arange(len(FEATURE_COLUMNS), dtype=float) + i
            self.store.record(features, {
                'anomaly_score': score, 'baseline_deviation': 0.1,
                'isolation_score': 0.2, 'is_anomalous': score > 0.3,
            })

    def test_records_round_trip_through_csv(self):
        self._record(5)
        self.store._flush_buffer()
        timestamps, matrix, scores = self.store.load_history(days=1)
        self.assertEqual(len(timestamps), 5)
        self.assertEqual(matrix.shape, (5, len(FEATURE_COLUMNS)))
        # First row was arange(18) + 0
        self.assertAlmostEqual(matrix[0][0], 0.0)
        self.assertAlmostEqual(matrix[4][0], 4.0)

    def test_header_is_written_once_per_file(self):
        self._record(3)
        self.store._flush_buffer()
        self._record(3)
        self.store._flush_buffer()
        path = os.path.join(self.store.store_dir,
                            f"features_{datetime.now():%Y-%m-%d}.csv")
        with open(path, newline='') as f:
            rows = list(csv.reader(f))
        headers = [r for r in rows if r and r[0] == 'timestamp']
        self.assertEqual(len(headers), 1, "header must not repeat on re-open")
        self.assertEqual(len(rows), 7)  # 1 header + 6 data

    def test_max_rows_is_respected(self):
        self._record(20)
        self.store._flush_buffer()
        timestamps, matrix, _ = self.store.load_history(days=1, max_rows=5)
        self.assertLessEqual(len(timestamps), 5)

    def test_recent_scores_filter_by_time(self):
        self._record(3)
        self.assertEqual(len(self.store.get_recent_scores(minutes=90)), 3)
        # Age every entry out of the window
        for entry in self.store._recent_scores:
            entry['timestamp'] -= 100 * 60
        self.assertEqual(len(self.store.get_recent_scores(minutes=90)), 0)

    def test_storage_stats_report_real_numbers(self):
        self._record(4)
        self.store._flush_buffer()
        stats = self.store.get_storage_stats()
        self.assertGreaterEqual(stats['total_rows_written'], 4)
        self.assertEqual(stats['file_count'], 1)
        # total_size_mb rounds to 2dp, so a handful of rows legitimately reads 0.0
        self.assertGreaterEqual(stats['total_size_mb'], 0)
        self.assertEqual(stats['newest_date'], f"{datetime.now():%Y-%m-%d}")

    def test_retention_removes_old_files(self):
        old_date = (datetime.now() - timedelta(days=400)).strftime('%Y-%m-%d')
        old_file = os.path.join(self.store.store_dir, f"features_{old_date}.csv")
        with open(old_file, 'w') as f:
            f.write(','.join(FEATURE_COLUMNS) + '\n')
        self.store.max_days = 90
        self.store._cleanup_old_files()
        self.assertFalse(os.path.exists(old_file))

    def test_corrupt_row_does_not_abort_the_load(self):
        self._record(3)
        self.store._flush_buffer()
        path = os.path.join(self.store.store_dir,
                            f"features_{datetime.now():%Y-%m-%d}.csv")
        with open(path, 'a') as f:
            f.write('this,is,not,a,valid,row\n')
        timestamps, matrix, _ = self.store.load_history(days=1)
        self.assertEqual(len(timestamps), 3, "good rows must still load")

    def test_shutdown_is_idempotent(self):
        self._record(2)
        self.store.shutdown()
        self.store.shutdown()  # must not raise


# ══════════════════════════════════════════════════════════════════════
# Forensics payload scanning — the largest detection surface
# ══════════════════════════════════════════════════════════════════════
class TestForensicsCredentialDetection(unittest.TestCase):

    def setUp(self):
        c = cfg()
        c.set('forensics', 'store_raw_credentials', False)
        self.db = ForensicsDB(c)
        self.f = NetworkForensics(forensics_db=self.db)

    def _scan(self, payload, **kw):
        params = dict(src_ip='192.168.1.10', dst_ip='198.51.100.5',
                      src_port=40000, dst_port=21, protocol='TCP',
                      payload_size=len(payload), length=len(payload) + 54)
        params.update(kw)
        self.f.analyze_packet_with_payload(pkt(**params), payload)
        return self.f.credentials_found

    def test_ftp_credentials_are_detected(self):
        self._scan(b'USER admin\r\n')
        found = self._scan(b'PASS s3cr3t-ftp\r\n')
        protocols = {c['protocol'] for c in found}
        self.assertIn('FTP', protocols)

    def test_http_basic_auth_is_decoded(self):
        import base64
        token = base64.b64encode(b'alice:hunter2').decode()
        found = self._scan(
            f'GET /admin HTTP/1.1\r\nHost: intranet\r\n'
            f'Authorization: Basic {token}\r\n\r\n'.encode(),
            dst_port=80)
        self.assertTrue([c for c in found if 'HTTP' in c['protocol']])

    def test_telnet_password_is_detected(self):
        found = self._scan(b'Password: letmein\r\n', dst_port=23)
        self.assertTrue(found)

    def test_snmp_community_string_is_detected(self):
        found = self._scan(b'\x30\x26\x02\x01\x00\x04\x06public\xa0',
                           dst_port=161, protocol='UDP')
        self.assertTrue([c for c in found if 'SNMP' in c['protocol'].upper()])

    def test_displayed_value_is_masked(self):
        found = self._scan(b'PASS supersecretpassword\r\n')
        for cred in found:
            self.assertNotIn('supersecretpassword', cred['value'])

    def test_tls_payload_yields_nothing(self):
        """A TLS record must not be mined for credentials."""
        before = len(self.f.credentials_found)
        self._scan(b'\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03' + os.urandom(200),
                   dst_port=443)
        self.assertEqual(len(self.f.credentials_found), before)

    def test_empty_and_binary_payloads_are_safe(self):
        for payload in (b'', b'\x00' * 100, os.urandom(256), b'\xff\xfe\xfd'):
            self.f.analyze_packet_with_payload(
                pkt(src_ip='192.168.1.10', dst_ip='198.51.100.5',
                    dst_port=21, protocol='TCP', payload_size=len(payload)),
                payload)  # must not raise

    def test_insecure_service_is_recorded(self):
        for _ in range(6):
            self.f.analyze_packet(pkt(src_ip='192.168.1.10', dst_ip='192.168.1.60',
                                      src_port=40000, dst_port=23, protocol='TCP',
                                      length=100, payload_size=40))
        self.assertTrue(self.f.insecure_services)
        svc = next(iter(self.f.insecure_services.values()))
        self.assertIn('elnet', svc['service'])

    def test_private_key_in_transit_is_flagged(self):
        self._scan(b'-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n', dst_port=80)
        self.assertTrue([d for d in self.f.sensitive_data
                         if 'Private Key' in d['data_type']])

    def test_luhn_rejects_invalid_card_numbers(self):
        self.assertTrue(NetworkForensics._luhn_check('4111111111111111'))
        self.assertFalse(NetworkForensics._luhn_check('4111111111111112'))
        self.assertFalse(NetworkForensics._luhn_check('123'))

    def test_credit_card_is_masked_to_last_four(self):
        self._scan(b'POST /pay HTTP/1.1\r\nHost: shop\r\n\r\n'
                   b'card_number=4111111111111111&cvv=123', dst_port=80)
        cards = [d for d in self.f.sensitive_data if d['data_type'] == 'Credit Card']
        for card in cards:
            self.assertNotIn('4111111111111111', card['value'])
            self.assertIn('1111', card['value'])


# ══════════════════════════════════════════════════════════════════════
# AlertVerifier — decides the severity the user actually sees
# ══════════════════════════════════════════════════════════════════════
class TestAlertVerification(unittest.TestCase):

    def setUp(self):
        self.v = AlertVerifier(cfg())

    def _alert(self, rule_id, severity=Severity.HIGH, **evidence):
        return Alert(rule_id=rule_id, severity=severity, title=f'{rule_id} test',
                     description='test', evidence=dict(evidence),
                     src_ip=evidence.get('src_ip', '192.168.1.10'),
                     dst_ip=evidence.get('dst_ip', '198.51.100.5'))

    def test_every_alert_gets_a_verdict(self):
        """
        verify_alert() rebound `evidence` to a fresh dict whenever the alert had
        none, so the verdict it wrote never reached the alert.
        """
        for rule in ['THREAT-INTEL-IP', 'PORT-SCAN', 'BRUTE-FORCE', 'DATA-EXFIL',
                     'DNS-TUNNEL', 'DNS-BAD-TLD', 'DNS-FLOOD', 'ML-ANOMALY',
                     'ARP-SPOOF', 'SYN-FLOOD', 'ICMP-FLOOD', 'BAD-PORT',
                     'BL-IP-SRC', 'FORENSICS-CREDENTIAL', 'FORENSICS-INSECURE-SVC',
                     'FORENSICS-SENSITIVE-DATA', 'ODD-HOURS', 'UNKNOWN-RULE']:
            with self.subTest(rule=rule):
                alert = self._alert(rule)
                self.v.verify_alert(alert)
                verdict = alert.evidence.get('alert_verification', {})
                self.assertIn('verdict', verdict)
                self.assertIn('reasoning', verdict)

    def test_verification_never_raises_on_empty_evidence(self):
        for rule in ['THREAT-INTEL-IP', 'PORT-SCAN', 'DATA-EXFIL', 'ML-ANOMALY']:
            alert = Alert(rule_id=rule, severity='HIGH', title='t', description='d')
            self.v.verify_alert(alert)  # must not raise

    def test_false_positive_verdict_downgrades_severity(self):
        alert = self._alert('PORT-SCAN', severity=Severity.HIGH)
        self.v._adjust_severity(alert, AlertVerdict.FALSE_POSITIVE, 0.9)
        self.assertEqual(alert.severity, 'LOW')
        self.assertIn('FALSE POSITIVE', alert.title)

    def test_verified_threat_upgrades_severity(self):
        alert = self._alert('THREAT-INTEL-IP', severity=Severity.MEDIUM)
        self.v._adjust_severity(alert, AlertVerdict.VERIFIED_THREAT, 0.9)
        self.assertEqual(alert.severity, 'HIGH')
        self.assertIn('CONFIRMED', alert.title)

    def test_stats_track_verdict_distribution(self):
        for rule in ['PORT-SCAN', 'DATA-EXFIL', 'DNS-TUNNEL']:
            self.v.verify_alert(self._alert(rule))
        self.assertEqual(self.v.stats['total_verified'], 3)

    def test_alert_threshold_comes_from_config(self):
        """It was hardcoded to 0.25 and disagreed with ml.alert_threshold."""
        c = cfg()
        c.set('ml', 'alert_threshold', 0.7)
        self.assertAlmostEqual(AlertVerifier(c).alert_threshold, 0.7)


# ══════════════════════════════════════════════════════════════════════
# AlertCorrelator — incident grouping
# ══════════════════════════════════════════════════════════════════════
class TestAlertCorrelation(unittest.TestCase):

    def setUp(self):
        self.c = AlertCorrelator(cfg())

    def _alert(self, rule, category, src='203.0.113.5'):
        return Alert(rule_id=rule, severity=Severity.HIGH, title=rule,
                     description='d', src_ip=src, category=category)

    def test_same_source_groups_into_one_incident(self):
        first = self.c.process_alert(self._alert('PORT-SCAN', 'Reconnaissance'))
        second = self.c.process_alert(self._alert('PORT-SCAN', 'Reconnaissance'))
        self.assertIs(first, second)
        self.assertEqual(len(first.alerts), 2)

    def test_different_sources_stay_separate(self):
        a = self.c.process_alert(self._alert('PORT-SCAN', 'Reconnaissance', '203.0.113.5'))
        b = self.c.process_alert(self._alert('PORT-SCAN', 'Reconnaissance', '203.0.113.9'))
        self.assertIsNot(a, b)

    def test_recon_to_attack_escalates(self):
        self.c.process_alert(self._alert('PORT-SCAN', 'Reconnaissance'))
        incident = self.c.process_alert(self._alert('BRUTE-FORCE', 'Brute Force'))
        self.assertTrue(incident.severity in ('HIGH', 'CRITICAL'))
        self.assertTrue(incident.narrative)

    def test_incidents_survive_a_save_reload_cycle(self):
        self.c.process_alert(self._alert('PORT-SCAN', 'Reconnaissance'))
        self.c.save()
        restored = AlertCorrelator(cfg())
        self.assertTrue(restored.get_stats()['total_incidents'] >= 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)


# ══════════════════════════════════════════════════════════════════════
# PCAP write -> read round trip (both modules were 0% covered)
# ══════════════════════════════════════════════════════════════════════
class TestPcapRoundTrip(unittest.TestCase):
    """
    The export button is a headline feature and nothing verified that the bytes it
    writes are a valid PCAP, let alone that the analyser can read them back.
    """

    def setUp(self):
        if not SCAPY_REAL:
            self.skipTest('real scapy unavailable')
        self.tmp = tempfile.mkdtemp(prefix='ns_pcap_')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _frames(self, count=25):
        """Synthesise Ethernet/IP/TCP frames without touching the network."""
        from scapy.all import Ether, IP, TCP, Raw
        return [bytes(Ether(src='aa:bb:cc:dd:ee:01', dst='aa:bb:cc:dd:ee:02') /
                      IP(src='192.168.1.50', dst='93.184.216.34') /
                      TCP(sport=40000 + i, dport=80, flags='PA') /
                      Raw(load=b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'))
                for i in range(count)]

    def test_exported_file_is_a_valid_pcap(self):
        from src.pcap_writer import PcapWriter
        from scapy.all import rdpcap

        writer = PcapWriter(cfg(), output_dir=self.tmp)
        for frame in self._frames(25):
            writer.buffer_packet(frame)
        path = writer.export_buffer(filename='roundtrip.pcap', last_minutes=5)

        self.assertIsNotNone(path, "export returned no path")
        self.assertTrue(os.path.exists(path))
        packets = rdpcap(path)
        self.assertEqual(len(packets), 25)
        self.assertEqual(packets[0]['IP'].src, '192.168.1.50')
        self.assertEqual(packets[0]['TCP'].dport, 80)

    def test_analyser_reads_back_what_the_writer_produced(self):
        from src.pcap_writer import PcapWriter
        from src.pcap_analyzer import PcapAnalyzer

        writer = PcapWriter(cfg(), output_dir=self.tmp)
        for frame in self._frames(30):
            writer.buffer_packet(frame)
        path = writer.export_buffer(filename='analyse.pcap', last_minutes=5)

        analyzer = PcapAnalyzer(cfg())
        result = analyzer.analyze_file(path)

        self.assertIsInstance(result, dict)
        stats = result.get('stats', result)
        self.assertEqual(stats.get('total_packets'), 30)
        self.assertIn('192.168.1.50', str(result))

    def test_empty_buffer_exports_nothing(self):
        from src.pcap_writer import PcapWriter
        writer = PcapWriter(cfg(), output_dir=self.tmp)
        self.assertIsNone(writer.export_buffer(filename='empty.pcap'))

    def test_recording_rotates_and_prunes(self):
        from src.pcap_writer import PcapWriter
        c = cfg()
        c.set('capture', 'pcap_max_file_mb', 0)   # rotate on every packet
        c.set('capture', 'pcap_max_files', 3)
        writer = PcapWriter(c, output_dir=self.tmp)
        writer.start_recording(filename='rot.pcap')
        for frame in self._frames(10):
            writer.buffer_packet(frame)
        writer.stop_recording()
        recordings = [f for f in os.listdir(self.tmp)
                      if f.startswith('netsentinel_recording_')]
        self.assertLessEqual(len(recordings), 4,
                             "old recordings must be pruned to pcap_max_files")

    def test_rotation_failure_does_not_kill_recording(self):
        """A failed rotation used to leave a closed handle and silently stop capture."""
        from src.pcap_writer import PcapWriter
        writer = PcapWriter(cfg(), output_dir=self.tmp)
        writer.start_recording(filename='survive.pcap')
        writer.output_dir = os.path.join(self.tmp, 'does-not-exist')  # break rotation
        writer._rotate_recording()
        self.assertTrue(writer.is_recording)
        self.assertIsNotNone(writer._record_file)
        self.assertFalse(writer._record_file.closed)
        writer.buffer_packet(self._frames(1)[0])   # must still write
        self.assertGreaterEqual(writer._record_packets, 1)
        writer.stop_recording()


# ══════════════════════════════════════════════════════════════════════
# PCAP-on-alert
# ══════════════════════════════════════════════════════════════════════
class TestPcapOnAlert(unittest.TestCase):
    """
    A CRITICAL alert used to leave the user with a rule name and an IP and nothing
    to actually look at. The ring buffer already holds the traffic; this writes it
    out before it ages away.
    """

    def setUp(self):
        if not SCAPY_REAL:
            self.skipTest('real scapy unavailable')
        from src.pcap_writer import PcapWriter
        self.tmp = tempfile.mkdtemp(prefix='ns_alertpcap_')
        self.writer = PcapWriter(cfg(), output_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _fill(self):
        from scapy.all import Ether, IP, TCP, Raw
        for i in range(120):
            src, dst = (('203.0.113.9', '192.168.1.50') if i % 2
                        else ('192.168.1.50', '203.0.113.9'))
            self.writer.buffer_packet(bytes(
                Ether() / IP(src=src, dst=dst) / TCP(sport=4444, dport=80) / Raw(b'x' * 40)))
        for _ in range(80):      # unrelated hosts
            self.writer.buffer_packet(bytes(
                Ether() / IP(src='10.9.9.9', dst='10.8.8.8') / TCP() / Raw(b'y' * 40)))

    def test_export_produces_a_readable_pcap(self):
        from scapy.all import rdpcap
        self._fill()
        alert = Alert('SYN-FLOOD', Severity.CRITICAL, 'flood', 'd',
                      src_ip='203.0.113.9', dst_ip='192.168.1.50')
        path = self.writer.export_for_alert(alert)
        self.assertIsNotNone(path)
        self.assertTrue(rdpcap(path))

    def test_capture_is_narrowed_to_the_hosts_involved(self):
        from scapy.all import rdpcap
        self._fill()
        alert = Alert('SYN-FLOOD', Severity.CRITICAL, 'flood', 'd',
                      src_ip='203.0.113.9', dst_ip='192.168.1.50')
        packets = rdpcap(self.writer.export_for_alert(alert))
        self.assertEqual(len(packets), 120, "unrelated traffic should be filtered out")
        for p in packets:
            self.assertIn(p['IP'].src, ('203.0.113.9', '192.168.1.50'))

    def test_falls_back_to_everything_when_hosts_do_not_match(self):
        """Better to save the window than to save nothing."""
        from scapy.all import rdpcap
        self._fill()
        alert = Alert('ARP-SPOOF', Severity.CRITICAL, 'spoof', 'd', src_ip='192.168.99.99')
        packets = rdpcap(self.writer.export_for_alert(alert))
        self.assertEqual(len(packets), 200)

    def test_empty_buffer_returns_none(self):
        alert = Alert('SYN-FLOOD', Severity.CRITICAL, 'flood', 'd', src_ip='1.2.3.4')
        self.assertIsNone(self.writer.export_for_alert(alert))

    def test_filename_cannot_escape_the_output_directory(self):
        """rule_id reaches the filename, so it must be sanitised."""
        self._fill()
        alert = Alert('../../etc/evil', Severity.CRITICAL, 'x', 'd',
                      src_ip='203.0.113.9')
        path = self.writer.export_for_alert(alert)
        self.assertIsNotNone(path)
        self.assertEqual(os.path.dirname(os.path.abspath(path)),
                         os.path.abspath(self.tmp))

    def test_old_alert_captures_are_pruned(self):
        c = cfg()
        c.set('capture', 'pcap_max_alert_files', 3)
        from src.pcap_writer import PcapWriter
        writer = PcapWriter(c, output_dir=self.tmp)
        self.writer = writer
        self._fill()
        for i in range(8):
            writer.export_for_alert(
                Alert(f'RULE{i}', Severity.CRITICAL, 'x', 'd', src_ip='203.0.113.9'))
        saved = [f for f in os.listdir(self.tmp) if f.startswith('alert_')]
        self.assertLessEqual(len(saved), 3)


class TestFrameEndpointMatching(unittest.TestCase):
    """The byte-level endpoint check used to narrow an alert capture."""

    def test_ipv4_endpoints_are_matched(self):
        if not SCAPY_REAL:
            self.skipTest('real scapy unavailable')
        from scapy.all import Ether, IP, TCP
        from src.pcap_writer import _frame_involves
        frame = bytes(Ether() / IP(src='10.0.0.1', dst='10.0.0.2') / TCP())
        self.assertTrue(_frame_involves(frame, {'10.0.0.1'}))
        self.assertTrue(_frame_involves(frame, {'10.0.0.2'}))
        self.assertFalse(_frame_involves(frame, {'10.0.0.3'}))

    def test_ipv6_endpoints_are_matched(self):
        if not SCAPY_REAL:
            self.skipTest('real scapy unavailable')
        from scapy.all import Ether, IPv6, TCP
        from src.pcap_writer import _frame_involves
        frame = bytes(Ether() / IPv6(src='2001:db8::1', dst='2001:db8::2') / TCP())
        self.assertTrue(_frame_involves(frame, {'2001:db8::1'}))
        self.assertFalse(_frame_involves(frame, {'2001:db8::9'}))

    def test_truncated_and_non_ip_frames_are_safe(self):
        from src.pcap_writer import _frame_involves
        for frame in (b'', b'\x00' * 10, b'\x00' * 40, os.urandom(60)):
            self.assertIsInstance(_frame_involves(frame, {'10.0.0.1'}), bool)
