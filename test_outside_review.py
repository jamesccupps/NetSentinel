"""
Fixes from the outside review of 2026-11-05 (NetSentinel-review-2026-11-05.md).

Each test fails on the code the review read (bacd645).
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Isolated HOME + real Scapy where available. Must precede any src import.
import _test_support  # noqa: E402,F401

from src.capture import PacketInfo  # noqa: E402
from src.config import Config, as_float, as_int  # noqa: E402


def cfg():
    c = Config().load()
    c.set('threat_intel', 'auto_update', False)
    return c


def pkt(**kw):
    p = PacketInfo()
    for k, v in kw.items():
        setattr(p, k, v)
    return p


class TestNumericSettings(unittest.TestCase):
    """M3: a hand-typed setting reached the code as a string."""

    def test_whole_numbers_in_any_spelling(self):
        self.assertEqual(as_int(5514, 1), 5514)
        self.assertEqual(as_int(' 5514 ', 1), 5514)
        self.assertEqual(as_int('5514', 1), 5514)
        self.assertEqual(as_int(30.0, 1), 30)
        self.assertIsInstance(as_int('30', 1), int)

    def test_a_typo_falls_back_to_the_default(self):
        for typo in ('55l4', '5,514', '30d', '', None, True, 'nan', 'inf', 2.5, [], {}):
            with self.subTest(typo=typo):
                self.assertEqual(as_int(typo, 7, name='x.y'), 7)

    def test_out_of_range_is_clamped(self):
        self.assertEqual(as_int(70000, 5514, lo=1, hi=65535), 65535)
        self.assertEqual(as_int(-3, 10, lo=1), 1)
        self.assertEqual(as_float('1.5', 0.5, lo=0.0, hi=1.0), 1.0)

    def test_floats(self):
        self.assertEqual(as_float('0.25', 0.5), 0.25)
        self.assertEqual(as_float('high', 0.5, name='ml.x'), 0.5)
        self.assertEqual(as_float(float('nan'), 0.5), 0.5)


# A made-up parking message: agency 28, a made-up transponder number.
TAG = b'28:90517734'
PARKING_RFID = (b'<Message><Command>UpdateRfid</Command><SenderId>GATE-PC-9</SenderId>'
                b'<TicketNumber>4410</TicketNumber>'
                b'<EntryCredential>' + TAG + b'</EntryCredential></Message>')
PARKING_CARD = (b'<Message><Command>UpdateCreditCard</Command><SenderId>GATE-PC-9</SenderId>'
                b'<TicketNumber>4411</TicketNumber><CardType>Visa</CardType>'
                b'<LastFour>4242</LastFour></Message>')


class TestParkingCredentialsMasked(unittest.TestCase):
    """H4: the full RFID tag went into alerts, the timeline and review bundles."""

    def setUp(self):
        from src.forensics import NetworkForensics
        from src.forensics_db import ForensicsDB
        c = cfg()
        c.set('forensics', 'store_raw_credentials', False)
        self.f = NetworkForensics(forensics_db=ForensicsDB(c))

    def _send(self, payload):
        from src.forensics import SKIDATA_PORT
        self.f.analyze_packet_with_payload(
            pkt(src_ip='192.168.20.40', dst_ip='192.168.20.5', src_port=40000,
                dst_port=SKIDATA_PORT, protocol='UDP', payload_size=len(payload),
                length=len(payload) + 42),
            payload)

    def test_the_tag_number_is_never_shown(self):
        self._send(PARKING_RFID)
        self.assertTrue(self.f.credentials_found, 'the parking tag was not detected')
        shown = json.dumps({'credentials': [
            {k: v for k, v in c.items() if k not in ('raw_value', 'value_raw')}
            for c in self.f.credentials_found],
            'sensitive': self.f.sensitive_data,
            'timeline': list(self.f.timeline)}, default=str)
        self.assertNotIn('90517734', shown)
        self.assertNotIn('0517734', shown)
        self.assertIn('****34', shown)

    def test_card_and_tag_digits_stay_out_of_a_review_bundle(self):
        from src.review import _Redactor
        self._send(PARKING_RFID)
        self._send(PARKING_CARD)
        redact = _Redactor()
        for cred in self.f.credentials_found:
            record = {'rule_id': 'FORENSICS-CREDENTIAL', 'title': 'Parking credential',
                      'description': cred['value'],
                      'evidence': {'protocol': cred['protocol'], 'value': cred['value'],
                                   'extra': cred.get('extra') or {}}}
            out = json.dumps(redact.alert(record))
            with self.subTest(cred=cred['credential_type']):
                self.assertNotIn('4242', out)
                self.assertNotIn('****34', out)
                self.assertNotIn('90517734', out)

    def test_nested_evidence_keeps_only_known_text(self):
        """A parser's own field names reached the bundle unless a deny-list knew them."""
        from src.review import _Redactor
        out = _Redactor().evidence({'extra': {'gate_pc': 'GATE-PC-9', 'badge_id': 'B-77812',
                                              'count': 3},
                                    'alert_verification': {'verdict': 'LIKELY_REAL',
                                                           'reasoning': ['x']}})
        self.assertEqual(out['extra'], {'gate_pc': 'GATE-PC-9', 'count': 3})
        self.assertEqual(out['alert_verification']['verdict'], 'LIKELY_REAL')

    def test_a_query_without_a_scheme_is_dropped(self):
        from src.review import _Redactor
        out = _Redactor().evidence({'http_path': '/login?user=ops&pw=x1',
                                    'extra': {'url': 'h.example/p?token=abc#frag'}})
        self.assertEqual(out['http_path'], '/login?[query removed]')
        self.assertEqual(out['extra']['url'], 'h.example/p?[query removed]')


class TestUnifiPinBeforeKey(unittest.TestCase):
    """H2: the API key went out in the request, and the pin was checked after."""

    def _connection(self, der):
        from types import SimpleNamespace
        from unittest import mock
        conn = mock.MagicMock()
        conn.sock.getpeercert.return_value = der
        conn.getresponse.return_value = SimpleNamespace(status=200, read=lambda n: b'{}')
        return mock.patch('http.client.HTTPSConnection', return_value=conn), conn

    def test_a_certificate_that_is_not_the_pinned_one_never_gets_the_key(self):
        import hashlib
        from src.unifi import CertificateChanged, https_get
        patch, conn = self._connection(b'an impostor certificate')
        with patch:
            with self.assertRaises(CertificateChanged):
                https_get('192.168.1.1', '/proxy/network/integration/v1/sites', 'test-key',
                          pin=hashlib.sha256(b'the console certificate').hexdigest())
        conn.connect.assert_called_once()
        conn.request.assert_not_called()

    def test_the_pinned_certificate_gets_the_request(self):
        import hashlib
        from src.unifi import https_get
        der = b'the console certificate'
        patch, conn = self._connection(der)
        with patch:
            status, _, fingerprint = https_get('192.168.1.1', '/x', 'test-key',
                                               pin=hashlib.sha256(der).hexdigest())
        self.assertEqual((status, fingerprint), (200, hashlib.sha256(der).hexdigest()))
        conn.request.assert_called_once()

    def test_no_certificate_at_all_is_refused_before_the_key(self):
        from src.unifi import UnifiError, https_get
        patch, conn = self._connection(None)
        with patch:
            with self.assertRaises(UnifiError):
                https_get('192.168.1.1', '/x', 'test-key')
        conn.request.assert_not_called()

    def test_a_typo_in_the_refresh_interval_does_not_stop_startup(self):
        from src.unifi import UnifiInventory

        class Settings:
            def get(self, *keys, default=None):
                return {('unifi', 'refresh_minutes'): '5m'}.get(keys, default)

            def set(self, *a):
                pass
        self.assertEqual(UnifiInventory(Settings()).refresh_sec, 300)


class TestProgramsByAbsolutePath(unittest.TestCase):
    """H1: the elevated process ran route, ipconfig, powershell and tshark by bare
    name, and Windows looks for a bare name in the exe's own folder first."""

    # POSIX-only openers (gui.py): no exe-folder lookup there.
    POSIX_ONLY = {'open', 'xdg-open'}

    def test_no_program_is_started_by_bare_name(self):
        import ast
        import glob
        root = os.path.dirname(os.path.abspath(__file__))
        bare = []
        for path in glob.glob(os.path.join(root, 'src', '**', '*.py'), recursive=True):
            with open(path, encoding='utf-8') as f:
                tree = ast.parse(f.read())
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ('run', 'Popen', 'call', 'check_call',
                                               'check_output')
                        and node.args and isinstance(node.args[0], ast.List)
                        and node.args[0].elts):
                    continue
                first = node.args[0].elts[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str) \
                        and first.value not in self.POSIX_ONLY:
                    bare.append(f"{os.path.basename(path)}:{node.lineno} {first.value}")
        self.assertEqual(bare, [])

    def test_net_detect_runs_the_tools_it_was_given(self):
        from types import SimpleNamespace
        from unittest import mock
        from src import net_detect
        commands = []

        def run(cmd, **kw):
            commands.append(cmd[0])
            return SimpleNamespace(stdout='', returncode=0)

        with mock.patch.object(net_detect, 'PSUTIL_AVAILABLE', True), \
                mock.patch.object(net_detect, 'system_tool',
                                  side_effect=lambda *p: '|'.join(('SYS32',) + p)), \
                mock.patch.object(net_detect.subprocess, 'run', side_effect=run):
            net_detect.detect_default_gateway()
            net_detect.detect_configured_dns_servers()
            net_detect.detect_dhcp_server()
        self.assertTrue(commands)
        self.assertTrue(all(c.startswith('SYS32|') for c in commands), commands)

    @unittest.skipUnless(os.name == 'nt', 'Windows paths')
    def test_system32_comes_from_windows_not_the_environment(self):
        from unittest import mock
        from src.winpaths import system_tool
        real = system_tool('ipconfig.exe')
        self.assertTrue(os.path.isabs(real) and os.path.isfile(real), real)
        with mock.patch.dict(os.environ, {'SystemRoot': 'C:\\owner-writable',
                                          'windir': 'C:\\owner-writable'}):
            self.assertEqual(system_tool('ipconfig.exe'), real)

    @unittest.skipUnless(os.name == 'nt', 'Windows paths')
    def test_tshark_is_never_taken_from_path_on_windows(self):
        import tempfile
        from unittest import mock
        from src import pcap_analyzer
        with tempfile.TemporaryDirectory() as empty, \
                mock.patch.object(pcap_analyzer, 'program_files_dirs', return_value=[empty]), \
                mock.patch.object(pcap_analyzer.shutil, 'which', return_value='tshark'):
            self.assertIsNone(pcap_analyzer.find_tshark())


class TestModelNotPickled(unittest.TestCase):
    """H3: the HMAC that guarded the pickled model kept its key in the same
    user-writable folder, so any program running as the owner could sign a
    pickle that the elevated process then unpickled."""

    def test_a_signed_pickle_is_never_loaded_and_the_old_files_go(self):
        import hashlib
        import hmac
        import pickle
        from unittest import mock
        from src.config import APP_DIR, MODELS_DIR
        from src.ml_engine import AnomalyDetector

        class Evil:
            def __reduce__(self):
                return (Evil._ran.append, (True,))
        Evil._ran = []

        key = os.urandom(32)
        os.makedirs(MODELS_DIR, exist_ok=True)
        with open(os.path.join(APP_DIR, '.model_key'), 'wb') as f:
            f.write(key)
        blob = pickle.dumps(Evil())
        for name in ('isolation_forest.pkl', 'scaler.pkl'):
            with open(os.path.join(MODELS_DIR, name), 'wb') as f:
                f.write(hmac.new(key, blob, hashlib.sha256).digest() + blob)

        with mock.patch('pickle.loads', side_effect=AssertionError('unpickled')) as loads:
            det = AnomalyDetector(cfg())
        loads.assert_not_called()
        self.assertEqual(Evil._ran, [])
        self.assertFalse(det.is_trained)
        for path in (os.path.join(MODELS_DIR, 'isolation_forest.pkl'),
                     os.path.join(MODELS_DIR, 'scaler.pkl'), os.path.join(APP_DIR, '.model_key')):
            self.assertFalse(os.path.exists(path), path)

    def test_training_writes_no_model_file(self):
        import numpy as np
        from src.config import MODELS_DIR
        from src.ml_engine import AnomalyDetector, SKLEARN_AVAILABLE
        if not SKLEARN_AVAILABLE:
            self.skipTest('needs scikit-learn')
        det = AnomalyDetector(cfg())
        width = len(det.feature_extractor.feature_names)
        rng = np.random.default_rng(1)
        for row in rng.normal(size=(max(det.min_samples, 50), width)):
            det._training_buffer.append(row)
        det._train_model()
        self.assertTrue(det.is_trained)
        self.assertFalse([n for n in os.listdir(MODELS_DIR) if n.endswith('.pkl')])


class TestSignaturesThatDoNotVerify(unittest.TestCase):
    """H7: a signature whose Status was not Valid still counted as signed, and
    any trusted name found inside the publisher scored +3."""

    def setUp(self):
        import tempfile
        from src.process_verify import ProcessVerifier
        self.v = ProcessVerifier(cfg())
        handle, self.exe = tempfile.mkstemp(suffix='.exe')
        os.close(handle)
        self.addCleanup(os.remove, self.exe)

    def _verify(self, signature, location):
        from unittest import mock
        with mock.patch.object(self.v, '_check_signature', return_value=signature), \
                mock.patch.object(self.v, '_check_location', return_value=location), \
                mock.patch.object(self.v, '_get_file_metadata', return_value={'age_days': 30}):
            return self.v.verify_process(exe_path=self.exe)

    def test_a_forged_microsoft_signature_is_not_trusted(self):
        from src.process_verify import Verdict
        forged = {'signed': True, 'valid': False, 'publisher': 'Microsoft Corporation'}
        result = self._verify(forged, {'is_system_dir': True})
        self.assertNotIn(result['verdict'], (Verdict.VERIFIED_SAFE, Verdict.LIKELY_SAFE))
        self.assertTrue(result['checks'].get('invalid_signature'))
        self.assertNotIn('Digitally signed', result['summary'])
        self.assertFalse(self.v._known_good, 'a forged signature reached known-good')

    def test_a_valid_microsoft_signature_still_is(self):
        from src.process_verify import Verdict
        real = {'signed': True, 'valid': True, 'publisher': 'Microsoft Corporation'}
        self.assertEqual(self._verify(real, {'is_system_dir': True})['verdict'],
                         Verdict.VERIFIED_SAFE)

    def test_publishers_match_by_whole_name(self):
        from src.process_verify import is_trusted_publisher
        for name in ('Microsoft Corporation', 'Microsoft Windows Publisher',
                     'ESET, spol. s r.o.', 'Google LLC'):
            self.assertTrue(is_trusted_publisher(name), name)
        for name in ('Reset Ltd', 'Amdocs Ltd', 'Not Microsoft Corporation', ''):
            self.assertFalse(is_trusted_publisher(name), name)

    def test_the_writable_folders_under_windows_are_suspicious(self):
        from src.process_verify import _WINDOWS, _SYSTEM32
        for path in (os.path.join(_WINDOWS, 'Temp', 'svchost.exe'),
                     os.path.join(_SYSTEM32, 'spool', 'drivers', 'color', 'x.exe'),
                     os.path.join(_SYSTEM32, 'Tasks', 'x.exe')):
            loc = self.v._check_location(path)
            self.assertTrue(loc['is_suspicious_dir'], path)
            self.assertFalse(loc['is_system_dir'], path)
        self.assertTrue(self.v._check_location(
            os.path.join(_SYSTEM32, 'svchost.exe'))['is_system_dir'])


class TestVerdictSubjects(unittest.TestCase):
    """H6: a false-positive verdict stored its first subject, the destination,
    which for inbound and flood alerts is this PC: every later alert of that
    rule against this PC, from anyone, was then dropped for good."""

    PC = '192.168.10.32'

    def setUp(self):
        import tempfile
        from src.baseline_whitelist import ConfirmedFalsePositives
        self.dir = tempfile.mkdtemp(prefix='ns_verdicts_')
        self.store = ConfirmedFalsePositives(os.path.join(self.dir, 'confirmed.json'),
                                             local_addresses=lambda: frozenset({self.PC}))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, True)

    def alert(self, rule, src, dst, **evidence):
        from src.ids_engine import Alert
        return Alert(rule, 'HIGH', 't', 'd', src_ip=src, dst_ip=dst, category='Test',
                     evidence=evidence)

    def test_a_verdict_on_an_inbound_flood_names_the_sender(self):
        entry = self.store.add(self.alert('ICMP-FLOOD', '192.168.10.50', self.PC))
        self.assertEqual((entry['kind'], entry['value']), ('src_ip', '192.168.10.50'))
        self.assertIsNotNone(self.store.matches(self.alert('ICMP-FLOOD', '192.168.10.50', self.PC)))
        self.assertIsNone(self.store.matches(self.alert('ICMP-FLOOD', '203.0.113.66', self.PC)),
                          'a flood from anyone else must still alert')

    def test_this_pc_is_never_a_subject(self):
        from src.baseline_whitelist import alert_subjects
        out = self.alert('DATA-EXFIL', self.PC, '203.0.113.7')
        self.assertEqual(alert_subjects(out, {self.PC}), [('dst_ip', '203.0.113.7')])
        self.assertIsNone(self.store.add(self.alert('ODD-HOURS', self.PC, self.PC)))

    def test_a_claimed_name_is_not_the_subject_of_an_address_rule(self):
        entry = self.store.add(self.alert('THREAT-INTEL-IP', self.PC, '203.0.113.9',
                                          tls_sni='www.gstatic.com'))
        self.assertEqual((entry['kind'], entry['value']), ('dst_ip', '203.0.113.9'))
        self.assertIsNone(self.store.matches(self.alert('THREAT-INTEL-IP', self.PC, '198.51.100.4',
                                                        tls_sni='www.gstatic.com')))

    def test_an_old_verdict_naming_this_pc_stops_applying(self):
        from src.baseline_whitelist import ConfirmedFalsePositives
        with open(self.store.path, 'w', encoding='utf-8') as f:
            json.dump([{'rule_id': 'PORT-SCAN', 'kind': 'dst_ip', 'value': self.PC,
                        'note': '', 'review_id': '', 'added': 1.0}], f)
        with self.assertLogs('NetSentinel.BaselineWL', 'WARNING'):
            store = ConfirmedFalsePositives(self.store.path,
                                            local_addresses=lambda: frozenset({self.PC}))
        self.assertTrue(store.entries()[0]['names_this_pc'])
        self.assertIsNone(store.matches(self.alert('PORT-SCAN', '203.0.113.66', self.PC)))


class TestNamesThatVouch(unittest.TestCase):
    """H5: any TLS server name and any DNS answer, asked for or not, named an
    address, and the names then lowered its alerts: one handshake naming
    drive.google.com made a C2 address a "Shared Cloud IP" at LOW."""

    C2 = '203.0.113.66'
    PC = '192.168.1.5'
    RESOLVER = '192.168.1.1'

    def engine(self):
        from src.ids_engine import IDSEngine
        from src.net_detect import KNOWN_CLOUD_DOMAINS, NetworkEnvironment

        class Intel:
            def check_ip(inner, ip):
                return {'feed': 'feodo_c2', 'category': 'Malware',
                        'description': 'x'} if ip == self.C2 else None

            def check_domain(inner, domain):
                return None

        env = NetworkEnvironment()
        env._cloud_domain_set = set(KNOWN_CLOUD_DOMAINS)
        alerts = []
        ids = IDSEngine(cfg(), alert_callback=alerts.append, threat_intel=Intel(), net_env=env)
        if getattr(ids, 'lan', None) is not None:
            ids.lan.state_path = None
        return ids, alerts

    def hit(self, alerts):
        return next(a for a in alerts if a.rule_id == 'THREAT-INTEL-IP')

    def connect(self, ids, sni=''):
        ids.inspect_packet(pkt(src_ip=self.PC, dst_ip=self.C2, src_port=51000, dst_port=443,
                               protocol='TCP', flags='PA', tls_sni=sni))

    def query(self, ids, name, port=53001):
        ids.inspect_packet(pkt(src_ip=self.PC, dst_ip=self.RESOLVER, src_port=port, dst_port=53,
                               protocol='UDP', dns_query=name))

    def answer(self, ids, name, port=53001, src=None):
        ids.inspect_packet(pkt(src_ip=src or self.RESOLVER, dst_ip=self.PC, src_port=53,
                               dst_port=port, protocol='UDP', dns_query=name, dns_rcode=0,
                               dns_answers=(self.C2,), dns_response=self.C2))

    def test_a_handshake_name_does_not_make_a_c2_address_cloud(self):
        ids, alerts = self.engine()
        self.connect(ids, sni='drive.google.com')
        hit = self.hit(alerts)
        self.assertNotIn('Shared Cloud', hit.title)
        self.assertNotEqual(hit.severity, 'LOW')
        self.assertIn('drive.google.com', ids._get_domains_for_ip(self.C2), 'still shown')

    def test_an_answer_to_this_hosts_own_query_vouches(self):
        ids, alerts = self.engine()
        self.query(ids, 'docs.google.com')
        self.answer(ids, 'docs.google.com')
        self.assertEqual(ids._vouched_domains_for_ip(self.C2), {'docs.google.com'})
        self.connect(ids)
        self.assertIn('Shared Cloud', self.hit(alerts).title)

    def test_an_answer_nobody_asked_for_vouches_for_nothing(self):
        ids, alerts = self.engine()
        self.answer(ids, 'docs.google.com')                          # no query
        self.query(ids, 'mail.google.com', port=53002)
        self.answer(ids, 'mail.google.com', port=53002, src='192.168.1.77')   # wrong server
        self.answer(ids, 'www.google.com', port=53002)               # a name not asked
        self.assertEqual(ids._vouched_domains_for_ip(self.C2), set())
        self.connect(ids)
        self.assertNotIn('Shared Cloud', self.hit(alerts).title)

    def test_a_handshake_name_on_its_owners_addresses_vouches(self):
        from src.cloud_ranges import CloudRanges
        ids, _ = self.engine()
        ids.cloud_ranges = CloudRanges(
            {'providers': {'google': {'kind': 'cloud', 'v4': ['203.0.113.0/24']}}})
        self.connect(ids, sni='drive.google.com')
        self.assertEqual(ids._vouched_domains_for_ip(self.C2), {'drive.google.com'})
        ids.cloud_ranges = CloudRanges(
            {'providers': {'aws': {'kind': 'cloud', 'v4': ['203.0.113.0/24']}}})
        self.assertEqual(ids._vouched_domains_for_ip(self.C2), set(),
                         "a Google name on Amazon's addresses is a claim")

    def test_an_upload_to_a_claimed_name_is_not_a_known_service(self):
        from src.alert_verify import AlertVerifier
        from src.ids_engine import Alert
        ids, _ = self.engine()
        self.connect(ids, sni='drive.google.com')
        alert = Alert('DATA-EXFIL', 'HIGH', 't', 'd', src_ip=self.PC, dst_ip=self.C2,
                      evidence={'destination_ip': self.C2, 'megabytes_transferred': 100})
        out = AlertVerifier(cfg())._verify_data_exfil(alert, alert.evidence, ids)
        text = ' '.join(out['reasoning'])
        self.assertNotIn('known service', text)
        self.assertIn('Named only by the client', text)

    def test_a_known_service_needs_a_dot_before_it(self):
        from src.alert_verify import AlertVerifier
        from src.ids_engine import Alert
        alert = Alert('DATA-EXFIL', 'HIGH', 't', 'd', src_ip=self.PC, dst_ip=self.C2,
                      evidence={'destination_ip': self.C2, 'megabytes_transferred': 100,
                                'destination_domains': ['evildropbox.com']})
        out = AlertVerifier(cfg())._verify_data_exfil(alert, alert.evidence, None)
        self.assertNotIn('known service', ' '.join(out['reasoning']))


class TestReverseDnsLowersNothing(unittest.TestCase):
    """M6: the reverse DNS of an alerted address, which its owner writes, lowered
    the score when it named a cloud (-2) or, by substring, a scanner (-2)."""

    def verdict(self, rule, rdns, **evidence):
        from unittest import mock
        from src.alert_verify import AlertVerifier
        from src.ids_engine import Alert
        from src.net_detect import KNOWN_CLOUD_DOMAINS, NetworkEnvironment
        env = NetworkEnvironment()
        env._cloud_domain_set = set(KNOWN_CLOUD_DOMAINS)
        verifier = AlertVerifier(cfg(), net_env=env)
        alert = Alert(rule, 'HIGH', 't', 'd', src_ip='203.0.113.66', dst_ip='192.168.1.5',
                      evidence=dict(evidence))
        with mock.patch.object(verifier, '_reverse_dns', return_value=rdns):
            verifier.verify_alert(alert)
        v = alert.evidence['alert_verification']
        return v['verdict'], v.get('confidence'), alert.severity

    def test_a_cloud_name_in_reverse_dns_changes_nothing(self):
        plain = self.verdict('THREAT-INTEL-IP', 'host.example.org', matched_ip='203.0.113.66',
                             threat_category='Malware')
        cloud = self.verdict('THREAT-INTEL-IP', 'ec2-203-0-113-66.compute.amazonaws.com',
                             matched_ip='203.0.113.66', threat_category='Malware')
        self.assertEqual(plain, cloud)

    def test_a_scanner_name_in_reverse_dns_changes_nothing(self):
        plain = self.verdict('PORT-SCAN', 'host.example.org', scanner_ip='203.0.113.66',
                             ports_scanned=[22, 23, 80, 443, 3389])
        named = self.verdict('PORT-SCAN', 'scan-7.shodan.io', scanner_ip='203.0.113.66',
                             ports_scanned=[22, 23, 80, 443, 3389])
        self.assertEqual(plain, named)


class Typos:
    """A config whose given keys hold what someone typed; the rest default."""

    def __init__(self, **typed):
        self.typed = {tuple(k.split('__')): v for k, v in typed.items()}

    def get(self, *keys, default=None):
        return self.typed.get(keys, default)

    def set(self, *a):
        pass


class TestTyposInSettings(unittest.TestCase):
    """M3: a typo in a number setting stopped NetSentinel starting, or switched
    most IDS rules off without a word."""

    def test_a_typed_threshold_does_not_switch_the_ids_off(self):
        from src.ids_engine import IDSEngine
        alerts = []
        ids = IDSEngine(Typos(ids__port_scan_threshold='15x', ids__large_upload_mb='lots'),
                        alert_callback=alerts.append)
        if getattr(ids, 'lan', None) is not None:
            ids.lan.state_path = None
        self.assertEqual((ids.port_scan_threshold, ids.large_upload_mb), (15, 100))
        for port in range(20, 45):
            ids.inspect_packet(pkt(src_ip='192.168.1.5', dst_ip='203.0.113.9', src_port=40000,
                                   dst_port=port, protocol='TCP', flags='S'))
        self.assertIn('PORT-SCAN', [a.rule_id for a in alerts])

    def test_typos_do_not_stop_the_lan_and_review_parts_starting(self):
        import tempfile
        from src.lan_threats import LanThreatMonitor
        from src.review import ReviewRecorder
        lan = LanThreatMonitor(Typos(ids__arp_max_ips_per_mac='5x', ids__lan_baseline_hours='a day'),
                               offline=True)
        self.assertEqual((lan.arp_max_ips_per_mac, lan.baseline_hours), (5, 24))
        with tempfile.TemporaryDirectory() as folder:
            rec = ReviewRecorder(folder, None, Typos(review__capture_budget_mb='2GB',
                                                     review__capture_max_hours='1 day'))
            self.assertEqual((rec.capture_budget, rec.capture_max_age),
                             (2048 * 1024 * 1024, 24 * 3600))

    def test_the_settings_form_refuses_a_non_number(self):
        from src.gui import settings_from_form
        values, bad = settings_from_form({
            'ids.port_scan_threshold': '15x', 'syslog.port': '5,514',
            'ml.contamination': '0.1', 'ids.brute_force_threshold': ' 12 ',
            'capture.interface': 'Ethernet 2', 'alerts.sound_enabled': True})
        self.assertEqual(sorted(bad), ['ids.port_scan_threshold', 'syslog.port'])
        self.assertEqual(values['ml.contamination'], 0.1)
        self.assertEqual(values['ids.brute_force_threshold'], 12)
        self.assertEqual(values['capture.interface'], 'Ethernet 2')
        self.assertIs(values['alerts.sound_enabled'], True)

    def test_a_lower_case_severity_filter_still_filters(self):
        from src.alerts import AlertManager
        from src.ids_engine import Alert
        manager = AlertManager(Typos(alerts__severity_filter='high'))
        self.assertFalse(manager.add_alert(Alert('X', 'LOW', 't', 'd')))
        self.assertTrue(manager.add_alert(Alert('X', 'CRITICAL', 't', 'd')))


class TestReleaseWorkflow(unittest.TestCase):
    """M1: one job installed every unpinned dependency, then signed with the
    updater's key, with a write token in .git/config. A compromised package
    could read the key that signs every install's one-click update."""

    def setUp(self):
        try:
            import yaml
        except ImportError:
            self.skipTest('needs pyyaml')
        root = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(root, '.github', 'workflows', 'release.yml'),
                  encoding='utf-8') as f:
            self.flow = yaml.safe_load(f)
        self.jobs = self.flow['jobs']

    def steps(self, job):
        return self.jobs[job]['steps']

    def runs(self, job):
        return '\n'.join(s.get('run', '') for s in self.steps(job))

    def test_no_permission_unless_a_job_asks(self):
        self.assertEqual(self.flow['permissions'], {})
        writers = [name for name, job in self.jobs.items()
                   if (job.get('permissions') or {}).get('contents') == 'write']
        self.assertEqual(writers, ['publish'])

    def test_the_key_and_the_write_token_never_meet_third_party_code(self):
        import re
        with_key = [name for name, job in self.jobs.items()
                    if 'NETSENTINEL_SIGNING_KEY' in str(job)]
        self.assertEqual(with_key, ['sign'])
        installs = re.findall(r'pip install[^\n]*', self.runs('sign'))
        self.assertEqual(installs, ['pip install --require-hashes -r tools/sign-requirements.lock'])
        self.assertNotIn('pip install', self.runs('publish'))
        self.assertIn('--require-hashes -r requirements-build.lock', self.runs('build'))

    def test_actions_are_pinned_by_commit_and_keep_no_credentials(self):
        import re
        for name, job in self.jobs.items():
            for step in job['steps']:
                uses = step.get('uses')
                if not uses:
                    continue
                self.assertRegex(uses, r'@[0-9a-f]{40}$', f'{name}: {uses}')
                if uses.startswith('actions/checkout@'):
                    self.assertIs((step.get('with') or {}).get('persist-credentials'), False)

    def test_the_locks_pin_every_package_by_hash(self):
        root = os.path.dirname(os.path.abspath(__file__))
        for lock in ('requirements-build.lock', os.path.join('tools', 'sign-requirements.lock')):
            with open(os.path.join(root, lock), encoding='utf-8') as f:
                text = f.read()
            lines = [line for line in text.splitlines()
                     if line and not line.startswith((' ', '#'))]
            self.assertTrue(lines, lock)
            for line in lines:
                self.assertRegex(line, r'^[A-Za-z0-9_.-]+==[^\s]+ \\$', f'{lock}: {line}')
            self.assertGreaterEqual(text.count('--hash=sha256:'), len(lines), lock)


if __name__ == '__main__':
    unittest.main()
