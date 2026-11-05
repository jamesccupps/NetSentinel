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


if __name__ == '__main__':
    unittest.main()
