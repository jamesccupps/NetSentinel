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


if __name__ == '__main__':
    unittest.main()
