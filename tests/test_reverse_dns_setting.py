"""
Reverse DNS is the owner's choice, and off.
===========================================
The outside review of 2026-11-14 (N11): checking a THREAT-INTEL-IP, PORT-SCAN
or plain-HTTP alert asked DNS for the name behind the address. For an
attacker's address the reverse zone's name server is the attacker's own, and
it sees the question; CLAUDE.md says nothing about the owner's traffic leaves
for lookups. The owner chose (2026-11-15): off by default, a setting to turn
it on. And (N9) a lookup answers later, so the first alert for every address
was scored "+1, no reverse DNS record" before any answer had come.
"""

import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

BAD = '198.51.100.66'


def verify(verifier):
    from src.ids_engine import Alert
    alert = Alert('THREAT-INTEL-IP', 'HIGH', 't', 'd', src_ip='192.168.10.32', dst_ip=BAD,
                  evidence={'matched_ip': BAD, 'threat_category': 'Malware'})
    verifier.verify_alert(alert)
    return ' '.join(alert.evidence['alert_verification']['reasoning'])


class TestOffByDefault(unittest.TestCase):

    def test_nothing_is_asked(self):
        import src.alert_verify as av
        verifier = av.AlertVerifier(reset_config())
        self.assertFalse(verifier.reverse_dns)
        with mock.patch.object(av.socket, 'gethostbyaddr',
                               side_effect=AssertionError('asked DNS')):
            reasoning = verify(verifier)
            self.assertIsNone(verifier._reverse_dns(BAD))
        self.assertNotIn('reverse DNS', reasoning.lower())

    def test_the_setting_is_offered(self):
        from src.config import DEFAULT_CONFIG
        self.assertIs(DEFAULT_CONFIG['verification']['reverse_dns'], False)
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               'src', 'gui.py'), encoding='utf-8') as f:
            self.assertIn("'verification.reverse_dns'", f.read())


class TestTurnedOn(unittest.TestCase):

    def verifier(self, answer):
        import src.alert_verify as av
        verifier = av.AlertVerifier(reset_config(**{'verification.reverse_dns': True}))
        self.addCleanup(reset_config)
        patcher = mock.patch.object(av.socket, 'gethostbyaddr', side_effect=answer)
        patcher.start()
        self.addCleanup(patcher.stop)
        return verifier

    def settle(self, verifier):
        deadline = time.time() + 3
        while verifier._rdns_pending and time.time() < deadline:
            time.sleep(0.02)

    def test_an_unanswered_lookup_scores_nothing(self):
        verifier = self.verifier(lambda ip: time.sleep(0.5) or ('x.example', [], [ip]))
        self.assertNotIn('No reverse DNS record', verify(verifier))

    def test_a_finished_lookup_with_no_record_is_said(self):
        verifier = self.verifier(OSError('no PTR'))
        verify(verifier)
        self.settle(verifier)
        self.assertIn('No reverse DNS record', verify(verifier))

    def test_a_name_is_shown(self):
        verifier = self.verifier(lambda ip: ('host.example.org', [], [ip]))
        verify(verifier)
        self.settle(verifier)
        self.assertIn('Reverse DNS: host.example.org', verify(verifier))


if __name__ == '__main__':
    unittest.main()
