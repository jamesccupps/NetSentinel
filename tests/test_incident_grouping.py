"""
Incidents are grouped by the other host, not by this PC.
========================================================
The outside review of 2026-11-14 (N9): incidents were grouped by source
address. On a single PC that is this PC for nearly every alert, so unrelated
alerts five minutes apart became one "Multi-vector incident", and a threat
intel hit plus any data exposure became "Escalation ... a coordinated attack"
at HIGH. Addresses are made-up or documentation ones.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

PC = '192.168.10.32'
BAD, SHOP, OTHER = '198.51.100.66', '198.51.100.40', '192.168.10.66'


def correlator():
    from src.alert_correlator import AlertCorrelator
    return AlertCorrelator(reset_config(), own_addresses=lambda: frozenset({PC}))


def alert(rule, category, src=PC, dst=''):
    from src.ids_engine import Alert
    return Alert(rule, 'MEDIUM', rule, 'd', src_ip=src, dst_ip=dst, category=category)


class TestThisPC(unittest.TestCase):

    def test_two_things_this_pc_did_to_two_hosts_are_two_incidents(self):
        c = correlator()
        intel = c.process_alert(alert('THREAT-INTEL-IP', 'Threat Intelligence', dst=BAD))
        exposure = c.process_alert(alert('FORENSICS-SENSITIVE-DATA', 'Data Exposure', dst=SHOP))
        self.assertIsNot(intel, exposure)
        self.assertFalse(exposure.is_escalation)
        self.assertNotIn('Multi-vector', exposure.title)

    def test_two_things_with_one_host_are_one_incident(self):
        c = correlator()
        first = c.process_alert(alert('THREAT-INTEL-IP', 'Threat Intelligence', dst=BAD))
        second = c.process_alert(alert('DATA-EXFIL', 'Exfiltration', dst=BAD))
        self.assertIs(first, second)
        self.assertTrue(second.is_escalation)

    def test_another_host_attacking_this_pc_is_grouped_by_the_attacker(self):
        c = correlator()
        scan = c.process_alert(alert('PORT-SCAN', 'Reconnaissance', src=OTHER, dst=PC))
        brute = c.process_alert(alert('BRUTE-FORCE', 'Brute Force', src=OTHER, dst=PC))
        self.assertIs(scan, brute)
        self.assertTrue(brute.is_escalation)
        unrelated = c.process_alert(alert('PORT-SCAN', 'Reconnaissance', src='192.168.10.67',
                                          dst=PC))
        self.assertIsNot(unrelated, scan)

    def test_alerts_about_no_other_host_stay_with_their_rule(self):
        c = correlator()
        ml = c.process_alert(alert('ML-ANOMALY', 'Anomaly'))
        odd = c.process_alert(alert('ODD-HOURS', 'Anomaly'))
        self.assertIsNot(ml, odd)
        self.assertIs(c.process_alert(alert('ML-ANOMALY', 'Anomaly')), ml)


if __name__ == '__main__':
    unittest.main()
