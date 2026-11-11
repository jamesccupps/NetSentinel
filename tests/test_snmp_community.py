"""
SNMP's default community.
=========================
An HVAC scanner on the owner's PC sent "public" to 310 addresses. No device
answered, and that was 159 CRITICAL "Plaintext Credential (SNMP)" alerts, one
per host, each saying to change a password. The default is no secret: the news
is who sends it, once, and any device that answers to it. "public" also counted
anywhere in a packet, not only as the community.
Addresses are LAN examples; communities other than the defaults are made up.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_third_review import T0, DAY, PC, _Alerts, forensics, udp  # noqa: E402

DEVICE = '192.168.20.40'
OTHER = '192.168.20.41'


def tlv(tag, content):
    assert len(content) < 128
    return bytes([tag, len(content)]) + content


SYS_DESCR = tlv(0x06, bytes([0x2b, 6, 1, 2, 1, 1, 1, 0]))


def snmp(community=b'public', pdu=0xa0, version=1, value=tlv(0x05, b'')):
    """A one-varbind SNMP message: v1 is version 0, v2c is 1."""
    varbinds = tlv(0x30, tlv(0x30, SYS_DESCR + value))
    body = tlv(0x02, b'\x00\x00\x00\x01') + tlv(0x02, b'\x00') + tlv(0x02, b'\x00') + varbinds
    return tlv(0x30, tlv(0x02, bytes([version])) + tlv(0x04, community) + tlv(pdu, body))


def sweep(f, community=b'public', pdu=0xa0, hosts=150, ts=T0, src=PC):
    """A scanner asking one /24, one request per host."""
    for i in range(1, hosts + 1):
        f.analyze_packet(udp(src, 50000 + i, f'192.168.20.{i}', 161,
                             snmp(community, pdu), ts=ts + i))


def severity(alert):
    return str(getattr(alert.severity, 'name', alert.severity))


def verified(alert):
    from src.alert_verify import AlertVerifier
    AlertVerifier(reset_config()).verify_alert(alert)
    return alert.evidence['alert_verification']['verdict']


class TestParse(unittest.TestCase):

    def test_v1_and_v2c_headers(self):
        from src.forensics import parse_snmp
        self.assertEqual(parse_snmp(snmp(version=0)), ('v1', b'public', 'GetRequest'))
        self.assertEqual(parse_snmp(snmp(b'private', 0xa5)), ('v2c', b'private', 'GetBulkRequest'))

    def test_v3_and_other_bytes_have_no_community(self):
        from src.forensics import parse_snmp
        for payload in (snmp(version=3), b'\x30\x0c' + bytes(12), b'public', b'',
                        b'\x30\x10\x02\x01\x01\x04\x40public'):
            self.assertIsNone(parse_snmp(payload), payload)

    def test_a_cut_off_message_still_has_its_header(self):
        from src.forensics import parse_snmp
        self.assertEqual(parse_snmp(b'\x30\x26\x02\x01\x00\x04\x06public\xa0'),
                         ('v1', b'public', 'GetRequest'))
        self.assertEqual(parse_snmp(b'\x30\x26\x02\x01\x00\x04\x06public'),
                         ('v1', b'public', None))

    def test_a_long_form_length(self):
        from src.forensics import parse_snmp
        inner = snmp()[2:]
        self.assertEqual(parse_snmp(b'\x30\x81' + bytes([len(inner)]) + inner),
                         ('v2c', b'public', 'GetRequest'))


class TestDefaultCommunity(unittest.TestCase):

    def test_a_sweep_is_one_finding_not_one_per_host(self):
        f = forensics()
        sweep(f)
        [cred] = f.credentials_found
        self.assertEqual(cred['risk'], 'MEDIUM')
        self.assertEqual(cred['title'], "Default SNMP community 'public' sent")
        self.assertFalse(cred['extra']['answered'])

    def test_the_alert_is_medium_and_asks_for_no_password_change(self):
        from src.alert_verify import AlertVerdict
        from src.forensics import credential_alert
        f = forensics()
        sweep(f, hosts=3)
        alert = credential_alert(f.credentials_found[0])
        self.assertNotIn('Change this password', alert.evidence['recommendation'])
        self.assertEqual(verified(alert), AlertVerdict.INCONCLUSIVE)
        self.assertEqual(severity(alert), 'MEDIUM')
        self.assertNotIn('CONFIRMED', alert.title)

    def test_a_device_that_answers_is_its_own_alert(self):
        from src.alert_verify import AlertVerdict
        from src.forensics import credential_alert
        f = forensics()
        for minute in range(60):            # a monitoring tool polling it
            ts = T0 + minute * 60
            f.analyze_packet(udp(PC, 50001, DEVICE, 161, snmp(), ts=ts))
            f.analyze_packet(udp(DEVICE, 161, PC, 50001, snmp(pdu=0xa2), ts=ts + 0.01))
        answered = [c for c in f.credentials_found if c['extra']['answered']]
        self.assertEqual(len(f.credentials_found), 2)
        [cred] = answered
        self.assertEqual((cred['source_ip'], cred['destination_ip'], cred['port']),
                         (PC, DEVICE, 161))
        self.assertEqual(cred['risk'], 'HIGH')
        alert = credential_alert(cred)
        self.assertEqual(alert.title, "Device answers SNMP's default community 'public'")
        self.assertEqual(verified(alert), AlertVerdict.VERIFIED_THREAT)
        self.assertIn('CONFIRMED', alert.title)

    def test_private_answered_is_critical_and_a_default_write_is_high(self):
        f = forensics()
        f.analyze_packet(udp(DEVICE, 161, PC, 50001, snmp(b'private', 0xa2)))
        f.analyze_packet(udp(PC, 50002, OTHER, 161, snmp(b'private', 0xa3), ts=T0 + 1))
        risks = {c['extra']['answered']: c['risk'] for c in f.credentials_found}
        self.assertEqual(risks, {True: 'CRITICAL', False: 'HIGH'})

    def test_public_inside_a_value_is_not_the_community(self):
        f = forensics()
        value = tlv(0x04, b'public library printer')
        f.analyze_packet(udp(PC, 50001, DEVICE, 161, snmp(b'n0t-the-default', 0xa0, value=value)))
        f.analyze_packet(udp(DEVICE, 161, PC, 50001, snmp(b'n0t-the-default', 0xa2, value=value)))
        self.assertEqual(list(f.credentials_found), [])

    def test_once_a_day_per_sender(self):
        f = forensics()
        sweep(f, hosts=5)
        sweep(f, hosts=5, src='192.168.1.51')
        sweep(f, hosts=5, ts=T0 + DAY + 10)
        self.assertEqual(len(f.credentials_found), 3)

    def test_a_trap_with_the_default_names_its_sender(self):
        f = forensics()
        f.analyze_packet(udp(DEVICE, 50010, PC, 162, snmp(pdu=0xa7)))
        [cred] = f.credentials_found
        self.assertEqual((cred['source_ip'], cred['risk']), (DEVICE, 'MEDIUM'))
        self.assertIn('SNMPv2-Trap', cred['description'])


class TestTheApp(unittest.TestCase):

    def test_the_scan_raises_one_alert(self):
        f = forensics()
        alerts = _Alerts(f)
        alerts.app._credentials_alerted = {}
        sweep(f)
        alerts.app._check_forensics_alerts()
        self.assertEqual([a.rule_id for a in alerts.raised], ['FORENSICS-CREDENTIAL'])

    def test_the_first_device_asked_that_answers_is_still_reported(self):
        """
        The sender's alert names the first device it asked. When that device
        answered, its alert had the same protocol, ends, port and community, so
        the app's once-a-day check took it for a repeat and dropped it.
        """
        f = forensics()
        alerts = _Alerts(f)
        alerts.app._credentials_alerted = {}
        f.analyze_packet(udp(PC, 50001, DEVICE, 161, snmp()))
        f.analyze_packet(udp(DEVICE, 161, PC, 50001, snmp(pdu=0xa2), ts=T0 + 0.01))
        alerts.app._check_forensics_alerts()
        self.assertEqual(sorted(a.title for a in alerts.raised),
                         ["Default SNMP community 'public' sent",
                          "Device answers SNMP's default community 'public'"])


if __name__ == '__main__':
    unittest.main()
