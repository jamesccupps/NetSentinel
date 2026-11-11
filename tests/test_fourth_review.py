"""
What the fourth review of real alerts found.
============================================
18.6 hours of 1.10.0 raised 13 alerts. The CRITICAL was AMD's telemetry upload
key, read past the end of its header line and treated as a password of the
owner's. The HIGH was an SSDP search whose random source port was BACnet's. And
a Home Assistant token in plain HTTP on port 8123 raised nothing, because
credentials were looked for only on a list of HTTP ports.
Tokens and keys here are made up; addresses are documentation or LAN examples.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_third_review import T0, DAY, PC, _Alerts, forensics, tcp, udp  # noqa: E402

HA = '192.168.1.97'
AMD = '203.0.113.235'
FAKE_TOKEN = 'Bearer not.a-real.token-for-tests-only'
FAKE_KEY = '0' * 64


def request(host, path='/', headers=(), method='POST', body=b'{}'):
    lines = [f'{method} {path} HTTP/1.1', f'Host: {host}', *headers,
             f'Content-Length: {len(body)}']
    return ('\r\n'.join(lines) + '\r\n\r\n').encode() + body


def credentials(f):
    return [(c['protocol'], c['risk']) for c in f.credentials_found]


class TestHttpOnAnyPort(unittest.TestCase):

    def test_a_bearer_token_to_home_assistant_on_8123_is_found(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 39453, HA, 8123, request(
            'homeassistant.local:8123', '/api/states/sensor.pc',
            [f'Authorization: {FAKE_TOKEN}', 'Content-Type: application/json']), server=8123))
        self.assertEqual(credentials(f), [('HTTP Auth Token', 'CRITICAL')])
        [cred] = f.credentials_found
        self.assertEqual(cred['extra']['host'], 'homeassistant.local:8123')
        self.assertNotIn('for-tests-only', cred['value'])

    def test_bytes_on_another_port_without_a_request_line_are_not_read_as_http(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 50000, HA, 9999,
                             b'\x00\x01binary Authorization: x y password=hunter', server=9999))
        self.assertEqual(list(f.credentials_found), [])

    def test_a_response_from_an_unlisted_port_is_not_a_request(self):
        f = forensics()
        f.analyze_packet(tcp(HA, 8123, PC, 39453,
                             b'HTTP/1.1 200 OK\r\nAuthorization: Bearer x\r\n\r\n', server=8123))
        self.assertEqual(list(f.credentials_found), [])


class TestTheAuthorizationHeader(unittest.TestCase):

    def amd_upload(self, host='uploads.amd-auep.com', stored=None):
        f = forensics()
        if stored is not None:
            # What goes to the vault: the display value is masked either way.
            add = f._add_credential
            f._add_credential = lambda *a, **kw: (stored.append(kw.get('raw_value')),
                                                  add(*a, **kw))
        f.analyze_packet(tcp(PC, 20269, AMD, 80, request(
            host, '/upload', ['Connection: Keep-Alive', f'Authorization: {FAKE_KEY}',
                              'User-Agent: AMD', 'GUID: 00000000-0000-0000-0000-000000000000']),
            server=80))
        return f

    def test_a_bare_key_ends_at_its_line(self):
        stored = []
        self.amd_upload('example.com', stored)
        self.assertEqual(stored, [FAKE_KEY])

    def test_amds_telemetry_key_is_low_with_nothing_to_change(self):
        from src.forensics import credential_alert
        f = self.amd_upload()
        self.assertEqual(credentials(f), [('HTTP Auth Token (Vendor Telemetry)', 'LOW')])
        alert = credential_alert(f.credentials_found[0])
        self.assertEqual(str(getattr(alert.severity, 'name', alert.severity)), 'LOW')
        self.assertTrue(alert.evidence['recommendation'].startswith('Nothing to change'))
        self.assertNotIn('Change this password', alert.evidence['recommendation'])

    def test_verification_does_not_confirm_it(self):
        from src.alert_verify import AlertVerifier, AlertVerdict
        from src.forensics import credential_alert
        alert = credential_alert(self.amd_upload().credentials_found[0])
        AlertVerifier(reset_config()).verify_alert(alert)
        self.assertEqual(alert.evidence['alert_verification']['verdict'],
                         AlertVerdict.LIKELY_FALSE_POSITIVE)
        self.assertNotIn('CONFIRMED', alert.title)
        self.assertEqual(str(getattr(alert.severity, 'name', alert.severity)), 'LOW')

    def test_a_vendor_is_matched_on_a_dot_boundary(self):
        """"eset.com" was a substring test, so preset.com's tokens were ESET's."""
        f = forensics()
        f.analyze_packet(tcp(PC, 50001, '198.51.100.9', 80, request(
            'api.preset.com', '/', [f'Authorization: {FAKE_TOKEN}']), server=80))
        self.assertEqual(credentials(f), [('HTTP Auth Token', 'CRITICAL')])

    def test_an_empty_api_key_header_does_not_take_the_next_line(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 50002, '198.51.100.9', 80, request(
            'example.com', '/', ['X-Api-Key:', 'Accept: */*'], method='GET', body=b''),
            server=80))
        self.assertEqual(list(f.credentials_found), [])


def who_is(length=None):
    """A global BACnet Who-Is, with its BVLC length right unless told otherwise."""
    body = bytes([0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08])
    length = 4 + len(body) if length is None else length
    return bytes([0x81, 0x0b]) + length.to_bytes(2, 'big') + body


class TestBacnetIsItsFraming(unittest.TestCase):

    def kinds(self, *packets):
        f = forensics()
        for p in packets:
            f.analyze_packet(p)
        return [d['data_type'] for d in f.sensitive_data]

    def test_an_ssdp_search_from_port_47808_is_not_bacnet(self):
        search = (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
                  b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n')
        self.assertEqual(self.kinds(udp('192.168.1.90', 47808, '239.255.255.250', 1900,
                                        search)), [])

    def test_a_global_who_is_is_discovery(self):
        """Two bytes of APDU, and the old reading wanted three: never seen."""
        self.assertEqual(self.kinds(udp('192.168.1.60', 47808, '192.168.1.255', 47808,
                                        who_is())), ['BACnet Discovery'])

    def test_0x81_with_the_wrong_length_is_not_bacnet(self):
        """A DNS query from port 47808 has a random first byte; 0x81 is 1 in 256."""
        self.assertEqual(self.kinds(udp('192.168.1.60', 47808, '192.168.1.1', 53,
                                        who_is(length=300))), [])


def bvlc(npdu, function=0x0a, origin=b''):
    body = origin + npdu
    return bytes([0x81, function]) + (4 + len(body)).to_bytes(2, 'big') + body


# NPDU version 1, expecting a reply; then a confirmed request: type, max
# segments/APDU, invoke ID, service choice, and a few bytes of parameters.
def confirmed(service, invoke, npdu=b'\x01\x04', segmented=False):
    if segmented:
        apdu = bytes([0x08, 0x05, invoke, 0x00, 0x04, service])
    else:
        apdu = bytes([0x00, 0x05, invoke, service])
    return bvlc(npdu + apdu + b'\x0c\x00\x00\x00\x01\x19\x55')


class TestBacnetServices(unittest.TestCase):

    def kinds(self, payload):
        f = forensics()
        f.analyze_packet(udp('192.168.1.10', 47808, '192.168.1.60', 47808, payload))
        return [d['data_type'] for d in f.sensitive_data]

    def test_a_read_numbered_15_is_not_a_write(self):
        """The invoke ID was read as the service: request 15 was a WriteProperty."""
        self.assertEqual(self.kinds(confirmed(service=12, invoke=15)), [])

    def test_a_read_numbered_20_is_not_a_reset(self):
        self.assertEqual(self.kinds(confirmed(service=12, invoke=20)), [])

    def test_a_write_property_is_a_write(self):
        self.assertEqual(self.kinds(confirmed(service=15, invoke=1)), ['BACnet WRITE'])

    def test_reinitialize_device_is_a_reset(self):
        self.assertEqual(self.kinds(confirmed(service=20, invoke=7)), ['BACnet RESET'])

    def test_a_segmented_write_skips_its_sequence_and_window(self):
        self.assertEqual(self.kinds(confirmed(service=16, invoke=3, segmented=True)),
                         ['BACnet WRITE'])

    def test_a_routed_write_skips_the_source_address(self):
        # Control 0x0c: source network present, expecting a reply. SNET 5, a
        # 6-byte source address.
        npdu = b'\x01\x0c\x00\x05\x06' + bytes([192, 168, 5, 20, 0xba, 0xc0])
        self.assertEqual(self.kinds(confirmed(service=15, invoke=2, npdu=npdu)),
                         ['BACnet WRITE'])

    def test_a_forwarded_who_is_skips_the_origin(self):
        npdu = b'\x01\x20\xff\xff\x00\xff' + b'\x10\x08'
        payload = bvlc(npdu, function=0x04, origin=bytes([192, 168, 5, 20, 0xba, 0xc0]))
        self.assertEqual(self.kinds(payload), ['BACnet Discovery'])

    def test_a_network_layer_message_has_no_service(self):
        # Who-Is-Router-To-Network: control 0x80, message type 0x00.
        self.assertEqual(self.kinds(bvlc(b'\x01\x80\x00')), [])


class TestOneCredentialAlertADay(unittest.TestCase):

    def cred(self, value='Bearer ********', dst=HA):
        return {'protocol': 'HTTP Auth Token', 'credential_type': 'token',
                'value': value, 'source_ip': PC, 'destination_ip': dst, 'port': 8123,
                'risk': 'CRITICAL', 'extra': {}}

    def test_a_token_sent_on_every_request_alerts_once_a_day(self):
        alerts = _Alerts(forensics())
        alerts.app._credentials_alerted = {}
        seen = alerts.app._credential_alerted_today
        self.assertFalse(seen(self.cred(), now=T0))
        self.assertTrue(seen(self.cred(), now=T0 + 60))
        self.assertFalse(seen(self.cred('Bearer eyJ*****'), now=T0 + 120))
        self.assertFalse(seen(self.cred(dst='192.168.1.98'), now=T0 + 180))
        self.assertFalse(seen(self.cred(), now=T0 + DAY + 1))

    def test_the_app_raises_one_alert_for_repeats(self):
        f = forensics()
        alerts = _Alerts(f)
        alerts.app._credentials_alerted = {}
        for i in range(3):
            f.analyze_packet(tcp(PC, 39453 + i, HA, 8123, request(
                'homeassistant.local:8123', '/api/states/sensor.pc',
                [f'Authorization: {FAKE_TOKEN}']), server=8123, ts=T0 + i * 30))
        alerts.app._check_forensics_alerts()
        self.assertEqual([a.rule_id for a in alerts.raised], ['FORENSICS-CREDENTIAL'])


if __name__ == '__main__':
    unittest.main()
