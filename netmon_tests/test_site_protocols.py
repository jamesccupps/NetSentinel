"""
Identifying the systems on a site network.
===========================================
The parking-kiosk tests are the point of this file. Those broadcasts carry
cardholder and credential data, and the parser must read the command name and
nothing else. Every fixture here is synthetic with invented values, because a
real one is exactly the file that must not be in a repository — so the tests
stuff the fixtures with obviously-fake card numbers, PINs and credential
identifiers and then check none of it comes out.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.profile import SiteProfile  # noqa: E402
from netmon.protocols.site import (SERVICES, Service, identify,  # noqa: E402
                                   parse_eset_user_agent, parse_kiosk_command,
                                   parse_otis, parse_p2)


def kiosk_xml(command='RequestStatus', message_type='CoreCommand',
              encoding='utf-16-le', bom=False):
    """
    A synthetic kiosk broadcast, stuffed with things that must not come out.

    Invented values throughout — 4111... is the standard test card number and
    the rest is nonsense. A real capture of this traffic stays outside the
    repository.
    """
    document = (
        f'<?xml version="1.0" encoding="utf-16"?>'
        f'<BaseMessage xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        f'xsi:type="{message_type}">'
        f'<Command>{command}</Command>'
        f'<CardNumber>4111111111111111</CardNumber>'
        f'<CardHolder>A. Person</CardHolder>'
        f'<Pin>9876</Pin>'
        f'<RfidCredential>0123456789ABCDEF</RfidCredential>'
        f'<Track2>4111111111111111=25121011000012300000</Track2>'
        f'<SessionToken>eyJhbGciOiJIUzI1NiJ9.payload.signature</SessionToken>'
        f'</BaseMessage>')
    data = document.encode(encoding)
    return (b'\xff\xfe' + data) if bom and encoding == 'utf-16-le' else data


#: Everything in the fixture that must never appear in a parsed result.
FORBIDDEN = ('4111111111111111', 'A. Person', '9876', '0123456789ABCDEF',
             '25121011000012300000', 'eyJhbGciOiJIUzI1NiJ9')


# ─── Parking kiosks ──────────────────────────────────────────────────────────

class TestKioskIsMetadataOnly(unittest.TestCase):

    def test_the_command_is_read(self):
        result = parse_kiosk_command(kiosk_xml('RequestStatus'))
        self.assertEqual(result['command'], 'RequestStatus')

    def test_the_message_type_is_read(self):
        result = parse_kiosk_command(kiosk_xml(message_type='CoreCommand'))
        self.assertEqual(result['message_type'], 'CoreCommand')

    def test_nothing_else_comes_out(self):
        """
        The restriction is structural: this matches two named elements and
        never walks the document, so there is no path by which another field
        could be read.
        """
        result = parse_kiosk_command(kiosk_xml())
        blob = str(result)
        for secret in FORBIDDEN:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, blob)

    def test_only_two_keys_are_ever_returned(self):
        result = parse_kiosk_command(kiosk_xml())
        self.assertLessEqual(set(result), {'command', 'message_type'})

    def test_it_works_on_utf16_with_and_without_a_bom(self):
        for bom in (True, False):
            with self.subTest(bom=bom):
                result = parse_kiosk_command(kiosk_xml(bom=bom))
                self.assertEqual(result['command'], 'RequestStatus')

    def test_it_works_on_utf8_too(self):
        """Some firmware versions send UTF-8; the parser should not care."""
        result = parse_kiosk_command(kiosk_xml(encoding='utf-8'))
        self.assertEqual(result['command'], 'RequestStatus')

    def test_a_truncated_message_yields_what_it_can(self):
        """Snap length cuts these mid-document."""
        full = kiosk_xml()
        for cut in range(0, len(full), 7):
            with self.subTest(cut=cut):
                result = parse_kiosk_command(full[:cut])
                if result:
                    self.assertLessEqual(set(result), {'command', 'message_type'})

    def test_a_command_name_cannot_be_arbitrarily_long(self):
        """A crafted packet must not put a megabyte into an alert."""
        payload = b'<Command>' + b'A' * 100_000 + b'</Command>'
        result = parse_kiosk_command(payload)
        self.assertIsNone(result)

    def test_a_command_name_cannot_smuggle_control_characters(self):
        payload = b'<Command>Status\r\nInjected: yes</Command>'
        result = parse_kiosk_command(payload)
        self.assertIsNone(result)

    def test_a_non_kiosk_payload_returns_nothing(self):
        for payload in (b'', b'GET / HTTP/1.1', bytes(200), b'<other>x</other>'):
            with self.subTest(payload=payload[:20]):
                self.assertIsNone(parse_kiosk_command(payload))

    def test_random_bytes_never_raise(self):
        import random
        rng = random.Random(20260929)
        for _ in range(400):
            parse_kiosk_command(bytes(rng.randrange(256)
                                      for _ in range(rng.randrange(1, 300))))


# ─── Siemens P2 ──────────────────────────────────────────────────────────────

class TestSiemensP2(unittest.TestCase):

    def test_the_roster_is_read(self):
        payload = b'\x00\x01OCCDCC-SVR|5034\x00OCC-SIEMENS-BMS|5033'
        result = parse_p2(payload, dst_port=5034)
        self.assertIn('OCCDCC-SVR|5034', result['p2_nodes'])
        self.assertIn('OCC-SIEMENS-BMS|5033', result['p2_nodes'])

    def test_the_direction_is_recorded(self):
        """5034 runs panels to the supervisory server; 5033 runs both ways."""
        self.assertEqual(parse_p2(b'', dst_port=5034)['p2_direction'],
                         'panel-to-server')
        self.assertEqual(parse_p2(b'', dst_port=5033)['p2_direction'],
                         'bidirectional')

    def test_other_ports_are_not_p2(self):
        self.assertIsNone(parse_p2(b'NAME|5034', dst_port=443))

    def test_a_session_with_no_roster_still_reports_the_direction(self):
        result = parse_p2(b'\x00\x00\x00', dst_port=5033)
        self.assertNotIn('p2_nodes', result)

    def test_node_names_are_bounded(self):
        payload = b'A' * 5000 + b'|5034'
        result = parse_p2(payload, dst_port=5034)
        for node in result.get('p2_nodes', []):
            self.assertLessEqual(len(node), 70)

    def test_the_node_list_is_capped(self):
        payload = b' '.join(f'NODE{n}|5033'.encode() for n in range(500))
        result = parse_p2(payload, dst_port=5033)
        self.assertLessEqual(len(result['p2_nodes']), 16)

    def test_an_out_of_range_port_is_dropped(self):
        result = parse_p2(b'NODE|99999', dst_port=5033)
        self.assertNotIn('p2_nodes', result)

    def test_control_characters_cannot_reach_a_node_name(self):
        result = parse_p2(b'NAME\r\nInjected|5033', dst_port=5033)
        for node in result.get('p2_nodes', []):
            self.assertNotIn('\n', node)
            self.assertNotIn('\r', node)


# ─── Otis ────────────────────────────────────────────────────────────────────

class TestOtis(unittest.TestCase):

    def test_a_frame_is_recognised_by_its_magic(self):
        result = parse_otis(b'\xa5\x5a\x11\x00\x04abcd')
        self.assertTrue(result['otis_frame'])
        self.assertEqual(result['otis_type'], '0x11')

    def test_anything_else_is_not_an_otis_frame(self):
        for payload in (b'', b'\xa5', b'\x5a\xa5\x00\x00', b'GET / HTTP/1.1'):
            with self.subTest(payload=payload):
                self.assertIsNone(parse_otis(payload))

    def test_it_does_not_guess_at_the_fields(self):
        """
        The protocol has no public specification. Guessing would produce
        findings nobody could verify, which is worse than none.
        """
        result = parse_otis(b'\xa5\x5a\x11' + bytes(range(50)))
        self.assertEqual(set(result), {'otis_frame', 'otis_type', 'otis_length'})


# ─── ESET ────────────────────────────────────────────────────────────────────

class TestEsetUserAgent(unittest.TestCase):
    """
    The only place on the wire that says which Windows build a machine runs, so
    an out-of-support build becomes visible without touching the endpoint.
    """

    def test_a_build_is_read(self):
        result = parse_eset_user_agent('ESET Update (Windows; OS: 10.0.19044 UBR 3086)')
        self.assertEqual(result['os_build'], 19044)
        self.assertEqual(result['os_ubr'], 3086)

    def test_a_build_without_a_ubr(self):
        result = parse_eset_user_agent('Something OS: 10.0.26200')
        self.assertEqual(result['os_build'], 26200)
        self.assertNotIn('os_ubr', result)

    def test_an_unrelated_user_agent_yields_nothing(self):
        for agent in ('', None, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'):
            with self.subTest(agent=agent):
                self.assertIsNone(parse_eset_user_agent(agent))


# ─── Identification ──────────────────────────────────────────────────────────

class TestIdentify(unittest.TestCase):

    def test_by_port(self):
        for port, protocol, expected in ((7000, 'tcp', 'otis'),
                                         (1072, 'tcp', 'gallagher'),
                                         (22609, 'tcp', 'exacq'),
                                         (31769, 'udp', 'parking-kiosk'),
                                         (5033, 'tcp', 'siemens-p2'),
                                         (47808, 'udp', 'bacnet'),
                                         (51820, 'udp', 'wireguard')):
            with self.subTest(port=port):
                service = identify(dst_port=port, protocol=protocol)
                self.assertEqual(service.name, expected)

    def test_the_protocol_has_to_match(self):
        """UDP 7000 is not an elevator."""
        self.assertIsNone(identify(dst_port=7000, protocol='udp'))

    def test_by_magic_even_on_the_wrong_port(self):
        """A magic number is proof; a port is a guess."""
        service = identify(dst_port=9999, protocol='tcp', payload=b'\xa5\x5a\x00')
        self.assertEqual(service.name, 'otis')

    def test_by_name(self):
        for name, expected in (('relay-9f2.net.anydesk.com', 'anydesk'),
                               ('controlplane.tailscale.com', 'tailscale'),
                               ('update.eset.com', 'eset')):
            with self.subTest(name=name):
                self.assertEqual(identify(name=name).name, expected)

    def test_the_source_port_counts_too(self):
        self.assertEqual(identify(src_port=47808, protocol='udp').name, 'bacnet')

    def test_unknown_traffic_is_not_guessed_at(self):
        self.assertIsNone(identify(dst_port=12345, protocol='tcp'))

    def test_site_services_are_checked_first(self):
        """The site knows its own building better than this list does."""
        mine = Service('my-lighting', 'Lighting', ports=(7000,), protocol='tcp')
        service = identify(dst_port=7000, protocol='tcp', extra_services=[mine])
        self.assertEqual(service.name, 'my-lighting')

    def test_encryption_is_recorded_not_judged(self):
        """
        BACnet has no encryption by design and is not going to grow any. The
        flag decides whether crossing a boundary is interesting or alarming.
        """
        self.assertFalse(identify(dst_port=47808, protocol='udp').encrypted)
        self.assertTrue(identify(dst_port=1072, protocol='tcp').encrypted)

    def test_every_shipped_service_is_well_formed(self):
        for service in SERVICES:
            with self.subTest(service=service.name):
                self.assertTrue(service.description,
                                f'{service.name} has no description')
                self.assertTrue(service.ports or service.names or service.magic,
                                f'{service.name} cannot be identified at all')
                self.assertTrue(service.category, f'{service.name} has no category')

    def test_no_two_services_claim_the_same_port_and_protocol(self):
        seen = {}
        for service in SERVICES:
            for port in service.ports:
                key = (service.protocol, port)
                with self.subTest(port=port, protocol=service.protocol):
                    self.assertNotIn(
                        key, seen,
                        f'{service.name} and {seen.get(key)} both claim {key}')
                seen[key] = service.name


class TestProfileServices(unittest.TestCase):

    def test_a_profile_can_add_services(self):
        profile = SiteProfile({'services': [
            {'name': 'lighting', 'description': 'Lighting panel',
             'ports': [4001], 'protocol': 'tcp', 'category': 'building-automation'}]})
        self.assertEqual(len(profile.services), 1)
        self.assertEqual(identify(dst_port=4001, protocol='tcp',
                                  extra_services=profile.services).name, 'lighting')

    def test_a_malformed_entry_is_skipped_not_fatal(self):
        profile = SiteProfile({'services': [
            {'no_name': 'x'}, 'not a mapping', None,
            {'name': 'good', 'ports': [1234]}]})
        self.assertEqual([s.name for s in profile.services], ['good'])

    def test_no_services_is_fine(self):
        self.assertEqual(SiteProfile({}).services, ())


if __name__ == '__main__':
    unittest.main(verbosity=2)
