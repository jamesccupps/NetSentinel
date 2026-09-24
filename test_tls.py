"""
TLS ClientHello inspection.
============================
Fixtures are real ClientHello bytes built with Scapy's TLS layer, not hand-rolled
blobs, so the parser is tested against something a stack actually emits.

The point of this feature: before it, detection on HTTPS had nothing to work with
but an IP address. The `TestSniReachesDetection` cases are the ones that matter —
they prove the recovered name actually flows into the rules.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Isolated HOME + real Scapy where available. Must precede any src import.
import _test_support  # noqa: E402,F401
from _test_support import SCAPY_REAL  # noqa: E402

SCAPY_TLS = False
if SCAPY_REAL:
    try:
        from scapy.all import Ether, IP, TCP, UDP, Raw
        from scapy.layers.tls.record import TLS
        from scapy.layers.tls.handshake import TLSClientHello
        from scapy.layers.tls.extensions import (
            TLS_Ext_ServerName, ServerName, TLS_Ext_SupportedGroups,
            TLS_Ext_SupportedPointFormat, TLS_Ext_SignatureAlgorithms,
            TLS_Ext_ALPN, ProtocolName, TLS_Ext_SupportedVersion_CH,
        )
        SCAPY_TLS = True
    except Exception:  # pragma: no cover - scapy built without the TLS layer
        SCAPY_TLS = False

from src.tls_inspect import (  # noqa: E402
    parse_client_hello, looks_like_tls_handshake, looks_like_quic, is_grease,
)


def build_client_hello(sni=b'www.example.com', ciphers=None, alpn=True, tls13=True):
    """Real ClientHello record bytes."""
    exts = []
    if sni:
        exts.append(TLS_Ext_ServerName(servernames=[ServerName(servername=sni)]))
    exts.append(TLS_Ext_SupportedGroups(groups=['x25519', 'secp256r1', 'secp384r1']))
    exts.append(TLS_Ext_SupportedPointFormat(ecpl=['uncompressed']))
    exts.append(TLS_Ext_SignatureAlgorithms(sig_algs=['sha256+rsaepss', 'sha256+rsa']))
    if alpn:
        exts.append(TLS_Ext_ALPN(protocols=[ProtocolName(protocol=b'h2'),
                                            ProtocolName(protocol=b'http/1.1')]))
    if tls13:
        exts.append(TLS_Ext_SupportedVersion_CH(versions=['TLS 1.3', 'TLS 1.2']))
    ch = TLSClientHello(ciphers=ciphers or [0x1301, 0x1302, 0xc02b, 0xc02f], ext=exts)
    return bytes(TLS(msg=[ch]))


@unittest.skipUnless(SCAPY_TLS, "scapy TLS layer unavailable")
class TestClientHelloParsing(unittest.TestCase):

    def test_sni_is_recovered(self):
        r = parse_client_hello(build_client_hello(b'login.microsoftonline.com'))
        self.assertEqual(r['sni'], 'login.microsoftonline.com')

    def test_tls13_version_comes_from_the_extension(self):
        """TLS 1.3 pins legacy_version at 1.2 and puts the real one in an extension."""
        self.assertEqual(parse_client_hello(build_client_hello())['version'], 'TLS 1.3')
        self.assertEqual(
            parse_client_hello(build_client_hello(tls13=False))['version'], 'TLS 1.2')

    def test_alpn_is_extracted(self):
        self.assertEqual(parse_client_hello(build_client_hello())['alpn'],
                         ['h2', 'http/1.1'])

    def test_ja3_is_order_sensitive(self):
        a = parse_client_hello(build_client_hello(ciphers=[0x1301, 0x1302, 0xc02b]))
        b = parse_client_hello(build_client_hello(ciphers=[0xc02b, 0x1302, 0x1301]))
        self.assertNotEqual(a['ja3'], b['ja3'])

    def test_ja4_survives_reordering(self):
        """
        This is why JA4 exists: Chrome deliberately shuffles its extension order, so
        a JA3 hash changes on every connection while JA4 stays put.
        """
        a = parse_client_hello(build_client_hello(ciphers=[0x1301, 0x1302, 0xc02b]))
        b = parse_client_hello(build_client_hello(ciphers=[0xc02b, 0x1302, 0x1301]))
        self.assertEqual(a['ja4'], b['ja4'])

    def test_different_client_stacks_differ(self):
        a = parse_client_hello(build_client_hello(ciphers=[0x1301, 0x1302, 0xc02b, 0xc02f]))
        b = parse_client_hello(build_client_hello(ciphers=[0x002f, 0x0035]))
        self.assertNotEqual(a['ja4'], b['ja4'])
        self.assertNotEqual(a['ja3'], b['ja3'])

    def test_ja4_marks_whether_sni_was_present(self):
        with_sni = parse_client_hello(build_client_hello(b'example.com'))
        without = parse_client_hello(build_client_hello(sni=None))
        self.assertEqual(with_sni['ja4'][3], 'd')   # to a domain
        self.assertEqual(without['ja4'][3], 'i')    # straight to an IP
        self.assertIsNone(without['sni'])

    def test_ja4_shape(self):
        ja4 = parse_client_hello(build_client_hello())['ja4']
        parts = ja4.split('_')
        self.assertEqual(len(parts), 3)
        self.assertTrue(parts[0].startswith('t13d'))
        self.assertEqual(len(parts[1]), 12)
        self.assertEqual(len(parts[2]), 12)


class TestGrease(unittest.TestCase):
    """GREASE values are random per connection; including them breaks fingerprinting."""

    def test_grease_values_recognised(self):
        for v in (0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0xdada, 0xfafa):
            self.assertTrue(is_grease(v), hex(v))

    def test_real_values_are_not_grease(self):
        for v in (0x1301, 0x1302, 0xc02f, 0x0000, 0x000a, 0x0a0b, 0x0b0a, 0xffff):
            self.assertFalse(is_grease(v), hex(v))


class TestHostileInput(unittest.TestCase):
    """Every byte here is attacker-controlled. Nothing may raise."""

    def test_malformed_input_returns_none(self):
        cases = [
            b'', b'\x16', b'\x16\x03', b'\x16\x03\x01', b'\x16\x03\x01\x00',
            b'\x16\x03\x01\xff\xff\x01',
            b'\x16\x03\x01\x00\x05\x01\x00\x00\xff\xff',      # length beyond buffer
            b'\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00',      # ServerHello, not Client
            b'\x17\x03\x03\x00\x10' + b'A' * 16,              # application data
            b'GET / HTTP/1.1\r\n\r\n',
            b'\x00' * 200,
            b'\xff' * 200,
        ]
        for payload in cases:
            with self.subTest(payload=payload[:12]):
                self.assertIsNone(parse_client_hello(payload))

    def test_random_bytes_never_raise(self):
        for _ in range(300):
            parse_client_hello(os.urandom(64))
            parse_client_hello(b'\x16\x03\x01' + os.urandom(200))

    @unittest.skipUnless(SCAPY_TLS, "scapy TLS layer unavailable")
    def test_truncation_at_every_offset_is_safe(self):
        full = build_client_hello()
        for cut in range(len(full)):
            parse_client_hello(full[:cut])   # must not raise

    @unittest.skipUnless(SCAPY_TLS, "scapy TLS layer unavailable")
    def test_trailing_garbage_is_ignored(self):
        r = parse_client_hello(build_client_hello() + os.urandom(100))
        self.assertEqual(r['sni'], 'www.example.com')

    def test_non_hostname_sni_is_rejected(self):
        """A crafted SNI must not carry control characters into alerts or logs."""
        if not SCAPY_TLS:
            self.skipTest('scapy TLS layer unavailable')
        for evil in (b'evil.com\r\nX-Injected: 1', b'\x00\x01\x02', b'a' * 300):
            with self.subTest(sni=evil[:20]):
                r = parse_client_hello(build_client_hello(evil))
                if r is not None:
                    self.assertIsNone(r['sni'])

    def test_prefilter_is_cheap_and_correct(self):
        self.assertFalse(looks_like_tls_handshake(b''))
        self.assertFalse(looks_like_tls_handshake(b'GET / HTTP/1.1'))
        self.assertFalse(looks_like_tls_handshake(b'\x17\x03\x03\x00\x10\x01'))
        self.assertTrue(looks_like_tls_handshake(b'\x16\x03\x01\x00\x50\x01'))


class TestQuicDetection(unittest.TestCase):

    def test_quic_initial_recognised(self):
        self.assertTrue(looks_like_quic(b'\xc0\x00\x00\x00\x01' + b'\x00' * 20))

    def test_short_header_and_noise_rejected(self):
        self.assertFalse(looks_like_quic(b'\x40\x00\x00\x00\x01'))   # short header
        self.assertFalse(looks_like_quic(b'\x01\x02'))
        self.assertFalse(looks_like_quic(b''))


@unittest.skipUnless(SCAPY_TLS, "scapy TLS layer unavailable")
class TestSniReachesDetection(unittest.TestCase):
    """
    The parser is only worth having if the recovered name reaches the rules. Before
    this feature the domain-based rules could not fire on HTTPS at all.
    """

    def setUp(self):
        from src.capture import CaptureEngine
        from src.config import Config
        self.cfg = Config().load()
        self.cfg.set('threat_intel', 'auto_update', False)
        self.cfg.set('ids', 'blocked_ja4', [])
        self.capture = CaptureEngine(self.cfg)

    def _frame(self, host, dst='93.184.216.34'):
        ch = TLSClientHello(ciphers=[0x1301, 0xc02f], ext=[
            TLS_Ext_ServerName(servernames=[ServerName(servername=host.encode())]),
            TLS_Ext_SupportedVersion_CH(versions=['TLS 1.3']),
        ])
        return (Ether() / IP(src='192.168.1.50', dst=dst) /
                TCP(sport=51000, dport=443, flags='PA') /
                Raw(load=bytes(TLS(msg=[ch]))))

    def _info(self, host, dst='93.184.216.34'):
        return self.capture._extract_packet_info(self._frame(host, dst))

    def test_capture_populates_the_tls_fields(self):
        info = self._info('login.microsoftonline.com')
        self.assertEqual(info.tls_sni, 'login.microsoftonline.com')
        self.assertEqual(info.tls_version, 'TLS 1.3')
        self.assertTrue(info.tls_ja4)
        self.assertTrue(info.tls_ja3)
        self.assertEqual(info.domain, 'login.microsoftonline.com')

    def test_domain_falls_back_to_dns_query(self):
        from src.capture import PacketInfo
        p = PacketInfo()
        p.dns_query = 'example.com'
        self.assertEqual(p.domain, 'example.com')
        p.tls_sni = 'sni.example.net'
        self.assertEqual(p.domain, 'sni.example.net', "SNI must win over DNS")

    def test_high_abuse_tld_over_https_now_alerts(self):
        from src.ids_engine import IDSEngine
        alerts = []
        ids = IDSEngine(self.cfg, alert_callback=alerts.append)
        ids.inspect_packet(self._info('c2panel.xyz'))
        self.assertIn('DNS-BAD-TLD', [a.rule_id for a in alerts])

    def test_ip_to_domain_mapping_without_any_dns(self):
        """This is what survives DNS-over-HTTPS."""
        from src.ids_engine import IDSEngine
        ids = IDSEngine(self.cfg)
        ids.inspect_packet(self._info('cdn.example.org', dst='203.0.113.40'))
        self.assertIn('cdn.example.org', ids._get_domains_for_ip('203.0.113.40'))

    def test_blocked_fingerprint_alerts_on_encrypted_traffic(self):
        from src.ids_engine import IDSEngine
        info = self._info('ordinary-site.com')
        self.cfg.set('ids', 'blocked_ja4', [info.tls_ja4])
        alerts = []
        ids = IDSEngine(self.cfg, alert_callback=alerts.append)
        ids.inspect_packet(info)
        hits = [a for a in alerts if a.rule_id == 'TLS-FINGERPRINT']
        self.assertTrue(hits)
        self.assertEqual(hits[0].evidence['fingerprint'], info.tls_ja4)

    def test_blacklisted_domain_matches_on_sni(self):
        from src.ids_engine import IDSEngine
        self.cfg.set('blacklists', 'domains', ['evil-corp.net'])
        alerts = []
        ids = IDSEngine(self.cfg, alert_callback=alerts.append)
        ids.inspect_packet(self._info('cdn.evil-corp.net'))
        self.assertIn('BL-DOMAIN', [a.rule_id for a in alerts])
        self.cfg.set('blacklists', 'domains', [])

    def test_quic_is_marked_encrypted(self):
        frame = (Ether() / IP(src='192.168.1.50', dst='142.250.1.1') /
                 UDP(sport=51000, dport=443) /
                 Raw(load=b'\xc0\x00\x00\x00\x01' + b'\x00' * 40))
        info = self.capture._extract_packet_info(frame)
        self.assertTrue(info.is_encrypted)
        self.assertEqual(info.tls_version, 'QUIC')

    def test_non_tls_traffic_leaves_the_fields_empty(self):
        frame = (Ether() / IP(src='192.168.1.50', dst='93.184.216.34') /
                 TCP(sport=51000, dport=443, flags='PA') /
                 Raw(load=b'\x17\x03\x03\x00\x20' + b'X' * 32))
        info = self.capture._extract_packet_info(frame)
        self.assertEqual(info.tls_sni, '')
        self.assertEqual(info.tls_ja4, '')


class TestBpfFilterKeepsHandshake(unittest.TestCase):
    """
    The default filter used to match 'ACK set, SYN clear', which also catches
    PSH+ACK data segments — so it discarded the ClientHello this whole module
    depends on.
    """

    def test_default_filter_compiles(self):
        import shutil
        import subprocess
        from src.config import DEFAULT_CONFIG
        if not shutil.which('tcpdump'):
            self.skipTest('tcpdump unavailable')
        bpf = DEFAULT_CONFIG['capture']['bpf_filter']
        self.assertEqual(
            subprocess.run(['tcpdump', '-d', bpf], capture_output=True).returncode, 0,
            f"default bpf_filter does not compile: {bpf}")

    def test_default_filter_does_not_drop_data_packets(self):
        from src.config import DEFAULT_CONFIG
        bpf = DEFAULT_CONFIG['capture']['bpf_filter']
        # The inner expression must require an empty payload, so data survives.
        self.assertIn('tcp-push', bpf)
        self.assertIn('ip[2:2]', bpf)


if __name__ == '__main__':
    unittest.main(verbosity=2)
