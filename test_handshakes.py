"""
Handshakes that span packets, and what capture reads from the payload.
=======================================================================
H4: a post-quantum ClientHello is 1.7-1.9 KB, two TCP segments, and only the first
was parsed, so current browsers had no SNI, JA3 or JA4. Ports 8443 and 5061 were
never parsed at all. QUIC hellos were not read. These build real frames and run
them through CaptureEngine._extract_packet_info, the parser live capture and PCAP
analysis now share.
"""

import os
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import SCAPY_REAL, reset_config  # noqa: E402

SCAPY_TLS = False
if SCAPY_REAL:
    try:
        from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, ARP
        from scapy.layers.inet6 import ICMPv6ND_RA
        from scapy.layers.tls.record import TLS
        from scapy.layers.tls.handshake import TLSClientHello
        from scapy.layers.tls.extensions import (
            TLS_Ext_ServerName, ServerName, TLS_Ext_SupportedVersion_CH, TLS_Ext_Padding,
        )
        SCAPY_TLS = True
    except Exception:  # pragma: no cover
        SCAPY_TLS = False


def big_hello(host=b'pq.example.com', pad=1500):
    """A ClientHello the size of a post-quantum one (key share padding)."""
    ch = TLSClientHello(ciphers=[0x1301, 0x1302, 0xc02f], ext=[
        TLS_Ext_ServerName(servernames=[ServerName(servername=host)]),
        TLS_Ext_SupportedVersion_CH(versions=['TLS 1.3']),
        TLS_Ext_Padding(padding=b'\x00' * pad),
    ])
    return bytes(TLS(msg=[ch]))


def tcp_frame(payload, sport=50000, dport=443, seq=1000, src='192.168.1.5',
              dst='93.184.216.34'):
    return (Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src=src, dst=dst) /
            TCP(sport=sport, dport=dport, seq=seq, flags='PA') / Raw(load=payload))


# ─── QUIC Initial construction (the inverse of what capture does) ─────────────

def _varint2(n):
    return (0x4000 | n).to_bytes(2, 'big')


def crypto_frame(offset, data):
    return b'\x06' + _varint2(offset) + _varint2(len(data)) + data


def quic_initial(dcid, frames, pn=0):
    """A client Initial packet carrying `frames`, protected as RFC 9001 says."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from src.tls_inspect import quic_initial_keys, QUIC_V1
    key, iv, hp = quic_initial_keys(dcid, QUIC_V1)
    pn_len = 2
    payload = frames + b'\x00' * max(0, 1100 - len(frames))      # PADDING frames
    length = pn_len + len(payload) + 16
    first = 0xc0 | (pn_len - 1)
    header = (bytes([first]) + QUIC_V1.to_bytes(4, 'big') + bytes([len(dcid)]) + dcid +
              b'\x00' + b'\x00' + _varint2(length) + pn.to_bytes(pn_len, 'big'))
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, 'big')))
    packet = header + AESGCM(key).encrypt(nonce, payload, header)
    pn_offset = len(header) - pn_len
    sample = packet[pn_offset + 4:pn_offset + 20]
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    protected_pn = bytes(b ^ m for b, m in zip(packet[pn_offset:pn_offset + pn_len], mask[1:]))
    return bytes([first ^ (mask[0] & 0x0f)]) + packet[1:pn_offset] + protected_pn + \
        packet[pn_offset + pn_len:]


def udp_frame(payload, dport=443):
    return (Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src='192.168.1.5', dst='142.250.1.1') /
            UDP(sport=51000, dport=dport) / Raw(load=payload))


class TestQuicKeys(unittest.TestCase):
    """RFC 9001 Appendix A: keys for DCID 0x8394c8f03e515708."""

    def test_rfc9001_client_keys(self):
        from src.tls_inspect import quic_initial_keys
        key, iv, hp = quic_initial_keys(bytes.fromhex('8394c8f03e515708'))
        self.assertEqual(key.hex(), '1f369613dd76d5467730efcbe3b1a22d')
        self.assertEqual(iv.hex(), 'fa044b2f42a3fd3b46fb255c')
        self.assertEqual(hp.hex(), '9f50449e04a0e810283a1e9933adedd2')

    def test_rfc9001_server_keys(self):
        from src.tls_inspect import quic_initial_keys
        key, iv, hp = quic_initial_keys(bytes.fromhex('8394c8f03e515708'), side='server')
        self.assertEqual(key.hex(), 'cf3a5331653c364c88f0f379b6067e37')
        self.assertEqual(hp.hex(), 'c206b8d9b9f0f37644430b490eeaa314')

    def test_garbage_is_not_decrypted(self):
        from src.tls_inspect import decrypt_quic_initial
        self.assertIsNone(decrypt_quic_initial(b'\xc0\x00\x00\x00\x01' + os.urandom(1200)))
        self.assertIsNone(decrypt_quic_initial(b''))
        for _ in range(50):
            decrypt_quic_initial(os.urandom(300))          # must not raise


@unittest.skipUnless(SCAPY_TLS, "scapy TLS layer unavailable")
class TestHandshakesAcrossPackets(unittest.TestCase):

    def setUp(self):
        from src.capture import CaptureEngine
        self.capture = CaptureEngine(reset_config())

    def info(self, frame):
        return self.capture._extract_packet_info(frame)

    def test_hello_split_across_two_segments_is_read(self):
        record = big_hello()
        self.assertGreater(len(record), 1460, "fixture must need two segments")
        first = self.info(tcp_frame(record[:1000], seq=1000))
        second = self.info(tcp_frame(record[1000:], seq=2000))
        self.assertEqual(first.tls_sni, '')
        self.assertEqual(second.tls_sni, 'pq.example.com')
        self.assertTrue(second.tls_ja4.startswith('t13d'))
        self.assertTrue(second.tls_ja3)

    def test_a_retransmitted_segment_is_not_appended_twice(self):
        record = big_hello()
        self.info(tcp_frame(record[:1000], seq=1000))
        self.info(tcp_frame(record[:1000], seq=1000))       # retransmission
        done = self.info(tcp_frame(record[1000:], seq=2000))
        self.assertEqual(done.tls_sni, 'pq.example.com')

    def test_a_gap_abandons_the_flow_without_garbage(self):
        record = big_hello()
        self.info(tcp_frame(record[:1000], seq=1000))
        hole = self.info(tcp_frame(record[1100:], seq=2100))
        self.assertEqual(hole.tls_sni, '')

    def test_reassembly_is_bounded(self):
        from src.tls_inspect import ClientHelloReassembler
        r = ClientHelloReassembler(max_flows=50)
        record = big_hello()
        for i in range(500):
            r.feed(('10.0.0.1', 40000 + i, '1.1.1.1', 443), record[:600], seq=1, now=i)
        self.assertLessEqual(len(r), 50)

    def test_port_8443_and_5061_handshakes_are_parsed(self):
        """Both are credential-scan ports too, and that branch was an `elif`."""
        hello = bytes(TLS(msg=[TLSClientHello(ciphers=[0x1301], ext=[
            TLS_Ext_ServerName(servernames=[ServerName(servername=b'unifi.example')])])]))
        for port in (8443, 5061):
            with self.subTest(port=port):
                info = self.info(tcp_frame(hello, dport=port))
                self.assertEqual(info.tls_sni, 'unifi.example')

    def test_quic_hello_split_over_two_initials_gives_sni(self):
        """Chrome splits its hello across two Initials and shuffles the frames."""
        message = big_hello(b'quic.example.org')[5:]        # handshake message only
        half = len(message) // 2
        dcid = os.urandom(8)
        late = quic_initial(dcid, crypto_frame(half, message[half:]) + b'\x01', pn=1)
        early = quic_initial(dcid, b'\x01' + crypto_frame(0, message[:half]), pn=0)
        first = self.info(udp_frame(late))
        second = self.info(udp_frame(early))
        self.assertEqual(first.tls_sni, '')
        self.assertTrue(first.is_encrypted)
        self.assertEqual(second.tls_sni, 'quic.example.org')
        self.assertTrue(second.tls_ja4.startswith('q13'), second.tls_ja4)
        self.assertEqual(second.tls_version, 'QUIC')


@unittest.skipUnless(SCAPY_REAL, "real scapy unavailable")
class TestPayloadFields(unittest.TestCase):

    def setUp(self):
        from src.capture import CaptureEngine
        self.capture = CaptureEngine(reset_config())

    def info(self, frame, **kw):
        return self.capture._extract_packet_info(frame, **kw)

    def test_http_request_line_is_read(self):
        frame = tcp_frame(b'GET /bins/x86?a=1 HTTP/1.1\r\nHost: Mal.EXAMPLE:8080\r\n\r\n',
                          dport=8080)
        info = self.info(frame)
        self.assertEqual((info.http_method, info.http_host, info.http_path),
                         ('GET', 'mal.example:8080', '/bins/x86?a=1'))

    def test_http_fields_are_printable(self):
        info = self.info(tcp_frame(b'GET /a\x01b HTTP/1.1\r\nHost: x\x00y.example\r\n\r\n',
                                   dport=80))
        self.assertTrue(all(32 < ord(c) < 127 for c in info.http_path + info.http_host))

    def test_arp_sender_comes_from_the_arp_payload(self):
        frame = Ether(src='aa:aa:aa:aa:aa:aa', dst='02:00:00:00:00:05') / ARP(
            op=2, hwsrc='02:bb:bb:bb:bb:bb', psrc='192.168.1.1', pdst='192.168.1.5')
        info = self.info(frame)
        self.assertEqual(info.arp_op, 2)
        self.assertEqual(info.arp_hwsrc, '02:bb:bb:bb:bb:bb')
        self.assertEqual(info.src_mac, 'aa:aa:aa:aa:aa:aa')

    def test_icmpv6_router_advertisement_is_typed(self):
        info = self.info(Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IPv6(src='fe80::1', dst='ff02::1') / ICMPv6ND_RA())
        self.assertEqual((info.protocol, info.icmp_type), ('ICMPv6', 134))

    def test_offline_mode_uses_packet_time_and_no_process(self):
        frame = tcp_frame(b'x' * 10)
        frame.time = 1_600_000_000.5
        info = self.info(frame, offline=True)
        self.assertEqual(info.timestamp, 1_600_000_000.5)
        self.assertEqual(info.process_name, '')

    def test_dns_query_type_is_recorded(self):
        from scapy.all import DNS, DNSQR
        frame = (Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src='192.168.1.5', dst='192.168.1.1') /
                 UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname='x.example', qtype='TXT')))
        info = self.capture._extract_packet_info(Ether(bytes(frame)))
        self.assertEqual(info.dns_qtype, 16)

    def test_stratum_is_recognised(self):
        info = self.info(tcp_frame(
            b'{"id":1,"method":"mining.subscribe","params":["cpuminer/2.5"]}\n', dport=3333))
        self.assertEqual(info.app_protocol, 'stratum')


# ─── Certificates ─────────────────────────────────────────────────────────────

def make_cert(self_signed=True, expired=True):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'c2.example')])
    issuer = subject if self_signed else x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, 'Some CA')])
    now = datetime.now(timezone.utc)
    start, end = ((now - timedelta(days=400), now - timedelta(days=30)) if expired
                  else (now - timedelta(days=1), now + timedelta(days=90)))
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(start).not_valid_after(end).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def _hs(msg_type, body):
    return bytes([msg_type]) + len(body).to_bytes(3, 'big') + body


def server_flight(der, tls13=False):
    """ServerHello + Certificate + ServerHelloDone in one TLS record."""
    ext = b''
    if tls13:
        ext = b'\x00\x2b\x00\x02\x03\x04'
    hello = (b'\x03\x03' + os.urandom(32) + b'\x00' + b'\xc0\x2f' + b'\x00' +
             len(ext).to_bytes(2, 'big') + ext)
    entry = len(der).to_bytes(3, 'big') + der
    certificate = len(entry).to_bytes(3, 'big') + entry
    body = _hs(2, hello) + _hs(11, certificate) + _hs(14, b'')
    return b'\x16\x03\x03' + len(body).to_bytes(2, 'big') + body


@unittest.skipUnless(SCAPY_REAL, "real scapy unavailable")
class TestServerCertificates(unittest.TestCase):

    def setUp(self):
        from src.capture import CaptureEngine
        self.capture = CaptureEngine(reset_config())

    def _segments(self, flight, size=600):
        infos = []
        for i in range(0, len(flight), size):
            frame = tcp_frame(flight[i:i + size], sport=443, dport=50000, seq=5000 + i,
                              src='203.0.113.9', dst='192.168.1.5')
            infos.append(self.capture._extract_packet_info(frame))
        return infos

    def test_certificate_spanning_segments_is_reassembled(self):
        der = make_cert()
        infos = self._segments(server_flight(der))
        got = [i._tls_certs for i in infos if i._tls_certs]
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0][0], der)

    def test_tls13_server_hello_yields_no_certificate(self):
        infos = self._segments(server_flight(make_cert(), tls13=True))
        self.assertFalse([i for i in infos if i._tls_certs])

    def test_inspection_reports_self_signed_and_expired(self):
        from src.tls_certs import inspect_certificate
        info = inspect_certificate(make_cert(self_signed=True, expired=True))
        self.assertTrue(info['self_signed'])
        self.assertTrue(info['expired'])
        fine = inspect_certificate(make_cert(self_signed=False, expired=False))
        self.assertFalse(fine['self_signed'] or fine['expired'])
        self.assertIsNone(inspect_certificate(b'\x30\x03garbage'))

    def test_hostile_flights_never_raise(self):
        from src.tls_certs import ServerHandshakeReassembler
        r = ServerHandshakeReassembler()
        for i in range(200):
            r.feed(('a', i, 'b', 1), b'\x16\x03\x03\x00\x30\x02' + os.urandom(60), now=time.time())


if __name__ == '__main__':
    unittest.main()
