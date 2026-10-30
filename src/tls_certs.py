"""
Server certificates, read passively from TLS 1.2 and earlier handshakes.
=========================================================================
Up to TLS 1.2 the server's Certificate message travels in the clear right after
its ServerHello, so a sensor that sees the handshake can read the chain without
touching the session. TLS 1.3 encrypts it, so nothing here applies to 1.3, and
the ServerHello's supported_versions extension says which one a connection is.

What this is for: malware command-and-control very often runs on a self-signed
or long-expired certificate, because nobody it talks to checks. A browser would
refuse; a monitor seeing it is worth a look.

The server flight (ServerHello, Certificate, ServerKeyExchange, ServerHelloDone)
is several kilobytes, so it spans TCP segments and has to be joined per flow.
Every byte is attacker-controlled: lengths are checked, buffers are capped, and
a parse failure returns nothing.
"""

import hashlib
import logging
import struct
from collections import OrderedDict
from datetime import datetime, timezone

logger = logging.getLogger("NetSentinel.TLSCerts")

__all__ = ['ServerHandshakeReassembler', 'inspect_certificate']

TLS_RECORD_CHANGE_CIPHER_SPEC = 0x14
TLS_RECORD_HANDSHAKE = 0x16
HANDSHAKE_SERVER_HELLO = 0x02
HANDSHAKE_CERTIFICATE = 0x0b
HANDSHAKE_SERVER_HELLO_DONE = 0x0e
EXT_SUPPORTED_VERSIONS = 0x002b
TLS13 = 0x0304

# A real server flight is a few KB; chains with several intermediates reach 10-12.
MAX_FLIGHT_BYTES = 64 * 1024
MAX_CERTS = 10


class _Flow:
    __slots__ = ('buf', 'next_seq', 'started')

    def __init__(self, buf, next_seq, started):
        self.buf = buf
        self.next_seq = next_seq
        self.started = started


class ServerHandshakeReassembler:
    """
    Joins a server's handshake flight across TCP segments and returns the DER
    certificates of a TLS <= 1.2 handshake. Flows are capped, as are their bytes,
    and abandoned after a timeout.
    """

    MAX_FLOWS = 512
    TIMEOUT_SEC = 15.0

    def __init__(self, max_flows=None):
        self._flows = OrderedDict()
        self.max_flows = max_flows or self.MAX_FLOWS
        self.tls13_skipped = 0
        self.chains_read = 0

    def __len__(self):
        return len(self._flows)

    def feed(self, key, payload, seq=None, now=0.0):
        """
        One TCP payload sent by a server, for flow `key`. Returns a tuple of DER
        certificates (leaf first) once the Certificate message is whole, else None.
        """
        if not payload:
            return None
        flow = self._flows.get(key)
        if flow is None:
            if not (len(payload) >= 6 and payload[0] == TLS_RECORD_HANDSHAKE
                    and payload[1] == 0x03 and payload[5] == HANDSHAKE_SERVER_HELLO):
                return None
            self._expire(now)
            while len(self._flows) >= self.max_flows:
                self._flows.popitem(last=False)
            flow = self._flows[key] = _Flow(
                bytearray(), None if seq is None else seq, now)

        if seq is not None and flow.next_seq is not None:
            if seq + len(payload) <= flow.next_seq:
                return None
            if seq < flow.next_seq:
                payload = payload[flow.next_seq - seq:]
            elif seq > flow.next_seq:
                del self._flows[key]
                return None
        if flow.next_seq is not None:
            flow.next_seq += len(payload)
        flow.buf += payload
        if len(flow.buf) > MAX_FLIGHT_BYTES:
            del self._flows[key]
            return None

        try:
            status, certs = _scan_flight(flow.buf)
        except (ValueError, IndexError, struct.error) as e:
            logger.debug("Server flight parse failed: %s", e)
            status, certs = 'done', None
        if status == 'more':
            return None
        del self._flows[key]
        if status == 'tls13':
            self.tls13_skipped += 1
            return None
        if certs:
            self.chains_read += 1
        return certs

    def _expire(self, now):
        while self._flows:
            key, flow = next(iter(self._flows.items()))
            if now - flow.started <= self.TIMEOUT_SEC:
                break
            del self._flows[key]


def _scan_flight(buf):
    """
    Walk the handshake messages in `buf`. Returns ('more', None) while waiting,
    ('tls13', None) when the ServerHello negotiated 1.3, ('done', certs) when the
    Certificate message is complete, and ('done', None) when the flight ended
    without one.
    """
    handshake = bytearray()
    pos = 0
    while len(buf) - pos >= 5:
        content_type = buf[pos]
        record_len = (buf[pos + 3] << 8) | buf[pos + 4]
        if buf[pos + 1] != 0x03 or record_len > 18432:
            return 'done', None
        if content_type != TLS_RECORD_HANDSHAKE:
            # ChangeCipherSpec or anything else ends the plaintext flight.
            break
        if len(buf) - pos - 5 < record_len:
            handshake += buf[pos + 5:]
            pos = len(buf)
            break
        handshake += buf[pos + 5:pos + 5 + record_len]
        pos += 5 + record_len

    hpos = 0
    while len(handshake) - hpos >= 4:
        msg_type = handshake[hpos]
        msg_len = (handshake[hpos + 1] << 16) | (handshake[hpos + 2] << 8) | handshake[hpos + 3]
        if msg_len > MAX_FLIGHT_BYTES:
            return 'done', None
        if len(handshake) - hpos - 4 < msg_len:
            return 'more', None
        body = bytes(handshake[hpos + 4:hpos + 4 + msg_len])
        if msg_type == HANDSHAKE_SERVER_HELLO:
            if _server_hello_version(body) == TLS13:
                return 'tls13', None
        elif msg_type == HANDSHAKE_CERTIFICATE:
            return 'done', _certificate_list(body)
        elif msg_type == HANDSHAKE_SERVER_HELLO_DONE:
            return 'done', None
        hpos += 4 + msg_len
    if pos < len(buf) and buf[pos] != TLS_RECORD_HANDSHAKE:
        return 'done', None
    return 'more', None


def _server_hello_version(body):
    """The negotiated version: supported_versions if present, else legacy_version."""
    if len(body) < 38:
        raise ValueError('short ServerHello')
    legacy = struct.unpack('>H', body[0:2])[0]
    pos = 2 + 32
    sid_len = body[pos]
    pos += 1 + sid_len + 2 + 1          # session id, cipher suite, compression
    if pos + 2 > len(body):
        return legacy
    ext_total = struct.unpack('>H', body[pos:pos + 2])[0]
    pos += 2
    end = min(len(body), pos + ext_total)
    while pos + 4 <= end:
        ext_type, ext_len = struct.unpack('>HH', body[pos:pos + 4])
        pos += 4
        if ext_type == EXT_SUPPORTED_VERSIONS and ext_len == 2 and pos + 2 <= end:
            return struct.unpack('>H', body[pos:pos + 2])[0]
        pos += ext_len
    return legacy


def _certificate_list(body):
    """TLS 1.2 Certificate: a 24-bit list length, then 24-bit-length DER entries."""
    if len(body) < 3:
        raise ValueError('short Certificate')
    total = (body[0] << 16) | (body[1] << 8) | body[2]
    pos, end = 3, min(len(body), 3 + total)
    certs = []
    while pos + 3 <= end and len(certs) < MAX_CERTS:
        size = (body[pos] << 16) | (body[pos + 1] << 8) | body[pos + 2]
        pos += 3
        if size == 0 or pos + size > end:
            break
        certs.append(bytes(body[pos:pos + size]))
        pos += size
    return tuple(certs)


def _utc(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def inspect_certificate(der, now=None):
    """
    What matters about one DER certificate, as a plain dict, or None when it
    cannot be parsed (or `cryptography` is missing).

    `self_signed` means the issuer is the subject: a certificate nobody else
    vouches for. (Checking the signature as well would only separate a genuine
    self-signed certificate from one forging a CA's name, and both deserve the
    same look.) `expired` and `not_yet_valid` are against `now` (epoch seconds;
    packet time in a replay).
    """
    try:
        from cryptography import x509
    except ImportError:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as e:      # malformed DER raises ValueError or library errors
        logger.debug("Certificate did not parse: %s", e)
        return None

    try:
        not_before = _utc(cert.not_valid_before_utc)
        not_after = _utc(cert.not_valid_after_utc)
    except AttributeError:      # cryptography < 42
        not_before = _utc(cert.not_valid_before)
        not_after = _utc(cert.not_valid_after)
    moment = datetime.fromtimestamp(now, tz=timezone.utc) if now else datetime.now(timezone.utc)

    self_signed = cert.issuer == cert.subject

    def _name(name):
        try:
            return name.rfc4514_string()[:200]
        except Exception:
            return ''

    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = sans.value.get_values_for_type(x509.DNSName)[:10]
    except Exception:
        dns_names = []

    return {
        'subject': _name(cert.subject),
        'issuer': _name(cert.issuer),
        'dns_names': [str(n)[:253] for n in dns_names],
        'not_before': not_before.strftime('%Y-%m-%d'),
        'not_after': not_after.strftime('%Y-%m-%d'),
        'expired': moment > not_after,
        'not_yet_valid': moment < not_before,
        'days_past_expiry': max(0, (moment - not_after).days),
        'self_signed': self_signed,
        'sha256': hashlib.sha256(der).hexdigest(),
    }
