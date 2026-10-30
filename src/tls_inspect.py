"""
TLS ClientHello Inspection
===========================
Recovers what is still readable from an encrypted connection.

The ClientHello is sent in the clear, even under TLS 1.3, and carries two things
worth far more than the encrypted payload behind it:

- **SNI** — the hostname the client asked for. For a monitor that otherwise sees
  only an IP, this restores a destination name for the large majority of traffic.
  It survives DNS-over-HTTPS, because the name is in the TLS handshake rather than
  in a DNS query the sensor may never observe.

- **JA3 / JA4 fingerprints** — hashes over the offered cipher suites, extensions
  and curves. These identify the *client stack*, not the site: Chrome, Firefox,
  python-requests, Go, curl and common C2 frameworks all look different. A
  fingerprint that matches nothing the user runs, talking to a rare destination, is
  a strong signal that works on fully encrypted traffic.

JA3 is kept because most public threat intelligence is still keyed on it, but it is
fragile: Chrome shuffles its extension order on purpose, which changes the hash on
every connection. JA4 sorts the cipher and extension lists before hashing, so it is
stable across that shuffling. Both are emitted; prefer JA4 for matching.

References: JA3 (Salesforce, 2017), JA4+ (FoxIO, 2023), QUIC-TLS (RFC 9001).
Parsing is strictly bounds-checked — every input here is attacker-controlled.

Two transports need more than one packet:

- **TCP.** A post-quantum ClientHello (X25519MLKEM768 key share) is 1.7-1.9 KB,
  so it spans two TCP segments. Reading only the first segment lost the SNI and
  both fingerprints for every current Chrome, Edge and Firefox connection.
  `ClientHelloReassembler` joins the segments per flow, within fixed bounds.
- **QUIC.** The ClientHello rides in CRYPTO frames inside Initial packets, which
  are encrypted with keys anyone can derive from the Destination Connection ID
  (RFC 9001 §5.2). That is deliberate — it only stops middleboxes ossifying — so
  reading the SNI from it is the same passive inspection as on TCP. Chrome splits
  its hello across two Initials and shuffles the frames, so this reassembles too.
"""

import hashlib
import hmac
import logging
import struct
from collections import OrderedDict

logger = logging.getLogger("NetSentinel.TLS")

# Record layer
TLS_RECORD_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
HANDSHAKE_SERVER_HELLO = 0x02

# Extension IDs we care about by name
EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000a   # "elliptic curves" in JA3 terms
EXT_EC_POINT_FORMATS = 0x000b
EXT_SIGNATURE_ALGORITHMS = 0x000d
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002b

# A ClientHello beyond this is either fragmented across records or malformed.
# Either way we do not want to spend time on it in the packet path.
MAX_HELLO_BYTES = 16384

_TLS_VERSION_NAMES = {
    0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1',
    0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3',
}

# JA4 encodes the version as two characters.
_JA4_VERSION = {
    0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3',
}


def is_grease(value):
    """
    GREASE values (RFC 8701) are random placeholders clients inject to keep
    middleboxes honest. They change per connection, so including them would make
    every fingerprint unique. Both bytes are equal and the low nibble is 0xa.
    """
    return (value & 0x0f0f) == 0x0a0a and (value >> 8) == (value & 0xff)


class _Reader:
    """Bounds-checked sequential reader. Raises ValueError rather than slicing short."""

    __slots__ = ('_buf', '_pos', '_end')

    def __init__(self, buf, start=0, end=None):
        self._buf = buf
        self._pos = start
        self._end = len(buf) if end is None else min(end, len(buf))

    @property
    def remaining(self):
        return self._end - self._pos

    def read(self, n):
        if n < 0 or self._pos + n > self._end:
            raise ValueError(f"short read: wanted {n}, have {self.remaining}")
        chunk = self._buf[self._pos:self._pos + n]
        self._pos += n
        return chunk

    def u8(self):
        return self.read(1)[0]

    def u16(self):
        return struct.unpack('>H', self.read(2))[0]

    def u24(self):
        b = self.read(3)
        return (b[0] << 16) | (b[1] << 8) | b[2]

    def skip(self, n):
        self.read(n)

    def sub(self, n):
        """A reader over the next n bytes, advancing this one past them."""
        if n < 0 or self._pos + n > self._end:
            raise ValueError(f"short sub-reader: wanted {n}, have {self.remaining}")
        r = _Reader(self._buf, self._pos, self._pos + n)
        self._pos += n
        return r


def looks_like_tls_handshake(payload):
    """Cheap pre-filter so the packet path does not attempt a full parse per packet."""
    return (len(payload) >= 6
            and payload[0] == TLS_RECORD_HANDSHAKE
            and payload[1] == 0x03            # record version is always 0x03xx
            and payload[5] in (HANDSHAKE_CLIENT_HELLO, HANDSHAKE_SERVER_HELLO))


def parse_client_hello(payload):
    """
    Parse a TLS ClientHello out of raw TCP payload bytes.

    Returns a dict with sni, ja3, ja3_string, ja4, version, alpn — or None if this
    is not a parseable ClientHello. Never raises: a malformed or hostile record
    yields None.
    """
    try:
        return _parse_client_hello(payload)
    except (ValueError, struct.error, IndexError) as e:
        logger.debug("ClientHello parse failed: %s", e)
        return None


def parse_client_hello_message(message, transport='t'):
    """
    Parse a bare ClientHello handshake message (type byte, 24-bit length, body),
    as QUIC carries it in CRYPTO frames with no TLS record header around it.

    `transport` is JA4's first character: 't' for TCP, 'q' for QUIC.
    """
    try:
        if not message or message[0] != HANDSHAKE_CLIENT_HELLO:
            return None
        body = _Reader(message)
        body.u8()
        hs_len = body.u24()
        if hs_len > MAX_HELLO_BYTES:
            return None
        return _parse_hello_body(body.sub(min(hs_len, body.remaining)), transport)
    except (ValueError, struct.error, IndexError) as e:
        logger.debug("ClientHello parse failed: %s", e)
        return None


def _parse_client_hello(payload):
    if not looks_like_tls_handshake(payload) or payload[5] != HANDSHAKE_CLIENT_HELLO:
        return None

    rec = _Reader(payload)
    rec.u8()                       # content type (already checked)
    rec.u16()                      # record version — not the negotiated one
    record_len = rec.u16()
    if record_len == 0 or record_len > MAX_HELLO_BYTES:
        return None

    # Whatever of the record is present. A hello split across segments arrives
    # here whole once ClientHelloReassembler has joined it.
    body = rec.sub(min(record_len, rec.remaining))

    if body.u8() != HANDSHAKE_CLIENT_HELLO:
        return None
    hs_len = body.u24()
    return _parse_hello_body(body.sub(min(hs_len, body.remaining)), 't')


def _parse_hello_body(hello, transport):
    legacy_version = hello.u16()
    hello.skip(32)                                  # random
    hello.skip(hello.u8())                          # legacy session id

    cipher_bytes = hello.sub(hello.u16())
    ciphers = []
    while cipher_bytes.remaining >= 2:
        c = cipher_bytes.u16()
        if not is_grease(c):
            ciphers.append(c)

    hello.skip(hello.u8())                          # compression methods

    extensions = []
    sni = None
    curves = []
    point_formats = []
    sig_algs = []
    alpn = []
    supported_versions = []

    if hello.remaining >= 2:
        ext_block = hello.sub(hello.u16())
        while ext_block.remaining >= 4:
            ext_type = ext_block.u16()
            ext_data = ext_block.sub(ext_block.u16())
            if is_grease(ext_type):
                continue
            extensions.append(ext_type)

            if ext_type == EXT_SERVER_NAME:
                sni = _parse_sni(ext_data)
            elif ext_type == EXT_SUPPORTED_GROUPS:
                curves = _u16_list(ext_data.sub(ext_data.u16()))
            elif ext_type == EXT_EC_POINT_FORMATS:
                point_formats = list(ext_data.read(ext_data.u8()))
            elif ext_type == EXT_SIGNATURE_ALGORITHMS:
                sig_algs = _u16_list(ext_data.sub(ext_data.u16()))
            elif ext_type == EXT_ALPN:
                alpn = _parse_alpn(ext_data)
            elif ext_type == EXT_SUPPORTED_VERSIONS:
                supported_versions = [v for v in _u16_list(ext_data.sub(ext_data.u8()))
                                      if not is_grease(v)]

    # TLS 1.3 pins legacy_version at 1.2 and advertises the real one in an extension.
    negotiated = max(supported_versions) if supported_versions else legacy_version

    ja3_string = _ja3_string(legacy_version, ciphers, extensions, curves, point_formats)
    return {
        'sni': sni,
        'ja3': hashlib.md5(ja3_string.encode(), usedforsecurity=False).hexdigest(),
        'ja3_string': ja3_string,
        'ja4': _ja4(negotiated, ciphers, extensions, sig_algs, alpn, sni, transport),
        'version': _TLS_VERSION_NAMES.get(negotiated, f'0x{negotiated:04x}'),
        'alpn': alpn,
        'cipher_count': len(ciphers),
        'extension_count': len(extensions),
    }


def _u16_list(reader):
    out = []
    while reader.remaining >= 2:
        v = reader.u16()
        if not is_grease(v):
            out.append(v)
    return out


def _parse_sni(reader):
    """server_name extension: a list of names; only host_name (type 0) is defined."""
    names = reader.sub(reader.u16())
    while names.remaining >= 3:
        name_type = names.u8()
        value = names.read(names.u16())
        if name_type == 0:
            try:
                host = value.decode('ascii').lower().rstrip('.')
            except UnicodeDecodeError:
                return None
            # Reject anything that is not plausibly a hostname so a crafted SNI
            # cannot inject control characters into alerts or logs downstream.
            if host and len(host) <= 253 and all(
                    c.isalnum() or c in '.-_' for c in host):
                return host
            return None
    return None


def _parse_alpn(reader):
    protocols = []
    block = reader.sub(reader.u16())
    while block.remaining >= 1:
        value = block.read(block.u8())
        try:
            protocols.append(value.decode('ascii'))
        except UnicodeDecodeError:
            continue
    return protocols


def _ja3_string(version, ciphers, extensions, curves, point_formats):
    """JA3: version,ciphers,extensions,curves,point_formats — all decimal, dash-joined."""
    return ','.join([
        str(version),
        '-'.join(str(c) for c in ciphers),
        '-'.join(str(e) for e in extensions),
        '-'.join(str(c) for c in curves),
        '-'.join(str(p) for p in point_formats),
    ])


def _ja4(version, ciphers, extensions, sig_algs, alpn, sni, transport='t'):
    """
    JA4: ja4_a_ja4_b_ja4_c.

    Unlike JA3, the cipher and extension lists are sorted before hashing, which is
    what makes it stable against Chrome's deliberate extension shuffling.
    """
    proto = transport if transport in ('t', 'q') else 't'   # TCP or QUIC
    ver = _JA4_VERSION.get(version, '00')
    has_sni = 'd' if sni else 'i'                  # d = to a domain, i = to an IP
    nc = min(len(ciphers), 99)
    ne = min(len(extensions), 99)

    alpn_chars = '00'
    if alpn:
        first = alpn[0]
        if first:
            alpn_chars = f"{first[0]}{first[-1]}" if len(first) > 1 else f"{first[0]}{first[0]}"

    ja4_a = f"{proto}{ver}{has_sni}{nc:02d}{ne:02d}{alpn_chars}"

    ja4_b = hashlib.sha256(
        ','.join(f"{c:04x}" for c in sorted(ciphers)).encode()
    ).hexdigest()[:12]

    # SNI and ALPN are excluded from ja4_c: they describe the destination, not the
    # client, and including them would make the fingerprint per-site.
    sorted_exts = sorted(e for e in extensions if e not in (EXT_SERVER_NAME, EXT_ALPN))
    ja4_c_input = (','.join(f"{e:04x}" for e in sorted_exts) + '_'
                   + ','.join(f"{s:04x}" for s in sig_algs))
    ja4_c = hashlib.sha256(ja4_c_input.encode()).hexdigest()[:12]

    return f"{ja4_a}_{ja4_b}_{ja4_c}"


# ─── QUIC ────────────────────────────────────────────────────────────────────

def looks_like_quic(payload):
    """
    Long-header QUIC Initial packet (RFC 9000 §17.2).

    Worth recognising even without full parsing: UDP/443 is otherwise classified as
    generic UDP with no flags and is_encrypted=False, which silently miscategorises
    a large and growing share of modern traffic.
    """
    if len(payload) < 5:
        return False
    if not payload[0] & 0x80:           # long header form
        return False
    version = struct.unpack('>I', payload[1:5])[0]
    # 0x00000001 = QUIC v1; 0x?a?a?a?a = version negotiation GREASE; 0 = VN packet
    return version == 0x00000001 or version == 0x6b3343cf or version == 0


# ─── Reassembly across TCP segments ──────────────────────────────────────────

def _assemble_handshake(buf):
    """
    Collect handshake bytes from consecutive TLS records at the start of `buf`.

    Returns ('complete', message), ('more', None) or ('invalid', None). A hello
    may in principle span records as well as segments, so both are handled.
    """
    pos = 0
    handshake = bytearray()
    needed = None
    while True:
        if needed is not None and len(handshake) >= needed:
            return 'complete', bytes(handshake[:needed])
        if len(buf) - pos < 5:
            return 'more', None
        if buf[pos] != TLS_RECORD_HANDSHAKE or buf[pos + 1] != 0x03:
            return 'invalid', None
        record_len = (buf[pos + 3] << 8) | buf[pos + 4]
        if record_len == 0 or record_len > MAX_HELLO_BYTES:
            return 'invalid', None
        if len(buf) - pos - 5 < record_len:
            # Take what has arrived of this record; the length test above decides.
            handshake += buf[pos + 5:]
            if needed is None and len(handshake) >= 4:
                needed = 4 + ((handshake[1] << 16) | (handshake[2] << 8) | handshake[3])
            if needed is not None and len(handshake) >= needed:
                return 'complete', bytes(handshake[:needed])
            return 'more', None
        handshake += buf[pos + 5:pos + 5 + record_len]
        pos += 5 + record_len
        if needed is None and len(handshake) >= 4:
            if handshake[0] != HANDSHAKE_CLIENT_HELLO:
                return 'invalid', None
            needed = 4 + ((handshake[1] << 16) | (handshake[2] << 8) | handshake[3])
            if needed > MAX_HELLO_BYTES:
                return 'invalid', None


class _Pending:
    __slots__ = ('buf', 'next_seq', 'started')

    def __init__(self, buf, next_seq, started):
        self.buf = buf
        self.next_seq = next_seq
        self.started = started


class ClientHelloReassembler:
    """
    Joins a ClientHello split across TCP segments, one buffer per flow.

    Bounded three ways so a flood of half-sent hellos cannot grow it: a flow cap
    (oldest dropped first), a byte cap per flow, and a timeout. Segments must
    arrive in sequence; a gap abandons the flow rather than parse a hole.
    """

    MAX_FLOWS = 1024
    MAX_BYTES = 2 * (MAX_HELLO_BYTES + 5)
    TIMEOUT_SEC = 10.0

    def __init__(self, max_flows=None):
        self._pending = OrderedDict()
        self.max_flows = max_flows or self.MAX_FLOWS
        self.reassembled = 0

    def __len__(self):
        return len(self._pending)

    def feed(self, key, payload, seq=None, now=0.0):
        """
        One TCP payload for flow `key`. Returns the parsed hello (see
        parse_client_hello) once complete, else None.
        """
        if not payload:
            return None
        entry = self._pending.get(key)
        if entry is None:
            if not (looks_like_tls_handshake(payload)
                    and payload[5] == HANDSHAKE_CLIENT_HELLO):
                return None
            status, message = _assemble_handshake(payload)
            if status == 'complete':
                return parse_client_hello_message(message)
            if status == 'invalid':
                return parse_client_hello(payload)
            self._expire(now)
            while len(self._pending) >= self.max_flows:
                self._pending.popitem(last=False)
            self._pending[key] = _Pending(
                bytearray(payload), None if seq is None else seq + len(payload), now)
            return None

        if seq is not None and entry.next_seq is not None:
            if seq + len(payload) <= entry.next_seq:
                return None                       # pure retransmission
            if seq < entry.next_seq:
                payload = payload[entry.next_seq - seq:]
            elif seq > entry.next_seq:
                del self._pending[key]            # a hole: give up on this flow
                return None
            entry.next_seq += len(payload)
        entry.buf += payload
        if len(entry.buf) > self.MAX_BYTES:
            del self._pending[key]
            return None
        status, message = _assemble_handshake(entry.buf)
        if status == 'more':
            return None
        del self._pending[key]
        if status == 'invalid':
            return None
        self.reassembled += 1
        return parse_client_hello_message(message)

    def _expire(self, now):
        while self._pending:
            key, entry = next(iter(self._pending.items()))
            if now - entry.started <= self.TIMEOUT_SEC:
                break
            del self._pending[key]


# ─── QUIC Initial packets (RFC 9000 §17.2.2, RFC 9001 §5, RFC 9369) ───────────

QUIC_V1 = 0x00000001
QUIC_V2 = 0x6b3343cf

# Public constants from the RFCs. Initial keys come from these and the client's
# Destination Connection ID, both of which are on the wire.
_QUIC_SALT = {
    QUIC_V1: bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a'),
    QUIC_V2: bytes.fromhex('0dede3def700a6db819381be6e269dcbf9bd2ed9'),
}
_QUIC_LABELS = {
    QUIC_V1: (b'quic key', b'quic iv', b'quic hp'),
    QUIC_V2: (b'quicv2 key', b'quicv2 iv', b'quicv2 hp'),
}
# The long-header packet type that means Initial differs between versions.
_QUIC_INITIAL_TYPE = {QUIC_V1: 0, QUIC_V2: 1}

QUIC_FRAME_PADDING = 0x00
QUIC_FRAME_PING = 0x01
QUIC_FRAME_CRYPTO = 0x06

_MAX_DATAGRAM = 65535


def _hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret, label, length, context=b''):
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1) with SHA-256."""
    full = b'tls13 ' + label
    info = struct.pack('>H', length) + bytes([len(full)]) + full + bytes([len(context)]) + context
    out, block, counter = b'', b'', 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def quic_initial_keys(dcid, version=QUIC_V1, side='client'):
    """(key, iv, hp) protecting the client's (or server's) Initial packets."""
    initial = _hkdf_extract(_QUIC_SALT[version], dcid)
    secret = _hkdf_expand_label(initial, b'client in' if side == 'client' else b'server in', 32)
    key_label, iv_label, hp_label = _QUIC_LABELS[version]
    return (_hkdf_expand_label(secret, key_label, 16),
            _hkdf_expand_label(secret, iv_label, 12),
            _hkdf_expand_label(secret, hp_label, 16))


def _varint(buf, pos):
    """QUIC variable-length integer (RFC 9000 §16). Returns (value, new_pos)."""
    if pos >= len(buf):
        raise ValueError('varint past end')
    first = buf[pos]
    size = 1 << (first >> 6)
    if pos + size > len(buf):
        raise ValueError('varint truncated')
    value = first & 0x3f
    for b in buf[pos + 1:pos + size]:
        value = (value << 8) | b
    return value, pos + size


def decrypt_quic_initial(datagram):
    """
    Remove header protection from and decrypt the first QUIC Initial packet in a
    UDP datagram from a client.

    Returns (dcid, [(offset, data), ...]) — the CRYPTO frames it carried — or None
    for anything else: other versions, other packet types, a failed tag check.
    Needs the `cryptography` package; without it this quietly returns None.
    """
    try:
        return _decrypt_quic_initial(bytes(datagram[:_MAX_DATAGRAM]))
    except (ValueError, struct.error, IndexError) as e:
        logger.debug("QUIC Initial not decrypted: %s", e)
        return None


def _decrypt_quic_initial(buf):
    if len(buf) < 7 or not buf[0] & 0x80 or not buf[0] & 0x40:
        return None
    version = struct.unpack('>I', buf[1:5])[0]
    if version not in _QUIC_SALT:
        return None
    if (buf[0] & 0x30) >> 4 != _QUIC_INITIAL_TYPE[version]:
        return None
    pos = 5
    dcid_len = buf[pos]
    if dcid_len > 20:
        return None
    dcid = buf[pos + 1:pos + 1 + dcid_len]
    pos += 1 + dcid_len
    if pos >= len(buf):
        return None
    scid_len = buf[pos]
    if scid_len > 20:
        return None
    pos += 1 + scid_len
    token_len, pos = _varint(buf, pos)
    pos += token_len
    length, pos = _varint(buf, pos)
    pn_offset = pos
    if length < 20 or pn_offset + length > len(buf):
        return None

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
    except ImportError:
        return None

    key, iv, hp = quic_initial_keys(dcid, version)
    sample = buf[pn_offset + 4:pn_offset + 20]
    if len(sample) < 16:
        return None
    encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = encryptor.update(sample) + encryptor.finalize()
    first = buf[0] ^ (mask[0] & 0x0f)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(b ^ m for b, m in zip(buf[pn_offset:pn_offset + pn_len], mask[1:1 + pn_len]))
    packet_number = int.from_bytes(pn_bytes, 'big')
    header = bytes([first]) + buf[1:pn_offset] + pn_bytes
    ciphertext = buf[pn_offset + pn_len:pn_offset + length]
    nonce = bytes(a ^ b for a, b in zip(iv, packet_number.to_bytes(12, 'big')))
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        return None
    return dcid, _crypto_frames(plaintext)


def _crypto_frames(plaintext):
    """CRYPTO frames from a decrypted Initial payload. Stops at any frame type an
    Initial from a client does not carry, rather than guess its length."""
    frames = []
    pos = 0
    while pos < len(plaintext):
        frame_type, pos = _varint(plaintext, pos)
        if frame_type in (QUIC_FRAME_PADDING, QUIC_FRAME_PING):
            continue
        if frame_type == QUIC_FRAME_CRYPTO:
            offset, pos = _varint(plaintext, pos)
            size, pos = _varint(plaintext, pos)
            if pos + size > len(plaintext):
                break
            frames.append((offset, plaintext[pos:pos + size]))
            pos += size
            continue
        if frame_type in (0x02, 0x03):        # ACK, ACK with ECN counts
            _, pos = _varint(plaintext, pos)  # largest acknowledged
            _, pos = _varint(plaintext, pos)  # delay
            ranges, pos = _varint(plaintext, pos)
            _, pos = _varint(plaintext, pos)  # first range
            for _ in range(min(ranges, 256)):
                _, pos = _varint(plaintext, pos)
                _, pos = _varint(plaintext, pos)
            if frame_type == 0x03:
                for _ in range(3):
                    _, pos = _varint(plaintext, pos)
            continue
        break
    return frames


class QuicHelloReassembler:
    """
    Gathers the CRYPTO stream of a QUIC client's Initial packets, keyed by
    Destination Connection ID, until it holds a whole ClientHello.

    Bounded like ClientHelloReassembler: a connection cap, a byte cap, a timeout.
    """

    MAX_CONNECTIONS = 512
    TIMEOUT_SEC = 10.0

    def __init__(self):
        self._pending = OrderedDict()   # dcid -> [started, {offset: bytes}]
        self.decrypted = 0

    def __len__(self):
        return len(self._pending)

    def feed(self, datagram, now=0.0):
        """One UDP payload from a client. Returns the parsed hello (JA4 'q...')
        once the CRYPTO stream holds a complete ClientHello, else None."""
        result = decrypt_quic_initial(datagram)
        if result is None:
            return None
        self.decrypted += 1
        dcid, frames = result
        if not frames:
            return None
        entry = self._pending.get(dcid)
        if entry is None:
            self._expire(now)
            while len(self._pending) >= self.MAX_CONNECTIONS:
                self._pending.popitem(last=False)
            entry = self._pending[dcid] = [now, {}]
        chunks = entry[1]
        for offset, data in frames:
            if offset + len(data) > MAX_HELLO_BYTES + 4:
                self._pending.pop(dcid, None)
                return None
            if len(data) > len(chunks.get(offset, b'')):
                chunks[offset] = data

        stream = bytearray()
        for offset in sorted(chunks):
            if offset > len(stream):
                break                              # still a gap
            stream += chunks[offset][len(stream) - offset:]
        if len(stream) < 4:
            return None
        if stream[0] != HANDSHAKE_CLIENT_HELLO:
            self._pending.pop(dcid, None)
            return None
        needed = 4 + ((stream[1] << 16) | (stream[2] << 8) | stream[3])
        if len(stream) < needed:
            return None
        self._pending.pop(dcid, None)
        return parse_client_hello_message(bytes(stream[:needed]), transport='q')

    def _expire(self, now):
        while self._pending:
            dcid, entry = next(iter(self._pending.items()))
            if now - entry[0] <= self.TIMEOUT_SEC:
                break
            del self._pending[dcid]
