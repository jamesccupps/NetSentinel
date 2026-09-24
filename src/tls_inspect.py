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

References: JA3 (Salesforce, 2017), JA4+ (FoxIO, 2023).
Parsing is strictly bounds-checked — every input here is attacker-controlled.
"""

import hashlib
import logging
import struct

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


def _parse_client_hello(payload):
    if not looks_like_tls_handshake(payload) or payload[5] != HANDSHAKE_CLIENT_HELLO:
        return None

    rec = _Reader(payload)
    rec.u8()                       # content type (already checked)
    rec.u16()                      # record version — not the negotiated one
    record_len = rec.u16()
    if record_len == 0 or record_len > MAX_HELLO_BYTES:
        return None

    # A ClientHello can span records; we only handle the common single-record case
    # and take whatever of it arrived in this packet.
    body = rec.sub(min(record_len, rec.remaining))

    if body.u8() != HANDSHAKE_CLIENT_HELLO:
        return None
    hs_len = body.u24()
    hello = body.sub(min(hs_len, body.remaining))

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
        'ja4': _ja4(negotiated, ciphers, extensions, sig_algs, alpn, sni),
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


def _ja4(version, ciphers, extensions, sig_algs, alpn, sni):
    """
    JA4 for TCP: ja4_a_ja4_b_ja4_c.

    Unlike JA3, the cipher and extension lists are sorted before hashing, which is
    what makes it stable against Chrome's deliberate extension shuffling.
    """
    proto = 't'                                    # TCP; 'q' would be QUIC
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
