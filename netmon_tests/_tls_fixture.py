"""
A synthetic TLS ClientHello.

Built by hand rather than captured, so the fixture carries no real session and
can be committed. It is the minimum a parser needs: the record and handshake
headers, one cipher suite, and an SNI extension.
"""

import struct


def build_client_hello(server_name, version=0x0303):
    name = server_name.encode('ascii')

    sni_entry = b'\x00' + struct.pack('>H', len(name)) + name
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
    sni_extension = b'\x00\x00' + struct.pack('>H', len(sni_list)) + sni_list

    # A couple of real cipher suites so the fingerprint has something to chew on.
    ciphers = struct.pack('>HH', 0x1301, 0xc02f)
    extensions = sni_extension + b'\x00\x0b\x00\x02\x01\x00'   # + ec_point_formats

    body = (struct.pack('>H', version)
            + b'\x00' * 32                                     # client random
            + b'\x00'                                          # empty session id
            + struct.pack('>H', len(ciphers)) + ciphers
            + b'\x01\x00'                                      # one compression
            + struct.pack('>H', len(extensions)) + extensions)

    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + struct.pack('>H', len(handshake)) + handshake
