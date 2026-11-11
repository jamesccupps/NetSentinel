"""
Credentials are what a client sends.
====================================
On its first afternoon, 1.11.0 raised two "[CONFIRMED] Plaintext Credential
(HTTP Form)" alerts, CRITICAL, about a Visual Studio update that Windows Update's
Delivery Optimization fetched over plain HTTP from a cache server. The form
check read the server's side as well, and 27,000 packets of compressed data held
"Token:" and "pwD:" by chance. 1.10.x had skipped most of such downloads under
its old 500-packet cap, so the bug only now showed.
Addresses are documentation ranges; the "secrets" are made up.
"""

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401

from test_fourth_review import PC, forensics, request  # noqa: E402
from test_third_review import tcp  # noqa: E402

CACHE = '192.0.2.202'      # stands in for the Delivery Optimization cache server


def binary(size, planted=b''):
    """Compressed-looking bytes, with a credential-shaped run in the middle."""
    rng = random.Random(size)
    body = bytes(rng.randrange(256) for _ in range(size))
    middle = size // 2
    return body[:middle] + planted + body[middle:]


def credentials(f):
    return [(c['protocol'], c['credential_type']) for c in f.credentials_found]


class TestTheServersSideIsNotACredential(unittest.TestCase):

    def test_a_download_chunk_with_token_shaped_bytes_is_nothing(self):
        f = forensics()
        for planted in (b'Token:\x8a\x01Qz', b'pwD:\xe4\x9cR0\x11fake'):
            f.analyze_packet(tcp(CACHE, 80, PC, 58772, binary(1448, planted), server=80))
        self.assertEqual(credentials(f), [])

    def test_even_when_which_end_is_the_server_is_not_known(self):
        f = forensics()
        f.analyze_packet(tcp(CACHE, 80, PC, 1997, binary(1448, b'password=abc123x'), server=0))
        self.assertEqual(credentials(f), [])

    def test_a_response_header_naming_authorization_is_nothing(self):
        f = forensics()
        f.analyze_packet(tcp(CACHE, 80, PC, 50000, b'HTTP/1.1 200 OK\r\n'
                             b'Authorization: Bearer not-a-real-token\r\n'
                             b'X-Api-Key: not-a-real-key\r\n\r\n', server=80))
        self.assertEqual(credentials(f), [])


class TestABinaryUploadIsNotAForm(unittest.TestCase):

    def test_bytes_sent_to_the_server_that_are_not_text(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 50000, CACHE, 80, binary(1400, b'secret=Zq9\x07'), server=80))
        self.assertEqual(credentials(f), [])


class TestRealOnesStillCount(unittest.TestCase):

    def test_a_login_form_posted_in_plain_http(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 50000, CACHE, 80, request(
            'printer.example', '/login', ['Content-Type: application/x-www-form-urlencoded'],
            body=b'user=admin&password=not-a-real-one'), server=80))
        self.assertEqual(credentials(f), [('HTTP Form', 'password_field')])

    def test_a_bearer_token_sent_to_the_server(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 50000, CACHE, 80, request(
            'api.example', '/v1', ['Authorization: Bearer not-a-real-token'], method='GET',
            body=b''), server=80))
        self.assertEqual(credentials(f), [('HTTP Auth Token', 'token')])

    def test_a_session_cookie_sent_to_an_internet_server_is_still_seen(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 50000, '142.250.68.195', 80, request(
            'shop.example', '/', ['Cookie: sessionid=not-a-real-session'], method='GET',
            body=b''), server=80))
        self.assertIn('Session Cookie', [d['data_type'] for d in f.sensitive_data])


class TestTextOrNot(unittest.TestCase):

    def test_forms_and_json_are_text_and_compressed_data_is_not(self):
        from src.forensics import looks_like_text
        self.assertTrue(looks_like_text(b'user=admin&password=x'))
        self.assertTrue(looks_like_text(b'{"token": "x", "name": "K\xc3\xbcche"}'))
        self.assertFalse(looks_like_text(binary(1448)))
        self.assertFalse(looks_like_text(b''))


if __name__ == '__main__':
    unittest.main()
