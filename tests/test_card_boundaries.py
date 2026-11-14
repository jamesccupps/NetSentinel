"""
A card number has to stand on its own.
=======================================
On 2026-11-13 Ubuntu's apt, in WSL, asked a package server for a file by its
SHA-256 (/dists/.../by-hash/SHA256/<hash>), and NetSentinel raised a HIGH
"[CONFIRMED] Credit Card": sixteen digits in a row inside the hash passed
Luhn, as one in ten such runs does. The live pattern had no boundaries, and
the file scanner's only refused digits and dashes beside the number, so a
hash in a file was a CRITICAL payment card too. Now letters and digits on
either side mean it is part of something else.

The hashes here are made up or computed; the only card number is the
public test number every payment processor documents.
"""

import hashlib
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401

from test_third_review import T0, http_get, tcp  # noqa: E402

PC = '192.168.10.32'
MIRROR = '203.0.113.23'
SHOP = '198.51.100.40'
TEST_CARD = '4111111111111111'      # the documented test Visa
# A made-up SHA-256 with the test number inside it, letters on both sides.
HASH = 'c0ffee' + TEST_CARD + 'deadbeef' * 5 + 'ab'
APT = 'Debian APT-HTTP/1.3 (2.7.14) non-interactive'


def apt_by_hash(digest=HASH, ts=T0):
    path = f'/ubuntu/dists/noble-security/universe/dep11/by-hash/SHA256/{digest}'
    return tcp(PC, 50412, MIRROR, 80, http_get('security.ubuntu.com', path, APT),
               server=80, ts=ts)


def card_post(ts=T0):
    body = f'card_number={TEST_CARD}&cvv=123&exp=12%2F30'.encode()
    return tcp(PC, 50413, SHOP, 80,
               http_get('shop.example', '/checkout', method='POST', body=body),
               server=80, ts=ts)


def luhn(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch) * (2 if i % 2 else 1)
        total += d - 9 if d > 9 else d
    return total % 10 == 0


class TestThePattern(unittest.TestCase):

    def found(self, data):
        from src.forensics import CC_PATTERN_RE
        m = CC_PATTERN_RE.search(data)
        return m.group(0).decode() if m else None

    def test_digits_inside_a_hash_are_not_a_card(self):
        self.assertEqual(HASH.count(TEST_CARD), 1)
        self.assertEqual(len(HASH), 64)
        self.assertIsNone(self.found(HASH.encode()))
        self.assertIsNone(self.found(f'/by-hash/SHA256/{HASH} HTTP/1.1'.encode()))

    def test_no_card_in_thousands_of_real_hashes(self):
        """The unbounded pattern found Luhn-valid "cards" in these; none now."""
        from src.forensics import CC_PATTERN_RE
        unbounded = re.compile(rb'(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})')
        digests = [hashlib.sha256(str(i).encode()).hexdigest().encode() for i in range(20000)]
        before = [d for d in digests
                  if (m := unbounded.search(d)) and luhn(m.group(0).decode())]
        self.assertTrue(before, 'the sample should hold hashes the old pattern took for cards')
        self.assertEqual([d for d in digests if CC_PATTERN_RE.search(d)], [])

    def test_part_of_a_longer_number_is_not_a_card(self):
        self.assertIsNone(self.found(f'id={TEST_CARD}0'.encode()))
        self.assertIsNone(self.found(f'id=7{TEST_CARD}'.encode()))

    def test_a_card_on_its_own_is_still_found(self):
        for data in (f'card_number={TEST_CARD}&cvv=123',
                     f'{{"pan":"{TEST_CARD}"}}',
                     f'pan {TEST_CARD}',
                     TEST_CARD,
                     f'%22pan%22%3A%22{TEST_CARD}%22',     # URL-encoded JSON
                     f'pan%3D{TEST_CARD}%26'):              # an encoded form
            self.assertEqual(self.found(data.encode()), TEST_CARD, data)


class TestLiveTraffic(unittest.TestCase):

    def cards(self, *packets):
        from src.forensics import NetworkForensics
        f = NetworkForensics()
        for p in packets:
            f.analyze_packet(p)
        return [d for d in f.sensitive_data if d['data_type'] == 'Credit Card']

    def test_an_apt_by_hash_request_is_not_a_card(self):
        self.assertEqual(self.cards(apt_by_hash()), [])

    def test_a_card_posted_over_plain_http_is(self):
        [card] = self.cards(card_post())
        self.assertNotIn(TEST_CARD, card['value'])
        self.assertIn('1111', card['value'])


class TestFileScans(unittest.TestCase):

    def cards(self, text):
        from src.file_scan import scan_bytes
        return [s['value'] for s in scan_bytes('x.txt', text.encode('utf-8'))['secrets']
                if s['kind'] == 'card_number']

    def test_a_hash_in_a_file_is_not_a_card(self):
        self.assertEqual(self.cards(f'SHA256: {HASH}\n--hash=sha256:{HASH} \\\n'), [])

    def test_a_card_in_a_file_still_is(self):
        self.assertEqual(self.cards(f'card {TEST_CARD}\n'), ['**** **** **** 1111'])
        self.assertEqual(self.cards('Visa: 4111 1111 1111 1111.\n'), ['**** **** **** 1111'])
        self.assertEqual(self.cards(f'pan%3D{TEST_CARD}\n'), ['**** **** **** 1111'])


if __name__ == '__main__':
    unittest.main()
