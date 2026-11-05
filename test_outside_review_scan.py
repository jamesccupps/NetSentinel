"""
Hostile input: fixes from the outside review of 2026-11-05 for file scans and
the syslog receiver (NetSentinel-review-2026-11-05.md, H8 and M2).

Each test fails on the code the review read. The timing tests use bounds far
above what the fixed code takes, so a slow CI runner does not flake them, and
far below what the old code took.
"""

import os
import random
import re
import sys
import time
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src import file_scan  # noqa: E402

_OLD_PDF_STREAM = re.compile(rb'stream\r?\n(.*?)endstream', re.S)


def old_pdf_bodies(data):
    return [m.group(1) for m in _OLD_PDF_STREAM.finditer(data)]


class TestPdfStreams(unittest.TestCase):
    """H8: the stream regex was quadratic, and a search holds the GIL."""

    SAMPLES = [
        b'%PDF-1.4\n1 0 obj<</Length 5>>stream\nhello\nendstream\nendobj\n',
        b'%PDF-1.4\nstream\r\nwindows\r\nendstream\n',
        b'%PDF-1.4\nstreamNoNewline endstream stream\nafter\nendstream',
        b'%PDF-1.4\nstream\nA\nendstreamstream\nB\nendstream',              # back to back
        b'%PDF-1.4\nstream\nendstream',                                     # empty body
        b'%PDF-1.4\nstream\r\r\nnot a body endstream stream\nlast\nendstream',
        b'%PDF-1.4\nendstream\nlooks like a body\nendstream\n',             # 'stream' in 'endstream'
        b'%PDF-1.4\nstream\nopen with no end',
        b'%PDF-1.4\nstream\nfirst stream\nsecond endstream',
        b'',
    ]

    def test_the_same_bodies_as_the_regex(self):
        for sample in self.SAMPLES:
            with self.subTest(sample=sample[:40]):
                self.assertEqual(list(file_scan._iter_pdf_streams(sample)), old_pdf_bodies(sample))

    def test_the_same_bodies_as_the_regex_on_shuffled_pieces(self):
        pieces = [b'stream', b'endstream', b'\n', b'\r', b'\r\n', b'x', b'stre', b'am', b'end', b' ']
        rng = random.Random(20261105)
        for _ in range(3000):
            sample = b''.join(rng.choice(pieces) for _ in range(rng.randrange(1, 30)))
            self.assertEqual(list(file_scan._iter_pdf_streams(sample)), old_pdf_bodies(sample),
                             sample)

    def test_real_compressed_streams_still_inflate(self):
        body = zlib.compress(b'BT /F1 12 Tf (quarterly totals) Tj ET')
        data = (b'%PDF-1.4\n4 0 obj<</Filter/FlateDecode>>stream\r\n' + body +
                b'\r\nendstream\nendobj\n')
        self.assertIn('quarterly totals', ''.join(file_scan._pdf_streams(data, [])))

    def test_a_hostile_pdf_is_read_in_linear_time(self):
        # 'stream\n' over and over with no 'endstream': 64 KB took seconds, 256 KB minutes
        data = b'%PDF-1.4\n' + b'stream\n' * (256 * 1024 // 7)
        started = time.perf_counter()
        self.assertEqual(file_scan._pdf_streams(data, []), [])
        self.assertLess(time.perf_counter() - started, 1.0)

    def test_a_hostile_pdf_scan_finishes(self):
        data = b'%PDF-1.4\n' + b'stream\n' * (256 * 1024 // 7)
        started = time.perf_counter()
        file_scan.scan_bytes('invoice.pdf', data)
        self.assertLess(time.perf_counter() - started, 10.0)


if __name__ == '__main__':
    unittest.main()
