"""
Fixes from the outside review of 2026-11-05 (NetSentinel-review-2026-11-05.md).

Each test fails on the code the review read (bacd645).
"""

import unittest

from src.config import as_float, as_int


class TestNumericSettings(unittest.TestCase):
    """M3: a hand-typed setting reached the code as a string."""

    def test_whole_numbers_in_any_spelling(self):
        self.assertEqual(as_int(5514, 1), 5514)
        self.assertEqual(as_int(' 5514 ', 1), 5514)
        self.assertEqual(as_int('5514', 1), 5514)
        self.assertEqual(as_int(30.0, 1), 30)
        self.assertIsInstance(as_int('30', 1), int)

    def test_a_typo_falls_back_to_the_default(self):
        for typo in ('55l4', '5,514', '30d', '', None, True, 'nan', 'inf', 2.5, [], {}):
            with self.subTest(typo=typo):
                self.assertEqual(as_int(typo, 7, name='x.y'), 7)

    def test_out_of_range_is_clamped(self):
        self.assertEqual(as_int(70000, 5514, lo=1, hi=65535), 65535)
        self.assertEqual(as_int(-3, 10, lo=1), 1)
        self.assertEqual(as_float('1.5', 0.5, lo=0.0, hi=1.0), 1.0)

    def test_floats(self):
        self.assertEqual(as_float('0.25', 0.5), 0.25)
        self.assertEqual(as_float('high', 0.5, name='ml.x'), 0.5)
        self.assertEqual(as_float(float('nan'), 0.5), 0.5)


if __name__ == '__main__':
    unittest.main()
