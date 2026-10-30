"""
CI annotations for failing tests: the log needs a GitHub sign-in, annotations do not.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools.ci_failures import annotations, failures  # noqa: E402

SAMPLE = """\
test_a (test_x.TestA.test_a) ... ok
test_b (test_x.TestA.test_b) ... FAIL

======================================================================
ERROR: test_c (test_y.TestC.test_c)
Docstring line
----------------------------------------------------------------------
Traceback (most recent call last):
  File "test_y.py", line 3, in test_c
    open('/nope')
FileNotFoundError: [Errno 2] No such file or directory: '/nope'

======================================================================
FAIL: test_b (test_x.TestA.test_b)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "test_x.py", line 9, in test_b
    self.assertEqual(1, 2)
AssertionError: 1 != 2

----------------------------------------------------------------------
Ran 3 tests in 0.010s

FAILED (failures=1, errors=1)
"""


class TestCiFailures(unittest.TestCase):

    def test_each_failure_and_its_reason(self):
        self.assertEqual(failures(SAMPLE), [
            ('ERROR', 'test_y.TestC.test_c',
             "FileNotFoundError: [Errno 2] No such file or directory: '/nope'"),
            ('FAIL', 'test_x.TestA.test_b', 'AssertionError: 1 != 2'),
        ])

    def test_annotations_escape_what_workflow_commands_reserve(self):
        lines = annotations(SAMPLE)
        self.assertEqual(lines[1], '::error title=FAIL test_x.TestA.test_b::AssertionError: 1 != 2')
        self.assertTrue(lines[0].startswith('::error title=ERROR test_y.TestC.test_c::'))
        self.assertEqual(annotations('Ran 3 tests\n\nOK\n'), [])

    def test_a_long_run_is_capped(self):
        many = ''.join(f"{'=' * 70}\nFAIL: t{n} (m.C.t{n})\n{'-' * 70}\nAssertionError: x\n\n"
                       for n in range(50))
        lines = annotations(many, limit=40)
        self.assertEqual(len(lines), 41)
        self.assertIn('10 more failures', lines[-1])


if __name__ == '__main__':
    unittest.main(verbosity=2)
