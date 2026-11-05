"""
What the outside review of 2026-11-05 found in netmon.
======================================================
One section per finding, named by its number in the review. Each test failed
on the code before its fix.

No network: the controller, ntfy and the clock are fakes, as elsewhere in
netmon_tests. Addresses are 10.10.x, 192.168.10.x and documentation ranges, and
every name is made up.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import _test_support  # noqa: E402,F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')
RULES = os.path.join(ROOT, 'netmon', 'rules')
DEPLOY = os.path.join(ROOT, 'netmon', 'deploy')


# ─── M23: the capture unit could not start ───────────────────────────────────

class TestTheCaptureUnitCanStart(unittest.TestCase):
    """
    systemd cannot run here, so this reads the unit. ProtectSystem=strict left
    /var read-only to the ExecStartPre mkdir, the bounding set had no CAP_CHOWN
    for its chown, and ReadWritePaths named a directory a fresh install does
    not have yet, which fails the namespace setup for the whole unit.
    """

    def settings(self, name):
        with open(os.path.join(DEPLOY, 'netmon-capture.service'),
                  encoding='utf-8') as handle:
            text = handle.read().replace('\\\n', ' ')
        return [line.split('=', 1)[1] for line in text.splitlines()
                if line.startswith(name + '=')]

    def test_the_directory_is_made_outside_the_sandbox(self):
        steps = self.settings('ExecStartPre')
        self.assertTrue(steps)
        for step in steps:
            with self.subTest(step=step.strip()):
                self.assertTrue(step.startswith('+'), step)

    def test_a_missing_directory_does_not_fail_the_namespace(self):
        paths = self.settings('ReadWritePaths')
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=path.strip()):
                self.assertTrue(path.startswith('-'), path)

    def test_tcpdump_still_drops_to_the_netmon_user_itself(self):
        """
        User=netmon would start tcpdump unprivileged, and its -Z (which
        RingBuffer.capture_command emits) would then fail.
        """
        self.assertEqual(self.settings('User'), [])
        command = ' '.join(self.settings('ExecStart'))
        self.assertIn('-Z netmon', command)


if __name__ == '__main__':
    unittest.main(verbosity=2)
