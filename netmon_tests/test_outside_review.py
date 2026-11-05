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


# ─── M19: a BACnet SimpleACK raised a critical push ──────────────────────────

class TestBacnetAcknowledgements(unittest.TestCase):
    """
    A SimpleACK names the service it acknowledges, and the rule did not look
    at the APDU type, so the controller's reply to every allowed write was a
    critical finding of its own: the reply runs controller to workstation,
    which no allowlist entry covers.
    """

    @classmethod
    def setUpClass(cls):
        from netmon.profile import load_profile
        from netmon.rules_engine import load_rules
        cls.profile = load_profile(EXAMPLE)
        cls.rule = load_rules(RULES).by_id('bacnet_control')

    def fire(self, payload, src, dst):
        from netmon.events import Event, enrich
        from netmon.protocols.bacnet import parse
        event = Event(kind='bacnet', src_ip=src, dst_ip=dst, src_port=47808,
                      dst_port=47808, protocol='udp', vlan=20)
        event.fields.update(parse(payload).as_fields())
        enrich(event, self.profile)
        return self.rule.evaluate(event)

    @staticmethod
    def frame(apdu):
        body = bytes([0x01, 0x04]) + apdu
        return bytes([0x81, 0x0A]) + (4 + len(body)).to_bytes(2, 'big') + body

    def write_property(self):
        # Confirmed-Request, invoke 1, WriteProperty to analog-value-3.
        return self.frame(bytes([0x00, 0x05, 0x01, 15, 0x0C])
                          + ((2 << 22) | 3).to_bytes(4, 'big') + bytes([0x19, 85]))

    def simple_ack(self):
        return self.frame(bytes([0x20, 0x01, 15]))

    def test_the_acknowledgement_of_an_allowed_write_is_quiet(self):
        # 10.10.20.10 may write to 10.10.20.21 in the example profile.
        self.assertEqual(self.fire(self.write_property(),
                                   '10.10.20.10', '10.10.20.21'), [])
        self.assertEqual(self.fire(self.simple_ack(),
                                   '10.10.20.21', '10.10.20.10'), [])

    def test_a_write_outside_the_allowlist_still_fires(self):
        findings = self.fire(self.write_property(), '10.10.60.50', '10.10.20.21')
        self.assertEqual([f.rule_id for f in findings], ['bacnet_control'])
        self.assertEqual(findings[0].severity, 'critical')


if __name__ == '__main__':
    unittest.main(verbosity=2)
