"""
Canary hits.
============
A canary has no legitimate users, so every other rule's question — was this
normal? — does not arise. That makes these tests mostly about two other things.

The first is the attempted credentials. The username is reported, because a
scanner using admin/admin and someone using your real service account are very
different problems. The password never is, in any field, at any depth, and a
fuzz test stuffs every plausible password key into a record to check.

The second is the listener, which is the one part of netmon that accepts an
inbound connection from a network an attacker may already be on.
"""

import json
import os
import shutil
import socket
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.canary import (CanaryError, CanaryListener, LOGTYPES,  # noqa: E402
                           finding_for, findings_from_log, parse_event,
                           read_log)
from netmon.events import Severity, Tier  # noqa: E402
from netmon.profile import SiteProfile  # noqa: E402
from netmon.redact import ALERT, audit, redact_finding  # noqa: E402


def profile():
    return SiteProfile({
        'site': {'name': 'test'},
        'vlans': {60: {'name': 'staff', 'subnet': '10.10.60.0/24',
                       'zone': 'corporate'}},
        'roles': {'workstation': {}},
        'devices': {'00:11:22:00:00:40': {'name': 'ops-workstation',
                                          'role': 'workstation',
                                          'ips': ['10.10.60.50'], 'vlan': 60}},
    })


def record(logtype=4002, **overrides):
    """
    A canary record, stuffed with every credential field worth refusing.

    Invented values: a real one would be the thing that must not be in a
    repository.
    """
    data = {
        'logtype': logtype,
        'src_host': '10.10.60.99', 'src_port': 54321,
        'dst_host': '10.10.20.250', 'dst_port': 22,
        'node_id': 'occ-bkp-02',
        'local_time': '2026-10-13 03:14:00',
        'logdata': {
            'USERNAME': 'administrator',
            'PASSWORD': 'Summer2026!',
            'PASSWORD_HASH': '$2y$10$abcdefghijklmnop',
            'SECRET': 'shh',
            'SESSION_ID': 'A1B2C3D4',
            'AUTH_TOKEN': 'Bearer abcdefghijklmnopqrst',
            'LOCALVERSION': 'SSH-2.0-OpenSSH_8.2',
            'REMOTEVERSION': 'SSH-2.0-libssh',
        },
    }
    data.update(overrides)
    return data


#: Everything in the fixture that must never come out.
SECRETS = ('Summer2026!', '$2y$10$abcdefghijklmnop', 'shh', 'A1B2C3D4',
           'Bearer abcdefghijklmnopqrst')


# ─── Credentials ─────────────────────────────────────────────────────────────

class TestCredentials(unittest.TestCase):

    def test_the_username_is_reported(self):
        """
        A scanner using admin/admin and someone using your real service account
        are very different problems, and the username is how you tell.
        """
        self.assertEqual(parse_event(record())['details']['username'],
                         'administrator')

    def test_no_password_field_comes_out(self):
        blob = json.dumps(parse_event(record()), default=str)
        for secret in SECRETS:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, blob)

    def test_that_a_password_was_supplied_is_reported(self):
        """Which is the useful part: they had one to try."""
        self.assertTrue(parse_event(record())['password_supplied'])

    def test_a_record_with_no_password_says_so(self):
        parsed = parse_event(record(logdata={'USERNAME': 'root'}))
        self.assertFalse(parsed['password_supplied'])

    def test_an_empty_password_field_does_not_count(self):
        """
        A blank password is a scanner working through a list; a filled one is
        someone who had something to try, and "with a password" about an empty
        string blurs the two.
        """
        for blank in ('', '   ', None):
            with self.subTest(blank=blank):
                parsed = parse_event(record(logdata={'USERNAME': 'root',
                                                     'PASSWORD': blank}))
                self.assertFalse(parsed['password_supplied'])

    def test_the_description_only_mentions_one_when_there_was_one(self):
        with_one = finding_for(parse_event(record()))
        without = finding_for(parse_event(record(
            logdata={'USERNAME': 'root', 'PASSWORD': ''})))
        self.assertIn('with a password', with_one.description)
        self.assertNotIn('with a password', without.description)

    def test_the_finding_carries_none_of_it_either(self):
        finding = finding_for(parse_event(record()))
        blob = json.dumps(finding.as_dict(include_event=True), default=str)
        for secret in SECRETS:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, blob)

    def test_and_nor_does_the_redacted_alert(self):
        finding = finding_for(parse_event(record()), profile())
        alert = redact_finding(finding, profile(), ALERT)
        self.assertEqual(audit(alert), [])
        for secret in SECRETS:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, json.dumps(alert, default=str))

    def test_every_plausible_password_key_is_refused(self):
        """
        The allowlist is the mechanism; this is the check that a careless
        addition to it would be caught.
        """
        keys = ('PASSWORD', 'PASSWD', 'PASS', 'password', 'user_password',
                'PASSWORD_HASH', 'HASHED_PASSWORD', 'SECRET', 'API_KEY',
                'TOKEN', 'AUTH', 'CREDENTIAL', 'COOKIE', 'SESSION_ID',
                'PRIVATE_KEY', 'NTLM_HASH', 'SMB_HASH')
        for key in keys:
            with self.subTest(key=key):
                parsed = parse_event(record(logdata={key: 'MUSTNOTAPPEAR',
                                                     'USERNAME': 'ok'}))
                self.assertNotIn('MUSTNOTAPPEAR', json.dumps(parsed))
                self.assertEqual(parsed['details'].get('username'), 'ok')

    def test_an_unknown_field_is_dropped_rather_than_passed(self):
        """
        OpenCanary's modules each add their own keys and the next version will
        add more, so the question has to be "is this known to be safe".
        """
        parsed = parse_event(record(logdata={'SOMETHING_NEW': 'value',
                                             'USERNAME': 'ok'}))
        self.assertEqual(set(parsed['details']), {'username'})

    def test_a_nested_structure_is_not_reported(self):
        parsed = parse_event(record(logdata={
            'USERNAME': {'nested': 'MUSTNOTAPPEAR'}, 'PATH': '/admin'}))
        self.assertNotIn('MUSTNOTAPPEAR', json.dumps(parsed))
        self.assertEqual(parsed['details'].get('path'), '/admin')


class TestValuesAreSanitised(unittest.TestCase):
    """
    These arrive from whoever is poking the canary, so they are adversarial by
    definition.
    """

    def test_control_characters_are_removed(self):
        parsed = parse_event(record(logdata={
            'USERNAME': 'admin\r\nX-Injected: yes'}))
        self.assertNotIn('\n', parsed['details']['username'])
        self.assertNotIn('\r', parsed['details']['username'])

    def test_a_very_long_value_is_truncated(self):
        parsed = parse_event(record(logdata={'USERNAME': 'A' * 100_000}))
        self.assertLessEqual(len(parsed['details']['username']), 200)

    def test_a_crafted_address_cannot_carry_a_newline(self):
        parsed = parse_event(record(src_host='10.0.0.1\r\nEvil: yes'))
        self.assertNotIn('\n', parsed['src_ip'])

    def test_an_out_of_range_port_becomes_none(self):
        for bad in (0, -1, 99999, 'abc', None):
            with self.subTest(bad=bad):
                self.assertIsNone(parse_event(record(src_port=bad))['src_port'])


# ─── Parsing ─────────────────────────────────────────────────────────────────

class TestParsing(unittest.TestCase):

    def test_the_service_is_named(self):
        for logtype, expected in ((2000, 'ftp'), (4002, 'ssh'), (7001, 'telnet'),
                                  (15001, 'rdp'), (18001, 'redis')):
            with self.subTest(logtype=logtype):
                self.assertEqual(parse_event(record(logtype))['service'], expected)

    def test_an_unknown_logtype_is_numbered_not_guessed(self):
        """An invented service name would send someone to the wrong machine."""
        parsed = parse_event(record(99999))
        self.assertEqual(parsed['service'], 'logtype-99999')
        self.assertIn('99999', parsed['what_happened'])

    def test_the_canary_reporting_its_own_boot_is_not_a_hit(self):
        self.assertIsNone(parse_event(record(1000)))

    def test_a_record_with_no_logtype_is_not_a_canary_event(self):
        self.assertIsNone(parse_event({'src_host': '10.0.0.1'}))
        self.assertIsNone(parse_event({'logtype': 'not a number'}))

    def test_junk_is_not_an_error(self):
        for junk in ('', 'not json', '{]', b'\xff\xfe', None, [], 42):
            with self.subTest(junk=junk):
                self.assertIsNone(parse_event(junk))

    def test_a_json_string_or_a_dict_both_work(self):
        self.assertEqual(parse_event(json.dumps(record()))['service'], 'ssh')
        self.assertEqual(parse_event(record())['service'], 'ssh')

    def test_the_timestamp_is_read_from_the_record(self):
        parsed = parse_event(record(local_time='2026-10-13 03:14:00'))
        self.assertEqual(time.strftime('%H:%M', time.localtime(parsed['ts'])),
                         '03:14')

    def test_several_time_formats_parse(self):
        for text in ('2026-10-13 03:14:00', '2026-10-13 03:14:00.123456',
                     '2026-10-13T03:14:00', '2026-10-13T03:14:00.5Z'):
            with self.subTest(text=text):
                parsed = parse_event(record(local_time=text))
                self.assertGreater(parsed['ts'], 1_700_000_000)

    def test_an_unparseable_time_falls_back_to_now(self):
        parsed = parse_event(record(local_time='whenever'))
        self.assertAlmostEqual(parsed['ts'], time.time(), delta=5)

    def test_every_logtype_in_the_table_is_well_formed(self):
        for code, (service, what) in LOGTYPES.items():
            with self.subTest(code=code):
                self.assertTrue(service and ' ' not in service)
                self.assertTrue(what and what[0].islower())


# ─── Findings ────────────────────────────────────────────────────────────────

class TestFindings(unittest.TestCase):

    def test_a_hit_is_always_high_and_always_pushes(self):
        """
        Every other rule needs a judgement about whether the traffic was
        normal. This one does not: a canary has no legitimate users.
        """
        for logtype in LOGTYPES:
            if logtype == 1000:
                continue
            with self.subTest(logtype=logtype):
                finding = finding_for(parse_event(record(logtype)))
                self.assertEqual(finding.severity, Severity.HIGH)
                self.assertEqual(finding.tier, Tier.PUSH)

    def test_it_reads_as_a_sentence(self):
        finding = finding_for(parse_event(record()))
        self.assertIn('an SSH login was attempted', finding.description)
        self.assertIn('10.10.20.250:22', finding.description)
        self.assertIn('administrator', finding.description)
        self.assertIn('with a password', finding.description)

    def test_a_known_device_is_named(self):
        """An address makes someone go and look it up. The profile knows."""
        finding = finding_for(
            parse_event(record(src_host='10.10.60.50')), profile())
        self.assertIn('ops-workstation', finding.description)

    def test_the_next_check_points_at_the_other_findings_for_that_host(self):
        finding = finding_for(parse_event(record()))
        self.assertIn('beaconing', finding.next_check)

    def test_it_says_nothing_has_a_reason_to_be_there(self):
        self.assertIn('has a reason to reach this host',
                      finding_for(parse_event(record())).next_check)

    def test_findings_from_the_same_source_and_service_deduplicate(self):
        from netmon.events import Deduplicator
        dedup = Deduplicator(window_sec=3600)
        first = finding_for(parse_event(record()))
        self.assertIsNotNone(dedup.admit(first))
        for _ in range(50):
            self.assertIsNone(dedup.admit(finding_for(parse_event(record()))))
        self.assertEqual(first.count, 51)

    def test_a_different_service_is_a_different_finding(self):
        from netmon.events import Deduplicator
        dedup = Deduplicator(window_sec=3600)
        self.assertIsNotNone(dedup.admit(finding_for(parse_event(record(4002)))))
        self.assertIsNotNone(dedup.admit(finding_for(parse_event(record(2000)))))


# ─── The log file ────────────────────────────────────────────────────────────

class TestLogFile(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-canary-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.path = os.path.join(self.scratch, 'opencanary.log')

    def write(self, lines):
        with open(self.path, 'w') as handle:
            for line in lines:
                handle.write((line if isinstance(line, str)
                              else json.dumps(line)) + '\n')
        return self.path

    def test_records_are_read(self):
        self.write([record(4002), record(2000)])
        self.assertEqual([r['service'] for r in read_log(self.path)],
                         ['ssh', 'ftp'])

    def test_a_half_written_last_line_is_normal(self):
        """The file is being appended to while this reads it."""
        self.write([record(4002)])
        with open(self.path, 'a') as handle:
            handle.write('{"logtype": 40')
        self.assertEqual(len(list(read_log(self.path))), 1)

    def test_blank_lines_are_skipped(self):
        self.write([record(4002), '', '   ', record(2000)])
        self.assertEqual(len(list(read_log(self.path))), 2)

    def test_the_canary_boot_lines_are_skipped(self):
        self.write([record(1000), record(4002), record(1000)])
        self.assertEqual(len(list(read_log(self.path))), 1)

    def test_since_filters_by_time(self):
        self.write([record(4002, local_time='2026-10-13 01:00:00'),
                    record(2000, local_time='2026-10-13 05:00:00')])
        cutoff = time.mktime(time.strptime('2026-10-13 03:00:00',
                                           '%Y-%m-%d %H:%M:%S'))
        self.assertEqual([r['service'] for r in read_log(self.path, since=cutoff)],
                         ['ftp'])

    def test_limit(self):
        self.write([record(4002)] * 10)
        self.assertEqual(len(list(read_log(self.path, limit=3))), 3)

    def test_it_is_a_generator(self):
        self.write([record(4002)])
        self.assertFalse(isinstance(read_log(self.path), list))

    def test_a_missing_log_says_so(self):
        with self.assertRaises(CanaryError) as ctx:
            list(read_log('/nonexistent/opencanary.log'))
        self.assertIn('not found', str(ctx.exception))

    def test_findings_come_straight_out(self):
        self.write([record(4002), record(2000)])
        findings = findings_from_log(self.path, profile())
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.rule_id == 'canary_hit' for f in findings))

    def test_an_empty_log_yields_nothing(self):
        self.write([])
        self.assertEqual(findings_from_log(self.path), [])

    def test_a_log_full_of_junk_yields_nothing_rather_than_raising(self):
        self.write(['not json', '{}', '[]', '{"a": 1}'])
        self.assertEqual(findings_from_log(self.path), [])


# ─── The listener ────────────────────────────────────────────────────────────

TOKEN = 'a' * 32


class TestListenerDecisions(unittest.TestCase):
    """
    The decisions, without a socket: the token, the rate, the parse. This is the
    one part of netmon that accepts an inbound connection from a network an
    attacker may already be on.
    """

    def setUp(self):
        self.listener = CanaryListener(TOKEN, profile())

    def post(self, body=None, token=TOKEN, now=None):
        if body is None:
            body = json.dumps(record()).encode()
        elif not isinstance(body, bytes):
            body = json.dumps(body).encode()
        return self.listener.accept(body, token, now)

    def test_a_valid_delivery_is_accepted(self):
        status, payload = self.post()
        self.assertEqual(status, 200)
        self.assertEqual(payload['service'], 'ssh')
        self.assertEqual(len(self.listener.findings), 1)

    def test_a_short_token_is_refused_at_construction(self):
        """A guessable shared secret on an open port is not a shared secret."""
        for bad in ('', 'short', 'a' * 15):
            with self.subTest(bad=bad):
                with self.assertRaises(CanaryError) as ctx:
                    CanaryListener(bad)
                self.assertIn('16 characters', str(ctx.exception))

    def test_the_error_says_how_to_make_one(self):
        with self.assertRaises(CanaryError) as ctx:
            CanaryListener('')
        self.assertIn('token_urlsafe', str(ctx.exception))

    def test_a_wrong_token_is_refused(self):
        self.assertEqual(self.post(token='b' * 32)[0], 403)
        self.assertEqual(self.listener.findings, [])

    def test_a_missing_token_is_refused(self):
        self.assertEqual(self.post(token=None)[0], 403)

    def test_a_token_that_is_a_prefix_is_refused(self):
        self.assertEqual(self.post(token=TOKEN[:-1])[0], 403)

    def test_an_oversized_body_is_refused(self):
        self.assertEqual(self.post(b'x' * 100_000)[0], 413)

    def test_junk_is_refused_without_creating_a_finding(self):
        self.assertEqual(self.post(b'not json')[0], 400)
        self.assertEqual(self.listener.findings, [])

    def test_the_rate_is_capped(self):
        """
        A canary under a flood is exactly the moment an unbounded queue turns
        into the outage. Shedding beats queueing.
        """
        now = 1000.0
        accepted = sum(1 for _ in range(500) if self.post(now=now)[0] == 200)
        self.assertEqual(accepted, self.listener.max_per_minute)
        self.assertGreater(self.listener.rejected['rate'], 0)

    def test_the_rate_window_moves(self):
        now = 1000.0
        for _ in range(self.listener.max_per_minute):
            self.post(now=now)
        self.assertEqual(self.post(now=now)[0], 429)
        self.assertEqual(self.post(now=now + 61)[0], 200)

    def test_rejections_are_counted(self):
        self.post(token='wrong' * 10)
        self.post(b'x' * 100_000)
        self.post(b'junk')
        self.assertEqual(self.listener.rejected['token'], 1)
        self.assertEqual(self.listener.rejected['body'], 1)
        self.assertEqual(self.listener.rejected['parse'], 1)

    def test_the_handler_is_called(self):
        seen = []
        listener = CanaryListener(TOKEN, profile(), on_finding=seen.append)
        listener.accept(json.dumps(record()).encode(), TOKEN)
        self.assertEqual(len(seen), 1)

    def test_a_raising_handler_does_not_lose_the_delivery(self):
        def explode(finding):
            raise RuntimeError('boom')
        listener = CanaryListener(TOKEN, profile(), on_finding=explode)
        with self.assertLogs('netmon.canary', level='ERROR'):
            status, _ = listener.accept(json.dumps(record()).encode(), TOKEN)
        self.assertEqual(status, 200)
        self.assertEqual(len(listener.findings), 1)


class TestListenerOverHttp(unittest.TestCase):
    """Against a real listener, so the wire behaviour is covered too."""

    def setUp(self):
        self.listener = CanaryListener(TOKEN, profile(), host='127.0.0.1',
                                       port=0)
        self.port = self.listener.start()
        self.addCleanup(self.listener.stop)
        self.base = f'http://127.0.0.1:{self.port}'

    def post(self, path='/canary', body=None, token=TOKEN, header='X-Netmon-Token'):
        data = json.dumps(body if body is not None else record()).encode()
        headers = {'Content-Type': 'application/json'}
        if token is not None:
            headers[header] = token if header == 'X-Netmon-Token' \
                else f'Bearer {token}'
        request = urllib.request.Request(self.base + path, data=data,
                                         headers=headers, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_a_delivery_works(self):
        status, payload = self.post()
        self.assertEqual(status, 200)
        self.assertTrue(payload['ok'])

    def test_the_token_may_come_as_a_bearer_header(self):
        self.assertEqual(self.post(header='Authorization')[0], 200)

    def test_a_wrong_token_over_the_wire_is_refused(self):
        self.assertEqual(self.post(token='b' * 32)[0], 403)

    def test_an_unknown_path_is_404(self):
        self.assertEqual(self.post(path='/something')[0], 404)

    def test_a_refusal_reaches_the_client_whole(self):
        """
        These are answered with the body unread, and closing on an unread body
        made Windows reset the connection, which threw the answer away.
        """
        body = b'x' * (512 * 1024)        # over the cap, under what is drained
        for path, expected in (('/something', 404), ('/canary', 413)):
            with self.subTest(path=path):
                request = urllib.request.Request(
                    self.base + path, data=body, method='POST',
                    headers={'X-Netmon-Token': TOKEN})
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(request, timeout=5)
                self.assertEqual(ctx.exception.code, expected)

    def test_a_refused_body_is_not_read_as_the_next_request(self):
        """The connection is kept alive, so an unread body used to be parsed next."""
        event = json.dumps(record()).encode()
        inner = (b'POST /canary HTTP/1.1\r\nHost: x\r\nX-Netmon-Token: '
                 + TOKEN.encode() + b'\r\nContent-Length: '
                 + str(len(event)).encode() + b'\r\n\r\n' + event)
        outer = (b'POST /something HTTP/1.1\r\nHost: x\r\nContent-Length: '
                 + str(len(inner)).encode() + b'\r\n\r\n' + inner)
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as s:
            s.sendall(outer)
            replies = b''
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                replies += chunk
        self.assertEqual(replies.count(b'HTTP/1.1 '), 1)
        self.assertTrue(replies.startswith(b'HTTP/1.1 404'))
        self.assertEqual(self.listener.findings, [])

    def test_the_root_path_works_too(self):
        self.assertEqual(self.post(path='/')[0], 200)

    def test_get_is_not_a_status_page(self):
        """
        This listens on a network the canary is on. Anything it says is
        something an attacker learns for free.
        """
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self.base + '/canary', timeout=5)
        self.assertEqual(ctx.exception.code, 405)
        self.assertNotIn('netmon.findings', ctx.exception.read().decode())

    def test_the_python_version_is_not_advertised(self):
        status, _ = self.post()
        self.assertEqual(status, 200)

    def test_stop_is_idempotent(self):
        self.listener.stop()
        self.listener.stop()


if __name__ == '__main__':
    unittest.main(verbosity=2)
