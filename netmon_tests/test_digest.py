"""
The daily digest, and the day's findings behind it.
===================================================
What was wrong before this file existed:

- The digest listed what happened and nothing about what was still waiting:
  no unanswered pushes, no standing configuration problems, no silences.
- Acknowledged and maintenance findings looked exactly like the rest, because
  `build_digest` never read `finding.silenced`.
- "events" was the number of capture files.
- The day's findings lived in memory, so a restart lost them.
- A fresh analyzer per capture file meant a recurring finding pushed again on
  every rotation.
- There was no email digest.

No network: SMTP is a fake with the same calls as smtplib.
"""

import json
import os
import shutil
import ssl
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import _test_support  # noqa: E402,F401

from netmon import alerting  # noqa: E402
from netmon.alerting import (AlertingError, EmailConfig, build_digest,  # noqa: E402
                             load_email_config, send_email_digest)
from netmon.events import Event, Finding  # noqa: E402
from netmon.service import Service, ServiceConfig  # noqa: E402
from netmon.silence import Silences  # noqa: E402
from netmon.window import FindingWindow  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')


def finding(rule='bacnet_control', device='ahu-controller-1', key='k',
            severity='critical', tier='push', count=1):
    event = Event(kind='bacnet', ts=1000.0, src_ip='10.10.60.50',
                  dst_ip='10.10.20.21', src_mac='00:11:22:00:00:40')
    event.fields.update({'src_vlan': 60, 'dst_vlan': 20, 'src_name':
                         'ops-workstation', 'payload': b'never kept'})
    return Finding(rule, 'A BACnet command', severity=severity, tier=tier,
                   description=f'{rule} on {device}', device=device, key=key,
                   event=event, count=count, evidence={'service': 'WriteProperty'})


class _Clock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


class _Case(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-digest-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.path = os.path.join(self.scratch, 'findings.json')
        self.clock = _Clock()

    def window(self):
        return FindingWindow(self.path, clock=self.clock)


# ─── The window ──────────────────────────────────────────────────────────────

class TestAdmission(_Case):

    def test_the_first_of_an_identity_is_new(self):
        self.assertTrue(self.window().admit(finding()))

    def test_a_repeat_is_counted_not_admitted(self):
        """The same finding from the next capture file."""
        window = self.window()
        self.assertTrue(window.admit(finding()))
        self.assertFalse(window.admit(finding(count=3)))
        self.assertEqual(len(window), 1)
        self.assertEqual(window.findings()[0].count, 4)

    def test_a_different_key_is_a_different_finding(self):
        window = self.window()
        window.admit(finding(key='a'))
        self.assertTrue(window.admit(finding(key='b')))

    def test_the_window_is_bounded(self):
        window = FindingWindow(self.path, cap=10, clock=self.clock)
        for n in range(50):
            window.admit(finding(key=str(n)))
        self.assertEqual(len(window), 10)


class TestRestarts(_Case):

    def test_the_days_findings_survive_a_restart(self):
        first = self.window()
        first.admit(finding())
        first.admit(finding())
        first.add_events(5000)
        first.save()
        second = self.window()
        self.assertTrue(second.loaded)
        self.assertEqual(len(second), 1)
        self.assertEqual(second.findings()[0].count, 2)
        self.assertEqual(second.events, 5000)

    def test_a_repeat_after_a_restart_is_still_a_repeat(self):
        first = self.window()
        first.admit(finding())
        first.save()
        self.assertFalse(self.window().admit(finding()))

    def test_what_is_kept_is_enough_to_redact_and_never_a_payload(self):
        first = self.window()
        first.admit(finding())
        first.save()
        with open(self.path, encoding='utf-8') as handle:
            text = handle.read()
        self.assertNotIn('never kept', text)
        self.assertNotIn('payload', text)
        restored = self.window().findings()[0]
        self.assertEqual(restored.event.get('src_vlan'), 60)
        self.assertEqual(restored.event.src_ip, '10.10.60.50')
        self.assertEqual(restored.evidence, {'service': 'WriteProperty'})

    def test_a_damaged_file_is_an_empty_window(self):
        with open(self.path, 'w', encoding='utf-8') as handle:
            handle.write('{"entries": [{"nonsense": 1}]}')
        window = self.window()
        self.assertFalse(window.loaded)
        self.assertEqual(len(window), 0)

    def test_the_file_is_owner_only(self):
        window = self.window()
        window.admit(finding())
        window.save()
        if os.name == 'nt':
            self.skipTest('POSIX permission model only')
        self.assertEqual(os.stat(self.path).st_mode & 0o077, 0)


class TestOpenPushes(_Case):

    def test_an_unanswered_push_carries_over_the_digest(self):
        window = self.window()
        item = finding()
        window.admit(item)
        window.mark_pushed(item)
        window.rollover()
        self.assertEqual(len(window), 0)
        self.assertEqual(len(window.open_items()['pushes']), 1)

    def test_and_does_not_push_again_while_open(self):
        window = self.window()
        item = finding()
        window.admit(item)
        window.mark_pushed(item)
        window.rollover()
        self.assertFalse(window.admit(finding()))
        self.assertEqual(window.open_items()['pushes'][0]['count'], 2)

    def test_an_ack_answers_it(self):
        silences = Silences(os.path.join(self.scratch, 's.json'),
                            clock=self.clock)
        window = self.window()
        item = finding()
        window.admit(item)
        window.mark_pushed(item)
        silences.add('ack', 'bacnet_control', 'ahu-controller-1', 'k')
        self.assertEqual(window.open_items(silences)['pushes'], [])

    def test_one_not_seen_for_a_week_goes(self):
        window = self.window()
        item = finding()
        window.admit(item)
        window.mark_pushed(item)
        self.clock.now += 8 * 86400
        self.assertEqual(window.open_items()['pushes'], [])
        window.rollover()
        self.assertTrue(window.admit(finding()))


# ─── The digest text ─────────────────────────────────────────────────────────

class _View:
    def __init__(self, findings, events=4321):
        self.findings = findings
        self.events_seen = events

    def by_severity(self):
        return list(self.findings)

    def report(self):
        return {'events': self.events_seen, 'findings': len(self.findings)}


class TestTheDigest(unittest.TestCase):

    def test_acknowledged_and_maintenance_findings_are_marked(self):
        acked, maintained, plain = (finding(key='a'), finding(key='b'),
                                    finding(key='c'))
        acked.silenced = {'kind': 'ack', 'id': '1', 'reason': 'commissioning'}
        maintained.silenced = {'kind': 'maintenance', 'id': '2', 'reason': ''}
        text = build_digest(_View([acked, maintained, plain]))
        self.assertIn('[acknowledged: commissioning]', text)
        self.assertIn('[maintenance]', text)
        self.assertIn('2 acknowledged or under maintenance', text)

    def test_the_checklist_leads(self):
        open_items = {
            'pushes': [{'rule': 'bacnet_control', 'severity': 'critical',
                        'description': 'a write', 'first_pushed': 1e9,
                        'count': 3}],
            'standing': [{'rule': 'vlan_leak', 'description': 'trunk carries all'}],
            'silences': [{'id': 'ab12', 'kind': 'maintenance',
                          'device': 'chiller-controller', 'until': None,
                          'reason': 'vendor on site'}],
        }
        text = build_digest(_View([finding()]), open_items=open_items)
        self.assertIn('Open items', text)
        self.assertLess(text.index('Open items'), text.index('CRITICAL  bacnet'))
        self.assertIn('[ ] CRITICAL bacnet_control — a write', text)
        self.assertIn('seen 3 times', text)
        self.assertIn('[ ] vlan_leak — trunk carries all', text)
        self.assertIn('maintenance device=chiller-controller until cleared '
                      '— vendor on site', text)

    def test_an_empty_checklist_says_so(self):
        text = build_digest(_View([]), open_items={'pushes': [], 'standing': [],
                                                   'silences': []})
        self.assertIn('[x] nothing waiting', text)


# ─── The service ─────────────────────────────────────────────────────────────

class _Notifier:
    """Pushes what it is given and records it; captures the digest."""

    def __init__(self, fail_digest=False):
        self.pushed = []
        self.digests = []
        self.fail_digest = fail_digest

    def send(self, findings):
        self.pushed.extend(findings)
        return list(findings), []

    def send_digest(self, analyzer, title=None, open_items=None, body=None):
        if self.fail_digest:
            raise AlertingError('unreachable')
        self.digests.append(body)
        return True


class _ServiceCase(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-digestsvc-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.state = os.path.join(self.scratch, 'state')

    def service(self, notifier=None):
        config = ServiceConfig(profile_path=EXAMPLE, state_dir=self.state,
                               notify=False)
        config.web_port = None
        service = Service(config, clock=lambda: 1_000_000.0)
        service.notifier = notifier
        return service


class TestServiceDeduplication(_ServiceCase):

    def test_a_recurring_finding_pushes_once_across_capture_files(self):
        """Each file got a fresh analyzer, so each rotation pushed it again."""
        notifier = _Notifier()
        service = self.service(notifier)
        for _ in range(4):                      # four rotated files
            service.deliver([finding()])
        self.assertEqual(len(notifier.pushed), 1)
        self.assertEqual(service.recent[0].count, 4)
        self.assertEqual(service.counts['repeats'], 3)

    def test_or_across_a_restart(self):
        notifier = _Notifier()
        self.service(notifier).deliver([finding()])
        again = _Notifier()
        restarted = self.service(again)
        restarted.deliver([finding()])
        self.assertEqual(again.pushed, [])
        self.assertEqual(len(restarted.recent), 1)

    def test_the_days_findings_survive_a_restart(self):
        self.service().deliver([finding(key='a'), finding(key='b')])
        self.assertEqual(len(self.service().recent), 2)


class TestServiceDigest(_ServiceCase):

    def test_the_digest_has_the_checklist_marks_and_true_count(self):
        notifier = _Notifier()
        service = self.service(notifier)
        service.window.add_events(98765)
        service.window.set_standing([{'rule': 'vlan_leak', 'key': 'p1',
                                      'description': 'trunk carries every VLAN'}])
        service.deliver([finding(key='pushed')])
        acked = finding(key='acked', tier='digest', severity='medium')
        service.silences.add('ack', 'bacnet_control', 'ahu-controller-1', 'acked',
                             reason='known')
        service.deliver([acked])
        service.silences.add('maintenance', device='chiller-controller',
                             reason='vendor on site')

        self.assertTrue(service.send_digest())
        body = notifier.digests[0]
        self.assertIn('98765 events', body)
        self.assertIn('Open items', body)
        self.assertIn('trunk carries every VLAN', body)
        self.assertIn('Pushed and not yet acknowledged (1)', body)
        self.assertIn('[acknowledged: known]', body)
        self.assertIn('vendor on site', body)

    def test_a_delivered_digest_starts_a_new_window(self):
        notifier = _Notifier()
        service = self.service(notifier)
        service.window.add_events(10)
        service.deliver([finding()])
        service.send_digest()
        self.assertEqual(service.recent, [])
        self.assertEqual(service.window.events, 0)
        # The push is still open, so it is still on tomorrow's checklist.
        self.assertIn('Pushed and not yet acknowledged (1)', service.digest_body())

    def test_a_failed_digest_keeps_the_window(self):
        service = self.service(_Notifier(fail_digest=True))
        service.deliver([finding()])
        self.assertFalse(service.send_digest())
        self.assertEqual(len(service.recent), 1)

    def test_snoozed_findings_stay_out_of_the_digest(self):
        notifier = _Notifier()
        service = self.service(notifier)
        service.deliver([finding(key='x', tier='digest', severity='low')])
        service.silences.add('snooze', rule='bacnet_control',
                             until=time.time() + 3600)
        service.send_digest()
        # Neither in the findings nor as an open push: the snooze answers it.
        self.assertNotIn('bacnet_control on ahu-controller-1', notifier.digests[0])
        self.assertIn('snooze rule=bacnet_control', notifier.digests[0])


# ─── Email ───────────────────────────────────────────────────────────────────

class _SMTP:
    """The calls smtplib.SMTP and SMTP_SSL take, recorded."""
    made = []

    def __init__(self, security, host, port, timeout, context):
        self.security, self.host, self.port = security, host, port
        self.timeout, self.context = timeout, context
        self.calls = []
        self.messages = []
        _SMTP.made.append(self)

    def ehlo(self):
        self.calls.append('ehlo')

    def starttls(self, context=None):
        self.calls.append('starttls')
        self.tls_context = context

    def login(self, username, password):
        self.calls.append(('login', username))

    def send_message(self, message):
        self.calls.append('send')
        self.messages.append(message)

    def quit(self):
        self.calls.append('quit')


def email(**overrides):
    settings = dict(host='smtp.example.test', security='starttls',
                    username='sensor@example.test', password='not-a-real-one',
                    sender='sensor@example.test', recipients=['ops@example.test'])
    settings.update(overrides)
    return EmailConfig(**settings)


class TestEmail(unittest.TestCase):

    def setUp(self):
        _SMTP.made = []

    def test_starttls_then_login_then_send(self):
        send_email_digest(email(), 'the body', 'Site — daily report',
                          smtp_factory=_SMTP)
        smtp = _SMTP.made[0]
        self.assertEqual((smtp.host, smtp.port), ('smtp.example.test', 587))
        self.assertEqual(smtp.calls, ['ehlo', 'starttls', 'ehlo',
                                      ('login', 'sensor@example.test'),
                                      'send', 'quit'])
        self.assertIsInstance(smtp.tls_context, ssl.SSLContext)
        self.assertEqual(smtp.tls_context.verify_mode, ssl.CERT_REQUIRED)
        message = smtp.messages[0]
        self.assertEqual(message['To'], 'ops@example.test')
        self.assertEqual(message['Subject'], 'Site — daily report')
        self.assertIn('the body', message.get_content())

    def test_smtps_uses_port_465_and_no_starttls(self):
        send_email_digest(email(security='ssl'), 'b', 's', smtp_factory=_SMTP)
        smtp = _SMTP.made[0]
        self.assertEqual((smtp.security, smtp.port), ('ssl', 465))
        self.assertNotIn('starttls', smtp.calls)

    def test_plain_smtp_to_another_host_is_refused(self):
        with self.assertRaises(AlertingError) as ctx:
            send_email_digest(email(security='none'), 'b', 's',
                              smtp_factory=_SMTP)
        self.assertIn('unencrypted', str(ctx.exception))
        self.assertEqual(_SMTP.made, [])

    def test_credentials_are_never_sent_without_tls(self):
        with self.assertRaises(AlertingError):
            send_email_digest(email(security='none', host='localhost'), 'b', 's',
                              smtp_factory=_SMTP)

    def test_a_local_relay_without_credentials_is_allowed(self):
        send_email_digest(email(security='none', host='localhost', username='',
                                password=''), 'b', 's', smtp_factory=_SMTP)
        self.assertNotIn('starttls', _SMTP.made[0].calls)

    def test_a_newline_in_the_subject_cannot_add_headers(self):
        send_email_digest(email(), 'b', 'Site\r\nBcc: someone@evil.example',
                          smtp_factory=_SMTP)
        message = _SMTP.made[0].messages[0]
        self.assertIsNone(message['Bcc'])

    def test_an_address_with_a_newline_is_refused(self):
        with self.assertRaises(AlertingError):
            email(recipients=['ops@example.test\r\nBcc: x@evil.example']).validate()

    def test_a_failure_names_only_its_kind(self):
        import smtplib

        class _Refusing(_SMTP):
            def login(self, username, password):
                raise smtplib.SMTPAuthenticationError(535, b'password was hunter2')

        with self.assertRaises(AlertingError) as ctx:
            send_email_digest(email(), 'b', 's', smtp_factory=_Refusing)
        self.assertNotIn('hunter2', str(ctx.exception))
        self.assertIn('SMTPAuthenticationError', str(ctx.exception))

    def test_describe_never_includes_the_password(self):
        self.assertNotIn('not-a-real-one', json.dumps(email().describe()))

    def test_recipients_may_be_a_string(self):
        self.assertEqual(EmailConfig(recipients='a@x.test, b@x.test').recipients,
                         ['a@x.test', 'b@x.test'])


class TestEmailSettings(unittest.TestCase):
    """From the secrets file, under its owner-only check."""

    def setUp(self):
        if os.name == 'nt':
            self.skipTest('POSIX permission model only')
        self.scratch = tempfile.mkdtemp(prefix='netmon-smtp-')
        self.addCleanup(shutil.rmtree, self.scratch, True)

    def write(self, data, mode=0o600):
        path = os.path.join(self.scratch, 'secrets.json')
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump(data, handle)
        os.chmod(path, mode)
        return path

    def test_the_settings_are_read(self):
        config = load_email_config(self.write({
            'smtp_host': 'smtp.example.test', 'smtp_port': 2587,
            'smtp_username': 'u@example.test', 'smtp_password': 'p',
            'smtp_from': 'u@example.test', 'smtp_to': ['ops@example.test']}),
            environ={})
        self.assertEqual((config.host, config.port), ('smtp.example.test', 2587))
        self.assertTrue(config.configured)

    def test_a_loose_secrets_file_is_refused(self):
        with self.assertRaises(AlertingError):
            load_email_config(self.write({'smtp_host': 'h'}, mode=0o644),
                              environ={})

    def test_no_smtp_host_means_no_email(self):
        self.assertIsNone(load_email_config(self.write({'ntfy_topic': 't'}),
                                            environ={}))


class TestServiceEmail(_ServiceCase):

    def test_the_digest_is_emailed(self):
        _SMTP.made = []
        service = self.service()
        service.email = email()
        service.deliver([finding()])
        with mock.patch.object(alerting, '_smtp', _SMTP):
            self.assertTrue(service.send_digest())
        sent = _SMTP.made[0].messages[0]
        self.assertIn('Open items', sent.get_content())
        self.assertIn('daily report', sent['Subject'])

    def test_email_alone_is_enough_for_a_digest_to_be_due(self):
        service = self.service()
        service.email = email()
        self.assertFalse(service._due_for_digest(1_000_000.0))   # schedules it
        self.assertTrue(service._due_for_digest(1_000_000.0 + 2 * 86400))

    def test_one_channel_failing_does_not_stop_the_other(self):
        _SMTP.made = []
        service = self.service(_Notifier(fail_digest=True))
        service.email = email()
        service.deliver([finding()])
        with mock.patch.object(alerting, '_smtp', _SMTP):
            self.assertTrue(service.send_digest())
        self.assertEqual(len(_SMTP.made), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
