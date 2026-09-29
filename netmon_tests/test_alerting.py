"""
Getting findings to a person.
==============================
No network. The HTTP call is injected, so tests exercise the real body-building,
the real headers and the real refusals — which is where the bugs are — without
depending on a server being up.

Three things this file is really about: that an open ntfy topic is refused, that
a secrets file with loose permissions is refused, and that a device name from
the network cannot inject HTTP headers.
"""

import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.alerting import (AlertingError, Notifier, NotifierConfig,  # noqa: E402
                             build_digest, load_config)
from netmon.events import Event, Finding, Severity, Tier  # noqa: E402
from netmon.profile import load_profile  # noqa: E402
from netmon.redact import audit  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')


def finding(rule='bacnet_control', severity=Severity.CRITICAL, tier=Tier.PUSH,
            description='something happened', device='ahu-controller-1',
            evidence=None, count=1, src_ip='10.10.20.21', vlan=20):
    event = Event(kind='bacnet', src_ip=src_ip, dst_ip='10.10.20.10', vlan=vlan)
    event.fields['src_vlan'] = vlan
    item = Finding(rule, 'A BACnet command outside the allowlist',
                   severity=severity, tier=tier, description=description,
                   device=device, event=event, evidence=evidence or {})
    item.count = count
    return item


class _Recorder:
    """Stands in for the HTTP call, keeping what would have gone out."""

    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def __call__(self, url, body, headers, timeout):
        self.calls.append({'url': url, 'body': body.decode('utf-8'),
                           'headers': dict(headers), 'timeout': timeout})
        if self.fail:
            raise OSError('connection refused')
        return 200


# ─── Refusing to publish where anyone can read ───────────────────────────────

class TestOpenTopicsAreRefused(unittest.TestCase):
    """
    ntfy's public server has no access control on a topic: anyone who guesses
    the name receives everything, forever. These alerts name devices, addresses
    and weaknesses — publishing them to a guessable string is a live feed of the
    site's soft spots.
    """

    def test_the_public_server_without_a_token_is_refused(self):
        config = NotifierConfig(server='https://ntfy.sh', topic='my-site')
        with self.assertRaises(AlertingError) as ctx:
            config.validate()
        self.assertIn('public', str(ctx.exception))

    def test_the_refusal_says_what_to_do_instead(self):
        config = NotifierConfig(server='https://ntfy.sh', topic='x')
        with self.assertRaises(AlertingError) as ctx:
            config.validate()
        message = str(ctx.exception)
        self.assertIn('access token', message)
        self.assertIn('host your own', message)

    def test_the_public_server_with_a_token_is_fine(self):
        NotifierConfig(server='https://ntfy.sh', topic='x',
                       token='tk_abc').validate()

    def test_a_self_hosted_server_needs_no_token(self):
        NotifierConfig(server='https://ntfy.internal.example', topic='x').validate()

    def test_a_token_over_plain_http_is_refused(self):
        with self.assertRaises(AlertingError) as ctx:
            NotifierConfig(server='http://ntfy.example', topic='x',
                           token='tk').validate()
        self.assertIn('http', str(ctx.exception))

    def test_plain_http_without_a_token_is_allowed(self):
        """A server reachable only on the management network is a real setup."""
        NotifierConfig(server='http://ntfy.internal', topic='x').validate()

    def test_missing_server_or_topic_is_refused(self):
        for config in (NotifierConfig(topic='x'),
                       NotifierConfig(server='https://a.example')):
            with self.subTest(config=config.describe()):
                with self.assertRaises(AlertingError):
                    config.validate()

    def test_disabled_alerting_validates(self):
        NotifierConfig(enabled=False).validate()


# ─── Secrets ─────────────────────────────────────────────────────────────────

class TestSecrets(unittest.TestCase):

    def write_secrets(self, data, mode=0o600):
        handle, path = tempfile.mkstemp(suffix='.json')
        with os.fdopen(handle, 'w') as f:
            json.dump(data, f)
        os.chmod(path, mode)
        self.addCleanup(os.unlink, path)
        return path

    def test_a_secrets_file_is_read(self):
        path = self.write_secrets({'ntfy_server': 'https://a.example',
                                   'ntfy_topic': 't', 'ntfy_token': 'tk'})
        config = load_config(path, environ={})
        self.assertEqual(config.server, 'https://a.example')
        self.assertEqual(config.token, 'tk')

    def test_a_group_readable_secrets_file_is_refused(self):
        """A secrets file everyone can read is not a secrets file."""
        path = self.write_secrets({'ntfy_token': 'tk'}, mode=0o640)
        with self.assertRaises(AlertingError) as ctx:
            load_config(path, environ={})
        self.assertIn('chmod 600', str(ctx.exception))

    def test_a_world_readable_secrets_file_is_refused(self):
        path = self.write_secrets({'ntfy_token': 'tk'}, mode=0o644)
        with self.assertRaises(AlertingError):
            load_config(path, environ={})

    def test_the_error_does_not_echo_the_file(self):
        """The message about a broken secrets file must not quote it."""
        handle, path = tempfile.mkstemp(suffix='.json')
        with os.fdopen(handle, 'w') as f:
            f.write('{"ntfy_token": "tk_verysecret", broken')
        os.chmod(path, 0o600)
        self.addCleanup(os.unlink, path)
        with self.assertRaises(AlertingError) as ctx:
            load_config(path, environ={})
        self.assertNotIn('tk_verysecret', str(ctx.exception))

    def test_the_environment_wins_over_the_file(self):
        """So a unit file or a container can set it without editing disk."""
        path = self.write_secrets({'ntfy_token': 'from-file'})
        config = load_config(path, environ={'NETMON_NTFY_TOKEN': 'from-env'})
        self.assertEqual(config.token, 'from-env')

    def test_the_environment_alone_is_enough(self):
        config = load_config(None, environ={
            'NETMON_NTFY_SERVER': 'https://a.example', 'NETMON_NTFY_TOPIC': 't'})
        self.assertEqual(config.topic, 't')

    def test_a_missing_secrets_file_says_so(self):
        with self.assertRaises(AlertingError) as ctx:
            load_config('/nonexistent/secrets.json', environ={})
        self.assertIn('not found', str(ctx.exception))

    def test_describe_never_includes_the_token(self):
        config = NotifierConfig(server='https://a.example', topic='t',
                                token='tk_verysecret')
        self.assertNotIn('tk_verysecret', json.dumps(config.describe()))
        self.assertTrue(config.describe()['authenticated'])

    def test_alerting_can_be_disabled_by_environment(self):
        config = load_config(None, environ={'NETMON_ALERTS_ENABLED': 'false'})
        self.assertFalse(config.enabled)


# ─── Sending ─────────────────────────────────────────────────────────────────

class _SendCase(unittest.TestCase):

    def setUp(self):
        self.profile = load_profile(EXAMPLE)
        self.recorder = _Recorder()
        self.config = NotifierConfig(server='https://ntfy.internal',
                                     topic='occ-alerts')
        self.notifier = Notifier(self.config, self.profile, opener=self.recorder)


class TestSending(_SendCase):

    def test_a_push_finding_is_sent(self):
        sent, skipped = self.notifier.send([finding()])
        self.assertEqual(len(sent), 1)
        self.assertEqual(len(self.recorder.calls), 1)

    def test_the_url_is_the_server_and_topic(self):
        self.notifier.send([finding()])
        self.assertEqual(self.recorder.calls[0]['url'],
                         'https://ntfy.internal/occ-alerts')

    def test_a_digest_finding_is_not_pushed(self):
        """A notification for something that can wait is how push gets muted."""
        sent, skipped = self.notifier.send([finding(tier=Tier.DIGEST)])
        self.assertEqual(sent, [])
        self.assertEqual(len(skipped), 1)
        self.assertEqual(self.recorder.calls, [])

    def test_a_low_severity_push_is_held_back(self):
        sent, _ = self.notifier.send([finding(severity=Severity.LOW)])
        self.assertEqual(sent, [])

    def test_the_severity_floor_is_configurable(self):
        self.config.min_push_severity = Severity.MEDIUM
        sent, _ = self.notifier.send([finding(severity=Severity.MEDIUM)])
        self.assertEqual(len(sent), 1)

    def test_priority_follows_severity(self):
        self.notifier.send([finding(severity=Severity.CRITICAL)])
        self.assertEqual(self.recorder.calls[0]['headers']['Priority'], '5')

    def test_the_token_is_sent_as_a_bearer_header(self):
        self.config.token = 'tk_abc'
        self.notifier.send([finding()])
        self.assertEqual(self.recorder.calls[0]['headers']['Authorization'],
                         'Bearer tk_abc')

    def test_the_kept_record_does_not_include_the_token(self):
        """This notifier keeps what it sent; that record must not hold a secret."""
        self.config.token = 'tk_verysecret'
        self.notifier.send([finding()])
        self.assertNotIn('tk_verysecret', json.dumps(self.notifier.sent))

    def test_disabled_alerting_sends_nothing(self):
        self.config.enabled = False
        sent, skipped = self.notifier.send([finding()])
        self.assertEqual(sent, [])
        self.assertEqual(self.recorder.calls, [])

    def test_dry_run_records_without_sending(self):
        self.config.dry_run = True
        sent, _ = self.notifier.send([finding()])
        self.assertEqual(len(sent), 1)
        self.assertEqual(self.recorder.calls, [])
        self.assertEqual(len(self.notifier.sent), 1)

    def test_a_delivery_failure_is_reported_not_raised(self):
        """One unreachable server must not stop the rest of the run."""
        notifier = Notifier(self.config, self.profile, opener=_Recorder(fail=True))
        with self.assertLogs('netmon.alerting', level='ERROR') as logs:
            sent, skipped = notifier.send([finding(), finding(device='b')])
        self.assertEqual(len(logs.output), 2)
        self.assertEqual(sent, [])
        self.assertEqual(len(skipped), 2)
        self.assertEqual(len(notifier.failures), 2)


class TestMessageContent(_SendCase):

    def body(self, item):
        self.notifier.send([item])
        return self.recorder.calls[0]['body']

    def test_it_carries_the_description(self):
        self.assertIn('something happened', self.body(finding()))

    def test_it_carries_the_device_context(self):
        """
        An alert saying 10.10.20.21 makes someone go and look it up. The
        profile already knows the role, VLAN and zone.
        """
        body = self.body(finding())
        self.assertIn('controller', body)
        self.assertIn('building-automation', body)

    def test_it_carries_the_next_check(self):
        item = finding()
        item.next_check = 'tshark -r capture.pcap -Y bacapp'
        self.assertIn('next: tshark', self.body(item))

    def test_it_says_how_many_times(self):
        self.assertIn('seen 1017 times', self.body(finding(count=1017)))

    def test_a_single_occurrence_says_nothing_about_counts(self):
        self.assertNotIn('seen 1 times', self.body(finding()))

    def test_evidence_is_included(self):
        body = self.body(finding(evidence={'service': 'WriteProperty',
                                           'object': 'analog-value-7'}))
        self.assertIn('service=WriteProperty', body)

    def test_a_credential_value_never_reaches_the_body(self):
        body = self.body(finding(evidence={'credential_type': 'http-basic',
                                           'credential_value': 'hunter2'}))
        self.assertIn('http-basic', body)
        self.assertNotIn('hunter2', body)

    def test_the_whole_message_audits_clean(self):
        body = self.body(finding(evidence={
            'credential_type': 'http-basic', 'credential_value': 'hunter2',
            'cookie': 'JSESSIONID=abc123'}))
        self.assertEqual(audit(body), [])


class TestHeaderInjection(_SendCase):
    """
    The title header carries a device name, and device names come from the
    network. A hostname with a newline in it would otherwise inject headers.
    """

    def title_for(self, text):
        item = finding()
        item.title = text
        self.notifier.send([item])
        return self.recorder.calls[0]['headers']['Title']

    def test_newlines_are_stripped(self):
        title = self.title_for('normal\r\nPriority: 5\r\nX-Injected: yes')
        self.assertNotIn('\n', title)
        self.assertNotIn('\r', title)

    def test_the_injected_header_does_not_become_a_header(self):
        self.notifier.send([finding()])
        headers = self.recorder.calls[0]['headers']
        self.assertNotIn('X-Injected', headers)

    def test_non_ascii_is_removed_rather_than_encoded(self):
        """Latin-1 header encoding would mangle it; dropping it is honest."""
        title = self.title_for('café — контроллер')
        self.assertTrue(all(ord(c) < 128 for c in title))

    def test_a_very_long_title_is_truncated(self):
        self.assertLessEqual(len(self.title_for('x' * 5000)), 200)

    def test_an_empty_title_still_produces_one(self):
        self.assertTrue(self.title_for(''))


# ─── The digest ──────────────────────────────────────────────────────────────

class _Analyzer:
    def __init__(self, findings, events=1000, suppressed=0):
        self.findings = findings
        self.events_seen = events
        self._suppressed = suppressed

    def by_severity(self):
        return sorted(self.findings, key=lambda f: -Severity.rank(f.severity))

    def report(self):
        by_severity = {}
        for item in self.findings:
            by_severity[item.severity] = by_severity.get(item.severity, 0) + 1
        return {'events': self.events_seen, 'findings': len(self.findings),
                'by_severity': by_severity,
                'suppressed_repeats': self._suppressed}


class TestDigest(unittest.TestCase):

    def setUp(self):
        self.profile = load_profile(EXAMPLE)

    def test_an_empty_digest_does_not_claim_an_all_clear(self):
        text = build_digest(_Analyzer([]), self.profile)
        self.assertIn('Nothing found', text)
        self.assertIn('covered the VLANs', text)

    def test_it_groups_by_rule(self):
        findings = [finding(rule='bacnet_control', device=f'ahu-{n}')
                    for n in range(3)]
        text = build_digest(_Analyzer(findings), self.profile)
        self.assertEqual(text.count('bacnet_control'), 1)
        self.assertIn('3 devices', text)

    def test_worst_first(self):
        findings = [finding(rule='low_one', severity=Severity.LOW),
                    finding(rule='critical_one', severity=Severity.CRITICAL)]
        text = build_digest(_Analyzer(findings), self.profile)
        self.assertLess(text.index('critical_one'), text.index('low_one'))

    def test_counts_are_the_true_counts(self):
        text = build_digest(_Analyzer([finding(count=1017)]), self.profile)
        self.assertIn('1017', text)

    def test_it_reports_what_was_collapsed(self):
        text = build_digest(_Analyzer([finding()], suppressed=340), self.profile)
        self.assertIn('340 repeats collapsed', text)

    def test_long_groups_are_summarised(self):
        findings = [finding(device=f'device-{n}') for n in range(20)]
        text = build_digest(_Analyzer(findings), self.profile)
        self.assertIn('and 14 more', text)

    def test_it_is_capped(self):
        findings = [finding(rule=f'rule-{n}') for n in range(100)]
        text = build_digest(_Analyzer(findings), self.profile, limit=10)
        self.assertIn('90 further findings', text)

    def test_the_digest_audits_clean(self):
        findings = [finding(evidence={'credential_value': 'hunter2',
                                      'cookie': 'JSESSIONID=abc123'})]
        self.assertEqual(audit(build_digest(_Analyzer(findings), self.profile)), [])

    def test_sending_a_digest_uses_the_digest_topic(self):
        recorder = _Recorder()
        config = NotifierConfig(server='https://ntfy.internal', topic='alerts',
                               digest_topic='reports')
        notifier = Notifier(config, self.profile, opener=recorder)
        notifier.send_digest(_Analyzer([finding()]))
        self.assertEqual(recorder.calls[0]['url'], 'https://ntfy.internal/reports')

    def test_a_digest_is_sent_at_low_priority(self):
        recorder = _Recorder()
        notifier = Notifier(NotifierConfig(server='https://ntfy.internal',
                                           topic='t'), self.profile,
                            opener=recorder)
        notifier.send_digest(_Analyzer([finding()]))
        self.assertEqual(recorder.calls[0]['headers']['Priority'], '2')


if __name__ == '__main__':
    unittest.main(verbosity=2)
