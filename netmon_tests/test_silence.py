"""
Acknowledge, snooze, maintenance.

Mostly about the edges: an ack covers exactly one finding, a snooze must end,
nothing silences everything, and an unreadable store errs towards noise.
"""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.alerting import Notifier, NotifierConfig  # noqa: E402
from netmon.events import Event, Finding, Tier  # noqa: E402
from netmon.silence import SilenceError, Silences, _main  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')
RULES = os.path.join(ROOT, 'netmon', 'rules')
NOW = 1_800_000_000.0


def finding(rule='bacnet_control', device='ahu-controller-1', key='k1',
            src_ip='10.10.60.50', src_name='ops-workstation'):
    event = Event(kind='bacnet', src_ip=src_ip, dst_ip='10.10.20.21', ts=NOW)
    event.fields['src_name'] = src_name
    return Finding(rule, 'A write', severity='critical', tier=Tier.PUSH,
                   description='something', device=device, key=key,
                   event=event, ts=NOW)


class _Case(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-silence-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.path = os.path.join(self.scratch, 'state', 'silences.json')
        self.now = [NOW]
        self.store = Silences(self.path, clock=lambda: self.now[0])

    def later(self, seconds):
        self.now[0] += seconds


class TestAck(_Case):

    def test_it_holds_back_that_finding_but_keeps_it_for_the_digest(self):
        self.store.add('ack', 'bacnet_control', 'ahu-controller-1', 'k1')
        self.assertEqual(self.store.decide(finding()), 'digest')

    def test_it_covers_exactly_one_finding(self):
        self.store.add('ack', 'bacnet_control', 'ahu-controller-1', 'k1')
        for other in (finding(key='k2'), finding(device='ahu-controller-2'),
                      finding(rule='bacnet_topology')):
            with self.subTest(other=(other.rule_id, other.device, other.key)):
                self.assertEqual(self.store.decide(other), 'push')

    def test_it_needs_a_rule_and_a_device(self):
        for rule, device in (('', 'x'), ('r', ''), ('', '')):
            with self.assertRaises(SilenceError):
                self.store.add('ack', rule, device)

    def test_it_lapses_after_thirty_days_by_default(self):
        self.store.add('ack', 'bacnet_control', 'ahu-controller-1', 'k1')
        self.later(31 * 86400)
        self.assertEqual(self.store.decide(finding()), 'push')

    def test_the_finding_is_marked(self):
        entry = self.store.add('ack', 'bacnet_control', 'ahu-controller-1', 'k1',
                               reason='known')
        item = finding()
        self.store.decide(item)
        self.assertEqual(item.silenced['id'], entry['id'])


class TestSnooze(_Case):

    def test_by_rule(self):
        self.store.add('snooze', rule='bacnet_control', until=NOW + 3600)
        self.assertEqual(self.store.decide(finding()), 'drop')
        self.assertEqual(self.store.decide(finding(rule='new_device')), 'push')

    def test_by_the_device_the_finding_is_about(self):
        self.store.add('snooze', device='AHU-Controller-1', until=NOW + 3600)
        self.assertEqual(self.store.decide(finding()), 'drop')

    def test_by_the_source_name_address_or_mac(self):
        for device in ('ops-workstation', '10.10.60.50'):
            with self.subTest(device=device):
                store = Silences(os.path.join(self.scratch, device, 's.json'),
                                 clock=lambda: NOW)
                store.add('snooze', device=device, until=NOW + 3600)
                self.assertEqual(store.decide(finding()), 'drop')

    def test_it_must_end(self):
        with self.assertRaises(SilenceError) as ctx:
            self.store.add('snooze', rule='bacnet_control')
        self.assertIn('mute', str(ctx.exception))

    def test_more_than_thirty_days_belongs_in_the_profile(self):
        with self.assertRaises(SilenceError) as ctx:
            self.store.add('snooze', rule='r', until=NOW + 31 * 86400)
        self.assertIn('profile', str(ctx.exception))

    def test_it_expires(self):
        self.store.add('snooze', rule='bacnet_control', until=NOW + 3600)
        self.later(3601)
        self.assertEqual(self.store.decide(finding()), 'push')

    def test_a_time_in_the_past_is_refused(self):
        with self.assertRaises(SilenceError):
            self.store.add('snooze', rule='r', until=NOW - 1)


class TestMaintenance(_Case):

    def test_it_holds_back_pushes_and_keeps_the_record(self):
        self.store.add('maintenance', device='ahu-controller-1')
        self.assertEqual(self.store.decide(finding()), 'digest')

    def test_it_may_be_open_ended(self):
        self.store.add('maintenance', device='ahu-controller-1')
        self.later(365 * 86400)
        self.assertEqual(self.store.decide(finding()), 'digest')

    def test_a_snooze_beats_it_when_both_apply(self):
        self.store.add('maintenance', device='ahu-controller-1')
        self.store.add('snooze', rule='bacnet_control', until=NOW + 60)
        self.assertEqual(self.store.decide(finding()), 'drop')


class TestRefusals(_Case):

    def test_nothing_silences_everything(self):
        for kind in ('snooze', 'maintenance'):
            with self.subTest(kind=kind):
                with self.assertRaises(SilenceError) as ctx:
                    self.store.add(kind, until=NOW + 60)
                self.assertIn('everything', str(ctx.exception))

    def test_an_unknown_kind(self):
        with self.assertRaises(SilenceError):
            self.store.add('mute', rule='r', until=NOW + 60)


class TestTheStore(_Case):

    def test_it_persists_owner_only(self):
        self.store.add('maintenance', device='x')
        self.assertEqual(os.stat(self.path).st_mode & 0o077, 0)
        self.assertEqual(len(Silences(self.path, clock=lambda: NOW).active()), 1)

    def test_a_change_from_elsewhere_is_picked_up(self):
        """So `netmon snooze` takes effect in a running service."""
        other = Silences(self.path, clock=lambda: NOW)
        self.assertEqual(self.store.decide(finding()), 'push')
        other.add('snooze', rule='bacnet_control', until=NOW + 60)
        self.assertEqual(self.store.decide(finding()), 'drop')

    def test_an_unreadable_store_applies_nothing(self):
        """Errs towards noise: a corrupt file must not swallow a BACnet write."""
        self.store.add('snooze', rule='bacnet_control', until=NOW + 60)
        with open(self.path, 'w') as handle:
            handle.write('not json')
        with self.assertLogs('netmon.silence', level='WARNING'):
            self.assertEqual(self.store.decide(finding()), 'push')

    def test_remove(self):
        entry = self.store.add('maintenance', device='x')
        self.assertTrue(self.store.remove(entry['id']))
        self.assertFalse(self.store.remove(entry['id']))
        self.assertEqual(self.store.active(), [])

    def test_expired_entries_are_pruned_on_write(self):
        self.store.add('snooze', rule='a', until=NOW + 60)
        self.later(120)
        self.store.add('maintenance', rule='b')
        with open(self.path) as handle:
            self.assertEqual(len(json.load(handle)['entries']), 1)


class TestNotifier(_Case):

    def test_silenced_findings_are_not_pushed(self):
        calls = []
        notifier = Notifier(NotifierConfig(server='https://ntfy.internal', topic='t'),
                            opener=lambda *a: calls.append(a) or 200,
                            silences=self.store)
        self.store.add('maintenance', device='ahu-controller-1')
        sent, skipped = notifier.send([finding(), finding(device='ahu-controller-2')])
        self.assertEqual([f.device for f in sent], ['ahu-controller-2'])
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(notifier.silenced), 1)


class TestService(_Case):

    def service(self):
        from netmon.service import Service, ServiceConfig
        config = ServiceConfig(profile_path=EXAMPLE, state_dir=os.path.dirname(self.path),
                               notify=False)
        config.web_port = None
        return Service(config)

    def test_a_snooze_keeps_it_out_of_the_digest_and_maintenance_does_not(self):
        service = self.service()
        service.silences.add('snooze', rule='bacnet_control', until=time.time() + 60)
        service.silences.add('maintenance', rule='new_device')
        service.deliver([finding(), finding(rule='new_device', key='k9')])
        self.assertEqual([f.rule_id for f in service.recent], ['new_device'])


class TestCommandLine(_Case):

    def run_cli(self, *args):
        import io
        from contextlib import redirect_stderr, redirect_stdout
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = _main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_snooze_list_clear(self):
        state = os.path.dirname(self.path)
        code, out, _ = self.run_cli('snooze', '--state', state, '--rule', 'r',
                                    '--hours', '2', '--reason', 'testing')
        self.assertEqual(code, 0)
        entry_id = out.split()[1]
        self.assertIn(entry_id, self.run_cli('list', '--state', state)[1])
        self.assertEqual(self.run_cli('clear', '--state', state, entry_id)[0], 0)
        self.assertIn('Nothing is silenced', self.run_cli('list', '--state', state)[1])

    def test_a_refusal_exits_nonzero_and_says_why(self):
        code, _, err = self.run_cli('maintenance', '--state', os.path.dirname(self.path))
        self.assertEqual(code, 1)
        self.assertIn('everything', err)

    def test_the_dispatcher_passes_the_action_through(self):
        import io
        from contextlib import redirect_stdout
        from netmon.__main__ import main
        with redirect_stdout(io.StringIO()):
            code = main(['ack', '--state', os.path.dirname(self.path),
                         '--rule', 'r', '--device', 'd'])
        self.assertEqual(code, 0)
        self.assertEqual(Silences(self.path).active()[0]['kind'], 'ack')


class TestWeb(_Case):

    def setUp(self):
        super().setUp()
        from netmon.web import WebServer
        self.server = WebServer(EXAMPLE, RULES, None, host='127.0.0.1', port=0,
                                allow_edit=True, silences_path=self.path)
        self.base = f'http://127.0.0.1:{self.server.start()}'
        self.addCleanup(self.server.stop)

    def post(self, path, body):
        request = urllib.request.Request(
            self.base + path, data=json.dumps(body).encode(), method='POST',
            headers={'Content-Type': 'application/json',
                     'X-Netmon-Token': self.server.token})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_add_list_clear(self):
        status, body = self.post('/api/silence', {'kind': 'snooze',
                                                  'rule': 'bacnet_control',
                                                  'hours': 2})
        self.assertEqual(status, 200)
        with urllib.request.urlopen(self.base + '/api/silences', timeout=5) as r:
            self.assertEqual(len(json.loads(r.read())['silences']), 1)
        self.assertEqual(self.post('/api/silence/clear',
                                   {'id': body['silence']['id']})[0], 200)

    def test_a_refusal_is_a_400(self):
        status, body = self.post('/api/silence', {'kind': 'snooze', 'hours': 2})
        self.assertEqual(status, 400)
        self.assertIn('everything', body['error'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
