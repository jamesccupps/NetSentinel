"""
Acknowledge, snooze and maintenance from the UI.
=================================================
The routes existed and nothing could reach them: the service never passed
`allow_edit`, `serve` had no `--allow-edit`, and `netmon web` never passed a
silences path and had no `--state`. These tests drive both entry points the
way a person would, and check a silence added *after* a finding was kept
still hides it — from the UI, the live view and the digest alike.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.events import Event, Finding  # noqa: E402
from netmon.silence import Silences  # noqa: E402
from netmon.web import WebServer, make_server  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')
RULES = os.path.join(ROOT, 'netmon', 'rules')
UI = os.path.join(ROOT, 'netmon', 'webui')


def ui_source(name):
    with open(os.path.join(UI, name), encoding='utf-8') as handle:
        return handle.read()


class _Findings:
    """The analyzer shape the UI reads, holding fixed findings."""

    def __init__(self, findings):
        self.findings = findings
        self.events_seen = len(findings)

    def by_severity(self):
        return list(self.findings)

    def report(self):
        return {'events': self.events_seen, 'findings': len(self.findings)}


def finding(rule='bacnet_control', device='ahu-controller-1', key='k1',
            severity='critical'):
    event = Event(kind='bacnet', ts=1000.0, src_ip='10.10.60.50',
                  dst_ip='10.10.20.21')
    return Finding(rule, 'title', severity=severity, tier='push',
                   description=f'{rule} on {device}', device=device, key=key,
                   event=event)


class TestFindingCarriesItsSilence(unittest.TestCase):

    def test_as_dict_says_whether_it_is_silenced(self):
        item = finding()
        self.assertIn('silenced', item.as_dict())
        self.assertIsNone(item.as_dict()['silenced'])
        item.silenced = {'kind': 'ack', 'id': 'abcd', 'reason': 'known'}
        self.assertEqual(item.as_dict()['silenced']['kind'], 'ack')


class _WebCase(unittest.TestCase):
    allow_edit = True

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-websilence-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.state = os.path.join(self.scratch, 'state')
        self.findings = [finding(), finding(rule='new_device',
                                            device='00:11:22:33:44:55',
                                            key='00:11:22:33:44:55',
                                            severity='medium')]
        self.server = make_server(EXAMPLE, RULES, _Findings(self.findings),
                                  port=0, allow_edit=self.allow_edit,
                                  state_dir=self.state)
        self.port = self.server.start()
        self.addCleanup(self.server.stop)
        self.base = f'http://127.0.0.1:{self.port}'

    def get_json(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as response:
            return json.loads(response.read())

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

    def shown(self, query=''):
        return {f['rule_id']: f for f in
                self.get_json('/api/findings' + query)['findings']}


class TestTheWebCommandReachesTheRoutes(_WebCase):

    def test_state_gives_the_server_a_silences_file(self):
        self.assertEqual(self.server.silences_path,
                         os.path.join(self.state, 'silences.json'))
        self.assertTrue(self.get_json('/api/summary')['silences'])

    def test_the_page_says_the_buttons_are_live(self):
        with urllib.request.urlopen(self.base + '/', timeout=5) as response:
            page = response.read().decode()
        self.assertIn('data-silences="true"', page)

    def test_the_command_line_takes_state(self):
        from netmon.web import _parser
        args = _parser().parse_args(['--profile', EXAMPLE, '--state', self.state,
                                     '--allow-edit'])
        self.assertEqual(args.state, self.state)
        self.assertTrue(args.allow_edit)

    def test_an_ack_is_recorded_and_shown(self):
        status, body = self.post('/api/silence', {
            'kind': 'ack', 'rule': 'bacnet_control', 'device': 'ahu-controller-1',
            'key': 'k1', 'reason': 'commissioning'})
        self.assertEqual(status, 200, body)
        shown = self.shown()
        self.assertEqual(shown['bacnet_control']['silenced']['kind'], 'ack')
        self.assertIsNone(shown['new_device']['silenced'])

    def test_a_snooze_added_later_hides_what_it_covers(self):
        """The finding was already kept when the snooze arrived."""
        status, _ = self.post('/api/silence', {
            'kind': 'snooze', 'rule': 'bacnet_control',
            'device': 'ahu-controller-1', 'hours': 4})
        self.assertEqual(status, 200)
        self.assertNotIn('bacnet_control', self.shown())
        self.assertIn('new_device', self.shown())

    def test_snoozed_findings_can_be_asked_for_so_they_can_be_cleared(self):
        self.post('/api/silence', {'kind': 'snooze', 'device': 'ahu-controller-1',
                                   'hours': 1})
        shown = self.shown('?snoozed=1')
        self.assertEqual(shown['bacnet_control']['silenced']['kind'], 'snooze')

    def test_clearing_brings_it_back(self):
        _, body = self.post('/api/silence', {
            'kind': 'snooze', 'device': 'ahu-controller-1', 'hours': 1})
        self.assertNotIn('bacnet_control', self.shown())
        status, _ = self.post('/api/silence/clear', {'id': body['silence']['id']})
        self.assertEqual(status, 200)
        self.assertIsNone(self.shown()['bacnet_control']['silenced'])

    def test_maintenance_marks_without_hiding(self):
        self.post('/api/silence', {'kind': 'maintenance',
                                   'device': 'ahu-controller-1'})
        shown = self.shown()
        self.assertEqual(shown['bacnet_control']['silenced']['kind'],
                         'maintenance')

    def test_the_refusals_still_apply(self):
        status, body = self.post('/api/silence', {'kind': 'snooze', 'hours': 1})
        self.assertEqual(status, 400)
        self.assertIn('everything', body['error'])

    def test_the_devices_view_leaves_out_snoozed_findings(self):
        self.post('/api/silence', {'kind': 'snooze', 'device': 'ahu-controller-1',
                                   'hours': 1})
        devices = {d['name']: d for d in self.get_json('/api/devices')['devices']}
        self.assertEqual(devices['ahu-controller-1']['findings'], [])


class TestReadOnlyStillShowsSilences(_WebCase):
    allow_edit = False

    def test_writing_is_refused(self):
        status, body = self.post('/api/silence', {
            'kind': 'ack', 'rule': 'bacnet_control', 'device': 'ahu-controller-1'})
        self.assertEqual(status, 403)
        self.assertIn('editing is off', body['error'])

    def test_but_silences_made_elsewhere_are_applied(self):
        """A CLI ack or the running service's state shows in a read-only UI."""
        Silences(os.path.join(self.state, 'silences.json')).add(
            'ack', 'bacnet_control', 'ahu-controller-1', 'k1')
        self.assertEqual(self.shown()['bacnet_control']['silenced']['kind'], 'ack')

    def test_the_buttons_are_not_offered(self):
        with urllib.request.urlopen(self.base + '/', timeout=5) as response:
            self.assertIn('data-silences="false"', response.read().decode())


class TestTheServiceReachesTheRoutes(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-svcsilence-')
        self.addCleanup(shutil.rmtree, self.scratch, True)

    def config(self, *extra):
        from netmon.service import _parser, config_from_args
        return config_from_args(_parser().parse_args(
            ['--profile', EXAMPLE, '--state', self.scratch, '--no-notify',
             '--web-port', '0', *extra]))

    def test_serve_takes_allow_edit(self):
        self.assertTrue(self.config('--allow-edit').allow_edit)
        self.assertFalse(self.config().allow_edit)

    def test_the_ui_it_starts_can_write_silences(self):
        from netmon.service import Service
        service = Service(self.config('--allow-edit'), clock=lambda: 1000.0)
        service.start_web()
        self.addCleanup(service.web.stop)
        self.assertTrue(service.web.allow_edit)
        self.assertEqual(service.web.silences_path,
                         os.path.join(self.scratch, 'silences.json'))

    def test_without_the_flag_the_ui_is_read_only(self):
        from netmon.service import Service
        service = Service(self.config(), clock=lambda: 1000.0)
        service.start_web()
        self.addCleanup(service.web.stop)
        self.assertFalse(service.web.allow_edit)

    def test_the_live_view_applies_silences_added_later(self):
        from netmon.service import Service, _LiveView
        service = Service(self.config(), clock=lambda: 1000.0)
        service.deliver([finding(), finding(rule='new_device', device='x',
                                            key='x', severity='low')])
        view = _LiveView(service)
        self.assertEqual(len(view.findings), 2)
        service.silences.add('snooze', rule='bacnet_control',
                             device='ahu-controller-1',
                             until=__import__('time').time() + 3600)
        self.assertEqual([f.rule_id for f in view.findings], ['new_device'])
        self.assertEqual(view.report()['findings'], 1)


class TestThePage(unittest.TestCase):

    def test_the_tier_filter_offers_weekly(self):
        """os_support is a weekly rule; without the option it cannot be shown
        on its own."""
        self.assertIn('value="weekly"', ui_source('index.html'))

    def test_the_verify_button_is_not_exempt_from_read_only(self):
        """It posts, every post is refused read-only, so it must be disabled."""
        self.assertNotIn("'cf-verify'", ui_source('app.js'))

    def test_the_silence_buttons_exist_and_use_text_only(self):
        source = ui_source('app.js')
        for route in ('/api/silence', '/api/silence/clear', '/api/silences'):
            self.assertIn(route, source)
        self.assertNotIn('innerHTML', source.replace(
            'never innerHTML', '').replace('never as HTML', ''))


class TestVisible(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-visible-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.store = Silences(os.path.join(self.scratch, 's.json'))

    def test_a_cleared_silence_clears_the_mark(self):
        item = finding()
        entry = self.store.add('ack', 'bacnet_control', 'ahu-controller-1', 'k1')
        self.store.visible([item])
        self.assertEqual(item.silenced['id'], entry['id'])
        self.store.remove(entry['id'])
        self.store.visible([item])
        self.assertIsNone(item.silenced)


class TestServerDefaults(unittest.TestCase):

    def test_no_state_means_no_silences(self):
        self.assertEqual(make_server(EXAMPLE, RULES).silences_path, '')

    def test_the_summariser_is_off_by_default(self):
        self.assertFalse(WebServer(EXAMPLE, RULES, None).allow_summarise)


if __name__ == '__main__':
    unittest.main(verbosity=2)
