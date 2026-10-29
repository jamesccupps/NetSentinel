"""
The summariser button, and the budget behind it.
================================================
The button is off unless `--allow-summarise`. Pressing it shows the exact
redacted message and an estimate and sends nothing; a second request sends
that message, once. Behind both, the day's budget is enforced: the spend file
lives under `--state` (under systemd, `~/.cache` is not writable and the budget
was silently zero), a location that cannot record spend refuses the request,
the check runs under a lock because the server is threaded, and there is an
hourly cap and a timeout.

No network: the model client is a fake, and the `anthropic` package is not
needed.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import _test_support  # noqa: E402,F401

from netmon.events import Event, Finding, Severity  # noqa: E402
from netmon.profile import load_profile  # noqa: E402
from netmon.summarise import (MIN_OUTPUT_TOKENS, SPEND_FILE,  # noqa: E402
                              Summariser, SummariserConfig, SummaryError,
                              estimate_tokens, load_summariser_config)
from netmon.web import WebServer  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')
RULES = os.path.join(ROOT, 'netmon', 'rules')
PROFILE = load_profile(EXAMPLE)


def finding(device='ahu-controller-1', vlan=20, src='10.10.60.50',
            dst='10.10.20.21'):
    event = Event(kind='bacnet', src_ip=src, dst_ip=dst, vlan=vlan)
    event.fields['src_vlan'] = vlan
    return Finding('bacnet_control', 'A title', severity=Severity.CRITICAL,
                   description=f'{device} was written to', device=device,
                   event=event)


class _Analyzer:
    def __init__(self, findings):
        self.findings = findings
        self.events_seen = 1234

    def by_severity(self):
        return list(self.findings)

    def report(self):
        return {'events': self.events_seen, 'findings': len(self.findings)}


class _Usage:
    input_tokens = 1000
    output_tokens = 500


class _Block:
    type = 'text'
    text = json.dumps({'assessment': 'Quiet.', 'priorities': [
        {'rule': 'bacnet_control', 'device': 'ahu-controller-1',
         'why_it_matters': '<b>bold</b>', 'likely_benign': False,
         'reasoning': 'r', 'confidence': 'high'}]})


class _Response:
    def __init__(self, stop_reason='end_turn'):
        self.content = [_Block()]
        self.stop_reason = stop_reason
        self.stop_details = None
        self.model = 'claude-opus-5-5'
        self.usage = _Usage()


class _Client:
    """Records requests; can be made to hold a request open."""

    def __init__(self, stop_reason='end_turn'):
        self.requests = []
        self.stop_reason = stop_reason
        self.hold = None
        self.entered = threading.Event()
        outer = self

        class _Messages:
            def create(self, **kwargs):
                outer.requests.append(kwargs)
                outer.entered.set()
                if outer.hold is not None:
                    outer.hold.wait(5)
                return _Response(outer.stop_reason)

        class _Beta:
            messages = _Messages()

        self.messages = _Messages()
        self.beta = _Beta()


class _Case(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-button-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.state = os.path.join(self.scratch, 'state')

    def summariser(self, client=None, **config):
        config.setdefault('state_dir', self.state)
        config.setdefault('api_key', 'test-key-not-real')
        client = client or _Client()
        return Summariser(SummariserConfig(**config), client=client), client


# ─── Where the spend lives ───────────────────────────────────────────────────

class TestTheSpendFile(_Case):

    def test_it_lives_under_the_state_directory(self):
        summariser, _ = self.summariser()
        self.assertEqual(summariser.spend.path, os.path.join(self.state, SPEND_FILE))

    def test_the_loader_takes_the_state_directory(self):
        config = load_summariser_config(environ={}, state_dir=self.state)
        self.assertEqual(config.state_path, os.path.join(self.state, SPEND_FILE))

    def test_an_explicit_path_still_wins(self):
        path = os.path.join(self.scratch, 'elsewhere.json')
        summariser, _ = self.summariser(state_path=path)
        self.assertEqual(summariser.spend.path, path)

    def test_a_location_that_cannot_record_spend_refuses_to_send(self):
        """
        Under systemd's ProtectHome, ~/.cache could not be written: every
        recording failed, every read found nothing, and the budget was zero.
        A budget that cannot be recorded is not enforced, so nothing is sent.
        """
        blocker = os.path.join(self.scratch, 'a-file')
        with open(blocker, 'w', encoding='utf-8') as handle:
            handle.write('x')
        summariser, client = self.summariser(
            state_path=os.path.join(blocker, 'spend.json'))
        with self.assertRaises(SummaryError) as ctx:
            summariser.summarise(_Analyzer([finding()]), PROFILE)
        self.assertIn('budget cannot be recorded', str(ctx.exception))
        self.assertEqual(client.requests, [])

    def test_the_spend_is_written_atomically_and_owner_only(self):
        summariser, _ = self.summariser()
        summariser.summarise(_Analyzer([finding()]), PROFILE)
        self.assertFalse(os.path.exists(summariser.spend.path + '.tmp'))
        if os.name == 'nt':
            self.skipTest('POSIX permission model only')
        self.assertEqual(os.stat(summariser.spend.path).st_mode & 0o077, 0)


# ─── Enforcement ─────────────────────────────────────────────────────────────

class TestEnforcement(_Case):

    def test_the_hourly_cap(self):
        summariser, client = self.summariser(hourly_sends=2)
        for _ in range(2):
            summariser.summarise(_Analyzer([finding()]), PROFILE)
        with self.assertRaises(SummaryError) as ctx:
            summariser.summarise(_Analyzer([finding()]), PROFILE)
        self.assertIn('last hour', str(ctx.exception))
        self.assertEqual(len(client.requests), 2)

    def test_the_cap_lifts_after_an_hour(self):
        now = [10_000.0]
        summariser, client = self.summariser(hourly_sends=1)
        summariser.spend._clock = lambda: now[0]
        summariser.summarise(_Analyzer([finding()]), PROFILE)
        now[0] += 3601
        summariser.summarise(_Analyzer([finding()]), PROFILE)
        self.assertEqual(len(client.requests), 2)

    def test_output_is_capped_at_what_the_day_has_left(self):
        summariser, client = self.summariser(daily_token_budget=12_000,
                                             max_tokens=16_000)
        prepared = summariser.prepare(_Analyzer([finding()]), PROFILE)
        summariser.send(prepared)
        asked = client.requests[0]['max_tokens']
        self.assertLessEqual(asked, 12_000 - prepared['estimated_input_tokens'])
        self.assertGreaterEqual(asked, MIN_OUTPUT_TOKENS)

    def test_but_never_below_the_floor_an_answer_needs(self):
        summariser, client = self.summariser(daily_token_budget=500)
        summariser.summarise(_Analyzer([finding()]), PROFILE)
        self.assertEqual(client.requests[0]['max_tokens'], MIN_OUTPUT_TOKENS)

    def test_a_declined_request_is_still_counted(self):
        """Refused or not, the tokens were spent."""
        summariser, _ = self.summariser(client=_Client(stop_reason='refusal'))
        with self.assertRaises(SummaryError):
            summariser.summarise(_Analyzer([finding()]), PROFILE)
        self.assertEqual(summariser.spend.read(), 1500)
        self.assertEqual(len(summariser.spend.sends_last_hour()), 1)

    def test_a_second_request_while_one_runs_is_refused(self):
        """The UI is threaded; two clicks must not both pass the check."""
        client = _Client()
        client.hold = threading.Event()
        first, _ = self.summariser(client=client)
        second, _ = self.summariser(client=client)       # same spend file
        errors = []
        worker = threading.Thread(
            target=lambda: first.summarise(_Analyzer([finding()]), PROFILE))
        worker.start()
        try:
            self.assertTrue(client.entered.wait(5))
            try:
                second.summarise(_Analyzer([finding()]), PROFILE)
            except SummaryError as e:
                errors.append(str(e))
        finally:
            client.hold.set()
            worker.join(5)
        self.assertEqual(len(errors), 1)
        self.assertIn('another summary', errors[0])
        self.assertEqual(len(client.requests), 1)

    def test_the_client_gets_a_timeout_and_bounded_retries(self):
        captured = {}

        class _Module:
            class Anthropic:
                def __init__(self, **kwargs):
                    captured.update(kwargs)

        saved = sys.modules.get('anthropic')
        sys.modules['anthropic'] = _Module
        try:
            Summariser(SummariserConfig(api_key='k', timeout=45, max_retries=0,
                                        state_dir=self.state))._anthropic()
        finally:
            if saved is None:
                sys.modules.pop('anthropic', None)
            else:
                sys.modules['anthropic'] = saved
        self.assertEqual(captured['timeout'], 45)
        self.assertEqual(captured['max_retries'], 0)


# ─── Preview, then send ──────────────────────────────────────────────────────

class TestPrepare(_Case):

    def test_preparing_sends_nothing(self):
        summariser, client = self.summariser()
        prepared = summariser.prepare(_Analyzer([finding()]), PROFILE)
        self.assertEqual(client.requests, [])
        self.assertIn('<findings>', prepared['message'])
        self.assertGreater(prepared['estimated_input_tokens'],
                           estimate_tokens(prepared['message']))

    def test_what_is_sent_is_exactly_what_was_shown(self):
        summariser, client = self.summariser()
        prepared = summariser.prepare(_Analyzer([finding()]), PROFILE)
        summariser.send(prepared)
        self.assertEqual(client.requests[0]['messages'][0]['content'],
                         prepared['message'])

    def test_preparing_refuses_a_dirty_payload(self):
        summariser, _ = self.summariser()
        item = finding()
        item.description = 'Authorization: Basic aHVudGVyMjpodW50ZXIy'
        with self.assertRaises(SummaryError):
            summariser.prepare(_Analyzer([item]), PROFILE)

    def test_the_estimate_rounds_up(self):
        self.assertEqual(estimate_tokens(''), 0)
        self.assertEqual(estimate_tokens('abcd'), 2)


# ─── The routes ──────────────────────────────────────────────────────────────

class _WebCase(_Case):
    allow_summarise = True
    with_analysis = True

    def setUp(self):
        super().setUp()
        self.client = _Client()
        analyzer = _Analyzer([finding(),
                              finding(device='door-panel-north', vlan=40,
                                      src='10.10.40.10', dst='10.10.40.1')]) \
            if self.with_analysis else None
        self.server = WebServer(
            EXAMPLE, RULES, analyzer, port=0,
            allow_summarise=self.allow_summarise, state_dir=self.state,
            summariser_factory=lambda: Summariser(
                SummariserConfig(api_key='k', state_dir=self.state),
                client=self.client))
        self.port = self.server.start()
        self.addCleanup(self.server.stop)

    def post(self, path, body, token=True):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['X-Netmon-Token'] = self.server.token
        request = urllib.request.Request(
            f'http://127.0.0.1:{self.port}{path}', data=json.dumps(body).encode(),
            headers=headers, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())


class TestTheButtonIsOffByDefault(_WebCase):
    allow_summarise = False

    def test_both_routes_are_refused(self):
        for path in ('/api/summarise/preview', '/api/summarise/send'):
            with self.subTest(path=path):
                status, body = self.post(path, {})
                self.assertEqual(status, 403)
                self.assertIn('summariser is off', body['error'])
        self.assertEqual(self.client.requests, [])

    def test_the_default_server_has_it_off(self):
        self.assertFalse(WebServer(EXAMPLE, RULES, None).allow_summarise)


class TestTheButton(_WebCase):

    def test_the_preview_shows_the_message_and_sends_nothing(self):
        status, body = self.post('/api/summarise/preview', {})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.client.requests, [])
        self.assertIn('<findings>', body['message'])
        self.assertIn('ahu-controller-1', body['message'])
        self.assertGreater(body['estimated_input_tokens'], 0)
        self.assertEqual(body['budget']['spent_today'], 0)
        self.assertEqual(body['withheld_from_restricted_segments'], 1)
        self.assertNotIn('door-panel-north', body['message'])
        self.assertNotIn('10.10.40', body['message'])

    def test_send_sends_exactly_the_preview_once(self):
        _, preview = self.post('/api/summarise/preview', {})
        status, body = self.post('/api/summarise/send',
                                 {'preview_id': preview['preview_id']})
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.client.requests), 1)
        self.assertEqual(self.client.requests[0]['messages'][0]['content'],
                         preview['message'])
        self.assertEqual(body['budget']['spent_today'], 1500)
        # The result comes back as data; the page renders it as text.
        self.assertEqual(body['result']['priorities'][0]['why_it_matters'],
                         '<b>bold</b>')

        again, _ = self.post('/api/summarise/send',
                             {'preview_id': preview['preview_id']})
        self.assertEqual(again, 404)
        self.assertEqual(len(self.client.requests), 1)

    def test_an_unknown_preview_sends_nothing(self):
        status, _ = self.post('/api/summarise/send', {'preview_id': 'made-up'})
        self.assertEqual(status, 404)
        self.assertEqual(self.client.requests, [])

    def test_an_expired_preview_sends_nothing(self):
        _, preview = self.post('/api/summarise/preview', {})
        made, prepared = self.server._previews[preview['preview_id']]
        self.server._previews[preview['preview_id']] = (made - 3600, prepared)
        status, _ = self.post('/api/summarise/send',
                              {'preview_id': preview['preview_id']})
        self.assertEqual(status, 404)
        self.assertEqual(self.client.requests, [])

    def test_the_token_is_required_for_both(self):
        for path in ('/api/summarise/preview', '/api/summarise/send'):
            with self.subTest(path=path):
                status, _ = self.post(path, {}, token=False)
                self.assertEqual(status, 403)

    def test_the_budget_is_enforced_through_the_button(self):
        os.makedirs(self.state, exist_ok=True)
        with open(os.path.join(self.state, SPEND_FILE), 'w',
                  encoding='utf-8') as handle:
            json.dump({'day': time.strftime('%Y-%m-%d', time.gmtime()),
                       'tokens': 10 ** 9}, handle)
        _, preview = self.post('/api/summarise/preview', {})
        status, body = self.post('/api/summarise/send',
                                 {'preview_id': preview['preview_id']})
        self.assertEqual(status, 400)
        self.assertIn('budget', body['error'])
        self.assertEqual(self.client.requests, [])

    def test_a_restricted_device_cannot_be_previewed(self):
        status, body = self.post('/api/summarise/preview',
                                 {'device': 'door-panel-north'})
        self.assertEqual(status, 400)
        self.assertIn('not sent', body['error'])

    def test_waiting_previews_are_bounded(self):
        for _ in range(self.server.max_previews + 5):
            self.post('/api/summarise/preview', {})
        self.assertLessEqual(len(self.server._previews), self.server.max_previews)


class TestWithNothingToSummarise(_WebCase):
    with_analysis = False

    def test_it_says_so(self):
        status, body = self.post('/api/summarise/preview', {})
        self.assertEqual(status, 400)
        self.assertIn('nothing to summarise', body['error'])


class TestTheFlags(unittest.TestCase):

    def test_web_takes_allow_summarise_and_secrets(self):
        from netmon.web import _parser
        args = _parser().parse_args(['--profile', EXAMPLE, '--allow-summarise',
                                     '--secrets', 's.json'])
        self.assertTrue(args.allow_summarise)
        self.assertEqual(args.secrets, 's.json')

    def test_serve_takes_allow_summarise(self):
        from netmon.service import _parser, config_from_args
        config = config_from_args(_parser().parse_args(
            ['--profile', EXAMPLE, '--allow-summarise']))
        self.assertTrue(config.allow_summarise)
        self.assertFalse(config_from_args(_parser().parse_args(
            ['--profile', EXAMPLE])).allow_summarise)

    def test_the_page_offers_the_tab_only_when_on(self):
        with open(os.path.join(ROOT, 'netmon', 'webui', 'index.html'),
                  encoding='utf-8') as handle:
            page = handle.read()
        self.assertIn('data-summarise="{{SUMMARISE}}"', page)
        with open(os.path.join(ROOT, 'netmon', 'webui', 'app.js'),
                  encoding='utf-8') as handle:
            script = handle.read()
        self.assertIn('/api/summarise/preview', script)
        self.assertIn('/api/summarise/send', script)


try:
    from scapy.all import Dot1Q, Ether, IP, TCP, wrpcap
    HAVE_SCAPY = True
except Exception:                                              # pragma: no cover
    HAVE_SCAPY = False


@unittest.skipUnless(HAVE_SCAPY, 'needs scapy to write a capture')
class TestTheServiceCountsEvents(unittest.TestCase):
    """`events_seen` was the number of capture files, so a day of traffic read
    as "12 events" everywhere it was reported — the digest and the model."""

    def test_events_are_packets_not_files(self):
        from netmon.service import Service, ServiceConfig, _LiveView
        scratch = tempfile.mkdtemp(prefix='netmon-events-')
        self.addCleanup(shutil.rmtree, scratch, True)
        ring = os.path.join(scratch, 'ring')
        os.makedirs(ring)
        now = time.time()
        for when, count in ((now - 3600, 5), (now, 1)):
            name = time.strftime('netmon-%Y%m%d-%H%M%S.pcap', time.localtime(when))
            wrpcap(os.path.join(ring, name), [
                Ether(src='00:11:22:00:00:40', dst='00:aa:bb:cc:dd:ee')
                / Dot1Q(vlan=60) / IP(src='10.10.60.50', dst='10.10.20.21')
                / TCP(dport=22)] * count)
        config = ServiceConfig(profile_path=EXAMPLE, ring_dir=ring,
                               state_dir=os.path.join(scratch, 'state'),
                               notify=False)
        config.web_port = None
        service = Service(config)
        service.analyse_new_captures()
        self.assertEqual(service.counts['captures'], 1)
        self.assertEqual(service.counts['events'], 5)
        self.assertEqual(_LiveView(service).events_seen, 5)
        self.assertEqual(_LiveView(service).report()['events'], 5)


if __name__ == '__main__':
    unittest.main(verbosity=2)
