"""
Headless mode and the read-only HTTP API.
==========================================
Tests run against a real HTTP listener on an OS-assigned port, not against the
route functions directly, so the wire behaviour — status codes, content types,
headers — is covered too.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src.headless import HeadlessServer  # noqa: E402
from src.ids_engine import Alert, Severity  # noqa: E402


class _StubConfig:
    def __init__(self):
        self.values = {}

    def get(self, *keys, default=None):
        return self.values.get(keys, default)


class _StubApp:
    """
    A minimal stand-in with the surface HeadlessServer actually uses.

    Constructing a real NetSentinelApp per test would download threat feeds and
    spin up half a dozen threads to test a JSON serialiser.
    """

    class _Capture:
        is_running = True

    class _Alerts:
        def __init__(self):
            self.items = []

        def get_alerts(self, limit=100, **kw):
            return self.items[:limit]

        def acknowledge_alert(self, alert_id):
            for alert in self.items:
                if alert.id == alert_id:
                    alert.acknowledged = True
                    return True
            return False

        def acknowledge_all(self):
            for alert in self.items:
                alert.acknowledged = True

    class _Correlator:
        _all_incidents = []

        def get_stats(self):
            return {'total_incidents': 0, 'active_incidents': 0}

    class _Devices:
        def get_summary(self):
            return {'total_devices': 2, 'by_type': {'workstation': 2}, 'devices': []}

    def __init__(self):
        self.capture_engine = self._Capture()
        self.alert_manager = self._Alerts()
        self.alert_correlator = self._Correlator()
        self.device_learner = self._Devices()
        self.can_start = True
        self.last_start_error = ''
        self.verdicts = []
        self.verdict_has_no_subject = False
        self.review_on = True
        self.config = _StubConfig()

    def start_monitoring(self):
        if not self.can_start:
            self.last_start_error = 'Packet capture failed to start.'
            return False
        self.capture_engine.is_running = True
        return True

    def stop_monitoring(self):
        self.capture_engine.is_running = False

    def record_verdict(self, alert_id, verdict, note=''):
        if verdict not in ('real', 'false_positive'):
            raise ValueError(verdict)
        if not any(a.id == alert_id for a in self.alert_manager.items):
            raise KeyError(alert_id)
        if self.verdict_has_no_subject:
            raise LookupError('This alert names no host or domain to tie a verdict to.')
        self.verdicts.append((alert_id, verdict))
        return ({'rule_id': 'SYN-FLOOD', 'kind': 'src_ip', 'value': '203.0.113.9'}
                if verdict == 'false_positive' else None)

    def build_review_bundle(self, **options):
        if not self.review_on:
            raise FileNotFoundError('No alerts recorded yet.')
        return {'folder': 'f', 'zip': 'f.zip', 'alerts': 4, 'groups': 4, 'digests': 0,
                'files': 3, 'bytes': 1000, 'masked': 0}

    def get_dashboard_data(self):
        return {
            'capture': {'packets_captured': 12345, 'bytes_captured': 987654,
                        'packets_per_sec': 42.5, 'bytes_per_sec': 1024.0,
                        'flows_active': 7, 'packets_dropped': 3,
                        'start_time': 1_000_000.0},
            'alerts': {'total': len(self.alert_manager.items), 'unacknowledged': 2,
                       'by_severity': {'LOW': 1, 'MEDIUM': 0, 'HIGH': 2, 'CRITICAL': 1}},
            'ml': {'is_trained': True, 'baseline_samples': 500},
            'ml_result': {'anomaly_score': 0.82},
            'correlator': {'active_incidents': 1},
            'device_learner': {'total_devices': 2},
            'is_monitoring': self.capture_engine.is_running,
            'score_history': [{'t': i} for i in range(1000)],
            'resources': {'available': True, 'cpu_percent': 1.5, 'rss_bytes': 64 << 20,
                          'threads': 9, 'low_priority': False},
        }


class _ApiTestCase(unittest.TestCase):

    def setUp(self):
        self.app = _StubApp()
        for n, (rule, sev) in enumerate([('SYN-FLOOD', Severity.CRITICAL),
                                         ('PORT-SCAN', Severity.HIGH),
                                         ('DNS-FAST-FLUX', Severity.HIGH),
                                         ('ODD-HOURS', Severity.LOW)]):
            alert = Alert(rule, sev, f'{rule} test', 'demo',
                          src_ip='203.0.113.9', dst_ip='192.168.1.50',
                          category='Test')
            # Explicit, because Windows' clock can give all four the same time.
            alert.timestamp = 1_700_000_000.0 + n
            self.app.alert_manager.items.append(alert)

        # Port 0 lets the OS pick, so tests never collide with a real service.
        self.server = HeadlessServer(self.app, host='127.0.0.1', port=0)
        self.port = self.server.start()
        self.base = f'http://127.0.0.1:{self.port}'

    def tearDown(self):
        self.server.stop()

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as r:
            return r.status, dict(r.headers), r.read().decode()

    def get_json(self, path):
        return json.loads(self.get(path)[2])

    def request(self, path, data=None, headers=None, method=None):
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def post(self, path, data=b'', token=None, **headers):
        headers['X-NetSentinel-Token'] = self.server.token if token is None else token
        return self.request(path, data=data, headers=headers, method='POST')


class TestServerLifecycle(_ApiTestCase):

    def test_os_assigns_a_real_port(self):
        self.assertGreater(self.port, 0)

    def test_start_is_idempotent(self):
        self.assertEqual(self.server.start(), self.port)

    def test_stop_is_idempotent(self):
        self.server.stop()
        self.server.stop()   # must not raise

    def test_defaults_to_localhost(self):
        self.assertEqual(HeadlessServer(self.app).host, '127.0.0.1')


class TestEndpoints(_ApiTestCase):

    def test_health(self):
        body = self.get_json('/health')
        self.assertEqual(body['status'], 'ok')
        self.assertTrue(body['monitoring'])
        self.assertIn('uptime_sec', body)

    def test_index_is_human_readable(self):
        status, headers, body = self.get('/status.txt')
        self.assertEqual(status, 200)
        self.assertTrue(headers['Content-Type'].startswith('text/plain'))
        self.assertIn('NetSentinel', body)
        self.assertIn('Capture', body)
        self.assertIn('CRITICAL', body)   # threat level from anomaly_score 0.82

    def test_status_returns_the_dashboard(self):
        body = self.get_json('/api/status')
        self.assertIn('capture', body)
        self.assertIn('alerts', body)
        self.assertEqual(body['capture']['packets_captured'], 12345)

    def test_the_overview_says_what_netsentinel_costs(self):
        """The handoff asked for CPU, RAM, drops and sampling on the dashboard."""
        o = self.get_json('/api/overview')
        self.assertEqual(o['resources']['cpu_percent'], 1.5)
        self.assertEqual(o['resources']['rss_bytes'], 64 << 20)
        self.assertIn('sample_rate', o['capture'])
        self.assertIn('packets_dropped', o['capture'])
        metrics = self.get('/api/metrics')[2]
        self.assertIn('netsentinel_process_resident_memory_bytes 67108864', metrics)
        self.assertIn('netsentinel_capture_sample_rate', metrics)

    def test_status_omits_the_score_time_series(self):
        """1000 points per call would dominate the response for no benefit."""
        self.assertNotIn('score_history', self.get_json('/api/status'))

    def test_alerts_are_serialisable_and_newest_first(self):
        body = self.get_json('/api/alerts')
        self.assertEqual(body['count'], 4)
        self.assertEqual(body['alerts'][0]['rule_id'], 'ODD-HOURS')
        self.assertIn('counts_by_severity', body)

    def test_alerts_respect_limit(self):
        self.assertEqual(self.get_json('/api/alerts?limit=2')['count'], 2)

    def test_alerts_respect_severity_filter(self):
        body = self.get_json('/api/alerts?severity=HIGH')
        self.assertEqual(body['count'], 2)
        self.assertTrue(all(a['severity'] == 'HIGH' for a in body['alerts']))

    def test_severity_filter_is_case_insensitive(self):
        self.assertEqual(self.get_json('/api/alerts?severity=high')['count'], 2)

    def test_devices(self):
        self.assertEqual(self.get_json('/api/devices')['total_devices'], 2)

    def test_incidents(self):
        body = self.get_json('/api/incidents')
        self.assertIn('stats', body)
        self.assertIn('incidents', body)

    def test_unknown_path_is_404_json(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.get('/does-not-exist')
        self.assertEqual(ctx.exception.code, 404)
        self.assertEqual(json.loads(ctx.exception.read())['error'], 'not found')


class TestParameterHandling(_ApiTestCase):
    """Query parameters come from the network; none of them may raise."""

    def test_garbage_limit_falls_back_to_the_default(self):
        for value in ('abc', '-5', '', '1e9', 'null', '0'):
            with self.subTest(limit=value):
                body = self.get_json(f'/api/alerts?limit={value}')
                self.assertGreaterEqual(body['count'], 0)

    def test_limit_is_capped(self):
        body = self.get_json('/api/alerts?limit=999999')
        self.assertLessEqual(body['count'], 4)

    def test_unknown_severity_returns_nothing_rather_than_erroring(self):
        self.assertEqual(self.get_json('/api/alerts?severity=BOGUS')['count'], 0)

    def test_repeated_parameters_do_not_break(self):
        self.assertIsNotNone(self.get_json('/api/alerts?limit=1&limit=2'))


class TestMetricsExposition(_ApiTestCase):

    def setUp(self):
        super().setUp()
        self.status, self.headers, self.body = self.get('/api/metrics')

    def test_content_type_is_prometheus(self):
        self.assertIn('text/plain', self.headers['Content-Type'])
        self.assertIn('version=0.0.4', self.headers['Content-Type'])

    def test_every_metric_has_help_and_type(self):
        names = {line.split()[0].split('{')[0]
                 for line in self.body.splitlines()
                 if line and not line.startswith('#')}
        for name in names:
            self.assertIn(f'# HELP {name}', self.body, f'{name} lacks HELP')
            self.assertIn(f'# TYPE {name}', self.body, f'{name} lacks TYPE')

    def test_values_come_from_the_app(self):
        self.assertIn('netsentinel_packets_captured_total 12345', self.body)
        self.assertIn('netsentinel_alerts_total 4', self.body)
        self.assertIn('netsentinel_ml_trained 1', self.body)
        self.assertIn('netsentinel_anomaly_score 0.82', self.body)

    def test_severity_labels_are_present(self):
        for level in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            self.assertIn(f'severity="{level}"', self.body)

    def test_every_value_parses_as_a_number(self):
        for line in self.body.splitlines():
            if not line or line.startswith('#'):
                continue
            with self.subTest(line=line):
                float(line.rsplit(' ', 1)[1])


class TestResponseHardening(_ApiTestCase):
    """This serves captured credentials and device inventory."""

    def test_security_headers_are_set(self):
        for path in ('/', '/health', '/api/status', '/api/metrics'):
            with self.subTest(path=path):
                _, headers, _ = self.get(path)
                self.assertEqual(headers['Cache-Control'], 'no-store')
                self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
                self.assertEqual(headers['X-Frame-Options'], 'DENY')

    def test_python_version_is_not_advertised(self):
        _, headers, _ = self.get('/health')
        self.assertNotIn('Python', headers.get('Server', ''))

    def test_api_is_read_only(self):
        """A read endpoint does not take a POST; the controls are their own routes."""
        request = urllib.request.Request(self.base + '/api/status', data=b'{}',
                                         method='POST')
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(request, timeout=5)
        self.assertIn(ctx.exception.code, (400, 405, 501))

    def test_a_failing_route_returns_500_not_a_stack_trace(self):
        def explode(params):
            raise RuntimeError('boom')
        self.server.routes['/api/status'] = explode
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.get('/api/status')
        self.assertEqual(ctx.exception.code, 500)
        self.assertEqual(json.loads(ctx.exception.read())['error'], 'internal error')


class TestDashboard(_ApiTestCase):
    """The browser dashboard, and what keeps other web pages from driving it."""

    def test_the_page_carries_the_token_and_a_strict_policy(self):
        status, headers, body = self.get('/')
        self.assertEqual(status, 200)
        self.assertTrue(headers['Content-Type'].startswith('text/html'))
        self.assertIn(self.server.token, body)
        self.assertNotIn('__NETSENTINEL', body)
        self.assertIn("script-src 'self'", headers['Content-Security-Policy'])
        for path in ('/static/app.js', '/static/style.css'):
            self.assertEqual(self.get(path)[0], 200)

    def test_overview(self):
        o = self.get_json('/api/overview')
        self.assertEqual(o['threat']['label'], 'CRITICAL')
        self.assertEqual(o['capture']['flows_active'], 7)
        self.assertTrue(o['monitoring'])

    def test_a_foreign_host_name_is_refused(self):
        """DNS rebinding: evil.example resolving to 127.0.0.1 must not read the API."""
        status, _ = self.request('/api/status', headers={'Host': f'evil.example:{self.port}'})
        self.assertEqual(status, 421)
        status, _ = self.request('/api/status', headers={'Host': f'localhost:{self.port}'})
        self.assertEqual(status, 200)

    def test_posts_need_the_token(self):
        self.assertEqual(self.post('/api/scan/new', token='')[0], 403)
        self.assertEqual(self.post('/api/scan/new', token='wrong')[0], 403)
        self.assertEqual(self.post('/api/scan/new')[0], 201)

    def test_a_page_open_across_a_restart_can_find_the_new_token(self):
        """A tab opened before a restart held the old process's token, and every
        button said "missing or wrong token" until the page was reloaded. On those
        words the page now reads the new token from / and tries once more."""
        from src import headless
        status, reply = self.post('/api/alerts/ack-all', token='from-the-last-run')
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(reply)['error'], headless.TOKEN_REFUSED)
        with open(os.path.join(headless.WEBUI_DIR, 'app.js'), encoding='utf-8') as f:
            source = f.read()
        self.assertIn(f"const TOKEN_REFUSED = '{headless.TOKEN_REFUSED}'", source)
        self.assertIn("fetch('/'", source)
        self.assertIn(f'<meta name="netsentinel-token" content="{self.server.token}">',
                      self.get('/')[2])
        self.assertNotEqual(HeadlessServer(self.app).token, self.server.token)

    def test_a_cross_origin_post_is_refused_even_with_the_token(self):
        status, _ = self.post('/api/scan/new', Origin='https://evil.example')
        self.assertEqual(status, 403)
        status, _ = self.post('/api/scan/new', Origin=f'http://127.0.0.1:{self.port}')
        self.assertEqual(status, 201)

    def test_upload_and_scan(self):
        from test_batch_scan import FakeAnalyzer
        self.server._make_analyzer = FakeAnalyzer
        status, body = self.post('/api/scan/new')
        sid = json.loads(body)['id']
        config = b'password = "Hunter2Secret"\nserver 8.8.8.8\n'
        status, body = self.post(f'/api/scan/upload?id={sid}&name=../../etc/app.conf', config)
        self.assertEqual(status, 201)
        self.assertEqual(json.loads(body)['stored'].replace('\\', '/'), 'etc/app.conf')
        self.assertEqual(self.post(f'/api/scan/start?id={sid}')[0], 202)
        for _ in range(100):
            state = self.get_json(f'/api/scan?id={sid}')
            if state['state'] != 'running':
                break
            time.sleep(0.05)
        self.assertEqual(state['state'], 'done')
        report = state['report']
        self.assertEqual([s['kind'] for s in report['secrets']], ['password'])
        self.assertEqual(report['indicators']['ipv4'][0]['value'], '8.8.8.8')
        self.assertNotIn('Hunter2Secret', json.dumps(state))
        self.assertEqual(self.post(f'/api/scan/upload?id={sid}&name=x', b'x')[0], 409)

    def test_many_files_travel_in_one_request(self):
        def record(name, data):
            raw = name.encode()
            return len(raw).to_bytes(2, 'big') + raw + len(data).to_bytes(4, 'big') + data
        sid = json.loads(self.post('/api/scan/new')[1])['id']
        body = b''.join(record(f'logs/{i}.log', f'host 10.0.0.{i}'.encode()) for i in range(50))
        status, reply = self.post(f'/api/scan/upload-batch?id={sid}', body)
        self.assertEqual((status, json.loads(reply)['stored']), (201, 50))
        self.assertEqual(self.get_json(f'/api/scan?id={sid}')['files'], 50)
        # a record claiming more bytes than were sent is refused, not read past
        bad = record('x.log', b'abc')[:-1]
        self.assertEqual(self.post(f'/api/scan/upload-batch?id={sid}', bad)[0], 400)

    def test_an_unknown_scan_is_404(self):
        self.assertEqual(self.request('/api/scan?id=nope')[0], 404)

    def test_a_refused_upload_still_gets_its_answer(self):
        """
        A refusal is sent before the body is read, and closing with the body
        unread made Windows reset the connection: the browser lost the answer
        and showed a network error instead.
        """
        body = b'x' * (16 * 1024 * 1024)       # more than the socket buffers hold
        for path, token, expected in [('/api/status', None, 405),
                                      ('/api/nowhere', None, 404),
                                      ('/api/scan/new', 'wrong', 403)]:
            with self.subTest(path=path):
                status, reply = self.post(path, body, token=token)
                self.assertEqual(status, expected)
                self.assertIn('error', json.loads(reply))

    def test_a_refusal_does_not_wait_for_the_body(self):
        """
        Clients may hold a large body back until they hear the server will take
        it (curl's Expect: 100-continue). Reading the body before answering
        would leave both sides waiting for the other.
        """
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as s:
            s.sendall(b'POST /api/nowhere HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                      b'Content-Length: 1000000\r\n\r\n')
            self.assertEqual(s.recv(64).split()[1], b'404')

    def test_a_silent_client_is_not_waited_on_forever(self):
        from src import headless
        quiet, peer = socket.socketpair()
        self.addCleanup(quiet.close)
        self.addCleanup(peer.close)
        with mock.patch.object(headless, 'LINGER_SECONDS', 0.2):
            started = time.monotonic()
            headless._drain(quiet)
        self.assertLess(time.monotonic() - started, 2)


class TestControls(_ApiTestCase):
    """Start, stop and acknowledge: token-gated, and on loopback binds only."""

    def test_monitoring_starts_and_stops_from_the_browser(self):
        self.assertEqual(self.post('/api/monitoring/stop')[0], 200)
        self.assertFalse(self.get_json('/api/overview')['monitoring'])
        status, reply = self.post('/api/monitoring/start')
        self.assertEqual((status, json.loads(reply)), (200, {'monitoring': True}))
        self.assertTrue(self.get_json('/api/overview')['monitoring'])

    def test_a_failed_start_says_why(self):
        self.app.can_start = False
        status, reply = self.post('/api/monitoring/start')
        self.assertEqual(status, 503)
        self.assertIn('failed to start', json.loads(reply)['error'])

    def test_one_alert_or_all_can_be_acknowledged(self):
        first, rest = self.app.alert_manager.items[0], self.app.alert_manager.items[1:]
        self.assertEqual(self.post(f'/api/alerts/ack?id={first.id}')[0], 200)
        self.assertTrue(first.acknowledged)
        self.assertFalse(any(a.acknowledged for a in rest))
        self.assertTrue(self.get_json('/api/alerts')['alerts'][-1]['acknowledged'])

        self.assertEqual(self.post('/api/alerts/ack?id=999999')[0], 404)
        self.assertEqual(self.post('/api/alerts/ack?id=nope')[0], 400)
        self.assertEqual(self.post('/api/alerts/ack-all')[0], 200)
        self.assertTrue(all(a.acknowledged for a in rest))

    def test_controls_need_the_token(self):
        for token in ('', 'wrong'):
            with self.subTest(token=token):
                self.assertEqual(self.post('/api/monitoring/stop', token=token)[0], 403)
        self.assertTrue(self.app.capture_engine.is_running)

    def test_controls_take_no_body(self):
        self.assertEqual(self.post('/api/monitoring/stop', b'{}')[0], 400)
        self.assertTrue(self.app.capture_engine.is_running)

    def test_a_verdict_from_the_browser(self):
        alert = self.app.alert_manager.items[0]
        status, reply = self.post(f'/api/alerts/verdict?id={alert.id}&verdict=false_positive')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(reply)['suppressing']['value'], '203.0.113.9')
        self.assertEqual(self.app.verdicts, [(alert.id, 'false_positive')])
        self.assertEqual(self.post('/api/alerts/verdict?id=999999&verdict=real')[0], 404)
        self.assertEqual(self.post(f'/api/alerts/verdict?id={alert.id}&verdict=maybe')[0], 400)
        self.app.verdict_has_no_subject = True
        self.assertEqual(self.post(
            f'/api/alerts/verdict?id={alert.id}&verdict=false_positive')[0], 409)

    def test_a_review_bundle_from_the_browser(self):
        status, reply = self.post('/api/review/bundle')
        self.assertEqual((status, json.loads(reply)['zip']), (201, 'f.zip'))
        self.app.review_on = False
        status, reply = self.post('/api/review/bundle')
        self.assertEqual(status, 409)
        self.assertIn('No alerts', json.loads(reply)['error'])

    def test_the_audit_page_reads_and_refuses_politely(self):
        page = self.get_json('/api/audit')
        self.assertFalse(page['enabled'])
        self.assertIsInstance(page['choices'], list)
        status, reply = self.post('/api/audit/start?network=192.168.1.0/24')
        self.assertEqual(status, 403)
        self.assertIn('Settings', json.loads(reply)['error'])

        self.app.config.values[('audit', 'enabled')] = True
        status, reply = self.post('/api/audit/start?network=203.0.113.0/24')
        self.assertEqual(status, 400, 'a public range is never scanned')
        self.assertIn('not a private network', json.loads(reply)['error'])

    def test_scan_findings_can_be_ignored_and_unignored(self):
        finding = {'kind': 'ipv4', 'value': '203.0.113.77'}
        status, _ = self.post('/api/scan/ignore', json.dumps({'finding': finding}).encode(),
                              **{'Content-Type': 'application/json'})
        self.assertEqual(status, 201)
        entries = self.get_json('/api/scan/ignored')['ignored']
        mine = [e for e in entries if e.get('shown') == '203.0.113.77']
        self.assertEqual(len(mine), 1)
        self.assertEqual(self.post(f"/api/scan/unignore?id={mine[0]['id']}")[0], 200)
        self.assertFalse(any(e.get('shown') == '203.0.113.77'
                             for e in self.get_json('/api/scan/ignored')['ignored']))
        self.assertEqual(self.post('/api/scan/ignore', b'not json')[0], 400)
        self.assertEqual(self.post('/api/scan/ignore', b'{}', token='wrong')[0], 403)

    def test_the_overview_credits_db_ip_only_when_geoip_is_on(self):
        self.assertIsNone(self.get_json('/api/overview')['geoip_attribution'])

        class _Geo:
            def annotate_talkers(self, talkers):
                return [{'ip': ip, 'bytes': b, 'country': 'DE'} for ip, b in talkers]

            def get_stats(self):
                return {'attribution': 'IP Geolocation by DB-IP'}
        self.app.ids_engine = type('Ids', (), {'geoip': _Geo()})()
        o = self.get_json('/api/overview')
        self.assertEqual(o['geoip_attribution'], 'IP Geolocation by DB-IP')

    def test_the_overview_says_whether_controls_work(self):
        self.assertTrue(self.get_json('/api/overview')['controls'])

    def test_controls_are_refused_off_loopback(self):
        """
        Bound to a network, the token is all that stands between that network and
        turning monitoring off. Called directly, so no test binds a public address.
        """
        from src.headless import RequestRefused
        public = HeadlessServer(self.app, host='0.0.0.0', port=0)
        self.assertFalse(public.controls_allowed)
        for route in (public._post_monitoring_stop, public._post_monitoring_start,
                      public._post_alerts_ack_all):
            with self.subTest(route=route.__name__), \
                    self.assertRaises(RequestRefused) as ctx:
                route({}, None, 0)
            self.assertEqual(ctx.exception.status, 403)
        self.assertTrue(self.app.capture_engine.is_running)
        self.assertFalse(public._route_overview({})[0]['controls'])


class TestUploadNames(unittest.TestCase):
    def test_names_cannot_leave_the_folder(self):
        from src.web_scan import safe_relpath
        cases = {'../../etc/passwd': os.path.join('etc', 'passwd'),
                 'C:\\Windows\\win.ini': os.path.join('C_', 'Windows', 'win.ini'),
                 '/abs/x.pcap': os.path.join('abs', 'x.pcap'),
                 '..': 'upload', '': 'upload', 'a/./b': os.path.join('a', 'b')}
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(safe_relpath(name), expected)


class TestCommandLine(unittest.TestCase):

    def test_defaults_do_not_enable_headless(self):
        import main
        args = main.parse_args([])
        self.assertFalse(args.headless)
        self.assertEqual(args.host, '127.0.0.1')
        self.assertEqual(args.port, 8737)

    def test_headless_flags_parse(self):
        import main
        args = main.parse_args(['--headless', '--host', '0.0.0.0',
                                '--port', '9000', '--no-api'])
        self.assertTrue(args.headless)
        self.assertEqual(args.host, '0.0.0.0')
        self.assertEqual(args.port, 9000)
        self.assertTrue(args.no_api)

    def test_help_and_version_exit_cleanly(self):
        import main
        for flag in ('--help', '--version'):
            with self.subTest(flag=flag), self.assertRaises(SystemExit) as ctx:
                main.parse_args([flag])
            self.assertEqual(ctx.exception.code, 0)

    def test_core_app_does_not_import_tkinter(self):
        """
        The whole premise of headless mode: the engine never needed a display.
        Guards against a stray `import tkinter` creeping into a core module.
        """
        import glob
        root = os.path.dirname(os.path.abspath(__file__))
        for path in glob.glob(os.path.join(root, 'src', '*.py')):
            if os.path.basename(path) == 'gui.py':
                continue
            with open(path, encoding='utf-8') as f:
                source = f.read()
            with self.subTest(module=os.path.basename(path)):
                self.assertNotIn('import tkinter', source)
                self.assertNotIn('from tkinter', source)


class TestLogFile(unittest.TestCase):

    def test_the_log_file_is_utf8(self):
        """
        Windows opened it in its ANSI code page, and logging drops a line it
        cannot encode, so a lookup of an international domain never reached it.
        In a fresh interpreter, because only the first logging setup applies.
        """
        home = tempfile.mkdtemp(prefix='ns_log_')
        self.addCleanup(shutil.rmtree, home, True)
        script = (
            "import logging, main\n"
            "handler = next(h for h in logging.getLogger().handlers\n"
            "               if isinstance(h, logging.FileHandler))\n"
            "logging.getLogger('t').warning('lookup of \\u65e5\\u672c.example')\n"
            "print(handler.encoding)\n"
            "print(handler.baseFilename)\n")
        env = dict(os.environ, HOME=home, USERPROFILE=home, PYTHONIOENCODING='utf-8')
        done = subprocess.run([sys.executable, '-c', script], capture_output=True,
                              text=True, encoding='utf-8', env=env, timeout=120,
                              cwd=os.path.dirname(os.path.abspath(__file__)))
        self.assertEqual(done.returncode, 0, done.stderr)
        encoding, path = done.stdout.splitlines()[-2:]
        self.assertEqual(encoding, 'utf-8')
        with open(path, encoding='utf-8') as f:
            self.assertIn('lookup of 日本.example', f.read())


if __name__ == '__main__':
    unittest.main(verbosity=2)
