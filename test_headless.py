"""
Headless mode and the read-only HTTP API.
==========================================
Tests run against a real HTTP listener on an OS-assigned port, not against the
route functions directly, so the wire behaviour — status codes, content types,
headers — is covered too.
"""

import json
import os
import sys
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src.headless import HeadlessServer  # noqa: E402
from src.ids_engine import Alert, Severity  # noqa: E402


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
            'is_monitoring': True,
            'score_history': [{'t': i} for i in range(1000)],
        }


class _ApiTestCase(unittest.TestCase):

    def setUp(self):
        self.app = _StubApp()
        for rule, sev in [('SYN-FLOOD', Severity.CRITICAL),
                          ('PORT-SCAN', Severity.HIGH),
                          ('DNS-FAST-FLUX', Severity.HIGH),
                          ('ODD-HOURS', Severity.LOW)]:
            alert = Alert(rule, sev, f'{rule} test', 'demo',
                          src_ip='203.0.113.9', dst_ip='192.168.1.50',
                          category='Test')
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
        """No endpoint may change state; POST must not be accepted."""
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
        self.assertEqual(args.port, 8787)

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
            with open(path) as f:
                source = f.read()
            with self.subTest(module=os.path.basename(path)):
                self.assertNotIn('import tkinter', source)
                self.assertNotIn('from tkinter', source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
