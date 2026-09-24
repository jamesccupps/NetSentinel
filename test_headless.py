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
        status, headers, body = self.get('/')
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
