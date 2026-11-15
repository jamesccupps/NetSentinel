"""
The dashboard opens only from NetSentinel.
==========================================
The outside review of 2026-11-14 (N1): GET / handed the page, with the token
in it, to anything that sent a loopback Host header, so any program on this
PC, of any account and without rights, could fetch the token and use every
control of a process running as Administrator: stop monitoring, mark alerts
false (which silences the rule), accept exposures, start an audit. Every GET
needed only the Host header. Off loopback the page and token went to anyone
who could reach the port, and the upload routes were not behind the loopback
check.

Now the session is a cookie that only a link the app opens hands out; the
page never carries the token; uploads are loopback only.
"""

import json
import os
import sys
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401

from test_headless import _ApiTestCase  # noqa: E402


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(url, cookie=None):
    """(status, headers, body) without following a redirect, as another program would."""
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(url, headers={'Cookie': cookie} if cookie else {})
    try:
        with opener.open(request, timeout=5) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


class TestAnotherProgram(_ApiTestCase):
    """What a program on this PC gets by asking the port, with no link from the app."""

    def test_the_page_says_to_open_it_from_netsentinel_and_carries_nothing(self):
        status, headers, body = fetch(self.base + '/')
        self.assertEqual(status, 401)
        self.assertIn('Open the dashboard from NetSentinel', body)
        self.assertNotIn(self.server.token, body)
        self.assertNotIn(self.server.session, body)
        self.assertNotIn('Set-Cookie', headers)

    def test_no_data_route_answers(self):
        from src.headless import SESSION_REFUSED
        for path in ('/api/session', '/api/alerts', '/api/overview', '/api/exposures',
                     '/api/devices', '/api/status', '/status.txt', '/api/unifi-logs/devices'):
            with self.subTest(path=path):
                status, _, body = fetch(self.base + path)
                self.assertEqual(status, 401)
                self.assertEqual(json.loads(body)['error'], SESSION_REFUSED)

    def test_no_control_answers_even_with_the_token(self):
        """Guessing or stealing the token is not enough without the cookie."""
        for path in ('/api/monitoring/stop', '/api/alerts/ack-all', '/api/scan/new'):
            with self.subTest(path=path):
                status, _ = self.post(path, session=False)
                self.assertEqual(status, 401)
        self.assertTrue(self.app.capture_engine.is_running)

    def test_a_wrong_cookie_or_key_is_refused(self):
        from src.headless import SESSION_COOKIE
        self.assertEqual(fetch(self.base + '/api/alerts', f'{SESSION_COOKIE}=guess')[0], 401)
        self.assertEqual(fetch(self.base + '/api/alerts', 'malformed;;==')[0], 401)
        self.assertEqual(fetch(self.base + '/open?key=guess')[0], 403)
        self.assertEqual(fetch(self.base + '/open')[0], 403)

    def test_health_metrics_and_the_scripts_need_no_session(self):
        for path in ('/health', '/api/metrics', '/static/app.js', '/static/style.css'):
            with self.subTest(path=path):
                self.assertEqual(fetch(self.base + path)[0], 200)


class TestALinkFromTheApp(_ApiTestCase):

    def open(self, url):
        status, headers, _ = fetch(url)
        self.assertEqual(status, 303)
        cookie = headers['Set-Cookie']
        return headers['Location'], cookie

    def test_it_sets_a_strict_http_only_session_and_goes_to_the_page(self):
        location, cookie = self.open(self.server.open_url('#audit'))
        self.assertEqual(location, '/')          # the link's #audit is kept by the browser
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Strict', cookie)
        session = cookie.split(';')[0]
        self.assertEqual(fetch(self.base + '/', session)[0], 200)
        token = json.loads(fetch(self.base + '/api/session', session)[2])['token']
        self.assertEqual(token, self.server.token)

    def test_a_link_works_once(self):
        url = self.server.open_url()
        self.open(url)
        self.assertEqual(fetch(url)[0], 403)

    def test_a_link_left_unused_expires(self):
        from src import headless
        url = self.server.open_url()
        later = time.monotonic() + headless.OPEN_LINK_SECONDS + 1
        with mock.patch.object(headless.time, 'monotonic', return_value=later):
            self.assertEqual(fetch(url)[0], 403)

    def test_headless_has_a_link_that_works_again(self):
        """Printed to its console once; nobody can click a new one there."""
        url = self.server.open_url(reusable=True)
        self.open(url)
        self.open(url)

    def test_another_processs_session_does_not_open_this_one(self):
        from src.headless import SESSION_COOKIE, HeadlessServer
        other = HeadlessServer(self.app)
        self.assertEqual(fetch(self.base + '/api/alerts', f'{SESSION_COOKIE}={other.session}')[0],
                         401)

    def test_the_desktop_app_opens_the_link_not_the_bare_address(self):
        from src import gui
        g = gui.NetSentinelGUI.__new__(gui.NetSentinelGUI)
        g.app = type('App', (), {'web_server': self.server})()
        with mock.patch('webbrowser.open') as opened:
            g._open_dashboard('#audit')
        [url] = opened.call_args[0]
        self.assertIn('/open?key=', url)
        self.assertTrue(url.endswith('#audit'))
        self.open(url)

    def test_headless_prints_the_link_to_the_console_not_the_log(self):
        import io
        from contextlib import redirect_stdout
        from src import headless

        class _App:
            last_start_error = ''

            def start_monitoring(self):
                return True

            def stop_monitoring(self):
                pass

        out = io.StringIO()
        with redirect_stdout(out), mock.patch.object(headless, 'DEFAULT_PORT', 0), \
                mock.patch.object(headless.time, 'sleep', side_effect=KeyboardInterrupt), \
                self.assertLogs('NetSentinel.Headless', level='INFO') as logs:
            self.assertEqual(headless.run_headless(_App(), port=0), 0)
        self.assertIn('/open?key=', out.getvalue())
        self.assertFalse(any('key=' in line for line in logs.output))


class TestOffLoopback(_ApiTestCase):

    def test_uploads_are_refused_off_loopback(self):
        """Parsed by a process running as Administrator; called directly, so no
        test binds a public address."""
        from src.headless import HeadlessServer, RequestRefused
        public = HeadlessServer(self.app, host='0.0.0.0', port=0)
        for route in (public._post_scan_new, public._post_scan_upload,
                      public._post_scan_upload_batch, public._post_scan_start):
            with self.subTest(route=route.__name__), self.assertRaises(RequestRefused) as ctx:
                route({'id': ['x'], 'name': ['a.txt']}, None, 0)
            self.assertEqual(ctx.exception.status, 403)


if __name__ == '__main__':
    unittest.main()
