"""
Foreign Host headers.
=====================
The page carries the token every write needs. A page on any website can point
its own hostname at 127.0.0.1 (DNS rebinding) and then read this server as
same-origin, so while bound to loopback a request naming any other host is
refused before anything is served — the page included.
"""

import http.client
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.web import WebServer, _host_name  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')
RULES = os.path.join(ROOT, 'netmon', 'rules')


class _Case(unittest.TestCase):
    allow_edit = True

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-hosts-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        profile = os.path.join(self.scratch, 'site.yaml')
        shutil.copy(EXAMPLE, profile)
        self.server = WebServer(profile, RULES, None, host='127.0.0.1', port=0,
                                allow_edit=self.allow_edit)
        self.port = self.server.start()
        self.addCleanup(self.server.stop)

    def request(self, method, path, host, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        self.addCleanup(connection.close)
        sent = {'Host': host}
        sent.update(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            sent['Content-Type'] = 'application/json'
        connection.request(method, path, body=data, headers=sent)
        response = connection.getresponse()
        return response.status, response.read().decode('utf-8', 'replace')


class TestRebinding(_Case):

    def test_the_page_is_not_served_to_a_foreign_host(self):
        status, body = self.request('GET', '/', 'attacker.example')
        self.assertEqual(status, 421)
        self.assertNotIn(self.server.token, body)

    def test_the_api_is_not_served_to_a_foreign_host(self):
        for path in ('/api/devices', '/api/profile', '/api/summary',
                     '/static/app.js'):
            with self.subTest(path=path):
                status, _ = self.request('GET', path, 'attacker.example:8788')
                self.assertEqual(status, 421)

    def test_head_is_checked_too(self):
        status, _ = self.request('HEAD', '/', 'attacker.example')
        self.assertEqual(status, 421)

    def test_a_write_from_a_foreign_host_is_refused_even_with_the_token(self):
        status, body = self.request(
            'POST', '/api/reload', 'attacker.example', body={},
            headers={'X-Netmon-Token': self.server.token})
        self.assertEqual(status, 421)
        self.assertIn('Host', body)

    def test_a_missing_host_is_refused(self):
        status, _ = self.request('GET', '/', '')
        self.assertEqual(status, 421)

    def test_every_loopback_spelling_is_served(self):
        for host in (f'127.0.0.1:{self.port}', f'localhost:{self.port}',
                     f'[::1]:{self.port}', 'LOCALHOST', '127.0.0.1'):
            with self.subTest(host=host):
                status, body = self.request('GET', '/', host)
                self.assertEqual(status, 200)
                self.assertIn(self.server.token, body)

    def test_a_loopback_lookalike_is_not_loopback(self):
        for host in ('localhost.attacker.example', '127.0.0.1.nip.io',
                     'evil-localhost'):
            with self.subTest(host=host):
                self.assertEqual(self.request('GET', '/', host)[0], 421)


class TestCrossSiteWrites(_Case):

    def post(self, headers):
        sent = {'X-Netmon-Token': self.server.token}
        sent.update(headers)
        return self.request('POST', '/api/reload', f'127.0.0.1:{self.port}',
                            body={}, headers=sent)

    def test_a_null_origin_is_refused(self):
        """Sandboxed frames and file:// pages send `Origin: null`."""
        status, body = self.post({'Origin': 'null'})
        self.assertEqual(status, 403)
        self.assertIn('cross-origin', body)

    def test_a_cross_site_fetch_is_refused_without_an_origin(self):
        status, body = self.post({'Sec-Fetch-Site': 'cross-site'})
        self.assertEqual(status, 403)
        self.assertIn('cross-origin', body)

    def test_the_origin_check_ignores_case(self):
        status, _ = self.post({'Origin': f'HTTP://127.0.0.1:{self.port}'})
        self.assertEqual(status, 200)

    def test_same_origin_is_allowed(self):
        status, _ = self.post({'Origin': f'http://127.0.0.1:{self.port}',
                               'Sec-Fetch-Site': 'same-origin'})
        self.assertEqual(status, 200)


class TestWhereTheAllowlistApplies(unittest.TestCase):

    def test_a_loopback_bind_has_one(self):
        for host in ('127.0.0.1', 'localhost', '::1'):
            with self.subTest(host=host):
                self.assertIsNotNone(WebServer(EXAMPLE, RULES, None,
                                               host=host).allowed_hosts())

    def test_any_other_bind_does_not(self):
        """The names it is reached by are the site's business; the firewall is
        the boundary, which the startup warning says."""
        self.assertIsNone(WebServer(EXAMPLE, RULES, None,
                                    host='0.0.0.0').allowed_hosts())
        self.assertIsNone(WebServer(EXAMPLE, RULES, None,
                                    host='10.10.1.5').allowed_hosts())

    def test_an_ipv6_url_is_bracketed(self):
        server = WebServer(EXAMPLE, RULES, None, host='::1', port=8788)
        self.assertEqual(server.url(), 'http://[::1]:8788/')


class TestHostParsing(unittest.TestCase):

    def test_shapes(self):
        cases = {'127.0.0.1:8788': '127.0.0.1', 'LocalHost:1': 'localhost',
                 '[::1]:8788': '::1', '[::1]': '::1', '::1': '::1',
                 'localhost': 'localhost', '': '', None: ''}
        for header, expected in cases.items():
            with self.subTest(header=header):
                self.assertEqual(_host_name(header), expected)


if __name__ == '__main__':
    unittest.main(verbosity=2)
