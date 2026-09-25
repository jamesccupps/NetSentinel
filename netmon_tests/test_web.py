"""
The web UI.
===========
Tests run against a real listener on an OS-assigned port, so the wire behaviour
— status codes, headers, the token check — is covered rather than assumed.

The security tests are the point of this file. This page serves a complete map
of the network and has no login, so what protects it is that it listens on
localhost, refuses cross-origin writes, will not serve anything outside its own
directory, and does not write at all unless editing was explicitly turned on.
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

from netmon.analyze import Analyzer  # noqa: E402
from netmon.profile import load_profile  # noqa: E402
from netmon.rules_engine import load_rules  # noqa: E402
from netmon.sources.unifi_csv import COLUMNS, read_flows  # noqa: E402
from netmon.web import WebServer  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')
RULES = os.path.join(ROOT, 'netmon', 'rules')


def read(path):
    with open(path, encoding='utf-8') as f:
        return f.read()


def write_export(path):
    base = {name: '' for name in COLUMNS}
    base.update({'Action': 'allowed', 'Protocol': 'tcp', 'Direction': 'outgoing',
                 'Packets': '12', 'Bytes Sent': '500', 'Bytes Rec.': '1000'})
    rows = [dict(base, **{
        'UTC Date / Time': '2026-09-24T14:02:00Z', 'Src. MAC': '00:11:22:00:00:02',
        'Src. Ip': '10.10.20.21', 'Dst. Ip': '203.0.113.200', 'Dst. Port': '443',
        'Query': 'relay-9f2.net.anydesk.com'})]
    with open(path, 'w') as f:
        f.write(';'.join(COLUMNS) + '\n')
        for row in rows:
            f.write(';'.join(str(row[name]) for name in COLUMNS) + '\n')
    return path


class _WebTestCase(unittest.TestCase):
    allow_edit = False
    with_analysis = True

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-web-')
        self.addCleanup(shutil.rmtree, self.scratch, True)

        # Work on copies: a test that writes must never touch the shipped files.
        self.profile_path = os.path.join(self.scratch, 'site.yaml')
        shutil.copy(EXAMPLE, self.profile_path)
        self.rules_dir = os.path.join(self.scratch, 'rules')
        shutil.copytree(RULES, self.rules_dir)

        analyzer = None
        if self.with_analysis:
            export = write_export(os.path.join(self.scratch, 'flows.csv'))
            analyzer = Analyzer(load_profile(self.profile_path),
                                load_rules(self.rules_dir))
            analyzer.feed(read_flows(export))

        self.server = WebServer(self.profile_path, self.rules_dir, analyzer,
                                host='127.0.0.1', port=0,
                                allow_edit=self.allow_edit)
        self.port = self.server.start()
        self.addCleanup(self.server.stop)
        self.base = f'http://127.0.0.1:{self.port}'

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as response:
            return response.status, dict(response.headers), response.read().decode()

    def get_json(self, path):
        return json.loads(self.get(path)[2])

    def post(self, path, body, token=None, origin=None):
        headers = {'Content-Type': 'application/json'}
        if token is not None:
            headers['X-Netmon-Token'] = token
        if origin is not None:
            headers['Origin'] = origin
        request = urllib.request.Request(
            self.base + path, data=json.dumps(body).encode(),
            headers=headers, method='POST')
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())


# ─── Serving ─────────────────────────────────────────────────────────────────

class TestServing(_WebTestCase):

    def test_the_page_loads(self):
        status, headers, body = self.get('/')
        self.assertEqual(status, 200)
        self.assertTrue(headers['Content-Type'].startswith('text/html'))
        self.assertIn('netmon', body)

    def test_static_assets_load_with_the_right_types(self):
        for path, expected in (('/static/style.css', 'text/css'),
                               ('/static/app.js', 'application/javascript')):
            with self.subTest(path=path):
                status, headers, _ = self.get(path)
                self.assertEqual(status, 200)
                self.assertTrue(headers['Content-Type'].startswith(expected))

    def test_the_page_carries_a_token(self):
        body = self.get('/')[2]
        self.assertIn(f'data-token="{self.server.token}"', body)
        self.assertNotIn('{{TOKEN}}', body)

    def test_the_page_knows_whether_editing_is_on(self):
        self.assertIn('data-editable="false"', self.get('/')[2])

    def test_unknown_paths_are_404_json(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.get('/nope')
        self.assertEqual(ctx.exception.code, 404)

    def test_head_returns_headers_without_a_body(self):
        request = urllib.request.Request(self.base + '/', method='HEAD')
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b'')


class TestResponseHardening(_WebTestCase):

    def test_security_headers_on_every_response(self):
        for path in ('/', '/static/app.js', '/api/summary'):
            with self.subTest(path=path):
                _, headers, _ = self.get(path)
                self.assertEqual(headers['Cache-Control'], 'no-store')
                self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
                self.assertEqual(headers['X-Frame-Options'], 'DENY')
                self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
                self.assertIn("default-src 'self'",
                              headers['Content-Security-Policy'])

    def test_the_policy_forbids_external_resources(self):
        """
        Nothing is fetched from anywhere. A sensor may have no route off the
        network, and a page that silently depends on a CDN renders blank there.
        """
        policy = self.get('/')[1]['Content-Security-Policy']
        self.assertIn("script-src 'self'", policy)
        self.assertIn("frame-ancestors 'none'", policy)

    def test_the_python_version_is_not_advertised(self):
        self.assertNotIn('Python', self.get('/')[1].get('Server', ''))

    def test_the_ui_source_contains_no_external_references(self):
        for name in ('index.html', 'app.js', 'style.css'):
            with self.subTest(name=name):
                source = self.get(f'/static/{name}')[2] if name != 'index.html' \
                    else self.get('/')[2]
                for scheme in ('http://', 'https://'):
                    self.assertNotIn(scheme + 'cdn', source)
                    self.assertNotIn(scheme + 'unpkg', source)
                    self.assertNotIn('fonts.googleapis', source)

    def test_the_ui_never_assigns_innerhtml(self):
        """
        Device names, SNI values and rule text come from the network being
        watched. Treating any of it as markup would let whatever is out there
        script this page.
        """
        source = self.get('/static/app.js')[2]
        # The assignment is the hazard; the word appears in a comment saying so.
        for hazard in ('.innerHTML =', '.outerHTML =', 'insertAdjacentHTML',
                       'document.write'):
            with self.subTest(hazard=hazard):
                self.assertNotIn(hazard, source)

    def test_paths_outside_the_ui_directory_are_refused(self):
        for path in ('/static/../web.py', '/static/../../setup.py',
                     '/static/../profiles/example-site.yaml',
                     '/static/%2e%2e/web.py'):
            with self.subTest(path=path):
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    self.get(path)
                self.assertEqual(ctx.exception.code, 404)


# ─── Read API ────────────────────────────────────────────────────────────────

class TestReadApi(_WebTestCase):

    def test_summary(self):
        body = self.get_json('/api/summary')
        self.assertEqual(body['site']['site'], 'Example Operations Centre')
        self.assertGreaterEqual(body['rules']['rules'], 15)
        self.assertFalse(body['editable'])

    def test_findings(self):
        body = self.get_json('/api/findings')
        self.assertEqual(body['count'], 1)
        self.assertEqual(body['findings'][0]['rule_id'], 'remote_access_tool')

    def test_findings_filter_by_severity(self):
        self.assertEqual(self.get_json('/api/findings?min_severity=critical')['count'], 1)
        self.assertEqual(
            self.get_json('/api/findings?min_severity=info&rule=bad_address')['count'], 0)

    def test_findings_filter_by_tier(self):
        self.assertEqual(self.get_json('/api/findings?tier=digest')['count'], 0)
        self.assertEqual(self.get_json('/api/findings?tier=push')['count'], 1)

    def test_a_garbage_filter_does_not_error(self):
        for query in ('?min_severity=nonsense', '?limit=abc', '?limit=-1',
                      '?tier=%00', '?rule=' + 'x' * 5000):
            with self.subTest(query=query):
                self.assertIn('count', self.get_json('/api/findings' + query))

    def test_devices_lists_everything_not_only_problems(self):
        """A list that shows only problems cannot tell you something went quiet."""
        body = self.get_json('/api/devices')
        self.assertEqual(len(body['devices']), 12)
        self.assertEqual(sum(1 for d in body['devices'] if d['findings']), 1)

    def test_devices_marks_metadata_only_segments(self):
        body = self.get_json('/api/devices')
        restricted = [d for d in body['devices'] if d['metadata_only']]
        self.assertTrue(restricted)
        self.assertTrue(all(d['vlan'] in (40, 50) for d in restricted))

    def test_vlans_are_listed_with_their_payload_policy(self):
        vlans = {v['id']: v for v in self.get_json('/api/devices')['vlans']}
        self.assertTrue(vlans[40]['metadata_only'])
        self.assertFalse(vlans[20]['metadata_only'])

    def test_rules_are_listed_with_their_grounding(self):
        rules = self.get_json('/api/rules')['rules']
        self.assertTrue(all(r['grounded_in'] for r in rules))

    def test_the_profile_source_is_served(self):
        body = self.get_json('/api/profile')
        self.assertIn('vlans:', body['source'])

    def test_a_rule_file_outside_the_rules_directory_is_refused(self):
        body = self.get_json('/api/rule?file=../../profile.py')
        self.assertIn('error', body)


class TestWithoutAnalysis(_WebTestCase):
    with_analysis = False

    def test_the_findings_view_says_nothing_has_been_run(self):
        """Rather than an empty list, which reads as an all-clear."""
        body = self.get_json('/api/findings')
        self.assertEqual(body['findings'], [])
        self.assertIn('note', body)

    def test_devices_still_works(self):
        self.assertEqual(len(self.get_json('/api/devices')['devices']), 12)


# ─── Capture filter builder ──────────────────────────────────────────────────

class TestFilterBuilder(_WebTestCase):

    def test_it_builds_the_safe_mixed_form(self):
        body = self.get_json('/api/filter?vlans=5,6&untagged=true')
        self.assertIn('ether[12:2]', body['bpf'])
        self.assertNotIn('vlan 5', body['bpf'])
        self.assertNotIn('vlan 6', body['bpf'])

    def test_it_says_the_result_is_unverified(self):
        """
        The whole reason the builder exists is that filters which look right
        match the wrong frames. Presenting one as settled would undo that.
        """
        body = self.get_json('/api/filter?vlans=5')
        self.assertTrue(body['unverified'])
        self.assertIn('Npcap', body['note'])

    def test_it_offers_the_wireshark_equivalent(self):
        body = self.get_json('/api/filter?vlans=5,6')
        self.assertEqual(body['wireshark'], '(vlan.id == 5 or vlan.id == 6)')

    def test_no_selection_means_capture_everything(self):
        self.assertEqual(self.get_json('/api/filter')['bpf'], '')

    def test_an_impossible_combination_is_reported_not_crashed(self):
        body = self.get_json('/api/filter?protocol=arp&ports=80')
        self.assertIn('no ports', body['error'])

    def test_garbage_input_does_not_error(self):
        for query in ('vlans=abc', 'vlans=' + '9' * 400, 'drop_ports=-1',
                      'vlans=5,,,6', 'drop_hosts=' + ',' * 100):
            with self.subTest(query=query):
                self.assertIn('bpf', self.get_json('/api/filter?' + query))

    def test_verification_needs_a_capture_that_exists(self):
        status, body = self.post('/api/filter/verify',
                                 {'bpf': 'tcp', 'pcap': '/nope.pcap'},
                                 token=self.server.token)
        self.assertEqual(status, 403)      # editing is off in this case


# ─── Writing ─────────────────────────────────────────────────────────────────

class TestWritingIsOffByDefault(_WebTestCase):

    def test_every_write_route_is_refused(self):
        for path in ('/api/profile/save', '/api/rules/save', '/api/reload',
                     '/api/filter/verify'):
            with self.subTest(path=path):
                status, body = self.post(path, {}, token=self.server.token)
                self.assertEqual(status, 403)
                self.assertIn('editing is off', body['error'])

    def test_the_profile_on_disk_is_untouched(self):
        before = read(self.profile_path)
        self.post('/api/profile/save', {'source': 'site: {name: hacked}'},
                  token=self.server.token)
        self.assertEqual(read(self.profile_path), before)


class TestWritingWhenEnabled(_WebTestCase):
    allow_edit = True

    def test_a_valid_profile_is_saved(self):
        source = read(self.profile_path).replace(
            'Example Operations Centre', 'Renamed Site')
        status, body = self.post('/api/profile/save', {'source': source},
                                 token=self.server.token)
        self.assertEqual(status, 200)
        self.assertEqual(body['summary']['site'], 'Renamed Site')
        self.assertIn('Renamed Site', read(self.profile_path))

    def test_the_previous_version_is_kept(self):
        original = read(self.profile_path)
        self.post('/api/profile/save', {'source': original.replace(
            'Example Operations Centre', 'Renamed')}, token=self.server.token)
        self.assertEqual(read(self.profile_path + '.bak'), original)

    def test_an_invalid_profile_is_refused_and_nothing_is_written(self):
        """
        Someone editing the profile is usually doing so because something is
        already wrong. Writing a broken one would stop the monitor starting.
        """
        before = read(self.profile_path)
        status, body = self.post(
            '/api/profile/save', {'source': 'devices: {not-a-mac: {name: x}}'},
            token=self.server.token)
        self.assertEqual(status, 400)
        self.assertIn('not a MAC address', body['detail'])
        self.assertEqual(read(self.profile_path), before)

    def test_malformed_yaml_is_refused(self):
        status, body = self.post('/api/profile/save',
                                 {'source': 'site: {unclosed'},
                                 token=self.server.token)
        self.assertEqual(status, 400)
        self.assertIn('YAML', body['error'])

    def test_a_valid_rule_file_is_saved(self):
        source = read(os.path.join(self.rules_dir, 'core.yaml'))
        status, body = self.post('/api/rules/save',
                                 {'file': 'core.yaml', 'source': source},
                                 token=self.server.token)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body['rules']['rules'], 15)

    def test_an_invalid_rule_file_is_refused_and_nothing_is_written(self):
        path = os.path.join(self.rules_dir, 'core.yaml')
        before = read(path)
        status, body = self.post(
            '/api/rules/save',
            {'file': 'core.yaml', 'source': '- id: x\n  when: {a: {bogus: 1}}\n'},
            token=self.server.token)
        self.assertEqual(status, 400)
        self.assertIn('unknown operator', body['detail'])
        self.assertEqual(read(path), before)

    def test_a_rule_file_outside_the_directory_cannot_be_written(self):
        status, body = self.post(
            '/api/rules/save', {'file': '../../profile.py', 'source': 'x'},
            token=self.server.token)
        self.assertEqual(status, 400)
        self.assertIn('no such rule file', body['error'])

    def test_verification_reports_a_missing_capture(self):
        status, body = self.post('/api/filter/verify',
                                 {'bpf': 'tcp', 'pcap': '/nope.pcap'},
                                 token=self.server.token)
        self.assertEqual(status, 400)
        self.assertIn('no such capture', body['error'])


class TestWriteAuthorisation(_WebTestCase):
    allow_edit = True

    def test_a_write_without_a_token_is_refused(self):
        status, body = self.post('/api/reload', {})
        self.assertEqual(status, 403)
        self.assertIn('token', body['error'])

    def test_a_write_with_the_wrong_token_is_refused(self):
        status, _ = self.post('/api/reload', {}, token='not-the-token')
        self.assertEqual(status, 403)

    def test_a_cross_origin_write_is_refused_even_with_a_valid_token(self):
        """
        Another page in the same browser must not be able to drive this one.
        """
        status, body = self.post('/api/reload', {}, token=self.server.token,
                                 origin='http://evil.example')
        self.assertEqual(status, 403)
        self.assertIn('cross-origin', body['error'])

    def test_a_same_origin_write_is_allowed(self):
        status, _ = self.post('/api/reload', {}, token=self.server.token,
                              origin=f'http://127.0.0.1:{self.port}')
        self.assertEqual(status, 200)

    def test_each_server_gets_its_own_token(self):
        other = WebServer(self.profile_path, self.rules_dir, None, port=0)
        self.addCleanup(other.stop)
        self.assertNotEqual(other.token, self.server.token)
        self.assertGreaterEqual(len(other.token), 32)

    def test_an_oversized_body_is_refused(self):
        status, body = self.post('/api/profile/save',
                                 {'source': 'x' * (3 * 1024 * 1024)},
                                 token=self.server.token)
        self.assertEqual(status, 413)
        self.assertIn('too large', body['error'])

    def test_a_body_that_is_not_json_is_refused(self):
        request = urllib.request.Request(
            self.base + '/api/reload', data=b'not json',
            headers={'X-Netmon-Token': self.server.token}, method='POST')
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(ctx.exception.code, 400)

    def test_an_unknown_post_route_is_404(self):
        status, _ = self.post('/api/nope', {}, token=self.server.token)
        self.assertEqual(status, 404)


class TestDefaults(unittest.TestCase):

    def test_it_binds_to_localhost(self):
        """
        This page is a map of the network and has no login. Listening anywhere
        else should take a deliberate act.
        """
        server = WebServer(EXAMPLE, RULES, None)
        self.assertEqual(server.host, '127.0.0.1')

    def test_editing_is_off(self):
        self.assertFalse(WebServer(EXAMPLE, RULES, None).allow_edit)

    def test_stop_is_idempotent(self):
        server = WebServer(EXAMPLE, RULES, None, port=0)
        server.start()
        server.stop()
        server.stop()

    def test_start_is_idempotent(self):
        server = WebServer(EXAMPLE, RULES, None, port=0)
        self.addCleanup(server.stop)
        self.assertEqual(server.start(), server.start())


if __name__ == '__main__':
    unittest.main(verbosity=2)
