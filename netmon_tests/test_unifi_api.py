"""
Bootstrapping a profile from the UniFi controller.
===================================================
The certificate tests run against real TLS servers with real self-signed
certificates, one of them an impostor presenting a different one. Pinning is
the kind of thing that must be shown to work rather than asserted — a pin that
is checked after the request body is sent, or not checked at all, looks
identical from the calling code.

The merge tests are the other half: a sync that clobbered hand-written roles
would be run exactly once.
"""

import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml  # noqa: E402

from netmon.profile import SiteProfile  # noqa: E402
from netmon.sources.unifi_api import (UnifiApiError, UnifiClient,  # noqa: E402
                                      _clean_name, _guess_role, build_profile,
                                      certificate_fingerprint, fetch_inventory,
                                      merge_profile, write_profile)

HAVE_OPENSSL = shutil.which('openssl') is not None


# ─── A controller to talk to ─────────────────────────────────────────────────

SAMPLE = {
    'devices': [{'mac': '00:11:22:33:44:55', 'name': 'Core Switch',
                 'ip': '10.0.1.2', 'type': 'usw', 'model': 'USW-Pro-24'}],
    'clients': [{'mac': 'aa:bb:cc:00:00:01', 'hostname': 'AHU-Controller-1',
                 'ip': '10.0.20.21', 'vlan': 20, 'sw_port': 7}],
    'known_clients': [{'mac': 'aa:bb:cc:00:00:02', 'name': 'Lobby Camera',
                       'fixed_ip': '10.0.30.5'}],
    'networks': [{'vlan': 20, 'name': 'HVAC', 'ip_subnet': '10.0.20.0/24',
                  'gateway_ip': '10.0.20.1'}],
}


def _handler_for(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, payload, status=200):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            state['requests'].append(('GET', self.path,
                                      dict(self.headers.items())))
            if state.get('status'):
                return self._send({'error': 'no'}, state['status'])
            for name, rows in SAMPLE.items():
                if name.replace('_', '') in self.path.replace('/', '') \
                        or _endpoint_matches(name, self.path):
                    return self._send({'data': rows})
            self._send({'data': []})

        def do_POST(self):
            state['requests'].append(('POST', self.path, {}))
            self.send_response(200)
            self.send_header('Set-Cookie', 'TOKEN=abc; Path=/')
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'{}')

    return Handler


def _endpoint_matches(name, path):
    return {'devices': 'stat/device', 'clients': 'stat/sta',
            'known_clients': 'rest/user',
            'networks': 'rest/networkconf'}[name] in path


def _make_cert(directory, name):
    key = os.path.join(directory, f'{name}.key')
    crt = os.path.join(directory, f'{name}.crt')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', key, '-out', crt, '-days', '1',
                    '-subj', '/CN=localhost'], check=True, capture_output=True)
    return key, crt


class _ServerCase(unittest.TestCase):
    """A real HTTPS controller, and a real impostor presenting another cert."""

    @classmethod
    def setUpClass(cls):
        if not HAVE_OPENSSL:
            raise unittest.SkipTest('needs openssl to make a certificate')
        cls.scratch = tempfile.mkdtemp(prefix='netmon-unifi-')
        cls.servers = []
        cls.real, cls.real_port, cls.real_state = cls._serve('real')
        cls.fake, cls.fake_port, cls.fake_state = cls._serve('fake')
        cls.real_fingerprint = certificate_fingerprint('127.0.0.1', cls.real_port)
        cls.fake_fingerprint = certificate_fingerprint('127.0.0.1', cls.fake_port)

    @classmethod
    def _serve(cls, name):
        key, crt = _make_cert(cls.scratch, name)
        state = {'requests': []}
        server = HTTPServer(('127.0.0.1', 0), _handler_for(state))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(crt, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        cls.servers.append(server)
        return server, server.server_address[1], state

    @classmethod
    def tearDownClass(cls):
        for server in getattr(cls, 'servers', []):
            server.shutdown()
            server.server_close()
        shutil.rmtree(getattr(cls, 'scratch', ''), ignore_errors=True)

    def setUp(self):
        self.real_state['requests'].clear()
        self.fake_state['requests'].clear()
        self.real_state.pop('status', None)

    def client(self, port=None, **kw):
        return UnifiClient(f'https://127.0.0.1:{port or self.real_port}',
                           api_key='test-key', **kw)


# ─── Certificates ────────────────────────────────────────────────────────────

class TestCertificatePinning(_ServerCase):
    """
    A UniFi gateway on your own network presents a self-signed certificate, and
    the usual advice is to turn verification off — which converts "this is the
    controller" into "this is whatever answered", on the one connection about to
    hand over an API key.
    """

    def test_the_right_pin_connects(self):
        client = self.client(fingerprint=self.real_fingerprint)
        self.assertEqual(len(client.get('/api/s/default/stat/device')), 1)

    def test_an_impostor_presenting_another_certificate_is_refused(self):
        client = self.client(port=self.fake_port,
                             fingerprint=self.real_fingerprint)
        with self.assertRaises(UnifiApiError) as ctx:
            client.get('/api/s/default/stat/device')
        self.assertIn('fingerprint does not match', str(ctx.exception))

    def test_the_impostor_never_sees_the_request(self):
        """
        The check has to happen before anything is sent. A pin verified after
        the request body went out looks identical from the calling code.
        """
        client = self.client(port=self.fake_port,
                             fingerprint=self.real_fingerprint)
        with self.assertRaises(UnifiApiError):
            client.get('/api/s/default/stat/device')
        self.assertEqual(self.fake_state['requests'], [])

    def test_a_self_signed_certificate_without_a_pin_is_refused(self):
        with self.assertRaises(UnifiApiError) as ctx:
            self.client().get('/api/s/default/stat/device')
        self.assertIn('self-signed', str(ctx.exception))

    def test_that_refusal_points_at_the_right_fix(self):
        """Not 'turn verification off', which is what people do otherwise."""
        with self.assertRaises(UnifiApiError) as ctx:
            self.client().get('/api/s/default/stat/device')
        self.assertIn('--fingerprint', str(ctx.exception))

    def test_insecure_connects_and_says_what_it_gives_up(self):
        with self.assertLogs('netmon.sources.unifi_api', level='WARNING') as logs:
            client = self.client(port=self.fake_port, insecure=True)
        self.assertEqual(len(client.get('/api/s/default/stat/device')), 1)
        self.assertIn('read the API key', ' '.join(logs.output))

    def test_the_fingerprint_can_be_read_from_the_host(self):
        self.assertRegex(self.real_fingerprint,
                         r'^([0-9A-F]{2}:){31}[0-9A-F]{2}$')

    def test_two_certificates_have_different_fingerprints(self):
        self.assertNotEqual(self.real_fingerprint, self.fake_fingerprint)

    def test_the_fingerprint_may_be_given_in_any_notation(self):
        plain = self.real_fingerprint.replace(':', '')
        for value in (plain, plain.lower(), self.real_fingerprint,
                      self.real_fingerprint.lower()):
            with self.subTest(value=value[:16]):
                client = self.client(fingerprint=value)
                self.assertEqual(len(client.get('/api/s/default/stat/device')), 1)

    def test_no_fingerprint_means_ordinary_verification_not_none(self):
        """An empty value is 'not given', and falls back to the CA path."""
        client = self.client(fingerprint='')
        with self.assertRaises(UnifiApiError) as ctx:
            client.get('/api/s/default/stat/device')
        self.assertIn('self-signed', str(ctx.exception))

    def test_a_malformed_fingerprint_is_refused_at_construction(self):
        for bad in ('abc', 'not-a-fingerprint', 'AA:BB', 'AB' * 40):
            with self.subTest(bad=bad):
                with self.assertRaises(UnifiApiError) as ctx:
                    self.client(fingerprint=bad)
                self.assertIn('64 hex characters', str(ctx.exception))

    def test_an_unreachable_host_is_reported(self):
        with self.assertRaises(UnifiApiError) as ctx:
            certificate_fingerprint('127.0.0.1', 1)
        self.assertIn('could not reach', str(ctx.exception))


# ─── Read-only ───────────────────────────────────────────────────────────────

class TestItIsReadOnly(_ServerCase):

    def test_the_client_has_no_write_method(self):
        """
        Structural, not a convention: there is no post, put or delete to reach
        for by accident. Adding one would be a deliberate act.
        """
        client = self.client(fingerprint=self.real_fingerprint)
        for verb in ('post', 'put', 'delete', 'patch', 'write', 'set', 'update'):
            with self.subTest(verb=verb):
                self.assertFalse(hasattr(client, verb))

    def test_a_full_sync_issues_only_gets(self):
        client = self.client(fingerprint=self.real_fingerprint)
        fetch_inventory(client)
        methods = {method for method, _, _ in self.real_state['requests']}
        self.assertEqual(methods, {'GET'})

    def test_login_is_the_only_post_and_only_without_a_key(self):
        client = self.client(fingerprint=self.real_fingerprint)
        client.login()
        self.assertEqual(self.real_state['requests'], [])

    def test_the_api_key_is_sent_as_a_header(self):
        client = self.client(fingerprint=self.real_fingerprint)
        client.get('/api/s/default/stat/device')
        _, _, headers = self.real_state['requests'][0]
        # HTTP header names are case-insensitive and urllib normalises them.
        lowered = {k.lower(): v for k, v in headers.items()}
        self.assertEqual(lowered.get('x-api-key'), 'test-key')

    def test_the_key_never_appears_in_the_url(self):
        """A URL ends up in logs and in proxy access records; a header does not."""
        client = self.client(fingerprint=self.real_fingerprint)
        client.get('/api/s/default/stat/device')
        _, path, _ = self.real_state['requests'][0]
        self.assertNotIn('test-key', path)

    def test_describe_never_includes_the_key(self):
        client = self.client(fingerprint=self.real_fingerprint)
        self.assertNotIn('test-key', json.dumps(client.describe()))
        self.assertTrue(client.describe()['authenticated'])


class TestFetching(_ServerCase):

    def test_everything_is_fetched(self):
        inventory = fetch_inventory(self.client(fingerprint=self.real_fingerprint))
        self.assertEqual(len(inventory['devices']), 1)
        self.assertEqual(len(inventory['clients']), 1)
        self.assertEqual(len(inventory['networks']), 1)
        self.assertEqual(inventory['errors'], {})

    def test_one_endpoint_failing_does_not_lose_the_rest(self):
        """A controller that will not list its networks can still list devices."""
        self.real_state['status'] = 500
        inventory = fetch_inventory(self.client(fingerprint=self.real_fingerprint))
        self.assertTrue(inventory['errors'])
        self.assertEqual(inventory['devices'], [])

    def test_bad_credentials_say_what_is_needed(self):
        self.real_state['status'] = 403
        with self.assertRaises(UnifiApiError) as ctx:
            self.client(fingerprint=self.real_fingerprint).get('/api/x')
        self.assertIn('view-only', str(ctx.exception))


# ─── Building a profile ──────────────────────────────────────────────────────

class TestBuildProfile(unittest.TestCase):

    def build(self, inventory=None, existing=None):
        return build_profile(inventory or dict(SAMPLE), 'Test Site', existing)

    def test_vlans_come_from_the_networks(self):
        profile, _ = self.build()
        self.assertEqual(profile['vlans'][20]['subnet'], '10.0.20.0/24')
        self.assertEqual(profile['vlans'][20]['gateway'], '10.0.20.1')

    def test_infrastructure_gets_a_role(self):
        profile, _ = self.build()
        self.assertEqual(profile['devices']['00:11:22:33:44:55']['role'],
                         'network_device')

    def test_a_role_is_guessed_from_the_name(self):
        profile, _ = self.build()
        self.assertEqual(profile['devices']['aa:bb:cc:00:00:01']['role'],
                         'controller')
        self.assertEqual(profile['devices']['aa:bb:cc:00:00:02']['role'],
                         'camera')

    def test_an_unguessable_name_gets_no_role_rather_than_a_wrong_one(self):
        """A wrong role is worse than none, because rules act on it."""
        profile, _ = self.build({'clients': [
            {'mac': 'aa:bb:cc:00:00:09', 'hostname': 'DESKTOP-4F2X', 'ip': '10.0.60.5'}]})
        self.assertEqual(profile['devices']['aa:bb:cc:00:00:09']['role'], 'unknown')

    def test_the_switch_port_is_recorded(self):
        profile, _ = self.build()
        self.assertEqual(profile['devices']['aa:bb:cc:00:00:01']['switch_port'],
                         'port 7')

    def test_referenced_roles_are_defined_so_it_validates(self):
        profile, _ = self.build()
        SiteProfile(profile)             # must not raise
        for device in profile['devices'].values():
            if device['role'] != 'unknown':
                self.assertIn(device['role'], profile['roles'])

    def test_the_result_loads_as_a_profile(self):
        profile, _ = self.build()
        loaded = SiteProfile(profile)
        self.assertEqual(loaded.summary()['devices'], 3)

    def test_a_malformed_mac_is_skipped(self):
        profile, _ = self.build({'clients': [
            {'mac': 'not-a-mac', 'hostname': 'x'},
            {'mac': None, 'hostname': 'y'},
            {'mac': 'aa:bb:cc:00:00:03', 'hostname': 'ok'}]})
        self.assertEqual(list(profile['devices']), ['aa:bb:cc:00:00:03'])

    def test_junk_rows_do_not_stop_the_build(self):
        profile, _ = self.build({'clients': ['not a dict', 42, None],
                                 'networks': ['junk'], 'devices': [None]})
        self.assertEqual(profile['devices'], {})


class TestNamesAreSanitised(unittest.TestCase):
    """
    Names come from DHCP and from whoever set them, so they reach this from the
    network. One must not carry a newline into a notification header or a quote
    into the profile.
    """

    def test_control_characters_are_removed(self):
        self.assertNotIn('\n', _clean_name('evil\r\nX-Injected: yes'))

    def test_quotes_and_yaml_punctuation_are_removed(self):
        for hostile in ('a"b', "a'b", 'a: b', 'a\x00b', '{a}', '[a]', '&a'):
            with self.subTest(hostile=hostile):
                cleaned = _clean_name(hostile)
                for character in '"\'\x00{}[]&:':
                    self.assertNotIn(character, cleaned)

    def test_a_very_long_name_is_truncated(self):
        self.assertLessEqual(len(_clean_name('x' * 5000)), 64)

    def test_placeholders_become_empty(self):
        for placeholder in ('', 'unknown', 'N/A', 'null', 'None'):
            with self.subTest(placeholder=placeholder):
                self.assertEqual(_clean_name(placeholder), '')

    def test_a_sanitised_name_still_loads_as_yaml(self):
        profile, _ = build_profile({'clients': [
            {'mac': 'aa:bb:cc:00:00:01',
             'hostname': 'evil"\n  role: admin\n  x: '}]}, 'Site')
        text = yaml.safe_dump(profile)
        reloaded = yaml.safe_load(text)
        self.assertEqual(reloaded['devices']['aa:bb:cc:00:00:01']['role'],
                         'unknown')


class TestMergingKeepsWhatYouWrote(unittest.TestCase):
    """A sync that clobbered hand-written roles would be run exactly once."""

    def existing(self):
        return {
            'site': {'name': 'My Site', 'quiet_hours': [21, 5]},
            'vlans': {20: {'name': 'building-automation', 'zone': 'ot',
                           'subnet': '10.0.20.0/24'}},
            'roles': {'controller': {'internet_expected': False}},
            'devices': {'aa:bb:cc:00:00:01': {
                'name': 'AHU 1 (north plant room)', 'role': 'controller',
                'ips': ['10.0.20.21'], 'vlan': 20,
                'notes': 'Vendor-supplied; firmware never updated'}},
            'expected_flows': [{'src': 'controller', 'dst': '10.0.20.0/24'}],
            'metadata_only_vlans': [40],
        }

    def test_a_hand_written_name_survives(self):
        profile, _ = build_profile(dict(SAMPLE), 'x', self.existing())
        self.assertEqual(profile['devices']['aa:bb:cc:00:00:01']['name'],
                         'AHU 1 (north plant room)')

    def test_a_hand_written_note_survives(self):
        profile, _ = build_profile(dict(SAMPLE), 'x', self.existing())
        self.assertIn('firmware', profile['devices']['aa:bb:cc:00:00:01']['notes'])

    def test_a_hand_written_role_is_not_re_guessed(self):
        existing = self.existing()
        existing['devices']['aa:bb:cc:00:00:01']['role'] = 'automation_server'
        profile, _ = build_profile(dict(SAMPLE), 'x', existing)
        self.assertEqual(profile['devices']['aa:bb:cc:00:00:01']['role'],
                         'automation_server')

    def test_the_zone_on_a_vlan_survives(self):
        """The controller cannot know it, and it is what makes rules portable."""
        profile, _ = build_profile(dict(SAMPLE), 'x', self.existing())
        self.assertEqual(profile['vlans'][20]['zone'], 'ot')

    def test_everything_the_controller_knows_nothing_about_survives(self):
        profile, _ = build_profile(dict(SAMPLE), 'x', self.existing())
        self.assertEqual(profile['metadata_only_vlans'], [40])
        self.assertEqual(len(profile['expected_flows']), 1)

    def test_the_site_name_and_quiet_hours_survive(self):
        profile, _ = build_profile(dict(SAMPLE), 'Other', self.existing())
        self.assertEqual(profile['site']['name'], 'My Site')
        self.assertEqual(profile['site']['quiet_hours'], [21, 5])

    def test_new_devices_are_added(self):
        profile, report = build_profile(dict(SAMPLE), 'x', self.existing())
        self.assertIn('00:11:22:33:44:55', profile['devices'])
        self.assertEqual(len(report['devices_added']), 2)
        self.assertEqual(report['devices_kept'], 1)

    def test_a_device_that_was_not_seen_is_kept_not_deleted(self):
        """
        A device that is merely switched off should not vanish, and one that has
        genuinely gone is a decision for a person.
        """
        existing = self.existing()
        existing['devices']['de:ad:be:ef:00:01'] = {'name': 'Old Panel',
                                                    'role': 'controller'}
        profile, report = build_profile(dict(SAMPLE), 'x', existing)
        self.assertIn('de:ad:be:ef:00:01', profile['devices'])
        self.assertEqual(len(report['devices_not_seen']), 1)
        self.assertIn('Old Panel', report['devices_not_seen'][0])

    def test_an_address_the_controller_now_reports_is_filled_in(self):
        """Merging keeps judgements, not stale facts."""
        existing = self.existing()
        del existing['devices']['aa:bb:cc:00:00:01']['ips']
        profile, _ = build_profile(dict(SAMPLE), 'x', existing)
        self.assertEqual(profile['devices']['aa:bb:cc:00:00:01']['ips'],
                         ['10.0.20.21'])


class TestWriting(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-write-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.path = os.path.join(self.scratch, 'site.yaml')

    def test_it_writes_a_loadable_profile(self):
        profile, _ = build_profile(dict(SAMPLE), 'Test Site')
        write_profile(profile, self.path)
        with open(self.path) as handle:
            SiteProfile(yaml.safe_load(handle))

    def test_it_is_written_owner_only(self):
        """It is a map of the network."""
        profile, _ = build_profile(dict(SAMPLE), 'Test Site')
        write_profile(profile, self.path)
        self.assertEqual(os.stat(self.path).st_mode & 0o077, 0)

    def test_it_explains_what_the_controller_cannot_know(self):
        profile, _ = build_profile(dict(SAMPLE), 'Test Site')
        write_profile(profile, self.path)
        with open(self.path) as handle:
            header = handle.read()
        for expected in ('zone', 'store_payload', 'expected_flows',
                         'out of version control'):
            self.assertIn(expected, header)

    def test_the_previous_version_is_kept(self):
        profile, _ = build_profile(dict(SAMPLE), 'Test Site')
        write_profile(profile, self.path)
        write_profile(profile, self.path)
        self.assertTrue(os.path.exists(self.path + '.bak'))

    def test_no_temporary_file_is_left(self):
        profile, _ = build_profile(dict(SAMPLE), 'Test Site')
        write_profile(profile, self.path)
        self.assertFalse(os.path.exists(self.path + '.tmp'))

    def test_merging_into_a_file_on_disk(self):
        with open(self.path, 'w') as handle:
            yaml.safe_dump({'devices': {'aa:bb:cc:00:00:01': {
                'name': 'Hand written', 'role': 'controller'}}}, handle)
        profile, report = merge_profile(dict(SAMPLE), self.path)
        self.assertEqual(profile['devices']['aa:bb:cc:00:00:01']['name'],
                         'Hand written')
        self.assertEqual(report['devices_kept'], 1)

    def test_merging_into_a_file_that_is_not_a_mapping_is_refused(self):
        with open(self.path, 'w') as handle:
            handle.write('- a\n- b\n')
        with self.assertRaises(UnifiApiError):
            merge_profile(dict(SAMPLE), self.path)


class TestRoleGuessing(unittest.TestCase):

    def test_the_hints_that_exist(self):
        for name, expected in (('Lobby Camera', 'camera'),
                               ('NVR-01', 'recorder'),
                               ('AHU-3', 'controller'),
                               ('Door Reader North', 'door_controller'),
                               ('Parking Kiosk 2', 'kiosk'),
                               ('OCC-SIEMENS-BMS', 'automation_server')):
            with self.subTest(name=name):
                self.assertEqual(_guess_role(name), expected)

    def test_anything_else_is_unknown(self):
        for name in ('DESKTOP-4F2X', 'iPhone', '', 'device-17'):
            with self.subTest(name=name):
                self.assertEqual(_guess_role(name), 'unknown')

    def test_infrastructure_is_recognised_by_type(self):
        self.assertEqual(_guess_role('anything', 'usw', True), 'network_device')
        self.assertEqual(_guess_role('anything', 'weird', True), 'network_device')


if __name__ == '__main__':
    unittest.main(verbosity=2)
