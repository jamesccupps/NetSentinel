"""
UniFi: device names from the owner's console, read only.
=========================================================
NetSentinel knew an address and a MAC maker; the console knows what the owner
named each device. These fake the console (no network): the sites and clients
endpoints of the Network Integration API, paged as the real one is.
Names, addresses and the key are made up.
"""

import json
import logging
import os
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401

from src.unifi import API, CertificateChanged, UnifiInventory  # noqa: E402

KEY = 'test-key-not-real'
PIN = 'ab' * 32
SITE = '88f7af54-98f8-306a-a1c7-c9349722b1f6'


class Settings:
    def __init__(self, **values):
        self.values = {('unifi', 'enabled'): True, ('unifi', 'host'): '192.168.1.1',
                       ('unifi', 'site'): 'default', ('unifi', 'api_key'): KEY}
        self.values.update({('unifi', k): v for k, v in values.items()})
        self.saved = {}

    def get(self, *keys, default=None):
        return self.values.get(keys, default)

    def set(self, *keys_and_value):
        self.saved[keys_and_value[:-1]] = keys_and_value[-1]


CLIENTS = [
    {'type': 'WIRELESS', 'id': f'c{n}', 'name': name, 'connectedAt': '2026-11-01T10:00:00Z',
     'ipAddress': f'192.168.1.{n}', 'access': {'type': 'DEFAULT'},
     **({'macAddress': f'02:00:00:00:00:{n:02x}'} if n % 2 else {})}
    for n, name in [(10, 'Office 3D Printer'), (11, 'Kitchen Plug'), (12, 'Hall Speaker')]]


class FakeConsole:
    """Answers the paths the inventory asks for; records them, and the key."""

    def __init__(self, fingerprint=PIN, status=200, page=2):
        self.fingerprint, self.status, self.page = fingerprint, status, page
        self.paths, self.keys = [], []

    def __call__(self, host, path, key, pin=''):
        if pin and pin != self.fingerprint:
            raise CertificateChanged()      # as https_get does: before the key is sent
        self.paths.append(path)
        self.keys.append(key)
        if self.status != 200:
            return self.status, b'{}', self.fingerprint
        if path.startswith(f'{API}/sites?'):
            body = {'data': [{'id': SITE, 'internalReference': 'default', 'name': 'Default'}]}
        elif '/clients/' in path:
            client_id = path.rsplit('/', 1)[1]
            n = int(client_id[1:])
            body = {'id': client_id, 'macAddress': f'02:00:00:00:00:{n:02x}'}
        else:
            offset = int(path.split('offset=')[1].split('&')[0])
            body = {'offset': offset, 'limit': self.page, 'totalCount': len(CLIENTS),
                    'data': CLIENTS[offset:offset + self.page]}
        return 200, json.dumps(body).encode(), self.fingerprint


def inventory(console=None, **settings):
    config = Settings(**settings)
    inv = UnifiInventory(config, fetch=console or FakeConsole())
    inv.config_used = config
    return inv


class TestReading(unittest.TestCase):

    def test_clients_are_read_page_by_page_and_named_by_ip_and_mac(self):
        console = FakeConsole(page=2)
        inv = inventory(console)
        self.assertTrue(inv.refresh())
        self.assertEqual(inv.count, 3)
        self.assertEqual(inv.name_for(ip='192.168.1.10'), 'Office 3D Printer')
        self.assertEqual(inv.name_for(mac='02:00:00:00:00:0B'), 'Kitchen Plug')
        self.assertEqual(inv.client_for(ip='192.168.1.12')['connection'], 'wireless')
        self.assertIsNone(inv.name_for(ip='192.168.1.99'))
        self.assertEqual(sum('clients?offset=' in p for p in console.paths), 2)

    def test_a_mac_missing_from_the_list_comes_from_the_detail_once(self):
        console = FakeConsole()
        inv = inventory(console)
        inv.refresh()
        inv.refresh()
        self.assertEqual(inv.name_for(mac='02:00:00:00:00:0a'), 'Office 3D Printer')
        details = [p for p in console.paths if '/clients/' in p]
        self.assertEqual(sorted(details), sorted({p for p in details}), 'a detail was asked twice')

    def test_it_only_ever_reads(self):
        """GET only, to the sites and clients endpoints: never a write."""
        console = FakeConsole()
        inventory(console).refresh()
        self.assertTrue(all(p.startswith(f'{API}/sites') for p in console.paths))
        self.assertFalse(any('action' in p for p in console.paths))
        with mock.patch('http.client.HTTPSConnection') as conn:
            conn.return_value.getresponse.return_value = SimpleNamespace(
                status=200, read=lambda n: b'{}')
            conn.return_value.sock.getpeercert.return_value = b'cert'
            from src.unifi import https_get
            https_get('192.168.1.1', f'{API}/sites', KEY)
        self.assertEqual(conn.return_value.request.call_args.args[0], 'GET')
        self.assertEqual(conn.return_value.request.call_args.kwargs['headers']['X-API-KEY'], KEY)

    def test_off_or_unconfigured_it_asks_nothing(self):
        for settings in ({'enabled': False}, {'api_key': ''}, {'host': ''}):
            console = FakeConsole()
            self.assertFalse(inventory(console, **settings).refresh())
            self.assertEqual(console.paths, [])


class TestTrust(unittest.TestCase):

    def test_the_certificate_is_pinned_on_first_use_and_a_new_one_refused(self):
        inv = inventory(FakeConsole(fingerprint=PIN))
        self.assertTrue(inv.refresh())
        self.assertEqual(inv.config_used.saved[('unifi', 'cert_sha256')], PIN)
        swapped = inventory(FakeConsole(fingerprint='cd' * 32), cert_sha256=PIN)
        self.assertFalse(swapped.refresh())
        self.assertIn('certificate changed', swapped.error)
        self.assertEqual(swapped.status()['state'], 'failed')

    def test_a_console_on_the_internet_is_refused(self):
        console = FakeConsole()
        inv = inventory(console, host='8.8.8.8')
        self.assertFalse(inv.refresh())
        self.assertIn('private address', inv.error)
        self.assertEqual(console.paths, [])

    def test_a_refused_key_says_so_and_the_key_is_never_logged(self):
        inv = inventory(FakeConsole(status=401))
        with self.assertLogs('NetSentinel.UniFi', level=logging.DEBUG) as logs:
            self.assertFalse(inv.refresh())
        self.assertIn('refused the API key', inv.error)
        self.assertNotIn(KEY, '\n'.join(logs.output) + inv.error + json.dumps(inv.status()))

    def test_a_network_error_is_named_by_type_only(self):
        def broken(host, path, key, pin=''):
            raise OSError(f'failed GET {path} with {key}')
        inv = inventory(broken)
        self.assertFalse(inv.refresh())
        self.assertEqual(inv.error, 'The console could not be read (OSError).')


class TestWhereNamesGo(unittest.TestCase):

    def ready(self):
        inv = inventory()
        inv.refresh()
        return inv

    def test_alerts_carry_the_names_and_review_bundles_drop_them(self):
        from src.app import NetSentinelApp
        from src.ids_engine import Alert
        from src import review
        app = NetSentinelApp.__new__(NetSentinelApp)
        app.unifi = self.ready()
        alert = Alert('PORT-SCAN', 'HIGH', 't', 'd', src_ip='192.168.1.10', dst_ip='203.0.113.5')
        app._name_devices(alert)
        self.assertEqual(alert.evidence, {'src_name': 'Office 3D Printer'})
        self.assertTrue({'src_name', 'dst_name'} <= review._DROP_KEYS)

    def test_the_threat_data_page_has_a_row(self):
        inv = self.ready()
        row = inv.status()
        self.assertEqual((row['state'], row['entries']), ('ok', 3))
        self.assertIn('Read only', row['note'])
        self.assertEqual(inventory(enabled=False).status()['state'], 'off')
        self.assertEqual(inventory(api_key='').status()['state'], 'needs key')


from test_headless import _ApiTestCase  # noqa: E402


class TestDevicesPage(_ApiTestCase):

    def test_devices_get_the_consoles_names(self):
        class Devices:
            def get_summary(self):
                return {'total_devices': 1, 'by_type': {}, 'devices': [
                    {'ip': '192.168.1.11', 'mac': '02:00:00:00:00:0b', 'hostname': 'kasa'}]}
        self.app.device_learner = Devices()
        inv = inventory()
        inv.refresh()
        self.app.unifi = inv
        [device] = self.get_json('/api/devices')['devices']
        self.assertEqual((device['name'], device['connection']), ('Kitchen Plug', 'wireless'))


if __name__ == '__main__':
    unittest.main()
