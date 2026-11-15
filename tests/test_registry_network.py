"""
DNS and DHCP servers in any language of Windows.
================================================
The outside review of 2026-11-14 (N9): the DNS servers, DHCP server and part
of the gateways came from ipconfig's text, matched in English ("DNS Servers")
and German ("DNS-Server") only, so on Windows in any other language none were
found. Windows keeps them in the registry, the same in every language. The
registry here is faked; addresses are made up.
"""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401

PC = '192.168.10.32'


class FakeWinreg:
    """The part of winreg registry_settings uses, over {adapter: {value: data}}."""

    HKEY_LOCAL_MACHINE = 'HKLM'

    def __init__(self, adapters):
        self.adapters = adapters

    class _Key:
        def __init__(self, values=None, names=None):
            self.values, self.names = values, names

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def OpenKey(self, parent, name):
        if parent == self.HKEY_LOCAL_MACHINE:
            return self._Key(names=list(self.adapters))
        return self._Key(values=self.adapters[name])

    def EnumKey(self, key, index):
        if index >= len(key.names):
            raise OSError('no more')
        return key.names[index]

    def QueryValueEx(self, key, name):
        if name not in key.values:
            raise FileNotFoundError(name)
        return key.values[name], 1


ADAPTERS = {
    '{wired}': {'EnableDHCP': 1, 'DhcpIPAddress': PC, 'DhcpServer': '192.168.10.1',
                'DhcpNameServer': '192.168.10.1 9.9.9.9',
                'DhcpDefaultGateway': ['192.168.10.1']},
    # Connected nowhere now: it keeps the last network's settings.
    '{wifi}': {'EnableDHCP': 1, 'DhcpIPAddress': '10.88.4.17', 'DhcpServer': '10.88.4.1',
               'DhcpNameServer': '10.88.4.1', 'DhcpDefaultGateway': ['10.88.4.1']},
    '{static}': {'EnableDHCP': 0, 'IPAddress': ['172.20.0.5'], 'NameServer': '172.20.0.53,172.20.0.54',
                 'DhcpNameServer': '172.20.0.1', 'DefaultGateway': ['172.20.0.1']},
}


class TestTheRegistry(unittest.TestCase):

    def settings(self, local):
        from src.net_detect import registry_settings
        return registry_settings(local, winreg=FakeWinreg(ADAPTERS))

    def test_the_connected_adapters_servers(self):
        self.assertEqual(self.settings(['127.0.0.1', PC]),
                         {'dns': ['192.168.10.1', '9.9.9.9'], 'dhcp': ['192.168.10.1'],
                          'gateways': ['192.168.10.1']})

    def test_a_static_name_server_wins_over_dhcps(self):
        self.assertEqual(self.settings(['172.20.0.5'])['dns'], ['172.20.0.53', '172.20.0.54'])

    def test_off_windows_it_finds_nothing(self):
        from src.net_detect import registry_settings
        with mock.patch.dict(sys.modules, {'winreg': None}):
            self.assertEqual(registry_settings([PC]), {'dns': [], 'dhcp': [], 'gateways': []})


class TestDetection(unittest.TestCase):

    def test_detection_finds_them_without_ipconfigs_words(self):
        """ipconfig in French says "Serveurs DNS"; the registry does not care."""
        from src import net_detect
        french = mock.Mock(stdout='   Serveurs DNS. . . . . . . : 192.168.10.1\n'
                                  '   Serveur DHCP . . . . . . . : 192.168.10.1\n')
        with mock.patch.object(net_detect, 'registry_settings',
                               lambda local_ips=None, winreg=None: {
                                   'dns': ['192.168.10.1'], 'dhcp': ['192.168.10.1'],
                                   'gateways': ['192.168.10.1']}), \
                mock.patch.object(net_detect.subprocess, 'run', return_value=french):
            self.assertEqual(net_detect.detect_configured_dns_servers(), ['192.168.10.1'])
            self.assertEqual(net_detect.detect_dhcp_server(), ['192.168.10.1'])
            self.assertIn('192.168.10.1', net_detect.detect_default_gateway())


if __name__ == '__main__':
    unittest.main()
