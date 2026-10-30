"""Active subnet audit: which networks it may touch. Nothing here sends a packet."""

import ipaddress
import os
import socket
import sys
import types
import unittest
import unittest.mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src import audit  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
_REAL_INTERFACE_ADDRESSES = audit._interface_addresses
NET = '10.77.0.0/24'
IFACES = [('eth-test', '10.77.0.5/24')]


# ══════════════════════════════════════════════════════════════════════
# Scope: the core of the feature
# ══════════════════════════════════════════════════════════════════════
class TestScope(unittest.TestCase):

    def refuse(self, network, interfaces, reason):
        with self.assertRaises(audit.ScopeError) as ctx:
            audit.validate_network(network, interfaces)
        self.assertEqual(ctx.exception.reason, reason, str(ctx.exception))

    def test_public_range_is_refused_even_on_a_local_interface(self):
        self.refuse('8.8.8.0/24', [('wan', '8.8.8.5/24')], 'public')
        self.refuse('203.0.113.0/24', [('wan', '203.0.113.9/24')], 'public')

    def test_reserved_ranges_are_refused(self):
        for net, iface in (('100.64.0.0/24', '100.64.0.9/10'),   # CGNAT (Tailscale lives here)
                           ('224.0.0.0/24', '224.0.0.9/24'),
                           ('0.0.0.0/8', '0.0.0.9/8'),
                           ('2001:db8::/120', '2001:db8::5/64'),
                           ('0.0.0.0/0', '10.77.0.5/24')):
            with self.subTest(net=net):
                self.refuse(net, [('x', iface)], 'public')

    def test_larger_than_a_slash_16_is_refused(self):
        wide = [('corp', '10.0.0.5/8')]
        self.refuse('10.0.0.0/15', wide, 'too-large')
        self.refuse('10.0.0.0/8', wide, 'too-large')
        self.refuse('fd12::/64', [('ula', 'fd12::5/64')], 'too-large')
        self.assertEqual(str(audit.validate_network('10.0.0.0/16', wide)), '10.0.0.0/16')
        self.assertEqual(str(audit.validate_network('fd12::/112', [('ula', 'fd12::5/64')])),
                         'fd12::/112')

    def test_loopback_is_refused(self):
        lo = [('lo', '127.0.0.1/8'), ('lo6', '::1/128')]
        for net in ('127.0.0.0/8', '127.0.0.1', '127.0.0.0/24', '::1'):
            with self.subTest(net=net):
                self.refuse(net, lo, 'loopback')

    def test_network_not_on_any_local_interface_is_refused(self):
        self.refuse('10.99.0.0/24', IFACES, 'not-local')
        self.refuse('192.168.1.0/24', IFACES, 'not-local')
        self.refuse('10.77.0.0/24', [], 'not-local')

    def test_ipv6_link_local_is_refused(self):
        self.refuse('fe80::/120', [('eth', 'fe80::5/64')], 'link-local-v6')

    def test_rubbish_is_refused(self):
        for text in ('', None, 'my network', '10.0.0.0/33', '300.1.1.0/24'):
            with self.subTest(text=text):
                self.refuse(text, IFACES, 'invalid')

    def test_accepted_forms(self):
        self.assertEqual(str(audit.validate_network('10.77.0.9/24', IFACES)), '10.77.0.0/24')
        self.assertEqual(str(audit.validate_network('10.77.0.9', IFACES)), '10.77.0.9/32')
        self.assertEqual(str(audit.validate_network('10.77.0.128/25', IFACES)), '10.77.0.128/25')
        apipa = [('eth', '169.254.3.4/16')]
        self.assertEqual(str(audit.validate_network('169.254.0.0/16', apipa)), '169.254.0.0/16')

    def test_overlapping_or_empty_choices_are_refused(self):
        with self.assertRaises(audit.ScopeError) as ctx:
            audit.validate_networks(['10.77.0.0/24', '10.77.0.0/25'], IFACES)
        self.assertEqual(ctx.exception.reason, 'overlap')
        with self.assertRaises(audit.ScopeError) as ctx:
            audit.validate_networks([], IFACES)
        self.assertEqual(ctx.exception.reason, 'empty')

    def test_network_and_broadcast_addresses_are_skipped(self):
        ifaces = audit._normalise_interfaces(IFACES)
        self.assertEqual([str(a) for a in audit._targets(ipaddress.ip_network('10.77.0.0/30'), ifaces)],
                         ['10.77.0.1', '10.77.0.2'])
        wide = [str(a) for a in audit._targets(ipaddress.ip_network('10.77.0.0/23'), ifaces)]
        for skipped in ('10.77.0.0', '10.77.0.255', '10.77.1.255'):
            self.assertNotIn(skipped, wide)
        self.assertIn('10.77.1.0', wide)   # a host address in a /23
        self.assertEqual(len(wide), 509)
        self.assertEqual([str(a) for a in audit._targets(ipaddress.ip_network('10.77.0.9/32'), ifaces)],
                         ['10.77.0.9'])

    def test_down_interface_does_not_count_as_local(self):
        nic = types.SimpleNamespace
        fake_psutil = types.SimpleNamespace(
            net_if_addrs=lambda: {
                'Ethernet': [nic(family=socket.AF_INET, address='192.168.50.7',
                                 netmask='255.255.255.0')],
                'Wi-Fi': [nic(family=socket.AF_INET, address='169.254.9.9', netmask='255.255.0.0')],
                'Ethernet6': [nic(family=socket.AF_INET6, address='fd12::7%3', netmask=None)],
            },
            net_if_stats=lambda: {'Ethernet': nic(isup=True), 'Wi-Fi': nic(isup=False),
                                  'Ethernet6': nic(isup=True)})
        with unittest.mock.patch.object(audit, 'psutil', fake_psutil):
            ifaces = _REAL_INTERFACE_ADDRESSES()
        names = {name for name, _ in ifaces}
        self.assertEqual(names, {'Ethernet', 'Ethernet6'})
        self.assertIn(('Ethernet6', ipaddress.ip_interface('fd12::7/64')), ifaces)
        with self.assertRaises(audit.ScopeError) as ctx:
            audit.validate_network('169.254.0.0/16', ifaces)
        self.assertEqual(ctx.exception.reason, 'not-local')
        audit.validate_network('192.168.50.0/24', ifaces)


class TestLocalNetworks(unittest.TestCase):

    def test_choices_from_interfaces(self):
        ifaces = [('Ethernet', '192.168.50.7/24'), ('Wi-Fi', '192.168.50.9/24'),
                  ('Corp', '10.20.30.40/8'), ('Loopback Pseudo-Interface 1', '127.0.0.1/8'),
                  ('Tailscale', '100.121.218.20/32'), ('WAN', '81.2.69.1/24'),
                  ('vEthernet (WSL)', '172.28.80.1/20'), ('Ethernet6', 'fd12::7/64'),
                  ('ppp0', '10.99.0.1/32')]
        nets = {n['network']: n for n in audit.local_networks(ifaces)}
        self.assertEqual(set(nets), {'192.168.50.0/24', '10.20.30.0/24', '172.28.80.0/20'})
        self.assertEqual(nets['192.168.50.0/24']['interface'], 'Ethernet, Wi-Fi')
        self.assertEqual(nets['192.168.50.0/24']['addresses'], 254)
        self.assertEqual(nets['192.168.50.0/24']['kind'], 'rfc1918')
        self.assertEqual(nets['10.20.30.0/24']['narrowed_from'], '10.0.0.0/8')
        self.assertTrue(nets['172.28.80.0/20']['virtual'])
        self.assertFalse(nets['192.168.50.0/24']['virtual'])
        self.assertEqual(list(nets)[-1], '172.28.80.0/20')      # virtual adapters last
        for net in nets:
            audit.validate_network(net, ifaces)

    def test_this_machine(self):
        """Reads this computer's interfaces (no packets sent): every choice validates."""
        for n in audit.local_networks():
            self.assertEqual(str(audit.validate_network(n['network'])), n['network'])


class TestParsePorts(unittest.TestCase):

    def test_parse(self):
        self.assertEqual(audit.parse_ports('80, 22,8000-8002 22'), [22, 80, 8000, 8001, 8002])
        self.assertEqual(audit.parse_ports([443, '22']), [22, 443])
        self.assertEqual(len(audit.parse_ports('1-1024')), 1024)
        for bad in ('', '0', '65536', '10-5', 'ssh', '1-1025'):
            with self.subTest(bad=bad), self.assertRaises(audit.ScopeError):
                audit.parse_ports(bad)


if __name__ == '__main__':
    unittest.main()
