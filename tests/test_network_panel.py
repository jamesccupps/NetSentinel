"""
"This network" on both dashboards.
==================================
NetSentinel finds this PC's address, the subnet, gateway, DHCP and DNS servers
when it starts, and uses them for detection; both dashboards were handed them
and neither showed any. Addresses are made-up LAN examples.
"""

import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401

from test_headless import _ApiTestCase  # noqa: E402

PC = '192.168.10.32'
ENV = {
    'detected': True,
    # As NetworkEnvironment lists them on a Windows PC with a virtual adapter
    # (WSL or Hyper-V) and two adapters connected nowhere.
    'local_ips': ['fe80::1c2d:3e4f:5a6b:7c8d', '169.254.10.20', '172.20.48.1', PC,
                  '169.254.2.141', '2001:db8::32'],
    'local_subnet': '192.168.10.0/24',
    'gateways': ['192.168.10.1'],
    'dhcp_servers': ['192.168.10.1'],
    'dns_servers': ['192.168.10.1', '9.9.9.9'],
}
ADAPTER = {'name': 'Ethernet', 'description': 'Example Gigabit Controller', 'ip': PC}


class TestTheRows(unittest.TestCase):

    def rows(self, env=ENV, adapter=ADAPTER):
        from src.presentation import network_rows
        return dict(network_rows(env, adapter))

    def test_what_it_shows(self):
        from src.presentation import network_rows
        self.assertEqual(network_rows(ENV, ADAPTER), [
            ('This PC', PC),
            ('Subnet', '192.168.10.0/24'),
            ('Gateway', '192.168.10.1'),
            ('DHCP server', '192.168.10.1'),
            ('DNS servers', '192.168.10.1, 9.9.9.9'),
            ('Adapter', 'Ethernet (Example Gigabit Controller)'),
            ('Other addresses', '172.20.48.1, 2001:db8::32'),
        ])

    def test_link_local_addresses_are_left_out(self):
        """Windows gives one to every adapter that is connected nowhere."""
        shown = ' '.join(self.rows().values())
        self.assertNotIn('169.254.', shown)
        self.assertNotIn('fe80:', shown)

    def test_this_pc_is_the_captured_adapters_address_not_a_vpns(self):
        """The summary kept five addresses of a set; when this PC's LAN address
        was not among them, its Tailscale address (100.x) was "This PC"."""
        env = dict(ENV, local_ips=['100.100.20.7', 'fe80::1', '169.254.1.1'])
        rows = self.rows(env)
        self.assertEqual(rows['This PC'], PC)
        self.assertEqual(rows['Other addresses'], '100.100.20.7')

    def test_the_order_does_not_change_with_the_sets(self):
        from src.presentation import network_rows
        shuffled = dict(ENV, local_ips=list(reversed(ENV['local_ips'])))
        self.assertEqual(network_rows(shuffled, ADAPTER), network_rows(ENV, ADAPTER))

    def test_the_app_passes_every_address(self):
        from src.app import NetSentinelApp
        app = NetSentinelApp.__new__(NetSentinelApp)
        many = ['10.9.0.%d' % i for i in range(1, 9)] + [PC]
        app.net_env = SimpleNamespace(local_ips=many, get_summary=lambda: dict(ENV, local_ips=many[:5]))
        app.capture_engine = SimpleNamespace(interface_info=lambda: {})
        self.assertEqual(dict(app.network_rows())['This PC'], PC)

    def test_without_the_adapter_this_pc_is_the_one_on_the_subnet(self):
        rows = self.rows(adapter={})
        self.assertEqual(rows['This PC'], PC)
        self.assertNotIn('Adapter', rows)

    def test_an_adapter_with_no_description_is_its_name(self):
        self.assertEqual(self.rows(adapter={'name': 'eth0', 'description': 'eth0'})['Adapter'],
                         'eth0')

    def test_before_detection_it_says_so(self):
        from src.presentation import network_rows
        self.assertEqual(network_rows({'detected': False}), [('This PC', 'Not detected yet')])
        self.assertEqual(network_rows(None), [('This PC', 'Not detected yet')])


class TestTheAdapter(unittest.TestCase):

    def test_the_capture_names_its_adapter_without_logging_each_time(self):
        from src import capture
        engine = capture.CaptureEngine.__new__(capture.CaptureEngine)
        engine.interface = 'auto'
        saved = (capture.SCAPY_AVAILABLE, getattr(capture, 'conf', None))
        capture.SCAPY_AVAILABLE = True
        capture.conf = SimpleNamespace(iface=SimpleNamespace(
            name='Ethernet', description='Example Gigabit Controller', ip=PC))
        try:
            with self.assertNoLogs('NetSentinel', level='INFO'):
                self.assertEqual(engine.interface_info(), ADAPTER)
            engine.interface = 'eth1'                  # set in config.json
            self.assertEqual(engine.interface_info(), {'name': 'eth1'})
        finally:
            capture.SCAPY_AVAILABLE, capture.conf = saved


class TestTheBrowserDashboard(_ApiTestCase):

    def test_the_overview_carries_the_rows(self):
        self.assertEqual(self.get_json('/api/overview')['network'],
                         [['This PC', PC], ['Gateway', '192.168.10.1']])

    def test_an_app_without_them_still_has_an_overview(self):
        self.server.app = SimpleNamespace(**{k: getattr(self.server.app, k)
                                             for k in dir(self.server.app)
                                             if not k.startswith('__') and k != 'network_rows'})
        self.assertEqual(self.get_json('/api/overview')['network'], [])

    def test_the_page_has_the_panel_and_writes_it_as_text(self):
        root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src',
                            'webui')
        with open(os.path.join(root, 'index.html'), encoding='utf-8') as f:
            self.assertIn('<h2>This network</h2><dl id="network" class="facts">', f.read())
        with open(os.path.join(root, 'app.js'), encoding='utf-8') as f:
            script = f.read()
        self.assertIn("$('network').replaceChildren(", script)
        self.assertIn("[h('dt', null, label), h('dd', null, value)]", script)


class TestTheDesktopDashboard(unittest.TestCase):

    def setUp(self):
        import tkinter as tk
        try:
            self.root = tk.Tk()
        except tk.TclError as e:           # no display (GitHub's Linux runners)
            self.skipTest(f'no display for Tk: {e}')
        self.root.withdraw()
        self.addCleanup(self.root.destroy)

    def test_the_card_shows_the_rows_and_redraws_only_when_they_change(self):
        import tkinter as tk
        from src import gui
        rows = [[('This PC', PC), ('Gateway', '192.168.10.1')]]
        g = gui.NetSentinelGUI.__new__(gui.NetSentinelGUI)
        g.root = self.root
        g.app = SimpleNamespace(network_rows=lambda: rows[0])
        g._network_rows = tk.Frame(self.root)
        g._network_shown = None
        g._refresh_network()
        texts = [w.cget('text') for w in g._network_rows.winfo_children()]
        self.assertEqual(texts, ['This PC', PC, 'Gateway', '192.168.10.1'])
        first = g._network_rows.winfo_children()[0]
        g._refresh_network()
        self.assertIs(g._network_rows.winfo_children()[0], first)
        rows[0] = [('This PC', '192.168.10.33')]
        g._refresh_network()
        self.assertEqual([w.cget('text') for w in g._network_rows.winfo_children()],
                         ['This PC', '192.168.10.33'])


if __name__ == '__main__':
    unittest.main()
