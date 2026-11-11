"""
The gateway's traffic log, received over syslog.
=================================================
A UniFi gateway without a drive will not export its traffic log, but it will
send it to a syslog server as it happens. These cover the receiver: what it
accepts, how it reads the formats, what it keeps per device, and the files it
stores and prunes. One test sends a real datagram over loopback; nothing else
touches a socket. Addresses and names are made up, but for one Google address
where an internet one is needed (Python counts documentation ranges as private).
"""

import json
import os
import shutil
import socket
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401

from src.syslog_receiver import MAX_PER_SECOND, SyslogReceiver, parse  # noqa: E402

GATEWAY = '192.168.1.1'
T0 = 1_790_000_000.0

CEF = ('<14>1 2026-11-02T15:00:00Z UDM-Pro CEF - - - CEF:0|Ubiquiti|UniFi Network|10.6.109|'
       '201|Allowed Connection|1|src=192.168.1.40 spt=51515 dst=203.0.113.9 dpt=443 proto=TCP '
       'UNIFIclientAlias=Living Room Speaker UNIFIclientMac=02:00:00:00:00:40 '
       'UNIFIdomain=api.example-speaker.com act=allow')
IPTABLES = ('<4>Nov  2 15:00:01 UDM-Pro kernel: [IOT_WAN-D-2147483647] IN=br12 OUT=eth8 '
            'MAC=02:00:00:00:00:41 SRC=192.168.1.41 DST=198.51.100.7 LEN=60 PROTO=TCP '
            'SPT=40000 DPT=443 WINDOW=64240 SYN')


class Settings:
    def __init__(self, **values):
        self.values = {('syslog', 'enabled'): True, ('syslog', 'bind'): '127.0.0.1',
                       ('syslog', 'port'): 0, ('syslog', 'allowed_senders'): GATEWAY}
        self.values.update({('syslog', k): v for k, v in values.items()})

    def get(self, *keys, default=None):
        return self.values.get(keys, default)


class _Case(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='ns_syslog_')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def receiver(self, names=None, **settings):
        r = SyslogReceiver(Settings(**settings), data_dir=self.tmp, clock=lambda: T0, names=names)
        self.addCleanup(r.stop)
        return r


class TestFormats(unittest.TestCase):

    def test_cef_from_unifi(self):
        r = parse(CEF)
        self.assertEqual((r['src'], r['dst'], r['dport'], r['proto']),
                         ('192.168.1.40', '203.0.113.9', '443', 'TCP'))
        self.assertEqual((r['client'], r['domain'], r['action']),
                         ('Living Room Speaker', 'api.example-speaker.com', 'allow'))
        self.assertEqual(r['event'], 'Allowed Connection')

    def test_an_iptables_line_and_its_rule(self):
        r = parse(IPTABLES)
        self.assertEqual((r['src'], r['dst'], r['dport'], r['rule']),
                         ('192.168.1.41', '198.51.100.7', '443', 'IOT_WAN-D-2147483647'))
        self.assertEqual(r['action'], 'block')

    def test_a_real_unifi_message_with_its_short_header(self):
        """UniFi 10.6 sends no priority and a 3164-style header; the header pattern
        took "CEF" for the program name and cut the CEF off."""
        r = parse('Nov 02 17:22:17 HOME-UDM CEF:0|Ubiquiti|UniFi Network|10.6.109|544|'
                  'Network Accessed|4|UNIFIcategory=Audit UNIFIhost=HOME UDM '
                  'UNIFIaccessMethod=web UNIFIadmin=Sam Admin src=192.168.1.20 '
                  'UNIFIutcTime=2026-11-02T22:22:17.796Z msg=Sam Admin accessed UniFi Network '
                  'using the web. Source IP: 192.168.1.20')
        self.assertEqual((r['event'], r['category'], r['src']),
                         ('Network Accessed', 'Audit', '192.168.1.20'))
        self.assertTrue(r['message'].startswith('Sam Admin accessed'))

    def test_a_real_firewall_block_names_the_client_not_src(self):
        """UniFi 10.6's "Blocked by Firewall" has no src=; it was never counted."""
        r = parse('Nov 02 17:32:34 HOME-UDM CEF:0|Ubiquiti|UniFi Network|10.6.109|203|'
                  'Blocked by Firewall|4|UNIFIcategory=Security UNIFIhost=HOME UDM proto=TCP '
                  'spt=50261 dpt=80 act=blocked app=HTTP UNIFIrisk=low UNIFIpolicyName=IOT TV '
                  'to WAN UNIFIpolicyType=Firewall UNIFIdirection=outgoing '
                  'deviceInboundInterface=Home IOT deviceOutboundInterface=Internet 1 '
                  'dst=142.250.68.195 UNIFIsrcClientAlias=Living Room TV '
                  'UNIFIsrcClientHostname=Samsung UNIFIsrcClientIp=192.168.1.45 '
                  'UNIFIsrcClientMac=02:00:00:00:00:45 UNIFIsrcZone=Home IOT UNIFIdstZone=External '
                  'UNIFIdstDomain=tv.example.com UNIFIfirewallPolicy=IOT TV to WAN '
                  'UNIFIflowCount=1 msg=Living Room TV was blocked from accessing 142.250.68.195')
        self.assertEqual((r['src'], r['dst'], r['dport'], r['domain']),
                         ('192.168.1.45', '142.250.68.195', '80', 'tv.example.com'))
        self.assertEqual((r['client'], r['client_mac'], r['rule'], r['action']),
                         ('Living Room TV', '02:00:00:00:00:45', 'IOT TV to WAN', 'block'))

    def test_the_gateways_own_lines_name_the_host_twice(self):
        r = parse('<29>Nov  2 17:34:39 HOME-UDM HOME-UDM ulogd[2678068]: NFLOG netlink '
                  'buffer size has been set to 4194304')
        self.assertEqual(r['program'], 'ulogd')
        self.assertTrue(r['raw'].startswith('NFLOG netlink'))

    def test_a_kernel_firewall_line_after_its_uptime(self):
        r = parse('<4>Nov  2 15:00:01 HOME-UDM HOME-UDM kernel: [123456.789012] '
                  '[IOT_WAN-D-2147483647] IN=br12 OUT=eth8 SRC=192.168.1.41 '
                  'DST=142.250.68.195 PROTO=TCP SPT=40000 DPT=443')
        self.assertEqual((r['program'], r['rule'], r['action']),
                         ('kernel', 'IOT_WAN-D-2147483647', 'block'))

    def test_something_unknown_is_kept_trimmed(self):
        r = parse('<13>Nov  2 15:00:02 UDM-Pro hostapd: ' + 'x' * 2000)
        self.assertNotIn('src', r)
        self.assertEqual(len(r['raw']), 400)


class TestWhatIsAccepted(_Case):

    def test_a_sender_not_allowed_is_dropped_unread(self):
        r = self.receiver()
        self.assertIsNone(r.handle(CEF.encode(), '192.168.1.66'))
        self.assertEqual((r.dropped_sender, r.received), (1, 0))
        self.assertEqual(r.days(), [])

    def test_a_flood_is_capped_per_second(self):
        r = self.receiver()
        for _ in range(MAX_PER_SECOND + 10):
            r.handle(b'<14>hello', GATEWAY, now=T0)
        self.assertEqual(r.dropped_rate, 10)

    def test_without_an_address_or_a_sender_it_does_not_listen(self):
        for settings in ({'bind': ''}, {'allowed_senders': ''}, {'enabled': False}):
            r = self.receiver(**settings)
            self.assertFalse(r.start())
            self.assertIsNone(r._sock)

    def test_a_real_datagram_over_loopback(self):
        r = self.receiver(allowed_senders='127.0.0.1')
        self.assertTrue(r.start())
        port = r._sock.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(CEF.encode(), ('127.0.0.1', port))
        deadline = time.time() + 5
        while not r.received and time.time() < deadline:
            time.sleep(0.02)
        self.assertEqual(r.received, 1)


class TestPerDevice(_Case):

    def test_destinations_are_counted_per_device_with_the_consoles_name(self):
        r = self.receiver(names=lambda ip: 'Speaker (UniFi)' if ip == '192.168.1.40' else None)
        for _ in range(3):
            r.handle(CEF.encode(), GATEWAY)
        r.handle(IPTABLES.encode(), GATEWAY)
        devices = {d['ip']: d for d in r.devices()}
        speaker = devices['192.168.1.40']
        self.assertEqual(speaker['name'], 'Speaker (UniFi)')
        self.assertEqual(speaker['top'][0]['to'], 'api.example-speaker.com:443')
        self.assertEqual(speaker['top'][0]['allowed'], 3)
        self.assertEqual(devices['192.168.1.41']['blocked'], 1)

    def test_an_inbound_connection_is_not_a_device_reaching_out(self):
        r = self.receiver()
        r.handle(b'<4>SRC=142.250.68.195 DST=192.168.1.41 PROTO=TCP SPT=443 DPT=40000', GATEWAY)
        self.assertEqual(r.devices(), [])


class TestStorage(_Case):

    def test_each_day_is_a_file_of_json_lines(self):
        r = self.receiver()
        r.handle(CEF.encode(), GATEWAY)
        [day] = r.days()
        with open(r.day_path(day), encoding='utf-8') as f:
            record = json.loads(f.readline())
        self.assertEqual((record['src'], record['sender']), ('192.168.1.40', GATEWAY))

    def test_old_days_go_and_then_the_oldest_until_it_fits(self):
        r = self.receiver(keep_days=10, max_mb=1)
        for day, size in (('2026-01-01', 10), ('2026-09-01', 700_000), ('2026-09-02', 700_000),
                          ('2026-09-03', 10)):
            with open(r.day_path(day), 'w', encoding='utf-8') as f:
                f.write('x' * size)
        r.prune(now=time.mktime((2026, 9, 3, 12, 0, 0, 0, 0, -1)))
        self.assertEqual(r.days(), ['2026-09-02', '2026-09-03'])

    def test_the_status_counts_one_day_as_a_day(self):
        r = self.receiver()
        r.handle(CEF.encode(), GATEWAY)
        self.assertEqual(r.status()['note'], '1 day kept on disk.')

    def test_a_day_must_look_like_a_date(self):
        with self.assertRaises(ValueError):
            self.receiver().day_path('../../config')


from test_headless import _ApiTestCase  # noqa: E402


class TestDashboard(_ApiTestCase):

    def test_devices_and_export(self):
        tmp = tempfile.mkdtemp(prefix='ns_syslog_api_')
        self.addCleanup(shutil.rmtree, tmp, True)
        r = SyslogReceiver(Settings(), data_dir=tmp)
        r.handle(CEF.encode(), GATEWAY)
        self.app.syslog = r
        data = self.get_json('/api/unifi-logs/devices')
        self.assertEqual(data['devices'][0]['ip'], '192.168.1.40')
        day = data['days'][0]
        status, headers, body = self.get(f'/api/unifi-logs/export?day={day}')
        self.assertIn('ndjson', headers['Content-Type'])
        self.assertEqual(json.loads(body.splitlines()[0])['dst'], '203.0.113.9')
        code, _ = self.request('/api/unifi-logs/export?day=2020-01-01')
        self.assertEqual(code, 404)


if __name__ == '__main__':
    unittest.main()
