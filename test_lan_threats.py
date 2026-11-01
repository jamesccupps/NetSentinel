"""
Attacks on the LAN: ARP, rogue DHCP and routers, name poisoning, lateral
movement, uploads and new devices (src/lan_threats.py, raised by IDSEngine).
"""

import os
import shutil
import struct
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from src.capture import PacketInfo  # noqa: E402
from src.ids_engine import IDSEngine  # noqa: E402


def pkt(ts=None, **kw):
    p = PacketInfo()
    if ts is not None:
        p.timestamp = ts
    for k, v in kw.items():
        setattr(p, k, v)
    return p


def arp(ip, mac, ts=None, target='192.168.1.50', ether=None, op=2):
    return pkt(ts=ts, protocol='ARP', src_ip=ip, dst_ip=target, arp_op=op, arp_hwsrc=mac,
               src_mac=ether or mac)


class _Lan(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='ns_lan_')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.state = os.path.join(self.tmp, 'lan_state.json')
        self.env = SimpleNamespace(gateways=['192.168.1.1'], dhcp_servers=['192.168.1.1'],
                                   local_ips=['192.168.1.50'], local_subnet='192.168.1.0/24',
                                   is_known_cloud_domain=lambda d: False,
                                   is_cloud_hosting_domain=lambda d: False,
                                   is_gateway=lambda ip: ip == '192.168.1.1',
                                   is_configured_resolver=lambda ip: False,
                                   should_skip_ids=lambda *a, **k: False)

    def engine(self, env=None, created=None):
        alerts = []
        ids = IDSEngine(reset_config(), alert_callback=alerts.append,
                        net_env=self.env if env is None else env)
        try:
            from src.lan_threats import LanThreatMonitor
        except ImportError:             # the base code, when checking these fail there
            return ids, alerts
        ids.lan = LanThreatMonitor(reset_config(), net_env=ids.net_env, state_path=self.state)
        if created is not None:
            ids.lan.state['created'] = created
        return ids, alerts

    @staticmethod
    def rules(alerts):
        return [a.rule_id for a in alerts]


class TestArp(_Lan):

    def test_the_sender_mac_comes_from_the_arp_payload(self):
        """A relay keeps the Ethernet source constant; the claim is in the payload."""
        ids, alerts = self.engine(env=False)
        ids.inspect_packet(arp('192.168.1.20', '02:00:00:00:00:01', ether='02:aa:aa:aa:aa:aa'))
        for _ in range(2):              # a spoofer repeats its claim
            ids.inspect_packet(arp('192.168.1.20', '02:00:00:00:00:02',
                                   ether='02:aa:aa:aa:aa:aa'))
        self.assertIn('ARP-SPOOF', self.rules(alerts))

    def test_a_proxy_relaying_the_same_claim_is_not_spoofing(self):
        ids, alerts = self.engine(env=False)
        ids.inspect_packet(arp('192.168.1.21', '00:1b:21:00:00:01', ether='00:1b:21:00:00:aa'))
        ids.inspect_packet(arp('192.168.1.21', '00:1b:21:00:00:01', ether='00:1b:21:00:00:bb'))
        self.assertNotIn('ARP-SPOOF', self.rules(alerts))

    def test_gateway_mac_is_pinned_across_restarts(self):
        ids, _ = self.engine()
        ids.inspect_packet(arp('192.168.1.1', '00:11:22:33:44:55'))
        ids.lan.save(force=True)
        restarted, alerts = self.engine()
        self.assertEqual(restarted.lan.state['gateway_macs']['192.168.1.1']['mac'],
                         '00:11:22:33:44:55')
        restarted.inspect_packet(arp('192.168.1.1', '00:de:ad:be:ef:01'))
        spoof = [a for a in alerts if a.rule_id == 'ARP-SPOOF']
        self.assertTrue(spoof)
        self.assertEqual(spoof[0].severity, 'CRITICAL')
        self.assertTrue(spoof[0].evidence['gateway'])

    def test_failover_macs_move_without_an_alert(self):
        ids, alerts = self.engine()
        ids.inspect_packet(arp('192.168.1.1', '00:00:5e:00:01:01'))
        ids.inspect_packet(arp('192.168.1.1', '00:00:5e:00:01:02'))
        ids.inspect_packet(arp('192.168.1.30', '00:00:0c:07:ac:01'))
        ids.inspect_packet(arp('192.168.1.30', '00:00:0c:07:ac:02'))
        self.assertNotIn('ARP-SPOOF', self.rules(alerts))

    def test_an_address_reassigned_long_after_is_not_spoofing(self):
        """DHCP gives an old address to a new device: the old claim is stale."""
        ids, alerts = self.engine(env=False)
        ids.inspect_packet(arp('192.168.1.40', '00:1b:21:00:00:01', ts=1_000_000.0))
        ids.inspect_packet(arp('192.168.1.40', '00:1b:21:00:00:02', ts=1_000_000.0 + 3600))
        self.assertNotIn('ARP-SPOOF', self.rules(alerts))

    def test_flapping_between_two_macs_is_critical(self):
        ids, alerts = self.engine(env=False)
        for mac in ('00:1b:21:00:00:01', '00:1b:21:00:00:02', '00:1b:21:00:00:01'):
            ids._alert_cooldowns.clear()
            for _ in range(2):          # each side keeps repeating its claim
                ids.inspect_packet(arp('192.168.1.41', mac))
        self.assertEqual([a.severity for a in alerts if a.rule_id == 'ARP-SPOOF'][-1],
                         'CRITICAL')

    def test_one_mac_claiming_many_addresses(self):
        ids, alerts = self.engine(env=False)
        for i in range(8):
            ids.inspect_packet(arp(f'192.168.1.{100 + i}', '00:1b:21:aa:bb:cc'))
        self.assertIn('ARP-MAC-MULTI-IP', self.rules(alerts))

    def test_a_burst_of_gratuitous_arp(self):
        ids, alerts = self.engine(env=False)
        for i in range(25):
            ids.inspect_packet(arp('192.168.1.60', '00:1b:21:00:00:09', target='192.168.1.60',
                                   ts=2_000_000.0 + i))
        self.assertIn('ARP-GRATUITOUS-BURST', self.rules(alerts))


def dhcp_payload(msg_type, server):
    import ipaddress
    bootp = bytearray(236)
    bootp[0] = 2
    options = (b'\x63\x82\x53\x63' + bytes([53, 1, msg_type]) +
               bytes([54, 4]) + ipaddress.IPv4Address(server).packed + b'\xff')
    return bytes(bootp) + options


class TestRogueServers(_Lan):

    def _offer(self, server, src=None):
        return pkt(protocol='UDP', src_ip=src or server, dst_ip='255.255.255.255',
                   src_port=67, dst_port=68, src_mac='00:1b:21:00:00:67',
                   _raw_payload=dhcp_payload(2, server), payload_size=300)

    def test_an_unknown_dhcp_server(self):
        ids, alerts = self.engine()
        ids.inspect_packet(self._offer('192.168.1.1'))
        self.assertNotIn('ROGUE-DHCP', self.rules(alerts))
        ids.inspect_packet(self._offer('192.168.1.99'))
        self.assertIn('ROGUE-DHCP', self.rules(alerts))

    def test_without_a_configured_server_the_first_is_learned(self):
        env = SimpleNamespace(**dict(vars(self.env), dhcp_servers=[], gateways=[]))
        ids, alerts = self.engine(env=env, created=0)     # baseline long over
        ids.inspect_packet(self._offer('10.0.0.1'))
        ids.inspect_packet(self._offer('10.0.0.1'))
        self.assertNotIn('ROGUE-DHCP', self.rules(alerts))
        ids.inspect_packet(self._offer('10.0.0.66'))
        self.assertIn('ROGUE-DHCP', self.rules(alerts))

    def test_a_new_router_advertisement_after_the_baseline(self):
        ids, alerts = self.engine(created=0)
        ra = dict(protocol='ICMPv6', icmp_type=134, dst_ip='ff02::1')
        ids.inspect_packet(pkt(src_ip='fe80::1', src_mac='00:11:22:33:44:55', **ra))
        ids.inspect_packet(pkt(src_ip='fe80::1', src_mac='00:11:22:33:44:55', **ra))
        self.assertNotIn('ROGUE-RA', self.rules(alerts))
        ids.inspect_packet(pkt(src_ip='fe80::bad', src_mac='00:1b:21:66:66:66', **ra))
        self.assertIn('ROGUE-RA', self.rules(alerts))

    def test_dhcpv6_answers_from_a_new_server(self):
        ids, alerts = self.engine(created=0)
        reply = dict(protocol='UDP', src_port=547, dst_port=546, dst_ip='fe80::50',
                     _raw_payload=b'\x07abc', payload_size=4)
        ids.inspect_packet(pkt(src_ip='fe80::1', src_mac='00:11:22:33:44:55', **reply))
        ids.inspect_packet(pkt(src_ip='fe80::666', src_mac='00:1b:21:66:66:67', **reply))
        self.assertIn('ROGUE-DHCPV6', self.rules(alerts))


def _wire(name, netbios=False):
    if netbios:
        raw = name.upper().ljust(15)[:15].encode() + b'\x00'
        return bytes([32]) + b''.join(bytes([0x41 + (b >> 4), 0x41 + (b & 0x0f)])
                                      for b in raw) + b'\x00'
    return b''.join(bytes([len(part)]) + part.encode() for part in name.split('.')) + b'\x00'


def name_response(names, address, netbios=False):
    """A DNS-format response answering `names` with `address`."""
    import ipaddress
    out = struct.pack('>HHHHHH', 0x1234, 0x8400, 0, len(names), 0, 0)
    for name in names:
        if netbios:
            out += _wire(name, netbios=True) + struct.pack('>HHIH', 0x20, 1, 300, 6)
            out += b'\x00\x00' + ipaddress.IPv4Address(address).packed
        else:
            addr = ipaddress.ip_address(address)
            rtype = 1 if addr.version == 4 else 28
            out += _wire(name) + struct.pack('>HHIH', rtype, 1, 30, len(addr.packed))
            out += addr.packed
    return out


def name_query(names, netbios=False):
    """A DNS-format query asking for `names`."""
    out = struct.pack('>HHHHHH', 0x1234, 0, len(names), 0, 0, 0)
    for name in names:
        out += _wire(name, netbios) + struct.pack('>HH', 0x20 if netbios else 1, 1)
    return out


class TestNamePoisoning(_Lan):

    def _ask(self, ids, names, port=5355, netbios=False):
        payload = name_query(names, netbios=netbios)
        ids.inspect_packet(pkt(protocol='UDP', src_ip='192.168.1.50', dst_ip='224.0.0.252',
                               src_port=50000, dst_port=port, src_mac='00:1b:21:00:00:50',
                               _raw_payload=payload, payload_size=len(payload)))

    def _answer(self, ids, names, src_ip='192.168.1.66', mac='00:1b:21:66:00:01',
                port=5355, address=None, netbios=False):
        payload = name_response(names, address or src_ip, netbios=netbios)
        ids.inspect_packet(pkt(protocol='UDP', src_ip=src_ip, dst_ip='192.168.1.50',
                               src_port=port, dst_port=50000, src_mac=mac,
                               _raw_payload=payload, payload_size=len(payload)))

    def test_one_host_answering_many_names_is_responder(self):
        ids, alerts = self.engine()
        for name in ('fileserver', 'wpad', 'printer', 'intranet'):
            self._ask(ids, [name])
            self._answer(ids, [name])
        hit = [a for a in alerts if a.rule_id == 'NAME-POISONING']
        self.assertTrue(hit)
        self.assertIn('wpad', hit[0].evidence['names_answered'])
        self.assertEqual(hit[0].evidence['responder'], '00:1b:21:66:00:01')

    def test_netbios_answers_are_read_too(self):
        ids, alerts = self.engine()
        for name in ('FILESERVER', 'WPAD', 'PRINTER', 'INTRANET'):
            self._ask(ids, [name], port=137, netbios=True)
            self._answer(ids, [name], port=137, netbios=True)
        self.assertIn('NAME-POISONING', self.rules(alerts))

    def test_a_host_answering_its_own_name_over_v4_and_v6_is_fine(self):
        ids, alerts = self.engine()
        self._answer(ids, ['laptop.local'], src_ip='192.168.1.70', mac='00:1b:21:00:00:70',
                     port=5353)
        self._answer(ids, ['laptop.local'], src_ip='fe80::70', mac='00:1b:21:00:00:70',
                     port=5353)
        self.assertNotIn('NAME-POISONING', self.rules(alerts))
        self.assertEqual(len(ids.lan._name_owners['laptop']), 1,
                         "one host's IPv4 and IPv6 answers counted as two responders")

    def test_hostile_payloads_never_raise(self):
        from src.lan_threats import parse_dns_wire
        for i in range(300):
            parse_dns_wire(os.urandom(i % 80))
            parse_dns_wire(b'\x00\x00\x84\x00\x00\x00\x00\x01' + os.urandom(40))
        # A compression pointer loop
        self.assertIsNone(parse_dns_wire(struct.pack('>HHHHHH', 1, 0x8400, 0, 1, 0, 0) +
                                         b'\xc0\x0c'))


class TestLateralAndUploads(_Lan):

    def test_fan_out_over_smb_and_rdp(self):
        ids, alerts = self.engine()
        for i in range(9):
            ids.inspect_packet(pkt(protocol='TCP', flags='S', src_ip='192.168.1.80',
                                   dst_ip=f'192.168.1.{150 + i}', src_port=50000 + i,
                                   dst_port=445 if i % 2 else 3389))
        self.assertNotIn('LATERAL-MOVEMENT', self.rules(alerts))
        ids.inspect_packet(pkt(protocol='TCP', flags='S', src_ip='192.168.1.80',
                               dst_ip='192.168.1.170', src_port=50100, dst_port=5985))
        self.assertIn('LATERAL-MOVEMENT', self.rules(alerts))

    def _upload(self, ids, ts, mb, weight=1, src='192.168.1.90'):
        chunk = 1_000_000
        for i in range(int(mb)):
            ids.inspect_packet(pkt(ts=ts + i * 0.01, protocol='TCP', src_ip=src,
                                   dst_ip='45.155.205.10', src_port=50000, dst_port=443,
                                   payload_size=chunk // weight, sample_weight=weight))

    def test_an_upload_far_above_the_hosts_own_baseline(self):
        ids, alerts = self.engine()
        start = 3_000_000.0
        for w in range(14):                     # an hour of ~5 MB windows
            self._upload(ids, start + w * 300, 5)
        self.assertNotIn('UPLOAD-SPIKE', self.rules(alerts))
        self._upload(ids, start + 14 * 300, 80)
        spike = [a for a in alerts if a.rule_id == 'UPLOAD-SPIKE']
        self.assertTrue(spike)
        self.assertEqual(spike[0].evidence['source_ip'], '192.168.1.90')

    def test_sampling_weight_is_counted(self):
        """At 1-in-4 sampling, each delivered packet stands for four."""
        ids, alerts = self.engine()
        start = 4_000_000.0
        for w in range(14):
            self._upload(ids, start + w * 300, 5, src='192.168.1.91')
        self._upload(ids, start + 14 * 300, 80, weight=4, src='192.168.1.91')
        self.assertIn('UPLOAD-SPIKE', self.rules(alerts))


class TestNewDevices(_Lan):

    def test_a_device_after_the_baseline_is_reported_with_its_vendor(self):
        ids, alerts = self.engine(created=0)
        ids.inspect_packet(arp('192.168.1.120', '3c:22:fb:12:34:56'))
        hit = [a for a in alerts if a.rule_id == 'NEW-DEVICE']
        self.assertTrue(hit)
        self.assertIn('Apple', hit[0].evidence['vendor'])
        ids.inspect_packet(arp('192.168.1.120', '3c:22:fb:12:34:56'))
        self.assertEqual(self.rules(alerts).count('NEW-DEVICE'), 1)

    def test_randomised_macs_and_the_baseline_period_are_quiet(self):
        ids, alerts = self.engine(created=0)
        ids.inspect_packet(arp('192.168.1.121', '3a:22:fb:12:34:57'))    # locally administered
        self.assertNotIn('NEW-DEVICE', self.rules(alerts))
        learning, alerts2 = self.engine()                                # baseline just began
        learning.inspect_packet(arp('192.168.1.122', '00:1b:21:12:34:58'))
        self.assertNotIn('NEW-DEVICE', self.rules(alerts2))


if __name__ == '__main__':
    unittest.main()
