"""
What the second review of real alerts found.
============================================
A day of 1.9.0 on the owner's network raised 263 alerts, none of them an
attack. The first looked at was a CRITICAL "ARP Spoofing": two smart-home
devices that each remembered an old address, 192.168.1.80, from the network
they were set up on, and announced it once whenever they rejoined Wi-Fi, hours
apart. Most of the rest came from rules that named a service by either port of
a connection, on a PC whose outgoing connections use local ports from 1024 up.
Addresses and MACs here are made up or the public services involved.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import SCAPY_REAL, reset_config  # noqa: E402

from test_lan_threats import _Lan, arp, pkt  # noqa: E402

STALE = '192.168.1.80'
PLUG, LIGHT = '00:1b:21:00:00:a1', '00:1b:21:00:00:b2'
HOUR = 3600.0
T0 = 1_790_000_000.0
PC, PI, ROUTER = '192.168.8.32', '192.168.8.69', '192.168.8.1'
GOOGLE = '142.250.68.195'


def tcp(src, sport, dst, dport, flags='PA', payload=b'', server=0, ts=T0):
    """A TCP packet as capture hands it on, server_port included."""
    return pkt(ts=ts, protocol='TCP', src_ip=src, src_port=sport, dst_ip=dst,
               dst_port=dport, flags=flags, payload_size=len(payload),
               length=len(payload) + 54, _raw_payload=payload or None, server_port=server)


def forensics():
    from src.forensics import NetworkForensics
    return NetworkForensics()


def kinds(f):
    return [d['data_type'] for d in f.sensitive_data]


class TestWhichEndIsTheServer(unittest.TestCase):

    def roles(self, *packets, local=(), listening=()):
        from src.capture import TcpRoles
        roles = TcpRoles()
        return [roles.server_port(p, local, listening) for p in packets]

    def test_the_handshake_says_which_end_is_the_server(self):
        self.assertEqual(self.roles(tcp(PC, 5901, GOOGLE, 443, 'S'),
                                    tcp(GOOGLE, 443, PC, 5901, 'SA'),
                                    tcp(GOOGLE, 443, PC, 5901, 'PA')), [443, 443, 443])

    def test_mid_connection_this_computer_is_the_server_only_if_it_listens(self):
        """Joined after the handshake, as at start-up."""
        reply = tcp(GOOGLE, 443, PC, 5901)
        self.assertEqual(self.roles(reply, local={PC}), [443])
        self.assertEqual(self.roles(tcp(PI, 50000, PC, 8787), local={PC},
                                    listening={8787}), [8787])
        self.assertEqual(self.roles(tcp(PI, 50000, ROUTER, 80)), [0], 'unknown stays unknown')

    @unittest.skipUnless(SCAPY_REAL, 'needs scapy')
    def test_capture_marks_every_tcp_packet(self):
        from scapy.all import IP, TCP, Ether
        from src.capture import CaptureEngine
        engine = CaptureEngine(reset_config())
        mac = dict(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')
        syn = Ether(**mac) / IP(src=PC, dst=PI) / TCP(sport=9050, dport=8500, flags='S')
        reply = Ether(**mac) / IP(src=PI, dst=PC) / TCP(sport=8500, dport=9050, flags='PA')
        infos = [engine._extract_packet_info(p, offline=True) for p in (syn, reply)]
        self.assertEqual([i.server_port for i in infos], [8500, 8500])


class TestServicesByTheServersPort(_Lan):
    """Replies to this computer's own outgoing ports, named as services."""

    def test_a_reply_to_local_port_5901_is_not_a_vnc_server(self):
        f = forensics()
        for _ in range(6):
            f.analyze_packet(tcp(GOOGLE, 443, PC, 5901, payload=b'\x17\x03\x03' + b'x' * 200,
                                 server=443))
        self.assertNotIn((PC, 5901), f.insecure_services)

    def test_an_http_get_from_local_port_6379_is_not_redis(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 6379, PI, 8500, payload=b'GET /status HTTP/1.1\r\n'
                                                          b'Host: pi:8500\r\n\r\n', server=8500))
        self.assertNotIn('Redis No Auth', kinds(f))

    def test_a_reply_to_local_port_9100_is_not_a_print_job(self):
        f = forensics()
        f.analyze_packet(tcp(PI, 8500, PC, 9100, payload=b'{"ok": true}' * 20, server=8500))
        self.assertNotIn('Network Printer', kinds(f))

    def test_a_reply_to_local_port_9050_is_not_tor(self):
        from src.ioc_scanner import IOCScanner
        found = IOCScanner(reset_config()).check_packet_ioc(
            tcp(PI, 8500, PC, 9050, payload=b'x' * 50, server=8500))
        self.assertFalse([x for x in found if x['rule_id'] == 'IOC-TOR'])

    def test_a_reply_to_local_port_6666_is_not_a_bad_port(self):
        ids, alerts = self.engine(env=False)
        ids.known_bad_ports.add(6666)
        ids.inspect_packet(tcp('34.36.133.15', 443, PC, 6666, 'A', server=443))
        self.assertNotIn('BAD-PORT', self.rules(alerts))
        ids.inspect_packet(tcp(PC, 50000, '203.0.113.9', 6666, 'S', server=6666))
        self.assertIn('BAD-PORT', self.rules(alerts), 'a connection to one still is')


class TestProtocolChecks(unittest.TestCase):

    def test_redis_needs_a_redis_command(self):
        """`a and b or c`: any payload with GET in it on 6379 counted."""
        f = forensics()
        f.analyze_packet(tcp(PC, 50000, PI, 6379, payload=b'GET / HTTP/1.1\r\n\r\n', server=6379))
        self.assertNotIn('Redis No Auth', kinds(f))
        f.analyze_packet(tcp(PC, 50001, PI, 6379, payload=b'*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n',
                             server=6379))
        self.assertIn('Redis No Auth', kinds(f))

    def test_a_few_bytes_on_port_502_are_not_modbus(self):
        """A printer and a router answering an audit's probe were CRITICAL Modbus."""
        f = forensics()
        f.analyze_packet(tcp('192.168.8.54', 502, PC, 59640, payload=b'\x00\x01\x02\x03',
                             server=502))
        self.assertNotIn('Modbus/SCADA', kinds(f))
        write = b'\x00\x01\x00\x00\x00\x06\x01\x06\x00\x10\x00\x2a'
        f.analyze_packet(tcp(PC, 59641, '192.168.8.54', 502, payload=write, server=502))
        self.assertIn('Modbus WRITE', kinds(f))

    def test_bacnet_is_udp(self):
        """A web client whose port happened to be 47808 made localcast "BACnet"."""
        f = forensics()
        f.analyze_packet(tcp(PC, 8787, '192.168.12.42', 47808,
                             payload=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'))
        self.assertNotIn('BACnet', kinds(f))


class TestFastFluxBesideCdns(unittest.TestCase):

    def flux(self, name, addresses, ttls):
        from src.dns_analysis import DnsResponseMonitor
        mon = DnsResponseMonitor(reset_config())
        mon.cdn_check = lambda *a: False            # neither name is a known CDN
        out = []
        for i, (addr, ttl) in enumerate(zip(addresses, ttls)):
            out += mon.observe_response(PC, name, 0, (addr,), ttl, T0 + i * 60)
        return [f for f in out if f['type'] == 'fast_flux']

    def test_a_cdn_in_two_networks_is_not_fast_flux(self):
        """api.weather.gov on Akamai: HIGH every five minutes, all night."""
        addresses = ['23.201.34.13', '23.201.34.8', '23.49.248.143', '23.49.248.147',
                     '23.49.248.152', '23.49.248.153', '23.49.248.168', '23.49.248.169']
        self.assertEqual(self.flux('api.weather.gov', addresses, [20] * 8), [])

    def test_a_cached_ttl_counting_down_is_not_a_short_ttl(self):
        """The router's cache hands out what is left of the TTL, down to 1."""
        addresses = [f'{60 + i}.{i}.1.1' for i in range(10)]
        self.assertEqual(self.flux('busy.example.org', addresses,
                                   [3600, 1800, 600, 120, 30, 1, 3500, 900, 60, 1]), [])

    def test_real_fast_flux_still_is_and_once_an_hour(self):
        addresses = [f'{60 + i}.{i}.1.1' for i in range(12)]
        self.assertEqual(len(self.flux('pharma.example', addresses, [30] * 12)), 1)


class TestScansAndFloods(_Lan):

    def test_one_audit_is_one_port_scan_alert_about_its_target(self):
        """A 7-second audit of three hosts raised 87, naming internet servers."""
        ids, alerts = self.engine(env=False)
        n = 0
        for port in (21, 22, 23, 25, 53, 80, 81, 88, 110, 135, 143, 389, 445, 993, 3306):
            for host in ('192.168.8.54', ROUTER, PI):
                n += 1
                ids.inspect_packet(tcp(PC, 40000 + n, host, port, 'S', server=port, ts=T0 + n / 100))
                ids.inspect_packet(tcp(PC, 50000 + n, f'142.250.{n % 7}.3', 443, 'S', server=443,
                                       ts=T0 + n / 100))
        scans = [a for a in alerts if a.rule_id == 'PORT-SCAN']
        self.assertEqual(len(scans), 1)
        self.assertIn(scans[0].dst_ip, ('192.168.8.54', ROUTER, PI))
        self.assertFalse([t for t in scans[0].evidence['target_ips'] if t.startswith('142.')])

    def test_a_client_retrying_is_not_a_syn_flood(self):
        """51 SYNs at 5 a second to a Raspberry Pi was a CRITICAL "SYN Flood"."""
        ids, alerts = self.engine(env=False)
        for i in range(60):
            ids.inspect_packet(tcp(PC, 20000 + i, PI, 8500, 'S', server=8500, ts=T0 + i / 6))
        self.assertNotIn('SYN-FLOOD', self.rules(alerts))
        for i in range(400):
            ids.inspect_packet(tcp('203.0.113.66', 30000 + i, PC, 3389, 'S', server=3389,
                                   ts=T0 + 20 + i / 50))
        self.assertIn('SYN-FLOOD', self.rules(alerts), 'a real flood still is')


class TestEsetAndCertificates(unittest.TestCase):

    DIGEST = (b'GET /v1/update.ver HTTP/1.1\r\nHost: update.eset.com\r\n'
              b'Authorization: Digest username="EAV-0000000000", realm="eset", '
              b'nonce="%d", uri="/v1/update.ver", response="0123456789abcdef"\r\n\r\n')

    def test_esets_hourly_login_is_noted_once_a_day(self):
        f = forensics()
        for hour in range(3):
            f.analyze_packet(tcp(PC, 50000 + hour, '38.90.226.40', 80, server=80,
                                 payload=self.DIGEST % hour, ts=T0 + hour * HOUR))
        self.assertEqual(len([c for c in f.credentials_found
                              if 'Update Service' in c.get('protocol', '')]), 1)

    def test_an_updaters_hashed_login_is_not_confirmed(self):
        """The verifier confirmed every credential, raising ESET's LOW to HIGH."""
        from src.alert_verify import AlertVerifier
        from src.ids_engine import Alert
        alert = Alert('FORENSICS-CREDENTIAL', 'LOW', 't', 'd', evidence={
            'protocol': 'HTTP Digest Auth (Update Service)', 'credential_type': 'digest_hash'})
        info = AlertVerifier(reset_config())._verify_credential_exposure(alert, alert.evidence)
        self.assertEqual(info['verdict'], 'LIKELY_FALSE_POSITIVE')

    def test_a_revocation_check_is_not_an_insecure_service(self):
        """Let's Encrypt, HARICA and DigiCert CRL fetches were each one."""
        from src.app import NetSentinelApp
        f = forensics()
        for i in range(6):
            f.analyze_packet(tcp(PC, 50000, '185.93.1.243', 80, server=80, payload=(
                b'GET /HARICA-TLS-Root-2021-RSA.crl HTTP/1.1\r\nHost: crl.harica.gr\r\n'
                b'User-Agent: Microsoft-CryptoAPI/10.0\r\n\r\n'), ts=T0 + i))
        app = NetSentinelApp.__new__(NetSentinelApp)
        raised = []
        app.forensics = f
        app._forensics_cred_cursor = app._forensics_sensitive_cursor = 0
        app._forensics_alerted_services, app._forensics_alerted_sensitive = set(), set()
        app._alert_gateway = raised.append
        app._check_forensics_alerts()
        self.assertFalse([a for a in raised if a.rule_id == 'FORENSICS-INSECURE-SVC'])


class TestStaleAddressAnnouncements(_Lan):

    def spoof_alerts(self, alerts):
        return [a for a in alerts if a.rule_id == 'ARP-SPOOF']

    def test_devices_announcing_an_old_address_hours_apart_are_not_spoofing(self):
        """The CRITICAL that started this review: once each, hours apart."""
        ids, alerts = self.engine(env=False)
        for n, mac in enumerate((LIGHT, PLUG, LIGHT, PLUG, LIGHT)):
            ids._alert_cooldowns.clear()
            ids.inspect_packet(arp(STALE, mac, ts=1_000_000.0 + n * 5.7 * HOUR, target=STALE))
        self.assertEqual(self.spoof_alerts(alerts), [])

    def test_a_back_and_forth_hours_apart_is_not_two_hosts_fighting(self):
        """Flapping counted however far apart the changes were."""
        ids, alerts = self.engine(env=False)
        for n, mac in enumerate((LIGHT, PLUG, LIGHT)):
            ids._alert_cooldowns.clear()
            for repeat in range(2):
                ids.inspect_packet(arp(STALE, mac, ts=1_000_000.0 + n * 5 * HOUR + repeat))
        self.assertEqual(self.spoof_alerts(alerts), [])

    def test_a_spoofer_contesting_an_address_is_still_caught(self):
        ids, alerts = self.engine(env=False)
        t = 1_000_000.0
        ids.inspect_packet(arp('192.168.1.30', PLUG, ts=t))
        for i in range(2):
            ids.inspect_packet(arp('192.168.1.30', '00:1b:21:66:66:66', ts=t + 5 + i))
        ids._alert_cooldowns.clear()
        for i in range(2):                  # the owner answers back
            ids.inspect_packet(arp('192.168.1.30', PLUG, ts=t + 9 + i))
        found = self.spoof_alerts(alerts)
        self.assertEqual([a.severity for a in found], ['HIGH', 'CRITICAL'])
        self.assertNotIn('gateway', found[0].evidence['recommendation'].lower(),
                         'it told you to check the gateway for a device that is not one')


class TestStaleGatewayPin(unittest.TestCase):

    def test_this_computer_is_no_longer_pinned_as_a_gateway(self):
        """Pinned before the route-table fix, and kept across restarts after it."""
        from src.lan_threats import LanThreatMonitor
        tmp = tempfile.mkdtemp(prefix='ns_pin_')
        self.addCleanup(shutil.rmtree, tmp, True)
        path = os.path.join(tmp, 'lan_state.json')
        pins = {'192.168.8.1': {'mac': '00:11:22:33:44:55', 'pinned_at': 1, 'last_seen': 1},
                '192.168.8.32': {'mac': '00:1b:21:00:00:32', 'pinned_at': 1, 'last_seen': 1}}
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({'gateway_macs': pins}, f)
        env = SimpleNamespace(gateways=['192.168.8.1'], local_ips=['192.168.8.32', '127.0.0.1'])
        lan = LanThreatMonitor(None, net_env=env, state_path=path)
        self.assertEqual(sorted(lan.state['gateway_macs']), ['192.168.8.1'])


@unittest.skipUnless(SCAPY_REAL, 'needs scapy')
class TestArpCaptures(unittest.TestCase):

    def test_an_arp_alert_saves_its_arp(self):
        """The capture said "no packet named the alert's hosts": ARP was never read."""
        from scapy.all import ARP, Dot1Q, Ether
        from src.pcap_writer import _frame_involves
        announce = (Ether(src=LIGHT, dst='ff:ff:ff:ff:ff:ff') / Dot1Q(vlan=3)
                    / ARP(op=1, hwsrc=LIGHT, psrc=STALE, pdst=STALE))
        self.assertTrue(_frame_involves(bytes(announce), {STALE}))
        asking = Ether(src=PLUG, dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, hwsrc=PLUG,
                                                                psrc='192.168.12.169',
                                                                pdst=STALE)
        self.assertTrue(_frame_involves(bytes(asking), {STALE}))
        self.assertFalse(_frame_involves(bytes(asking), {'192.168.12.1'}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
