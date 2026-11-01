"""
What the third review of real alerts found.
===========================================
A day of 1.9.1 on the owner's network raised 36 alerts, none CRITICAL. The nine
HIGH ones were Akamai's address churn (fast-flux), Tailscale reaching peers
behind one NAT (a port scan), and Home Assistant announcing its own names (name
poisoning). The rest were services named by port on the wrong transport, ESET's
LiveGrid, certificate checks and Windows Update over plain HTTP, one alert per
CDN address, version banners rated MEDIUM, and a DNS burst charged to the web
servers that came after it.
Addresses and MACs here are made up or the public services involved.
"""

import base64
import ipaddress
import os
import struct
import sys
import unittest
from types import SimpleNamespace
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_lan_threats import _Lan, _wire, name_query, pkt  # noqa: E402

T0 = 1_790_000_000.0
DAY = 86400.0
PC, ROUTER = '192.168.1.50', '192.168.1.1'
NAT = '203.0.113.7'                     # three Tailscale peers behind one NAT
HA, HA_MAC = '192.168.1.97', '2c:cf:67:00:00:01'


def udp(src, sport, dst, dport, payload=b'\x01' * 32, ts=T0, **kw):
    return pkt(ts=ts, protocol='UDP', src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
               payload_size=len(payload), length=len(payload) + 42,
               _raw_payload=payload, **kw)


def tcp(src, sport, dst, dport, payload=b'', flags='PA', server=0, ts=T0):
    return pkt(ts=ts, protocol='TCP', src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
               flags=flags, payload_size=len(payload), length=len(payload) + 54,
               _raw_payload=payload or None, server_port=server)


def http_get(host, path='/', agent=None, method='GET', body=b''):
    lines = [f'{method} {path} HTTP/1.1', f'Host: {host}']
    if agent:
        lines.append(f'User-Agent: {agent}')
    if body:
        lines.append(f'Content-Length: {len(body)}')
    return ('\r\n'.join(lines) + '\r\n\r\n').encode() + body


# ─── Fast-flux ───────────────────────────────────────────────────────────────

class TestFastFluxThroughACdn(unittest.TestCase):

    def flux(self, name, chain, addresses):
        from src.dns_analysis import DnsResponseMonitor
        mon = DnsResponseMonitor(reset_config())
        out = []
        for i, addr in enumerate(addresses):
            out += mon.observe_response(PC, name, 0, tuple(chain) + (addr,), 20, T0 + i * 20)
        return [f for f in out if f['type'] == 'fast_flux']

    # Akamai's own addresses, spread over many /16s as it hands them out.
    AKAMAI = [f'23.{n}.{i}.{i + 8}' for n in (43, 44, 196, 201, 209, 211, 212)
              for i in range(4)]

    def test_a_cname_into_akamai_is_not_fast_flux(self):
        """api.weather.gov: HIGH six times in a day, every one of them Akamai."""
        chain = ('sancert.weather.gov.edgekey.net', 'e353369.dscg.akamaiedge.net')
        self.assertEqual(self.flux('api.weather.gov', chain, self.AKAMAI), [])
        chain = ('catalog.gamepass.com.edgesuite.net', 'a1992.dscd.akamai.net')
        self.assertEqual(self.flux('catalog.gamepass.com', chain, self.AKAMAI), [])

    def test_a_name_on_its_own_addresses_still_is(self):
        homes = [f'{a}.{i}.20.{i + 1}' for a in (24, 68, 71, 73, 98, 174) for i in range(3)]
        self.assertEqual(len(self.flux('pharma.example', (), homes)), 1)

    def test_a_cname_to_a_name_no_cdn_owns_still_is(self):
        homes = [f'{a}.{i}.20.{i + 1}' for a in (24, 68, 71, 73, 98, 174) for i in range(3)]
        self.assertEqual(len(self.flux('shop.example', ('edge.pharma.example',), homes)), 1)


# ─── Port scan ───────────────────────────────────────────────────────────────

class TestPeersBehindOneNat(_Lan):

    def test_tailscale_to_peers_behind_one_nat_is_not_a_scan(self):
        """Seven high ports to one NAT, and the low ports were DNS and web elsewhere."""
        ids, alerts = self.engine(env=False)
        ts = T0
        for port in (3804, 14990, 15197, 25080, 36429, 41641, 65308, 2841, 8081):
            ts += 1
            ids.inspect_packet(udp(PC, 41641, NAT, port, ts=ts))
        for port in (53, 1900, 5351):
            ts += 1
            ids.inspect_packet(udp(PC, 50000 + port, ROUTER, port, ts=ts))
        for port in (80, 443, 3478, 5349):
            ts += 1
            ids.inspect_packet(tcp(PC, 20000 + port, '141.101.90.1', port, flags='S',
                                   server=port, ts=ts))
        for host, port in (('192.168.1.54', 8009), (HA, 8123)):
            ts += 1
            ids.inspect_packet(tcp(PC, 30000 + port, host, port, flags='S', server=port, ts=ts))
        self.assertNotIn('PORT-SCAN', self.rules(alerts))

    def test_many_ports_on_one_host_with_service_ports_still_is(self):
        ids, alerts = self.engine(env=False)
        for i, port in enumerate((21, 22, 23, 25, 80, 110, 139, 143, 443, 445, 3306,
                                  3389, 5900, 8080, 8443, 9100)):
            ids.inspect_packet(udp(PC, 41641, NAT, port, ts=T0 + i))
        scans = [a for a in alerts if a.rule_id == 'PORT-SCAN']
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].dst_ip, NAT)


# ─── Name poisoning ──────────────────────────────────────────────────────────

def record(name, rtype, rdata):
    return _wire(name) + struct.pack('>HHIH', rtype, 0x8001, 120, len(rdata)) + rdata


def a(name, address):
    packed = ipaddress.ip_address(address).packed
    return record(name, 1 if len(packed) == 4 else 28, packed)


def srv(name, target, port):
    return record(name, 33, struct.pack('>HHH', 0, 0, port) + _wire(target))


def ptr(name, target):
    return record(name, 12, _wire(target))


def mdns(*records):
    return struct.pack('>HHHHHH', 0, 0x8400, 0, len(records), 0, 0) + b''.join(records)


INSTANCE = '0123456789abcdef0123456789abcdef.local'     # its zeroconf host name
MATTER = '2CCF67000001AAAA.local'                       # the Matter server's
ADDON = 'esphome-builder-abcdefgh.local'


class TestHomeAssistantsOwnNames(_Lan):

    def send(self, ids, payload, src=HA, mac=HA_MAC, sport=5353, dst='224.0.0.251',
             dport=5353, ts=T0):
        ids.inspect_packet(udp(src, sport, dst, dport, payload, ts=ts, src_mac=mac))

    def announce(self, ids, ts=T0):
        self.send(ids, mdns(
            ptr('_home-assistant._tcp.local', 'Home._home-assistant._tcp.local'),
            srv('Home._home-assistant._tcp.local', INSTANCE, 8123), a(INSTANCE, HA),
            srv('ABCDEF0123456789-0000000000000001._matter._tcp.local', MATTER, 5540),
            a(MATTER, HA), a(MATTER, 'fe80::97'),
            ptr('97.1.168.192.in-addr.arpa', 'homeassistant.local'),
            a('homeassistant.local', HA), a(ADDON, HA)), ts=ts)

    def test_announcing_its_own_names_unasked_is_not_poisoning(self):
        """Its hostname, instance ID, Matter name and an add-on: a HIGH, at night."""
        ids, alerts = self.engine()
        self.announce(ids)
        self.assertNotIn('NAME-POISONING', self.rules(alerts))

    def test_answering_lookups_for_the_names_its_services_use_is_not_either(self):
        ids, alerts = self.engine()
        self.announce(ids)
        for i, name in enumerate((INSTANCE, MATTER, 'homeassistant.local', ADDON)):
            ts = T0 + 60 + i * 30
            self.send(ids, name_query([name]), src=PC, mac='00:1b:21:00:00:50', ts=ts)
            self.send(ids, mdns(a(name, HA)), ts=ts + 0.1)
        self.assertNotIn('NAME-POISONING', self.rules(alerts))

    def test_this_pcs_own_lookups_from_port_5355_are_not_name_answers(self):
        """Ordinary DNS: from a local port that happens to be 5355, answered from 53."""
        ids, alerts = self.engine()
        for i, name in enumerate(('fileserver.example', 'wpad.example', 'mail.example',
                                  'intranet.example')):
            ts = T0 + i
            q = struct.pack('>HHHHHH', i, 0x0100, 1, 0, 0, 0) + _wire(name) + b'\x00\x01\x00\x01'
            ids.inspect_packet(udp(PC, 5355, ROUTER, 53, q, ts=ts))
            r = (struct.pack('>HHHHHH', i, 0x8180, 0, 1, 0, 0)
                 + _wire(name) + struct.pack('>HHIH', 1, 1, 30, 4) + bytes([192, 168, 1, 9]))
            ids.inspect_packet(udp(ROUTER, 53, PC, 5355, r, ts=ts + 0.01,
                                   src_mac='00:1b:21:00:00:01'))
        self.assertNotIn('NAME-POISONING', self.rules(alerts))


# ─── Forensics ───────────────────────────────────────────────────────────────

def forensics():
    from src.forensics import NetworkForensics
    return NetworkForensics()


def kinds(f):
    return {d['data_type']: d['risk'] for d in f.sensitive_data}


class _Alerts:
    """The app's forensics-to-alert step, without the rest of the app."""

    def __init__(self, f):
        from src.app import NetSentinelApp
        self.app = app = NetSentinelApp.__new__(NetSentinelApp)
        self.raised = []
        app.forensics, app.ids_engine = f, None
        app._forensics_cred_cursor = app._forensics_sensitive_cursor = 0
        app._forensics_alerted_services, app._forensics_alerted_sensitive = set(), set()
        app._insecure_names_alerted = {}
        app._alert_gateway = self.raised.append

    def insecure(self):
        self.app._check_forensics_alerts()
        return [a for a in self.raised if a.rule_id == 'FORENSICS-INSECURE-SVC']


class TestServicesOnTheirOwnTransport(unittest.TestCase):

    def test_wireguard_to_a_nat_port_that_is_8081_is_not_http(self):
        f = forensics()
        for i in range(8):
            f.analyze_packet(udp(PC, 41641, NAT, 8081, bytes(range(i, i + 148)), ts=T0 + i))
        self.assertEqual(f.insecure_services, {})

    def test_http_on_8081_and_snmp_on_161_still_are(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 50000, '192.168.1.20', 8081, http_get('192.168.1.20:8081'),
                             server=8081))
        f.analyze_packet(udp(PC, 50001, '192.168.1.21', 161, b'\x30\x0c' + bytes(12)))
        self.assertEqual({k[1] for k in f.insecure_services}, {8081, 161})


class TestEsetLiveGrid(unittest.TestCase):

    def test_livegrid_lookups_are_not_missing_agents_or_exposed(self):
        """ESET's reputation lookups: no User-Agent, a body ESET encrypts itself."""
        f = forensics()
        request = http_get('i1.livegrid.eset.systems', '/livegrid', method='POST',
                           body=bytes((i * 151) % 256 for i in range(77)))
        for i in range(6):
            f.analyze_packet(tcp(PC, 50000 + i, '38.90.226.46', 80, request, server=80,
                                 ts=T0 + i))
        self.assertNotIn('Missing User Agent', kinds(f))
        self.assertEqual(_Alerts(f).insecure(), [])


def der(tag, body):
    size = bytes([len(body)]) if len(body) < 0x80 else b'\x81' + bytes([len(body)])
    return bytes([tag]) + size + body


# An OCSP request for one certificate: SHA-1 issuer name and key hashes, a serial.
CERT_ID = der(0x30, der(0x30, der(0x06, bytes.fromhex('2b0e03021a')) + b'\x05\x00')
              + der(0x04, b'\x3f' * 20) + der(0x04, b'\xfb' * 20) + der(0x02, b'\x0c\x9a\x51'))
OCSP_REQUEST = der(0x30, der(0x30, der(0x30, der(0x30, CERT_ID))))
OCSP_B64 = base64.b64encode(OCSP_REQUEST).decode()


class TestSignedOverPlainHttp(unittest.TestCase):

    def test_ocsp_by_get_is_recognised_whoever_answers_it(self):
        from src.forensics import is_signed_fetch
        self.assertTrue(is_signed_fetch(
            'status.thawte.com', http_get('status.thawte.com', '/' + quote(OCSP_B64, safe=''))))
        self.assertTrue(is_signed_fetch(
            'oneocsp.microsoft.com',
            http_get('oneocsp.microsoft.com', '/ocsp/' + quote(OCSP_B64, safe=''))))

    def test_other_paths_are_not(self):
        from src.forensics import is_signed_fetch
        for path in ('/', '/index.html', '/MFEwTzBNMEswSTAJBgUr', '/' + OCSP_B64[:-8],
                     '/api/v1/' + base64.b64encode(b'{"user": 1}').decode()):
            self.assertFalse(is_signed_fetch('status.example.com', http_get('x', path)), path)

    def test_windows_update_from_a_cache_server_addressed_by_ip(self):
        from src.forensics import is_signed_fetch
        agent = 'Microsoft-Delivery-Optimization/10.1'
        for path in ('/filestreamingservice/files/c4b50504-a8f3-4c3b-9296-f280ad40c1d2',
                     '/filestreamingservice//files/0f1c0c50-b501-4e58-9b56-1b1ab85d7e10'):
            self.assertTrue(is_signed_fetch('203.0.113.9', http_get('203.0.113.9', path, agent)))
        self.assertFalse(is_signed_fetch('203.0.113.9', http_get(
            '203.0.113.9', '/filestreamingservice/files/x', 'Mozilla/5.0')))


class TestOneAlertPerServiceName(unittest.TestCase):

    STEAM = 'clientconfig.akamai.steamstatic.com'

    def fetch(self, f, server, host, ts):
        request = http_get(host, '/appinfo/1510/sha/54e5a2d6', 'Valve/Steam HTTP Client 1.0')
        for i in range(6):
            f.analyze_packet(tcp(PC, 50000 + i, server, 80, request, server=80, ts=ts + i))

    def test_a_cdn_service_on_a_new_address_is_not_a_new_alert(self):
        """Steam's client config: five LOW alerts in a day, one per Akamai address."""
        f = forensics()
        alerts = _Alerts(f)
        for n, server in enumerate(('23.201.34.172', '23.201.34.170', '23.204.152.169')):
            f._ip_to_domains[server].add(self.STEAM)
            self.fetch(f, server, self.STEAM, T0 + n * 3600)
            alerts.insecure()
        self.assertEqual(len(alerts.insecure()), 1)

    def test_another_service_or_another_day_is(self):
        f = forensics()
        alerts = _Alerts(f)
        f._ip_to_domains['23.201.34.172'].add(self.STEAM)
        f._ip_to_domains['100.50.34.161'].add('config.example.com')
        self.fetch(f, '23.201.34.172', self.STEAM, T0)
        self.fetch(f, '100.50.34.161', 'config.example.com', T0)
        self.assertEqual(len(alerts.insecure()), 2)
        svc = {'ip': '23.204.152.169', 'port': 80}
        f._ip_to_domains['23.204.152.169'].add(self.STEAM)
        app = alerts.app
        self.assertTrue(app._insecure_service_named_today(svc, now=app._insecure_names_alerted[
            (80, self.STEAM)] + 3600))
        self.assertFalse(app._insecure_service_named_today(svc, now=app._insecure_names_alerted[
            (80, self.STEAM)] + DAY + 1))


class TestObservedIsLow(unittest.TestCase):

    def response(self, f, server, banner):
        payload = f'HTTP/1.1 200 OK\r\nServer: {banner}\r\nContent-Length: 0\r\n\r\n'.encode()
        f.analyze_packet(tcp(server, 80, HA, 50000, payload, server=80))

    def test_a_version_banner_is_low_and_an_end_of_life_one_high(self):
        """Home Assistant talking to two new smart plugs: two MEDIUM alerts."""
        f = forensics()
        self.response(f, '192.168.1.81', 'SHIP/2.0 lighttpd/1.4.59')
        self.assertEqual(kinds(f).get('HTTP Server Info'), 'LOW')
        f = forensics()
        self.response(f, '192.168.1.82', 'Apache/2.2.15 (Unix)')
        self.assertEqual(kinds(f).get('HTTP Server Info'), 'HIGH')

    def test_a_missing_user_agent_is_low(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 50000, '192.168.1.81', 80, http_get('192.168.1.81'),
                             server=80))
        self.assertEqual(kinds(f).get('Missing User Agent'), 'LOW')


# ─── DNS volume ──────────────────────────────────────────────────────────────

class TestDnsFloodOnLookupsOnly(_Lan):

    def env_with_resolver(self):
        env = SimpleNamespace(**vars(self.env))
        env.is_configured_resolver = lambda ip: ip == ROUTER
        return env

    def lookups(self, ids, resolver, n, ts=T0):
        for i in range(n):
            ids.inspect_packet(udp(PC, 50000 + i, resolver, 53, ts=ts + i / 10,
                                   dns_query=f'site{i}.example.com'))

    def test_a_page_load_through_the_own_resolver_is_not_a_flood(self):
        """51 lookups, then QUIC to the sites: two alerts naming Google's servers."""
        ids, alerts = self.engine(env=self.env_with_resolver())
        self.lookups(ids, ROUTER, 55)
        for i, server in enumerate(('142.250.188.3', '142.251.41.163', '142.250.217.131')):
            ids.inspect_packet(udp(PC, 58460 + i, server, 443, ts=T0 + 6 + i / 10,
                                   tls_sni='www.gstatic.com'))
        self.assertNotIn('DNS-FLOOD', self.rules(alerts))

    def test_a_flood_elsewhere_is_one_alert(self):
        ids, alerts = self.engine(env=self.env_with_resolver())
        self.lookups(ids, '203.0.113.53', 120)
        self.assertEqual(self.rules(alerts).count('DNS-FLOOD'), 1)


if __name__ == '__main__':
    unittest.main()
