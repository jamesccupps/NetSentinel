"""Active subnet audit: scope refusals, discovery, rate limits, findings, certificates,
the diff, progress and cancel. Nothing here leaves loopback: every run_audit gets a
fake prober, and the real socket code is only pointed at listeners on 127.0.0.1."""

import io
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import time
import types
import unittest
import unittest.mock
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src import audit  # noqa: E402
from src import forensics  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))
_REAL_INTERFACE_ADDRESSES = audit._interface_addresses
NET = '10.77.0.0/24'
IFACES = [('eth-test', '10.77.0.5/24')]


class FakeConfig:
    """Just the audit section, fast by default so tests do not wait on rate limits."""

    def __init__(self, **values):
        self.values = {'enabled': True, 'max_rate': 100000, 'host_delay_ms': 0,
                       'gentle_max_rate': 100000, 'gentle_host_delay_ms': 0,
                       'connect_timeout_sec': 0.2}
        self.values.update(values)

    def get(self, *keys, default=None):
        if len(keys) == 2 and keys[0] == 'audit':
            return self.values.get(keys[1], default)
        return default


class FakeProber:
    """
    A pretend LAN. hosts maps ip -> {'ports': {port: banner}, 'mac', 'refuses',
    'arp'}: listed ports are open, others refused (or silently dropped when
    refuses is False). Unlisted addresses do not exist.
    """

    def __init__(self, hosts, arp=True, http=None, tls=None, on_connect=None, delay=0.0):
        self.hosts = hosts
        self.arp = arp
        self.http = http or {}
        self.tls = tls or {}
        self.on_connect = on_connect
        self.delay = delay
        self.lock = threading.Lock()
        self.calls = []
        self.banner_waits = {}
        self.active = 0
        self.max_active = 0
        self.per_host = {}
        self.max_per_host = 0

    def tcp_connect(self, ip, port, timeout, banner_wait=0.0):
        with self.lock:
            self.calls.append(('tcp', ip, port))
            self.banner_waits[(ip, port)] = banner_wait
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.per_host[ip] = self.per_host.get(ip, 0) + 1
            self.max_per_host = max(self.max_per_host, self.per_host[ip])
        try:
            if self.on_connect:
                self.on_connect(self, ip, port)
            if self.delay:
                time.sleep(self.delay)
            host = self.hosts.get(ip)
            if host is None:
                return 'filtered', b''
            ports = host.get('ports', {})
            if port in ports:
                return 'open', (ports[port] if banner_wait else b'')
            return ('closed', b'') if host.get('refuses', True) else ('filtered', b'')
        finally:
            with self.lock:
                self.active -= 1
                self.per_host[ip] -= 1

    def http_probe(self, ip, port, timeout):
        with self.lock:
            self.calls.append(('http', ip, port))
        return self.http.get((ip, port))

    def tls_probe(self, ip, port, timeout, http=False):
        with self.lock:
            self.calls.append(('tls', ip, port))
        return self.tls.get((ip, port), {'error': 'no connection'})

    def arp_sweep(self, ips, *, rate, cancel, tick, timeout=1.0):
        with self.lock:
            self.calls.append(('arp', tuple(ips)))
        if self.arp is not True:
            raise audit.ArpUnavailable(self.arp or 'Npcap is not installed', remaining=list(ips))
        tick(len(ips))
        wanted = set(ips)
        return {ip: {'mac': h.get('mac', '02:00:00:00:00:01'), 'vendor': None}
                for ip, h in self.hosts.items() if ip in wanted and h.get('arp', True)}

    def tcp_calls(self):
        return [c for c in self.calls if c[0] == 'tcp']


class _NoLiveProber:
    def __init__(self, *a, **k):
        raise AssertionError('a test tried to use the real network prober')


def http_result(status=200, server='lighttpd', title=None, redirect_https=False, auth=None):
    return {'status': status, 'server': server, 'title': title,
            'redirect_https': redirect_https, 'auth': auth, 'tls_hint': False}


def make_cert(not_before_days, not_after_days, cn='device.test', signer=None, key=None,
              hash_name='sha256'):
    """A certificate valid from now+not_before_days to now+not_after_days, self-signed
    unless signer=(issuer name, issuer key) is given."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer, issuer_key = signer if signer else (subject, key)
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now + timedelta(days=not_before_days))
            .not_valid_after(now + timedelta(days=not_after_days))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(cn), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),
                critical=False)
            .sign(issuer_key, getattr(hashes, hash_name.upper())()))
    return cert, key


def der(cert):
    from cryptography.hazmat.primitives import serialization
    return cert.public_bytes(serialization.Encoding.DER)


class RunCase(unittest.TestCase):
    """Base for anything that calls run_audit: a scratch store, and no way to reach
    the real network even by mistake."""

    def setUp(self):
        self.store = tempfile.mkdtemp(prefix='ns_audit_')
        self.addCleanup(shutil.rmtree, self.store, True)
        for name, value in (('LiveProber', _NoLiveProber),
                            ('_interface_addresses', lambda: list(IFACES))):
            patcher = unittest.mock.patch.object(audit, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def audit(self, prober, networks=NET, interfaces=IFACES, config=None, **kwargs):
        return audit.run_audit(networks, prober=prober, interfaces=interfaces,
                               config=config or FakeConfig(), store_dir=self.store, **kwargs)

    def host(self, report, ip):
        for rec in report['networks']:
            for h in rec['hosts']:
                if h['ip'] == ip:
                    return h
        return None

    def ids(self, report, ip=None):
        return {(f['id'], f['host'], f['port']) for f in report['findings']
                if ip is None or f['host'] == ip}


# ══════════════════════════════════════════════════════════════════════
# Scope: the core of the feature
# ══════════════════════════════════════════════════════════════════════
class TestScope(RunCase):

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

    def test_one_refused_network_means_nothing_is_scanned(self):
        prober = FakeProber({'10.77.0.10': {'ports': {80: b''}}})
        corp = IFACES + [('corp', '10.0.0.1/8'), ('lo', '127.0.0.1/8')]
        for nets, ifaces in ((['10.77.0.0/24', '8.8.8.0/24'], IFACES),
                             (['10.77.0.0/24', '10.99.0.0/24'], IFACES),
                             (['10.77.0.0/24', '127.0.0.0/8'], corp),
                             (['10.0.0.0/8'], corp)):
            with self.subTest(nets=nets), self.assertRaises(audit.ScopeError):
                self.audit(prober, networks=nets, interfaces=ifaces)
        self.assertEqual(prober.calls, [])

    def test_bad_port_list_means_nothing_is_scanned(self):
        prober = FakeProber({})
        for ports in ('0', '70000', 'http', '1-2000', '90-80'):
            with self.subTest(ports=ports), self.assertRaises(audit.ScopeError):
                self.audit(prober, ports=ports)
        self.assertEqual(prober.calls, [])

    def test_disabled_audit_refuses_until_opted_in(self):
        prober = FakeProber({'10.77.0.10': {'ports': {80: b''}}})
        with self.assertRaises(audit.AuditDisabled):
            self.audit(prober, config=FakeConfig(enabled=False))
        with self.assertRaises(audit.AuditDisabled):
            audit.start_audit(NET, prober=prober, interfaces=IFACES,
                              config=FakeConfig(enabled=False), store_dir=self.store)
        self.assertEqual(prober.calls, [])
        report = self.audit(prober, config=FakeConfig(enabled=False), require_enabled=False)
        self.assertTrue(report['complete'])

    def test_saved_choices_are_revalidated(self):
        cfg = FakeConfig(networks=['10.77.0.0/24', '8.8.8.0/24', 'junk', '10.99.0.0/24'])
        self.assertEqual(audit.saved_networks(cfg), ['10.77.0.0/24'])
        self.assertEqual(audit.saved_networks(FakeConfig()), [])

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

    def test_broadcast_address_is_never_probed(self):
        prober = FakeProber({}, arp='no npcap')
        self.audit(prober, networks='10.77.0.0/29', ports='80')
        probed = {c[1] for c in prober.tcp_calls()}
        self.assertNotIn('10.77.0.0', probed)
        self.assertNotIn('10.77.0.7', probed)
        self.assertIn('10.77.0.6', probed)

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
        # RunCase patches _interface_addresses; this needs the real one, over fake psutil.
        with unittest.mock.patch.object(audit, 'psutil', fake_psutil):
            ifaces = _REAL_INTERFACE_ADDRESSES()
        names = {name for name, _ in ifaces}
        self.assertEqual(names, {'Ethernet', 'Ethernet6'})
        self.assertIn(('Ethernet6', ipaddress.ip_interface('fd12::7/64')), ifaces)
        with self.assertRaises(audit.ScopeError) as ctx:
            audit.validate_network('169.254.0.0/16', ifaces)
        self.assertEqual(ctx.exception.reason, 'not-local')
        audit.validate_network('192.168.50.0/24', ifaces)

    def test_scope_guard_refuses_a_stray_address(self):
        prober = FakeProber({'10.78.0.1': {'ports': {80: b''}}})
        guarded = audit._ScopedProber(prober, [ipaddress.ip_network(NET)])
        for call in (lambda: guarded.tcp_connect('10.78.0.1', 80, 1),
                     lambda: guarded.http_probe('8.8.8.8', 80, 1),
                     lambda: guarded.tls_probe('10.77.1.1', 443, 1),
                     lambda: guarded.arp_sweep(['10.77.0.9', '10.78.0.1'], rate=1,
                                               cancel=threading.Event(), tick=print)):
            with self.assertRaises(audit.ScopeError):
                call()
        self.assertEqual(prober.calls, [])
        self.assertEqual(guarded.tcp_connect('10.77.0.9', 80, 1)[0], 'filtered')

    def test_a_reply_from_outside_the_network_is_never_probed(self):
        """A spoofed or misrouted ARP answer must not widen the scan."""
        class StrayArp(FakeProber):
            def arp_sweep(self, ips, **kw):
                found = super().arp_sweep(ips, **kw)
                found['10.78.0.1'] = {'mac': '02:00:00:00:00:99', 'vendor': None}
                return found
        prober = StrayArp({'10.77.0.10': {'ports': {80: b''}}, '10.78.0.1': {'ports': {80: b''}}})
        report = self.audit(prober, ports='80')
        self.assertIsNone(self.host(report, '10.78.0.1'))
        self.assertNotIn('10.78.0.1', {c[1] for c in prober.tcp_calls()})



# ══════════════════════════════════════════════════════════════════════
# Discovery
# ══════════════════════════════════════════════════════════════════════
class TestDiscovery(RunCase):
    WORLD = {
        '10.77.0.10': {'ports': {22: b'SSH-2.0-OpenSSH_9.6'}, 'mac': '00:11:22:33:44:55'},
        '10.77.0.20': {'ports': {}},                               # up, refuses everything
        '10.77.0.40': {'ports': {8080: b''}, 'refuses': False},    # ignores every ping port
    }

    def test_arp_sweep_when_available(self):
        prober = FakeProber(self.WORLD)
        report = self.audit(prober, ports='22,8080')
        rec = report['networks'][0]
        self.assertEqual(rec['discovery']['method'], 'arp')
        self.assertIsNone(rec['discovery']['arp_unavailable'])
        self.assertEqual({h['ip'] for h in rec['hosts']},
                         {'10.77.0.5', '10.77.0.10', '10.77.0.20', '10.77.0.40'})
        self.assertEqual(self.host(report, '10.77.0.10')['mac'], '00:11:22:33:44:55')
        self.assertEqual(self.host(report, '10.77.0.40')['open_ports'], [8080])
        arp = [c for c in prober.calls if c[0] == 'arp']
        self.assertEqual(len(arp[0][1]), 253)                  # 254 hosts minus this computer
        self.assertNotIn('10.77.0.5', arp[0][1])

    def test_tcp_ping_fallback_is_reported(self):
        prober = FakeProber(self.WORLD, arp='needs administrator rights')
        report = self.audit(prober, ports='22,8080')
        rec = report['networks'][0]
        self.assertEqual(rec['discovery']['method'], 'tcp-connect')
        self.assertEqual(rec['discovery']['arp_unavailable'], 'needs administrator rights')
        self.assertTrue(any('TCP connect ping' in n for n in rec['notes']))
        ips = {h['ip'] for h in rec['hosts']}
        # A refused connect proves the host is up...
        self.assertIn('10.77.0.20', ips)
        self.assertEqual(self.host(report, '10.77.0.20')['found_by'], 'tcp-connect')
        # ...but a host that drops every ping port is invisible without ARP.
        self.assertNotIn('10.77.0.40', ips)
        ping_ports = {c[2] for c in prober.tcp_calls() if c[1] == '10.77.0.99'}
        self.assertEqual(ping_ports, set(audit.DISCOVERY_PORTS))

    def test_tcp_ping_stops_at_the_first_answer(self):
        prober = FakeProber(self.WORLD, arp='no')
        self.audit(prober, ports='22')
        first = audit.DISCOVERY_PORTS[0]
        ping_calls = [c for c in prober.tcp_calls() if c[1] == '10.77.0.20' and c[2] != 22]
        self.assertEqual(ping_calls, [('tcp', '10.77.0.20', first)])

    def test_off_link_part_of_a_network_is_tcp_pinged(self):
        world = {'10.77.0.10': {'ports': {22: b''}}, '10.77.1.10': {'ports': {22: b''}}}
        prober = FakeProber(world)
        report = self.audit(prober, networks='10.77.0.0/23', ports='22')
        rec = report['networks'][0]
        self.assertEqual(rec['discovery']['method'], 'arp+tcp-connect')
        arp_ips = next(c[1] for c in prober.calls if c[0] == 'arp')
        self.assertTrue(all(ip.startswith('10.77.0.') for ip in arp_ips))
        self.assertEqual(self.host(report, '10.77.1.10')['found_by'], 'tcp-connect')
        self.assertEqual(self.host(report, '10.77.0.10')['found_by'], 'arp')

    def test_this_computer_is_audited_and_marked(self):
        prober = FakeProber({'10.77.0.5': {'ports': {445: b'', 135: b'', 3389: b''}}})
        report = self.audit(prober)
        me = self.host(report, '10.77.0.5')
        self.assertTrue(me['self'])
        self.assertIn('this-computer', me['tags'])
        smb = [f for f in report['findings'] if f['id'] == 'AUDIT-SMB-WORKSTATION']
        self.assertTrue(smb[0]['title'].endswith('(this computer)'))
        self.assertNotIn('10.77.0.5', next(c[1] for c in prober.calls if c[0] == 'arp'))

    def test_gentle_mode_pings_fewer_ports(self):
        prober = FakeProber({}, arp='no')
        self.audit(prober, networks='10.77.0.0/29', gentle=True)
        pinged = {c[2] for c in prober.tcp_calls() if c[1] != '10.77.0.5'}
        self.assertEqual(pinged, set(audit.GENTLE_DISCOVERY_PORTS))


# ══════════════════════════════════════════════════════════════════════
# Port scan and rate limits
# ══════════════════════════════════════════════════════════════════════
class TestPortScan(RunCase):

    def test_default_and_gentle_port_lists(self):
        self.assertTrue(30 <= len(audit.TOP_PORTS) <= 100, len(audit.TOP_PORTS))
        self.assertLess(len(audit.GENTLE_PORTS), len(audit.TOP_PORTS) / 3)
        self.assertEqual(len(set(audit.TOP_PORTS)), len(audit.TOP_PORTS))
        for must in (21, 23, 80, 135, 139, 445, 1900, 3389, 5000, 5900, 5985, 5986, 8080, 8443):
            self.assertIn(must, audit.TOP_PORTS)
        world = {'10.77.0.10': {'ports': {}}}
        normal = FakeProber(world)
        rec = self.audit(normal)['networks'][0]
        self.assertEqual(rec['ports'], list(audit.TOP_PORTS))
        self.assertEqual({c[2] for c in normal.tcp_calls() if c[1] == '10.77.0.10'},
                         set(audit.TOP_PORTS))
        gentle = FakeProber(world)
        rec = self.audit(gentle, gentle=True)['networks'][0]
        self.assertEqual(rec['mode'], 'gentle')
        self.assertEqual({c[2] for c in gentle.tcp_calls() if c[1] == '10.77.0.10'},
                         set(audit.GENTLE_PORTS))

    def test_custom_port_list(self):
        prober = FakeProber({'10.77.0.10': {'ports': {22: b'', 8000: b''}}})
        report = self.audit(prober, ports='22,7999-8001')
        self.assertEqual({c[2] for c in prober.tcp_calls()}, {22, 7999, 8000, 8001})
        self.assertEqual(self.host(report, '10.77.0.10')['open_ports'], [22, 8000])

    def test_gentle_networks_are_always_gentle(self):
        prober = FakeProber({'10.77.0.10': {'ports': {}}})
        rec = self.audit(prober, config=FakeConfig(gentle_networks=['10.77.0.0/16']))['networks'][0]
        self.assertEqual(rec['mode'], 'gentle')
        self.assertEqual(rec['ports'], list(audit.GENTLE_PORTS))

    def test_banner_is_read_only_where_the_server_speaks_first(self):
        prober = FakeProber({'10.77.0.10': {'ports': {
            23: b'\xff\xfb\x01\xff\xfb\x03Debian GNU/Linux\r\nlogin: \x1b[31m',
            80: b'should never be read'}}})
        report = self.audit(prober, ports='23,80')
        svc = {s['port']: s for s in self.host(report, '10.77.0.10')['services']}
        self.assertEqual(svc[23]['banner'], 'Debian GNU/Linux login: [31m')
        self.assertNotIn('banner', svc[80])
        self.assertGreater(prober.banner_waits[('10.77.0.10', 23)], 0)
        self.assertEqual(prober.banner_waits[('10.77.0.10', 80)], 0)

    def test_concurrency_is_capped(self):
        world = {f'10.77.0.{i}': {'ports': {}} for i in range(10, 20)}
        prober = FakeProber(world, delay=0.01)
        self.audit(prober, ports='1-12', config=FakeConfig(concurrency=3))
        self.assertLessEqual(prober.max_active, 3)
        self.assertGreaterEqual(prober.max_active, 2)

    def test_gentle_mode_opens_one_connection_per_host_at_a_time(self):
        prober = FakeProber({'10.77.0.10': {'ports': {}}}, delay=0.01)
        self.audit(prober, gentle=True, config=FakeConfig(gentle_concurrency=6))
        self.assertEqual(prober.max_per_host, 1)

    def test_rate_limiter_spaces_attempts(self):
        clock = {'t': 100.0}
        waits = []

        def wait(seconds, cancel):
            waits.append(seconds)
            clock['t'] += seconds
            return False

        overall = audit.RateLimiter(10, 0, clock=lambda: clock['t'], wait=wait)
        for i in range(5):
            self.assertTrue(overall.acquire(f'h{i}'))
        self.assertAlmostEqual(clock['t'], 100.4)   # 10/s: five attempts span 0.4 s

        clock['t'] = 0.0
        per_host = audit.RateLimiter(1000, 0.5, clock=lambda: clock['t'], wait=wait)
        for _ in range(3):
            per_host.acquire('same')
        self.assertAlmostEqual(clock['t'], 1.0)     # 0, 0.5, 1.0
        per_host.acquire('other')                    # a different host is not held up
        self.assertAlmostEqual(clock['t'], 1.001, places=3)

    def test_rate_limiter_wakes_on_cancel(self):
        limiter = audit.RateLimiter(0.1, 0)          # one attempt per 10 s
        cancel = threading.Event()
        self.assertTrue(limiter.acquire('h', cancel))
        threading.Timer(0.05, cancel.set).start()
        started = time.monotonic()
        self.assertFalse(limiter.acquire('h2', cancel))
        self.assertLess(time.monotonic() - started, 2)

    def test_real_rates_are_read_from_config(self):
        cfg = FakeConfig(concurrency=7, max_rate=50, host_delay_ms=40, gentle_concurrency=1,
                         gentle_max_rate=2, gentle_host_delay_ms=900, connect_timeout_sec=1.5)
        self.assertEqual(audit._settings(cfg, False), {
            'concurrency': 7, 'max_rate': 50, 'host_delay_ms': 40, 'connect_timeout_sec': 1.5})
        self.assertEqual(audit._settings(cfg, True), {
            'concurrency': 1, 'max_rate': 2, 'host_delay_ms': 900, 'connect_timeout_sec': 1.5})
        silly = FakeConfig(concurrency=-5, max_rate='fast', connect_timeout_sec=999)
        s = audit._settings(silly, False)
        self.assertEqual((s['concurrency'], s['max_rate'], s['connect_timeout_sec']), (1, 200, 10))


# ══════════════════════════════════════════════════════════════════════
# Risky services
# ══════════════════════════════════════════════════════════════════════
class TestFindings(RunCase):

    def run_world(self, world, http=None, tls=None, **kwargs):
        return self.audit(FakeProber(world, http=http, tls=tls), **kwargs)

    def test_each_finding_has_severity_why_and_fix(self):
        world = {'10.77.0.10': {'ports': {p: b'' for p in (21, 23, 135, 139, 1900, 2375, 3306,
                                                           3389, 5900, 5985, 5986, 6379, 502)}}}
        report = self.run_world(world)
        self.assertTrue(report['findings'])
        for f in report['findings']:
            with self.subTest(finding=f['id'], port=f['port']):
                self.assertIn(f['severity'], audit.SEVERITIES)
                self.assertGreater(len(f['why']), 40)
                self.assertGreater(len(f['fix']), 20)
                self.assertEqual(f['network'], NET)
        by_port = {f['port']: f for f in report['findings'] if f['host'] == '10.77.0.10'}
        expect = {21: ('AUDIT-FTP', 'HIGH'), 23: ('AUDIT-TELNET', 'HIGH'),
                  135: ('AUDIT-RPC', 'LOW'), 139: ('AUDIT-NETBIOS', 'LOW'),
                  1900: ('AUDIT-UPNP', 'MEDIUM'), 2375: ('AUDIT-DOCKER-API', 'CRITICAL'),
                  3306: ('AUDIT-DATABASE', 'MEDIUM'), 3389: ('AUDIT-RDP', 'MEDIUM'),
                  5900: ('AUDIT-VNC', 'HIGH'), 5985: ('AUDIT-WINRM', 'MEDIUM'),
                  5986: ('AUDIT-WINRM', 'LOW'), 6379: ('AUDIT-DATABASE', 'HIGH'),
                  502: ('AUDIT-OT-PROTOCOL', 'HIGH')}
        for port, (fid, sev) in expect.items():
            with self.subTest(port=port):
                self.assertEqual((by_port[port]['id'], by_port[port]['severity']), (fid, sev))
        ranks = [audit.SEVERITIES.index(f['severity']) for f in report['findings']]
        self.assertEqual(ranks, sorted(ranks))

    def test_advice_reuses_forensics_where_it_has_an_entry(self):
        for port in (21, 23, 445, 5900, 6379):
            why, fix = audit._advice(port)
            self.assertEqual(why, forensics.PROTOCOL_EXPLOITATION[port]['how_exploited'])
            self.assertEqual(fix, forensics.PROTOCOL_EXPLOITATION[port]['how_to_fix'])
        # RDP, SSDP/UPnP, WinRM and RPC/NetBIOS have no forensics entry: ours.
        for port in (3389, 1900, 5985, 5986, 135, 139):
            self.assertNotIn(port, forensics.PROTOCOL_EXPLOITATION)
            why, fix = audit._advice(port)
            self.assertNotEqual(why, forensics.DEFAULT_EXPLOITATION['how_exploited'])
            self.assertIn('1.', fix)

    def test_smb_depends_on_what_the_host_looks_like(self):
        world = {
            '10.77.0.10': {'ports': {445: b'', 135: b'', 3389: b''}},           # workstation
            '10.77.0.11': {'ports': {445: b'', 135: b'', 88: b'', 389: b'', 53: b''}},  # DC
            '10.77.0.12': {'ports': {445: b'', 548: b''}},                       # NAS
            '10.77.0.13': {'ports': {445: b''}},                                 # no idea
        }
        report = self.run_world(world)
        ws = [f for f in report['findings'] if f['host'] == '10.77.0.10' and 'SMB' in f['id']]
        self.assertEqual([(f['id'], f['severity']) for f in ws], [('AUDIT-SMB-WORKSTATION', 'MEDIUM')])
        self.assertIn('WannaCry', ws[0]['why'])
        self.assertEqual(ws[0]['evidence']['smb_ports'], [445])
        self.assertEqual(self.ids(report, '10.77.0.11'), set())   # SMB and RPC are a DC's job
        self.assertEqual(self.host(report, '10.77.0.11')['role'], 'domain-controller')
        self.assertEqual(self.ids(report, '10.77.0.12'), set())
        self.assertEqual({(f['id'], f['severity']) for f in report['findings']
                          if f['host'] == '10.77.0.13'}, {('AUDIT-SMB', 'LOW')})

    def test_admin_page_without_tls(self):
        world = {'10.77.0.10': {'ports': {80: b'', 8080: b'', 8000: b'', 9000: b''}}}
        http = {
            ('10.77.0.10', 80): http_result(title='Router Login'),
            ('10.77.0.10', 8080): http_result(status=401, title='401 Unauthorized', auth='basic'),
            ('10.77.0.10', 8000): http_result(status=301, title='Login', redirect_https=True),
            ('10.77.0.10', 9000): http_result(title='Welcome to nginx!', server='nginx'),
        }
        report = self.run_world(world, http=http)
        admin = {f['port']: f for f in report['findings'] if f['id'] == 'AUDIT-ADMIN-UI-HTTP'}
        self.assertEqual(set(admin), {80, 8080})
        self.assertEqual(admin[80]['severity'], 'MEDIUM')
        self.assertEqual(admin[8080]['severity'], 'HIGH')
        self.assertIn('Basic', admin[8080]['title'])
        self.assertEqual(admin[80]['evidence']['title'], 'Router Login')
        self.assertIn('admin-ui', self.host(report, '10.77.0.10')['tags'])

    def test_upnp_on_5000_is_recognised_by_its_server_header(self):
        world = {'10.77.0.10': {'ports': {5000: b''}}, '10.77.0.11': {'ports': {5000: b''}}}
        http = {('10.77.0.10', 5000): http_result(status=404, server='Linux/4.1 UPnP/1.0 miniupnpd/2.1'),
                ('10.77.0.11', 5000): http_result(status=403, server='AirTunes/620.8.2')}
        report = self.run_world(world, http=http)
        self.assertIn(('AUDIT-UPNP', '10.77.0.10', 5000), self.ids(report))
        self.assertEqual(self.ids(report, '10.77.0.11'), set())

    def test_tls_on_an_http_port_is_retried_as_tls(self):
        world = {'10.77.0.10': {'ports': {9090: b''}}}
        cert, _ = make_cert(-10, 300, cn='cockpit.test')
        http = {('10.77.0.10', 9090): {'status': None, 'tls_hint': True}}
        tls = {('10.77.0.10', 9090): {'cert_der': der(cert), 'tls_version': 'TLSv1.3',
                                       'http': http_result(title='Cockpit')}}
        prober = FakeProber(world, http=http, tls=tls)
        report = self.audit(prober)
        svc = self.host(report, '10.77.0.10')['services'][0]
        self.assertEqual(svc['tls']['cert']['subject'], 'cockpit.test')
        self.assertEqual(svc['http']['title'], 'Cockpit')
        self.assertNotIn(('AUDIT-ADMIN-UI-HTTP', '10.77.0.10', 9090), self.ids(report))
        self.assertIn(('tls', '10.77.0.10', 9090), prober.calls)

    def test_controllers_suggest_gentle_mode(self):
        world = {'10.77.0.10': {'ports': {80: b'', 1911: b''}},
                 '10.77.0.11': {'ports': {80: b''}}}
        http = {('10.77.0.11', 80): http_result(title='Niagara Web Login', server='Niagara Web Server/4.10')}
        report = self.run_world(world, http=http)
        rec = report['networks'][0]
        for ip in ('10.77.0.10', '10.77.0.11'):
            self.assertIn('building-controls', self.host(report, ip)['tags'])
            self.assertTrue(any(ip in n and 'gentle' in n for n in rec['notes']))
        self.assertIn(('AUDIT-NIAGARA-FOX', '10.77.0.10', 1911), self.ids(report))
        gentle = self.run_world(world, http=http, gentle=True)
        self.assertFalse(any('gentle mode next time' in n for n in gentle['networks'][0]['notes']))

    def test_old_tls_and_certificate_problems(self):
        expired, _ = make_cert(-400, -10)
        expiring, _ = make_cert(-300, 10)
        world = {'10.77.0.10': {'ports': {443: b'', 8443: b'', 993: b''}}}
        tls = {('10.77.0.10', 443): {'cert_der': der(expired), 'tls_version': 'TLSv1.3'},
               ('10.77.0.10', 8443): {'cert_der': der(expiring), 'tls_version': 'TLSv1'},
               ('10.77.0.10', 993): {'error': 'TLS handshake failed: SSLError'}}
        report = self.run_world(world, tls=tls)
        ids = self.ids(report)
        for item in (('AUDIT-CERT-EXPIRED', 443), ('AUDIT-CERT-SELF-SIGNED', 443),
                     ('AUDIT-CERT-EXPIRING', 8443), ('AUDIT-TLS-OLD', 8443)):
            self.assertIn((item[0], '10.77.0.10', item[1]), ids)
        self.assertNotIn(('AUDIT-CERT-EXPIRING', '10.77.0.10', 443), ids)
        svc = {s['port']: s for s in self.host(report, '10.77.0.10')['services']}
        self.assertEqual(svc[993]['tls'], {'error': 'TLS handshake failed: SSLError'})
        self.assertNotIn('cert_der', json.dumps(report))
        json.dumps(report)  # the whole report must be JSON-safe


# ══════════════════════════════════════════════════════════════════════
# The real socket code, on loopback only
# ══════════════════════════════════════════════════════════════════════
class Listener:
    """A one-thread TCP server on 127.0.0.1 that records what clients send."""

    def __init__(self, handler, tls_context=None):
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(5)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.handler = handler
        self.tls = tls_context
        self.received = []
        self.accepted = 0
        self.errors = []
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            self.accepted += 1
            conn.settimeout(3)
            try:
                if self.tls is not None:
                    conn = self.tls.wrap_socket(conn, server_side=True)
                self.handler(self, conn)
            except (OSError, ssl.SSLError) as exc:
                self.errors.append(exc)
            finally:
                conn.close()

    def read_request(self, conn):
        data = b''
        while b'\r\n\r\n' not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        self.received.append(data)
        return data

    def close(self):
        self._stop.set()
        self.thread.join(2)
        self.sock.close()


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestLoopbackProber(unittest.TestCase):

    def listen(self, handler, tls_context=None):
        listener = Listener(handler, tls_context)
        self.addCleanup(listener.close)
        return listener

    def test_connect_reads_a_banner_and_sends_nothing(self):
        def handler(server, conn):
            conn.sendall(b'SSH-2.0-OpenSSH_9.6 test\r\n')
            server.received.append(conn.recv(100))   # b'' once the client closes

        server = self.listen(handler)
        state, banner = audit.LiveProber().tcp_connect('127.0.0.1', server.port, 2.0, banner_wait=2.0)
        self.assertEqual((state, banner), ('open', b'SSH-2.0-OpenSSH_9.6 test\r\n'))
        deadline = time.monotonic() + 3
        while not server.received and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(server.received, [b''])

    def test_closed_port_is_reported_closed_at_once(self):
        """Windows retries a refused SYN for two seconds; without turning that off
        every closed port read as filtered and TCP-ping discovery missed hosts."""
        port = free_port()
        started = time.monotonic()
        state, _ = audit.LiveProber().tcp_connect('127.0.0.1', port, 3.0)
        self.assertEqual(state, 'closed')
        self.assertLess(time.monotonic() - started, 1.0)

    def test_http_probe_sends_one_plain_get_and_reads_the_title(self):
        def handler(server, conn):
            server.read_request(conn)
            conn.sendall(b'HTTP/1.1 302 Found\r\nServer: GoAhead-Webs\r\n'
                         b'Location: http://10.255.255.1/login\r\nContent-Type: text/html\r\n\r\n'
                         b'<html><head><TITLE>\r\n  Gateway &amp; Router\x1b]0;x\x07 '
                         b'</TITLE></head>')

        server = self.listen(handler)
        result = audit.LiveProber().http_probe('127.0.0.1', server.port, 2.0)
        self.assertEqual(result['status'], 302)
        self.assertEqual(result['server'], 'GoAhead-Webs')
        self.assertEqual(result['title'], 'Gateway & Router ]0;x')
        self.assertFalse(result['redirect_https'])
        time.sleep(0.3)
        self.assertEqual(server.accepted, 1)          # the redirect was not followed
        request = server.received[0]
        self.assertTrue(request.startswith(b'GET / HTTP/1.1\r\n'), request)
        lowered = request.lower()
        for forbidden in (b'authorization', b'cookie', b'password', b'?'):
            self.assertNotIn(forbidden, lowered)
        self.assertIn(b'connection: close', lowered)

    def test_http_probe_on_something_that_is_not_http(self):
        def handler(server, conn):
            server.read_request(conn)
            conn.sendall(b'\x15\x03\x01\x00\x02\x02\x46')   # a TLS alert

        server = self.listen(handler)
        result = audit.LiveProber().http_probe('127.0.0.1', server.port, 2.0)
        self.assertEqual(result, {'status': None, 'tls_hint': True})
        self.assertIsNone(audit.LiveProber().http_probe('127.0.0.1', free_port(), 1.0))

    def tls_server(self, cert, key):
        from cryptography.hazmat.primitives import serialization
        tmp = tempfile.mkdtemp(prefix='ns_audit_tls_')
        self.addCleanup(shutil.rmtree, tmp, True)
        certfile, keyfile = os.path.join(tmp, 'c.pem'), os.path.join(tmp, 'k.pem')
        with open(certfile, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(keyfile, 'wb') as f:
            f.write(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        return ctx

    def test_expired_self_signed_certificate_over_real_tls(self):
        cert, key = make_cert(-400, -3, cn='bms-controller.test')

        def handler(server, conn):
            server.read_request(conn)
            conn.sendall(b'HTTP/1.1 200 OK\r\nServer: Jetty\r\n\r\n<title>Building Login</title>')

        server = self.listen(handler, self.tls_server(cert, key))
        result = audit.LiveProber().tls_probe('127.0.0.1', server.port, 3.0, http=True)
        self.assertNotIn('error', result)
        self.assertEqual(result['cert_der'], der(cert))
        self.assertIn(result['tls_version'], ('TLSv1.2', 'TLSv1.3'))
        self.assertEqual(result['http']['title'], 'Building Login')
        self.assertTrue(server.received[0].startswith(b'GET / HTTP/1.1\r\nHost: 127.0.0.1:'))

        info = audit.parse_certificate(result['cert_der'])
        self.assertTrue(info['expired'])
        self.assertTrue(info['self_signed'])
        self.assertFalse(info['expiring'])
        self.assertEqual(info['days_left'], -3)
        self.assertEqual(info['subject'], 'bms-controller.test')
        self.assertIn('127.0.0.1', info['sans'])
        self.assertEqual(info['key'], 'EC secp256r1 256')

        host = {'ip': '10.77.0.10', 'self': False, 'role': 'unknown', 'services': [
            {'port': 443, 'tls': {'version': result['tls_version'], 'cert': info},
             'http': result['http']}]}
        ids = {f['id'] for f in audit._host_findings(host, 30)}
        self.assertEqual(ids, {'AUDIT-CERT-EXPIRED', 'AUDIT-CERT-SELF-SIGNED'})

    def test_tls_probe_without_http_and_against_plain_tcp(self):
        cert, key = make_cert(-1, 200)
        server = self.listen(lambda s, c: None, self.tls_server(cert, key))
        result = audit.LiveProber().tls_probe('127.0.0.1', server.port, 3.0)
        self.assertEqual(result['cert_der'], der(cert))
        self.assertNotIn('http', result)

        plain = self.listen(lambda s, c: c.sendall(b'220 not tls\r\n'))
        result = audit.LiveProber().tls_probe('127.0.0.1', plain.port, 2.0)
        self.assertIn('error', result)
        self.assertEqual(audit.LiveProber().tls_probe('127.0.0.1', free_port(), 1.0),
                         {'error': 'no connection'})


class TestArpSweep(unittest.TestCase):
    """LiveProber.arp_sweep against a stand-in for scapy.all: no packets leave."""

    def fake_scapy(self, answers, fail_on_call=None, use_pcap=True, on_call=None):
        calls = []

        def srp(pkt, iface=None, timeout=None, inter=None, retry=None, verbose=None):
            calls.append({'pdst': list(pkt.pdst), 'iface': iface, 'inter': inter})
            if on_call:
                on_call(len(calls))
            if fail_on_call == len(calls):
                raise PermissionError('denied')
            asked = set(pkt.pdst) | {'10.77.9.9'}       # plus one reply nobody asked for
            replies = [(None, types.SimpleNamespace(psrc=ip, hwsrc=mac.upper()))
                       for ip, mac in answers.items() if ip in asked]
            return replies, []

        class Ether:
            def __init__(self, dst):
                self.dst = dst

            def __truediv__(self, arp):
                return arp

        module = types.SimpleNamespace(
            ARP=lambda pdst: types.SimpleNamespace(pdst=pdst), Ether=Ether, srp=srp,
            conf=types.SimpleNamespace(
                use_pcap=use_pcap,
                route=types.SimpleNamespace(route=lambda ip: ('eth-test', '10.77.0.5', '0.0.0.0')),
                manufdb=types.SimpleNamespace(
                    _get_manuf=lambda mac: 'Tridium' if mac.startswith('00:01:f0') else mac)))
        return module, calls

    def sweep(self, module, ips, cancel=None, rate=100):
        ticks = []
        with unittest.mock.patch.dict(sys.modules, {'scapy.all': module}):
            found = audit.LiveProber().arp_sweep(ips, rate=rate, cancel=cancel or threading.Event(),
                                                 tick=ticks.append, timeout=0.01)
        return found, ticks

    def test_chunks_rate_vendor_and_stray_replies(self):
        ips = [f'10.77.{i // 250}.{i % 250 + 1}' for i in range(600)]
        answers = {ips[3]: '00:01:F0:AA:BB:CC', ips[400]: '02:00:00:00:00:02',
                   '10.77.9.9': '02:00:00:00:00:99'}
        module, calls = self.fake_scapy(answers)
        found, ticks = self.sweep(module, ips, rate=200)
        self.assertEqual(ticks, [256, 256, 88])
        self.assertEqual([len(c['pdst']) for c in calls], [256, 256, 88])
        self.assertTrue(all(c['inter'] == 1 / 200 and c['iface'] == 'eth-test' for c in calls))
        self.assertEqual(found, {ips[3]: {'mac': '00:01:f0:aa:bb:cc', 'vendor': 'Tridium'},
                                 ips[400]: {'mac': '02:00:00:00:00:02', 'vendor': None}})

    def test_failure_part_way_keeps_what_was_found(self):
        ips = [f'10.77.0.{i}' for i in range(1, 255)] + [f'10.77.1.{i}' for i in range(1, 255)]
        module, _ = self.fake_scapy({'10.77.0.7': '02:00:00:00:00:07'}, fail_on_call=2)
        with self.assertRaises(audit.ArpUnavailable) as ctx:
            self.sweep(module, ips)
        self.assertEqual(ctx.exception.reason, 'needs administrator rights')
        self.assertEqual(set(ctx.exception.found), {'10.77.0.7'})
        self.assertEqual(ctx.exception.remaining, ips[256:])

    def test_cancel_between_chunks(self):
        cancel = threading.Event()
        module, calls = self.fake_scapy({}, on_call=lambda n: cancel.set())
        self.sweep(module, [f'10.77.{i // 250}.{i % 250 + 1}' for i in range(600)], cancel=cancel)
        self.assertEqual(len(calls), 1)

    def test_no_npcap(self):
        module, calls = self.fake_scapy({}, use_pcap=False)
        with unittest.mock.patch.object(audit, '_NEEDS_NPCAP', True), \
                self.assertRaises(audit.ArpUnavailable) as ctx:
            self.sweep(module, ['10.77.0.9'])
        self.assertEqual(ctx.exception.reason, 'Npcap is not installed')
        self.assertEqual(ctx.exception.remaining, ['10.77.0.9'])
        self.assertEqual(calls, [])


class TestCertificateParsing(unittest.TestCase):

    def test_expiring_and_ca_issued(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Site Root CA')])
        cert, _ = make_cert(-100, 12, cn='nas.test', signer=(ca_name, ca_key))
        info = audit.parse_certificate(der(cert), warn_days=30)
        self.assertFalse(info['self_signed'])
        self.assertTrue(info['expiring'])
        self.assertFalse(info['expired'])
        self.assertEqual(info['issuer'], 'Site Root CA')
        self.assertIn(info['days_left'], (11, 12))
        self.assertFalse(audit.parse_certificate(der(cert), warn_days=5)['expiring'])

    def test_same_name_different_key_is_not_self_signed(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        other = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'device.test')])
        cert, _ = make_cert(-1, 100, cn='device.test', signer=(name, other))
        self.assertFalse(audit.parse_certificate(der(cert))['self_signed'])

    def test_not_yet_valid_and_weak(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        future, _ = make_cert(5, 100)
        info = audit.parse_certificate(der(future))
        self.assertTrue(info['not_yet_valid'])
        try:
            small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        except ValueError:
            self.skipTest('this cryptography refuses 1024-bit RSA keys')
        weak, _ = make_cert(-1, 100, key=small)
        info = audit.parse_certificate(der(weak))
        self.assertTrue(info['weak'])
        self.assertEqual(info['key'], 'RSA 1024')
        host = {'ip': '10.77.0.10', 'self': False, 'role': 'unknown',
                'services': [{'port': 443, 'tls': {'version': 'TLSv1.2', 'cert': info}}]}
        self.assertIn('AUDIT-CERT-WEAK', {f['id'] for f in audit._host_findings(host, 30)})

    def test_garbage_still_has_a_fingerprint(self):
        info = audit.parse_certificate(b'not a certificate')
        self.assertIn('error', info)
        self.assertEqual(len(info['fingerprint_sha256']), 64)


class TestHttpParsing(unittest.TestCase):

    def test_parse(self):
        p = audit.parse_http_response
        self.assertIsNone(p(b''))
        self.assertEqual(p(b'SSH-2.0-x'), {'status': None, 'tls_hint': False})
        r = p(b'HTTP/1.0 401 Unauthorized\nWWW-Authenticate: Basic realm="admin"\n\n')
        self.assertEqual((r['status'], r['auth']), (401, 'basic'))
        r = p(b'HTTP/1.1 301 Moved\r\nLocation: HTTPS://10.0.0.1/\r\n\r\n')
        self.assertTrue(r['redirect_https'])
        r = p(b'HTTP/1.1 400 Bad Request\r\n\r\n<title>400 The plain HTTP request was sent to '
              b'HTTPS port</title>')
        self.assertTrue(r['tls_hint'])
        r = p(b'HTTP/1.1 200 OK\r\n\r\n<title>' + b'A' * 500 + b'</title>')
        self.assertLessEqual(len(r['title']), 120)
        r = p(b'HTTP/1.1 200 OK\r\nServer: x\xe2\x80\xaey\r\n\r\n<title>\xff\xfe</title>')
        self.assertEqual(r['server'], 'x y')
        self.assertIsNone(r['title'])


# ══════════════════════════════════════════════════════════════════════
# Progress, cancel, and one audit at a time
# ══════════════════════════════════════════════════════════════════════
class TestProgressAndCancel(RunCase):
    WORLD = {f'10.77.0.{i}': {'ports': {22: b'', 443: b''}} for i in range(10, 16)}

    def test_progress_rises_to_one_from_the_calling_thread(self):
        seen = []
        me = threading.get_ident()
        report = self.audit(FakeProber(self.WORLD, delay=0.002),
                            progress=lambda f, m: seen.append((f, m, threading.get_ident())),
                            config=FakeConfig(concurrency=4))
        self.assertTrue(report['complete'])
        fractions = [f for f, _, _ in seen]
        self.assertEqual(fractions, sorted(fractions))
        self.assertTrue(all(0.0 <= f <= 1.0 for f in fractions))
        self.assertEqual(seen[-1][:2], (1.0, 'Done'))
        self.assertEqual({t for _, _, t in seen}, {me})
        messages = ' | '.join(m for _, m, _ in seen)
        self.assertIn('Finding hosts on 10.77.0.0/24', messages)
        self.assertIn('Scanning 7 hosts', messages)

    def test_two_networks_share_the_bar(self):
        seen = []
        ifaces = IFACES + [('eth2', '10.88.0.5/24')]
        self.audit(FakeProber({}), networks=['10.77.0.0/24', '10.88.0.0/24'], interfaces=ifaces,
                   progress=lambda f, m: seen.append((f, m)))
        second = next(f for f, m in seen if '10.88.0.0/24' in m)
        self.assertAlmostEqual(second, 0.5)

    def test_a_broken_progress_callback_does_not_stop_the_audit(self):
        def boom(f, m):
            raise RuntimeError('ui went away')
        self.assertTrue(self.audit(FakeProber(self.WORLD), progress=boom)['complete'])

    def test_cancel_stops_early_and_saves_nothing(self):
        cancel = threading.Event()

        def stop_after(prober, ip, port):
            if len(prober.tcp_calls()) >= 40:
                cancel.set()

        prober = FakeProber(self.WORLD, on_connect=stop_after)
        seen = []
        report = self.audit(prober, cancel=cancel, progress=lambda f, m: seen.append((f, m)))
        self.assertTrue(report['cancelled'])
        self.assertFalse(report['complete'])
        self.assertFalse(report['networks'][0]['complete'])
        self.assertIsNone(report['networks'][0]['saved'])
        total = len(self.WORLD) * len(audit.TOP_PORTS)
        self.assertLess(len(prober.tcp_calls()), total / 2)
        self.assertEqual(seen[-1][1], 'Cancelled')
        self.assertLess(seen[-1][0], 1.0)
        self.assertEqual(os.listdir(self.store), [])
        self.assertIsNone(audit.last_report(NET, self.store))

    def test_job_runs_in_the_background_and_cancels_from_another_thread(self):
        gate = threading.Event()

        def hold(prober, ip, port):
            gate.wait(5)

        prober = FakeProber(self.WORLD, on_connect=hold)
        job = audit.start_audit(NET, prober=prober, interfaces=IFACES, config=FakeConfig(),
                                store_dir=self.store)
        self.assertIs(audit.current_job(), job)
        self.assertEqual(job.status()['state'], 'running')
        deadline = time.monotonic() + 5
        while not audit.is_running() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(audit.is_running())
        with self.assertRaises(audit.AuditBusy):
            self.audit(FakeProber({}))
        with self.assertRaises(audit.AuditBusy):
            audit.start_audit(NET, prober=prober, interfaces=IFACES, config=FakeConfig(),
                              store_dir=self.store)
        job.cancel()            # from this thread, not the job's
        gate.set()
        self.assertTrue(job.wait(10))
        status = job.status()
        self.assertEqual(status['state'], 'cancelled')
        self.assertTrue(job.report['cancelled'])
        self.assertFalse(audit.is_running())

    def test_job_completes_and_reports(self):
        job = audit.start_audit([NET], prober=FakeProber(self.WORLD), interfaces=IFACES,
                                config=FakeConfig(), store_dir=self.store)
        self.assertTrue(job.wait(10))
        status = job.status()
        self.assertEqual((status['state'], status['fraction'], status['error']), ('done', 1.0, None))
        self.assertEqual(job.report['summary']['hosts'], 7)
        with self.assertRaises(audit.ScopeError):
            audit.start_audit('8.8.8.0/24', prober=FakeProber({}), interfaces=IFACES,
                              config=FakeConfig(), store_dir=self.store)


# ══════════════════════════════════════════════════════════════════════
# Saved results and the diff
# ══════════════════════════════════════════════════════════════════════
class TestPersistenceAndDiff(RunCase):

    def test_diff_of_two_records(self):
        def cert(fp):
            return {'tls': {'cert': {'fingerprint_sha256': fp, 'not_after': '2027-01-01T00:00:00Z'}}}
        old = {'network': NET, 'started': 't1', 'ports': [22, 80, 443],
               'discovery': {'method': 'arp'},
               'hosts': [{'ip': '10.77.0.10', 'open_ports': [22, 443],
                          'services': [{'port': 22}, dict(port=443, **cert('aa'))]},
                         {'ip': '10.77.0.11', 'open_ports': [80], 'services': [{'port': 80}]}],
               'findings': [{'id': 'AUDIT-OLD', 'host': '10.77.0.10', 'port': 22}]}
        new = {'network': NET, 'started': 't2', 'ports': [22, 23, 80, 443],
               'discovery': {'method': 'arp'},
               'hosts': [{'ip': '10.77.0.10', 'open_ports': [23, 80, 443],
                          'services': [{'port': 23}, {'port': 80}, dict(port=443, **cert('bb'))]},
                         {'ip': '10.77.0.12', 'mac': 'aa:bb:cc:00:00:01', 'open_ports': [22],
                          'services': [{'port': 22}]}],
               'findings': [{'id': 'AUDIT-TELNET', 'host': '10.77.0.10', 'port': 23}]}
        d = audit.diff(old, new)
        self.assertTrue(d['changed'])
        self.assertEqual((d['previous'], d['current']), ('t1', 't2'))
        self.assertEqual(d['new_hosts'], [{'ip': '10.77.0.12', 'mac': 'aa:bb:cc:00:00:01',
                                           'open_ports': [22]}])
        self.assertEqual([h['ip'] for h in d['gone_hosts']], ['10.77.0.11'])
        # 23 was not scanned last time, so it is not "newly opened".
        self.assertEqual([(p['host'], p['port']) for p in d['opened']], [('10.77.0.10', 80)])
        self.assertEqual([(p['host'], p['port']) for p in d['closed']], [('10.77.0.10', 22)])
        self.assertEqual(d['cert_changes'], [{
            'host': '10.77.0.10', 'port': 443, 'change': 'replaced', 'old_fingerprint': 'aa',
            'new_fingerprint': 'bb', 'old_not_after': '2027-01-01T00:00:00Z',
            'new_not_after': '2027-01-01T00:00:00Z'}])
        self.assertEqual([f['id'] for f in d['new_findings']], ['AUDIT-TELNET'])
        self.assertEqual([f['id'] for f in d['resolved_findings']], ['AUDIT-OLD'])
        self.assertFalse(d['discovery_changed'])
        same = audit.diff(new, new)
        self.assertFalse(same['changed'])
        self.assertIsNone(audit.diff(None, new))
        whole = audit.diff({'networks': [old]}, {'networks': [new]})
        self.assertEqual(whole['networks'][0]['opened'], d['opened'])

    def test_second_audit_shows_what_changed(self):
        world = {'10.77.0.10': {'ports': {22: b''}}}
        first = self.audit(FakeProber(world))
        rec = first['networks'][0]
        self.assertTrue(rec['first_audit'])
        self.assertIsNone(rec['diff'])
        self.assertTrue(os.path.isfile(rec['saved']))
        with open(rec['saved'], encoding='utf-8') as f:
            saved = json.load(f)
        self.assertNotIn('diff', saved)
        self.assertEqual(saved['network'], NET)

        world = {'10.77.0.10': {'ports': {22: b'', 23: b''}}, '10.77.0.11': {'ports': {80: b''}}}
        second = self.audit(FakeProber(world))
        d = second['networks'][0]['diff']
        self.assertFalse(second['networks'][0]['first_audit'])
        self.assertEqual([h['ip'] for h in d['new_hosts']], ['10.77.0.11'])
        self.assertEqual([(p['host'], p['port'], p['service']) for p in d['opened']],
                         [('10.77.0.10', 23, 'Telnet')])
        self.assertIn('AUDIT-TELNET', {f['id'] for f in d['new_findings']})
        self.assertEqual(second['summary']['new_hosts'], 1)
        self.assertEqual(second['summary']['opened_ports'], 1)
        self.assertEqual(audit.last_report(NET, self.store)['started'],
                         second['networks'][0]['started'])
        self.assertEqual(audit.last_report('10.77.0.99/24', self.store)['network'], NET)
        self.assertIsNone(audit.last_report('10.66.0.0/24', self.store))
        self.assertIsNone(audit.last_report('nonsense', self.store))

    def test_gentle_after_normal_does_not_report_everything_closed(self):
        world = {'10.77.0.10': {'ports': {22: b'', 3306: b''}}}
        self.audit(FakeProber(world))
        d = self.audit(FakeProber(world), gentle=True)['networks'][0]['diff']
        self.assertEqual(d['closed'], [])
        self.assertEqual(d['resolved_findings'], [])

    def test_old_audits_are_pruned_and_damage_is_skipped(self):
        cfg = FakeConfig(keep_reports=2)
        for i in range(3):
            self.audit(FakeProber({f'10.77.0.{10 + i}': {'ports': {}}}), config=cfg)
        files = sorted(os.listdir(self.store))
        self.assertEqual(len(files), 2)
        self.assertTrue(all(f.startswith('10.77.0.0_24__') for f in files))
        with open(os.path.join(self.store, files[-1]), 'w', encoding='utf-8') as f:
            f.write('{"truncated": ')
        rec = audit.last_report(NET, self.store)
        self.assertIn('10.77.0.11', {h['ip'] for h in rec['hosts']})

    def test_saved_under_the_data_directory_by_default(self):
        from src import config
        self.assertEqual(audit._store_dir(), os.path.join(config.DB_DIR, 'audit'))
        self.assertTrue(audit._store_dir().startswith(_test_support.TEST_HOME))

    def test_no_save_still_diffs(self):
        world = {'10.77.0.10': {'ports': {22: b''}}}
        self.audit(FakeProber(world))
        report = self.audit(FakeProber(world), save=False)
        self.assertIsNone(report['networks'][0]['saved'])
        self.assertFalse(report['networks'][0]['diff']['changed'])
        self.assertEqual(len(os.listdir(self.store)), 1)


# ══════════════════════════════════════════════════════════════════════
# Interfaces offered to the UI
# ══════════════════════════════════════════════════════════════════════
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


# ══════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════
class TestCli(RunCase):

    def cli(self, *argv, prober=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = audit.main(list(argv), prober=prober or FakeProber({}), interfaces=IFACES,
                              config=FakeConfig(enabled=False), store_dir=self.store)
        return code, out.getvalue(), err.getvalue()

    def test_json_report(self):
        world = {'10.77.0.10': {'ports': {23: b'login:'}}}
        code, out, err = self.cli('--network', NET, '--json', prober=FakeProber(world))
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertEqual(report['networks'][0]['network'], NET)
        self.assertIn('AUDIT-TELNET', {f['id'] for f in report['findings']})
        self.assertIn('Finding hosts', err)

    def test_text_report_is_plain_ascii(self):
        world = {'10.77.0.10': {'ports': {23: 'login: ☃'.encode('utf-8'), 6379: b''}}}
        code, out, _ = self.cli('-n', NET, '--gentle', '--ports', '23,6379', '-v',
                                prober=FakeProber(world))
        self.assertEqual(code, 0)
        out.encode('ascii')
        self.assertIn('gentle mode', out)
        self.assertIn('HIGH     10.77.0.10:23', out)
        self.assertIn('why:', out)
        self.assertIn('First audit of this network', out)
        code, out, _ = self.cli('-n', NET, '--ports', '23,6379', prober=FakeProber(world))
        self.assertIn('No changes since', out)

    def test_refusals_exit_2_and_send_nothing(self):
        prober = FakeProber({})
        for argv in (['--network', '8.8.8.0/24'], ['--network', '10.0.0.0/8'],
                     ['--network', '127.0.0.1'], ['--network', '10.99.0.0/24'],
                     ['--network', NET, '--ports', '0-99999']):
            with self.subTest(argv=argv):
                code, out, err = self.cli(*argv, prober=prober)
                self.assertEqual(code, 2)
                self.assertIn('audit:', err)
        self.assertEqual(prober.calls, [])
        with self.assertRaises(SystemExit) as ctx:
            self.cli()
        self.assertEqual(ctx.exception.code, 2)

    def test_list(self):
        code, out, _ = self.cli('--list')
        self.assertEqual(code, 0)
        self.assertIn('10.77.0.0/24', out)
        code, out, _ = self.cli('--list', '--json')
        self.assertEqual(json.loads(out)[0]['network'], '10.77.0.0/24')

    def test_module_runs_as_a_script(self):
        import subprocess
        env = dict(os.environ, PYTHONIOENCODING='utf-8')
        proc = subprocess.run([sys.executable, '-m', 'src.audit', '--network', '8.8.8.0/24'],
                              cwd=ROOT, env=env, capture_output=True, text=True,
                              encoding='utf-8', timeout=120)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn('not a private network', proc.stderr)


# ══════════════════════════════════════════════════════════════════════
# What the module may send, and the config keys it reads
# ══════════════════════════════════════════════════════════════════════
class TestSource(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, 'src', 'audit.py'), encoding='utf-8') as f:
            cls.source = f.read()

    def test_the_only_bytes_sent_are_one_get(self):
        """No logins, default-password checks or exploit probes: the one payload the
        module ever writes to a socket is the GET / request."""
        self.assertEqual(self.source.count('sendall('), 1)
        for call in ('.send(', 'sendto(', 'sendmsg(', 'makefile('):
            self.assertNotIn(call, self.source)
        request = re.search(r"request = \((.*?)\)\.encode", self.source, re.S).group(1)
        self.assertNotIn('Authorization', request)
        self.assertNotIn('Cookie', request)

    # The audit section the integration step adds to DEFAULT_CONFIG.
    EXPECTED_KEYS = {
        'enabled': False, 'networks': [], 'gentle_networks': [], 'concurrency': 32,
        'max_rate': 200, 'host_delay_ms': 20, 'gentle_concurrency': 2, 'gentle_max_rate': 5,
        'gentle_host_delay_ms': 500, 'connect_timeout_sec': 1.0, 'cert_warn_days': 30,
        'keep_reports': 20,
    }

    def test_every_config_key_is_read_literally_with_its_default(self):
        reads = dict(re.findall(
            r"get\(\s*'audit'\s*,\s*'(\w+)'\s*,\s*default=([^)]+?)\)", self.source))
        self.assertEqual(set(reads), set(self.EXPECTED_KEYS))
        for key, default in self.EXPECTED_KEYS.items():
            with self.subTest(key=key):
                self.assertEqual(eval(reads[key]), default)   # noqa: S307 - literal from our source


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
