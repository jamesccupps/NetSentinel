"""
A gateway detection that this PC started.
=========================================
On 2026-11-13 an SSH client on the owner's desktop retried an address on
another private network five times, and the UniFi gateway blocked it as "ET
SCAN Potential SSH Scan OUTBOUND". With both addresses private, the alert took
the other one for this network's: it put the desktop on the far side, said to
check what the other address runs on port 22, listed the desktop's own unrelated
alerts as "seen about this address", and named the desktop
"outlook.office365.com". Now it says this PC connected out, and which program.
Addresses are made-up LAN examples.
"""

import collections
import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_gateway_threats import PC, T0, cef  # noqa: E402
from test_lan_threats import pkt  # noqa: E402

ELSEWHERE = '172.20.40.9'           # an address on some other private network
SERVER = '192.168.10.21'            # a server on this network
SSH_SCAN = dict(event='Threat Detected and Blocked', act='blocked', risk='medium',
                policy='Scanning Activity', src=PC, dst=ELSEWHERE, spt=50426, dpt=22,
                direction='outgoing', proto='TCP',
                signature=('UNIFIipsSignature', 'ET SCAN Potential SSH Scan OUTBOUND'),
                signature_id=('UNIFIipsSignatureId', '2003068'))
PROGRAM = 'ssh.exe (process 4242)'


def record(**changes):
    from src.syslog_receiver import parse
    return parse(cef(**dict(SSH_SCAN, **changes)))


class TestWhichSideIsHere(unittest.TestCase):

    def test_this_pcs_own_address_is_here(self):
        from src.gateway_threats import sides
        self.assertEqual(sides(record(), own={PC}), (PC, 50426, ELSEWHERE, 22))

    def test_with_both_private_the_gateways_direction_decides(self):
        from src.gateway_threats import sides
        self.assertEqual(sides(record())[0], PC)
        incoming = record(src=ELSEWHERE, dst=SERVER, spt=51000, dpt=22, direction='incoming')
        self.assertEqual(sides(incoming)[:2], (SERVER, 22))

    def test_a_private_address_against_a_public_one_is_unchanged(self):
        from src.gateway_threats import sides
        self.assertEqual(sides(record(dst='8.8.8.8'))[0], PC)
        self.assertEqual(sides(record(src='8.8.8.8', dst=SERVER, direction='incoming'))[0],
                         SERVER)


class TestTheAlert(unittest.TestCase):

    def test_it_says_this_pc_connected_out_and_with_what(self):
        from src.gateway_threats import threat_alert
        a = threat_alert(record(), own={PC}, program=PROGRAM)
        ev = a.evidence
        self.assertEqual((ev['local_ip'], ev['remote_ip'], ev['program']), (PC, ELSEWHERE, PROGRAM))
        self.assertIn(f'to {ELSEWHERE}:22', ev['started_here'])
        self.assertTrue(ev['recommendation'].startswith(
            f'This PC started it: {PROGRAM} connected to {ELSEWHERE} on port 22'))
        self.assertNotIn('Look at what', ev['recommendation'])

    def test_without_the_program_it_says_so(self):
        from src.gateway_threats import threat_alert
        ev = threat_alert(record(), own={PC}).evidence
        self.assertNotIn('program', ev)
        self.assertIn('could not be told', ev['started_here'])
        self.assertIn('a program on this PC connected', ev['recommendation'])

    def test_another_devices_connection_is_not_this_pcs(self):
        from src.gateway_threats import threat_alert
        ev = threat_alert(record(src=SERVER), own={PC}).evidence
        self.assertNotIn('started_here', ev)
        self.assertEqual(ev['local_ip'], SERVER)

    def test_the_check_says_a_program_here_did_it(self):
        from src.alert_verify import AlertVerifier
        from src.gateway_threats import threat_alert
        a = threat_alert(record(), own={PC}, program=PROGRAM)
        AlertVerifier(reset_config()).verify_alert(a)
        check = a.evidence['alert_verification']
        self.assertIn(f'This PC opened the connection: {PROGRAM}', check['reasoning'])
        self.assertEqual(check['auto_assessment'], 'A program on this PC did what the gateway matched')


class _Manager:
    def __init__(self, alerts=()):
        self.alerts = list(alerts)

    def get_alerts(self, limit=300):
        return self.alerts


def app_for(own_alerts=()):
    from src.app import NetSentinelApp
    app = NetSentinelApp.__new__(NetSentinelApp)
    app.raised = []
    app._alert_gateway = app.raised.append
    app._gateway_threats_seen = {}
    app.alert_manager = _Manager(own_alerts)
    app.net_env = SimpleNamespace(local_ips={PC})
    return app


class TestTheApp(unittest.TestCase):

    def test_it_names_the_program_and_looks_up_the_far_side(self):
        from src.ids_engine import Alert
        mine = Alert('FORENSICS-SENSITIVE-DATA', 'LOW', 't', 'd', src_ip=PC, dst_ip=SERVER,
                     timestamp=T0 - 5)
        app = app_for([mine])
        asked = []
        app._program_for_connection = lambda port, remote: asked.append((port, remote)) or PROGRAM
        r = record()
        r['time'] = T0
        alert = app._gateway_threat(r, now=T0)
        self.assertEqual(asked, [(50426, ELSEWHERE)])
        self.assertEqual(alert.evidence['program'], PROGRAM)
        self.assertNotIn('netsentinel_also_saw', alert.evidence)   # about this PC, not the far side

    def test_a_program_is_only_looked_for_when_this_pc_started_it(self):
        app = app_for()
        app._program_for_connection = lambda port, remote: self.fail('looked up')
        r = record(src=ELSEWHERE, dst=SERVER, spt=51000, dpt=22, direction='incoming')
        self.assertNotIn('program', app._gateway_threat(r, now=T0).evidence)


class TestWhatHadThePort(unittest.TestCase):
    """capture.process_for_connection, with psutil's view of the connections faked."""

    def setUp(self):
        from src import capture
        self.capture = capture
        self.saved = (capture.psutil if hasattr(capture, 'psutil') else None,
                      capture.PSUTIL_AVAILABLE, dict(capture._recent_connections),
                      capture._port_process_cache)
        self.open = []
        Conn = collections.namedtuple('Conn', 'laddr raddr status pid')
        Addr = collections.namedtuple('Addr', 'ip port')
        self.conn = lambda lport, rip, pid: Conn(Addr(PC, lport), Addr(rip, 22), 'SYN_SENT', pid)
        names = {4242: 'ssh.exe', 777: 'Code.exe'}
        capture.psutil = SimpleNamespace(
            CONN_LISTEN='LISTEN', NoSuchProcess=LookupError, AccessDenied=PermissionError,
            net_connections=lambda kind='inet': list(self.open),
            net_if_addrs=lambda: {},
            Process=lambda pid: SimpleNamespace(name=lambda: names[pid]))
        capture.PSUTIL_AVAILABLE = True
        capture._recent_connections = {}

    def tearDown(self):
        psutil, available, recent, cache = self.saved
        if psutil is not None:
            self.capture.psutil = psutil
        self.capture.PSUTIL_AVAILABLE = available
        self.capture._recent_connections = recent
        self.capture._port_process_cache = cache

    def test_a_connection_still_trying_is_found(self):
        self.open = [self.conn(50426, ELSEWHERE, 4242)]
        self.assertEqual(self.capture.process_for_connection(50426, ELSEWHERE), ('ssh.exe', 4242))

    def test_one_that_ended_a_moment_ago_too(self):
        self.open = [self.conn(50426, ELSEWHERE, 4242)]
        self.capture.process_for_connection(50426, ELSEWHERE)
        self.open = []
        self.assertEqual(self.capture.process_for_connection(50426, ELSEWHERE), ('ssh.exe', 4242))

    def test_the_port_reused_for_somewhere_else_is_not_it(self):
        """Windows hands the port to another program's connection soon after."""
        self.open = [self.conn(50426, SERVER, 777)]
        self.assertIsNone(self.capture.process_for_connection(50426, ELSEWHERE))

    def test_after_five_minutes_it_is_forgotten(self):
        import time
        self.capture._recent_connections = {(50426, ELSEWHERE): ('ssh.exe', 4242, time.time() - 301)}
        self.assertIsNone(self.capture.process_for_connection(50426, ELSEWHERE))


class TestNoNameForThisPC(unittest.TestCase):

    def test_a_server_name_is_never_filed_under_this_pcs_address(self):
        from src.ids_engine import IDSEngine
        ids = IDSEngine(reset_config(), net_env=SimpleNamespace(
            local_ips={PC}, gateways=[], dhcp_servers=[], local_subnet='192.168.10.0/24',
            is_known_cloud_domain=lambda d: False, is_cloud_hosting_domain=lambda d: False,
            is_gateway=lambda ip: False, is_configured_resolver=lambda ip: False,
            should_skip_ids=lambda *a, **k: False))
        for src, dst in ((PC, '203.0.113.80'), ('203.0.113.80', PC)):
            ids.inspect_packet(pkt(ts=T0, protocol='TCP', src_ip=src, dst_ip=dst, src_port=443,
                                   dst_port=50000, tls_sni='outlook.office365.com'))
        self.assertEqual(ids._get_domains_for_ip(PC), set())
        self.assertEqual(ids._get_domains_for_ip('203.0.113.80'), {'outlook.office365.com'})

    def test_alerts_carry_no_names_for_this_pc(self):
        from src.app import NetSentinelApp
        from src.ids_engine import Alert
        app = NetSentinelApp.__new__(NetSentinelApp)
        app.net_env = SimpleNamespace(local_ips={PC})
        app.ids_engine = SimpleNamespace(_get_domains_for_ip=lambda ip: {'outlook.office365.com'})
        app.forensics = SimpleNamespace(_ip_to_domains={PC: {'outlook.office365.com'}})
        app.baseline_whitelist = app.exposures = None
        app.alert_verifier = SimpleNamespace(verify_alert=lambda alert, ids_engine=None: None)
        app.raised = []
        app._emit_alert = app.raised.append
        app._verified_alert_gateway(Alert('UNIFI-IPS', 'MEDIUM', 't', 'd', src_ip=PC,
                                          dst_ip=ELSEWHERE))
        app._verified_alert_gateway(Alert('UNIFI-IPS', 'MEDIUM', 't', 'd', src_ip=ELSEWHERE,
                                          dst_ip=PC))
        first, second = (a.evidence for a in app.raised)
        self.assertNotIn('source_domains', first)
        self.assertEqual(first['destination_domains'], ['outlook.office365.com'])
        self.assertNotIn('destination_domains', second)


if __name__ == '__main__':
    unittest.main()
