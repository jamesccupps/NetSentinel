"""
What the first review of real alerts found.
===========================================
The first exe with review mode raised six alerts in five minutes on the owner's
PC, and all six were false positives: plain-HTTP fetches from ESET, Windows
Update and Steam reported as sensitive data, Edge's updater as an insecure
service, a headless Edge run by a test as "LIKELY THREAT", and a WebRTC call as
name poisoning. Reviewing them also showed the PC's own address taken for a
gateway, and bundles whose traffic could not be read. Addresses and names here
are made up or the public services involved.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import SCAPY_REAL, reset_config  # noqa: E402

from src.capture import PacketInfo  # noqa: E402
from test_lan_threats import _Lan, name_query, name_response, pkt as lan_pkt  # noqa: E402

REPO = os.path.dirname(os.path.abspath(__file__))
PC, ROUTER = '192.168.8.32', '192.168.8.1'


def pkt(**kw):
    p = PacketInfo()
    for k, v in kw.items():
        setattr(p, k, v)
    return p


class TestGateway(unittest.TestCase):

    ROUTE_PRINT = (
        "===========================================================================\n"
        "IPv4 Route Table\n"
        "===========================================================================\n"
        "Active Routes:\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\n"
        f"          0.0.0.0          0.0.0.0      {ROUTER}     {PC}     25\n"
        "          0.0.0.0          0.0.0.0         On-link       10.8.0.2    5\n"
        "===========================================================================\n"
        "Persistent Routes:\n"
        "  Network Address          Netmask  Gateway Address  Metric\n"
        f"          0.0.0.0          0.0.0.0      {ROUTER}  Default\n")

    def test_this_computer_is_not_its_own_gateway(self):
        """The interface column was read as a gateway: Gateways: [router, this PC]."""
        from src import net_detect

        def run(cmd, **kw):
            out = self.ROUTE_PRINT if cmd[0] == 'route' else ''
            return SimpleNamespace(stdout=out, returncode=0)

        with mock.patch.object(net_detect, 'PSUTIL_AVAILABLE', True), \
                mock.patch.object(net_detect.subprocess, 'run', side_effect=run):
            self.assertEqual(net_detect.detect_default_gateway(), [ROUTER])


@unittest.skipUnless(SCAPY_REAL, 'needs scapy')
class TestBundleDigests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='ns_digest_')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def capture(self, name, packets):
        from scapy.all import wrpcap
        for n, p in enumerate(packets):
            p.time = 1_790_000_000 + n / 100
        path = os.path.join(self.tmp, name)
        wrpcap(path, packets)
        return path

    @staticmethod
    def tcp(src, dst, dport=443, payload=b''):
        from scapy.all import IP, TCP, Ether, Raw
        frame = (Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src=src, dst=dst)
                 / TCP(sport=50000, dport=dport, flags='PA'))
        return frame / Raw(load=payload) if payload else frame

    def test_the_command_line_can_read_the_traffic(self):
        """In a fresh interpreter only scapy.utils was loaded, so every packet read "Raw"."""
        path = self.capture('one.pcap', [self.tcp(PC, '198.51.100.7')])
        code = ("import sys; sys.path.insert(0, sys.argv[1]); "
                "from src.review import digest_pcap, _Redactor; "
                "print(digest_pcap(sys.argv[2], _Redactor(None)))")
        out = subprocess.run([sys.executable, '-c', code, REPO, path], capture_output=True,
                             text=True, encoding='utf-8', timeout=120, cwd=self.tmp).stdout
        self.assertIn(f'TCP   {PC}:50000 → 198.51.100.7:443', out)
        self.assertNotIn('  Raw', out)

    def test_the_alerts_own_connection_comes_first(self):
        """An alert on this PC saves all of its traffic; the 400-line cut lost the flow."""
        from src.review import _Redactor, digest_pcap
        noise = [self.tcp(PC, f'198.51.100.{n % 200 + 1}') for n in range(450)]
        request = self.tcp(PC, '150.171.28.11', 80,
                           b'GET /browsernetworktime/time/1/current HTTP/1.1\r\n'
                           b'Host: edge.microsoft.com\r\n\r\n')
        path = self.capture('busy.pcap', noise + [request])
        out = digest_pcap(path, _Redactor(None), focus=(PC, '150.171.28.11'))
        self.assertIn("the alert's own traffic: 1 packets", out)
        self.assertIn('HTTP GET edge.microsoft.com/browsernetworktime', out)
        self.assertLess(out.index('edge.microsoft.com'), out.index('Everything else'))
        self.assertIn('451 packets', out)
        self.assertIn('... 51 more packets', out)


class TestWebRtcNames(_Lan):

    def test_a_webrtc_call_is_not_name_poisoning(self):
        """Edge answered mDNS for four UUID names, its own addresses in a WebRTC call."""
        ids, alerts = self.engine()
        for name in ('3612d913-2ec0-47d2-ad52-92475112964d.local',
                     '3f9862de-5607-49ca-bc1d-66cc50bff11e.local',
                     '6a86d662-a55c-4b41-8d20-9e5d1816587d.local',
                     '92d745dd-3045-4701-88ef-479ba0dd763d.local'):
            payload = name_response([name], '192.168.1.70')
            ids.inspect_packet(lan_pkt(protocol='UDP', src_ip='192.168.1.70',
                                       dst_ip='224.0.0.251', src_port=5353, dst_port=5353,
                                       src_mac='00:1b:21:00:00:70', _raw_payload=payload,
                                       payload_size=len(payload)))
        self.assertNotIn('NAME-POISONING', self.rules(alerts))

    def test_responder_answering_a_uuid_too_is_still_caught(self):
        ids, alerts = self.engine()
        for name in ('wpad.local', 'fileserver.local', 'printer.local',
                     '3612d913-2ec0-47d2-ad52-92475112964d.local', 'intranet.local'):
            query = name_query([name])
            ids.inspect_packet(lan_pkt(protocol='UDP', src_ip='192.168.1.50',
                                       dst_ip='224.0.0.251', src_port=5353, dst_port=5353,
                                       src_mac='00:1b:21:00:00:50', _raw_payload=query,
                                       payload_size=len(query)))
            payload = name_response([name], '192.168.1.66')
            ids.inspect_packet(lan_pkt(protocol='UDP', src_ip='192.168.1.66',
                                       dst_ip='224.0.0.251', src_port=5353, dst_port=5353,
                                       src_mac='00:1b:21:66:00:01', _raw_payload=payload,
                                       payload_size=len(payload)))
        self.assertIn('NAME-POISONING', self.rules(alerts))


class TestForensics(unittest.TestCase):

    def setUp(self):
        from src.forensics import NetworkForensics
        self.f = NetworkForensics()

    def response(self, server, sport=80):
        payload = b'HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Length: 0\r\n\r\n'
        self.f.analyze_packet(pkt(src_ip=server, dst_ip=PC, src_port=sport, dst_port=50000,
                                  protocol='TCP', payload_size=len(payload),
                                  _raw_payload=payload))

    def request(self, server, host, n=1, path='/filestreamingservice/files/x'):
        payload = (f'GET {path} HTTP/1.1\r\nHost: {host}\r\n'
                   f'User-Agent: Microsoft-Delivery-Optimization/10.1\r\n\r\n').encode()
        for _ in range(n):
            self.f.analyze_packet(pkt(src_ip=PC, dst_ip=server, src_port=50001, dst_port=80,
                                      protocol='TCP', payload_size=len(payload),
                                      length=len(payload) + 54, _raw_payload=payload))

    def kinds(self):
        return [d['data_type'] for d in self.f.sensitive_data]

    def test_an_internet_servers_banner_is_not_sensitive_data(self):
        """ESET, Windows Update and Steam's Server headers each raised an alert."""
        self.response('38.90.226.44')
        self.assertNotIn('HTTP Server Info', self.kinds())
        self.response('192.168.8.54', 8008)
        self.assertIn('HTTP Server Info', self.kinds())

    def alerts_for(self):
        from src.app import NetSentinelApp
        app = NetSentinelApp.__new__(NetSentinelApp)
        raised = []
        app.forensics = self.f
        app._forensics_cred_cursor = app._forensics_sensitive_cursor = 0
        app._forensics_alerted_services, app._forensics_alerted_sensitive = set(), set()
        app._alert_gateway = raised.append
        app._check_forensics_alerts()
        return [a for a in raised if a.rule_id == 'FORENSICS-INSECURE-SVC']

    def test_a_signed_update_over_http_is_not_an_insecure_service(self):
        """Edge's updater fetched over plain HTTP, as it is meant to."""
        self.request('199.232.210.172', 'msedge.b.tlu.dl.delivery.mp.microsoft.com', n=6)
        self.assertEqual(self.alerts_for(), [])

    def test_the_same_server_serving_anything_else_still_counts(self):
        self.request('199.232.210.172', 'msedge.b.tlu.dl.delivery.mp.microsoft.com', n=3)
        self.request('199.232.210.172', 'shop.example.com', n=3, path='/cart')
        self.assertEqual(len(self.alerts_for()), 1)

    def test_update_hosts_match_on_a_dot_boundary(self):
        from src.forensics import is_software_update_host
        self.assertTrue(is_software_update_host('ctldl.windowsupdate.com'))
        self.assertTrue(is_software_update_host('update.eset.com:80'))
        self.assertFalse(is_software_update_host('update.eset.com.example.net'))
        self.assertFalse(is_software_update_host('notwindowsupdate.com'))


class TestVerifier(unittest.TestCase):

    def verdict(self, data_type, severity='LOW'):
        from src.alert_verify import AlertVerifier
        from src.ids_engine import Alert
        alert = Alert('FORENSICS-SENSITIVE-DATA', severity, 't', 'd',
                      evidence={'data_type': data_type})
        return AlertVerifier(reset_config())._verify_sensitive_data(alert, alert.evidence)

    def test_a_banner_is_not_a_likely_threat(self):
        """Every kind of finding was "LIKELY THREAT 70%", a version banner included."""
        self.assertEqual(self.verdict('HTTP Server Info')['verdict'], 'INCONCLUSIVE')

    def test_an_uncommon_client_is_not_a_likely_threat(self):
        """A headless Edge run by a test was a [LIKELY THREAT]."""
        self.assertEqual(self.verdict('Suspicious User Agent', 'HIGH')['verdict'],
                         'INCONCLUSIVE')
        self.assertEqual(self.verdict('Suspicious User Agent', 'CRITICAL')['verdict'],
                         'LIKELY_THREAT')

    def test_exposed_data_still_is(self):
        self.assertEqual(self.verdict('Session Cookie')['verdict'], 'LIKELY_THREAT')
        self.assertEqual(self.verdict('Private Key')['verdict'], 'VERIFIED_THREAT')
        self.assertEqual(self.verdict('Parking Card Data (PCI-DSS Violation)')['verdict'],
                         'VERIFIED_THREAT')


if __name__ == '__main__':
    unittest.main(verbosity=2)
