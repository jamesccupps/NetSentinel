"""
The detection corpus.
=====================
Every change that quiets a false alarm must leave the real attacks loud. This
file replays the attacks NetSentinel exists to catch, each of which must still
alert at no less than its severity, and the false alarms a week of 1.14 raised
on the owner's network, each of which must stay quiet. A change that silences
an attack fails here, whatever it was meant to fix.

Add an attack here when a rule is added, and a false alarm when one is fixed.
Addresses are made up or documentation ones; MACs are from the documentation
range 00:00:5e:00:53:xx; every credential is fake.
"""

import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_dns_tunnel import encoded, query  # noqa: E402
from test_lan_threats import arp, dhcp_payload, name_query, name_response, pkt  # noqa: E402
from test_snmp_community import snmp, sweep  # noqa: E402
from test_third_review import T0, DAY, http_get, tcp, udp  # noqa: E402
from test_upload_history import engine as upload_engine, exfil, upload  # noqa: E402

PC = '192.168.10.32'
GATEWAY = '192.168.10.1'
HA = '192.168.10.197'
METER = '192.168.10.132'
NAS = '192.168.10.21'
EVIL = '192.168.10.66'
GW_MAC, EVIL_MAC = '00:00:5e:00:53:01', '00:00:5e:00:53:66'
SITE = '203.0.113.80'
FAKE_TOKEN = 'Bearer not.a-real.token-for-tests-only'
_RANK = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}


def sev(alert):
    return str(getattr(alert.severity, 'name', alert.severity))


class _Lan:
    """An IDS engine on a /24 with a known gateway, its LAN state in a temp folder."""

    def __init__(self, case):
        self.tmp = tempfile.mkdtemp(prefix='ns_corpus_')
        case.addCleanup(shutil.rmtree, self.tmp, True)
        self.env = SimpleNamespace(
            gateways=[GATEWAY], dhcp_servers=[GATEWAY], local_ips=[PC],
            local_subnet='192.168.10.0/24', is_known_cloud_domain=lambda d: False,
            is_cloud_hosting_domain=lambda d: False, is_gateway=lambda ip: ip == GATEWAY,
            is_configured_resolver=lambda ip: False, should_skip_ids=lambda *a, **k: False)
        self.state = os.path.join(self.tmp, 'lan_state.json')

    def engine(self):
        from src.ids_engine import IDSEngine
        from src.lan_threats import LanThreatMonitor
        alerts = []
        ids = IDSEngine(reset_config(), alert_callback=alerts.append, net_env=self.env)
        ids.lan = LanThreatMonitor(reset_config(), net_env=self.env, state_path=self.state)
        ids.lan.state['created'] = 0                       # the baseline is long over
        return ids, alerts


class _Pipeline:
    """Forensics, the app's forensics-to-alert step and its gateway, with an exposures list."""

    def __init__(self, registry=None):
        from src.alert_verify import AlertVerifier
        from src.app import NetSentinelApp
        from src.exposures import ExposureRegistry
        from src.forensics import NetworkForensics
        self.forensics = NetworkForensics()
        self.raised = []
        app = NetSentinelApp.__new__(NetSentinelApp)
        app.forensics, app.ids_engine, app.baseline_whitelist = self.forensics, None, None
        app._forensics_cred_cursor = app._forensics_sensitive_cursor = 0
        app._forensics_alerted_services, app._forensics_alerted_sensitive = set(), set()
        app._insecure_names_alerted, app._credentials_alerted = {}, {}
        app.alert_verifier = AlertVerifier(reset_config())
        app.exposures = registry if registry is not None else ExposureRegistry()
        app._emit_alert = self.raised.append
        app._alert_gateway = app._verified_alert_gateway
        self.app = app

    def feed(self, *packets):
        for p in packets:
            self.forensics.analyze_packet(p)
        self.app._check_forensics_alerts()
        return self.raised


def ha_token_request():
    body = b'{}'
    request = ('POST /api/states/sensor.pc HTTP/1.1\r\nHost: homeassistant.local:8123\r\n'
               f'Authorization: {FAKE_TOKEN}\r\nContent-Length: {len(body)}\r\n\r\n').encode() + body
    return tcp(PC, 39453, HA, 8123, request, server=8123)


# ═══════════════════════════════════════════════════════════════════════════
#  Attacks: each must still alert, at no less than its severity
# ═══════════════════════════════════════════════════════════════════════════

class TestAttacksStillAlert(unittest.TestCase):

    def assertRaised(self, alerts, rule, at_least, title=None):
        hits = [a for a in alerts if a.rule_id == rule and (title is None or title in a.title)]
        self.assertTrue(hits, f'{rule} was not raised: {[a.rule_id for a in alerts]}')
        best = max(_RANK[sev(a)] for a in hits)
        self.assertGreaterEqual(best, _RANK[at_least], f'{rule} below {at_least}')
        return hits

    def test_someone_impersonating_the_gateway(self):
        lan = _Lan(self)
        ids, _ = lan.engine()
        ids.inspect_packet(arp(GATEWAY, GW_MAC, target=PC))
        ids.lan.save(force=True)
        ids, alerts = lan.engine()
        ids.inspect_packet(arp(GATEWAY, EVIL_MAC, target=PC))
        self.assertRaised(alerts, 'ARP-SPOOF', 'CRITICAL')

    def test_a_rogue_dhcp_server(self):
        ids, alerts = _Lan(self).engine()
        offer = dhcp_payload(2, EVIL)
        ids.inspect_packet(pkt(protocol='UDP', src_ip=EVIL, dst_ip='255.255.255.255',
                               src_port=67, dst_port=68, src_mac=EVIL_MAC,
                               _raw_payload=offer, payload_size=len(offer)))
        self.assertRaised(alerts, 'ROGUE-DHCP', 'HIGH')

    def test_responder_answering_everyones_names(self):
        ids, alerts = _Lan(self).engine()
        for name in ('fileserver', 'wpad', 'printer', 'intranet'):
            q = name_query([name])
            ids.inspect_packet(pkt(protocol='UDP', src_ip=PC, dst_ip='224.0.0.252',
                                   src_port=50000, dst_port=5355, src_mac='00:00:5e:00:53:32',
                                   _raw_payload=q, payload_size=len(q)))
            a = name_response([name], EVIL)
            ids.inspect_packet(pkt(protocol='UDP', src_ip=EVIL, dst_ip=PC, src_port=5355,
                                   dst_port=50000, src_mac=EVIL_MAC,
                                   _raw_payload=a, payload_size=len(a)))
        self.assertRaised(alerts, 'NAME-POISONING', 'HIGH')

    def test_a_dns_tunnel(self):
        from src.ids_engine import IDSEngine
        alerts = []
        ids = IDSEngine(reset_config(), alert_callback=alerts.append)
        ids.inspect_packet(query(PC, f'{encoded(40)}.t.tunnel-domain.example'))
        self.assertRaised(alerts, 'DNS-TUNNEL', 'MEDIUM')

    def test_a_port_scan(self):
        from src.ids_engine import IDSEngine
        alerts = []
        ids = IDSEngine(reset_config(), alert_callback=alerts.append)
        for i in range(20):
            ids.inspect_packet(tcp(EVIL, 40000 + i, NAS, 20 + i * 7, flags='S', ts=T0 + i))
        self.assertRaised(alerts, 'PORT-SCAN', 'MEDIUM')

    def test_an_unknown_program_uploading_somewhere_new(self):
        ids, alerts = upload_engine()
        upload(ids, 1.2, process='svch0st.exe')
        [alert] = exfil(alerts)
        self.assertEqual(sev(alert), 'HIGH')
        self.assertTrue(alert.evidence['first_large_upload'])

    def test_a_routine_upload_ten_times_its_usual(self):
        ids, alerts = upload_engine()
        upload(ids, 1.2)
        upload(ids, 1.2, ts=T0 + DAY)
        upload(ids, 12.5, ts=T0 + 2 * DAY)
        self.assertEqual(len(exfil(alerts)), 2)

    def test_an_upload_marked_real_is_not_learnt(self):
        ids, alerts = upload_engine()
        upload(ids, 1.2, process='rclone.exe')
        ids.uploads.hold('rclone.exe', '93.184.216.34')
        upload(ids, 1.2, process='rclone.exe', ts=T0 + DAY)
        self.assertEqual(len(exfil(alerts)), 2)

    def test_an_attack_tools_user_agent(self):
        from src.forensics import NetworkForensics
        f = NetworkForensics()
        f.analyze_packet(tcp(EVIL, 50000, NAS, 80, http_get(NAS, '/', 'sqlmap/1.8'), server=80))
        [item] = [d for d in f.sensitive_data if d['data_type'] == 'Suspicious User Agent']
        self.assertEqual(item['risk'], 'CRITICAL')
        self.assertEqual(item['evidence']['matched'], 'sqlmap')

    def test_automation_after_the_browsers_own_job(self):
        from src.forensics import NetworkForensics
        f = NetworkForensics()
        edge = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like '
                'Gecko) HeadlessChrome/158.0.0.0 Safari/537.36 Edg/158.0.0.0')
        f.analyze_packet(tcp(PC, 50000, SITE, 80, http_get('edge.microsoft.com', '/', edge),
                             server=80))
        f.analyze_packet(tcp(PC, 50001, SITE, 80, http_get('bank.example.com', '/', edge),
                             server=80, ts=T0 + 1))
        self.assertEqual([d['evidence']['host'] for d in f.sensitive_data
                          if d['data_type'] == 'Suspicious User Agent'], ['bank.example.com'])

    def test_a_plaintext_ftp_login(self):
        raised = _Pipeline().feed(tcp(PC, 50000, NAS, 21, b'USER demo\r\n', server=21),
                                  tcp(PC, 50000, NAS, 21, b'PASS example-only\r\n', server=21,
                                      ts=T0 + 1))
        hits = self.assertRaised(raised, 'FORENSICS-CREDENTIAL', 'HIGH')
        self.assertTrue(all(a.evidence['exposure']['why'] == 'new' for a in hits))

    def test_a_device_that_answers_the_default_write_community(self):
        raised = _Pipeline().feed(udp(PC, 50001, METER, 161, snmp(b'private')),
                                  udp(METER, 161, PC, 50001, snmp(b'private', 0xa2),
                                      ts=T0 + 0.01))
        [answer] = self.assertRaised(raised, 'FORENSICS-CREDENTIAL', 'HIGH',
                                     title="Device answers SNMP's default community")
        self.assertEqual(answer.evidence['severity_before_exposure_cap'], 'CRITICAL')

    def test_an_exposure_back_after_it_was_marked_fixed(self):
        pipeline = _Pipeline()
        pipeline.feed(ha_token_request())
        [first] = pipeline.raised
        pipeline.app.exposures.set_state(first.evidence['exposure']['id'], 'fixed')
        later = _Pipeline(registry=pipeline.app.exposures)
        later.feed(ha_token_request())
        [again] = later.raised
        self.assertEqual(again.evidence['exposure']['why'], 'seen again')


# ═══════════════════════════════════════════════════════════════════════════
#  This week's false alarms: each must stay quiet
# ═══════════════════════════════════════════════════════════════════════════

class TestFalseAlarmsStayQuiet(unittest.TestCase):

    def test_an_snmp_sweep_is_one_alert_not_one_per_host(self):
        """159 CRITICAL alerts in three minutes on 11-09, one scanner asking a /24."""
        pipeline = _Pipeline()
        sweep(pipeline.forensics, hosts=159, src=PC)
        pipeline.app._check_forensics_alerts()
        self.assertEqual(len(pipeline.raised), 1)

    def test_the_gateway_serving_dhcp_on_its_other_network(self):
        """Two HIGH "Unknown DHCP Server" alerts: the UniFi gateway's other VLAN, its own MAC."""
        ids, alerts = _Lan(self).engine()
        ids.inspect_packet(arp(GATEWAY, GW_MAC, target=PC))
        offer = dhcp_payload(2, '192.168.20.1')
        ids.inspect_packet(pkt(protocol='UDP', src_ip='192.168.20.1', dst_ip='255.255.255.255',
                               src_port=67, dst_port=68, src_mac=GW_MAC,
                               _raw_payload=offer, payload_size=len(offer)))
        self.assertNotIn('ROGUE-DHCP', [a.rule_id for a in alerts])

    def test_a_password_field_in_what_a_server_sends(self):
        """Three CRITICAL "HTTP Form" alerts on 11-02, from a server's reply to this PC."""
        page = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
                b'<form>password=example-only&remember=1</form>')
        pipeline = _Pipeline()
        pipeline.feed(tcp(SITE, 80, PC, 50000, page, server=80))
        self.assertEqual(pipeline.raised, [])

    def test_tailscale_to_its_peer_the_next_day(self):
        """Thirteen HIGH "Large Data Transfer" alerts for three routine pairs."""
        ids, alerts = upload_engine()
        for day in range(4):
            upload(ids, 1.2 + day * 0.4, ts=T0 + day * DAY)
        self.assertEqual(len(exfil(alerts)), 1)

    def test_edges_own_headless_job(self):
        """Five HIGH "Suspicious User Agent" alerts: Edge, headless, asking Microsoft."""
        from src.forensics import NetworkForensics
        f = NetworkForensics()
        edge = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like '
                'Gecko) HeadlessChrome/158.0.0.0 Safari/537.36 Edg/158.0.0.0')
        for i, ip in enumerate(('198.51.100.11', '198.51.100.12', '198.51.100.13')):
            f.analyze_packet(tcp(PC, 50000 + i, ip, 80, http_get('edge.microsoft.com', '/', edge),
                                 server=80, ts=T0 + i))
        self.assertEqual([d for d in f.sensitive_data
                          if d['data_type'] == 'Suspicious User Agent'], [])

    def test_home_assistants_token_on_four_days(self):
        """Four CRITICAL alerts for one standing condition; now one, at HIGH."""
        from src.exposures import ExposureRegistry
        path = os.path.join(tempfile.mkdtemp(prefix='ns_corpus_'), 'exposures.json')
        raised = []
        for _ in range(4):                  # four runs of NetSentinel, one a day
            registry = ExposureRegistry()
            registry.attach(path)
            pipeline = _Pipeline(registry=registry)
            raised += pipeline.feed(ha_token_request())
            registry.save(force=True)
        self.assertEqual([sev(a) for a in raised], ['HIGH'])


if __name__ == '__main__':
    unittest.main()
