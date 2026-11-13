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

from test_bacnet_mode import i_am  # noqa: E402
from test_dga_names import GENERATED, ONEDRIVE_SYNC, WEB_PAGES, dga_findings  # noqa: E402
from test_dns_tunnel import encoded, query  # noqa: E402
from test_fourth_review import confirmed, who_is  # noqa: E402
from test_gateway_threats import EDGE, _GeoIP, cef  # noqa: E402
from test_lan_threats import arp, dhcp_payload, name_query, name_response, pkt  # noqa: E402
from test_path_probes import tcp_traceroute, traceroute_pings  # noqa: E402
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

    def __init__(self, registry=None, **forensics_options):
        from src.alert_verify import AlertVerifier
        from src.app import NetSentinelApp
        from src.exposures import ExposureRegistry
        from src.forensics import NetworkForensics
        self.forensics = NetworkForensics(**forensics_options)
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


# A PC that runs a building's controls, and its network.
BAS_PC, CONTROLLER, BAS_BROADCAST = '192.168.10.40', '192.168.10.141', '192.168.10.255'


def building_pipeline(mode):
    """_Pipeline on the building-controls PC, with bacnet.mode as given."""
    return _Pipeline(net_env=SimpleNamespace(local_ips={BAS_PC}), bacnet_mode=mode)


def bacnet(src, dst, payload, ts=T0):
    return udp(src, 47808, dst, 47808, payload, ts=ts)


def gateway_app(geoip=None):
    """The app's gateway with the real checker, for the UniFi gateway's IPS events."""
    from src.alert_verify import AlertVerifier
    from src.app import NetSentinelApp
    from src.exposures import ExposureRegistry
    from src.ids_engine import IDSEngine

    class _Manager:
        def get_alerts(self, limit=300):
            return []

    app = NetSentinelApp.__new__(NetSentinelApp)
    app.raised = []
    app.ids_engine = IDSEngine(reset_config())
    app.ids_engine.geoip = geoip
    app.alert_verifier = AlertVerifier(reset_config())
    app.baseline_whitelist, app.alert_manager = None, _Manager()
    app.exposures = ExposureRegistry()
    app._gateway_threats_seen = {}
    app._emit_alert = app.raised.append
    app._alert_gateway = app._verified_alert_gateway
    return app


def ping_engine():
    from src.ids_engine import IDSEngine
    alerts = []
    return IDSEngine(reset_config(), alert_callback=alerts.append), alerts


def ping(ids, src, dst, ts, icmp_type=8):
    ids.inspect_packet(pkt(ts=ts, src_ip=src, dst_ip=dst, protocol='ICMP',
                           icmp_type=icmp_type, payload_size=56))


def as_alerts(findings):
    """IOC findings in the shape assertRaised reads."""
    return [SimpleNamespace(rule_id=f['rule_id'], severity=f['severity'], title=f['title'])
            for f in findings]


class _HostingGeoIP:
    """Owners for made-up public addresses: the second octet picks the company."""

    def lookup(self, ip):
        owner = {151: (64496, 'Example Hosting GmbH'), 152: (64497, 'Example Hosting'),
                 153: (64498, 'Shells Ltd'), 154: (64499, 'Rack Servers, Inc.'),
                 155: (64500, 'Deft Example')}.get(int(ip.split('.')[1]))
        return {'asn': owner[0], 'as_org': owner[1]} if owner else {}


def dns_answer(ids, name, answers, ttl, ts):
    p = pkt(ts=ts, src_ip=GATEWAY, dst_ip=PC, src_port=53, dst_port=51000, protocol='UDP',
            dns_query=name, dns_rcode=0, dns_answers=tuple(answers), dns_ttl=ttl, length=90)
    ids.inspect_packet(p)


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

    def test_a_bacnet_write_from_another_computer(self):
        """On the building-controls PC, its own writes are routine; anyone else's is not."""
        for mode in ('watch', 'workstation'):
            raised = building_pipeline(mode).feed(
                bacnet(EVIL, CONTROLLER, confirmed(service=15, invoke=1)))
            self.assertRaised(raised, 'FORENSICS-SENSITIVE-DATA', 'HIGH', title='BACnet WRITE')

    def test_a_building_controller_reset_from_anywhere(self):
        raised = building_pipeline('workstation').feed(
            bacnet(BAS_PC, CONTROLLER, confirmed(service=20, invoke=2)))
        self.assertRaised(raised, 'FORENSICS-SENSITIVE-DATA', 'HIGH', title='BACnet RESET')

    def test_a_ping_flood_at_one_host(self):
        ids, alerts = ping_engine()
        for i in range(1500):
            ping(ids, '198.51.100.9', PC, T0 + i * 0.005)
        self.assertRaised(alerts, 'ICMP-FLOOD', 'HIGH')

    def test_an_unreachable_flood(self):
        """BlackNurse: ICMP errors by the thousands a second, at a firewall's CPU."""
        ids, alerts = ping_engine()
        for i in range(4000):
            ping(ids, '198.51.100.9', PC, T0 + i * 0.0005, icmp_type=3)
        self.assertRaised(alerts, 'ICMP-FLOOD', 'HIGH')

    def test_a_syn_flood_from_this_network(self):
        ids, alerts = ping_engine()
        for i in range(800):
            ids.inspect_packet(pkt(ts=T0 + i * 0.01, src_ip=PC, src_port=20000 + i,
                                   dst_ip='45.60.10.114', dst_port=443, protocol='TCP',
                                   flags='S', ttl=128))
        self.assertRaised(alerts, 'SYN-FLOOD', 'CRITICAL')

    def test_a_dga_burst(self):
        """Generated names, including under co.uk and a dynamic-DNS provider."""
        self.assertRaised(as_alerts(dga_findings(GENERATED)), 'IOC-DGA', 'HIGH')

    def test_fast_flux_on_home_machines(self):
        """Three addresses an answer, never the same twice, all over the internet."""
        ids, alerts = ping_engine()
        for i in range(6):
            answer = [f'{70 + i * 3 + k}.{20 + k}.{i}.9' for k in range(3)]
            dns_answer(ids, 'pharma.example', answer, 60, T0 + i * 60)
        self.assertRaised(alerts, 'DNS-FAST-FLUX', 'HIGH')

    def test_a_ping_sweep_of_the_network(self):
        ids, alerts = ping_engine()
        for i in range(2, 100):
            ping(ids, EVIL, f'192.168.10.{i}', T0 + i * 0.02)
        self.assertRaised(alerts, 'PING-SWEEP', 'MEDIUM')

    def test_an_exploit_the_gateway_caught(self):
        from src.syslog_receiver import parse
        app = gateway_app(geoip=_GeoIP())
        app._gateway_threat(parse(cef(
            event='Threat Detected', act='allowed', risk='high', policy='Exploits',
            src='5.5.5.5', dst=NAS, spt=54012, dpt=8080, proto='TCP',
            signature=('UNIFIipsSignature', 'ET EXPLOIT Example RCE Attempt'),
            signature_id=('UNIFIipsSignatureId', '2034647'))))
        [alert] = self.assertRaised(app.raised, 'UNIFI-IPS', 'HIGH')
        self.assertEqual(alert.evidence['alert_verification']['verdict'], 'LIKELY_THREAT')

    def test_a_listed_attacker_on_a_shared_edge_reaching_in(self):
        from src.ids_engine import IDSEngine

        class Intel:
            def check_ip(self, ip):
                return ({'feed': 'cins_army', 'category': 'Active Attacker',
                         'description': 'x', 'attacker_feed': True} if ip == EDGE else None)

            def check_domain(self, domain):
                return None

        alerts = []
        ids = IDSEngine(reset_config(), alert_callback=alerts.append, threat_intel=Intel())
        ids.geoip = _GeoIP()
        ids.inspect_packet(pkt(src_ip=EDGE, src_port=50000, dst_ip=PC, dst_port=3389,
                               protocol='TCP', flags='S'))
        self.assertRaised(alerts, 'THREAT-INTEL-IP', 'HIGH')

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

    def test_tailscale_timing_its_relay_servers(self):
        """160 HIGH "ICMP Flood" alerts on 11-10: 29 relays, a few pings a second each."""
        ids, alerts = ping_engine()
        relays = [f'45.{i}.{i}.10' for i in range(1, 30)]
        for tick in range(240 * 5):
            ping(ids, PC, relays[tick % 29], T0 + tick * 0.2)
        self.assertEqual([a.rule_id for a in alerts if a.rule_id in ('ICMP-FLOOD', 'PING-SWEEP')],
                         [])

    def test_a_vpn_exit_node_losing_its_uplink(self):
        """One more HIGH "ICMP Flood" on 11-10, found replaying the day: the exit
        node answered this PC's HTTPS connections with 492 "host unreachable" in
        4.5 minutes, up to 86 in ten seconds."""
        ids, alerts = ping_engine()
        times = [T0 + i * 0.1 for i in range(86)] + [T0 + 10 + i * 0.63 for i in range(406)]
        for ts in times:
            ping(ids, '100.68.0.5', PC, ts, icmp_type=3)
        self.assertEqual([a.rule_id for a in alerts if a.rule_id == 'ICMP-FLOOD'], [])

    def test_discord_testing_its_voice_servers(self):
        """Two HIGH "Known Malicious IP" on 11-11 and the gateway blocking a reply:
        Cloudflare addresses on the CINS list, outside Cloudflare's published ranges."""
        from src.ids_engine import IDSEngine
        from src.syslog_receiver import parse

        class Intel:
            def check_ip(self, ip):
                return ({'feed': 'cins_army', 'category': 'Active Attacker',
                         'description': 'x', 'attacker_feed': True} if ip == EDGE else None)

            def check_domain(self, domain):
                return None

        alerts = []
        ids = IDSEngine(reset_config(), alert_callback=alerts.append, threat_intel=Intel())
        ids.geoip = _GeoIP()
        ids.inspect_packet(pkt(src_ip=PC, src_port=63580, dst_ip=EDGE, dst_port=19327,
                               protocol='UDP', payload_size=8))
        self.assertNotIn('THREAT-INTEL-IP', [a.rule_id for a in alerts])
        app = gateway_app(geoip=_GeoIP())
        app._gateway_threat(parse(cef()))
        [blocked] = app.raised
        self.assertEqual(blocked.severity, 'LOW')
        self.assertEqual(blocked.evidence['alert_verification']['verdict'], 'LIKELY_FALSE_POSITIVE')

    def test_a_path_monitor_mapping_its_routes(self):
        """56 HIGH "ICMP Flood" and two CRITICAL "SYN Flood" in two hours on 11-12:
        PingerPlot on a work laptop stepping the TTL from 1 to 11 to a public
        resolver, and from 1 to 12 in SYNs to a mail server, every second."""
        ids, alerts = ping_engine()
        traceroute_pings(ids, '8.8.8.8', hops=11, seconds=120)
        tcp_traceroute(ids, '45.60.10.114', hops=12, seconds=120, ts=T0 + 200)
        self.assertEqual([a.rule_id for a in alerts if a.rule_id in ('ICMP-FLOOD', 'SYN-FLOOD')],
                         [])

    def test_a_onedrive_sync_and_an_evening_of_web_pages(self):
        """Two HIGH "Domain Generation Algorithm" alerts: OneDrive's storage accounts,
        SharePoint, Azure SignalR, and the UUIDs and hashes in Claude's and Google's
        frame hosts."""
        self.assertEqual(dga_findings(ONEDRIVE_SYNC) + dga_findings(WEB_PAGES), [])

    def test_an_ad_servers_pool_in_one_answer(self):
        """A HIGH "Fast-Flux Hosting": an ad server's name answered once with 67
        addresses at four hosting companies, one of them under two AS numbers."""
        ids, alerts = ping_engine()
        ids.geoip = _HostingGeoIP()
        pool = [f'{60 + i % 9}.{151 + i % 5}.{i}.{i % 7}' for i in range(67)]
        dns_answer(ids, 's.console.ads.example', ['s.routing.example', *pool], 37, T0)
        dns_answer(ids, 's.console.ads.example', pool, 37, T0 + 400)
        self.assertNotIn('DNS-FAST-FLUX', [a.rule_id for a in alerts])

    def test_an_ad_servers_expired_certificate_every_hour(self):
        """An expired certificate on an ad exchange's sync server, filed under this
        PC at a new random port each time: a new exposure every hour."""
        from src.exposures import ExposureRegistry
        from src.ids_engine import Alert
        registry = ExposureRegistry()
        seen = []
        for hour, port in enumerate((26224, 37665, 41022)):
            seen.append(registry.observe(Alert(
                'TLS-CERT-INVALID', 'MEDIUM', 'Untrusted Server Certificate (expired)', 'x',
                src_ip='45.60.35.228', src_port=443, dst_ip=PC, dst_port=port),
                now=T0 + hour * 3600)['report'])
        self.assertEqual(seen, [True, False, False])

    def test_building_controllers_answering_discovery(self):
        """Each was a CRITICAL "[CONFIRMED] Plaintext Credential (BACnet)", under the
        broadcast address, saying to change its password: no secret is in an I-Am."""
        raised = _Pipeline().feed(*(bacnet(f'192.168.10.{150 + i}', BAS_BROADCAST, i_am(),
                                           ts=T0 + i) for i in range(40)))
        self.assertEqual([a.rule_id for a in raised], [])

    def test_a_building_controls_pc_polling_and_writing_all_day(self):
        """bacnet.mode 'workstation': this PC's own BACnet is its job."""
        packets = [bacnet(BAS_PC, BAS_BROADCAST, who_is())]
        for i in range(30):
            packets.append(bacnet(BAS_PC, CONTROLLER, confirmed(service=12, invoke=i % 256),
                                  ts=T0 + i))
            packets.append(bacnet(BAS_PC, CONTROLLER, confirmed(service=15, invoke=i % 256),
                                  ts=T0 + i + 0.5))
        raised = building_pipeline('workstation').feed(*packets)
        self.assertEqual([a.rule_id for a in raised], [])

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
