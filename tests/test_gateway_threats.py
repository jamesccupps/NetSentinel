"""
The gateway's IDS/IPS detections, and two false alarms from 2026-11-10/11.
==========================================================================
- The UniFi gateway sent its "Threat Detected and Blocked" events over syslog
  and NetSentinel stored them and did nothing more; the owner learnt of one
  from the UniFi phone app instead.
- That one was Discord testing its voice servers: one 8-byte UDP packet each
  to 25 addresses in Cloudflare's 104.29.0.0/16, two of them on the CINS list.
  NetSentinel raised two HIGH "Known Malicious IP" alerts and the gateway
  blocked a reply. Cloudflare's published ranges do not cover that /16.
- Tailscale timing its 29 relay servers at a few pings a second each was 160
  HIGH "ICMP Flood" alerts in four minutes: the rule counted per source.
Addresses here are made up or public example ones; MACs are documentation ones.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_lan_threats import pkt  # noqa: E402

PC, GATEWAY = '192.168.10.32', '192.168.10.1'
EDGE = '93.184.216.34'              # stands for a Cloudflare-owned address
OTHER = '5.5.5.5'
T0 = 1_790_000_000.0


def cef(event='Threat Detected and Blocked', act='blocked', risk='medium',
        policy='CINS Army Reputation List', src=EDGE, dst=PC, spt=19327, dpt=63580,
        direction='incoming', signature=('UNIFIipsSignature', 'ET CINS Active Threat '
                                         'Intelligence Poor Reputation IP group 46'),
        signature_id=('UNIFIipsSignatureId', '2403454'), proto='UDP'):
    sig = f' {signature[0]}={signature[1]}' if signature else ''
    sid = f' {signature_id[0]}={signature_id[1]}' if signature_id else ''
    return (f'Nov 11 07:02:59 HOME-GW CEF:0|Ubiquiti|UniFi Network|11.0.99|201|{event}|7|'
            f'UNIFIcategory=Security UNIFIhost=Home Gateway proto={proto} spt={spt} dpt={dpt} '
            f'act={act} app=Other UNIFIrisk={risk} UNIFIpolicyName={policy} '
            f'UNIFIpolicyType=IDS/IPS UNIFIdirection={direction} deviceOutboundInterface=Home LAN '
            f'UNIFIdeviceMac=00:00:5e:00:53:01 UNIFIdeviceName=Home Gateway '
            f'UNIFIdeviceModel=UDM-Pro src={src} dst={dst} '
            f'UNIFIdstDomain=216.184.93.in-addr.arpa{sig}{sid} '
            f'msg=A network intrusion attempt from {src} to {dst} has been detected and blocked.')


class _Settings:
    def get(self, *keys, default=None):
        return {('syslog', 'enabled'): True, ('syslog', 'bind'): '127.0.0.1',
                ('syslog', 'port'): 0, ('syslog', 'allowed_senders'): GATEWAY}.get(keys, default)


class _GeoIP:
    def lookup(self, ip):
        return {'asn': 13335, 'as_org': 'Cloudflare, Inc.'} if ip == EDGE else {}


class TestReadingTheEvent(unittest.TestCase):

    def test_the_signature_and_its_number(self):
        from src.syslog_receiver import parse
        r = parse(cef())
        self.assertEqual(r['signature'], 'ET CINS Active Threat Intelligence Poor Reputation IP '
                                         'group 46')
        self.assertEqual(r['signature_id'], '2403454')
        self.assertEqual((r['risk'], r['policy_type'], r['direction'], r['rule']),
                         ('medium', 'IDS/IPS', 'incoming', 'CINS Army Reputation List'))

    def test_a_signature_in_a_labelled_custom_string(self):
        from src.syslog_receiver import parse
        r = parse(cef(signature=None, signature_id=None) +
                  ' cs4Label=Signature cs4=ET SCAN Example cs5Label=Signature ID cs5=2001')
        self.assertEqual((r['signature'], r['signature_id']), ('ET SCAN Example', '2001'))

    def test_a_reverse_zone_is_not_a_name(self):
        from src.syslog_receiver import parse
        self.assertNotIn('domain', parse(cef()))

    def test_a_threat_keeps_its_whole_message_and_others_are_cut(self):
        from src.syslog_receiver import RAW_KEPT, parse
        long_tail = ' UNIFIextra=' + 'x' * 600
        self.assertGreater(len(parse(cef() + long_tail)['raw']), RAW_KEPT)
        wifi = ('CEF:0|Ubiquiti|UniFi Network|11.0.99|400|WiFi Client Connected|1|'
                'UNIFIcategory=Client Devices' + long_tail)
        self.assertEqual(len(parse(wifi)['raw']), RAW_KEPT)

    def test_what_counts_as_a_threat(self):
        from src.syslog_receiver import is_threat, parse
        self.assertTrue(is_threat(parse(cef())))
        self.assertTrue(is_threat(parse(cef(event='Threat Detected', act='allowed'))))
        self.assertFalse(is_threat(parse('CEF:0|Ubiquiti|UniFi Network|11.0|400|WiFi Client '
                                         'Connected|1|UNIFIcategory=Client Devices')))
        self.assertFalse(is_threat(parse('CEF:0|Ubiquiti|UniFi Network|11.0|100|Blocked by '
                                         'Firewall|1|UNIFIcategory=Security act=block')))


class TestTheReceiverHandsThemOn(unittest.TestCase):

    def setUp(self):
        from src.syslog_receiver import SyslogReceiver
        self.tmp = tempfile.mkdtemp(prefix='ns_gw_')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.r = SyslogReceiver(_Settings(), data_dir=self.tmp, clock=lambda: T0)

    def test_only_threats_reach_the_app(self):
        got = []
        self.r.on_threat = got.append
        self.r.handle(cef().encode(), GATEWAY)
        self.r.handle(b'CEF:0|Ubiquiti|UniFi Network|11.0|400|WiFi Client Connected|1|'
                      b'UNIFIcategory=Client Devices', GATEWAY)
        self.assertEqual([g['event'] for g in got], ['Threat Detected and Blocked'])

    def test_a_failing_hand_off_never_stops_receiving(self):
        def broken(record):
            raise RuntimeError('no')
        self.r.on_threat = broken
        record = self.r.handle(cef().encode(), GATEWAY)
        self.assertEqual(record['event'], 'Threat Detected and Blocked')
        self.assertEqual(self.r.stored, 1)


class TestTheAlert(unittest.TestCase):

    def test_a_reputation_block_of_a_reply(self):
        from src.gateway_threats import threat_alert
        from src.syslog_receiver import parse
        a = threat_alert(parse(cef()))
        self.assertEqual((a.rule_id, a.severity, a.category), ('UNIFI-IPS', 'MEDIUM', 'Gateway IPS'))
        self.assertTrue(a.title.startswith('UniFi blocked: ET CINS'))
        ev = a.evidence
        self.assertEqual((ev['local_ip'], ev['remote_ip'], ev['signature_id']), (PC, EDGE, '2403454'))
        self.assertTrue(ev['reputation_list'])
        self.assertIn('ephemeral', ev['looks_like_a_reply'])
        self.assertIn('talked to it first', ev['recommendation'])

    def test_an_attack_on_a_server_here_is_no_reply(self):
        from src.gateway_threats import threat_alert
        from src.syslog_receiver import parse
        a = threat_alert(parse(cef(
            event='Threat Detected', act='allowed', risk='high', policy='Exploits',
            spt=54012, dpt=8080, proto='TCP', src=OTHER, dst='192.168.10.21',
            signature=('UNIFIipsSignature', 'ET EXPLOIT Example RCE Attempt'),
            signature_id=('UNIFIipsSignatureId', '2034647'))))
        self.assertEqual((a.severity, a.evidence['gateway_action']), ('HIGH', 'detected, not blocked'))
        self.assertNotIn('looks_like_a_reply', a.evidence)
        self.assertFalse(a.evidence['reputation_list'])
        self.assertIn('port 8080', a.evidence['recommendation'])


class TestTheApp(unittest.TestCase):

    def app(self, own=()):
        from src.app import NetSentinelApp

        class _Manager:
            def get_alerts(self, limit=300):
                return list(own)

        app = NetSentinelApp.__new__(NetSentinelApp)
        app.raised = []
        app._alert_gateway = app.raised.append
        app._gateway_threats_seen = {}
        app.alert_manager = _Manager()
        return app

    def test_one_alert_per_signature_and_pair_per_ten_minutes(self):
        from src.syslog_receiver import parse
        app = self.app()
        for i in range(5):
            app._gateway_threat(parse(cef()), now=T0 + i)
        app._gateway_threat(parse(cef()), now=T0 + 700)
        self.assertEqual(len(app.raised), 2)

    def test_it_says_what_netsentinel_saw_of_the_address(self):
        from src.ids_engine import Alert
        from src.syslog_receiver import parse
        record = parse(cef())
        own = Alert('THREAT-INTEL-IP', 'HIGH', 't', 'd', src_ip=PC, dst_ip=EDGE,
                    timestamp=T0 - 1, evidence={'matched_ip': EDGE})
        app = self.app(own=[own])
        record['time'] = T0
        alert = app._gateway_threat(record, now=T0)
        self.assertEqual(len(alert.evidence['netsentinel_also_saw']), 1)
        self.assertTrue(alert.evidence['netsentinel_also_saw'][0].startswith('THREAT-INTEL-IP at'))


class TestTheCheck(unittest.TestCase):

    def verify(self, record, geoip=None, intel=None):
        from src.alert_verify import AlertVerifier
        from src.gateway_threats import threat_alert
        from src.ids_engine import IDSEngine
        from src.syslog_receiver import parse
        ids = IDSEngine(reset_config())
        ids.geoip = geoip
        alert = threat_alert(parse(record))
        AlertVerifier(reset_config(), threat_intel=intel).verify_alert(alert, ids_engine=ids)
        return alert

    def test_a_reputation_hit_on_a_shared_edge_reply_is_likely_safe(self):
        alert = self.verify(cef(), geoip=_GeoIP())
        self.assertEqual(alert.evidence['alert_verification']['verdict'], 'LIKELY_FALSE_POSITIVE')
        self.assertEqual(alert.severity, 'LOW')
        self.assertIn("Cloudflare's", ' '.join(alert.evidence['alert_verification']['reasoning']))

    def test_without_knowing_the_owner_it_is_left_open(self):
        alert = self.verify(cef())
        self.assertEqual(alert.evidence['alert_verification']['verdict'], 'INCONCLUSIVE')
        self.assertEqual(alert.severity, 'MEDIUM')

    def test_an_attack_signature_is_a_likely_threat(self):
        alert = self.verify(cef(event='Threat Detected', act='allowed', risk='high',
                                policy='Exploits', src=OTHER, dst='192.168.10.21', spt=54012,
                                dpt=8080, signature=('UNIFIipsSignature', 'ET EXPLOIT Example'),
                                signature_id=None), geoip=_GeoIP())
        self.assertEqual(alert.evidence['alert_verification']['verdict'], 'LIKELY_THREAT')
        self.assertEqual(alert.severity, 'HIGH')

    def test_a_listed_c2_is_not_excused_by_its_network(self):
        class Intel:
            def check_ip(self, ip):
                return {'category': 'Botnet C2', 'attacker_feed': False} if ip == EDGE else None
        alert = self.verify(cef(), geoip=_GeoIP(), intel=Intel())
        self.assertNotEqual(alert.evidence['alert_verification']['verdict'],
                            'LIKELY_FALSE_POSITIVE')


class TestAttackerListsOnSharedEdges(unittest.TestCase):

    def engine(self, feed):
        from src.ids_engine import IDSEngine

        class Intel:
            def check_ip(inner, ip):
                return dict(feed) if ip == EDGE else None

            def check_domain(inner, domain):
                return None

        alerts = []
        ids = IDSEngine(reset_config(), alert_callback=alerts.append, threat_intel=Intel())
        ids.geoip = _GeoIP()
        return ids, alerts

    CINS = {'feed': 'cins_army', 'category': 'Active Attacker', 'description': 'x',
            'attacker_feed': True}
    C2 = {'feed': 'feodo_c2', 'category': 'Botnet C2', 'description': 'x', 'attacker_feed': False}

    def probe(self, ids, inbound=False):
        """Discord's latency test: one 8-byte UDP packet to the voice server's port."""
        if inbound:
            p = pkt(src_ip=EDGE, src_port=50000, dst_ip=PC, dst_port=3389, protocol='TCP',
                    flags='S')
        else:
            p = pkt(src_ip=PC, src_port=63580, dst_ip=EDGE, dst_port=19327, protocol='UDP',
                    payload_size=8)
        ids.inspect_packet(p)

    def rules(self, alerts):
        return [a.rule_id for a in alerts]

    def test_reaching_a_listed_attacker_on_cloudflare_is_not_an_alert(self):
        ids, alerts = self.engine(self.CINS)
        self.probe(ids)
        self.assertNotIn('THREAT-INTEL-IP', self.rules(alerts))
        self.assertEqual(ids.cloud_exempted, 1)

    def test_a_c2_there_still_is(self):
        ids, alerts = self.engine(self.C2)
        self.probe(ids)
        self.assertIn('THREAT-INTEL-IP', self.rules(alerts))

    def test_the_attacker_reaching_in_still_is(self):
        ids, alerts = self.engine(self.CINS)
        self.probe(ids, inbound=True)
        self.assertIn('THREAT-INTEL-IP', self.rules(alerts))

    def test_without_geoip_nothing_changes(self):
        ids, alerts = self.engine(self.CINS)
        ids.geoip = None
        self.probe(ids)
        self.assertIn('THREAT-INTEL-IP', self.rules(alerts))


class TestIcmp(unittest.TestCase):

    def engine(self):
        from src.ids_engine import IDSEngine
        alerts = []
        return IDSEngine(reset_config(), alert_callback=alerts.append), alerts

    def ping(self, ids, src, dst, ts, icmp_type=8):
        ids.inspect_packet(pkt(ts=ts, src_ip=src, dst_ip=dst, protocol='ICMP',
                               icmp_type=icmp_type, payload_size=56))

    def test_a_vpn_timing_its_relay_servers_is_not_a_flood(self):
        """29 servers, a few pings a second each, for four minutes."""
        ids, alerts = self.engine()
        relays = [f'45.{i}.{i}.10' for i in range(1, 30)]
        for tick in range(240 * 5):
            self.ping(ids, PC, relays[tick % 29], T0 + tick * 0.2)
        rules = [a.rule_id for a in alerts]
        self.assertNotIn('ICMP-FLOOD', rules)
        self.assertNotIn('PING-SWEEP', rules)

    def test_a_peer_checking_the_path_is_not_either(self):
        ids, alerts = self.engine()
        for i in range(120):
            self.ping(ids, '100.68.0.5', PC, T0 + i / 3)
        self.assertNotIn('ICMP-FLOOD', [a.rule_id for a in alerts])

    def test_a_flood_at_one_host_is_one_alert(self):
        ids, alerts = self.engine()
        for i in range(3000):
            self.ping(ids, OTHER, PC, T0 + i * 0.01)
        flood = [a for a in alerts if a.rule_id == 'ICMP-FLOOD']
        self.assertEqual(len(flood), 1)
        self.assertEqual(flood[0].evidence['target_ip'], PC)

    def test_a_ping_sweep_of_the_lan(self):
        ids, alerts = self.engine()
        for i in range(1, 80):
            self.ping(ids, '192.168.10.66', f'192.168.10.{i}', T0 + i * 0.05)
        sweep = [a for a in alerts if a.rule_id == 'PING-SWEEP']
        self.assertEqual(len(sweep), 1)
        self.assertEqual(sweep[0].severity, 'MEDIUM')
        self.assertGreaterEqual(sweep[0].evidence['hosts_pinged'], 20)


if __name__ == '__main__':
    unittest.main()
