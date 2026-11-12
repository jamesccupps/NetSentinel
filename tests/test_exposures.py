"""
Exposures, kept apart from alerts.
==================================
In a week of the owner's alerts, 248 of 277 were 43 standing conditions
reported again and again: Home Assistant's token over plain HTTP on four days,
an energy monitor's Modbus port rated CRITICAL, unencrypted services every
day. They are a list of things to fix, not a stream of events.
Addresses and names here are made up.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_headless import _ApiTestCase  # noqa: E402

PC, HA, METER = '192.168.10.32', '192.168.10.197', '192.168.10.132'
T0 = 1_790_000_000.0
DAY = 86400.0


def alert(rule, severity='CRITICAL', src=PC, dst=HA, port=8123, title=None, **evidence):
    from src.ids_engine import Alert
    return Alert(rule, severity, title or f'{rule} title', 'what it is', src_ip=src,
                 dst_ip=dst, dst_port=port, evidence=dict(evidence))


def ha_token(src=PC):
    return alert('FORENSICS-CREDENTIAL', title='[CONFIRMED] Plaintext Credential (HTTP Auth Token)',
                 src=src, protocol='HTTP Auth Token', credential_type='token',
                 value='abcd1234****', extra={'host': 'homeassistant.local'},
                 recommendation='Use HTTPS.')


def modbus():
    return alert('FORENSICS-INSECURE-SVC', dst=METER, port=502, service='Modbus',
                 title='Unencrypted Modbus Service', how_to_fix='Firewall port 502.')


CERT_SERVER = '45.155.205.80'       # documentation ranges count as private in Python


def certificate(client_port):
    """As the engine raises it: on the server's packet, to this PC's random port."""
    from src.ids_engine import Alert
    return Alert('TLS-CERT-INVALID', 'MEDIUM', 'Untrusted Server Certificate (expired)',
                 'presented an expired certificate', src_ip=CERT_SERVER, src_port=443,
                 dst_ip=PC, dst_port=client_port,
                 evidence={'src_name': 'sync.ads.example', 'server': f'{CERT_SERVER}:443'})


class TestWhatIsAnExposure(unittest.TestCase):

    def key(self, a):
        from src.exposures import exposure_key
        return exposure_key(a)

    def test_standing_conditions_are(self):
        self.assertEqual(self.key(ha_token()),
                         ('credential', 'HTTP Auth Token', 'token', 'homeassistant.local', 8123))
        self.assertEqual(self.key(modbus())[0], 'service')
        self.assertEqual(self.key(alert('VULN-KEV', dst=METER, port=80))[0], 'vulnerability')
        self.assertEqual(self.key(alert('TLS-CERT-SELF-SIGNED', port=443))[0], 'certificate')
        self.assertEqual(self.key(alert('FORENSICS-SENSITIVE-DATA', port=6379,
                                        data_type='Redis No Auth'))[0], 'data')

    def test_a_device_answering_snmp_is_but_asking_is_not(self):
        answered = alert('FORENSICS-CREDENTIAL', 'HIGH', port=161,
                         protocol='SNMP (Default Community)', credential_type='community_string',
                         extra={'answered': True})
        asked = alert('FORENSICS-CREDENTIAL', 'MEDIUM', port=161,
                      protocol='SNMP (Default Community)', credential_type='community_string',
                      extra={'answered': False})
        self.assertIsNotNone(self.key(answered))
        self.assertIsNone(self.key(asked))

    def test_things_happening_are_not(self):
        for a in (alert('PORT-SCAN'), alert('DATA-EXFIL'), alert('ARP-SPOOF'),
                  alert('NEW-DEVICE'),
                  alert('FORENSICS-SENSITIVE-DATA', data_type='Suspicious User Agent'),
                  alert('FORENSICS-SENSITIVE-DATA', data_type='HTTP Attack Pattern'),
                  alert('FORENSICS-SENSITIVE-DATA', data_type='BACnet WRITE'),
                  alert('FORENSICS-CREDENTIAL', protocol='Modbus/SCADA',
                        credential_type='control_command')):
            with self.subTest(a.rule_id, ev=a.evidence):
                self.assertIsNone(self.key(a))


class TestTheList(unittest.TestCase):

    def registry(self):
        from src.exposures import ExposureRegistry
        return ExposureRegistry()

    def test_once_and_capped_at_high(self):
        r = self.registry()
        first = ha_token()
        seen = r.observe(first, now=T0)
        self.assertEqual((seen['report'], seen['why']), (True, 'new'))
        self.assertEqual(first.severity, 'HIGH')
        self.assertEqual(first.evidence['severity_before_exposure_cap'], 'CRITICAL')
        self.assertEqual(first.evidence['exposure']['id'], seen['id'])
        for day in range(1, 4):
            again = r.observe(ha_token(), now=T0 + day * DAY)
            self.assertFalse(again['report'])
        [entry] = r.entries()
        self.assertEqual((entry['count'], entry['state'], entry['severity']), (4, 'open', 'HIGH'))
        self.assertEqual(entry['title'], 'Plaintext Credential (HTTP Auth Token)')
        self.assertEqual(r.counts()['repeats_folded'], 3)

    def test_fixed_then_seen_again_is_reported(self):
        r = self.registry()
        ident = r.observe(modbus(), now=T0)['id']
        r.set_state(ident, 'fixed')
        self.assertEqual(r.observe(modbus(), now=T0 + DAY)['why'], 'seen again')
        self.assertEqual(r.entries()[0]['state'], 'open')

    def test_accepted_is_quiet_until_it_gets_worse(self):
        r = self.registry()
        ident = r.observe(alert('FORENSICS-INSECURE-SVC', 'MEDIUM', dst=METER, port=23,
                                service='Telnet'), now=T0)['id']
        r.set_state(ident, 'accepted')
        quiet = r.observe(alert('FORENSICS-INSECURE-SVC', 'MEDIUM', dst=METER, port=23,
                                service='Telnet'), now=T0 + 60)
        self.assertEqual((quiet['report'], quiet['why']), (False, 'accepted'))
        worse = r.observe(alert('FORENSICS-INSECURE-SVC', 'HIGH', dst=METER, port=23,
                                service='Telnet'), now=T0 + 120)
        self.assertEqual((worse['report'], worse['why']), (True, 'worse'))
        self.assertEqual(r.entries()[0]['state'], 'open')

    def test_every_client_is_one_exposure_of_the_server(self):
        r = self.registry()
        r.observe(ha_token(src=PC), now=T0)
        r.observe(ha_token(src='192.168.10.40'), now=T0 + 5)
        [entry] = r.entries()
        self.assertEqual(entry['clients'], [PC, '192.168.10.40'])

    def test_a_certificate_is_an_exposure_of_the_server(self):
        """Filed by its destination, it was this PC at the port it connected from,
        and the same server an hour later a second entry."""
        r = self.registry()
        first = r.observe(certificate(26224), now=T0)
        again = r.observe(certificate(37665), now=T0 + 3600)
        self.assertEqual((first['why'], again['why']), ('new', 'repeat'))
        [entry] = r.entries()
        self.assertEqual((entry['device'], entry['port'], entry['device_name']),
                         (CERT_SERVER, 443, 'sync.ads.example'))
        self.assertEqual((entry['clients'], entry['count']), ([PC], 2))

    def test_a_misfiled_certificate_is_dropped_on_load(self):
        from src.exposures import ExposureRegistry
        path = os.path.join(tempfile.mkdtemp(), 'exposures.json')
        old = {'state': 'open', 'severity': 'MEDIUM', 'first_seen': T0, 'last_seen': T0,
               'count': 1}
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({'version': 1, 'entries': [
                dict(old, id='a1', kind='certificate', device=PC, port=26224),
                dict(old, id='b2', kind='certificate', device=CERT_SERVER, port=443),
                dict(old, id='c3', kind='service', device=METER, port=502)]}, f)
        r = ExposureRegistry()
        r.attach(path)
        self.assertEqual(sorted(e['id'] for e in r.entries()), ['b2', 'c3'])

    def test_no_credential_value_is_kept(self):
        r = self.registry()
        r.observe(ha_token(), now=T0)
        self.assertNotIn('abcd1234', json.dumps(r.entries()))

    def test_open_worst_first(self):
        r = self.registry()
        r.observe(alert('FORENSICS-INSECURE-SVC', 'LOW', dst=METER, port=80, service='HTTP'), now=T0)
        ident = r.observe(ha_token(), now=T0 + 1)['id']
        r.observe(modbus(), now=T0 + 2)
        r.set_state(ident, 'accepted')
        self.assertEqual([(e['severity'], e['state']) for e in r.entries()],
                         [('HIGH', 'open'), ('LOW', 'open'), ('HIGH', 'accepted')])

    def test_an_unknown_id_or_state_is_refused(self):
        r = self.registry()
        ident = r.observe(modbus(), now=T0)['id']
        with self.assertRaises(KeyError):
            r.set_state('nope', 'fixed')
        with self.assertRaises(ValueError):
            r.set_state(ident, 'ignored')

    def test_kept_across_runs(self):
        from src.exposures import ExposureRegistry
        path = os.path.join(tempfile.mkdtemp(), 'exposures.json')
        first = ExposureRegistry()
        first.attach(path)
        first.observe(ha_token(), now=T0)
        first.save(force=True)
        second = ExposureRegistry()
        second.attach(path)
        self.assertFalse(second.observe(ha_token(), now=T0 + DAY)['report'])

    def test_an_unreadable_file_starts_fresh(self):
        from src.exposures import ExposureRegistry
        path = os.path.join(tempfile.mkdtemp(), 'exposures.json')
        with open(path, 'w', encoding='utf-8') as f:
            f.write('{"entries": [{"id": 3}, "nonsense"]}')
        r = ExposureRegistry()
        r.attach(path)
        self.assertEqual(r.entries(), [])


class TestTheGateway(unittest.TestCase):

    def app(self):
        from src.app import NetSentinelApp
        from src.exposures import ExposureRegistry

        class _Verifier:
            def verify_alert(self, alert, ids_engine=None):
                pass

        app = NetSentinelApp.__new__(NetSentinelApp)
        app.emitted = []
        app._emit_alert = app.emitted.append
        app.alert_verifier, app.ids_engine, app.baseline_whitelist = _Verifier(), None, None
        app.exposures = ExposureRegistry()
        return app

    def test_an_exposure_is_alerted_once_and_an_event_every_time(self):
        app = self.app()
        for _ in range(3):
            app._verified_alert_gateway(ha_token())
            app._verified_alert_gateway(alert('PORT-SCAN', 'HIGH', port=0))
        self.assertEqual([a.rule_id for a in app.emitted],
                         ['FORENSICS-CREDENTIAL', 'PORT-SCAN', 'PORT-SCAN', 'PORT-SCAN'])

    def test_confirming_an_exposure_does_not_raise_it(self):
        from src.alert_verify import AlertVerdict, AlertVerifier
        v = AlertVerifier(reset_config())
        telnet = alert('FORENSICS-INSECURE-SVC', 'MEDIUM', dst=METER, port=23, service='Telnet')
        scan = alert('PORT-SCAN', 'MEDIUM')
        for a in (telnet, scan):
            v._adjust_severity(a, AlertVerdict.VERIFIED_THREAT, 0.9)
        self.assertEqual((telnet.severity, scan.severity), ('MEDIUM', 'HIGH'))
        self.assertTrue(telnet.title.startswith('[CONFIRMED]'))


class TestTheDashboard(_ApiTestCase):

    def setUp(self):
        super().setUp()
        from src.exposures import ExposureRegistry
        self.app.exposures = ExposureRegistry()
        self.ident = self.app.exposures.observe(ha_token(), now=T0)['id']

    def test_the_list_and_its_counts(self):
        page = self.get_json('/api/exposures')
        self.assertEqual([e['id'] for e in page['exposures']], [self.ident])
        self.assertTrue(page['controls'])
        self.assertEqual(self.get_json('/api/overview')['exposures']['open'], 1)

    def test_marking_one_needs_the_token(self):
        path = f'/api/exposures/state?id={self.ident}&state=accepted'
        self.assertEqual(self.post(path, token='wrong')[0], 403)
        self.assertEqual(self.app.exposures.entries()[0]['state'], 'open')
        status, reply = self.post(path)
        self.assertEqual((status, json.loads(reply)['state']), (200, 'accepted'))
        self.assertEqual(self.post('/api/exposures/state?id=nope&state=fixed')[0], 404)
        self.assertEqual(self.post(f'/api/exposures/state?id={self.ident}&state=gone')[0], 400)

    def test_the_page_shows_untrusted_text_as_text(self):
        """Titles and descriptions come off the network: textContent, never innerHTML."""
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(here, 'src', 'webui', 'app.js'), encoding='utf-8') as f:
            script = f.read()
        start = script.index('// ─── Exposures')
        section = script[start:script.index('// ─── Devices', start)]
        self.assertNotIn('innerHTML', section)


if __name__ == '__main__':
    unittest.main()
