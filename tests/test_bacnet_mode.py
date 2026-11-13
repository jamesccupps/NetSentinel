"""
BACnet on a building-controls PC.
=================================
On a PC that runs a building's HVAC controls, nearly every alert was BACnet,
and the desktop window barely opened. Every controller that answered
discovery (I-Am) was put in the vault as a "credential", which raised a
CRITICAL "[CONFIRMED] Plaintext Credential (BACnet)" filed under the broadcast
address and saying to change a password. BACnet and Modbus writes did the same.
There was no way to say that this PC's BACnet traffic is its job.

Now a device announcing itself goes to the device list, writes are findings
and never credentials, and bacnet.mode says what this PC is: 'watch' (the
default), 'workstation' or 'off'. Addresses are made-up LAN examples.
"""

import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_fourth_review import bvlc, confirmed, who_is  # noqa: E402
from test_third_review import T0, tcp, udp  # noqa: E402

WORKSTATION = '192.168.50.10'       # the PC running the building's controls
CONTROLLER = '192.168.50.31'
OTHER_HOST = '192.168.50.77'        # some other computer on the building network
BROADCAST = '192.168.50.255'


def i_am():
    """A controller's I-Am, broadcast: device 1, 1476-byte APDUs, vendor 5."""
    apdu = bytes([0x10, 0x00, 0xc4, 0x02, 0x00, 0x00, 0x01, 0x22, 0x05, 0xc4,
                  0x91, 0x03, 0x21, 0x05])
    return bvlc(b'\x01\x00' + apdu, function=0x0b)


def forensics(mode=None):
    """As the app makes it; with no mode, as it always was (watch)."""
    from src.forensics import NetworkForensics
    if mode is None:
        return NetworkForensics()
    return NetworkForensics(net_env=SimpleNamespace(local_ips={WORKSTATION}), bacnet_mode=mode)


def bacnet(f, src, dst, payload, ts=T0):
    f.analyze_packet(udp(src, 47808, dst, 47808, payload, ts=ts))


def kinds(f):
    return [d['data_type'] for d in f.sensitive_data]


MODBUS_WRITE = b'\x00\x01\x00\x00\x00\x06\x01\x06\x00\x10\x00\x2a'


class TestNothingHereIsACredential(unittest.TestCase):

    def test_a_device_announcing_itself_is_not_a_credential(self):
        f = forensics()
        heard = []
        f.on_bacnet_device = heard.append
        bacnet(f, CONTROLLER, BROADCAST, i_am())
        self.assertEqual(list(f.credentials_found), [])
        self.assertEqual(kinds(f), [])
        self.assertEqual(heard, [CONTROLLER])

    def test_a_bacnet_write_is_a_finding_not_a_credential(self):
        f = forensics()
        bacnet(f, OTHER_HOST, CONTROLLER, confirmed(service=15, invoke=1))
        self.assertEqual(kinds(f), ['BACnet WRITE'])
        self.assertEqual(list(f.credentials_found), [])

    def test_a_modbus_write_is_a_finding_not_a_credential(self):
        f = forensics()
        f.analyze_packet(tcp(OTHER_HOST, 59641, CONTROLLER, 502, payload=MODBUS_WRITE,
                             server=502))
        self.assertEqual(kinds(f), ['Modbus WRITE'])
        self.assertEqual(list(f.credentials_found), [])


class TestBroadcastsAreNoDevice(unittest.TestCase):
    """Controllers answer discovery to the broadcast address, which became an
    "Unencrypted BACnet Service" of its own."""

    def test_answers_to_the_broadcast_address_list_no_service(self):
        f = forensics()
        for i in range(6):
            bacnet(f, f'192.168.50.{40 + i}', BROADCAST, i_am())
        self.assertEqual(f.insecure_services, {})

    def test_the_subnets_own_broadcast_and_multicast_too(self):
        from src.forensics import NetworkForensics
        f = NetworkForensics(net_env=SimpleNamespace(local_ips={WORKSTATION},
                                                     local_subnet='192.168.50.0/25'))
        for dst in ('192.168.50.127', '239.255.255.250', '255.255.255.255'):
            for i in range(6):
                bacnet(f, CONTROLLER, dst, i_am())
        self.assertEqual(f.insecure_services, {})
        for i in range(6):
            bacnet(f, WORKSTATION, CONTROLLER, confirmed(service=12, invoke=i))
        self.assertEqual(list(f.insecure_services), [(CONTROLLER, 47808)])


class TestWorkstation(unittest.TestCase):
    """bacnet.mode 'workstation': this PC's own BACnet is its job."""

    def test_its_own_discovery_polling_and_writes_are_expected(self):
        f = forensics('workstation')
        bacnet(f, WORKSTATION, BROADCAST, who_is())
        bacnet(f, CONTROLLER, BROADCAST, i_am())
        bacnet(f, WORKSTATION, CONTROLLER, confirmed(service=12, invoke=1))
        bacnet(f, WORKSTATION, CONTROLLER, confirmed(service=15, invoke=2))
        self.assertEqual(kinds(f), [])
        self.assertEqual([e for e in f.timeline if e['type'] == 'bacnet'], [])

    def test_bacnet_is_not_listed_as_an_unencrypted_service(self):
        watch, workstation = forensics(), forensics('workstation')
        for f in (watch, workstation):
            for i in range(6):
                bacnet(f, WORKSTATION, CONTROLLER, confirmed(service=12, invoke=i))
        self.assertIn((CONTROLLER, 47808), watch.insecure_services)
        self.assertNotIn((CONTROLLER, 47808), workstation.insecure_services)

    def test_a_reset_is_still_reported_even_from_this_pc(self):
        f = forensics('workstation')
        bacnet(f, WORKSTATION, CONTROLLER, confirmed(service=20, invoke=3))
        self.assertEqual(kinds(f), ['BACnet RESET'])

    def test_another_computer_writing_or_discovering_still_alerts(self):
        f = forensics('workstation')
        bacnet(f, OTHER_HOST, CONTROLLER, confirmed(service=15, invoke=4))
        bacnet(f, OTHER_HOST, BROADCAST, who_is())
        self.assertEqual(kinds(f), ['BACnet WRITE', 'BACnet Discovery'])

    def test_in_watch_mode_this_pc_discovering_still_alerts(self):
        f = forensics('watch')
        bacnet(f, WORKSTATION, BROADCAST, who_is())
        self.assertEqual(kinds(f), ['BACnet Discovery'])


class TestOff(unittest.TestCase):

    def test_nothing_about_bacnet_is_recorded(self):
        """For a capture opened in the File Analyzer; live, the filter drops it."""
        f = forensics('off')
        bacnet(f, OTHER_HOST, CONTROLLER, confirmed(service=15, invoke=1))
        bacnet(f, OTHER_HOST, CONTROLLER, confirmed(service=20, invoke=2))
        bacnet(f, CONTROLLER, BROADCAST, i_am())
        self.assertEqual(kinds(f), [])
        self.assertEqual(f.insecure_services, {})
        self.assertEqual(list(f.timeline), [])

    def test_other_traffic_is_still_inspected(self):
        f = forensics('off')
        f.analyze_packet(tcp(OTHER_HOST, 59641, CONTROLLER, 502, payload=MODBUS_WRITE,
                             server=502))
        self.assertEqual(kinds(f), ['Modbus WRITE'])


class TestCaptureFilter(unittest.TestCase):

    def tearDown(self):
        reset_config(**{'bacnet.mode': 'watch'})

    def test_off_leaves_bacnet_out_of_the_capture(self):
        from src.config import DEFAULT_CONFIG, capture_filter
        cfg = reset_config(**{'bacnet.mode': 'off',
                              'capture.bpf_filter': DEFAULT_CONFIG['capture']['bpf_filter']})
        self.assertEqual(capture_filter(cfg), 'not udp portrange 47808-47823 and ('
                         + DEFAULT_CONFIG['capture']['bpf_filter'] + ')')
        cfg.set('capture', 'bpf_filter', '')
        self.assertEqual(capture_filter(cfg), 'not udp portrange 47808-47823')

    def test_the_other_modes_leave_the_filter_alone(self):
        from src.config import capture_filter
        for mode in ('watch', 'workstation', 'nonsense'):
            cfg = reset_config(**{'bacnet.mode': mode, 'capture.bpf_filter': 'not port 9'})
            self.assertEqual(capture_filter(cfg), 'not port 9', mode)

    def test_a_typed_mode_is_read_kindly_and_a_wrong_one_is_watch(self):
        from src.config import bacnet_mode
        self.assertEqual(bacnet_mode(reset_config(**{'bacnet.mode': ' Workstation '})),
                         'workstation')
        self.assertEqual(bacnet_mode(reset_config(**{'bacnet.mode': 'workstaton'})), 'watch')
        self.assertEqual(bacnet_mode(reset_config(**{'bacnet.mode': None})), 'watch')

    def test_the_settings_form_keeps_the_mode_a_word(self):
        from src.gui import _Choice, BACNET_CHOICES, settings_from_form
        choice = _Choice(SimpleNamespace(get=lambda: BACNET_CHOICES[1][1]), BACNET_CHOICES)
        values, bad = settings_from_form({'bacnet.mode': choice.get()})
        self.assertEqual((values, bad), ({'bacnet.mode': 'workstation'}, []))


class TestWhatWasSavedBefore(unittest.TestCase):

    def test_the_vault_drops_what_was_never_a_credential(self):
        import shutil
        from src.config import DB_DIR
        from src.forensics_db import ForensicsDB, _decrypt
        shutil.rmtree(os.path.join(DB_DIR, 'forensics'), ignore_errors=True)
        cfg = reset_config(**{'forensics.save_credentials': True,
                              'forensics.vault_passphrase': '',
                              'forensics.retention_days': 365})
        db = ForensicsDB(cfg)
        now = __import__('time').time()
        db.store_credential('BACnet', 'device_identity', '', 'BACnet device at x',
                            CONTROLLER, BROADCAST, 47808, now)
        db.store_credential('BACnet', 'control_command', '', 'WriteProperty from x',
                            WORKSTATION, CONTROLLER, 47808, now)
        db.store_credential('Modbus/SCADA', 'control_command', '', 'Unit 1',
                            WORKSTATION, CONTROLLER, 502, now)
        db.store_credential('FTP', 'password', '', 'hun*****', WORKSTATION, CONTROLLER, 21, now)
        db.flush()
        try:
            reopened = ForensicsDB(cfg)
            self.assertEqual([(c['protocol'], c['credential_type'])
                              for c in reopened.search_credentials()], [('FTP', 'password')])
            with open(reopened._creds_file, encoding='utf-8') as f:
                on_disk = json.loads(_decrypt(f.read(), reopened._key))
            self.assertEqual(len(on_disk), 1)
        finally:
            shutil.rmtree(os.path.join(DB_DIR, 'forensics'), ignore_errors=True)

    def test_exposures_drop_a_device_announcement_filed_as_a_login(self):
        from src.exposures import ExposureRegistry
        path = os.path.join(tempfile.mkdtemp(), 'exposures.json')
        old = {'state': 'open', 'severity': 'HIGH', 'first_seen': T0, 'last_seen': T0,
               'count': 1, 'kind': 'credential'}
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({'version': 1, 'entries': [
                dict(old, id='a1', key=['credential', 'BACnet', 'device_identity',
                                        BROADCAST, '47808'], device=BROADCAST, port=47808),
                dict(old, id='b2', key=['credential', 'FTP', 'password', CONTROLLER, '21'],
                     device=CONTROLLER, port=21)]}, f)
        r = ExposureRegistry()
        r.attach(path)
        self.assertEqual([e['id'] for e in r.entries()], ['b2'])


class TestDeviceList(unittest.TestCase):

    def learner(self):
        from src.device_learner import DeviceLearner
        dl = DeviceLearner(reset_config(), net_env=SimpleNamespace(local_ips={WORKSTATION},
                                                                   gateways=[]))
        dl.devices.clear()
        return dl

    def test_a_device_that_announces_itself_is_a_building_controller(self):
        dl = self.learner()
        dl.note_bacnet_device(CONTROLLER)
        self.assertEqual(dl.get_device(CONTROLLER).device_type, 'building_controller')

    def test_this_pc_answering_discovery_is_not_one(self):
        dl = self.learner()
        dl.note_bacnet_device(WORKSTATION)
        dl.note_bacnet_device('8.8.8.8')
        self.assertEqual(dl.devices, {})

    def test_the_app_tells_the_device_list(self):
        """Wired in app.py: forensics' I-Am reaches DeviceLearner.note_bacnet_device."""
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'src', 'app.py')
        with open(path, encoding='utf-8') as f:
            self.assertIn('self.forensics.on_bacnet_device = '
                          'self.device_learner.note_bacnet_device', f.read())


class TestVaultHelpers(unittest.TestCase):

    def test_an_unknown_port_is_left_off(self):
        """The alert showed a BACnet device's source as '...:0'."""
        from src.presentation import endpoint
        self.assertEqual(endpoint(CONTROLLER, 0), CONTROLLER)
        self.assertEqual(endpoint(CONTROLLER, None), CONTROLLER)
        self.assertEqual(endpoint(CONTROLLER, 47808), f'{CONTROLLER}:47808')
        self.assertEqual(endpoint('', 80), '')

    def test_the_table_is_newest_first_and_capped(self):
        from src.presentation import vault_rows
        creds = [{'timestamp': t} for t in range(5000)]
        rows, total = vault_rows(creds, limit=2000)
        self.assertEqual((len(rows), total), (2000, 5000))
        self.assertEqual(rows[0]['timestamp'], 4999)

    def test_an_alert_finds_its_vault_entry(self):
        from src.presentation import find_vault_entry
        creds = [
            {'protocol': 'HTTP', 'destination_ip': CONTROLLER, 'port': 80,
             'source_ip': OTHER_HOST, 'credential_type': 'basic_auth', 'timestamp': 3},
            {'protocol': 'HTTP', 'destination_ip': CONTROLLER, 'port': 80,
             'source_ip': WORKSTATION, 'credential_type': 'basic_auth', 'timestamp': 1},
            {'protocol': 'FTP', 'destination_ip': CONTROLLER, 'port': 21,
             'source_ip': WORKSTATION, 'credential_type': 'password', 'timestamp': 2},
        ]
        self.assertIs(find_vault_entry(creds, 'HTTP', CONTROLLER, 80, client=WORKSTATION,
                                       credential_type='basic_auth'), creds[1])
        self.assertIs(find_vault_entry(creds, 'HTTP', CONTROLLER, '80'), creds[0])
        self.assertIsNone(find_vault_entry(creds, 'Telnet', CONTROLLER, 23))


if __name__ == '__main__':
    unittest.main()
