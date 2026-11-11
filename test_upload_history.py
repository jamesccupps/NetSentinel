"""
Uploads judged by program, destination and their own history.
==============================================================
A week of 1.14 on the owner's network raised 13 HIGH "Large Data Transfer"
alerts for three routine pairs: Tailscale to one peer, Chrome Remote Desktop to
the same machine, and Claude to Anthropic. The rule counted bytes per address,
alerted at 100 MB, doubled, and forgot the address when it went quiet, so every
day started again; its check rated Tailscale more suspicious as bytes grew and
"direct IP" counted against a VPN whose peers are all direct IPs.
Addresses are public example ones (documentation ranges count as private here,
so an upload to one never leaves the network) or made up.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_third_review import T0, DAY, PC, tcp  # noqa: E402

PEER = '93.184.216.34'
OTHER = '5.5.5.5'
MB = 1024 * 1024


def engine(floor_mb=1):
    from src.ids_engine import IDSEngine
    cfg = reset_config()
    cfg.set('ids', 'large_upload_mb', floor_mb)
    alerts = []
    return IDSEngine(cfg, alert_callback=alerts.append), alerts


def upload(ids, mb, dst=PEER, process='tailscaled.exe', ts=T0, step=1.0):
    """mb of 1460-byte segments, one every step seconds' worth of a minute."""
    n = int(mb * MB / 1460) + 1
    for i in range(n):
        p = tcp(PC, 41641, dst, 443, b'\x00' * 1460, ts=ts + i * step / n * 60)
        p.process_name = process
        ids.inspect_packet(p)


def exfil(alerts):
    return [a for a in alerts if a.rule_id == 'DATA-EXFIL']


class TestTheHistory(unittest.TestCase):

    def test_the_first_large_upload_of_a_pair_is_reported(self):
        ids, alerts = engine()
        upload(ids, 1.2)
        [alert] = exfil(alerts)
        self.assertTrue(alert.evidence['first_large_upload'])
        self.assertEqual(alert.evidence['process'], 'tailscaled.exe')
        self.assertIn('first large upload', alert.evidence['description'])
        self.assertEqual(str(getattr(alert.severity, 'name', alert.severity)), 'HIGH')

    def test_a_day_like_its_usual_is_quiet_and_four_times_it_is_not(self):
        ids, alerts = engine()
        upload(ids, 1.2)                          # day one: reported
        upload(ids, 1.2, ts=T0 + DAY)             # day two, the same: quiet
        upload(ids, 3.0, ts=T0 + 2 * DAY)         # day three, under 4 x 1.2: quiet
        self.assertEqual(len(exfil(alerts)), 1)
        upload(ids, 13.0, ts=T0 + 3 * DAY)        # past 4 x its biggest day (3.0)
        later = exfil(alerts)[1:]
        self.assertEqual(len(later), 1, [a.description for a in later])
        ev = later[0].evidence
        self.assertFalse(ev['first_large_upload'])
        self.assertEqual(ev['usual_daily_max_mb'], 3.0)
        self.assertEqual(ev['days_with_uploads'], 3)
        self.assertEqual(ev['threshold_mb'], 12.0)
        self.assertIn('biggest day here', ev['description'])

    def test_one_day_escalates_by_four_not_two(self):
        ids, alerts = engine()
        upload(ids, 4.5, step=10)
        self.assertEqual([round(a.evidence['threshold_mb']) for a in exfil(alerts)], [1, 4])

    def test_another_program_to_the_same_place_has_its_own_history(self):
        ids, alerts = engine()
        upload(ids, 1.2)
        upload(ids, 1.2, ts=T0 + DAY)
        upload(ids, 1.2, ts=T0 + DAY + 600, process='unknown_tool.exe')
        self.assertEqual([a.evidence['process'] for a in exfil(alerts)],
                         ['tailscaled.exe', 'unknown_tool.exe'])

    def test_one_service_on_several_addresses_shares_a_history(self):
        """By the registrable domain a DNS answer gave the address."""
        ids, alerts = engine()
        ids._ip_vouched[PEER].add('upload.example.com')
        ids._ip_vouched[OTHER].add('files.example.com')
        upload(ids, 1.2, process='claude.exe')
        upload(ids, 1.2, dst=OTHER, process='claude.exe', ts=T0 + DAY)
        self.assertEqual(len(exfil(alerts)), 1)

    def test_a_pair_marked_real_is_reported_from_the_floor_again(self):
        ids, alerts = engine()
        upload(ids, 1.2)
        ids.uploads.hold('tailscaled.exe', PEER)
        upload(ids, 1.2, ts=T0 + DAY)
        second = exfil(alerts)[1]
        self.assertIn('marked real', second.evidence['description'])

    def test_a_held_pair_learns_nothing(self):
        from src.upload_history import UploadHistory
        h = UploadHistory(1)
        h.hold('x.exe', PEER)
        h.add('x.exe', PEER, 1.5 * MB, T0)
        self.assertIsNotNone(h.add('x.exe', PEER, 1.5 * MB, T0 + DAY))


class TestUpkeep(unittest.TestCase):

    def test_kept_across_runs(self):
        from src.upload_history import UploadHistory
        path = os.path.join(tempfile.mkdtemp(), 'uploads.json')
        first = UploadHistory(1)
        first.attach(path)
        first.add('tailscaled.exe', PEER, 1.5 * MB, T0)
        first.flush(T0 + 60)
        first.save(force=True)
        with open(path, encoding='utf-8') as f:
            self.assertIn('tailscaled.exe|ip:' + PEER, json.load(f)['pairs'])
        second = UploadHistory(1)
        second.attach(path)
        self.assertIsNone(second.add('tailscaled.exe', PEER, 1.5 * MB, T0 + DAY))

    def test_without_a_file_nothing_is_written(self):
        """Engines in tests (and capture analysis) keep it in memory only."""
        from src.upload_history import UploadHistory
        h = UploadHistory(1)
        h.add('a.exe', PEER, 2 * MB, T0)
        h.save(force=True)                    # no path: nothing to do, no error
        self.assertIsNone(h.path)

    def test_days_past_thirty_are_forgotten(self):
        from src.upload_history import UploadHistory
        h = UploadHistory(1)
        h.add('a.exe', PEER, 1.5 * MB, T0)
        h.flush(T0 + 31 * DAY)
        self.assertEqual(h._pairs, {})
        self.assertIsNotNone(h.add('a.exe', PEER, 1.5 * MB, T0 + 31 * DAY))

    def test_an_unreadable_file_starts_fresh(self):
        from src.upload_history import UploadHistory
        path = os.path.join(tempfile.mkdtemp(), 'uploads.json')
        with open(path, 'w', encoding='utf-8') as f:
            f.write('{"pairs": {"a|ip:x": {"days": {"2026-11-01": "lots"}}, "b": 3}}')
        h = UploadHistory(1)
        h.attach(path)
        self.assertEqual(h._pairs, {'a|ip:x': {'days': {}, 'held': False}})


class _Verifier:
    """A process verifier that answers with the signature it was given."""

    def __init__(self, valid, signed=True, publisher='CN=Tailscale Inc., O=Tailscale Inc.',
                 trusted=False, verdict='LIKELY_SAFE'):
        self.result = {'verdict': verdict, 'summary': '', 'checks': {
            'digital_signature': {'signed': signed, 'valid': valid, 'publisher': publisher},
            'trusted_publisher': trusted}}

    def verify_process(self, process_name=None, pid=None, exe_path=None):
        return self.result


class TestTheCheck(unittest.TestCase):

    def check(self, process='tailscaled.exe', mb=120, verifier=None, **extra):
        from src.alert_verify import AlertVerifier
        from src.ids_engine import Alert
        evidence = {'destination_ip': PEER, 'megabytes_transferred': mb,
                    'process': process, 'pid': 4242, 'first_large_upload': True, **extra}
        alert = Alert('DATA-EXFIL', 'HIGH', 't', 'd', src_ip=PC, dst_ip=PEER,
                      evidence=evidence)
        v = AlertVerifier(reset_config(), process_verifier=verifier)
        return v._verify_data_exfil(alert, evidence, None), evidence

    def test_a_signed_vpn_to_its_peer_is_not_a_likely_threat(self):
        out, ev = self.check(verifier=_Verifier(valid=True))
        self.assertEqual(out['verdict'], 'INCONCLUSIVE')
        self.assertIn('signed by Tailscale Inc.', ' '.join(out['reasoning']))
        self.assertEqual(ev['program_check']['signed_by'], 'Tailscale Inc.')
        out, _ = self.check(mb=420, verifier=_Verifier(valid=True))
        self.assertEqual(out['verdict'], 'INCONCLUSIVE', out['reasoning'])

    def test_an_unsigned_program_to_a_bare_address_still_is(self):
        out, _ = self.check(process='updater.exe',
                            verifier=_Verifier(valid=False, signed=False))
        self.assertEqual(out['verdict'], 'LIKELY_THREAT')

    def test_a_broken_signature_is_worse_than_none(self):
        out, ev = self.check(verifier=_Verifier(valid=False, signed=True))
        self.assertEqual(out['verdict'], 'VERIFIED_THREAT')
        self.assertEqual(ev['program_check']['signature'], 'does not verify')

    def test_a_signed_general_purpose_tool_gets_no_credit(self):
        out, _ = self.check(process='curl.exe', verifier=_Verifier(
            valid=True, publisher='CN=Microsoft Windows', trusted=True))
        self.assertEqual(out['verdict'], 'LIKELY_THREAT')
        self.assertIn('general-purpose tool', ' '.join(out['reasoning']))

    def test_a_known_pair_past_its_usual_counts_against_it(self):
        base, _ = self.check(verifier=_Verifier(valid=True))
        known, _ = self.check(verifier=_Verifier(valid=True), first_large_upload=False,
                              days_with_uploads=12, usual_daily_max_mb=30)
        self.assertGreater(known['confidence'], base['confidence'])
        self.assertIn('12 of the last 30 days', ' '.join(known['reasoning']))

    def test_without_a_verifier_a_name_is_still_only_a_name(self):
        out, _ = self.check(process='msedge.exe')
        self.assertIn('by name', ' '.join(out['reasoning']))

    def test_the_check_runs_off_the_packet_path(self):
        from src import app
        self.assertIn('DATA-EXFIL', app._SLOW_VERIFY_RULES)


class TestAVerdictOfReal(unittest.TestCase):

    def test_real_holds_the_pair(self):
        from src.app import NetSentinelApp
        from src.ids_engine import Alert
        ids, _ = engine()
        app = NetSentinelApp.__new__(NetSentinelApp)
        alert = Alert('DATA-EXFIL', 'HIGH', 't', 'd', src_ip=PC, dst_ip=PEER,
                      evidence={'destination_ip': PEER, 'process': 'tailscaled.exe'})

        class _Manager:
            def get_alert(self, alert_id):
                return alert

            def acknowledge_alert(self, alert_id):
                alert.acknowledged = True

        class _Baseline:
            confirmed = None

        app.alert_manager, app.review, app.ids_engine = _Manager(), None, ids
        app.baseline_whitelist = _Baseline()
        app.record_verdict(1, 'real')
        self.assertTrue(ids.uploads._pairs['tailscaled.exe|ip:' + PEER]['held'])


if __name__ == '__main__':
    unittest.main()
