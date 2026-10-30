"""
Restricted segments, for findings that never went through enrichment.
======================================================================
Redaction for the model checked the VLAN fields enrichment writes onto an
event. Canary hits and configuration findings never pass through enrichment:
a canary event carries the visitor's address and no VLAN, and a drift finding
carries a VLAN list, a network name or a forward target and no packet at all.
Both reached the model whatever segment they named. Everything here uses the
example profile, where VLANs 40 (access control) and 50 (kiosks) are
metadata-only.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.canary import finding_for, parse_event  # noqa: E402
from netmon.drift import audit as drift_audit, diff as drift_diff  # noqa: E402
from netmon.events import Event, Finding  # noqa: E402
from netmon.profile import load_profile  # noqa: E402
from netmon.redact import (AI, ALERT, audit, device_is_restricted,  # noqa: E402
                           redact_finding, redact_findings, summary_for_model)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROFILE = load_profile(os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml'))


def canary(src, dst='10.10.20.250', logtype=4002):
    return finding_for(parse_event({'logtype': logtype, 'src_host': src,
                                    'dst_host': dst, 'dst_port': 22,
                                    'logdata': {'USERNAME': 'root'}}), PROFILE)


def withheld(finding):
    return redact_finding(finding, PROFILE, audience=AI) is None


class TestCanaryHits(unittest.TestCase):

    def test_a_visitor_from_the_access_control_vlan_is_withheld(self):
        self.assertTrue(withheld(canary('10.10.40.10')))

    def test_a_canary_placed_on_the_kiosk_vlan_is_withheld(self):
        self.assertTrue(withheld(canary('10.10.60.99', dst='10.10.50.200')))

    def test_an_ordinary_hit_still_goes(self):
        self.assertFalse(withheld(canary('10.10.60.99')))

    def test_alerts_still_carry_them(self):
        """Metadata from a restricted segment is what an alert is for."""
        record = redact_finding(canary('10.10.40.10'), PROFILE, audience=ALERT)
        self.assertIsNotNone(record)
        self.assertIn('door-panel-north', record['description'])


def _state(**sections):
    base = {'networks': [{'_id': 'n40', 'name': 'access-control', 'vlan': 40},
                         {'_id': 'n20', 'name': 'building-automation', 'vlan': 20}],
            'port_profiles': [], 'port_forwards': [], 'firewall_rules': [],
            'wlans': [], 'ports': {}}
    base.update(sections)
    return base


class TestConfigurationFindings(unittest.TestCase):

    def test_a_port_profile_tagging_a_restricted_vlan_is_withheld(self):
        findings = drift_audit(_state(port_profiles=[
            {'_id': 'p1', 'name': 'trunk', 'tagged_networkconf_ids': ['n40']}]),
            PROFILE)
        self.assertEqual([f.rule_id for f in findings], ['vlan_leak'])
        self.assertTrue(withheld(findings[0]))

    def test_a_forward_into_a_restricted_subnet_is_withheld(self):
        findings = drift_audit(_state(port_forwards=[
            {'_id': 'f1', 'name': 'kiosk-admin', 'dst_port': '8443',
             'fwd': '10.10.50.20', 'fwd_port': '443', 'proto': 'tcp'}]), PROFILE)
        self.assertEqual(len(findings), 1)
        self.assertTrue(withheld(findings[0]))

    def test_a_forward_elsewhere_still_goes(self):
        findings = drift_audit(_state(port_forwards=[
            {'_id': 'f2', 'name': 'bas-ui', 'dst_port': '443',
             'fwd': '10.10.20.10', 'fwd_port': '443', 'proto': 'tcp'}]), PROFILE)
        self.assertFalse(withheld(findings[0]))

    def test_a_new_restricted_network_is_withheld(self):
        previous = _state()
        current = _state(networks=previous['networks'] + [
            {'_id': 'n50', 'name': 'kiosks', 'vlan': 50,
             'ip_subnet': '10.10.50.0/24'}])
        findings = [f for f in drift_diff(previous, current, PROFILE)
                    if f.rule_id == 'new_network']
        self.assertEqual(len(findings), 1)
        self.assertTrue(withheld(findings[0]))

    def test_a_port_profile_gaining_a_restricted_network_is_withheld(self):
        previous = _state(port_profiles=[{'_id': 'p1', 'name': 'trunk',
                                          'tagged_networkconf_ids': []}])
        current = _state(port_profiles=[{'_id': 'p1', 'name': 'trunk',
                                         'tagged_networkconf_ids': ['n40']}])
        gained = [f for f in drift_diff(previous, current, PROFILE)
                  if f.title == 'A port profile gained a VLAN']
        self.assertEqual(len(gained), 1)
        self.assertTrue(withheld(gained[0]))

    def test_a_disabled_rule_naming_nothing_restricted_still_goes(self):
        findings = drift_audit(_state(firewall_rules=[
            {'_id': 'r1', 'name': 'block guest', 'enabled': False,
             'ruleset': 'LAN_IN', 'action': 'drop'}]), PROFILE)
        self.assertFalse(withheld(findings[0]))


class TestByDeviceAndZone(unittest.TestCase):

    def test_a_finding_naming_a_restricted_device_is_withheld(self):
        self.assertTrue(withheld(Finding('x', 't', device='door-panel-north',
                                         description='something')))

    def test_a_restricted_mac_is_withheld(self):
        self.assertTrue(withheld(Finding('x', 't', device='00:11:22:00:00:30')))

    def test_a_zone_only_restricted_vlans_use_is_withheld(self):
        self.assertTrue(withheld(Finding('x', 't', device='somewhere',
                                         evidence={'zone': 'restricted'})))

    def test_an_ordinary_zone_is_not(self):
        self.assertFalse(withheld(Finding('x', 't', device='somewhere',
                                          evidence={'zone': 'ot'})))

    def test_an_address_in_the_text_is_enough(self):
        self.assertTrue(withheld(Finding(
            'x', 't', description='something reached 10.10.40.11 at night')))

    def test_an_unenriched_event_is_resolved_from_its_addresses(self):
        event = Event(kind='flow', src_ip='10.10.60.50', dst_ip='10.10.50.20')
        self.assertTrue(withheld(Finding('x', 't', device='ops-workstation',
                                         event=event)))

    def test_a_lookalike_name_is_not_a_match(self):
        self.assertFalse(withheld(Finding('x', 't', device='ops-workstation',
                                          description='door-panel-northwest wing')))


class TestTheSummary(unittest.TestCase):

    class _Window:
        def __init__(self, findings):
            self.findings = findings
            self.events_seen = 10

        def by_severity(self):
            return list(self.findings)

    def test_withheld_canary_and_drift_findings_are_counted_not_sent(self):
        restricted = drift_audit(_state(port_profiles=[
            {'_id': 'p1', 'name': 'trunk', 'tagged_networkconf_ids': ['n40']}]),
            PROFILE)
        window = self._Window([canary('10.10.40.10'), canary('10.10.60.99')]
                              + restricted)
        payload = summary_for_model(window, PROFILE)
        self.assertEqual(payload['withheld_from_restricted_segments'], 2)
        self.assertEqual(len(payload['findings']), 1)
        text = str(payload)
        for leaked in ('10.10.40', 'door-panel', 'access-control', 'trunk'):
            self.assertNotIn(leaked, text)
        self.assertEqual(audit(payload), [])

    def test_redact_findings_counts_the_same(self):
        records, count = redact_findings([canary('10.10.40.10')], PROFILE, AI)
        self.assertEqual((records, count), ([], 1))


class TestInvestigate(unittest.TestCase):

    def test_a_restricted_device_is_refused_even_with_no_findings(self):
        from netmon.summarise import Summariser, SummariserConfig, SummaryError

        class _Empty:
            findings = []
            events_seen = 0

        class _Client:
            def __getattr__(self, name):
                raise AssertionError('nothing may be sent')

        summariser = Summariser(SummariserConfig(api_key='x'), client=_Client())
        for device in ('door-panel-north', '10.10.40.10', '00:11:22:00:00:30'):
            with self.subTest(device=device):
                with self.assertRaises(SummaryError) as ctx:
                    summariser.investigate(_Empty(), PROFILE, device)
                self.assertIn('not sent', str(ctx.exception))

    def test_the_helper(self):
        self.assertTrue(device_is_restricted('kiosk-entry', PROFILE))
        self.assertFalse(device_is_restricted('bas-server', PROFILE))


if __name__ == '__main__':
    unittest.main(verbosity=2)
