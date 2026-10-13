"""
Configuration drift.
====================
The packet rules watch what the network does; this watches what it is allowed to
do, and that changes without any packet being unusual.

The split these tests are mostly about: a **standing** problem is wrong on the
first run and the hundredth, and a finding that only appeared the moment it
changed would miss every site that was already misconfigured. **Drift** needs a
baseline, so the first run records one and reports nothing — reporting the whole
configuration as new would be true and useless.
"""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.drift import (CONFIG_ENDPOINTS, audit, check, diff,  # noqa: E402
                          format_findings, load_state, save_state, snapshot)
from netmon.events import Severity, Tier  # noqa: E402
from netmon.profile import SiteProfile  # noqa: E402
from netmon.redact import ALERT, audit as redaction_audit, redact_finding  # noqa: E402


def profile():
    return SiteProfile({
        'site': {'name': 'test'},
        'vlans': {20: {'name': 'ot', 'subnet': '10.10.20.0/24', 'zone': 'ot'},
                  40: {'name': 'restricted', 'subnet': '10.10.40.0/24',
                       'store_payload': False}},
    })


def state(**overrides):
    """A controller configuration with nothing wrong with it."""
    data = {
        'taken_at': 1790000000.0, 'site': 'default', 'host': 'https://x',
        'errors': {},
        'networks': [{'_id': 'n20', 'name': 'ot', 'vlan': 20,
                      'ip_subnet': '10.10.20.0/24'},
                     {'_id': 'n40', 'name': 'restricted', 'vlan': 40,
                      'ip_subnet': '10.10.40.0/24'}],
        'port_profiles': [{'_id': 'p1', 'name': 'OT only', 'forward': 'customize',
                           'native_networkconf_id': 'n20',
                           'tagged_networkconf_ids': []}],
        'port_forwards': [],
        'firewall_rules': [{'_id': 'f1', 'name': 'block ot to wan',
                            'enabled': True, 'action': 'drop',
                            'ruleset': 'LAN_OUT'}],
        'firewall_groups': [],
        'wlans': [{'_id': 'w1', 'name': 'Staff', 'enabled': True,
                   'security': 'wpapsk', 'is_guest': False}],
        'devices': [{'_id': 'd1', 'mac': '00:11:22:33:44:55', 'name': 'sw1'}],
        'ports': {'00:11:22:33:44:55/1': {'name': 'ahu', 'portconf_id': 'p1',
                                          'up': True, 'enable': True}},
    }
    data.update(overrides)
    return data


def rules_fired(findings):
    return sorted({f.rule_id for f in findings})


# ─── Standing problems ───────────────────────────────────────────────────────

class TestStandingProblems(unittest.TestCase):
    """
    Wrong now, reported until fixed. These need no baseline: a port profile
    allowing every VLAN is wrong on the first run too.
    """

    def test_a_clean_configuration_produces_nothing(self):
        self.assertEqual(audit(state(), profile()), [])

    def test_a_port_profile_forwarding_everything(self):
        findings = audit(state(port_profiles=[
            {'_id': 'p1', 'name': 'All networks', 'forward': 'all'}]), profile())
        self.assertEqual(rules_fired(findings), ['vlan_leak'])
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].tier, Tier.PUSH)

    def test_the_finding_explains_why_all_is_usually_a_mistake(self):
        findings = audit(state(port_profiles=[
            {'_id': 'p1', 'name': 'All', 'forward': 'all'}]), profile())
        self.assertIn('default', findings[0].next_check)

    def test_a_profile_tagging_a_metadata_only_segment(self):
        findings = audit(state(port_profiles=[
            {'_id': 'p1', 'name': 'Mixed', 'forward': 'customize',
             'tagged_networkconf_ids': ['n40']}]), profile())
        self.assertEqual(rules_fired(findings), ['vlan_leak'])
        self.assertIn('40', findings[0].description)

    def test_tagging_an_ordinary_segment_is_fine(self):
        self.assertEqual(audit(state(port_profiles=[
            {'_id': 'p1', 'name': 'Mixed', 'forward': 'customize',
             'tagged_networkconf_ids': ['n20']}]), profile()), [])

    def test_an_enabled_port_forward_is_reported(self):
        findings = audit(state(port_forwards=[
            {'_id': 'pf1', 'name': 'web', 'enabled': True, 'src': 'any',
             'dst_port': '443', 'fwd': '192.168.1.239', 'fwd_port': '443',
             'proto': 'tcp'}]), profile())
        self.assertEqual(rules_fired(findings), ['exposure_change'])
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_a_forward_from_a_named_source_is_milder(self):
        findings = audit(state(port_forwards=[
            {'_id': 'pf1', 'name': 'vendor', 'enabled': True,
             'src': '203.0.113.9', 'dst_port': '22', 'fwd': '10.10.20.10',
             'fwd_port': '22', 'proto': 'tcp'}]), profile())
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_a_disabled_forward_is_not_reported(self):
        self.assertEqual(audit(state(port_forwards=[
            {'_id': 'pf1', 'name': 'old', 'enabled': False, 'src': 'any',
             'dst_port': '80'}]), profile()), [])

    def test_a_disabled_firewall_rule_is_reported(self):
        findings = audit(state(firewall_rules=[
            {'_id': 'f1', 'name': 'block ot to wan', 'enabled': False,
             'action': 'drop', 'ruleset': 'LAN_OUT'}]), profile())
        self.assertEqual(rules_fired(findings), ['firewall_rule_disabled'])

    def test_that_finding_says_why_a_disabled_rule_matters(self):
        """It reads as protection that is not there."""
        findings = audit(state(firewall_rules=[
            {'_id': 'f1', 'name': 'x', 'enabled': False, 'action': 'drop'}]),
            profile())
        self.assertIn('not there', findings[0].next_check)

    def test_an_open_wireless_network(self):
        findings = audit(state(wlans=[
            {'_id': 'w1', 'name': 'Open', 'enabled': True, 'security': 'open',
             'is_guest': False}]), profile())
        self.assertEqual(rules_fired(findings), ['open_wireless'])
        self.assertEqual(findings[0].tier, Tier.PUSH)

    def test_an_open_guest_network_is_milder(self):
        findings = audit(state(wlans=[
            {'_id': 'w1', 'name': 'Guest', 'enabled': True, 'security': 'open',
             'is_guest': True}]), profile())
        self.assertEqual(findings[0].severity, Severity.LOW)
        self.assertEqual(findings[0].tier, Tier.DIGEST)

    def test_a_disabled_wireless_network_is_not_reported(self):
        self.assertEqual(audit(state(wlans=[
            {'_id': 'w1', 'name': 'Old', 'enabled': False,
             'security': 'open'}]), profile()), [])

    def test_junk_rows_do_not_stop_the_audit(self):
        findings = audit(state(port_profiles=[None, 'junk', 42,
                                              {'_id': 'p', 'name': 'All',
                                               'forward': 'all'}]), profile())
        self.assertEqual(rules_fired(findings), ['vlan_leak'])

    def test_an_empty_configuration_is_not_an_error(self):
        self.assertEqual(audit({}, profile()), [])

    def test_it_works_without_a_profile(self):
        findings = audit(state(port_profiles=[
            {'_id': 'p1', 'name': 'All', 'forward': 'all'}]))
        self.assertEqual(rules_fired(findings), ['vlan_leak'])


# ─── Drift ───────────────────────────────────────────────────────────────────

class TestDrift(unittest.TestCase):

    def test_a_first_run_reports_nothing(self):
        """
        Reporting the whole configuration as new would be true and useless, and
        would teach whoever set it up to ignore the next run too.
        """
        self.assertEqual(diff(None, state(), profile()), [])
        self.assertEqual(diff({}, state(), profile()), [])

    def test_no_change_reports_nothing(self):
        self.assertEqual(diff(state(), state(), profile()), [])

    def test_a_new_port_forward(self):
        after = state(port_forwards=[
            {'_id': 'pf1', 'name': 'new thing', 'enabled': True, 'src': 'any',
             'dst_port': '8080', 'fwd': '10.10.20.10', 'fwd_port': '8080',
             'proto': 'tcp'}])
        findings = diff(state(), after, profile())
        self.assertEqual(rules_fired(findings), ['exposure_change'])
        self.assertEqual(findings[0].tier, Tier.PUSH)
        self.assertIn('8080', findings[0].description)

    def test_a_removed_port_forward_is_noted_not_alarming(self):
        before = state(port_forwards=[
            {'_id': 'pf1', 'name': 'old', 'enabled': True, 'dst_port': '80'}])
        findings = diff(before, state(), profile())
        self.assertEqual(findings[0].severity, Severity.INFO)

    def test_a_deleted_firewall_rule(self):
        findings = diff(state(), state(firewall_rules=[]), profile())
        self.assertEqual(rules_fired(findings), ['firewall_change'])
        self.assertEqual(findings[0].tier, Tier.PUSH)
        self.assertIn('documentation', findings[0].next_check)

    def test_a_firewall_rule_turned_off(self):
        after = state(firewall_rules=[
            {'_id': 'f1', 'name': 'block ot to wan', 'enabled': False,
             'action': 'drop', 'ruleset': 'LAN_OUT'}])
        findings = diff(state(), after, profile())
        changes = [f for f in findings if f.rule_id == 'firewall_change']
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].severity, Severity.HIGH)

    def test_a_rule_that_changed_from_drop_to_accept(self):
        after = state(firewall_rules=[
            {'_id': 'f1', 'name': 'block ot to wan', 'enabled': True,
             'action': 'accept', 'ruleset': 'LAN_OUT'}])
        findings = diff(state(), after, profile())
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn('accept', findings[0].description)

    def test_a_new_firewall_rule_is_milder_than_a_deleted_one(self):
        after = state(firewall_rules=state()['firewall_rules'] + [
            {'_id': 'f2', 'name': 'extra', 'enabled': True, 'action': 'drop'}])
        findings = diff(state(), after, profile())
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_a_port_profile_switched_to_all(self):
        after = state(port_profiles=[
            {'_id': 'p1', 'name': 'OT only', 'forward': 'all'}])
        findings = diff(state(), after, profile())
        leaks = [f for f in findings if f.rule_id == 'vlan_leak']
        self.assertEqual(leaks[0].severity, Severity.HIGH)
        self.assertIn('all of them at once', leaks[0].next_check)

    def test_a_port_profile_that_gained_a_vlan(self):
        after = state(port_profiles=[
            {'_id': 'p1', 'name': 'OT only', 'forward': 'customize',
             'tagged_networkconf_ids': ['n40']}])
        findings = diff(state(), after, profile())
        gained = [f for f in findings if 'gained' in f.title]
        self.assertEqual(len(gained), 1)
        self.assertIn('restricted', gained[0].description)

    def test_a_switch_port_that_changed_profile(self):
        after = state(
            port_profiles=state()['port_profiles'] + [
                {'_id': 'p2', 'name': 'All networks', 'forward': 'all'}],
            ports={'00:11:22:33:44:55/1': {'name': 'ahu', 'portconf_id': 'p2',
                                           'up': True, 'enable': True}})
        findings = diff(state(), after, profile())
        changes = [f for f in findings if f.rule_id == 'port_profile_change']
        self.assertEqual(len(changes), 1)
        self.assertIn('All networks', changes[0].description)

    def test_a_per_port_override_counts_as_the_assignment(self):
        after = state(ports={'00:11:22:33:44:55/1': {
            'name': 'ahu', 'portconf_id': 'p1',
            'override_portconf_id': 'p2', 'up': True}})
        findings = diff(state(), after, profile())
        self.assertTrue([f for f in findings if f.rule_id == 'port_profile_change'])

    def test_a_new_network(self):
        after = state(networks=state()['networks'] + [
            {'_id': 'n99', 'name': 'new vlan', 'vlan': 99,
             'ip_subnet': '10.10.99.0/24'}])
        findings = diff(state(), after, profile())
        self.assertEqual(rules_fired(findings), ['new_network'])
        self.assertIn('site profile', findings[0].next_check)

    def test_a_new_wireless_network(self):
        after = state(wlans=state()['wlans'] + [
            {'_id': 'w2', 'name': 'Added', 'enabled': True,
             'security': 'wpapsk'}])
        findings = diff(state(), after, profile())
        self.assertEqual(rules_fired(findings), ['new_wireless'])

    def test_a_new_open_wireless_network_is_worse(self):
        after = state(wlans=state()['wlans'] + [
            {'_id': 'w2', 'name': 'Added', 'enabled': True, 'security': 'open'}])
        findings = diff(state(), after, profile())
        new = [f for f in findings if f.rule_id == 'new_wireless']
        self.assertEqual(new[0].severity, Severity.HIGH)

    def test_the_timestamp_is_the_snapshot_not_now(self):
        """So a finding from a nightly run reads with the time it was taken."""
        after = state(taken_at=1790000999.0, firewall_rules=[])
        findings = diff(state(), after, profile())
        self.assertEqual(findings[0].ts, 1790000999.0)

    def test_several_changes_at_once(self):
        after = state(
            firewall_rules=[],
            port_forwards=[{'_id': 'pf1', 'name': 'new', 'enabled': True,
                            'src': 'any', 'dst_port': '22', 'fwd': '10.10.20.10',
                            'fwd_port': '22', 'proto': 'tcp'}],
            port_profiles=[{'_id': 'p1', 'name': 'OT only', 'forward': 'all'}])
        findings = diff(state(), after, profile())
        self.assertEqual(rules_fired(findings),
                         ['exposure_change', 'firewall_change', 'vlan_leak'])


class TestHowLoudlyStandingProblemsAreReported(unittest.TestCase):
    """
    The spec's answer, and the right one: push the first time, digest after.
    Reported either way — a standing misconfiguration that stops being
    mentioned stops being fixed — but pushing the same one nightly is how push
    gets muted.
    """

    def broken(self):
        return state(port_profiles=[
            {'_id': 'p1', 'name': 'All networks', 'forward': 'all'}])

    def test_a_newly_wrong_profile_pushes(self):
        findings = audit(self.broken(), profile(), previous=state())
        self.assertEqual(findings[0].tier, Tier.PUSH)

    def test_one_that_was_already_wrong_goes_to_the_digest(self):
        findings = audit(self.broken(), profile(), previous=self.broken())
        self.assertEqual(findings[0].tier, Tier.DIGEST)

    def test_it_is_still_reported(self):
        """Not mentioning it any more is how it stays broken."""
        self.assertEqual(len(audit(self.broken(), profile(),
                                   previous=self.broken())), 1)

    def test_with_no_baseline_everything_newly_wrong_pushes(self):
        """The first run is the initial audit; you want to see it."""
        self.assertEqual(audit(self.broken(), profile())[0].tier, Tier.PUSH)

    def test_a_disabled_firewall_rule_follows_the_same_pattern(self):
        off = state(firewall_rules=[{'_id': 'f1', 'name': 'x', 'enabled': False,
                                     'action': 'drop'}])
        self.assertEqual(audit(off, profile(), previous=state())[0].tier, Tier.PUSH)
        self.assertEqual(audit(off, profile(), previous=off)[0].tier, Tier.DIGEST)

    def test_a_port_forward_is_an_inventory_line_not_an_alert(self):
        """
        It exists and you should know; it existing is not news. A *new* one is
        the alert, and that comes from the diff.
        """
        forwards = state(port_forwards=[
            {'_id': 'pf1', 'name': 'web', 'enabled': True, 'src': 'any',
             'dst_port': '443', 'fwd': '10.10.20.10', 'fwd_port': '443'}])
        for previous in (None, state(), forwards):
            with self.subTest(previous='none' if previous is None else 'some'):
                findings = audit(forwards, profile(), previous)
                self.assertEqual(findings[0].tier, Tier.DIGEST)


class TestTheTwoPassesDoNotDuplicate(unittest.TestCase):
    """
    A thing that is both newly wrong and a change was reported twice: once as
    state, once as transition. The transition is strictly more informative —
    "a port forward appeared" beats "a port forward exists" — so it wins.
    """

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-dup-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.path = os.path.join(self.scratch, 'state.json')

    def test_a_new_port_forward_is_reported_once(self):
        client = _FakeClient({'port_forwards': []})
        check(client, profile(), self.path)
        client.data['port_forwards'] = [
            {'_id': 'pf1', 'name': 'temp RDP', 'enabled': True, 'src': 'any',
             'dst_port': '3389', 'fwd': '10.10.20.10', 'fwd_port': '3389'}]
        findings, _ = check(client, profile(), self.path)
        forwards = [f for f in findings if 'pf1' in f.key]
        self.assertEqual(len(forwards), 1)

    def test_and_it_is_the_one_that_says_it_appeared(self):
        client = _FakeClient({'port_forwards': []})
        check(client, profile(), self.path)
        client.data['port_forwards'] = [
            {'_id': 'pf1', 'name': 'temp RDP', 'enabled': True, 'src': 'any',
             'dst_port': '3389', 'fwd': '10.10.20.10', 'fwd_port': '3389'}]
        findings, _ = check(client, profile(), self.path)
        forward = next(f for f in findings if 'pf1' in f.key)
        self.assertIn('who added it', forward.next_check)
        self.assertEqual(forward.tier, Tier.PUSH)

    def test_a_rule_turned_off_is_reported_as_the_change_not_the_state(self):
        client = _FakeClient({'firewall_rules': [
            {'_id': 'f1', 'name': 'block', 'enabled': True, 'action': 'drop'}]})
        check(client, profile(), self.path)
        client.data['firewall_rules'][0]['enabled'] = False
        findings, _ = check(client, profile(), self.path)
        rules = [f for f in findings if 'f1' in f.key]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].rule_id, 'firewall_change')

    def test_a_standing_problem_with_no_change_is_still_reported(self):
        client = _FakeClient({'port_profiles': [
            {'_id': 'p1', 'name': 'All', 'forward': 'all'}]})
        check(client, profile(), self.path)
        findings, report = check(client, profile(), self.path)
        self.assertEqual(report['changed'], 0)
        self.assertEqual(report['standing'], 1)
        self.assertEqual(findings[0].tier, Tier.DIGEST)

    def test_the_keys_identify_the_object_so_both_passes_agree(self):
        """
        The reconciliation only works because both passes name the same object
        the same way. They used to use the name and the id respectively, and
        nothing collapsed.
        """
        broken = state(port_forwards=[
            {'_id': 'pf1', 'name': 'web', 'enabled': True, 'src': 'any',
             'dst_port': '443', 'fwd': '10.10.20.10', 'fwd_port': '443'}])
        standing = audit(broken, profile())
        changes = diff(state(), broken, profile())
        self.assertEqual({f.key for f in standing}, {f.key for f in changes})


# ─── State on disk ───────────────────────────────────────────────────────────

class TestStateFile(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-drift-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.path = os.path.join(self.scratch, 'sub', 'unifi.json')

    def test_it_round_trips(self):
        save_state(state(), self.path)
        self.assertEqual(load_state(self.path)['taken_at'], 1790000000.0)

    def test_it_is_written_owner_only(self):
        """
        It is the network's defences written down: every firewall rule, every
        forward, every port's VLAN membership.
        """
        save_state(state(), self.path)
        self.assertEqual(os.stat(self.path).st_mode & 0o077, 0)

    def test_a_missing_file_is_a_first_run(self):
        self.assertIsNone(load_state(self.path))
        self.assertIsNone(load_state(''))

    def test_a_corrupt_file_is_treated_as_a_first_run(self):
        """Rather than failing the whole check over a cache file."""
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, 'w') as handle:
            handle.write('not json')
        with self.assertLogs('netmon.drift', level='WARNING'):
            self.assertIsNone(load_state(self.path))

    def test_no_temporary_file_is_left(self):
        save_state(state(), self.path)
        self.assertFalse(os.path.exists(self.path + '.tmp'))


# ─── Snapshots ───────────────────────────────────────────────────────────────

class _FakeClient:
    site = 'default'
    host = 'https://unifi.test'

    def __init__(self, data=None, fail=()):
        self.data = data or {}
        self.fail = set(fail)
        self.paths = []

    def get(self, path):
        from netmon.sources.unifi_api import UnifiApiError
        self.paths.append(path)
        for name, suffix in CONFIG_ENDPOINTS.items():
            if path.endswith(suffix):
                if name in self.fail:
                    raise UnifiApiError(f'{name} unavailable')
                return self.data.get(name, [])
        raise UnifiApiError(f'unexpected path {path}')


class TestSnapshot(unittest.TestCase):

    def test_everything_is_read(self):
        taken = snapshot(_FakeClient({
            'networks': [{'_id': 'n1', 'name': 'ot', 'vlan': 20}],
            'port_forwards': [{'_id': 'pf1', 'name': 'web', 'enabled': True}]}))
        self.assertEqual(len(taken['networks']), 1)
        self.assertEqual(len(taken['port_forwards']), 1)

    def test_one_endpoint_failing_does_not_lose_the_rest(self):
        taken = snapshot(_FakeClient(
            {'networks': [{'_id': 'n1', 'name': 'ot'}]}, fail=['wlans']))
        self.assertEqual(len(taken['networks']), 1)
        self.assertIn('wlans', taken['errors'])

    def test_only_the_fields_worth_comparing_are_kept(self):
        """
        A snapshot is for comparison. The less of the controller's internal
        state it carries, the less of it churns for reasons nobody cares about.
        """
        taken = snapshot(_FakeClient({'networks': [
            {'_id': 'n1', 'name': 'ot', 'vlan': 20,
             'site_id': 'abc', 'attr_no_delete': True, 'last_seen': 123}]}))
        self.assertEqual(set(taken['networks'][0]), {'_id', 'name', 'vlan'})

    def test_the_port_table_is_pulled_out_of_the_devices(self):
        """
        A device's statistics change every poll; its port assignments do not.
        Comparing whole device objects would report drift on every run.
        """
        taken = snapshot(_FakeClient({'devices': [
            {'_id': 'd1', 'mac': 'AA:BB:CC:00:00:01', 'name': 'sw',
             'uptime': 12345, 'rx_bytes': 99999,
             'port_table': [{'port_idx': 1, 'name': 'ahu',
                             'portconf_id': 'p1', 'up': True}]}]}))
        self.assertIn('aa:bb:cc:00:00:01/1', taken['ports'])
        self.assertNotIn('rx_bytes', json.dumps(taken['devices']))

    def test_a_port_override_is_recorded(self):
        taken = snapshot(_FakeClient({'devices': [
            {'_id': 'd1', 'mac': 'aa:bb:cc:00:00:01',
             'port_table': [{'port_idx': 3, 'portconf_id': 'p1'}],
             'port_overrides': [{'port_idx': 3, 'portconf_id': 'p2',
                                 'name': 'camera'}]}]}))
        port = taken['ports']['aa:bb:cc:00:00:01/3']
        self.assertEqual(port['override_portconf_id'], 'p2')
        self.assertEqual(port['name'], 'camera')

    def test_two_snapshots_of_an_unchanged_controller_do_not_drift(self):
        """The property that decides whether a nightly run is readable."""
        client = _FakeClient({
            'networks': [{'_id': 'n1', 'name': 'ot', 'vlan': 20}],
            'devices': [{'_id': 'd1', 'mac': 'aa:bb:cc:00:00:01',
                         'uptime': 1, 'rx_bytes': 1,
                         'port_table': [{'port_idx': 1, 'portconf_id': 'p1'}]}]})
        first = snapshot(client, now=1.0)
        client.data['devices'][0].update({'uptime': 9999, 'rx_bytes': 10 ** 9})
        second = snapshot(client, now=2.0)
        self.assertEqual(diff(first, second, profile()), [])


class TestCheck(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-check-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.path = os.path.join(self.scratch, 'unifi.json')

    def test_a_first_run_records_a_baseline_and_says_so(self):
        client = _FakeClient({'port_profiles': [
            {'_id': 'p1', 'name': 'All', 'forward': 'all'}]})
        findings, report = check(client, profile(), self.path)
        self.assertTrue(report['baseline'])
        self.assertEqual(report['changed'], 0)
        self.assertEqual(report['standing'], 1)
        self.assertTrue(os.path.exists(self.path))

    def test_the_second_run_reports_the_change(self):
        client = _FakeClient({'port_forwards': []})
        check(client, profile(), self.path)
        client.data['port_forwards'] = [
            {'_id': 'pf1', 'name': 'new', 'enabled': True, 'src': 'any',
             'dst_port': '22', 'fwd': '10.10.20.10', 'fwd_port': '22'}]
        findings, report = check(client, profile(), self.path)
        self.assertFalse(report['baseline'])
        self.assertEqual(report['changed'], 1)

    def test_no_save_leaves_the_baseline_alone(self):
        client = _FakeClient({'port_forwards': []})
        check(client, profile(), self.path)
        before = load_state(self.path)['taken_at']
        client.data['port_forwards'] = [{'_id': 'pf1', 'name': 'x',
                                         'enabled': True}]
        check(client, profile(), self.path, save=False)
        self.assertEqual(load_state(self.path)['taken_at'], before)

    def test_the_run_reports_what_it_counted(self):
        _, report = check(_FakeClient({'networks': [{'_id': 'n1'}, {'_id': 'n2'}]}),
                          profile(), self.path)
        self.assertEqual(report['counts']['networks'], 2)


# ─── These travel like any other finding ─────────────────────────────────────

class TestFindingsAreOrdinaryFindings(unittest.TestCase):
    """
    There is no packet behind these — they are states, not events — so they
    carry a synthetic one and travel through redaction, deduplication and the UI
    unchanged.
    """

    def all_findings(self):
        return audit(state(
            port_profiles=[{'_id': 'p1', 'name': 'All', 'forward': 'all'}],
            port_forwards=[{'_id': 'pf1', 'name': 'web', 'enabled': True,
                            'src': 'any', 'dst_port': '443',
                            'fwd': '192.168.1.239', 'fwd_port': '443'}],
            firewall_rules=[{'_id': 'f1', 'name': 'x', 'enabled': False,
                             'action': 'drop'}],
            wlans=[{'_id': 'w1', 'name': 'Open', 'enabled': True,
                    'security': 'open'}]), profile()) + diff(
            state(), state(firewall_rules=[]), profile())

    def test_every_finding_redacts_cleanly(self):
        for finding in self.all_findings():
            with self.subTest(rule=finding.rule_id):
                record = redact_finding(finding, profile(), ALERT)
                self.assertIsNotNone(record)
                self.assertEqual(redaction_audit(record), [])

    def test_every_finding_has_a_description_and_a_next_check(self):
        for finding in self.all_findings():
            with self.subTest(rule=finding.rule_id):
                self.assertTrue(finding.description)
                if finding.severity != Severity.INFO:
                    self.assertTrue(finding.next_check,
                                    f'{finding.rule_id} has no next check')

    def test_every_finding_deduplicates(self):
        from netmon.events import Deduplicator
        dedup = Deduplicator(window_sec=3600)
        findings = self.all_findings()
        admitted = [f for f in findings if dedup.admit(f) is not None]
        self.assertEqual(len(admitted), len(findings))
        again = [f for f in self.all_findings() if dedup.admit(f) is not None]
        self.assertEqual(again, [])

    def test_push_findings_are_at_least_medium(self):
        for finding in self.all_findings():
            if finding.tier == Tier.PUSH:
                with self.subTest(rule=finding.rule_id):
                    self.assertGreaterEqual(Severity.rank(finding.severity),
                                            Severity.rank(Severity.MEDIUM))

    def test_no_finding_carries_a_firewall_rule_body(self):
        """
        The findings name rules and ports, not the rules themselves. A snapshot
        is the network's defences; an alert should not be.
        """
        for finding in self.all_findings():
            blob = json.dumps(redact_finding(finding, profile(), ALERT),
                              default=str)
            with self.subTest(rule=finding.rule_id):
                for leaky in ('src_firewallgroup_ids', 'group_members',
                              'src_address', 'dst_address'):
                    self.assertNotIn(leaky, blob)


class TestFormatting(unittest.TestCase):

    def test_a_first_run_explains_itself(self):
        text = format_findings([], {'baseline': True, 'taken_at': 1.0,
                                    'previous_at': None, 'counts': {},
                                    'errors': {}})
        self.assertIn('baseline', text)
        self.assertIn('next run', text)

    def test_a_later_run_says_how_long_ago(self):
        text = format_findings([], {'baseline': False, 'taken_at': 7200.0,
                                    'previous_at': 0.0, 'counts': {},
                                    'errors': {}})
        self.assertIn('2.0 hours ago', text)

    def test_a_clean_run_says_so(self):
        text = format_findings([], {'baseline': False, 'taken_at': 1.0,
                                    'previous_at': 0.0, 'counts': {},
                                    'errors': {}})
        self.assertIn('Nothing wrong, and nothing changed', text)

    def test_findings_are_worst_first(self):
        findings = audit(state(
            port_profiles=[{'_id': 'p1', 'name': 'All', 'forward': 'all'}],
            firewall_rules=[{'_id': 'f1', 'name': 'x', 'enabled': False,
                             'action': 'drop'}]), profile())
        text = format_findings(findings, {'baseline': False, 'taken_at': 1.0,
                                          'previous_at': 0.0, 'counts': {},
                                          'errors': {}})
        self.assertLess(text.index('vlan_leak'), text.index('firewall_rule_disabled'))

    def test_an_unreadable_endpoint_is_mentioned(self):
        text = format_findings([], {'baseline': False, 'taken_at': 1.0,
                                    'previous_at': 0.0, 'counts': {},
                                    'errors': {'wlans': 'HTTP 403'}})
        self.assertIn('could not read wlans', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
