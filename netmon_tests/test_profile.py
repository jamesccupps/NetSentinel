"""
Site profile loading, lookup and validation.
=============================================
Two themes run through these tests.

The first is that a profile is written by a person, at speed, from a spreadsheet,
and will contain mistakes. Every mistake should either be corrected silently
(separator style), reported loudly (a duplicate address), or refused (a malformed
MAC) — never accepted and quietly misinterpreted.

The second is that `may_store_payload()` is a safety boundary, not a preference.
The tests below check it holds whichever way the profile expresses it, and that
it fails closed on anything ambiguous.
"""

import io
import logging
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml  # noqa: E402

from netmon.profile import (Device, ProfileError, SiteProfile,  # noqa: E402
                            load_profile, normalise_mac)

EXAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       'netmon', 'profiles', 'example-site.yaml')


def profile(**overrides):
    """A minimal valid profile, with room to break one thing at a time."""
    data = {
        'site': {'name': 'test site', 'quiet_hours': [22, 6]},
        'vlans': {
            20: {'name': 'ot', 'subnet': '10.0.20.0/24', 'zone': 'ot'},
            40: {'name': 'restricted', 'subnet': '10.0.40.0/24',
                 'zone': 'restricted', 'store_payload': False},
        },
        'roles': {'controller': {'internet_expected': False},
                  'server': {'internet_expected': True}},
        'devices': {
            '00:11:22:00:00:01': {'name': 'srv', 'role': 'server',
                                  'ips': ['10.0.20.10'], 'vlan': 20},
            '00:11:22:00:00:02': {'name': 'ctl', 'role': 'controller',
                                  'ips': ['10.0.20.21'], 'vlan': 20},
        },
    }
    data.update(overrides)
    return SiteProfile(data)


# ─── MAC normalisation ───────────────────────────────────────────────────────

class TestMacNormalisation(unittest.TestCase):

    def test_separator_styles_all_converge(self):
        for text in ('AA:BB:CC:DD:EE:FF', 'aa-bb-cc-dd-ee-ff', 'aabb.ccdd.eeff',
                     'AABBCCDDEEFF', 'aa bb cc dd ee ff'):
            with self.subTest(text=text):
                self.assertEqual(normalise_mac(text), 'aa:bb:cc:dd:ee:ff')

    def test_empty_stays_empty(self):
        for value in ('', None):
            self.assertEqual(normalise_mac(value), '')

    def test_junk_is_returned_for_the_validator_to_reject(self):
        """Not silently coerced into something MAC-shaped."""
        self.assertEqual(normalise_mac('not-a-mac'), 'not-a-mac')

    def test_a_yaml_sexagesimal_mac_is_recovered(self):
        """
        YAML 1.1 reads `10:11:22:33:44:55` as a base-60 number. Without this the
        device silently disappears from the profile, which is a worse failure
        than refusing to load.
        """
        parsed = yaml.safe_load('d: {10:11:22:33:44:55: x}')
        key = list(parsed['d'])[0]
        self.assertIsInstance(key, int)
        self.assertEqual(normalise_mac(key), '10:11:22:33:44:55')

    def test_the_boundary_cases_of_that_recovery(self):
        for text in ('99:59:59:59:59:59', '12:00:00:00:00:00', '10:00:00:00:00:00'):
            with self.subTest(text=text):
                key = list(yaml.safe_load('d: {%s: x}' % text)['d'])[0]
                self.assertEqual(normalise_mac(key), text)

    def test_macs_that_yaml_leaves_alone_are_left_alone(self):
        """Leading `00` or any group above 59 keeps it a string."""
        for text in ('00:11:22:33:44:55', '10:11:22:33:44:99'):
            with self.subTest(text=text):
                key = list(yaml.safe_load('d: {%s: x}' % text)['d'])[0]
                self.assertIsInstance(key, str)
                self.assertEqual(normalise_mac(key), text)

    def test_an_integer_that_was_never_a_mac_is_not_invented_into_one(self):
        """A typo should fail validation, not become a plausible address."""
        for junk in (0, 1, 12345, -5):
            with self.subTest(junk=junk):
                self.assertEqual(normalise_mac(junk), str(junk))

    def test_the_recovery_warns_so_the_profile_gets_fixed(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger('netmon.profile')
        logger.addHandler(handler)
        try:
            SiteProfile({'devices': {7923433495: {'name': 'x'}}})
        finally:
            logger.removeHandler(handler)
        self.assertIn('base-60', stream.getvalue())


# ─── Lookup ──────────────────────────────────────────────────────────────────

class TestLookup(unittest.TestCase):

    def setUp(self):
        self.p = profile()

    def test_by_mac_in_any_notation(self):
        for text in ('00:11:22:00:00:01', '00-11-22-00-00-01', '001122000001'):
            with self.subTest(text=text):
                self.assertEqual(self.p.device_for_mac(text).name, 'srv')

    def test_by_ip(self):
        self.assertEqual(self.p.device_for_ip('10.0.20.21').name, 'ctl')

    def test_unknown_mac_returns_none(self):
        self.assertIsNone(self.p.device_for_mac('ff:ff:ff:ff:ff:ff'))

    def test_identify_prefers_mac_over_ip(self):
        """MAC survives DHCP; when both are known and disagree, trust the MAC."""
        device = self.p.identify(mac='00:11:22:00:00:01', ip='10.0.20.21')
        self.assertEqual(device.name, 'srv')

    def test_identify_falls_back_to_ip(self):
        self.assertEqual(self.p.identify(ip='10.0.20.10').name, 'srv')

    def test_identify_never_returns_none(self):
        """
        Callers format the result into an alert. A None here would mean every
        rule needs a null check, and one of them would be missed.
        """
        device = self.p.identify(ip='203.0.113.9')
        self.assertIsInstance(device, Device)
        self.assertEqual(device.role, 'unknown')
        self.assertEqual(device.name, '203.0.113.9')

    def test_identify_with_nothing_still_returns_a_device(self):
        self.assertEqual(self.p.identify().name, 'unknown')

    def test_role_of(self):
        self.assertEqual(self.p.role_of(ip='10.0.20.21'), 'controller')
        self.assertEqual(self.p.role_of(ip='203.0.113.9'), 'unknown')

    def test_vlan_for_ip(self):
        self.assertEqual(self.p.vlan_for_ip('10.0.40.7').id, 40)

    def test_vlan_for_unrouted_ip_is_none(self):
        self.assertIsNone(self.p.vlan_for_ip('203.0.113.9'))

    def test_vlan_for_garbage_ip_is_none_not_an_exception(self):
        """Addresses reach this from packets; a malformed one must not raise."""
        self.assertIsNone(self.p.vlan_for_ip('not-an-ip'))
        self.assertIsNone(self.p.vlan_for_ip(''))


# ─── The payload prohibition ─────────────────────────────────────────────────

class TestPayloadPolicy(unittest.TestCase):
    """
    `store_payload: false` is the mechanism enforcing 'metadata only' on segments
    carrying credential or cardholder data. It has to hold however the profile
    happens to express it.
    """

    def test_store_payload_false_on_the_vlan(self):
        self.assertFalse(profile().may_store_payload(40))

    def test_the_explicit_list_also_works(self):
        p = profile(metadata_only_vlans=[20])
        self.assertFalse(p.may_store_payload(20))

    def test_the_two_forms_combine_rather_than_override(self):
        """Listing one VLAN explicitly must not re-enable payload on another."""
        p = profile(metadata_only_vlans=[20])
        self.assertFalse(p.may_store_payload(20))
        self.assertFalse(p.may_store_payload(40))

    def test_unrestricted_vlans_are_allowed(self):
        p = profile()
        self.assertTrue(p.may_store_payload(99))

    def test_string_vlan_ids_are_accepted(self):
        """A VLAN id arriving from a tag parser may be a string."""
        self.assertFalse(profile().may_store_payload('40'))

    def test_unknown_vlan_is_permitted(self):
        """
        Deliberate: an unprofiled VLAN is not automatically restricted, because
        treating every unknown as restricted would make the tool useless at a
        site that has not finished its profile. Restriction is stated, not
        guessed — which is why the validator and docs push hard on stating it.
        """
        self.assertTrue(profile().may_store_payload(None))

    def test_the_example_profile_restricts_its_sensitive_segments(self):
        p = load_profile(EXAMPLE)
        self.assertFalse(p.may_store_payload(40))
        self.assertFalse(p.may_store_payload(50))
        self.assertTrue(p.may_store_payload(20))


# ─── Expected flows ──────────────────────────────────────────────────────────

class TestExpectedFlows(unittest.TestCase):

    def setUp(self):
        self.p = profile(expected_flows=[
            {'src': 'server', 'dst': '10.0.20.0/24', 'ports': [47808],
             'protocol': 'udp'},
            {'src': '10.0.20.0/24', 'dst': '*', 'ports': [443]},
        ])

    def test_role_on_the_source_side(self):
        self.assertTrue(self.p.is_expected_flow('10.0.20.10', '10.0.20.21',
                                                47808, 'udp'))

    def test_a_different_role_does_not_match(self):
        self.assertFalse(self.p.is_expected_flow('10.0.20.21', '10.0.20.10',
                                                 47808, 'udp'))

    def test_wrong_port_does_not_match(self):
        self.assertFalse(self.p.is_expected_flow('10.0.20.10', '10.0.20.21',
                                                 502, 'udp'))

    def test_wrong_protocol_does_not_match(self):
        self.assertFalse(self.p.is_expected_flow('10.0.20.10', '10.0.20.21',
                                                 47808, 'tcp'))

    def test_wildcard_destination(self):
        self.assertTrue(self.p.is_expected_flow('10.0.20.99', '203.0.113.5', 443))

    def test_cidr_on_the_source_side(self):
        self.assertTrue(self.p.is_expected_flow('10.0.20.1', '8.8.8.8', 443))
        self.assertFalse(self.p.is_expected_flow('10.0.40.1', '8.8.8.8', 443))

    def test_no_flows_means_nothing_is_expected(self):
        self.assertFalse(profile().is_expected_flow('10.0.20.10', '10.0.20.21'))

    def test_a_port_is_only_checked_when_one_is_supplied(self):
        """Flow records from sources without port data still match."""
        self.assertTrue(self.p.is_expected_flow('10.0.20.10', '10.0.20.21',
                                                None, 'udp'))


# ─── BACnet writes ───────────────────────────────────────────────────────────

class TestBacnetAllowlist(unittest.TestCase):

    def setUp(self):
        self.p = profile(bacnet_write_allowlist=[
            {'src': '10.0.20.10', 'dst': ['10.0.20.21', '10.0.20.22']},
            {'src': '10.0.20.50', 'dst': '10.0.20.21',
             'objects': ['analog-value-7']},
        ])

    def test_allowed_source_and_destination(self):
        self.assertTrue(self.p.bacnet_write_allowed('10.0.20.10', '10.0.20.21'))

    def test_wrong_source_is_not_allowed(self):
        self.assertFalse(self.p.bacnet_write_allowed('10.0.60.9', '10.0.20.21'))

    def test_wrong_destination_is_not_allowed(self):
        self.assertFalse(self.p.bacnet_write_allowed('10.0.20.10', '10.0.20.99'))

    def test_a_single_destination_string_is_accepted(self):
        self.assertTrue(self.p.bacnet_write_allowed('10.0.20.50', '10.0.20.21',
                                                    'analog-value-7'))

    def test_object_scoping(self):
        self.assertFalse(self.p.bacnet_write_allowed('10.0.20.50', '10.0.20.21',
                                                     'binary-output-3'))

    def test_an_empty_allowlist_permits_nothing(self):
        """So a site that has not filled it in sees every write, not none."""
        self.assertFalse(profile().bacnet_write_allowed('10.0.20.10',
                                                        '10.0.20.21'))


# ─── Muted references ────────────────────────────────────────────────────────

class TestKnownDeadReferences(unittest.TestCase):

    def setUp(self):
        self.p = profile(known_dead_references=[
            {'target': '10.0.20.99', 'src_any': True},
            {'target': '10.0.30.99', 'src': ['10.0.30.10'], 'proto': 'tcp'},
        ])

    def test_any_source_to_a_decommissioned_target(self):
        self.assertTrue(self.p.is_known_dead_reference('10.0.20.1', '10.0.20.99'))
        self.assertTrue(self.p.is_known_dead_reference('10.0.60.9', '10.0.20.99'))

    def test_scoped_to_one_source(self):
        self.assertTrue(self.p.is_known_dead_reference('10.0.30.10', '10.0.30.99',
                                                       'tcp'))
        self.assertFalse(self.p.is_known_dead_reference('10.0.60.9', '10.0.30.99',
                                                        'tcp'))

    def test_scoped_to_one_protocol(self):
        self.assertFalse(self.p.is_known_dead_reference('10.0.30.10', '10.0.30.99',
                                                        'udp'))

    def test_an_unmuted_target_is_not_muted(self):
        self.assertFalse(self.p.is_known_dead_reference('10.0.20.1', '10.0.20.50'))


# ─── Quiet hours ─────────────────────────────────────────────────────────────

class TestQuietHours(unittest.TestCase):

    def test_a_window_that_wraps_midnight(self):
        p = profile(site={'quiet_hours': [22, 6]})
        for hour in (22, 23, 0, 3, 5):
            self.assertTrue(p.in_quiet_hours(hour), hour)
        for hour in (6, 12, 21):
            self.assertFalse(p.in_quiet_hours(hour), hour)

    def test_a_window_inside_one_day(self):
        p = profile(site={'quiet_hours': [9, 17]})
        self.assertTrue(p.in_quiet_hours(12))
        self.assertFalse(p.in_quiet_hours(20))

    def test_equal_bounds_disable_the_window(self):
        """Rather than meaning 'always', which nobody intends by writing [0, 0]."""
        p = profile(site={'quiet_hours': [0, 0]})
        self.assertFalse(p.in_quiet_hours(3))

    def test_the_default(self):
        self.assertEqual(SiteProfile({}).quiet_hours, (22, 6))


# ─── Validation ──────────────────────────────────────────────────────────────

class TestValidation(unittest.TestCase):

    def assertRefused(self, fragment, **overrides):
        with self.assertRaises(ProfileError) as ctx:
            profile(**overrides)
        self.assertIn(fragment, str(ctx.exception))

    def test_a_malformed_mac_is_refused_by_name(self):
        self.assertRefused('not-a-mac',
                           devices={'not-a-mac': {'name': 'x'}})

    def test_a_malformed_subnet_is_refused(self):
        self.assertRefused('not a network',
                           vlans={20: {'subnet': '10.0.20.0/99'}})

    def test_a_malformed_address_is_refused(self):
        self.assertRefused('not an address',
                           devices={'00:11:22:00:00:01': {'ips': ['10.0.20.999']}})

    def test_a_duplicate_address_is_refused(self):
        """
        Either a profile mistake or a genuine collision. Both are worth a human
        looking; silently picking one device would make every later lookup a
        coin flip.
        """
        self.assertRefused('claimed by both', devices={
            '00:11:22:00:00:01': {'ips': ['10.0.20.10']},
            '00:11:22:00:00:02': {'ips': ['10.0.20.10']},
        })

    def test_the_same_address_twice_on_one_device_is_fine(self):
        SiteProfile({'devices': {'00:11:22:00:00:01':
                                 {'ips': ['10.0.20.10', '10.0.20.10']}}})

    def test_quiet_hours_outside_the_clock_are_refused(self):
        self.assertRefused('outside 0-23', site={'quiet_hours': [22, 30]})

    def test_a_non_numeric_vlan_key_is_refused(self):
        with self.assertRaises(ProfileError) as ctx:
            SiteProfile({'vlans': {'ot': {'subnet': '10.0.20.0/24'}}})
        self.assertIn('not a VLAN id', str(ctx.exception))

    def test_every_problem_is_reported_at_once(self):
        """One load, one fix list — rather than one error per reload."""
        with self.assertRaises(ProfileError) as ctx:
            SiteProfile({'devices': {'bad-mac': {'ips': ['10.0.0.999']}}})
        message = str(ctx.exception)
        self.assertIn('bad-mac', message)
        self.assertIn('10.0.0.999', message)

    def test_an_undefined_role_warns_but_loads(self):
        """
        A typo in a role name should be visible without blocking the load — the
        rules treat it as an unrecognised role, which is degraded, not broken.
        """
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        logger = logging.getLogger('netmon.profile')
        logger.addHandler(handler)
        try:
            p = SiteProfile({'roles': {'controller': {}},
                             'devices': {'00:11:22:00:00:01':
                                         {'name': 'x', 'role': 'contoller'}}})
        finally:
            logger.removeHandler(handler)
        self.assertIn('contoller', stream.getvalue())
        self.assertEqual(p.role_of(mac='00:11:22:00:00:01'), 'contoller')

    def test_an_empty_profile_is_valid(self):
        """Useful for a first run before anything has been catalogued."""
        p = SiteProfile({})
        self.assertEqual(p.summary()['devices'], 0)


# ─── Loading ─────────────────────────────────────────────────────────────────

class TestLoading(unittest.TestCase):

    def write(self, text):
        handle, path = tempfile.mkstemp(suffix='.yaml')
        with os.fdopen(handle, 'w') as f:
            f.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def test_a_missing_file_says_so(self):
        with self.assertRaises(ProfileError) as ctx:
            load_profile('/nonexistent/site.yaml')
        self.assertIn('not found', str(ctx.exception))

    def test_malformed_yaml_names_the_file(self):
        path = self.write('site: {name: [unclosed\n')
        with self.assertRaises(ProfileError) as ctx:
            load_profile(path)
        self.assertIn(path, str(ctx.exception))

    def test_a_non_mapping_top_level_is_refused(self):
        with self.assertRaises(ProfileError) as ctx:
            load_profile(self.write('- a\n- b\n'))
        self.assertIn('must be a mapping', str(ctx.exception))

    def test_an_empty_file_loads_as_an_empty_profile(self):
        self.assertEqual(load_profile(self.write('')).summary()['devices'], 0)

    def test_the_path_is_recorded(self):
        path = self.write('site: {name: x}\n')
        self.assertEqual(load_profile(path).path, path)


# ─── The shipped example ─────────────────────────────────────────────────────

class TestExampleProfile(unittest.TestCase):
    """
    The example is documentation, and documentation that does not load is worse
    than none. It is also the fixture every other part of netmon will be
    demonstrated against.
    """

    @classmethod
    def setUpClass(cls):
        cls.p = load_profile(EXAMPLE)

    def test_it_loads_and_validates(self):
        self.assertTrue(self.p.validate())

    def test_it_demonstrates_every_section(self):
        summary = self.p.summary()
        for key in ('vlans', 'devices', 'roles', 'expected_flows',
                    'metadata_only_vlans', 'muted_references', 'watched_names'):
            with self.subTest(key=key):
                self.assertTrue(summary[key], f'{key} is empty in the example')

    def test_every_device_role_is_defined(self):
        for device in self.p.devices.values():
            with self.subTest(device=device.name):
                self.assertIn(device.role, self.p.roles)

    def test_every_device_address_sits_in_its_declared_vlan(self):
        """Catches a copy-paste slip in the example itself."""
        for device in self.p.devices.values():
            for ip in device.ips:
                with self.subTest(device=device.name, ip=ip):
                    found = self.p.vlan_for_ip(ip)
                    self.assertIsNotNone(found, f'{ip} is in no declared subnet')
                    self.assertEqual(found.id, device.vlan)

    def test_it_contains_only_documentation_range_addresses(self):
        """
        Nothing in the example should resemble a real site. RFC 1918 for the
        internal side, RFC 2606 `.test` names for the external side.
        """
        import ipaddress
        for device in self.p.devices.values():
            for ip in device.ips:
                with self.subTest(ip=ip):
                    self.assertTrue(ipaddress.ip_address(ip).is_private)
        for role in self.p.roles.values():
            for domain in role.allowed_domains:
                with self.subTest(domain=domain):
                    self.assertTrue(domain.endswith('.test'),
                                    f'{domain} is not a reserved example name')

    def test_it_carries_a_capture_section_the_bpf_builder_can_use(self):
        from netmon import bpf
        capture = self.p.raw['capture']
        filt = bpf.build_capture_filter(
            vlans=capture['vlans'],
            include_untagged=capture['include_untagged'],
            drop_hosts=capture['drop_hosts'],
            drop_ports=capture['drop_ports'])
        self.assertIn('ether[12:2]', filt)
        self.assertNotIn('0x0fff == 30', filt)   # video excluded by selection

    def test_the_restricted_vlans_are_never_capture_eligible_for_payload(self):
        """
        The example selects VLANs 40 and 50 for capture — deliberately, because
        metadata from them is useful — so the payload prohibition must come from
        may_store_payload(), not from the capture filter.
        """
        capture = self.p.raw['capture']
        self.assertIn(40, capture['vlans'])
        self.assertFalse(self.p.may_store_payload(40))


if __name__ == '__main__':
    unittest.main(verbosity=2)
