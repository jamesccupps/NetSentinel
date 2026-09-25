"""
Rules engine, and every core rule fired against its grounding scenario.
=======================================================================
Two halves.

`TestConditions` and friends cover the engine: the condition language, template
rendering, load-time validation. A rule file is edited by whoever runs the site,
so a typo must be caught when the file loads rather than at 3am on a live feed.

`TestCoreRules` builds, for each shipped rule, an event resembling the
observation the rule was written from, and asserts the rule fires. Each one also
gets a near-miss that must stay quiet, because a rule that fires on everything
is worse than no rule — it is the reason people mute monitors.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import netmon.handlers  # noqa: E402,F401  (registers the stateful handlers)
from netmon.events import (Deduplicator, Event, Finding, Severity,  # noqa: E402
                           Tier, enrich)
from netmon.profile import SiteProfile, load_profile  # noqa: E402
from netmon.rules_engine import (Rule, RuleError, RuleSet,  # noqa: E402
                                 evaluate_condition, load_rules, render)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')
CORE_RULES = os.path.join(ROOT, 'netmon', 'rules')


def event(kind='flow', **kw):
    fields = kw.pop('fields', {})
    e = Event(kind=kind, **kw)
    e.fields.update(fields)
    return e


# ─── The condition language ──────────────────────────────────────────────────

class TestConditions(unittest.TestCase):

    def setUp(self):
        self.e = event('tls', src_ip='10.0.0.5', dst_ip='1.2.3.4', dst_port=443,
                       protocol='tcp', bytes_to_dst=500_000,
                       fields={'sni': 'relay-abc.net.anydesk.com',
                               'src_name': 'hvac-pc', 'blocked': False})

    def test_an_empty_condition_matches(self):
        self.assertTrue(evaluate_condition({}, self.e))
        self.assertTrue(evaluate_condition(None, self.e))

    def test_scalar_equality(self):
        self.assertTrue(evaluate_condition({'kind': 'tls'}, self.e))
        self.assertFalse(evaluate_condition({'kind': 'dns'}, self.e))

    def test_string_equality_ignores_case(self):
        """Sources disagree about capitalisation; rules should not have to."""
        self.assertTrue(evaluate_condition({'kind': 'TLS'}, self.e))

    def test_numbers_match_across_string_and_int(self):
        """A CSV importer yields '443'; a packet parser yields 443."""
        self.assertTrue(evaluate_condition({'dst_port': '443'}, self.e))
        self.assertTrue(evaluate_condition({'dst_port': 443}, self.e))

    def test_a_list_is_membership(self):
        self.assertTrue(evaluate_condition({'dst_port': [80, 443]}, self.e))
        self.assertFalse(evaluate_condition({'dst_port': [80, 8080]}, self.e))

    def test_comparison_operators(self):
        self.assertTrue(evaluate_condition({'bytes_to_dst': {'gt': 1000}}, self.e))
        self.assertFalse(evaluate_condition({'bytes_to_dst': {'gt': 10 ** 9}}, self.e))
        self.assertTrue(evaluate_condition({'bytes_to_dst': {'lte': 500_000}}, self.e))

    def test_comparison_against_a_missing_field_is_false_not_an_error(self):
        """Half the sources do not supply half the fields."""
        self.assertFalse(evaluate_condition({'nonexistent': {'gt': 1}}, self.e))

    def test_regex(self):
        self.assertTrue(evaluate_condition(
            {'sni': {'matches': 'anydesk|teamviewer'}}, self.e))
        self.assertFalse(evaluate_condition({'sni': {'matches': '^example'}}, self.e))

    def test_regex_is_case_insensitive(self):
        self.assertTrue(evaluate_condition({'sni': {'matches': 'ANYDESK'}}, self.e))

    def test_contains(self):
        self.assertTrue(evaluate_condition({'sni': {'contains': 'net.anydesk'}}, self.e))
        self.assertTrue(evaluate_condition(
            {'sni': {'contains': ['nope', 'anydesk']}}, self.e))

    def test_negation(self):
        self.assertTrue(evaluate_condition({'kind': {'not': 'dns'}}, self.e))
        self.assertFalse(evaluate_condition({'kind': {'not': 'tls'}}, self.e))

    def test_negation_of_a_list(self):
        self.assertTrue(evaluate_condition({'kind': {'not': ['dns', 'dhcp']}}, self.e))
        self.assertFalse(evaluate_condition({'kind': {'not': ['dns', 'tls']}}, self.e))

    def test_exists(self):
        self.assertTrue(evaluate_condition({'sni': {'exists': True}}, self.e))
        self.assertTrue(evaluate_condition({'nothing': {'exists': False}}, self.e))
        self.assertFalse(evaluate_condition({'sni': {'exists': False}}, self.e))

    def test_exists_treats_empty_string_as_absent(self):
        """An importer that writes '' for a missing column means 'no value'."""
        self.e.fields['query'] = ''
        self.assertFalse(evaluate_condition({'query': {'exists': True}}, self.e))

    def test_false_is_not_absent(self):
        """`blocked: False` is an answer, not a missing field."""
        self.assertTrue(evaluate_condition({'blocked': False}, self.e))
        self.assertFalse(evaluate_condition({'blocked': True}, self.e))

    def test_any(self):
        self.assertTrue(evaluate_condition(
            {'any': [{'kind': 'dns'}, {'kind': 'tls'}]}, self.e))
        self.assertFalse(evaluate_condition(
            {'any': [{'kind': 'dns'}, {'kind': 'dhcp'}]}, self.e))

    def test_all(self):
        self.assertTrue(evaluate_condition(
            {'all': [{'kind': 'tls'}, {'dst_port': 443}]}, self.e))
        self.assertFalse(evaluate_condition(
            {'all': [{'kind': 'tls'}, {'dst_port': 80}]}, self.e))

    def test_clauses_are_anded(self):
        self.assertTrue(evaluate_condition({'kind': 'tls', 'dst_port': 443}, self.e))
        self.assertFalse(evaluate_condition({'kind': 'tls', 'dst_port': 80}, self.e))

    def test_zero_is_a_value_not_an_absence(self):
        """packets=0 from a source that counts them is meaningful."""
        e = event('flow', packets=0)
        self.assertTrue(evaluate_condition({'packets': 0}, e))


class TestRendering(unittest.TestCase):

    def setUp(self):
        self.e = event('tls', src_ip='10.0.0.5', dst_port=443,
                       fields={'src_name': 'hvac-pc', 'sni': 'example.test'})

    def test_substitution(self):
        self.assertEqual(render('{src_name} -> {sni}:{dst_port}', self.e),
                         'hvac-pc -> example.test:443')

    def test_a_missing_field_does_not_raise(self):
        self.assertEqual(render('{nope}', self.e), '?')

    def test_format_expressions_are_not_evaluated(self):
        """
        str.format on a rule-supplied string would expose the interpreter via
        `{x.__class__.__mro__}`. Rules are edited by site operators and shipped
        between sites; that is not a boundary to leave open.
        """
        for hostile in ('{sni.__class__}', '{sni!r}', '{sni:>100}',
                        '{0.__class__.__mro__}', '{sni[0]}'):
            with self.subTest(template=hostile):
                self.assertEqual(render(hostile, self.e), hostile)

    def test_braces_without_a_name_are_left_alone(self):
        self.assertEqual(render('{} {{}}', self.e), '{} {{}}')

    def test_empty_template(self):
        self.assertEqual(render('', self.e), '')
        self.assertEqual(render(None, self.e), '')


# ─── Load-time validation ────────────────────────────────────────────────────

class TestRuleValidation(unittest.TestCase):

    def assertRefused(self, spec, fragment):
        with self.assertRaises(RuleError) as ctx:
            Rule(spec)
        self.assertIn(fragment, str(ctx.exception))

    def test_a_rule_needs_an_id(self):
        self.assertRefused({'when': {'kind': 'dns'}}, 'needs an id')

    def test_a_field_rule_needs_a_condition(self):
        """Otherwise it matches every event, which nobody means."""
        self.assertRefused({'id': 'x'}, 'needs a `when`')

    def test_an_unknown_operator_is_caught_at_load(self):
        self.assertRefused({'id': 'x', 'when': {'a': {'greater': 1}}},
                           "unknown operator 'greater'")

    def test_an_unknown_operator_in_a_nested_condition_is_caught(self):
        self.assertRefused(
            {'id': 'x', 'when': {'any': [{'a': {'bogus': 1}}]}}, 'bogus')

    def test_an_unknown_operator_in_unless_is_caught(self):
        self.assertRefused({'id': 'x', 'when': {'kind': 'dns'},
                            'unless': {'a': {'bogus': 1}}}, 'unless')

    def test_an_unknown_tier_is_caught(self):
        self.assertRefused({'id': 'x', 'when': {'kind': 'dns'}, 'tier': 'urgent'},
                           'tier must be')

    def test_a_stateful_rule_needs_a_registered_handler(self):
        self.assertRefused({'id': 'x', 'type': 'stateful', 'handler': 'nope'},
                           'no handler named')

    def test_a_stateful_rule_needs_a_handler_name(self):
        self.assertRefused({'id': 'x', 'type': 'stateful'}, 'needs a handler')

    def test_an_unknown_severity_becomes_medium_rather_than_failing(self):
        """A severity typo should not stop the whole file loading."""
        self.assertEqual(Rule({'id': 'x', 'when': {'kind': 'dns'},
                               'severity': 'catastrophic'}).severity,
                         Severity.MEDIUM)

    def test_duplicate_ids_are_refused(self):
        rules = [Rule({'id': 'x', 'when': {'kind': 'dns'}}),
                 Rule({'id': 'x', 'when': {'kind': 'tls'}})]
        with self.assertRaises(RuleError) as ctx:
            RuleSet(rules)
        self.assertIn('duplicate rule id', str(ctx.exception))

    def test_the_offending_file_is_named(self):
        handle, path = tempfile.mkstemp(suffix='.yaml')
        with os.fdopen(handle, 'w') as f:
            f.write("- id: broken\n  when: {a: {bogus: 1}}\n")
        self.addCleanup(os.unlink, path)
        with self.assertRaises(RuleError) as ctx:
            load_rules(path)
        self.assertIn(os.path.basename(path), str(ctx.exception))


class TestRuleSetBehaviour(unittest.TestCase):

    def test_a_rule_that_raises_does_not_stop_the_others(self):
        """One bad regex should not take the monitor down."""
        class Exploding(Rule):
            def evaluate(self, e):
                raise RuntimeError('boom')

        rules = RuleSet([Exploding({'id': 'bad', 'when': {'kind': 'dns'}}),
                         Rule({'id': 'good', 'when': {'kind': 'dns'},
                               'title': 'fired'})])
        with self.assertLogs('netmon.rules', level='ERROR'):
            findings = rules.evaluate(event('dns'))
        self.assertEqual([f.rule_id for f in findings], ['good'])

    def test_disabled_rules_do_not_fire(self):
        rules = RuleSet([Rule({'id': 'x', 'when': {'kind': 'dns'},
                               'enabled': False})])
        self.assertEqual(rules.evaluate(event('dns')), [])

    def test_a_rule_can_be_disabled_at_runtime(self):
        rules = RuleSet([Rule({'id': 'x', 'when': {'kind': 'dns'}})])
        self.assertTrue(rules.enable('x', False))
        self.assertEqual(rules.evaluate(event('dns')), [])

    def test_escalation_raises_severity_and_tier_in_context(self):
        rule = Rule({'id': 'x', 'when': {'kind': 'dns'}, 'severity': 'low',
                     'tier': 'digest', 'title': 't',
                     'escalate': {'when': {'src_zone': 'ot'},
                                  'severity': 'critical', 'tier': 'push'}})
        quiet = rule.evaluate(event('dns', fields={'src_zone': 'corporate'}))[0]
        self.assertEqual((quiet.severity, quiet.tier), ('low', 'digest'))
        loud = rule.evaluate(event('dns', fields={'src_zone': 'ot'}))[0]
        self.assertEqual((loud.severity, loud.tier), ('critical', 'push'))

    def test_unless_cancels_a_match(self):
        rule = Rule({'id': 'x', 'when': {'kind': 'dns'},
                     'unless': {'dst_is_gateway': True}})
        self.assertEqual(rule.evaluate(event('dns', fields={'dst_is_gateway': True})), [])
        self.assertEqual(len(rule.evaluate(event('dns'))), 1)

    def test_the_device_falls_back_when_the_named_field_is_empty(self):
        """A finding with no device cannot be deduplicated or acknowledged."""
        rule = Rule({'id': 'x', 'when': {'kind': 'dns'}, 'device': 'src_name'})
        finding = rule.evaluate(event('dns', src_ip='10.0.0.9'))[0]
        self.assertEqual(finding.device, '10.0.0.9')


# ─── Enrichment decisions worth pinning down ─────────────────────────────────

class TestInsideOrOutside(unittest.TestCase):
    """
    Whether an address is off-site. `ipaddress.is_private` answers a different
    question and gets both edges wrong, so this is written out explicitly.
    """

    def setUp(self):
        self.profile = load_profile(EXAMPLE)

    def direction_to(self, ip):
        evt = event(src_ip='10.10.60.50', dst_ip=ip)
        enrich(evt, self.profile)
        return evt.get('direction')

    def test_rfc1918_is_inside(self):
        for ip in ('10.0.0.1', '172.16.5.5', '192.168.1.1'):
            with self.subTest(ip=ip):
                self.assertEqual(self.direction_to(ip), 'internal')

    def test_carrier_nat_is_inside(self):
        """`is_private` says False for 100.64/10, but it is not the internet."""
        self.assertEqual(self.direction_to('100.64.1.1'), 'internal')

    def test_documentation_ranges_are_outside(self):
        """
        `is_private` says True for these. A device reaching one has left the
        building by any definition that matters here, and using is_private would
        have made every outbound rule silently miss them.
        """
        for ip in ('203.0.113.9', '198.51.100.1', '192.0.2.1'):
            with self.subTest(ip=ip):
                self.assertEqual(self.direction_to(ip), 'outbound')

    def test_real_public_addresses_are_outside(self):
        self.assertEqual(self.direction_to('8.8.8.8'), 'outbound')

    def test_link_local_and_loopback_are_inside(self):
        for ip in ('169.254.1.1', '127.0.0.1'):
            with self.subTest(ip=ip):
                self.assertEqual(self.direction_to(ip), 'internal')

    def test_multicast_is_inside(self):
        self.assertEqual(self.direction_to('224.0.0.251'), 'internal')

    def test_inbound_is_recognised(self):
        evt = event(src_ip='8.8.8.8', dst_ip='10.10.60.50')
        enrich(evt, self.profile)
        self.assertEqual(evt.get('direction'), 'inbound')

    def test_a_malformed_address_does_not_raise(self):
        self.assertEqual(self.direction_to('not-an-ip'), 'internal')


class TestBacnetAllowlistFailsClosed(unittest.TestCase):
    """
    An allowlist entry scoped to specific objects must not authorise a message
    that names none. Otherwise one narrow exception — "this workstation may
    change setpoint 7" — silently authorises every write from that source whose
    object the parser could not read.
    """

    def setUp(self):
        self.profile = SiteProfile({'bacnet_write_allowlist': [
            {'src': '10.0.0.9', 'dst': ['10.0.0.20'], 'objects': ['analog-value-7']},
            {'src': '10.0.0.1', 'dst': ['10.0.0.20']},
        ]})

    def test_the_named_object_is_allowed(self):
        self.assertTrue(self.profile.bacnet_write_allowed(
            '10.0.0.9', '10.0.0.20', 'analog-value-7'))

    def test_another_object_is_not(self):
        self.assertFalse(self.profile.bacnet_write_allowed(
            '10.0.0.9', '10.0.0.20', 'binary-output-1'))

    def test_an_unnamed_object_is_not_covered_by_a_scoped_entry(self):
        self.assertFalse(self.profile.bacnet_write_allowed(
            '10.0.0.9', '10.0.0.20', None))

    def test_an_unscoped_entry_still_covers_everything_from_that_source(self):
        """Scoping is opt-in; an entry without `objects` means what it says."""
        self.assertTrue(self.profile.bacnet_write_allowed('10.0.0.1', '10.0.0.20'))
        self.assertTrue(self.profile.bacnet_write_allowed(
            '10.0.0.1', '10.0.0.20', 'anything'))


class TestTwoKindsOfWatchedName(unittest.TestCase):
    """
    `watched_names` are destinations nobody should reach; `poisonable_names` are
    local names only their owner may answer. Conflating them makes the poisoning
    rule silently never fire, because a site's list of bad destinations never
    contains its own hostnames.
    """

    def setUp(self):
        self.profile = SiteProfile({'watched_names': ['anydesk', 'ngrok'],
                                    'poisonable_names': ['wpad', 'occ-fs02']})

    def enriched(self, **fields):
        evt = event('dns', src_ip='10.0.0.5', fields=fields)
        enrich(evt, self.profile)
        return evt

    def test_a_watched_destination_is_matched_on_sni(self):
        evt = self.enriched(sni='relay-9f2.net.anydesk.com')
        self.assertEqual(evt.get('watched_name'), 'anydesk')
        self.assertEqual(evt.get('poisonable_name'), '')

    def test_a_poisonable_name_is_matched_on_the_query(self):
        evt = self.enriched(query='wpad.local')
        self.assertEqual(evt.get('poisonable_name'), 'wpad')
        self.assertEqual(evt.get('watched_name'), '')

    def test_a_poisonable_name_is_not_matched_from_an_sni(self):
        """A site whose hostname appears in someone's certificate is not poisoning."""
        evt = self.enriched(sni='occ-fs02.example.test')
        self.assertEqual(evt.get('poisonable_name'), '')

    def test_neither_list_matches_ordinary_traffic(self):
        evt = self.enriched(sni='www.example.test', query='www.example.test')
        self.assertEqual(evt.get('watched_name'), '')
        self.assertEqual(evt.get('poisonable_name'), '')

    def test_matching_ignores_case(self):
        self.assertEqual(self.enriched(query='WPAD').get('poisonable_name'), 'wpad')


# ─── Deduplication ───────────────────────────────────────────────────────────

class TestDeduplicator(unittest.TestCase):

    def setUp(self):
        self.now = [1000.0]
        self.dedup = Deduplicator(window_sec=60, clock=lambda: self.now[0])

    def make(self, key='k'):
        return Finding('r', 'title', device='dev', key=key)

    def test_the_first_occurrence_goes_out(self):
        self.assertIsNotNone(self.dedup.admit(self.make()))

    def test_repeats_within_the_window_are_held(self):
        self.dedup.admit(self.make())
        for _ in range(5):
            self.assertIsNone(self.dedup.admit(self.make()))

    def test_repeats_are_counted_not_discarded(self):
        """1,017 requests should report as 1,017, not as one."""
        first = self.make()
        self.dedup.admit(first)
        for _ in range(1016):
            self.dedup.admit(self.make())
        self.assertEqual(first.count, 1017)

    def test_a_new_window_reports_again(self):
        self.dedup.admit(self.make())
        self.now[0] += 61
        self.assertIsNotNone(self.dedup.admit(self.make()))

    def test_different_keys_are_separate(self):
        self.assertIsNotNone(self.dedup.admit(self.make('a')))
        self.assertIsNotNone(self.dedup.admit(self.make('b')))

    def test_snooze_silences_one_identity(self):
        self.dedup.snooze('r', 'dev', 'k', seconds=100)
        self.assertIsNone(self.dedup.admit(self.make()))

    def test_snooze_expires(self):
        self.dedup.snooze('r', 'dev', 'k', seconds=100)
        self.dedup.admit(self.make())
        self.now[0] += 101
        self.assertIsNotNone(self.dedup.admit(self.make()))

    def test_snooze_does_not_silence_other_devices(self):
        self.dedup.snooze('r', 'other', 'k', seconds=100)
        self.assertIsNotNone(self.dedup.admit(self.make()))

    def test_suppressed_counts_are_reportable(self):
        for _ in range(4):
            self.dedup.admit(self.make())
        self.assertEqual(self.dedup.suppressed_counts()[('r', 'dev', 'k')], 4)


# ─── The shipped rules, against what they were written from ──────────────────

class _RuleScenario(unittest.TestCase):
    """Fires one rule at a time, with the profile's enrichment applied."""

    @classmethod
    def setUpClass(cls):
        cls.profile = load_profile(EXAMPLE)
        cls.rules = load_rules(CORE_RULES)

    def fire(self, rule_id, evt, **enrich_kw):
        enrich(evt, self.profile, **enrich_kw)
        rule = self.rules.by_id(rule_id)
        self.assertIsNotNone(rule, f'no rule {rule_id}')
        rule.state = {}
        return rule.evaluate(evt)

    def assertFires(self, rule_id, evt, **kw):
        findings = self.fire(rule_id, evt, **kw)
        self.assertTrue(findings, f'{rule_id} did not fire')
        return findings[0]

    def assertQuiet(self, rule_id, evt, **kw):
        findings = self.fire(rule_id, evt, **kw)
        self.assertFalse(findings,
                         f'{rule_id} fired when it should not: '
                         f'{[f.description for f in findings]}')


class TestCoreRules(_RuleScenario):

    def test_the_file_loads(self):
        self.assertGreaterEqual(len(self.rules), 15)

    def test_bad_address(self):
        """A camera's address appearing on the management VLAN's tag."""
        self.assertFires('bad_address',
                         event(src_ip='10.10.30.41', dst_ip='10.10.1.1', vlan=1))

    def test_bad_address_stays_quiet_when_the_address_fits(self):
        self.assertQuiet('bad_address',
                         event(src_ip='10.10.20.21', dst_ip='10.10.20.10', vlan=20))

    def test_bad_address_catches_link_local(self):
        self.assertFires('bad_address',
                         event(src_ip='169.254.54.30', dst_ip='10.10.1.1'))

    def test_rogue_dhcp(self):
        self.assertFires('rogue_dhcp_ra',
                         event('dhcp', src_ip='10.10.60.50', src_mac='00:11:22:00:00:40',
                               fields={'message': 'offer'}))

    def test_the_gateway_answering_dhcp_is_fine(self):
        self.assertQuiet('rogue_dhcp_ra',
                         event('dhcp', src_ip='10.10.20.1',
                               fields={'message': 'offer'}))

    def test_name_poisoning(self):
        self.assertFires('name_poisoning',
                         event('llmnr', src_ip='10.10.60.50',
                               fields={'is_answer': True, 'query': 'wpad'}))

    def test_a_query_for_a_watched_name_is_not_poisoning(self):
        """Asking is normal; answering is the problem."""
        self.assertQuiet('name_poisoning',
                         event('llmnr', src_ip='10.10.60.50',
                               fields={'is_answer': False, 'query': 'wpad'}))

    def test_the_rightful_owner_answering_is_fine(self):
        self.assertQuiet('name_poisoning',
                         event('llmnr', src_ip='10.10.60.50',
                               fields={'is_answer': True, 'query': 'wpad',
                                       'answer_owner': True}))

    def test_dns_bypass(self):
        self.assertFires('dns_bypass',
                         event('dns', src_ip='10.10.60.50', dst_ip='1.1.1.1',
                               dst_port=53, fields={'query': 'example.test'}))

    def test_dns_to_the_gateway_is_fine(self):
        self.assertQuiet('dns_bypass',
                         event('dns', src_ip='10.10.60.50', dst_ip='10.10.60.1',
                               dst_port=53))

    def test_dns_bypass_escalates_on_a_controller_vlan(self):
        finding = self.assertFires(
            'dns_bypass',
            event('dns', src_ip='10.10.20.21', dst_ip='1.1.1.1', dst_port=53))
        self.assertEqual(finding.tier, Tier.PUSH)
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_a_restricted_vlan_is_exempt_from_dns_inspection(self):
        """Its payload is never read, so there is nothing to judge."""
        self.assertQuiet('dns_bypass',
                         event('dns', src_ip='10.10.40.10', dst_ip='1.1.1.1',
                               dst_port=53, vlan=40))

    def test_remote_access_tool(self):
        finding = self.assertFires(
            'remote_access_tool',
            event('tls', src_ip='10.10.60.50', dst_ip='203.0.113.7',
                  dst_port=443, fields={'sni': 'relay-9f2.net.anydesk.com'}))
        self.assertIn('anydesk', finding.description)

    def test_the_approved_tool_is_not_reported(self):
        self.assertQuiet('remote_access_tool',
                         event('tls', src_ip='10.10.20.10', dst_ip='203.0.113.8',
                               dst_port=443, fields={'sni': 'rmm.example-msp.test'}))

    def test_remote_access_escalates_on_a_controller(self):
        finding = self.assertFires(
            'remote_access_tool',
            event('tls', src_ip='10.10.20.21', dst_ip='203.0.113.7',
                  dst_port=443, fields={'sni': 'relay-9f2.net.anydesk.com'}))
        self.assertEqual(finding.tier, Tier.PUSH)
        self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_vpn_tunnel_by_port(self):
        self.assertFires('vpn_tunnel',
                         event(src_ip='10.10.60.50', dst_ip='203.0.113.20',
                               dst_port=51820, protocol='udp'))

    def test_vpn_tunnel_by_name(self):
        self.assertFires('vpn_tunnel',
                         event('tls', src_ip='10.10.60.50', dst_ip='203.0.113.21',
                               dst_port=443,
                               fields={'sni': 'controlplane.tailscale.com'}))

    def test_ordinary_https_is_not_a_tunnel(self):
        self.assertQuiet('vpn_tunnel',
                         event('tls', src_ip='10.10.60.50', dst_ip='203.0.113.22',
                               dst_port=443, fields={'sni': 'www.example.test'}))

    def test_port_mapping_request(self):
        self.assertFires('port_mapping_request',
                         event(src_ip='10.10.60.50', dst_ip='10.10.60.1',
                               dst_port=5351, protocol='udp'))

    def test_cleartext_credentials_reports_the_fact_not_the_value(self):
        finding = self.assertFires(
            'cleartext_credentials',
            event('http', src_ip='10.10.60.50', dst_ip='10.10.20.10', dst_port=80,
                  fields={'credential_type': 'http-basic',
                          'credential_value': 'hunter2'}))
        blob = (finding.description + str(finding.evidence)
                + finding.key + finding.next_check)
        self.assertNotIn('hunter2', blob)
        self.assertIn('http-basic', finding.description)

    def test_cleartext_credentials_is_not_reported_from_a_restricted_vlan(self):
        """
        The segment whose payload is never stored. There is nothing to report
        from because nothing was captured — and reporting would imply otherwise.
        """
        self.assertQuiet('cleartext_credentials',
                         event('http', src_ip='10.10.40.10', dst_ip='10.10.40.11',
                               dst_port=80, vlan=40,
                               fields={'credential_type': 'http-basic'}))

    def test_dmz_inbound(self):
        profile = SiteProfile({
            'vlans': {70: {'name': 'dmz', 'subnet': '192.168.1.0/24', 'zone': 'dmz'},
                      20: {'name': 'ot', 'subnet': '10.10.20.0/24', 'zone': 'ot'}}})
        evt = event(src_ip='192.168.1.239', dst_ip='10.10.20.10', dst_port=445)
        enrich(evt, profile)
        rule = self.rules.by_id('dmz_inbound')
        self.assertTrue(rule.evaluate(evt))

    def test_blocked_egress(self):
        self.assertFires('blocked_egress',
                         event(src_ip='10.10.60.50', dst_ip='203.0.113.99',
                               dst_port=443,
                               fields={'action': 'blocked', 'direction': 'outgoing',
                                       'policy': 'threat-list'}))

    def test_an_allowed_flow_is_not_a_block(self):
        self.assertQuiet('blocked_egress',
                         event(src_ip='10.10.60.50', dst_ip='203.0.113.99',
                               fields={'action': 'allowed', 'direction': 'outgoing'}))

    def test_cross_vlan_unexpected(self):
        finding = self.assertFires(
            'cross_vlan_unexpected',
            event(src_ip='10.10.60.50', dst_ip='10.10.20.21', dst_port=22,
                  protocol='tcp'))
        self.assertEqual(finding.tier, Tier.PUSH)     # into the ot zone

    def test_an_expected_cross_vlan_flow_is_quiet(self):
        """Operators viewing the BAS web UI — listed in the profile."""
        self.assertQuiet('cross_vlan_unexpected',
                         event(src_ip='10.10.60.50', dst_ip='10.10.20.10',
                               dst_port=443, protocol='tcp'))

    def test_a_muted_dead_reference_is_quiet(self):
        self.assertQuiet('cross_vlan_unexpected',
                         event(src_ip='10.10.60.50', dst_ip='10.10.20.99',
                               dst_port=502, protocol='tcp'))

    def test_bacnet_control(self):
        finding = self.assertFires(
            'bacnet_control',
            event('bacnet', src_ip='10.10.60.50', dst_ip='10.10.20.21',
                  dst_port=47808, protocol='udp',
                  fields={'service': 'WriteProperty', 'object': 'analog-value-3'}))
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.tier, Tier.PUSH)

    def test_an_allowlisted_bacnet_write_is_quiet(self):
        self.assertQuiet('bacnet_control',
                         event('bacnet', src_ip='10.10.20.10', dst_ip='10.10.20.21',
                               dst_port=47808, protocol='udp',
                               fields={'service': 'WriteProperty'}))

    def test_the_object_scoped_exception_is_honoured(self):
        self.assertQuiet('bacnet_control',
                         event('bacnet', src_ip='10.10.60.50', dst_ip='10.10.20.21',
                               fields={'service': 'WriteProperty',
                                       'object': 'analog-value-7'}))

    def test_the_object_scoped_exception_does_not_cover_other_objects(self):
        self.assertFires('bacnet_control',
                         event('bacnet', src_ip='10.10.60.50', dst_ip='10.10.20.21',
                               fields={'service': 'WriteProperty',
                                       'object': 'binary-output-1'}))

    def test_a_bacnet_read_is_not_a_control_message(self):
        self.assertQuiet('bacnet_control',
                         event('bacnet', src_ip='10.10.60.50', dst_ip='10.10.20.21',
                               fields={'service': 'ReadProperty'}))

    def test_bacnet_topology(self):
        self.assertFires('bacnet_topology',
                         event('bacnet', src_ip='10.10.60.50', dst_ip='10.10.20.21',
                               fields={'service': 'WriteBroadcastDistributionTable',
                                       'peer': '192.168.0.7'}))

    def test_sensor_chatter_is_inert_without_configured_capture_macs(self):
        """A site that has not listed its capture NICs gets silence, not noise."""
        self.assertQuiet('sensor_chatter',
                         event('dhcp', src_mac='00:11:22:00:00:40',
                               src_ip='10.10.60.50'))

    def test_sensor_chatter_fires_on_a_configured_capture_mac(self):
        evt = event('dhcp', src_mac='00:11:22:ff:ff:01', vlan=20)
        enrich(evt, self.profile)
        self.assertTrue(self.rules.by_id('sensor_chatter').evaluate(evt))


class TestStatefulRules(_RuleScenario):

    def state_for(self, rule_id):
        rule = self.rules.by_id(rule_id)
        rule.state = {}
        return rule

    def feed(self, rule, events):
        findings = []
        for evt in events:
            enrich(evt, self.profile)
            findings.extend(rule.evaluate(evt))
        return findings

    def test_new_device(self):
        rule = self.state_for('new_device')
        findings = self.feed(rule, [event(src_mac='aa:bb:cc:dd:ee:01',
                                          src_ip='10.10.20.77', vlan=20)])
        self.assertEqual(len(findings), 1)
        self.assertIn('aa:bb:cc:dd:ee:01', findings[0].description)

    def test_a_known_device_is_not_new(self):
        rule = self.state_for('new_device')
        self.assertEqual(self.feed(rule, [event(src_mac='00:11:22:00:00:02',
                                                src_ip='10.10.20.21')]), [])

    def test_a_new_device_reports_once(self):
        rule = self.state_for('new_device')
        events = [event(src_mac='aa:bb:cc:dd:ee:02', src_ip='10.10.20.78')
                  for _ in range(5)]
        self.assertEqual(len(self.feed(rule, events)), 1)

    def test_a_device_with_no_mac_is_skipped(self):
        """A flow export has no MAC; absence of evidence is not evidence."""
        rule = self.state_for('new_device')
        self.assertEqual(self.feed(rule, [event(src_ip='10.10.99.1')]), [])

    def test_overlapping_ip(self):
        rule = self.state_for('overlapping_ip')
        findings = self.feed(rule, [
            event(src_ip='10.10.20.50', src_mac='aa:bb:cc:00:00:01', vlan=20),
            event(src_ip='10.10.20.50', src_mac='aa:bb:cc:00:00:02', vlan=20)])
        self.assertEqual(len(findings), 1)
        self.assertIn('10.10.20.50', findings[0].description)

    def test_one_address_one_mac_is_quiet(self):
        rule = self.state_for('overlapping_ip')
        self.assertEqual(self.feed(rule, [
            event(src_ip='10.10.20.50', src_mac='aa:bb:cc:00:00:01'),
            event(src_ip='10.10.20.50', src_mac='aa:bb:cc:00:00:01')]), [])

    def test_overlapping_ip_reports_a_pair_once(self):
        rule = self.state_for('overlapping_ip')
        events = []
        for _ in range(4):
            events.append(event(src_ip='10.10.20.51', src_mac='aa:bb:cc:00:00:01'))
            events.append(event(src_ip='10.10.20.51', src_mac='aa:bb:cc:00:00:02'))
        self.assertEqual(len(self.feed(rule, events)), 1)

    def test_dhcp_loop(self):
        rule = self.state_for('dhcp_loop')
        events = [event('dhcp', src_mac='aa:bb:cc:00:00:09', ts=1000.0 + i * 3,
                        fields={'message': 'discover'}) for i in range(12)]
        findings = self.feed(rule, events)
        self.assertEqual(len(findings), 1)
        self.assertIn('10 DHCP', findings[0].description)

    def test_a_device_that_gets_an_offer_is_not_looping(self):
        rule = self.state_for('dhcp_loop')
        events = []
        for i in range(12):
            events.append(event('dhcp', src_mac='aa:bb:cc:00:00:0a',
                                ts=1000.0 + i * 3, fields={'message': 'discover'}))
            events.append(event('dhcp', src_ip='10.10.20.1',
                                dst_mac='aa:bb:cc:00:00:0a', ts=1000.0 + i * 3 + 1,
                                fields={'message': 'offer'}))
        self.assertEqual(self.feed(rule, events), [])

    def test_unanswered_name(self):
        rule = self.state_for('unanswered_name')
        events = [event('dns', src_ip='10.10.60.50', ts=1000.0 + i,
                        fields={'query': 'occ-fs02'}) for i in range(6)]
        findings = self.feed(rule, events)
        self.assertEqual(len(findings), 1)
        self.assertIn('occ-fs02', findings[0].description)

    def test_a_name_that_gets_answered_is_quiet(self):
        rule = self.state_for('unanswered_name')
        events = [event('dns', src_ip='10.10.60.50', ts=1000.0,
                        fields={'query': 'real.test', 'is_answer': True})]
        events += [event('dns', src_ip='10.10.60.50', ts=1000.0 + i,
                         fields={'query': 'real.test'}) for i in range(8)]
        self.assertEqual(self.feed(rule, events), [])

    def test_beaconing(self):
        rule = self.state_for('beaconing')
        events = [event('tls', src_ip='10.10.60.50', dst_ip='203.0.113.50',
                        dst_port=8443, ts=1000.0 + i * 3600)
                  for i in range(14)]
        findings = self.feed(rule, events)
        self.assertEqual(len(findings), 1)
        self.assertIn('3600s', findings[0].description)

    def test_irregular_traffic_is_not_beaconing(self):
        rule = self.state_for('beaconing')
        offsets = [0, 7, 400, 402, 900, 3000, 3005, 12000, 12500, 30000,
                   30001, 61000, 61050, 90000]
        events = [event('tls', src_ip='10.10.60.50', dst_ip='203.0.113.51',
                        dst_port=8443, ts=1000.0 + o) for o in offsets]
        self.assertEqual(self.feed(rule, events), [])

    def test_ntp_is_not_reported_as_beaconing(self):
        """It is periodic by design; so are software updaters and this is why
        the rule excludes the ports where periodicity is the whole point."""
        rule = self.state_for('beaconing')
        events = [event(src_ip='10.10.60.50', dst_ip='203.0.113.52',
                        dst_port=123, protocol='udp', ts=1000.0 + i * 64)
                  for i in range(20)]
        self.assertEqual(self.feed(rule, events), [])

    def test_new_destination_learns_before_it_reports(self):
        rule = self.state_for('egress_new_destination')
        early = [event('tls', src_ip='10.10.20.21', dst_ip='203.0.113.60',
                       ts=1000.0, fields={'sni': 'a.test'}),
                 event('tls', src_ip='10.10.20.21', dst_ip='203.0.113.61',
                       ts=2000.0, fields={'sni': 'b.test'})]
        self.assertEqual(self.feed(rule, early), [])

    def test_new_destination_reports_after_the_learning_window(self):
        rule = self.state_for('egress_new_destination')
        self.feed(rule, [event('tls', src_ip='10.10.20.21', dst_ip='203.0.113.60',
                               ts=1000.0, fields={'sni': 'a.test'})])
        later = event('tls', src_ip='10.10.20.21', dst_ip='203.0.113.99',
                      ts=1000.0 + 700_000, fields={'sni': 'new.test'})
        findings = self.feed(rule, [later])
        self.assertEqual(len(findings), 1)
        self.assertIn('new.test', findings[0].description)

    def test_new_destination_ignores_zones_it_is_not_scoped_to(self):
        rule = self.state_for('egress_new_destination')
        self.feed(rule, [event('tls', src_ip='10.10.60.50', ts=1000.0,
                               dst_ip='203.0.113.60', fields={'sni': 'a.test'})])
        self.assertEqual(self.feed(rule, [
            event('tls', src_ip='10.10.60.50', ts=1000.0 + 700_000,
                  dst_ip='203.0.113.99', fields={'sni': 'z.test'})]), [])

    def test_upload_volume_needs_history_before_it_judges(self):
        rule = self.state_for('upload_anomaly')
        self.assertEqual(self.feed(rule, [
            event(src_ip='10.10.60.50', dst_ip='203.0.113.70',
                  bytes_to_dst=500 * 1024 * 1024, ts=86400.0 * 10)]), [])

    def test_upload_volume_reports_a_spike_against_the_device_baseline(self):
        rule = self.state_for('upload_anomaly')
        quiet_days = [event(src_ip='10.10.60.50', dst_ip='203.0.113.70',
                            bytes_to_dst=60 * 1024 * 1024, ts=86400.0 * day + 43200)
                      for day in range(10, 20)]
        self.feed(rule, quiet_days)
        spike = event(src_ip='10.10.60.50', dst_ip='203.0.113.70',
                      bytes_to_dst=600 * 1024 * 1024, ts=86400.0 * 21 + 43200)
        findings = self.feed(rule, [spike])
        self.assertEqual(len(findings), 1)
        self.assertIn('MB', findings[0].description)

    def test_a_normal_day_does_not_report(self):
        rule = self.state_for('upload_anomaly')
        days = [event(src_ip='10.10.60.50', dst_ip='203.0.113.70',
                      bytes_to_dst=60 * 1024 * 1024, ts=86400.0 * day + 43200)
                for day in range(10, 25)]
        self.assertEqual(self.feed(rule, days), [])


class TestRulesAreWellFormed(_RuleScenario):
    """Properties every shipped rule should have, checked rather than assumed."""

    def test_every_rule_has_a_title(self):
        for rule in self.rules:
            self.assertTrue(rule.title and rule.title != rule.id, rule.id)

    def test_every_rule_says_what_it_is_grounded_in(self):
        """A rule nobody can trace to a real observation is one nobody trusts."""
        for rule in self.rules:
            with self.subTest(rule=rule.id):
                self.assertTrue(rule.grounded_in.strip(),
                                f'{rule.id} has no grounded_in')

    def test_every_field_rule_describes_its_finding(self):
        for rule in self.rules:
            if rule.type == 'field':
                with self.subTest(rule=rule.id):
                    self.assertTrue(rule.describe, f'{rule.id} has no describe')

    def test_every_field_rule_offers_a_next_check(self):
        """An alert with no suggested next step is a notification, not a finding."""
        for rule in self.rules:
            if rule.type == 'field':
                with self.subTest(rule=rule.id):
                    self.assertTrue(rule.next_check, f'{rule.id} has no next_check')

    def test_no_rule_puts_a_credential_field_in_its_evidence(self):
        """
        Evidence is written to logs, sent in alerts and included in AI prompts.
        A rule that names a value-bearing field there would carry the secret
        into all three.
        """
        forbidden = {'credential_value', 'password', 'cookie', 'session',
                     'card', 'rfid', 'payload', 'token', 'secret', 'hash'}
        for rule in self.rules:
            for name in rule.evidence_fields:
                with self.subTest(rule=rule.id, field=name):
                    self.assertFalse(
                        any(word in name.lower() for word in forbidden),
                        f'{rule.id} would put {name} into evidence')

    def test_no_rule_renders_a_payload_field_into_its_description(self):
        for rule in self.rules:
            for template in (rule.describe, rule.key_template, rule.next_check):
                with self.subTest(rule=rule.id):
                    for word in ('payload', 'credential_value', 'cookie', 'card'):
                        self.assertNotIn('{' + word, str(template))

    def test_push_rules_are_at_least_medium(self):
        """An immediate notification for something low is how push gets muted."""
        for rule in self.rules:
            if rule.tier == Tier.PUSH:
                with self.subTest(rule=rule.id):
                    self.assertGreaterEqual(Severity.rank(rule.severity),
                                            Severity.rank(Severity.MEDIUM))

    def test_no_rule_fires_on_an_empty_event(self):
        """
        A bare event with nothing filled in should match nothing. A rule that
        fires here would fire on every unparsed packet in the capture.
        """
        for rule in self.rules:
            if rule.type != 'field':
                continue
            evt = Event(kind='unknown')
            enrich(evt, self.profile)
            with self.subTest(rule=rule.id):
                self.assertEqual(rule.evaluate(evt), [],
                                 f'{rule.id} fired on an empty event')


if __name__ == '__main__':
    unittest.main(verbosity=2)
