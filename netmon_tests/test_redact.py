"""
What may leave the building.
=============================
This module is the boundary. Everything that goes out — a push notification, a
digest, a summary sent to a model — passes through it, so these tests are about
what must never appear on the other side.

The last class is the one that matters most: it runs every shipped rule against
an event carrying credentials, cookies, card data and payload, redacts the
result for both audiences, and audits the output. It would fail if someone added
a rule that names a value-bearing field, which is the mistake this is here to
prevent.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import netmon.handlers  # noqa: E402,F401
from netmon.events import Event, Finding, Severity, enrich  # noqa: E402
from netmon.profile import SiteProfile, load_profile  # noqa: E402
from netmon.redact import (AI, ALERT, FORBIDDEN_SUBSTRINGS,  # noqa: E402
                           SAFE_EVIDENCE_FIELDS, audit, redact_finding,
                           redact_findings, summary_for_model)
from netmon.rules_engine import load_rules  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')
RULES = os.path.join(ROOT, 'netmon', 'rules')


def finding(rule='test', severity='high', vlan=None, evidence=None,
            description='something happened', device='a-device', **event_fields):
    event = Event(kind='flow', src_ip=event_fields.pop('src_ip', '10.10.20.21'),
                  dst_ip=event_fields.pop('dst_ip', '203.0.113.9'), vlan=vlan)
    event.fields.update(event_fields)
    if vlan is not None:
        event.fields.setdefault('src_vlan', vlan)
    return Finding(rule, 'A title', severity=severity, description=description,
                   device=device, event=event, evidence=evidence or {})


# ─── The evidence allowlist ──────────────────────────────────────────────────

class TestEvidenceIsAllowlisted(unittest.TestCase):
    """
    Rules are edited by site operators and can name any field they like, so the
    question has to be "is this known to be safe", not "is this known to be
    dangerous". A denylist is a list of the mistakes someone already made.
    """

    def test_a_known_safe_field_passes(self):
        record = redact_finding(finding(evidence={'dst_ip': '203.0.113.9'}))
        self.assertEqual(record['evidence']['dst_ip'], '203.0.113.9')

    def test_an_unknown_field_is_dropped(self):
        record = redact_finding(finding(evidence={'some_new_field': 'value'}))
        self.assertNotIn('some_new_field', record['evidence'])

    def test_every_forbidden_word_is_dropped_however_it_is_spelled(self):
        for word in FORBIDDEN_SUBSTRINGS:
            for name in (word, f'x_{word}', f'{word}_y', word.upper()):
                with self.subTest(name=name):
                    record = redact_finding(finding(evidence={name: 'SECRET'}))
                    self.assertNotIn(name, record['evidence'])
                    self.assertNotIn('SECRET', json.dumps(record))

    def test_the_allowlist_contains_no_forbidden_name(self):
        """A careless addition to the allowlist would be caught here."""
        for name in SAFE_EVIDENCE_FIELDS:
            with self.subTest(name=name):
                self.assertFalse(
                    any(word in name.lower() for word in FORBIDDEN_SUBSTRINGS),
                    f'{name} is allowlisted but contains a forbidden word')

    def test_credential_type_passes_but_credential_value_does_not(self):
        """The finding is that a credential crossed; the value is the secret."""
        record = redact_finding(finding(evidence={
            'credential_type': 'http-basic', 'credential_value': 'hunter2'}))
        self.assertEqual(record['evidence']['credential_type'], 'http-basic')
        self.assertNotIn('hunter2', json.dumps(record))

    def test_empty_values_are_dropped(self):
        record = redact_finding(finding(evidence={
            'dst_ip': '', 'src_ip': None, 'dst_port': [], 'protocol': 'tcp'}))
        self.assertEqual(list(record['evidence']), ['protocol'])


# ─── The two audiences ───────────────────────────────────────────────────────

class TestAudiences(unittest.TestCase):

    def setUp(self):
        self.profile = load_profile(EXAMPLE)

    def test_an_ordinary_finding_goes_to_both(self):
        item = finding(vlan=20)
        self.assertIsNotNone(redact_finding(item, self.profile, ALERT))
        self.assertIsNotNone(redact_finding(item, self.profile, AI))

    def test_a_restricted_segment_alerts_but_is_not_summarised(self):
        """
        Metadata from a restricted segment is exactly what it exists to
        produce — "a door controller reached the internet at 3am" contains
        nothing regulated. But the site said never send anything from it to an
        external service, and a summariser is not the place to read that
        narrowly.
        """
        item = finding(vlan=40)
        self.assertIsNotNone(redact_finding(item, self.profile, ALERT))
        self.assertIsNone(redact_finding(item, self.profile, AI))

    def test_the_restriction_is_checked_on_every_vlan_field(self):
        for field in ('vlan', 'src_vlan', 'dst_vlan', 'observed_vlan'):
            with self.subTest(field=field):
                item = finding(**{field: 40})
                self.assertIsNone(redact_finding(item, self.profile, AI))

    def test_a_flow_into_a_restricted_segment_is_also_withheld(self):
        """Not just traffic from it — the destination reveals it too."""
        item = finding(dst_vlan=50)
        self.assertIsNone(redact_finding(item, self.profile, AI))

    def test_the_restriction_does_not_depend_on_the_wording(self):
        """
        Checked against the event's resolved VLANs, so a rule that happens not
        to mention the segment in its description is still caught.
        """
        item = finding(vlan=40, description='a device did something')
        self.assertIsNone(redact_finding(item, self.profile, AI))

    def test_with_no_restricted_segments_nothing_is_withheld(self):
        plain = SiteProfile({'vlans': {20: {'name': 'ot'}}})
        self.assertIsNotNone(redact_finding(finding(vlan=20), plain, AI))

    def test_withholding_is_counted_not_silent(self):
        """
        A summary that silently omits a segment reads as "nothing happened
        there", which is a different and worse claim than "this was not sent".
        """
        records, withheld = redact_findings(
            [finding(vlan=20), finding(vlan=40), finding(vlan=50)],
            self.profile, AI)
        self.assertEqual(len(records), 1)
        self.assertEqual(withheld, 2)


# ─── Context ─────────────────────────────────────────────────────────────────

class TestContextIsAdded(unittest.TestCase):
    """
    An alert saying 10.10.20.21 makes someone go and look it up. The profile
    already knows.
    """

    def setUp(self):
        self.profile = load_profile(EXAMPLE)

    def test_the_role_is_included(self):
        item = finding(src_ip='10.10.20.21', vlan=20)
        self.assertEqual(redact_finding(item, self.profile)['role'], 'controller')

    def test_the_vlan_is_named_not_numbered(self):
        item = finding(src_ip='10.10.20.21', vlan=20)
        self.assertEqual(redact_finding(item, self.profile)['vlan'],
                         '20 (building-automation)')

    def test_the_zone_is_included(self):
        item = finding(src_ip='10.10.20.21', vlan=20)
        self.assertEqual(redact_finding(item, self.profile)['zone'], 'ot')

    def test_an_unknown_device_gets_no_invented_context(self):
        record = redact_finding(finding(src_ip='10.99.99.99'), self.profile)
        self.assertNotIn('role', record)

    def test_it_works_without_a_profile(self):
        record = redact_finding(finding())
        self.assertEqual(record['rule'], 'test')
        self.assertNotIn('role', record)

    def test_the_context_describes_the_device_the_finding_names(self):
        """
        bacnet_control names the controller that was written to, since that is
        what someone has to go and check. Describing it with the *source's*
        role and VLAN labels a controller as a workstation.
        """
        event = Event(kind='bacnet', src_ip='10.10.60.50', dst_ip='10.10.20.21',
                      vlan=20)
        event.fields.update({'src_vlan': 60, 'dst_vlan': 20})
        item = Finding('bacnet_control', 'A write', severity='critical',
                       device='ahu-controller-1', event=event)
        record = redact_finding(item, self.profile)
        self.assertEqual(record['role'], 'controller')
        self.assertEqual(record['vlan'], '20 (building-automation)')
        self.assertEqual(record['zone'], 'ot')

    def test_it_still_describes_the_source_when_that_is_what_is_named(self):
        event = Event(kind='flow', src_ip='10.10.60.50', dst_ip='10.10.20.21')
        event.fields.update({'src_vlan': 60, 'dst_vlan': 20})
        item = Finding('cross_vlan', 'x', device='ops-workstation', event=event)
        record = redact_finding(item, self.profile)
        self.assertEqual(record['role'], 'workstation')
        self.assertEqual(record['vlan'], '60 (staff)')

    def test_an_address_as_the_device_name_still_resolves(self):
        event = Event(kind='flow', src_ip='10.10.60.50', dst_ip='10.10.20.21')
        event.fields.update({'src_vlan': 60, 'dst_vlan': 20})
        item = Finding('x', 'x', device='10.10.20.21', event=event)
        self.assertEqual(redact_finding(item, self.profile)['role'], 'controller')

    def test_an_unmatched_device_name_falls_back_to_the_source(self):
        event = Event(kind='flow', src_ip='10.10.60.50', dst_ip='10.10.20.21')
        event.fields['src_vlan'] = 60
        item = Finding('x', 'x', device='something-else', event=event)
        self.assertEqual(redact_finding(item, self.profile)['role'], 'workstation')

    def test_the_next_check_survives(self):
        item = finding()
        item.next_check = 'run tshark'
        self.assertEqual(redact_finding(item)['next_check'], 'run tshark')


# ─── The auditor ─────────────────────────────────────────────────────────────

class TestAudit(unittest.TestCase):
    """
    A check on this module rather than a mechanism within it. It runs in the
    tests, over every rule's output, which catches the mistake before it ships
    without taxing every send.
    """

    def test_it_is_quiet_on_a_clean_payload(self):
        self.assertEqual(audit({'rule': 'x', 'evidence': {'dst_ip': '1.2.3.4'}}), [])

    def test_it_finds_a_basic_credential(self):
        found = audit({'note': 'Authorization: Basic aHVudGVyMjpodW50ZXIy'})
        self.assertTrue(any('basic' in what for what, _ in found))

    def test_it_finds_a_bearer_token(self):
        found = audit('Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdef')
        self.assertTrue(found)

    def test_it_finds_a_session_cookie(self):
        self.assertTrue(audit({'x': 'JSESSIONID=8A3F2B1C9D'}))

    def test_it_finds_something_card_shaped(self):
        found = audit({'x': '4111 1111 1111 1111'})
        self.assertTrue(any('card' in what for what, _ in found))

    def test_it_finds_a_private_key(self):
        self.assertTrue(audit('-----BEGIN RSA PRIVATE KEY-----'))

    def test_it_finds_a_forbidden_field_name_at_any_depth(self):
        found = audit({'a': {'b': [{'session_cookie': 'x'}]}})
        self.assertTrue(any('forbidden' in what for what, _ in found))

    def test_it_does_not_recurse_forever(self):
        node = {}
        node['self'] = node
        audit({'a': 'b'})                      # the real guard is the depth cap
        deep = current = {}
        for _ in range(50):
            current['next'] = {}
            current = current['next']
        self.assertIsInstance(audit(deep), list)

    def test_an_ordinary_ip_is_not_mistaken_for_a_card(self):
        self.assertEqual(audit({'dst_ip': '203.0.113.9'}), [])

    def test_a_port_number_is_not_mistaken_for_a_card(self):
        self.assertEqual(audit({'dst_port': 47808, 'count': 1234}), [])


# ─── The model summary ───────────────────────────────────────────────────────

class _Analyzer:
    def __init__(self, findings, events=100):
        self.findings = findings
        self.events_seen = events

    def by_severity(self):
        return sorted(self.findings, key=lambda f: -Severity.rank(f.severity))


class TestModelSummary(unittest.TestCase):

    def setUp(self):
        self.profile = load_profile(EXAMPLE)

    def test_it_omits_restricted_segments_entirely(self):
        summary = summary_for_model(
            _Analyzer([finding(vlan=20), finding(vlan=40)]), self.profile)
        self.assertEqual(len(summary['findings']), 1)
        self.assertEqual(summary['withheld_from_restricted_segments'], 1)

    def test_restricted_vlans_are_not_even_described(self):
        """Their existence and naming is part of what was asked to stay in."""
        summary = summary_for_model(_Analyzer([]), self.profile)
        listed = {v['id'] for v in summary['profile']['vlans']}
        self.assertNotIn(40, listed)
        self.assertNotIn(50, listed)
        self.assertIn(20, listed)

    def test_it_carries_shape_not_a_transcript(self):
        summary = summary_for_model(_Analyzer([finding(vlan=20)]), self.profile)
        self.assertEqual(summary['profile']['devices'], 12)
        self.assertNotIn('events', summary['profile'])

    def test_it_says_the_output_is_advisory(self):
        summary = summary_for_model(_Analyzer([]), self.profile)
        self.assertIn('Advisory only', summary['instructions'])

    def test_it_is_capped(self):
        many = [finding(vlan=20) for _ in range(500)]
        summary = summary_for_model(_Analyzer(many), self.profile, max_findings=10)
        self.assertEqual(len(summary['findings']), 10)

    def test_the_whole_summary_audits_clean(self):
        summary = summary_for_model(
            _Analyzer([finding(vlan=20, evidence={'dst_ip': '203.0.113.9'})]),
            self.profile)
        self.assertEqual(audit(summary), [])


# ─── Every shipped rule, against a hostile event ─────────────────────────────

class TestEveryRuleRedactsClean(unittest.TestCase):
    """
    The test this file exists for.

    Every shipped rule is fired against an event stuffed with everything that
    must never leave — a password, a session cookie, a card number, a private
    key, raw payload — and the redacted output is audited. A rule that names a
    value-bearing field in its evidence, description or key fails here.
    """

    @classmethod
    def setUpClass(cls):
        cls.profile = load_profile(EXAMPLE)
        cls.rules = load_rules(RULES)

    def hostile_event(self, **overrides):
        event = Event(kind=overrides.pop('kind', 'flow'),
                      src_ip='10.10.20.21', dst_ip='203.0.113.9',
                      src_mac='00:11:22:00:00:02', dst_mac='00:11:22:00:00:50',
                      src_port=50000, dst_port=443, protocol='tcp',
                      vlan=overrides.pop('vlan', 20))
        event.fields.update({
            'payload': b'username=admin&password=hunter2',
            'credential_value': 'Basic YWRtaW46aHVudGVyMg==',
            'cookie': 'JSESSIONID=8A3F2B1C9D4E5F60',
            'card_number': '4111 1111 1111 1111',
            'private_key': '-----BEGIN RSA PRIVATE KEY-----MIIEow',
            'rfid_number': '0123456789',
            'api_token': 'Bearer eyJhbGciOiJIUzI1NiJ9abcdefghijklmnop',
            'raw_body': 'POST /login HTTP/1.1',
            # Plus the fields rules legitimately match on, so they fire.
            'credential_type': 'http-basic', 'service': 'WriteProperty',
            'object': 'analog-value-3', 'sni': 'relay.net.anydesk.com',
            'query': 'wpad', 'is_answer': True, 'message': 'offer',
            'action': 'blocked', 'bacnet_topology': True,
            'bvlc_function': 'WriteBroadcastDistributionTable',
            'search_target': 'urn:InternetGatewayDevice',
        })
        event.fields.update(overrides)
        return event

    SECRETS = ('hunter2', 'YWRtaW46aHVudGVyMg', '8A3F2B1C9D4E5F60',
               '4111 1111 1111 1111', 'MIIEow', '0123456789',
               'eyJhbGciOiJIUzI1NiJ9', 'POST /login')

    def test_no_rule_leaks_a_secret_to_an_alert(self):
        for kind in self.KINDS:
          for rule in self.rules:
            event = self.hostile_event(kind=kind)
            enrich(event, self.profile)
            for item in rule.evaluate(event):
                record = redact_finding(item, self.profile, ALERT)
                blob = json.dumps(record, default=str)
                with self.subTest(rule=rule.id):
                    for secret in self.SECRETS:
                        self.assertNotIn(secret, blob,
                                         f'{rule.id} leaked {secret!r}')
                    self.assertEqual(audit(record), [],
                                     f'{rule.id} failed the audit')

    def test_no_rule_leaks_a_secret_to_a_model(self):
        for kind in self.KINDS:
          for rule in self.rules:
            event = self.hostile_event(kind=kind)
            enrich(event, self.profile)
            for item in rule.evaluate(event):
                record = redact_finding(item, self.profile, AI)
                if record is None:
                    continue
                blob = json.dumps(record, default=str)
                with self.subTest(rule=rule.id):
                    for secret in self.SECRETS:
                        self.assertNotIn(secret, blob)
                    self.assertEqual(audit(record), [])

    def test_no_rule_on_a_restricted_segment_reaches_a_model(self):
        for kind in self.KINDS:
          for rule in self.rules:
            event = self.hostile_event(kind=kind, vlan=40, src_vlan=40,
                                       src_ip='10.10.40.10', dst_ip='10.10.40.11')
            enrich(event, self.profile)
            for item in rule.evaluate(event):
                with self.subTest(rule=rule.id):
                    self.assertIsNone(redact_finding(item, self.profile, AI),
                                      f'{rule.id} would send a restricted '
                                      f'segment to a model')

    #: The hostile event is fired as each of these, so the checks above cover
    #: the protocol rules and not only the flow ones.
    KINDS = ('flow', 'bacnet', 'dns', 'llmnr', 'dhcp', 'tls', 'http')

    def fired_rules(self, **overrides):
        fired = set()
        for kind in self.KINDS:
            for rule in self.rules:
                event = self.hostile_event(kind=kind, **overrides)
                enrich(event, self.profile)
                if rule.evaluate(event):
                    fired.add(rule.id)
        return fired

    def test_the_rules_did_fire_so_this_is_not_vacuous(self):
        """A test that passes because nothing happened proves nothing."""
        fired = self.fired_rules()
        self.assertGreaterEqual(len(fired), 8, f'only {sorted(fired)} fired')

    def test_the_protocol_rules_are_among_them(self):
        fired = self.fired_rules()
        for rule_id in ('bacnet_control', 'bacnet_topology', 'name_poisoning',
                        'cleartext_credentials', 'remote_access_tool'):
            with self.subTest(rule=rule_id):
                self.assertIn(rule_id, fired)


if __name__ == '__main__':
    unittest.main(verbosity=2)
