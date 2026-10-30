"""
The README against the code.
============================
The README said 21 rules in one place and 24 in another, and redact.py's
docstring cited VLAN 12 where the example profile's restricted VLANs are 40
and 50. These check the numbers and the flags the documentation names, so the
next drift fails a test instead of misleading someone at the sensor.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.rules_engine import load_rules  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as handle:
        return handle.read()


class TestTheReadme(unittest.TestCase):

    def setUp(self):
        self.readme = read('netmon', 'README.md')

    def test_every_rule_count_matches_the_shipped_rules(self):
        shipped = len(load_rules(os.path.join(ROOT, 'netmon', 'rules')))
        counts = [int(n) for n in
                  re.findall(r'\b(\d+) (?:detection )?rules\b', self.readme)]
        self.assertTrue(counts, 'the README no longer states a rule count')
        self.assertEqual(set(counts), {shipped})

    def test_the_new_flags_and_commands_are_documented(self):
        for text in ('--allow-summarise', '--allow-edit', '--state',
                     '--from-ring', '--diagnose-untagged', 'geoip --update',
                     'DB-IP', 'CC BY 4.0', 'smtp_security', 'cloudflare:',
                     'exits 3'):
            with self.subTest(text=text):
                self.assertIn(text, self.readme)

    def test_the_port_forward_question_is_stated_as_open(self):
        self.assertIn('unverified', self.readme.lower())


class TestTheModuleDocs(unittest.TestCase):

    def test_redact_does_not_cite_a_vlan_the_example_does_not_use(self):
        docstring = read('netmon', 'redact.py').split('"""')[1]
        self.assertNotIn('VLAN 12', docstring)
        self.assertIn('40 and 50', docstring)

    def test_geoip_credits_db_ip(self):
        self.assertIn('IP Geolocation by DB-IP', read('netmon', 'geoip.py'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
