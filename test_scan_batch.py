"""
Batch scans: what counts as known-bad, and keeping internal names away from
the feeds.
"""

import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from src import batch_scan  # noqa: E402
from test_batch_scan import FakeAnalyzer  # noqa: E402


class GradedThreatIntel:
    """Answers like ThreatIntelEngine: HIGH for a listing, MEDIUM for a listed
    parent, LOW for the built-in dynamic-DNS and TLD guesses."""

    ANSWERS = {
        'evil.example.com': {'feed': 'urlhaus', 'category': 'Malware Distribution', 'confidence': 'HIGH'},
        'cdn.bad.example.net': {'feed': 'urlhaus', 'category': 'Malware Distribution',
                                'confidence': 'MEDIUM', 'match_type': 'parent_domain'},
        'files.example.xyz': {'feed': 'builtin', 'category': 'Suspicious TLD',
                              'description': 'Domain uses high-abuse TLD (.xyz)', 'confidence': 'LOW'},
        'home.duckdns.org': {'feed': 'builtin', 'category': 'Dynamic DNS',
                             'description': 'Domain uses dynamic DNS service', 'confidence': 'LOW'},
    }

    def __init__(self):
        self.asked = []

    def check_ip(self, ip):
        self.asked.append(ip)
        return None

    def check_domain(self, domain):
        self.asked.append(domain)
        return self.ANSWERS.get(domain)


class _Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='scanbatch_')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def file(self, rel, data):
        path = os.path.join(self.tmp, 'in', rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(data if isinstance(data, bytes) else data.encode('utf-8'))
        return path

    def scan(self, *paths, **kw):
        return batch_scan.scan(list(paths), kw.pop('analyzer', None) or FakeAnalyzer(), **kw)


class TestKnownBad(_Case):
    """H3: a LOW-confidence guess (dynamic DNS, a .top TLD) was reported as known-bad."""

    TEXT = ('evil.example.com cdn.bad.example.net files.example.xyz home.duckdns.org\n'
            'fs01.corp.local printer.lan build.internal svc.example.test\n'
            '\\\\nas01\\share and Server=SQLPROD01; 10.1.2.3 198.51.100.7\n')

    def test_only_feed_listings_are_known_bad(self):
        report = self.scan(self.file('notes.txt', self.TEXT), threat_intel=GradedThreatIntel())
        self.assertEqual({t['value'] for t in report['threats']},
                         {'evil.example.com', 'cdn.bad.example.net'})
        self.assertEqual({t['value'] for t in report['suspicious']},
                         {'files.example.xyz', 'home.duckdns.org'})
        by_rule = {}
        for a in report['alerts']:
            by_rule.setdefault(a['rule_id'], []).append(a['severity'])
        self.assertEqual(by_rule['FILESCAN-THREAT-INTEL'], ['HIGH', 'HIGH'])
        self.assertEqual(by_rule['FILESCAN-SUSPICIOUS-INDICATOR'], ['LOW', 'LOW'])
        self.assertEqual((report['summary']['threats'], report['summary']['suspicious']), (2, 2))

    def test_internal_names_never_reach_a_feed(self):
        intel = GradedThreatIntel()
        self.scan(self.file('notes.txt', self.TEXT), threat_intel=intel)
        for name in ('fs01.corp.local', 'printer.lan', 'build.internal', 'svc.example.test',
                     'nas01', 'sqlprod01', '10.1.2.3'):
            self.assertNotIn(name, intel.asked)
        self.assertIn('evil.example.com', intel.asked)

    def test_window_top_is_not_known_bad_with_the_real_engine(self):
        from src.threat_intel import ThreatIntelEngine
        # an empty cache makes the engine fetch its feeds; tests stay offline
        with mock.patch.object(ThreatIntelEngine, '_download_feed', return_value=None):
            engine = ThreatIntelEngine(reset_config())
        report = self.scan(self.file('frame.js', 'if (window.top !== window.self) {}\n'
                                                 'load("https://static.example.top/a.js")\n'),
                           threat_intel=engine)
        self.assertEqual(report['threats'], [])
        self.assertNotIn('FILESCAN-THREAT-INTEL', {a['rule_id'] for a in report['alerts']})
        self.assertEqual([t['value'] for t in report['suspicious']], ['static.example.top'])

    def test_dns_names_from_captures_get_a_scope_too(self):
        class Capture(FakeAnalyzer):
            def analyze_file(self, path, callback=None):
                self.alerts = []
                return {'stats': {'top_dns_queries': [('wpad', 3), ('fs01.corp.local.', 2),
                                                      ('evil.example.com', 1)]}}
        intel = GradedThreatIntel()
        report = self.scan(self.file('cap.pcap', b'x'), analyzer=Capture(), threat_intel=intel)
        self.assertEqual([h['value'] for h in report['indicators']['host']], ['wpad'])
        self.assertEqual(intel.asked, ['evil.example.com'])


if __name__ == '__main__':
    unittest.main()
