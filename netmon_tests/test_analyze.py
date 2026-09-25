"""
The offline analyzer, end to end.
==================================
Profile plus rules plus an export, in and findings out. These are the tests that
would notice if any one piece stopped fitting the others — the parts all have
their own tests, and passing those says nothing about whether they compose.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.analyze import Analyzer, _main, format_findings  # noqa: E402
from netmon.events import Event, Severity, Tier  # noqa: E402
from netmon.profile import load_profile  # noqa: E402
from netmon.rules_engine import load_rules  # noqa: E402
from netmon.sources.unifi_csv import COLUMNS  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')
RULES = os.path.join(ROOT, 'netmon', 'rules')


def export(rows):
    """Write a synthetic export. Documentation addresses, invented names."""
    base = {name: '' for name in COLUMNS}
    base.update({'Action': 'allowed', 'Protocol': 'tcp', 'Direction': 'outgoing',
                 'Packets': '12', 'Bytes Sent': '500', 'Bytes Rec.': '1000',
                 'Flow Count': '1'})
    handle, path = tempfile.mkstemp(suffix='.csv')
    with os.fdopen(handle, 'w') as f:
        f.write(';'.join(COLUMNS) + '\n')
        for overrides in rows:
            record = dict(base)
            record.update(overrides)
            f.write(';'.join(str(record[name]) for name in COLUMNS) + '\n')
    return path


def browsing(count=25, mac='00:11:22:00:00:40', ip='10.10.60.50'):
    """Ordinary outbound HTTPS from a profiled workstation."""
    return [{'UTC Date / Time': f'2026-09-24T13:{n:02d}:00Z', 'Src. MAC': mac,
             'Src. Ip': ip, 'Src. Port': str(50000 + n),
             'Dst. Ip': f'203.0.113.{n}', 'Dst. Port': '443',
             'Src. Name': 'ops-workstation'} for n in range(1, count + 1)]


class _AnalyzerCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.profile = load_profile(EXAMPLE)
        cls.rules = load_rules(RULES)

    def run_rows(self, rows, **kw):
        from netmon.sources.unifi_csv import read_flows
        path = export(rows)
        self.addCleanup(os.unlink, path)
        analyzer = Analyzer(self.profile, self.rules, **kw)
        analyzer.feed(read_flows(path))
        return analyzer

    def rule_ids(self, analyzer):
        return sorted({f.rule_id for f in analyzer.findings})


class TestQuietOnNormalTraffic(_AnalyzerCase):
    """
    The property that decides whether anyone keeps the monitor switched on.
    Almost all traffic is ordinary, and a monitor that comments on it is one
    people mute — after which it detects nothing at all.
    """

    def test_ordinary_browsing_is_silent(self):
        self.assertEqual(self.rule_ids(self.run_rows(browsing())), [])

    def test_expected_cross_vlan_flows_are_silent(self):
        rows = [{'UTC Date / Time': '2026-09-24T13:05:00Z',
                 'Src. MAC': '00:11:22:00:00:40', 'Src. Ip': '10.10.60.50',
                 'Dst. Ip': '10.10.20.10', 'Dst. Port': '443',
                 'Src. Name': 'ops-workstation'}]
        self.assertEqual(self.rule_ids(self.run_rows(rows)), [])

    def test_the_bas_polling_its_controllers_is_silent(self):
        rows = [{'UTC Date / Time': f'2026-09-24T13:{n:02d}:00Z',
                 'Src. MAC': '00:11:22:00:00:01', 'Src. Ip': '10.10.20.10',
                 'Dst. Ip': '10.10.20.21', 'Dst. Port': '47808',
                 'Protocol': 'udp', 'Src. Name': 'bas-server'}
                for n in range(1, 30)]
        self.assertEqual(self.rule_ids(self.run_rows(rows)), [])

    def test_the_recorder_pulling_cameras_is_silent(self):
        rows = [{'UTC Date / Time': f'2026-09-24T13:{n:02d}:00Z',
                 'Src. MAC': '00:11:22:00:00:10', 'Src. Ip': '10.10.30.10',
                 'Dst. Ip': '10.10.30.41', 'Dst. Port': '554',
                 'Src. Name': 'nvr'} for n in range(1, 30)]
        self.assertEqual(self.rule_ids(self.run_rows(rows)), [])

    def test_a_muted_dead_reference_stays_muted(self):
        rows = [{'UTC Date / Time': f'2026-09-24T13:{n:02d}:00Z',
                 'Src. MAC': '00:11:22:00:00:01', 'Src. Ip': '10.10.20.10',
                 'Dst. Ip': '10.10.20.99', 'Dst. Port': '47808',
                 'Protocol': 'udp', 'Src. Name': 'bas-server'}
                for n in range(1, 20)]
        self.assertEqual(self.rule_ids(self.run_rows(rows)), [])


class TestItFindsWhatItShould(_AnalyzerCase):

    def test_a_remote_access_relay_from_a_controller(self):
        rows = [{'UTC Date / Time': '2026-09-24T14:02:00Z',
                 'Src. MAC': '00:11:22:00:00:02', 'Src. Ip': '10.10.20.21',
                 'Dst. Ip': '203.0.113.200', 'Dst. Port': '443',
                 'Query': 'relay-9f2.net.anydesk.com'}]
        analyzer = self.run_rows(rows)
        self.assertIn('remote_access_tool', self.rule_ids(analyzer))
        finding = next(f for f in analyzer.findings
                       if f.rule_id == 'remote_access_tool')
        self.assertEqual(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.tier, Tier.PUSH)

    def test_the_finding_names_the_device_not_just_the_address(self):
        """
        An alert that says 10.10.20.21 makes someone go and look it up. The
        profile already knows; an empty name column in the export must not beat
        it.
        """
        rows = [{'UTC Date / Time': '2026-09-24T14:02:00Z',
                 'Src. MAC': '00:11:22:00:00:02', 'Src. Ip': '10.10.20.21',
                 'Dst. Ip': '203.0.113.200', 'Dst. Port': '443',
                 'Query': 'relay-9f2.net.anydesk.com', 'Src. Name': ''}]
        finding = self.run_rows(rows).findings[0]
        self.assertIn('ahu-controller-1', finding.description)
        self.assertNotIn('?', finding.description)

    def test_an_unexpected_cross_vlan_flow(self):
        rows = [{'UTC Date / Time': '2026-09-24T16:10:00Z',
                 'Src. MAC': '00:11:22:00:00:40', 'Src. Ip': '10.10.60.50',
                 'Dst. Ip': '10.10.20.21', 'Dst. Port': '22',
                 'Src. Name': 'ops-workstation'}]
        self.assertIn('cross_vlan_unexpected', self.rule_ids(self.run_rows(rows)))

    def test_a_blocked_egress_attempt(self):
        rows = [{'UTC Date / Time': '2026-09-24T15:00:00Z', 'Action': 'blocked',
                 'Src. MAC': '00:11:22:00:00:40', 'Src. Ip': '10.10.60.50',
                 'Dst. Ip': '203.0.113.240', 'Dst. Port': '443',
                 'Policy': 'threat-list', 'Src. Name': 'ops-workstation'}]
        self.assertIn('blocked_egress', self.rule_ids(self.run_rows(rows)))

    def test_an_unprofiled_device_on_a_controller_vlan(self):
        rows = [{'UTC Date / Time': '2026-09-24T16:00:00Z',
                 'Src. MAC': 'aa:bb:cc:dd:ee:99', 'Src. Ip': '10.10.20.90',
                 'Dst. Ip': '10.10.20.10', 'Dst. Port': '443'}]
        analyzer = self.run_rows(rows)
        self.assertIn('new_device', self.rule_ids(analyzer))
        finding = next(f for f in analyzer.findings if f.rule_id == 'new_device')
        self.assertNotIn('None', finding.description)

    def test_a_mixed_day_finds_each_one_once(self):
        rows = browsing()
        rows.append({'UTC Date / Time': '2026-09-24T14:02:00Z',
                     'Src. MAC': '00:11:22:00:00:02', 'Src. Ip': '10.10.20.21',
                     'Dst. Ip': '203.0.113.200', 'Dst. Port': '443',
                     'Query': 'relay-9f2.net.anydesk.com'})
        rows += [{'UTC Date / Time': f'2026-09-24T15:0{i}:00Z', 'Action': 'blocked',
                  'Src. MAC': '00:11:22:00:00:40', 'Src. Ip': '10.10.60.50',
                  'Dst. Ip': '203.0.113.240', 'Dst. Port': '443',
                  'Policy': 'threat-list', 'Src. Name': 'ops-workstation'}
                 for i in range(6)]
        analyzer = self.run_rows(rows)
        self.assertEqual(self.rule_ids(analyzer),
                         ['blocked_egress', 'remote_access_tool'])


class TestDeduplicationInThePipeline(_AnalyzerCase):

    def test_repeats_collapse_to_one_finding(self):
        rows = [{'UTC Date / Time': f'2026-09-24T15:{i:02d}:00Z', 'Action': 'blocked',
                 'Src. MAC': '00:11:22:00:00:40', 'Src. Ip': '10.10.60.50',
                 'Dst. Ip': '203.0.113.240', 'Dst. Port': '443',
                 'Src. Name': 'ops-workstation'} for i in range(50)]
        analyzer = self.run_rows(rows)
        self.assertEqual(len(analyzer.findings), 1)

    def test_but_the_true_count_survives(self):
        rows = [{'UTC Date / Time': f'2026-09-24T15:{i:02d}:00Z', 'Action': 'blocked',
                 'Src. MAC': '00:11:22:00:00:40', 'Src. Ip': '10.10.60.50',
                 'Dst. Ip': '203.0.113.240', 'Dst. Port': '443',
                 'Src. Name': 'ops-workstation'} for i in range(50)]
        self.assertEqual(self.run_rows(rows).findings[0].count, 50)

    def test_different_destinations_are_different_findings(self):
        rows = [{'UTC Date / Time': f'2026-09-24T15:{i:02d}:00Z', 'Action': 'blocked',
                 'Src. MAC': '00:11:22:00:00:40', 'Src. Ip': '10.10.60.50',
                 'Dst. Ip': f'203.0.113.{200 + i}', 'Dst. Port': '443',
                 'Src. Name': 'ops-workstation'} for i in range(4)]
        self.assertEqual(len(self.run_rows(rows).findings), 4)

    def test_the_report_says_how_many_were_collapsed(self):
        rows = [{'UTC Date / Time': f'2026-09-24T15:{i:02d}:00Z', 'Action': 'blocked',
                 'Src. MAC': '00:11:22:00:00:40', 'Src. Ip': '10.10.60.50',
                 'Dst. Ip': '203.0.113.240', 'Dst. Port': '443',
                 'Src. Name': 'ops-workstation'} for i in range(10)]
        self.assertEqual(self.run_rows(rows).report()['suppressed_repeats'], 9)


class TestReporting(_AnalyzerCase):

    def test_findings_come_back_worst_first(self):
        analyzer = Analyzer(self.profile, self.rules)
        from netmon.events import Finding
        analyzer.findings = [Finding('a', 'a', severity='low'),
                             Finding('b', 'b', severity='critical'),
                             Finding('c', 'c', severity='medium')]
        self.assertEqual([f.rule_id for f in analyzer.by_severity()],
                         ['b', 'c', 'a'])

    def test_an_empty_result_says_so_without_claiming_all_clear(self):
        """
        Silence from one source is not evidence of absence — an export that did
        not cover a VLAN says nothing about it.
        """
        lines = format_findings(self.run_rows(browsing()))
        text = '\n'.join(lines)
        self.assertIn('Nothing found', text)
        self.assertIn('covers', text)

    def test_the_report_counts_what_it_read(self):
        report = self.run_rows(browsing(10)).report()
        self.assertEqual(report['events'], 10)
        self.assertEqual(report['findings'], 0)


class TestCommandLine(unittest.TestCase):

    def setUp(self):
        self.rows = browsing()
        self.rows.append({'UTC Date / Time': '2026-09-24T14:02:00Z',
                          'Src. MAC': '00:11:22:00:00:02',
                          'Src. Ip': '10.10.20.21', 'Dst. Ip': '203.0.113.200',
                          'Dst. Port': '443',
                          'Query': 'relay-9f2.net.anydesk.com'})
        self.path = export(self.rows)
        self.addCleanup(os.unlink, self.path)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = _main(list(args))
            except SystemExit as e:
                code = e.code
        return code, out.getvalue(), err.getvalue()

    def test_it_exits_nonzero_when_something_needs_attention(self):
        """So it can be a cron job that only speaks up when it matters."""
        code, _, _ = self.run_cli('--profile', EXAMPLE, '--unifi', self.path)
        self.assertEqual(code, 2)

    def test_it_exits_zero_on_a_quiet_export(self):
        path = export(browsing())
        self.addCleanup(os.unlink, path)
        code, _, _ = self.run_cli('--profile', EXAMPLE, '--unifi', path)
        self.assertEqual(code, 0)

    def test_json_output_parses(self):
        _, out, _ = self.run_cli('--profile', EXAMPLE, '--unifi', self.path, '--json')
        data = json.loads(out)
        self.assertIn('report', data)
        self.assertTrue(data['findings'])

    def test_min_severity_filters(self):
        _, out, _ = self.run_cli('--profile', EXAMPLE, '--unifi', self.path,
                                 '--min-severity', 'critical', '--json')
        data = json.loads(out)
        self.assertTrue(all(f['severity'] == 'critical' for f in data['findings']))

    def test_a_bad_profile_is_reported_not_traced(self):
        code, _, err = self.run_cli('--profile', '/nonexistent.yaml',
                                    '--unifi', self.path)
        self.assertEqual(code, 1)
        self.assertIn('profile', err)

    def test_a_bad_export_is_reported_not_traced(self):
        code, _, err = self.run_cli('--profile', EXAMPLE, '--unifi', '/nope.csv')
        self.assertEqual(code, 1)
        self.assertIn('export', err)

    def test_no_source_is_an_argument_error(self):
        code, _, _ = self.run_cli('--profile', EXAMPLE)
        self.assertEqual(code, 2)

    def test_limit_is_honoured(self):
        _, out, _ = self.run_cli('--profile', EXAMPLE, '--unifi', self.path,
                                 '--limit', '5', '--json')
        self.assertEqual(json.loads(out)['report']['events'], 5)


if __name__ == '__main__':
    unittest.main(verbosity=2)
