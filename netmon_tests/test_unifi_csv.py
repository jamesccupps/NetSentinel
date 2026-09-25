"""
UniFi flow CSV importer.
=========================
The fixture is synthetic. A real export is a complete record of who talked to
whom for a day, which is site data and does not belong in a repository — and the
real ones for this site also carry credential-bearing rows. Everything here uses
documentation addresses and invented names.

The tests that matter most are the ones about the byte columns. "Bytes Sent" is
what the source *downloaded*; getting that backwards inverts every upload rule,
so exfiltration would read as a download and the monitor would be silent on the
one thing it exists to catch.
"""

import gzip
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.events import enrich  # noqa: E402
from netmon.profile import SiteProfile  # noqa: E402
from netmon.sources.unifi_csv import (COLUMNS, UnifiCsvError,  # noqa: E402
                                      parse_row, parse_timestamp, read_flows,
                                      summarise)

HEADER = ';'.join(COLUMNS)


def row(**overrides):
    """One export row. Defaults are a plain allowed outbound HTTPS flow."""
    values = {
        'UTC Date / Time': '2026-09-24T13:05:00Z',
        'Date / Time': '2026-09-24 09:05:00',
        'Action': 'allowed', 'Service': 'https', 'Protocol': 'tcp',
        'Direction': 'outgoing', 'Risk': '', 'Policy': '', 'Policy Type': '',
        'Other Policies': '', 'Category': '', 'In': 'eth0', 'Out': 'eth1',
        'Src. MAC': '00:11:22:00:00:40', 'Src. Ip': '10.10.60.50',
        'Src. Port': '52344', 'Src. Name': 'ops-workstation',
        'Src. Network': 'staff', 'Src. Region': '', 'Src. Zone': 'corporate',
        'Dst. Domain': 'cdn.example.test', 'Dst. MAC': '',
        'Dst. Ip': '203.0.113.20', 'Dst. Port': '443', 'Dst. Name': '',
        'Dst. Network': 'WAN', 'Dst. Region': 'US', 'Dst. Zone': 'External',
        'Signature': '', 'Signature ID': '', 'Bytes': '1500',
        'Bytes Rec.': '1000', 'Bytes Sent': '500', 'Packets': '12',
        'Packets Rec.': '6', 'Packets Sent': '6', 'Session Id': 'abc123',
        'Flow Count': '1', 'Query': '', 'URL': '',
    }
    values.update(overrides)
    return values


def csv_text(rows, header=HEADER):
    lines = [header]
    for record in rows:
        lines.append(';'.join(str(record.get(name, '')) for name in COLUMNS))
    return '\n'.join(lines) + '\n'


class _FileTestCase(unittest.TestCase):

    def write(self, text, suffix='.csv', compress=False):
        handle, path = tempfile.mkstemp(suffix=suffix)
        os.close(handle)
        if compress:
            with gzip.open(path, 'wt', encoding='utf-8') as f:
                f.write(text)
        else:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(text)
        self.addCleanup(os.unlink, path)
        return path


# ─── The inversion ───────────────────────────────────────────────────────────

class TestByteDirection(unittest.TestCase):
    """
    The single most consequential detail in this format.

    The column labels are from the gateway's point of view: "Bytes Sent" is what
    it sent to the source, which is the source's download. Verified against a
    known 406 MB package download, which appears under "Bytes Sent".
    """

    def test_bytes_sent_is_what_the_source_downloaded(self):
        event = parse_row(row(**{'Bytes Sent': '406000000', 'Bytes Rec.': '2000'}))
        self.assertEqual(event.bytes_to_src, 406_000_000)

    def test_bytes_received_is_what_the_source_uploaded(self):
        event = parse_row(row(**{'Bytes Sent': '2000', 'Bytes Rec.': '94000000'}))
        self.assertEqual(event.bytes_to_dst, 94_000_000)

    def test_a_large_download_is_not_reported_as_an_upload(self):
        """
        The failure this guards against: taking the labels at face value makes
        every download look like exfiltration, and every real exfiltration look
        like a download.
        """
        event = parse_row(row(**{'Bytes Sent': '406000000', 'Bytes Rec.': '2000'}))
        self.assertLess(event.bytes_to_dst, event.bytes_to_src)

    def test_total_bytes_is_the_sum_either_way(self):
        event = parse_row(row(**{'Bytes Sent': '500', 'Bytes Rec.': '1000'}))
        self.assertEqual(event.total_bytes, 1500)

    def test_the_undercount_is_flagged_on_every_event(self):
        """
        A measured 24-hour export accounted for 20.8 GB where the gateway's own
        activity view showed 84.9 GB. Anything thresholding on these numbers
        should know they are a floor.
        """
        self.assertTrue(parse_row(row()).fields['byte_counts_are_a_floor'])


# ─── Timestamps ──────────────────────────────────────────────────────────────

class TestTimestamps(unittest.TestCase):
    """The UTC column mixes precisions within one file."""

    def test_second_precision(self):
        self.assertEqual(parse_timestamp('2026-09-24T13:05:00Z'), 1790255100.0)

    def test_microsecond_precision(self):
        self.assertAlmostEqual(parse_timestamp('2026-09-24T13:05:00.123456Z'),
                               1790255100.123456, places=5)

    def test_millisecond_precision(self):
        self.assertAlmostEqual(parse_timestamp('2026-09-24T13:05:00.123Z'),
                               1790255100.123, places=3)

    def test_space_separated(self):
        self.assertEqual(parse_timestamp('2026-09-24 13:05:00'), 1790255100.0)

    def test_explicit_offset(self):
        self.assertEqual(parse_timestamp('2026-09-24T09:05:00-04:00'), 1790255100.0)

    def test_a_naive_timestamp_is_read_as_utc(self):
        """The column says UTC; a missing suffix does not make it local."""
        self.assertEqual(parse_timestamp('2026-09-24T13:05:00'), 1790255100.0)

    def test_precisions_mixed_in_one_file_all_parse(self):
        rows = [row(**{'UTC Date / Time': stamp}) for stamp in (
            '2026-09-24T13:05:00Z', '2026-09-24T13:05:01.5Z',
            '2026-09-24T13:05:02.123456Z', '2026-09-24 13:05:03')]
        stamps = [parse_row(r).ts for r in rows]
        self.assertTrue(all(s > 0 for s in stamps), stamps)
        self.assertEqual(stamps, sorted(stamps))

    def test_an_unparseable_timestamp_gives_zero_not_an_exception(self):
        """One bad row must not abandon the other four hundred thousand."""
        self.assertEqual(parse_timestamp('not a date'), 0.0)
        self.assertEqual(parse_timestamp(''), 0.0)
        self.assertEqual(parse_timestamp(None), 0.0)

    def test_it_falls_back_to_the_local_column(self):
        event = parse_row(row(**{'UTC Date / Time': '',
                                 'Date / Time': '2026-09-24T13:05:00Z'}))
        self.assertEqual(event.ts, 1790255100.0)


# ─── Row parsing ─────────────────────────────────────────────────────────────

class TestRowParsing(unittest.TestCase):

    def test_the_basics(self):
        event = parse_row(row())
        self.assertEqual(event.kind, 'flow')
        self.assertEqual(event.src_ip, '10.10.60.50')
        self.assertEqual(event.dst_ip, '203.0.113.20')
        self.assertEqual(event.dst_port, 443)
        self.assertEqual(event.protocol, 'tcp')
        self.assertEqual(event.source, 'unifi_csv')

    def test_names_come_through(self):
        event = parse_row(row())
        self.assertEqual(event.fields['src_name'], 'ops-workstation')

    def test_a_blocked_flow_is_marked(self):
        event = parse_row(row(Action='blocked', Policy='threat-list'))
        self.assertTrue(event.fields['blocked'])
        self.assertEqual(event.fields['action'], 'blocked')
        self.assertEqual(event.fields['policy'], 'threat-list')

    def test_the_gateway_direction_does_not_shadow_the_computed_one(self):
        """
        UniFi says local/outgoing/incoming; enrichment computes
        internal/outbound/inbound. One field name for two vocabularies would
        make every rule using it depend on which source the event came from.
        """
        event = parse_row(row(Direction='outgoing'))
        self.assertEqual(event.fields['unifi_direction'], 'outgoing')
        enrich(event, SiteProfile({}))
        self.assertEqual(event.fields['direction'], 'outbound')
        self.assertEqual(event.fields['unifi_direction'], 'outgoing')

    def test_the_inferred_domain_is_not_called_domain(self):
        """
        It mislabels shared addresses — one CDN name appeared against nearly
        every device in a sample — and is blank for long-lived connections.
        Keeping it under `domain` would let rules match on it by accident.
        """
        event = parse_row(row())
        self.assertEqual(event.fields['domain_hint'], 'cdn.example.test')
        self.assertNotIn('domain', event.fields)

    def test_an_empty_port_becomes_none_not_zero(self):
        """Port 0 is a real port number; a blank column is not port 0."""
        event = parse_row(row(**{'Dst. Port': ''}))
        self.assertIsNone(event.dst_port)

    def test_an_out_of_range_port_is_rejected(self):
        self.assertIsNone(parse_row(row(**{'Dst. Port': '99999'})).dst_port)

    def test_malformed_byte_counts_become_zero(self):
        for value in ('', '-', 'n/a', 'NULL'):
            with self.subTest(value=value):
                self.assertEqual(parse_row(row(**{'Bytes Rec.': value})).bytes_to_dst, 0)

    def test_thousands_separators_are_handled(self):
        self.assertEqual(parse_row(row(**{'Bytes Rec.': '1,234,567'})).bytes_to_dst,
                         1_234_567)

    def test_macs_are_lowercased(self):
        event = parse_row(row(**{'Src. MAC': 'AA:BB:CC:DD:EE:FF'}))
        self.assertEqual(event.src_mac, 'aa:bb:cc:dd:ee:ff')

    def test_a_row_with_no_addresses_is_skipped(self):
        """A trailing blank line or a summary footer looks like this."""
        self.assertIsNone(parse_row(row(**{'Src. Ip': '', 'Dst. Ip': ''})))

    def test_a_row_with_only_one_address_is_kept(self):
        self.assertIsNotNone(parse_row(row(**{'Dst. Ip': ''})))

    def test_ips_signature_fields_come_through(self):
        event = parse_row(row(Signature='ET INFO Observed DNS Query',
                              **{'Signature ID': '2013028'}))
        self.assertEqual(event.fields['signature_id'], '2013028')


# ─── Reading files ───────────────────────────────────────────────────────────

class TestReadFlows(_FileTestCase):

    def test_a_normal_file(self):
        path = self.write(csv_text([row(), row(**{'Src. Ip': '10.10.60.51'})]))
        events = list(read_flows(path))
        self.assertEqual(len(events), 2)
        self.assertEqual(events[1].src_ip, '10.10.60.51')

    def test_it_is_a_generator(self):
        """A 407,000-row export is about 105 MB; nothing should accumulate."""
        path = self.write(csv_text([row()] * 3))
        self.assertFalse(isinstance(read_flows(path), list))

    def test_limit(self):
        path = self.write(csv_text([row()] * 10))
        self.assertEqual(len(list(read_flows(path, limit=3))), 3)

    def test_gzipped_files_are_read(self):
        path = self.write(csv_text([row()]), suffix='.csv.gz', compress=True)
        self.assertEqual(len(list(read_flows(path))), 1)

    def test_compression_is_detected_by_content_not_extension(self):
        """Exports arrive named every possible way."""
        path = self.write(csv_text([row()]), suffix='.csv', compress=True)
        self.assertEqual(len(list(read_flows(path))), 1)

    def test_a_byte_order_mark_does_not_break_the_header(self):
        path = self.write('﻿' + csv_text([row()]))
        self.assertEqual(len(list(read_flows(path))), 1)

    def test_blank_lines_are_skipped(self):
        path = self.write(csv_text([row()]) + '\n\n' + ';' * 39 + '\n')
        self.assertEqual(len(list(read_flows(path))), 1)

    def test_a_missing_file_says_so(self):
        with self.assertRaises(UnifiCsvError) as ctx:
            list(read_flows('/nonexistent/export.csv'))
        self.assertIn('not found', str(ctx.exception))

    def test_an_empty_file_says_so(self):
        with self.assertRaises(UnifiCsvError) as ctx:
            list(read_flows(self.write('')))
        self.assertIn('empty', str(ctx.exception))

    def test_a_comma_delimited_file_is_diagnosed(self):
        """
        The likeliest mistake. Splitting on ';' gives one column and zero
        events, which without this reads as "the export was empty".
        """
        path = self.write(','.join(COLUMNS) + '\n' + ','.join(['x'] * 40) + '\n')
        with self.assertRaises(UnifiCsvError) as ctx:
            list(read_flows(path))
        self.assertIn('semicolon', str(ctx.exception))

    def test_a_file_that_is_not_an_export_is_refused_by_name(self):
        path = self.write('alpha;beta;gamma\n1;2;3\n')
        with self.assertRaises(UnifiCsvError) as ctx:
            list(read_flows(path))
        self.assertIn('Src. Ip', str(ctx.exception))

    def test_a_firmware_column_rename_still_loads(self):
        header = HEADER.replace('Src. Ip', 'Src IP').replace('Dst. Ip', 'Dst IP')
        path = self.write(csv_text([row()], header=header))
        events = list(read_flows(path))
        self.assertEqual(events[0].src_ip, '10.10.60.50')

    def test_a_genuinely_unknown_column_is_noted_but_not_fatal(self):
        header = HEADER.replace('Risk', 'Threat Score')
        path = self.write(csv_text([row()], header=header))
        with self.assertLogs('netmon.sources.unifi', level='INFO') as logs:
            events = list(read_flows(path))
        self.assertEqual(len(events), 1)
        self.assertIn('Threat Score', ' '.join(logs.output))

    def test_a_short_row_does_not_stop_the_file(self):
        path = self.write(csv_text([row()]) + 'only;three;fields\n'
                          + ';'.join(str(row()[c]) for c in COLUMNS) + '\n')
        self.assertEqual(len(list(read_flows(path))), 2)

    def test_a_row_with_extra_columns_does_not_stop_the_file(self):
        path = self.write(csv_text([row()])
                          + ';'.join(list(str(row()[c]) for c in COLUMNS)
                                     + ['extra', 'more']) + '\n')
        self.assertEqual(len(list(read_flows(path))), 2)


class TestSummarise(_FileTestCase):

    def setUp(self):
        self.path = self.write(csv_text([
            row(),
            row(Action='blocked', **{'Src. Ip': '10.10.60.51',
                                     'Dst. Ip': '203.0.113.99'}),
            row(Protocol='udp', **{'UTC Date / Time': '2026-09-24T19:05:00Z',
                                   'Bytes Rec.': '5000'}),
        ]))
        self.stats = summarise(self.path)

    def test_counts(self):
        self.assertEqual(self.stats['rows'], 3)
        self.assertEqual(self.stats['blocked'], 1)
        self.assertEqual(self.stats['devices'], 2)

    def test_it_reports_upload_and_download_separately(self):
        self.assertEqual(self.stats['bytes_uploaded'], 1000 + 1000 + 5000)
        self.assertEqual(self.stats['bytes_downloaded'], 500 * 3)

    def test_it_reports_the_period_covered(self):
        """
        So a six-hour export is not mistaken for a day. Absence of a flow in an
        export is not evidence it did not happen.
        """
        self.assertEqual(self.stats['hours_covered'], 6.0)

    def test_it_reports_which_networks_appear(self):
        """A VLAN missing from the export is one this source cannot speak to."""
        self.assertEqual(self.stats['networks'], ['staff'])

    def test_action_and_protocol_breakdowns(self):
        self.assertEqual(self.stats['by_action'], {'allowed': 2, 'blocked': 1})
        self.assertEqual(self.stats['by_protocol'], {'tcp': 2, 'udp': 1})


class TestEndToEnd(_FileTestCase):
    """An export, enriched against a profile, through the rules."""

    def setUp(self):
        import netmon.handlers  # noqa: F401
        from netmon.rules_engine import load_rules
        self.rules = load_rules(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'netmon', 'rules'))
        self.profile = SiteProfile({
            'site': {'name': 'test'},
            'vlans': {60: {'name': 'staff', 'subnet': '10.10.60.0/24',
                           'zone': 'corporate', 'gateway': '10.10.60.1'}},
            'roles': {'workstation': {}},
            'devices': {'00:11:22:00:00:40': {'name': 'ops-workstation',
                                              'role': 'workstation',
                                              'ips': ['10.10.60.50'], 'vlan': 60}},
            'watched_names': ['anydesk'],
        })

    def run_file(self, rows):
        path = self.write(csv_text(rows))
        findings = []
        for event in read_flows(path):
            enrich(event, self.profile)
            findings.extend(self.rules.evaluate(event))
        return findings

    def test_a_blocked_flow_produces_a_finding(self):
        findings = self.run_file([row(Action='blocked', Policy='threat-list',
                                      **{'Dst. Ip': '203.0.113.99'})])
        self.assertIn('blocked_egress', [f.rule_id for f in findings])

    def test_ordinary_browsing_produces_nothing(self):
        """
        The calibration that matters. A monitor that fires on normal traffic is
        one nobody reads, and normal traffic is almost all of it.
        """
        rows = [row(**{'Src. Ip': '10.10.60.50', 'Dst. Ip': f'203.0.113.{n}',
                       'Src. Port': str(50000 + n)}) for n in range(1, 40)]
        self.assertEqual(self.run_file(rows), [])

    def test_dns_to_the_gateway_produces_nothing(self):
        self.assertEqual(self.run_file([
            row(Service='dns', Protocol='udp', **{'Dst. Ip': '10.10.60.1',
                                                  'Dst. Port': '53'})]), [])

    def test_the_importer_and_the_rules_agree_about_upload_direction(self):
        """
        End to end, the one that would silently break: a large upload must reach
        upload_anomaly as an upload. `Bytes Rec.` is the upload column.
        """
        rows = []
        for day in range(10, 22):
            uploaded = 600_000_000 if day == 21 else 60_000_000
            rows.append(row(**{
                'UTC Date / Time': f'2026-09-{day:02d}T13:05:00Z',
                'Bytes Rec.': str(uploaded), 'Bytes Sent': '1000',
                'Dst. Ip': '203.0.113.70'}))
        self.assertIn('upload_anomaly', [f.rule_id for f in self.run_file(rows)])

    def test_an_unprofiled_device_is_reported_once_on_a_first_run(self):
        """
        Intended behaviour, not noise: the first run over a site with no profile
        is a device inventory. Deduplication stops it repeating, and the answer
        is to fill in the profile rather than to soften the rule.
        """
        rows = [row(**{'Src. MAC': 'aa:bb:cc:00:00:99',
                       'Src. Ip': '10.10.60.77'}) for _ in range(5)]
        findings = [f for f in self.run_file(rows) if f.rule_id == 'new_device']
        self.assertEqual(len(findings), 1)

    def test_a_large_download_does_not_trigger_the_upload_rule(self):
        """The same twelve days with the columns the other way round."""
        rows = []
        for day in range(10, 22):
            downloaded = 600_000_000 if day == 21 else 60_000_000
            rows.append(row(**{
                'UTC Date / Time': f'2026-09-{day:02d}T13:05:00Z',
                'Bytes Sent': str(downloaded), 'Bytes Rec.': '1000',
                'Dst. Ip': '203.0.113.70'}))
        self.assertNotIn('upload_anomaly', [f.rule_id for f in self.run_file(rows)])


if __name__ == '__main__':
    unittest.main(verbosity=2)
