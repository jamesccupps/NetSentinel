"""
Country and network, from DB-IP Lite, offline.
===============================================
The databases are never in the repository and never fetched by a test: the
reader is handed a fake `open_database`, and the downloader a fake `fetch`.
What is checked is the logic around them — lookups merged from the two
files, a replaced file picked up, a download written atomically and refused
when it is not a database — and what enrichment and the rules do with the
answers.
"""

import gzip
import io
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon import geoip  # noqa: E402
from netmon.events import Event, enrich  # noqa: E402
from netmon.geoip import (ATTRIBUTION, DATABASES, GeoIP, GeoIPError,  # noqa: E402
                          normalise_asn, update)
from netmon.profile import load_profile  # noqa: E402
from netmon.redact import (FORBIDDEN_SUBSTRINGS, SAFE_EVIDENCE_FIELDS,  # noqa: E402
                           redact_finding)
from netmon.rules_engine import load_rules  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')
RULES = os.path.join(ROOT, 'netmon', 'rules')

#: Documentation addresses and ASNs only.
COUNTRIES = {'203.0.113.9': {'country': {'iso_code': 'NL'}},
             '198.51.100.7': {'registered_country': {'iso_code': 'us'}}}
ASNS = {'203.0.113.9': {'autonomous_system_number': 64511,
                        'autonomous_system_organization': 'Example\nNetworks  BV'},
        '198.51.100.7': {'autonomous_system_number': 64500,
                         'autonomous_system_organization': 'Payments Example'}}


class _Reader:
    def __init__(self, path, records):
        self.path = path
        self.records = records
        self.closed = False

    def get(self, ip):
        if ip == 'not-an-address':
            raise ValueError('bad address')
        return self.records.get(ip)

    def close(self):
        self.closed = True


class _Opener:
    def __init__(self):
        self.opened = []

    def __call__(self, path):
        records = COUNTRIES if 'country' in os.path.basename(path) else ASNS
        reader = _Reader(path, records)
        self.opened.append(reader)
        return reader


class _Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


class _GeoCase(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='netmon-geoip-')
        self.addCleanup(shutil.rmtree, self.dir, True)

    def install(self):
        for _, filename in DATABASES.values():
            with open(os.path.join(self.dir, filename), 'wb') as handle:
                handle.write(b'fake')

    def reader(self, clock=None):
        self.opener = _Opener()
        return GeoIP(self.dir, open_database=self.opener, clock=clock or _Clock())


class TestNormalising(unittest.TestCase):

    def test_spellings(self):
        for value in (64500, '64500', 'AS64500', 'as64500', ' AS64500 '):
            with self.subTest(value=value):
                self.assertEqual(normalise_asn(value), 64500)
        for value in (None, '', 'ASx', 0, -1, True, 2 ** 32):
            with self.subTest(value=value):
                self.assertIsNone(normalise_asn(value))


class TestLookups(_GeoCase):

    def test_both_databases_are_merged(self):
        self.install()
        self.assertEqual(self.reader().lookup('203.0.113.9'),
                         {'country': 'NL', 'asn': 64511,
                          'as_org': 'Example Networks BV'})

    def test_registered_country_is_the_fallback(self):
        self.install()
        self.assertEqual(self.reader().lookup('198.51.100.7')['country'], 'US')

    def test_unknown_and_invalid_addresses_are_empty(self):
        self.install()
        reader = self.reader()
        self.assertEqual(reader.lookup('192.0.2.1'), {})
        self.assertEqual(reader.lookup('not-an-address'), {})
        self.assertEqual(reader.lookup(''), {})

    def test_no_files_means_no_answers_not_an_error(self):
        reader = self.reader()
        self.assertEqual(reader.lookup('203.0.113.9'), {})
        self.assertFalse(reader.available())

    def test_a_replaced_file_is_picked_up_without_a_restart(self):
        self.install()
        clock = _Clock()
        reader = self.reader(clock)
        reader.lookup('203.0.113.9')
        first = len(self.opener.opened)
        path = os.path.join(self.dir, DATABASES['asn'][1])
        stat = os.stat(path)
        os.utime(path, (stat.st_atime, stat.st_mtime + 100))
        clock.now += geoip.RECHECK_SECONDS + 1
        reader.lookup('203.0.113.9')
        self.assertEqual(len(self.opener.opened), first + 1)
        self.assertTrue(self.opener.opened[first - 1].closed
                        or self.opener.opened[0].closed)

    def test_files_that_appear_later_are_found(self):
        clock = _Clock()
        reader = self.reader(clock)
        self.assertEqual(reader.lookup('203.0.113.9'), {})
        self.install()
        clock.now += geoip.RECHECK_SECONDS + 1
        self.assertEqual(reader.lookup('203.0.113.9')['country'], 'NL')

    def test_a_shared_reader_per_directory(self):
        self.assertIs(geoip.for_directory(self.dir), geoip.for_directory(self.dir))
        self.assertIsNone(geoip.for_directory(''))


def _gz(data):
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb') as handle:
        handle.write(data)
    return buffer.getvalue()


class _Response(io.BytesIO):
    status = 200


class TestUpdate(_GeoCase):

    MMDB = b'\x00' * 64 + geoip._MMDB_MARKER + b'metadata'

    def fetcher(self, missing_months=(), body=None):
        self.fetched = []

        def fetch(url, timeout):
            self.fetched.append(url)
            if any(month in url for month in missing_months):
                raise OSError('HTTP Error 404: Not Found')
            return _Response(body if body is not None else _gz(self.MMDB))
        return fetch

    def test_both_files_are_installed_with_attribution(self):
        done = update(self.dir, fetch=self.fetcher(), now=1_793_000_000,
                      open_database=_Opener())
        self.assertEqual(set(done), {'country', 'asn'})
        for _, filename in DATABASES.values():
            with open(os.path.join(self.dir, filename), 'rb') as handle:
                self.assertEqual(handle.read(), self.MMDB)
        with open(os.path.join(self.dir, 'SOURCE.txt'), encoding='utf-8') as handle:
            self.assertIn(ATTRIBUTION, handle.read())
        leftovers = [n for n in os.listdir(self.dir)
                     if n.endswith(('.download', '.new', '.tmp'))]
        self.assertEqual(leftovers, [])

    def test_the_urls_are_db_ip_over_https(self):
        update(self.dir, fetch=self.fetcher(), now=1_793_000_000,
               open_database=_Opener())
        self.assertTrue(all(u.startswith('https://download.db-ip.com/free/')
                            for u in self.fetched))

    def test_last_month_is_used_when_this_one_is_not_out(self):
        month = geoip._months(1_793_000_000)[0]
        done = update(self.dir, fetch=self.fetcher(missing_months=[month]),
                      now=1_793_000_000, open_database=_Opener())
        self.assertNotIn(month, done['country']['url'])

    def test_something_that_is_not_a_database_does_not_replace_one(self):
        self.install()
        with self.assertRaises(GeoIPError):
            update(self.dir, fetch=self.fetcher(body=_gz(b'<html>sorry</html>')),
                   now=1_793_000_000, open_database=_Opener())
        with open(os.path.join(self.dir, DATABASES['asn'][1]), 'rb') as handle:
            self.assertEqual(handle.read(), b'fake')

    def test_a_corrupt_download_does_not_replace_one(self):
        self.install()
        with self.assertRaises(GeoIPError):
            update(self.dir, fetch=self.fetcher(body=b'\x1f\x8b\x08garbage'),
                   now=1_793_000_000, open_database=_Opener())
        with open(os.path.join(self.dir, DATABASES['country'][1]), 'rb') as handle:
            self.assertEqual(handle.read(), b'fake')

    def test_plain_http_is_refused(self):
        with self.assertRaises(GeoIPError):
            geoip._fetch('http://download.db-ip.com/x', 5)

    def test_status_reports_what_is_missing(self):
        report = geoip.status(self.dir)
        self.assertFalse(report['country']['present'])
        self.install()
        self.assertTrue(geoip.status(self.dir)['asn']['present'])

    def test_the_command(self):
        import contextlib
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(geoip._main(['--dir', self.dir]), 1)
        self.assertIn('missing', out.getvalue())
        self.assertIn('DB-IP', out.getvalue())


# ─── Enrichment and the rules ────────────────────────────────────────────────

class _FakeGeo:
    def lookup(self, ip):
        return {'203.0.113.9': {'country': 'NL', 'asn': 64511,
                                'as_org': 'Example Networks'},
                '198.51.100.7': {'country': 'US', 'asn': 64500}}.get(ip, {})


class TestEnrichment(unittest.TestCase):

    def setUp(self):
        self.profile = load_profile(EXAMPLE)
        self.profile.set_geoip(_FakeGeo())

    def flow(self, src, dst, src_mac=''):
        return enrich(Event(kind='flow', src_ip=src, dst_ip=dst, src_mac=src_mac,
                            dst_port=443, protocol='tcp'), self.profile)

    def test_the_destination_of_outbound_traffic(self):
        event = self.flow('10.10.60.50', '203.0.113.9')
        self.assertEqual((event.get('dst_country'), event.get('dst_asn'),
                          event.get('dst_as_org')), ('NL', 64511, 'Example Networks'))

    def test_the_source_of_inbound_traffic(self):
        event = self.flow('203.0.113.9', '10.10.20.10')
        self.assertEqual(event.get('src_country'), 'NL')
        self.assertIsNone(event.get('dst_country'))

    def test_internal_traffic_is_not_looked_up(self):
        event = self.flow('10.10.60.50', '10.10.20.10')
        self.assertIsNone(event.get('dst_country'))

    def test_allowed_asns_are_enforced_for_a_role_that_lists_them(self):
        kiosk = '00:11:22:00:00:30'
        self.assertTrue(self.flow('10.10.50.20', '198.51.100.7',
                                  kiosk).get('dst_asn_allowed'))
        self.assertIs(self.flow('10.10.50.20', '203.0.113.9',
                                kiosk).get('dst_asn_allowed'), False)

    def test_a_role_with_no_list_is_not_judged(self):
        self.assertIsNone(self.flow('10.10.60.50', '203.0.113.9',
                                    '00:11:22:00:00:40').get('dst_asn_allowed'))

    def test_no_database_is_not_judged_either(self):
        self.profile.set_geoip(None)
        self.profile.geoip_dir = ''
        self.assertIsNone(self.flow('10.10.50.20', '203.0.113.9',
                                    '00:11:22:00:00:30').get('dst_asn_allowed'))

    def test_the_unifi_region_stands_in_for_a_country(self):
        from netmon.sources.unifi_csv import COLUMNS, parse_row
        self.profile.set_geoip(None)
        self.profile.geoip_dir = ''
        row = {name: '' for name in COLUMNS}
        row.update({'UTC Date / Time': '2026-09-24T14:02:00Z',
                    'Src. Ip': '10.10.60.50', 'Dst. Ip': '192.0.2.44',
                    'Src. Region': '', 'Dst. Region': 'de', 'Protocol': 'tcp'})
        event = enrich(parse_row(row), self.profile)
        self.assertEqual(event.get('dst_region'), 'de')
        self.assertEqual(event.get('dst_country'), 'DE')

    def test_a_region_that_is_not_a_code_is_kept_but_not_a_country(self):
        from netmon.sources.unifi_csv import COLUMNS, parse_row
        self.profile.set_geoip(None)
        self.profile.geoip_dir = ''
        row = {name: '' for name in COLUMNS}
        row.update({'Src. Ip': '10.10.60.50', 'Dst. Ip': '192.0.2.44',
                    'Dst. Region': 'Somewhere, Europe'})
        event = enrich(parse_row(row), self.profile)
        self.assertEqual(event.get('dst_region'), 'Somewhere, Europe')
        self.assertIsNone(event.get('dst_country'))


class TestTheRule(unittest.TestCase):

    def setUp(self):
        self.profile = load_profile(EXAMPLE)
        self.profile.set_geoip(_FakeGeo())
        self.rules = load_rules(RULES)

    def fired(self, dst):
        event = enrich(Event(kind='flow', src_ip='10.10.50.20', dst_ip=dst,
                             src_mac='00:11:22:00:00:30', dst_port=443,
                             protocol='tcp'), self.profile)
        return [f for f in self.rules.evaluate(event)
                if f.rule_id == 'egress_unexpected_network']

    def test_a_kiosk_reaching_another_network_is_reported(self):
        found = self.fired('203.0.113.9')
        self.assertEqual(len(found), 1)
        self.assertIn('AS64511', found[0].description)
        self.assertIn('in NL', found[0].description)
        self.assertEqual(found[0].evidence['dst_asn'], 64511)

    def test_its_processors_network_is_not(self):
        self.assertEqual(self.fired('198.51.100.7'), [])

    def test_nothing_to_judge_is_not_a_finding(self):
        """No database means no ASN. A bare `false` in the rule matched that
        as well, and every outbound flow from a listed role fired."""
        self.profile.set_geoip(None)
        self.profile.geoip_dir = ''
        self.assertEqual(self.fired('203.0.113.9'), [])

    def test_the_evidence_survives_redaction_for_an_alert(self):
        record = redact_finding(self.fired('203.0.113.9')[0], self.profile)
        self.assertEqual(record['evidence']['dst_country'], 'NL')
        self.assertEqual(record['evidence']['dst_as_org'], 'Example Networks')

    def test_new_destinations_carry_where_they_are(self):
        from netmon.handlers import new_destination
        rule = self.rules.by_id('egress_new_destination')
        state = {'started_at': 0.0}
        event = enrich(Event(kind='flow', ts=10 ** 7, src_ip='10.10.20.21',
                             dst_ip='203.0.113.9', dst_port=443, protocol='tcp'),
                       self.profile)
        found = new_destination(event, rule, state)
        self.assertIn('NL, AS64511', found.description)
        self.assertEqual(found.evidence['dst_asn'], 64511)


class TestTheAllowlist(unittest.TestCase):

    def test_the_new_fields_may_be_transmitted(self):
        for name in ('dst_country', 'dst_asn', 'dst_as_org', 'src_country',
                     'src_asn', 'src_as_org', 'dst_region', 'src_region'):
            with self.subTest(name=name):
                self.assertIn(name, SAFE_EVIDENCE_FIELDS)
                self.assertFalse(any(bad in name for bad in FORBIDDEN_SUBSTRINGS))

    def test_the_dispatcher_knows_the_command(self):
        from netmon.__main__ import COMMANDS
        self.assertEqual(COMMANDS['geoip'][0], 'netmon.geoip')

    def test_the_example_profile_leaves_geoip_off(self):
        """Opt-in: a copied example must not start looking things up."""
        saved = os.environ.pop('NETMON_GEOIP_DIR', None)
        try:
            self.assertEqual(load_profile(EXAMPLE).geoip_dir, '')
        finally:
            if saved is not None:
                os.environ['NETMON_GEOIP_DIR'] = saved

    def test_attribution_names_db_ip(self):
        self.assertIn('DB-IP', ATTRIBUTION)
        self.assertIn('CC BY 4.0', ATTRIBUTION)


if __name__ == '__main__':
    unittest.main(verbosity=2)
