"""
Threat data: what is downloaded, whether it is in use, and what it finds.
==========================================================================
URLhaus went unused for six months, first for want of a key and then as too
old to trust, and nothing said so. These cover the Threat data page, the
sources added alongside it, the lookup that has to stay quick with thousands
of listed networks, and HTTP found on a port no list names. Nothing here
touches the network: downloads are faked at the engine's own fetch.
Addresses are documentation ranges, and where one must be public a Google address,
or the listed addresses test_feeds.py uses
(Python counts documentation ranges as private); keys and tokens are made up.
"""

import ipaddress
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_third_review import T0, PC, forensics, tcp  # noqa: E402


class _Isolated(unittest.TestCase):
    """Each engine gets its own empty data directory, and no downloads."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='ns_threat_data_')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def engine(self, **overrides):
        from src.threat_intel import ThreatIntelEngine
        cfg = reset_config(**overrides)
        with mock.patch('src.config.DB_DIR', self.tmp):
            return ThreatIntelEngine(cfg)

    def cache(self, name, text, age_days=0):
        folder = os.path.join(self.tmp, 'threat_intel')
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, f'{name}.txt')
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text)
        stamp = time.time() - age_days * 86400
        os.utime(path, (stamp, stamp))

    def tearDown(self):
        reset_config(**{'threat_intel.abuse_ch_auth_key': '', 'threat_intel.ja3_feed': False})


class TestNetworkIndex(unittest.TestCase):

    def index(self, *cidrs):
        from src.threat_intel import _NetworkIndex
        return _NetworkIndex([(ipaddress.ip_network(c), {'feed': c}) for c in cidrs])

    def find(self, index, ip):
        hit = index.lookup(ipaddress.ip_address(ip))
        return str(hit[0]) if hit else None

    def test_an_address_in_a_block_is_found_and_one_outside_is_not(self):
        index = self.index('198.51.100.0/24', '203.0.113.0/25')
        self.assertEqual(self.find(index, '198.51.100.77'), '198.51.100.0/24')
        self.assertEqual(self.find(index, '203.0.113.5'), '203.0.113.0/25')
        self.assertIsNone(self.find(index, '203.0.113.200'))
        self.assertIsNone(self.find(index, '192.0.2.1'))

    def test_overlapping_blocks_give_the_most_specific(self):
        # A wide block, then one starting later inside it: the bisection lands
        # on a later, unrelated block and has to walk back to the wide one.
        index = self.index('10.0.0.0/8', '10.1.2.0/24', '10.200.0.0/16')
        self.assertEqual(self.find(index, '10.1.2.3'), '10.1.2.0/24')
        self.assertEqual(self.find(index, '10.250.0.1'), '10.0.0.0/8')

    def test_versions_are_kept_apart(self):
        index = self.index('2001:db8::/32', '192.0.2.0/24')
        self.assertEqual(self.find(index, '2001:db8::1'), '2001:db8::/32')
        self.assertIsNone(self.find(index, '2001:db9::1'))
        self.assertEqual(len(index), 2)


class TestFeedStatus(_Isolated):

    def states(self, ti):
        return {row['name']: (row['state'], row['note']) for row in ti.feed_status()}

    def test_a_feed_needing_a_key_says_so(self):
        state, note = self.states(self.engine(**{'threat_intel.auto_update': False}))[
            'urlhaus_domains']
        self.assertEqual(state, 'needs key')
        self.assertIn('abuse.ch Auth-Key', note)

    def test_a_week_old_cache_is_stale_and_says_it_is_not_used(self):
        self.cache('feodo_c2', '192.0.2.10\n', age_days=9)
        state, note = self.states(self.engine(**{'threat_intel.auto_update': False}))['feodo_c2']
        self.assertEqual(state, 'stale')
        self.assertIn('9 days old', note)
        self.assertIn('not used', note)

    def test_a_fresh_cache_is_in_use_with_its_count(self):
        self.cache('feodo_c2', '# comment\n192.0.2.10\n192.0.2.11\n')
        rows = {r['name']: r for r in self.engine(**{'threat_intel.auto_update': False})
                .feed_status()}
        self.assertEqual((rows['feodo_c2']['state'], rows['feodo_c2']['entries']), ('ok', 2))

    def test_an_optional_feed_left_off_is_off(self):
        state, _ = self.states(self.engine(**{'threat_intel.auto_update': False}))['sslbl_ja3']
        self.assertEqual(state, 'off')


class TestHttpOnAnUnlistedPort(unittest.TestCase):

    def request(self, f, dst, port, ts=T0):
        f.analyze_packet(tcp(PC, 50000, dst, port,
                             b'GET /api/ HTTP/1.1\r\nHost: x\r\n\r\n', server=port, ts=ts))

    def test_home_assistants_port_is_called_unencrypted_http(self):
        f = forensics()
        self.request(f, '192.168.1.97', 8123)
        svc = f.insecure_services[('192.168.1.97', 8123)]
        self.assertEqual((svc['service'], svc['risk'], svc['advice_port']), ('HTTP', 'LOW', 80))

    def test_to_the_internet_it_is_medium(self):
        f = forensics()
        self.request(f, '142.250.68.195', 8123)
        self.assertEqual(f.insecure_services[('142.250.68.195', 8123)]['risk'], 'MEDIUM')

    def test_later_packets_to_it_count_without_a_request_line(self):
        f = forensics()
        self.request(f, '192.168.1.97', 8123)
        for i in range(4):
            f.analyze_packet(tcp(PC, 50000, '192.168.1.97', 8123, b'{"state": 1}',
                                 server=8123, ts=T0 + i + 1))
        self.assertEqual(f.insecure_services[('192.168.1.97', 8123)]['packet_count'], 5)

    def test_tls_and_other_bytes_on_an_unlisted_port_are_not_http(self):
        f = forensics()
        f.analyze_packet(tcp(PC, 50000, '192.168.1.97', 8443, b'\x16\x03\x01\x02\x00\x01',
                             server=8443))
        f.analyze_packet(tcp(PC, 50000, '192.168.1.97', 9999, b'SSH-2.0-OpenSSH_9.6\r\n',
                             server=9999))
        self.assertEqual(f.insecure_services, {})


# ─── The new feeds ───────────────────────────────────────────────────────────

SPAMHAUS = ('{"cidr":"45.155.205.0/24","sblid":"SBL000001","rir":"arin"}\n'
            '{"cidr":"bogus","sblid":"SBL000002"}\n'
            '{"type":"metadata","timestamp":1790000000,"size":2,"records":2,'
            '"copyright":"(c) 2026 The Spamhaus Project SLU",'
            '"terms":"https://www.spamhaus.org/drop/terms/"}\n')

THREATFOX = json.dumps({
    "1": [{"ioc_value": "185.220.101.200:8443", "ioc_type": "ip:port",
           "threat_type": "botnet_cc", "malware_printable": "Example RAT",
           "confidence_level": 100}],
    "2": [{"ioc_value": "c2.example.net", "ioc_type": "domain",
           "threat_type": "botnet_cc", "malware_printable": "Example RAT",
           "confidence_level": 75}],
    "3": [{"ioc_value": "guess.example.org", "ioc_type": "domain",
           "threat_type": "botnet_cc", "confidence_level": 25}],
    "4": [{"ioc_value": "a" * 64, "ioc_type": "sha256_hash",
           "threat_type": "payload", "confidence_level": 100}],
    "5": [{"ioc_value": "185.220.101.10:443", "ioc_type": "ip:port",
           "threat_type": "botnet_cc", "confidence_level": 100}],
})

ONIONOO = json.dumps({"version": "8.0", "relays": [
    {"or_addresses": ["198.51.100.30:9001", "[2001:db8::30]:443"],
     "exit_addresses": ["198.51.100.30"]},
    {"or_addresses": ["203.0.113.31:443"]},
]})


class TestNewFeeds(_Isolated):

    def offline(self, **overrides):
        return self.engine(**{'threat_intel.auto_update': False, **overrides})

    def test_spamhaus_drop_networks_match_and_carry_the_credit(self):
        self.cache('spamhaus_drop_v4', SPAMHAUS)
        ti = self.offline()
        hit = ti.check_ip('45.155.205.77')
        self.assertEqual((hit['feed'], hit['category'], hit['sbl']),
                         ('spamhaus_drop_v4', 'Hijacked Network', 'SBL000001'))
        row = {r['name']: r for r in ti.feed_status()}['spamhaus_drop_v4']
        self.assertEqual((row['state'], row['entries']), ('ok', 1))
        self.assertIn('The Spamhaus Project', row['note'])
        self.assertIn('list of 2026-', row['note'])

    def test_threatfox_addresses_keep_their_port_and_low_confidence_is_dropped(self):
        self.cache('threatfox', THREATFOX)
        self.cache('feodo_c2', '185.220.101.10\n')
        ti = self.offline(**{'threat_intel.abuse_ch_auth_key': 'test-key-not-real'})
        self.assertEqual(ti.check_ip('185.220.101.200')['ports'], {8443})
        self.assertEqual(ti.check_domain('c2.example.net')['feed'], 'threatfox')
        self.assertIsNone(ti._malicious_domains.get('guess.example.org'))
        # Feodo lists it on every port; ThreatFox's port must not narrow that.
        self.assertNotIn('ports', ti.check_ip('185.220.101.10'))

    def test_the_ids_matches_a_threatfox_address_on_its_port_only(self):
        from src.ids_engine import IDSEngine
        self.cache('threatfox', THREATFOX)
        cfg = reset_config(**{'threat_intel.abuse_ch_auth_key': 'test-key-not-real'})
        ti = self.offline(**{'threat_intel.abuse_ch_auth_key': 'test-key-not-real'})
        ids = IDSEngine(cfg, threat_intel=ti)
        rules = []
        for port in (443, 8443):
            alerts = ids.inspect_packet(tcp(PC, 50000 + port, '185.220.101.200', port,
                                            b'\x16\x03\x01', server=port)) or []
            rules.append(sorted(a.rule_id for a in alerts if a.rule_id == 'THREAT-INTEL-IP'))
        self.assertEqual(rules[0], [])
        self.assertTrue(rules[1], 'the listed port did not match')

    def test_a_threatfox_download_exports_its_hashes_for_file_scans(self):
        ti = self.offline(**{'threat_intel.abuse_ch_auth_key': 'test-key-not-real'})
        ti.auto_update = True
        from src.threat_intel import THREAT_FEEDS
        with mock.patch.object(ti, '_http_get', return_value=THREATFOX.encode()), \
                mock.patch('src.hash_feed.default_folder',
                           return_value=os.path.join(self.tmp, 'hash_lists')):
            ti._download_feed('threatfox', THREAT_FEEDS['threatfox'])
            from src.hash_feed import HashLists
            lists = HashLists(os.path.join(self.tmp, 'hash_lists'))
            self.assertEqual(lists.load(), 1)
            self.assertIsNotNone(lists.lookup('a' * 64))

    def test_malwarebazaar_full_is_unzipped_into_the_hash_folder_and_never_parsed(self):
        import io as _io
        import zipfile
        blob = _io.BytesIO()
        with zipfile.ZipFile(blob, 'w') as zf:
            zf.writestr('sha256_full.txt', '# sha256_hash\n' + '\n'.join(
                f'{i:064x}' for i in range(5)) + '\n')
        folder = os.path.join(self.tmp, 'hash_lists')
        ti = self.offline(**{'threat_intel.abuse_ch_auth_key': 'test-key-not-real'})
        ti.auto_update = True
        with mock.patch.object(ti, '_http_get', return_value=blob.getvalue()), \
                mock.patch('src.hash_feed.default_folder', return_value=folder), \
                mock.patch.object(ti, '_parse_feed_full', wraps=ti._parse_feed_full) as parse:
            ti._load_all_feeds()
            row = {r['name']: r for r in ti.feed_status()}['malwarebazaar_full']
        self.assertTrue(os.path.exists(os.path.join(folder, 'malwarebazaar_full.txt')))
        self.assertEqual((row['state'], row['entries']), ('ok', 5))
        self.assertNotIn('malwarebazaar_full', [c.args[0] for c in parse.call_args_list])

    def test_a_keyed_feeds_failure_never_logs_the_key(self):
        ti = self.offline(**{'threat_intel.abuse_ch_auth_key': 'secret-key-not-real'})
        from src.threat_intel import THREAT_FEEDS
        err = OSError('https://threatfox-api.abuse.ch/v2/files/exports/secret-key-not-real/x')
        with mock.patch.object(ti, '_http_get', side_effect=err), \
                self.assertLogs('NetSentinel.ThreatIntel', level='INFO') as logs:
            ti._download_feed('threatfox', THREAT_FEEDS['threatfox'])
        self.assertNotIn('secret-key-not-real', '\n'.join(logs.output))

    def test_tor_relays_are_known_by_address_and_or_port(self):
        self.cache('tor_relays', ONIONOO)
        ti = self.offline()
        self.assertTrue(ti.is_tor_relay('198.51.100.30', 9001))
        self.assertTrue(ti.is_tor_relay('2001:db8::30', 443))
        self.assertFalse(ti.is_tor_relay('198.51.100.30', 80))
        self.assertFalse(ti.is_tor_relay('198.51.100.99', 9001))
        self.assertIsNone(ti.check_ip('198.51.100.30'), 'a relay is not malicious')

    def test_ioc_tor_fires_on_a_relay_whatever_the_port(self):
        from src.ioc_scanner import IOCScanner
        self.cache('tor_relays', ONIONOO)
        scanner = IOCScanner(reset_config(), threat_intel=self.offline())
        to_relay = scanner.check_packet_ioc(tcp(PC, 50000, '203.0.113.31', 443, b'\x16\x03',
                                                server=443))
        to_web = scanner.check_packet_ioc(tcp(PC, 50001, '203.0.113.99', 443, b'\x16\x03',
                                              server=443))
        self.assertEqual([f['rule_id'] for f in to_relay], ['IOC-TOR'])
        self.assertEqual(to_web, [])

    def test_cins_and_the_missing_ja4db_are_on_the_status_page(self):
        self.cache('cins_army', '192.0.2.50\n192.0.2.51\n')
        rows = {r['name']: r for r in self.offline().feed_status()}
        self.assertEqual((rows['cins_army']['state'], rows['cins_army']['entries']), ('ok', 2))
        self.assertEqual(rows['ja4db']['state'], 'off')
        self.assertIn('enterprise', rows['ja4db']['note'])


# ─── Known exploited vulnerabilities ─────────────────────────────────────────

KEV = {"catalogVersion": "2026.10.30", "count": 2, "vulnerabilities": [
    {"cveID": "CVE-2021-41773", "vendorProject": "Apache", "product": "HTTP Server",
     "vulnerabilityName": "Apache HTTP Server Path Traversal", "dateAdded": "2021-11-03",
     "requiredAction": "Apply updates per vendor instructions.",
     "knownRansomwareCampaignUse": "Known", "forensicTriage": "No", "cwes": []},
    {"cveID": "CVE-2024-6387", "vendorProject": "OpenBSD", "product": "OpenSSH",
     "vulnerabilityName": "OpenSSH Signal Handler Race", "dateAdded": "2024-07-01",
     "requiredAction": "Apply updates per vendor instructions.",
     "knownRansomwareCampaignUse": "Unknown"},
]}


def nvd_item(cve, criteria, **bounds):
    return {"cve": {"id": cve, "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [
        dict({"vulnerable": True, "criteria": criteria}, **bounds),
        {"vulnerable": False, "criteria": "cpe:2.3:o:example:platform:-:*:*:*:*:*:*:*"},
    ]}]}]}}


NVD = {"totalResults": 2, "vulnerabilities": [
    nvd_item("CVE-2021-41773", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
    nvd_item("CVE-2024-6387", "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
             versionStartIncluding="8.5", versionEndExcluding="9.8"),
]}


class _VulnCase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='ns_vulns_')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def catalog(self, pages=None):
        from src.vulns import Catalog, KEV_URL
        pages = pages or [NVD]
        calls = []

        def fetch(url, limit):
            calls.append(url)
            if url == KEV_URL:
                return json.dumps(KEV).encode()
            return json.dumps(pages[len([c for c in calls if c != KEV_URL]) - 1]).encode()

        catalog = Catalog(None, data_dir=self.tmp, fetch=fetch, sleep=lambda s: None)
        catalog.update(force=True)
        catalog.calls = calls
        return catalog


class TestVersions(unittest.TestCase):

    def test_versions_compare_as_numbers_with_letters_after(self):
        from src.vulns import version_key as v
        self.assertLess(v('2.4.9'), v('2.4.49'))
        self.assertLess(v('1.0.2'), v('1.0.2k'))
        self.assertLess(v('1.0.2k'), v('1.0.10'))

    def test_a_rule_takes_in_its_range_and_its_exact_version(self):
        from src.vulns import affects
        ranged = ('CVE-X', '*', '8.5', '', '', '9.8')
        self.assertTrue(affects(ranged, '9.6'))
        self.assertFalse(affects(ranged, '9.8'))
        self.assertFalse(affects(ranged, '8.4'))
        self.assertTrue(affects(('CVE-Y', '2.4.49', '', '', '', ''), '2.4.49'))
        self.assertFalse(affects(('CVE-Y', '2.4.49', '', '', '', ''), '2.4.50'))
        self.assertFalse(affects(('CVE-Z', '-', '', '', '', ''), '1.0'))

    def test_banners_name_their_software(self):
        from src.vulns import identify
        found = {(n, v) for n, v, _ in identify('Apache/2.4.49 (Unix) OpenSSL/1.1.1k PHP/7.4.3')}
        self.assertEqual(found, {('Apache HTTP Server', '2.4.49'), ('OpenSSL', '1.1.1k'),
                                 ('PHP', '7.4.3')})
        self.assertEqual(identify('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13')[0][:2],
                         ('OpenSSH', '9.6'))
        self.assertEqual(identify('cloudflare'), [])


class TestCatalog(_VulnCase):

    def test_a_banner_in_a_listed_range_matches_its_cves(self):
        catalog = self.catalog()
        [m] = catalog.match('Apache/2.4.49 (Unix)')
        self.assertEqual((m['cve'], m['ransomware'], m['every_version']),
                         ('CVE-2021-41773', True, False))
        self.assertEqual(catalog.match('Apache/2.4.51 (Unix)'), [])
        [ssh] = catalog.match('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13')
        self.assertEqual(ssh['cve'], 'CVE-2024-6387')
        self.assertTrue(ssh['distro_build'])

    def test_the_cache_is_read_back_and_too_old_a_cache_is_not_used(self):
        from src.vulns import Catalog, MAX_AGE_SEC
        self.catalog()
        again = Catalog(None, data_dir=self.tmp, fetch=None)
        self.assertTrue(again.ready)
        old = time.time() - MAX_AGE_SEC - 60
        for name in ('kev.json', 'nvd_kev_rules.json'):
            os.utime(os.path.join(self.tmp, name), (old, old))
        stale = Catalog(None, data_dir=self.tmp, fetch=None)
        self.assertFalse(stale.ready)
        self.assertEqual({r['state'] for r in stale.status()}, {'stale'})

    def test_nvd_is_read_page_by_page(self):
        first = {"totalResults": 2, "vulnerabilities": NVD["vulnerabilities"][:1]}
        second = {"totalResults": 2, "vulnerabilities": NVD["vulnerabilities"][1:]}
        catalog = self.catalog(pages=[first, second])
        self.assertIn('startIndex=1', catalog.calls[-1])
        self.assertTrue(catalog.match('OpenSSH_9.0'))

    def test_status_credits_nvd_as_its_terms_ask(self):
        rows = {r['name']: r for r in self.catalog().status()}
        self.assertEqual(rows['vulns_kev']['state'], 'ok')
        self.assertIn('not endorsed or certified by the NVD', rows['vulns_nvd']['note'])

    def test_a_gzip_that_inflates_past_its_limit_is_refused(self):
        import gzip
        from src.vulns import _gunzip
        with self.assertRaises(ValueError):
            _gunzip(gzip.compress(b'\0' * 10000), 1000)
        self.assertEqual(_gunzip(gzip.compress(b'ok'), 1000), b'ok')


class TestVulnerabilityAlerts(_VulnCase):

    def test_a_lan_web_server_on_a_listed_version_raises_one_alert_a_day(self):
        from test_third_review import _Alerts
        f = forensics()
        alerts = _Alerts(f)
        alerts.app.vulns = self.catalog()
        alerts.app._vulns_alerted = {}
        response = (b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n'
                    b'Content-Length: 0\r\n\r\n')
        f.analyze_packet(tcp('192.168.1.20', 80, PC, 50000, response, server=80))
        alerts.app._check_software_seen(now=T0)
        f._http_servers.clear()
        f.analyze_packet(tcp('192.168.1.20', 80, PC, 50001, response, server=80))
        alerts.app._check_software_seen(now=T0 + 60)
        [alert] = [a for a in alerts.raised if a.rule_id == 'VULN-KEV']
        self.assertEqual(str(getattr(alert.severity, 'name', alert.severity)), 'HIGH')
        self.assertEqual(alert.evidence['cves'][0]['cve'], 'CVE-2021-41773')
        self.assertIn('not endorsed', alert.evidence['source'])

    def test_an_ssh_greeting_counts_from_the_server_only(self):
        f = forensics()
        f.analyze_packet(tcp('192.168.1.21', 22, PC, 50000, b'SSH-2.0-OpenSSH_9.6\r\n',
                             server=22))
        f.analyze_packet(tcp(PC, 50001, '192.168.1.22', 22, b'SSH-2.0-OpenSSH_9.6\r\n',
                             server=22))
        self.assertEqual([s['ip'] for s in f.software_seen], ['192.168.1.21'])

    def test_an_internet_servers_software_is_left_alone(self):
        f = forensics()
        f.analyze_packet(tcp('142.250.68.195', 22, PC, 50000, b'SSH-2.0-OpenSSH_9.6\r\n',
                             server=22))
        self.assertEqual(list(f.software_seen), [])

    def test_the_audit_reports_a_listed_version(self):
        from src import audit
        catalog = self.catalog()
        host = {'ip': '192.168.1.20', 'role': 'unknown', 'services': [
            {'port': 22, 'banner': 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13'}]}
        with mock.patch('src.vulns.get_catalog', return_value=catalog):
            findings = [f for f in audit._host_findings(host, 30) if f['id'] == 'AUDIT-KEV']
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['evidence']['cves'], ['CVE-2024-6387'])
        self.assertIn("distribution's build", findings[0]['why'])


# ─── Old defaults, and what the cap drops ────────────────────────────────────

class TestStaleDefaults(unittest.TestCase):

    def setUp(self):
        from src import config
        self.tmp = tempfile.mkdtemp(prefix='ns_cfg_')
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = os.path.join(self.tmp, 'config.json')
        patcher = mock.patch.object(config, 'CONFIG_FILE', self.path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def load(self, saved=None):
        from src.config import Config
        if saved is not None:
            with open(self.path, 'w', encoding='utf-8') as f:
                json.dump(saved, f)
        cfg = Config.__new__(Config)
        cfg._data = None
        return cfg.load()

    def test_the_old_filter_and_cap_are_replaced_once(self):
        from src.config import DEFAULT_CONFIG, STALE_DEFAULTS
        old_filter = STALE_DEFAULTS['capture-bpf-filter-2026-09'][2]
        cfg = self.load({'capture': {'bpf_filter': old_filter, 'max_pps': 500}})
        self.assertEqual(cfg.get('capture', 'bpf_filter'), DEFAULT_CONFIG['capture']['bpf_filter'])
        self.assertEqual(cfg.get('capture', 'max_pps'), 2000)
        # Set on purpose afterwards, it stays.
        cfg.set('capture', 'max_pps', 500)
        self.assertEqual(self.load().get('capture', 'max_pps'), 500)

    def test_a_value_someone_chose_is_left_alone(self):
        cfg = self.load({'capture': {'bpf_filter': 'not port 8787', 'max_pps': 800}})
        self.assertEqual((cfg.get('capture', 'bpf_filter'), cfg.get('capture', 'max_pps')),
                         ('not port 8787', 800))

    def test_a_new_install_has_nothing_to_replace_later(self):
        from src.config import STALE_DEFAULTS
        cfg = self.load()
        self.assertEqual(sorted(cfg.get('migrations', 'applied')), sorted(STALE_DEFAULTS))
        cfg.set('capture', 'max_pps', 500)
        self.assertEqual(self.load().get('capture', 'max_pps'), 500)


class TestTheCapShedsBulkFirst(unittest.TestCase):

    def packet(self, payload_size, flags='PA', **kw):
        from src.capture import PacketInfo
        p = PacketInfo()
        p.protocol, p.flags, p.payload_size = 'TCP', flags, payload_size
        p.src_ip, p.dst_ip, p.src_port, p.dst_port = PC, '203.0.113.5', 50000, 443
        for k, v in kw.items():
            setattr(p, k, v)
        return p

    def test_only_a_full_segment_that_told_extraction_nothing_is_bulk(self):
        from src.capture import _sheddable
        self.assertTrue(_sheddable(self.packet(1400)))
        self.assertFalse(_sheddable(self.packet(100)))
        self.assertFalse(_sheddable(self.packet(1400, flags='FA')))
        self.assertFalse(_sheddable(self.packet(1400, tls_sni='example.com')))
        self.assertFalse(_sheddable(self.packet(1400, http_method='POST')))
        self.assertFalse(_sheddable(self.packet(1400, dst_port=53)))

    def test_over_the_cap_bulk_is_counted_not_inspected_and_the_rest_waits_for_twice(self):
        from src.capture import CaptureEngine
        engine = CaptureEngine(reset_config(**{'capture.max_pps': 2}))
        bulk, small = self.packet(1400), self.packet(60)
        sequence = [small, small, bulk, small, small, small]
        engine._pps_window_start = time.time() + 60    # one window for the lot
        with mock.patch.object(engine, '_extract_packet_info', side_effect=sequence), \
                mock.patch.object(engine, '_raw_bytes', return_value=b''):
            for _ in sequence:
                engine._capture_callback(object())
        queued = []
        while not engine._packet_queue.empty():
            queued.append(engine._packet_queue.get_nowait())
        # 2 under the cap, the bulk one flagged, one more small up to 4, then dropped.
        self.assertEqual(len(queued), 4)
        self.assertEqual([p.account_only for p in queued], [False, False, True, False])
        self.assertEqual((engine._dropped_cap, engine._dropped_queue, engine._dropped_packets),
                         (2, 0, 2))

    def test_the_worker_tracks_a_bulk_packet_without_inspecting_it(self):
        from src.capture import CaptureEngine
        inspected = []
        engine = CaptureEngine(reset_config(), packet_callback=inspected.append)
        bulk = self.packet(1400)
        bulk.account_only = True
        engine._packet_queue.put(bulk)
        engine._packet_queue.put(self.packet(60))
        stop = threading.Event()
        worker = threading.Thread(target=engine._worker_loop, args=(stop,))
        worker.start()
        deadline = time.time() + 5
        while (len(inspected) < 1 or engine._shed_packets < 1) and time.time() < deadline:
            time.sleep(0.01)
        stop.set()
        worker.join(5)
        self.assertEqual((len(inspected), engine._shed_packets), (1, 1))
        self.assertEqual(engine.stats['protocols']['TCP'], 2)


class TestDataSources(_Isolated):

    def test_every_source_has_a_row(self):
        from types import SimpleNamespace
        from src import data_sources
        self.cache('feodo_c2', '192.0.2.10\n')
        app = SimpleNamespace(threat_intel=self.engine(**{'threat_intel.auto_update': False}),
                              vulns=None, ids_engine=None)
        with mock.patch('src.hash_feed.default_folder',
                        return_value=os.path.join(self.tmp, 'hash_lists')):
            rows = {r['name']: r for r in data_sources.collect(app)}
        for name in ('feodo_c2', 'urlhaus_domains', 'threatfox', 'spamhaus_drop_v4',
                     'tor_relays', 'cins_army', 'ja4db', 'whoisds_nrd', 'dbip_geoip',
                     'hash_lists', 'cloud_ranges', 'mining_pools', 'default_rules'):
            self.assertIn(name, rows)
        self.assertEqual(rows['cloud_ranges']['state'], 'bundled')
        self.assertEqual(rows['dbip_geoip']['state'], 'off')
        self.assertEqual(data_sources.when(None), '')


from test_headless import _ApiTestCase  # noqa: E402


class TestThreatDataPage(_ApiTestCase):

    def test_the_sources_route_lists_the_bundled_data_at_least(self):
        sources = self.get_json('/api/sources')['sources']
        self.assertIn('cloud_ranges', {s['name'] for s in sources})

    def test_the_dashboard_has_the_tab_and_the_drop_counters(self):
        page = self.get('/')[2]
        self.assertIn('id="page-sources"', page)
        capture = self.get_json('/api/overview')['capture']
        for key in ('packets_dropped_cap', 'packets_dropped_queue', 'packets_shed'):
            self.assertIn(key, capture)


if __name__ == '__main__':
    unittest.main()
