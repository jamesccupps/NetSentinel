"""
Threat feeds: matching that does not condemn the innocent, and lists that age.
==============================================================================
The github.com false alarm came from feeds matched too loosely. These pin the
boundaries (dynamic DNS on a label boundary, shared file hosts never becoming
"malicious domains", tenant subdomains still counting), that delisted entries stop
matching, that DShield's /24 blocks match, that URLs are compared normalised, and
that a feed which has gone away is not retried forever. Nothing here touches the
network: downloads are faked at urllib or at the engine's own download method.
"""

import io
import os
import sys
import shutil
import tempfile
import time
import unittest
import urllib.error
import zipfile
from datetime import date
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402


class _Isolated(unittest.TestCase):
    """Each engine gets its own empty data directory."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='ns_feeds_')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def engine(self, **overrides):
        from src.threat_intel import ThreatIntelEngine
        cfg = reset_config(**overrides)
        with mock.patch('src.config.DB_DIR', self.tmp):
            return ThreatIntelEngine(cfg)

    def tearDown(self):
        reset_config(**{'threat_intel.abuse_ch_auth_key': '', 'threat_intel.ja3_feed': False})


class _FakeResponse(io.BytesIO):
    def __init__(self, data, url):
        super().__init__(data)
        self._url = url

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestMatchingBoundaries(_Isolated):

    def test_dynamic_dns_matches_on_a_label_boundary(self):
        ti = self.engine()
        self.assertIsNone(ti.check_domain('myfooddns.net'),
                          "myfooddns.net is not a ddns.net host")
        self.assertEqual(ti.check_domain('home.ddns.net')['category'], 'Dynamic DNS')
        self.assertEqual(ti.check_domain('ddns.net')['category'], 'Dynamic DNS')

    def test_shared_file_hosts_never_become_malicious_domains(self):
        from src.threat_intel import THREAT_FEEDS
        ti = self.engine()
        lines = [
            'https://files.catbox.moe/abc.exe', 'https://store1.gofile.io/d/x',
            'https://pixeldrain.com/api/file/y', 'https://i.imgur.com/z.png',
            'https://gitee.com/u/r/raw/a.ps1', 'https://codeberg.org/u/r/raw/b',
            'https://ipfs.io/ipfs/bafy', 'https://bit.ly/3abc', 'https://is.gd/xyz',
            'https://cdn.discordapp.com/attachments/1/2/a.zip',
            'https://docs.google.com/uc?id=1',
            'https://evil-tenant.pages.dev/drop.exe',
            'http://malware.example/x.bin',
        ]
        _, domains, urls = ti._parse_feed('urlhaus_domains', THREAT_FEEDS['urlhaus_domains'],
                                          '\n'.join(lines))
        self.assertEqual(sorted(d for d, _ in domains),
                         ['evil-tenant.pages.dev', 'malware.example'])
        self.assertEqual(len(urls), len(lines), 'the exact URLs are still matched')

    def test_tenant_hosting_is_no_longer_first_party_cloud(self):
        """*.github.io was in KNOWN_CLOUD_DOMAINS, which exempted every Pages site."""
        from src.net_detect import NetworkEnvironment
        env = NetworkEnvironment()
        env.detect()
        for host in ('evil.github.io', 'evil.vercel.app', 'evil.netlify.app'):
            with self.subTest(host=host):
                self.assertFalse(env.is_known_cloud_domain(host))
                self.assertTrue(env.is_cloud_hosting_domain(host))
        self.assertTrue(env.is_known_cloud_domain('github.com'))

    def test_urls_are_compared_normalised(self):
        from src.threat_intel import normalize_url
        self.assertEqual(normalize_url('HTTP://Example.COM:80/a/B.exe#frag'),
                         'http://example.com/a/B.exe')
        self.assertEqual(normalize_url('http://example.com:8080/x'),
                         'http://example.com:8080/x')
        self.assertEqual(normalize_url('ftp://example.com/x'), '')


class TestFeedLifecycle(_Isolated):

    def _load(self, ti, texts):
        """Run a full load with each feed's download answered from `texts`."""
        ti.auto_update = True
        ti._feed_meta = {}
        with mock.patch.object(ti, '_download_feed',
                               side_effect=lambda name, cfg: texts.get(name)):
            ti._load_all_feeds()

    def test_delisted_entries_stop_matching(self):
        ti = self.engine()
        self._load(ti, {'blocklist_de': '185.220.101.7\n185.220.101.8\n'})
        self.assertIsNotNone(ti.check_ip('185.220.101.7'))
        self._load(ti, {'blocklist_de': '185.220.101.8\n'})
        self.assertIsNone(ti.check_ip('185.220.101.7'), "a delisted address still matched")
        self.assertIsNotNone(ti.check_ip('185.220.101.8'))

    def test_dshield_blocks_match_the_whole_slash_24(self):
        ti = self.engine()
        self._load(ti, {'dshield_top': '# DShield\nStart\tEnd\tNetblock\tAttacks\n'
                                       '45.155.205.0\t45.155.205.255\t24\t5000\tX\tUS\t-\n'})
        hit = ti.check_ip('45.155.205.77')
        self.assertIsNotNone(hit, "an address inside a listed /24 must match")
        self.assertEqual(hit['feed'], 'dshield_top')
        self.assertTrue(hit['attacker_feed'])
        self.assertIsNone(ti.check_ip('45.155.206.1'))

    def test_urlhaus_csv_export_is_read_and_offline_rows_dropped(self):
        ti = self.engine()
        ti.abuse_ch_auth_key = 'test-key'
        csv_text = ('# URLhaus export\n'
                    '"1","2026-10-28 10:00:00","HTTP://Bad.Example/x.exe","online","","malware_download","","",""\n'
                    '"2","2026-10-28 10:00:00","http://gone.example/y","offline","","","","",""\n')
        self._load(ti, {'urlhaus_domains': csv_text})
        self.assertIsNotNone(ti.check_url('http://bad.example/x.exe'))
        self.assertIsNone(ti.check_url('http://gone.example/y'))

    def test_a_stale_cache_is_not_trusted(self):
        from src.threat_intel import THREAT_FEEDS
        ti = self.engine()
        cache = os.path.join(ti.cache_dir, 'blocklist_de.txt')
        with open(cache, 'w', encoding='utf-8') as f:
            f.write('185.220.101.9\n')
        old = time.time() - 8 * 86400
        os.utime(cache, (old, old))
        ti._feed_meta = {name: {'last_download': time.time()} for name in THREAT_FEEDS}
        ti._load_all_feeds()
        self.assertIsNone(ti.check_ip('185.220.101.9'), "an 8-day-old list was used")


class TestDownloads(_Isolated):

    def test_no_download_while_constructing_with_auto_update_off(self):
        with mock.patch('urllib.request.urlopen') as urlopen:
            self.engine(**{'threat_intel.auto_update': False})
        self.assertEqual(urlopen.call_count, 0, "tests and offline use must not download")

    def test_a_gone_feed_is_logged_once_and_not_retried(self):
        ti = self.engine()
        ti.auto_update = True
        ti._feed_meta = {}
        gone = urllib.error.HTTPError('https://x', 410, 'Gone', {}, None)
        with mock.patch('urllib.request.urlopen', side_effect=gone) as urlopen, \
                self.assertLogs('NetSentinel.ThreatIntel', level='WARNING') as logs:
            ti._load_all_feeds()
            first = urlopen.call_count
            ti._load_all_feeds()
        self.assertGreater(first, 0)
        self.assertEqual(urlopen.call_count, first, "a 410 was retried")
        warned = [r for r in logs.output if '410' in r]
        self.assertEqual(len(warned), first, "one warning per feed, not one per attempt")

    def test_a_timeout_backs_off_for_an_hour(self):
        ti = self.engine()
        ti.auto_update = True
        ti._feed_meta = {}
        with mock.patch('urllib.request.urlopen', side_effect=TimeoutError('slow')) as urlopen:
            ti._load_all_feeds()
            first = urlopen.call_count
            ti._load_all_feeds()
        self.assertEqual(urlopen.call_count, first)

    def test_urlhaus_needs_a_key_and_the_key_is_not_logged(self):
        ti = self.engine()
        ti.auto_update = True
        ti._feed_meta = {}
        seen = []

        def fake(req, timeout=None):
            seen.append(req.full_url)
            return _FakeResponse(b'# empty\n', req.full_url)

        with mock.patch('urllib.request.urlopen', side_effect=fake):
            ti._load_all_feeds()
        self.assertFalse([u for u in seen if 'urlhaus' in u],
                         "URLhaus exports need an Auth-Key; without one, do not ask")

        key = 'k3y-0f-test-only'
        ti = self.engine(**{'threat_intel.abuse_ch_auth_key': key})
        ti.auto_update = True
        ti._feed_meta = {}
        seen.clear()
        with mock.patch('urllib.request.urlopen', side_effect=fake), \
                self.assertLogs('NetSentinel.ThreatIntel', level='INFO') as logs:
            ti._load_all_feeds()
        self.assertTrue([u for u in seen if 'urlhaus' in u and key in u])
        self.assertFalse([line for line in logs.output if key in line])

    def test_ja3_feed_is_off_unless_asked_for(self):
        ti = self.engine()
        self.assertTrue(ti._feed_skipped(__import__('src.threat_intel', fromlist=['x'])
                                         .THREAT_FEEDS['sslbl_ja3']))
        ti = self.engine(**{'threat_intel.ja3_feed': True})
        ti.auto_update = True
        ti._feed_meta = {}
        text = ('# ja3_md5,Firstseen,Lastseen,Listingreason\n'
                '6734f37431670b3ab4292b8f60f29984,2017-07-14 18:08:18,2019-07-27 20:42:54,Trickbot\n')
        with mock.patch.object(ti, '_download_feed',
                               side_effect=lambda name, cfg: text if name == 'sslbl_ja3' else None):
            ti._load_all_feeds()
        hit = ti.check_ja3('6734F37431670B3AB4292B8F60F29984')
        self.assertEqual(hit['malware'], 'Trickbot')


class TestNewlyRegisteredDomains(_Isolated):

    def test_daily_lists_are_fetched_cached_and_matched(self):
        ti = self.engine(**{'threat_intel.nrd_days': 2})
        blob = io.BytesIO()
        with zipfile.ZipFile(blob, 'w') as zf:
            zf.writestr('domain-names.txt', 'brand-new-domain.com\nfresh.co.uk\n')
        requested = []

        def fake_get(url, limit=None):
            requested.append(url)
            return blob.getvalue()

        today = date(2026, 10, 29)
        with mock.patch.object(ti, '_http_get', side_effect=fake_get):
            self.assertEqual(ti._update_nrd(today=today), 2)
            self.assertEqual(ti._update_nrd(today=today), 0, "cached days are not refetched")
        self.assertEqual(len(requested), 2)
        ti._load_nrd(today=today)
        hit = ti.check_new_domain('login.brand-new-domain.com')
        self.assertEqual(hit['registered_domain'], 'brand-new-domain.com')
        self.assertEqual(ti.check_new_domain('www.fresh.co.uk')['registered_domain'], 'fresh.co.uk')
        self.assertIsNone(ti.check_new_domain('example.org'))

    def test_a_hostile_zip_is_bounded(self):
        from src.threat_intel import _read_nrd_zip
        blob = io.BytesIO()
        with zipfile.ZipFile(blob, 'w') as zf:
            zf.writestr('a.txt', 'ok.example\nnot a domain\n' + 'x' * 300 + '.example\n')
        self.assertEqual(_read_nrd_zip(blob.getvalue()), ['ok.example'])


if __name__ == '__main__':
    unittest.main()
