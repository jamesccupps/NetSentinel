"""Batch capture scan: folders, zips, and what a hostile archive must not do."""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import unittest.mock
import zipfile
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import SCAPY_REAL, reset_config  # noqa: E402

from src import batch_scan  # noqa: E402
from src.ids_engine import Alert  # noqa: E402


def cred_alert(value='pas*****', src='10.0.0.5 → 10.0.0.9:21'):
    return Alert(rule_id='FORENSICS-CREDENTIAL', severity='CRITICAL',
                 title='Plaintext Credential Found (FTP)', description='',
                 category='Credential Exposure',
                 evidence={'protocol': 'FTP', 'credential_type': 'password',
                           'value': value, 'source': src})


class FakeAnalyzer:
    """Reads each capture's bytes: b'cred' finds a credential, b'boom' raises."""

    def __init__(self):
        self.seen = []
        self.paths = []
        self.alerts = []
        self.stats = {}
        self.is_analyzing = False
        self.progress = 0
        self.progress_text = ''

    def analyze_file(self, path, callback=None):
        self.paths.append(path)
        with open(path, 'rb') as f:
            data = f.read()
        self.seen.append(data)
        self.is_analyzing = True
        if data == b'boom':
            raise ValueError('not a capture')
        self.alerts = [cred_alert()] if data == b'cred' else []
        for a in self.alerts:
            if callback:
                callback(a)
        self.is_analyzing = False
        return {'stats': {'packets_analyzed': 3,
                          'top_talkers': [('10.0.0.5', 900)],
                          'top_dns_queries': [('Update.Example.COM.', 4)]},
                'alerts': [a.to_dict() for a in self.alerts]}


class _Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='batch_')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def file(self, rel, data=b'ok'):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(data)
        return path

    def zip(self, rel, members):
        path = os.path.join(self.tmp, rel)
        with zipfile.ZipFile(path, 'w') as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        return path


class TestCollecting(_Case):
    def test_a_folder_yields_its_captures_and_the_zips_inside_it(self):
        self.file('caps/a.pcap')
        self.file('caps/sub/b.pcapng')
        self.file('caps/notes.txt')
        self.zip('caps/more.zip', {'c.cap': b'ok', 'readme.md': b'x'})
        found, skipped = batch_scan.collect([os.path.join(self.tmp, 'caps')])
        names = [c.name.replace('\\', '/') for c in found]
        self.assertEqual(names, ['caps/a.pcap', 'caps/more.zip/c.cap', 'caps/more.zip/readme.md',
                                 'caps/notes.txt', 'caps/sub/b.pcapng'])
        self.assertEqual([c.is_capture for c in found], [True, True, False, False, True])
        self.assertEqual(skipped, [])

    def test_media_and_version_control_are_left_out(self):
        self.file('d/photo.JPG')
        self.file('d/.git/config', b'[remote] url = https://x:y@example.com')
        self.file('d/keep.log')
        found, skipped = batch_scan.collect([os.path.join(self.tmp, 'd')])
        self.assertEqual([os.path.basename(c.name) for c in found], ['keep.log'])
        self.assertEqual([s['reason'] for s in skipped], ['media file'])

    def test_skip_patterns_apply_on_disk_and_inside_zips(self):
        a = self.file('flash_0925.pcap')
        z = self.zip('z.zip', {'dir/FLASH_1.pcapng': b'x', 'keep.pcap': b'x'})
        found, skipped = batch_scan.collect([a, z], skip=['flash*'])
        self.assertEqual([c.name for c in found], ['z.zip/keep.pcap'])
        self.assertEqual(len(skipped), 2)

    def test_nested_and_password_protected_members_are_reported_not_opened(self):
        nested = self.zip('nested.zip', {'inner.zip': b'PK'})
        locked = self.zip('locked.zip', {'locked.pcap': b'x'})
        with open(locked, 'rb') as f:
            data = bytearray(f.read())
        # zipfile cannot write encryption; set the flag in both headers by hand
        data[6] |= 0x1
        data[data.find(b'PK\x01\x02') + 8] |= 0x1
        with open(locked, 'wb') as f:
            f.write(data)
        found, skipped = batch_scan.collect([nested, locked])
        self.assertEqual(found, [])
        self.assertEqual(sorted(s['reason'] for s in skipped),
                         ['nested archive', 'password-protected'])

    @unittest.skipUnless(hasattr(os, 'symlink'), 'no symlinks here')
    def test_symlinks_are_not_followed(self):
        outside = self.file('outside/secret.pcap')
        os.makedirs(os.path.join(self.tmp, 'caps'))
        try:
            os.symlink(outside, os.path.join(self.tmp, 'caps', 'link.pcap'))
        except OSError:
            self.skipTest('cannot create symlinks')
        found, skipped = batch_scan.collect([os.path.join(self.tmp, 'caps')])
        self.assertEqual(found, [])
        self.assertEqual(skipped[0]['reason'], 'symlink not followed')

    def test_the_file_limit_is_reported(self):
        for i in range(3):
            self.file(f'caps/{i}.pcap')
        found, skipped = batch_scan.collect([os.path.join(self.tmp, 'caps')], max_files=2)
        self.assertEqual(len(found), 2)
        self.assertIn('limit', skipped[0]['reason'])

    def test_unknown_inputs_are_reported(self):
        bad = self.file('bad.zip', b'not a zip')
        _, skipped = batch_scan.collect([bad, os.path.join(self.tmp, 'gone')])
        reasons = [s['reason'] for s in skipped]
        self.assertTrue(reasons[0].startswith('unreadable zip'))
        self.assertEqual(reasons[1], 'not found')


class TestScanning(_Case):
    def test_a_hostile_member_name_cannot_escape_the_work_directory(self):
        z = self.zip('evil.zip', {'../../escaped.pcap': b'ok', '/abs/x.pcap': b'ok'})
        analyzer = FakeAnalyzer()
        report = batch_scan.scan([z], analyzer)
        self.assertEqual(report['summary']['scanned'], 2)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'escaped.pcap')))
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.tmp), 'escaped.pcap')))
        for path in analyzer.paths:
            self.assertRegex(os.path.basename(path), r'^\d{5}\.pcap$')

    def test_extracted_copies_are_gone_afterwards(self):
        z = self.zip('z.zip', {'a.pcap': b'ok', 'b.pcap': b'ok'})
        analyzer = FakeAnalyzer()
        batch_scan.scan([z], analyzer)
        self.assertTrue(analyzer.paths)
        self.assertFalse(any(os.path.exists(p) for p in analyzer.paths))

    def test_an_oversized_member_fails_alone(self):
        z = self.zip('z.zip', {'big.pcap': b'x' * 5000, 'small.pcap': b'ok'})
        report = batch_scan.scan([z], FakeAnalyzer(), max_member_bytes=1000)
        errors = {f['file']: f.get('error') for f in report['files']}
        self.assertIn('larger than', errors['z.zip/big.pcap'])
        self.assertIsNone(errors['z.zip/small.pcap'])

    def test_one_bad_capture_does_not_stop_the_rest(self):
        a = self.file('a.pcap', b'boom')
        b = self.file('b.pcap', b'cred')
        analyzer = FakeAnalyzer()
        report = batch_scan.scan([a, b], analyzer)
        self.assertEqual(report['summary']['failed'], 1)
        self.assertEqual(report['summary']['credentials'], 1)
        self.assertFalse(analyzer.is_analyzing)

    def test_credentials_are_combined_across_captures_and_tagged(self):
        a = self.file('a.pcap', b'cred')
        z = self.zip('z.zip', {'b.pcap': b'cred'})
        live = []
        analyzer = FakeAnalyzer()
        report = batch_scan.scan([a, z], analyzer, on_alert=live.append)
        self.assertEqual(len(report['credentials']), 1)
        self.assertEqual(report['credentials'][0]['captures'], ['a.pcap', 'z.zip/b.pcap'])
        self.assertEqual(report['credentials'][0]['value'], 'pas*****')
        self.assertEqual([a.evidence['capture'] for a in live], ['a.pcap', 'z.zip/b.pcap'])
        self.assertEqual(len(analyzer.alerts), 2, 'export covers every capture')
        self.assertEqual(analyzer.stats['credentials'], 1)

    def test_cancelling_stops_between_captures(self):
        paths = [self.file(f'{i}.pcap') for i in range(3)]
        progress = []
        report = batch_scan.scan(paths, FakeAnalyzer(),
                                 on_progress=lambda i, n, name: progress.append(i),
                                 cancelled=lambda: len(progress) >= 1)
        self.assertTrue(report['cancelled'])
        self.assertEqual(progress, [0])

    def test_the_command_line_prints_a_summary(self):
        a = self.file('a.pcap', b'cred')
        out = io.StringIO()
        with unittest.mock.patch('src.pcap_analyzer.PcapAnalyzer', lambda cfg: FakeAnalyzer()), \
                redirect_stdout(out):
            self.assertEqual(batch_scan.main([a]), 0)
        self.assertIn('1 of 1 files scanned (1 captures), 1 exposed secrets', out.getvalue())
        self.assertIn('FTP password pas*****', out.getvalue())


class FakeThreatIntel:
    def check_ip(self, ip):
        return {'feed': 'test-feed', 'category': 'c2'} if ip == '198.51.100.7' else None

    def check_domain(self, domain):
        return {'feed': 'test-feed', 'category': 'phish'} if domain == 'evil.example.com' else None


class TestFileContents(_Case):
    CONFIG = (b'# app.conf\n'
              b'upstream = 198.51.100.7\n'
              b'db_url = postgres://app:Pg-Pass-991@db.internal:5432/app\n'
              b'password = "Tr0ub4dor&3"\n'
              b'notify https://evil.example.com/hook admin@corp.example.com\n'
              b'aws = AKIAIOSFODNN7EXAMPLE\n')

    def test_secrets_are_masked_with_their_line(self):
        z = self.zip('leak.zip', {'etc/app.conf': self.CONFIG})
        live = []
        report = batch_scan.scan([z], FakeAnalyzer(), on_alert=live.append)
        found = {(s['kind'], s['line']) for s in report['secrets']}
        self.assertEqual(found, {('url_password', 3), ('password', 4), ('aws_access_key', 6)})
        dumped = json.dumps(report, default=str)
        for raw in ('Pg-Pass-991', 'Tr0ub4dor&3', 'AKIAIOSFODNN7EXAMPLE'):
            self.assertNotIn(raw, dumped)
        self.assertTrue(all(a.evidence['file'] == 'leak.zip/etc/app.conf' for a in live))
        self.assertEqual({a.rule_id for a in live}, {'FILESCAN-SECRET'})

    def test_indicators_combine_files_and_captures(self):
        a = self.file('a.log', b'from 10.0.0.5 to 198.51.100.7 via update.example.com\n')
        b = self.file('b.pcap', b'ok')
        report = batch_scan.scan([a, b], FakeAnalyzer())
        ips = {e['value']: e for e in report['indicators']['ipv4']}
        self.assertEqual(ips['10.0.0.5']['files'], ['a.log', 'b.pcap'])
        self.assertEqual(ips['10.0.0.5']['scope'], 'private')
        self.assertEqual(ips['198.51.100.7']['files'], ['a.log'])
        domains = {e['value']: e['count'] for e in report['indicators']['domain']}
        self.assertEqual(domains['update.example.com'], 5)
        self.assertEqual(report['summary']['ipv4'], 2)

    def test_threat_feeds_flag_known_bad_indicators(self):
        a = self.file('app.conf', self.CONFIG)
        analyzer = FakeAnalyzer()
        report = batch_scan.scan([a], analyzer, threat_intel=FakeThreatIntel())
        # 198.51.100.0/24 is documentation space, never public, so never looked up
        self.assertEqual({t['value'] for t in report['threats']}, {'evil.example.com'})
        analyzer.threat_intel = FakeThreatIntel()
        with unittest.mock.patch('src.file_scan.ip_scope', return_value='public'):
            report = batch_scan.scan([a], analyzer)
        self.assertEqual({t['value'] for t in report['threats']},
                         {'198.51.100.7', 'evil.example.com'})
        self.assertIn('FILESCAN-THREAT-INTEL', {a['rule_id'] for a in report['alerts']})

    def test_an_office_document_is_read_not_unpacked(self):
        doc = io.BytesIO()
        with zipfile.ZipFile(doc, 'w') as zf:
            zf.writestr('word/document.xml', '<w:t>Contact</w:t> <w:t>ops@corp.example.com</w:t>'
                                             '<w:t>password: Sup3rS3cret</w:t>')
        path = self.file('handover.docx', doc.getvalue())
        report = batch_scan.scan([path], FakeAnalyzer())
        self.assertEqual(report['summary']['files'], 1)
        self.assertEqual([e['value'] for e in report['indicators']['email']], ['ops@corp.example.com'])
        self.assertEqual([s['kind'] for s in report['secrets']], ['password'])


class TestFileScanPatterns(unittest.TestCase):
    def scan(self, text):
        from src.file_scan import scan_bytes
        return scan_bytes('x.txt', text.encode('utf-8'))

    def test_only_luhn_valid_card_numbers_count(self):
        r = self.scan('4111 1111 1111 1111 and 4111 1111 1111 1112')
        self.assertEqual([s['value'] for s in r['secrets']], ['**** **** **** 1111'])

    def test_placeholders_and_code_are_not_passwords(self):
        r = self.scan("password = None\npassword: str\npwd = os.environ['PWD']\n"
                      "api_key=${API_KEY}\npassword = '********'\nsecret = get_secret()\n"
                      "password = self.config.password\n")
        self.assertEqual(r['secrets'], [])

    def test_code_is_not_full_of_domains_and_addresses(self):
        r = self.scan('logger.info("x")\nself.site = 1\nstd::vector<int> a::b\nrun.py notes.md\n')
        self.assertEqual(r['indicators']['domain'], {})
        self.assertEqual(r['indicators']['ipv6'], {})

    def test_a_password_in_a_url_never_reaches_the_indicators(self):
        r = self.scan('see https://bob:Pa55word@site.example.com/a and smb://u:Hidden9@nas.lan/x')
        dumped = json.dumps(r)
        self.assertNotIn('Pa55word', dumped)
        self.assertNotIn('Hidden9', dumped.replace('hidden9', 'Hidden9'))
        self.assertIn('https://bob:****@site.example.com/a', r['indicators']['url'])

    def test_utf16_text_is_searched(self):
        from src.file_scan import scan_bytes
        r = scan_bytes('export.txt', 'server 8.8.8.8 ok'.encode('utf-16-le'))
        self.assertIn('8.8.8.8', r['indicators']['ipv4'])


@unittest.skipUnless(SCAPY_REAL, 'needs real scapy')
class TestWithTheRealAnalyzer(_Case):
    def test_a_password_in_a_zipped_capture_is_found_and_stays_masked(self):
        from scapy.all import Ether, IP, TCP, Raw, wrpcap
        from src.pcap_analyzer import PcapAnalyzer
        password = 'hunter2secret'
        frames = [Ether() / IP(src='10.0.0.5', dst='10.0.0.9') /
                  TCP(sport=40000, dport=21, flags='PA', seq=1 + i * 40) / Raw(load=line)
                  for i, line in enumerate([b'USER alice\r\n',
                                            f'PASS {password}\r\n'.encode()])]
        cap = os.path.join(self.tmp, 'ftp.pcap')
        wrpcap(cap, frames)
        z = os.path.join(self.tmp, 'caps.zip')
        with zipfile.ZipFile(z, 'w') as zf:
            zf.write(cap, 'site/ftp.pcap')

        report = batch_scan.scan([z], PcapAnalyzer(reset_config()))

        types = {(c['protocol'], c['credential_type']) for c in report['credentials']}
        self.assertIn(('FTP', 'password'), types)
        self.assertNotIn(password, json.dumps(report, default=str))


if __name__ == '__main__':
    unittest.main()
