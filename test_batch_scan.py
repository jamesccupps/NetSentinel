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
        return {'stats': {'packets_analyzed': 3},
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
        self.assertEqual(names, ['caps/a.pcap', 'caps/more.zip/c.cap', 'caps/sub/b.pcapng'])
        self.assertEqual(skipped, [])

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
        txt = self.file('notes.txt')
        bad = self.file('bad.zip', b'not a zip')
        _, skipped = batch_scan.collect([txt, bad, os.path.join(self.tmp, 'gone')])
        reasons = [s['reason'] for s in skipped]
        self.assertEqual(reasons[0], 'not a capture or zip')
        self.assertTrue(reasons[1].startswith('unreadable zip'))
        self.assertEqual(reasons[2], 'not found')


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
        self.assertIn('1 of 1 captures scanned', out.getvalue())
        self.assertIn('FTP password pas*****', out.getvalue())


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
