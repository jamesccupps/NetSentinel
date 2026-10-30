"""
Archives in file scans: tar and its compressed forms, single gzip/bzip2/xz
files, 7z, nested archives to a depth limit, zips known by their bytes,
RAR reported, links refused, and the limits that stop decompression bombs.
"""

import bz2
import gzip
import io
import json
import lzma
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src import archives, batch_scan, file_scan  # noqa: E402
from test_batch_scan import FakeAnalyzer  # noqa: E402

SECRET_LINE = b'password = "Synth-Archive-%d"\n'


class FakeConfig:
    def __init__(self, **values):
        self.values = values

    def get(self, section, key, default=None):
        return self.values.get(key, default) if section == 'file_scan' else default


def tar_bytes(members, mode='w'):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def zip_bytes(members, compression=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', compression) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


class _Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='archives_')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def file(self, rel, data):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(data)
        return path

    def scan(self, *paths, analyzer=None, **kw):
        return batch_scan.scan(list(paths), analyzer or FakeAnalyzer(), **kw)

    @staticmethod
    def secret_files(report):
        return sorted(s['file'].replace('\\', '/') for s in report['secrets'])

    @staticmethod
    def reasons(report):
        return {s['file'].replace('\\', '/'): s['reason'] for s in report['skipped']}


class TestFormats(_Case):

    def test_tars_plain_and_compressed(self):
        for ext, mode in (('tar', 'w'), ('tar.gz', 'w:gz'), ('tgz', 'w:gz'),
                          ('tar.bz2', 'w:bz2'), ('tar.xz', 'w:xz')):
            with self.subTest(ext=ext):
                path = self.file(f'bundle.{ext}', tar_bytes({'etc/app.conf': SECRET_LINE % 1}, mode))
                report = self.scan(path)
                self.assertEqual(self.secret_files(report), [f'bundle.{ext}/etc/app.conf'])
                self.assertNotIn(b'Synth-Archive-1', json.dumps(report).encode())

    def test_single_compressed_files(self):
        line = b'GET /index.html from 198.51.100.61\n'
        for name, data in (('access.log.gz', gzip.compress(line)), ('access.log.bz2', bz2.compress(line)),
                           ('access.log.xz', lzma.compress(line))):
            with self.subTest(name=name):
                report = self.scan(self.file(name, data))
                (ip,) = report['indicators']['ipv4']
                self.assertEqual(ip['files'], [f'{name}/access.log'])

    def test_7z(self):
        try:
            import py7zr
        except ImportError:
            self.skipTest('py7zr not installed')
        path = os.path.join(self.tmp, 'backup.7z')
        with py7zr.SevenZipFile(path, 'w') as z:
            z.writestr(SECRET_LINE % 7, 'cfg/one.conf')
            z.writestr(b'plain 192.0.2.4\n', 'two.txt')
            z.writestr(zip_bytes({'inner.txt': SECRET_LINE % 8}), 'nested.zip')
        report = self.scan(path)
        self.assertEqual(self.secret_files(report),
                         ['backup.7z/cfg/one.conf', 'backup.7z/nested.zip/inner.txt'])
        entry = next(f for f in report['files'] if f['file'] == 'backup.7z')
        self.assertEqual((entry['type'], entry['archive'], entry['members']), ('archive', '7z', 3))

    def test_zips_are_known_by_their_bytes(self):
        data = zip_bytes({'res/config.properties': SECRET_LINE % 2})
        for name in ('app.jar', 'app.apk', 'backup.dat'):
            with self.subTest(name=name):
                report = self.scan(self.file(name, data))
                self.assertEqual(self.secret_files(report), [f'{name}/res/config.properties'])

    def test_office_documents_are_still_read_not_unpacked(self):
        doc = zip_bytes({'word/document.xml': '<w:t>' + (SECRET_LINE % 3).decode() + '</w:t>'})
        report = self.scan(self.file('handover.docx', doc))
        self.assertEqual(self.secret_files(report), ['handover.docx'])
        self.assertEqual(report['summary']['archives'], 0)

    def test_rar_is_reported_not_opened(self):
        rar = b'Rar!\x1a\x07\x01\x00' + os.urandom(64)
        report = self.scan(self.file('photos.rar', rar), self.file('renamed.bin', rar))
        reasons = self.reasons(report)
        for name in ('photos.rar', 'renamed.bin'):
            self.assertIn('UnRAR', reasons[name])
        self.assertTrue(all(s.get('sha256') for s in report['skipped']))
        self.assertEqual(report['summary']['scanned'], 0)

    def test_something_that_only_starts_like_an_archive_is_read_as_a_file(self):
        report = self.scan(self.file('notes.dat', b'PK\x03\x04 not really a zip ' + SECRET_LINE % 4))
        self.assertEqual(self.secret_files(report), ['notes.dat'])


class TestNesting(_Case):

    def test_nested_archives_open_to_the_depth_limit(self):
        level4 = zip_bytes({'lvl4.txt': SECRET_LINE % 4})
        level3 = zip_bytes({'lvl3.txt': SECRET_LINE % 3, 'level4.zip': level4})
        level2 = tar_bytes({'lvl2.txt': SECRET_LINE % 2, 'level3.zip': level3}, 'w:gz')
        level1 = self.file('level1.zip', zip_bytes({'lvl1.txt': SECRET_LINE % 1, 'level2.tgz': level2}))
        report = self.scan(level1)
        self.assertEqual(self.secret_files(report), [
            'level1.zip/level2.tgz/level3.zip/lvl3.txt', 'level1.zip/level2.tgz/lvl2.txt',
            'level1.zip/lvl1.txt'])
        self.assertIn('nested more than 3 deep',
                      self.reasons(report)['level1.zip/level2.tgz/level3.zip/level4.zip'])

    def test_the_depth_limit_is_a_setting(self):
        inner = zip_bytes({'deep.txt': SECRET_LINE % 5})
        path = self.file('outer.zip', zip_bytes({'inner.zip': inner}))
        report = self.scan(path, config=FakeConfig(archive_max_depth=1))
        self.assertEqual(report['secrets'], [])
        self.assertIn('nested', self.reasons(report)['outer.zip/inner.zip'])


class TestSafety(_Case):

    def test_links_and_special_files_in_a_tar_are_not_followed(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tf:
            for name, kind in (('etc-link', tarfile.SYMTYPE), ('hard', tarfile.LNKTYPE),
                               ('fifo', tarfile.FIFOTYPE)):
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = '/etc/shadow'
                tf.addfile(info)
        report = self.scan(self.file('links.tgz', buf.getvalue()))
        reasons = self.reasons(report)
        self.assertEqual(reasons['links.tgz/etc-link'], 'link not followed')
        self.assertEqual(reasons['links.tgz/hard'], 'link not followed')
        self.assertEqual(reasons['links.tgz/fifo'], 'special file')

    def test_hostile_member_names_land_in_numbered_temp_files(self):
        data = tar_bytes({'../../escaped.pcap': b'ok', '/abs/x.pcap': b'ok'}, 'w:gz')
        analyzer = FakeAnalyzer()
        report = self.scan(self.file('evil.tgz', data), analyzer=analyzer)
        self.assertEqual(report['summary']['scanned'], 2)
        for path in analyzer.paths:
            self.assertRegex(os.path.basename(path), r'^\d{5}\.pcap$')
            self.assertFalse(os.path.exists(path), 'extracted copies are deleted')
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.tmp), 'escaped.pcap')))

    def test_safe_extensions(self):
        self.assertEqual(batch_scan._safe_ext('a/b/c.PCAP'), '.pcap')
        self.assertEqual(batch_scan._safe_ext('x.p\\..\\..\\evil'), '')
        self.assertEqual(batch_scan._safe_ext('noext'), '')

    def test_a_decompression_bomb_is_stopped(self):
        bomb = zip_bytes({'zeros.bin': b'\x00' * (2 * 1024 * 1024), 'after.txt': SECRET_LINE % 9})
        for name, data in (('bomb.zip', bomb),
                           ('bomb.tgz', tar_bytes({'zeros.bin': b'\x00' * (2 * 1024 * 1024),
                                                   'after.txt': SECRET_LINE % 9}, 'w:gz'))):
            with self.subTest(name=name), mock.patch.object(batch_scan, 'RATIO_FLOOR', 64 * 1024):
                report = self.scan(self.file(name, data))
                errors = {f['file']: f.get('error', '') for f in report['files']}
                self.assertIn('decompression bomb', errors[f'{name}/zeros.bin'])
                self.assertEqual(report['secrets'], [], 'the rest of the archive is not opened')
                self.assertTrue(any('decompression bomb' in s['reason'] for s in report['skipped']))

    def test_one_budget_covers_an_archive_and_everything_inside_it(self):
        members = {f'part{i}.txt': (SECRET_LINE % i) + b'filler text\n' * 5000 for i in range(4)}
        inner = zip_bytes(members, zipfile.ZIP_STORED)
        path = self.file('big.zip', zip_bytes({'inner.zip': inner, 'tail.txt': SECRET_LINE % 8},
                                              zipfile.ZIP_STORED))
        report = self.scan(path, config=FakeConfig(archive_max_bytes=len(inner) + 130000))
        self.assertTrue(any('budget' in f.get('error', '') for f in report['files']))
        self.assertLess(len(report['secrets']), 5)

    def test_an_oversized_7z_member_fails_alone(self):
        try:
            import py7zr
        except ImportError:
            self.skipTest('py7zr not installed')
        path = os.path.join(self.tmp, 'mixed.7z')
        with py7zr.SevenZipFile(path, 'w') as z:
            z.writestr(b'x' * 5000, 'big.bin')
            z.writestr(SECRET_LINE % 6, 'small.conf')
        report = self.scan(path, max_member_bytes=1000)
        errors = {f['file']: f.get('error') for f in report['files']}
        self.assertIn('larger than', errors['mixed.7z/big.bin'])
        self.assertEqual(self.secret_files(report), ['mixed.7z/small.conf'])


class TestPdfBudget(unittest.TestCase):

    def test_pdf_streams_share_one_budget(self):
        streams = b''.join(b'stream\n' + zlib.compress(bytes([65 + i]) * 800) + b'\nendstream\n'
                           for i in range(3))
        with mock.patch.object(file_scan, 'MAX_PDF_BYTES', 1000):
            notes = []
            inflated = file_scan._pdf_streams(b'%PDF-1.4\n' + streams, notes)
        self.assertLessEqual(sum(len(s) for s in inflated), 1000)
        self.assertTrue(notes)


class TestDetect(unittest.TestCase):

    def test_magic_bytes(self):
        cases = {b'PK\x03\x04rest': archives.ZIP, b'7z\xbc\xaf\x27\x1c..': archives.SEVENZIP,
                 b'Rar!\x1a\x07\x00': archives.RAR, b'\x1f\x8b\x08\x00': archives.GZIP,
                 b'BZh91AY&SY..': archives.BZIP2, b'\xfd7zXZ\x00..': archives.XZ,
                 b'\x00' * 257 + b'ustar\x0000': archives.TAR, b'hello world': None,
                 b'BZh is not bzip2': None}
        for head, kind in cases.items():
            with self.subTest(head=head[:8]):
                self.assertEqual(archives.detect_bytes(head), kind)


if __name__ == '__main__':
    unittest.main()
