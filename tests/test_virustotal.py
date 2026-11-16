"""
VirusTotal: the program checks behind alerts, and the release check.
=====================================================================
With a key (verification.virustotal_api_key), each alert about a program on
this PC gets VirusTotal's verdict on the program's SHA-256. Lookups 15 seconds
apart were skipped, not queued, and the empty answer was kept for the program
for an hour: in a burst of alerts only the first got an answer. The key could
only be set by editing config.json. Nothing here touches the network.
"""

import io
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

FAKE_KEY = 'fake-vt-key-for-tests-0000000000000000000000000000000000000000'
HASHES = ['%064x' % n for n in (1, 2, 3)]


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def found(malicious=0):
    return json.dumps({'data': {'attributes': {'last_analysis_stats': {
        'malicious': malicious, 'suspicious': 0, 'undetected': 60 - malicious,
        'harmless': 0}}}}).encode()


def http_error(code):
    return urllib.error.HTTPError('https://www.virustotal.com/api/v3/files/x', code,
                                  'error', {}, None)


class _VerifierCase(unittest.TestCase):

    def verifier(self, answers, key=FAKE_KEY):
        """A verifier whose requests get `answers` in turn (bytes, or an exception)."""
        from src.process_verify import ProcessVerifier
        self.requests = []
        answers = list(answers)

        def fake_open(req, timeout=None):
            self.requests.append(req)
            answer = answers.pop(0)
            if isinstance(answer, Exception):
                raise answer
            return _Response(answer)

        self.addCleanup(reset_config)
        patcher = mock.patch('urllib.request.urlopen', side_effect=fake_open)
        patcher.start()
        self.addCleanup(patcher.stop)
        verifier = ProcessVerifier(reset_config(**{'verification.virustotal_api_key': key}))
        verifier._vt_open = fake_open
        self.waits = []
        verifier._sleep = self.waits.append
        return verifier


class TestLookups(_VerifierCase):

    def test_a_burst_waits_its_turn_instead_of_being_skipped(self):
        verifier = self.verifier([found(), found(), found(7)])
        answers = [verifier._check_virustotal(h) for h in HASHES]
        self.assertTrue(all(a.get('checked') for a in answers), answers)
        self.assertEqual(answers[2]['detections'], 7)
        self.assertEqual(len(self.waits), 2)
        self.assertAlmostEqual(self.waits[0], 15, delta=1)
        self.assertAlmostEqual(self.waits[1], 30, delta=1)

    def test_the_same_program_is_looked_up_once(self):
        verifier = self.verifier([found()])
        first = verifier._check_virustotal(HASHES[0])
        second = verifier._check_virustotal(HASHES[0])
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(first, second)
        self.assertTrue(second['found'])

    def test_a_day_old_answer_is_asked_for_again(self):
        from src.process_verify import VT_ANSWER_TTL_SEC
        verifier = self.verifier([found(), found(3)])
        verifier._check_virustotal(HASHES[0])
        answer, _ = verifier._vt_answers[HASHES[0]]
        verifier._vt_answers[HASHES[0]] = (answer, time.time() - VT_ANSWER_TTL_SEC - 1)
        self.assertEqual(verifier._check_virustotal(HASHES[0])['detections'], 3)
        self.assertEqual(len(self.requests), 2)

    def test_an_unknown_file_is_an_answer_too(self):
        verifier = self.verifier([http_error(404)])
        answer = verifier._check_virustotal(HASHES[0])
        self.assertEqual((answer['checked'], answer['found']), (True, False))
        verifier._check_virustotal(HASHES[0])
        self.assertEqual(len(self.requests), 1)

    def test_the_key_goes_in_a_header_never_the_address(self):
        verifier = self.verifier([found()])
        verifier._check_virustotal(HASHES[0])
        req = self.requests[0]
        self.assertNotIn(FAKE_KEY, req.full_url)
        self.assertEqual(req.get_header('X-apikey'), FAKE_KEY)
        self.assertTrue(req.full_url.endswith('/api/v3/files/' + HASHES[0]))

    def test_without_a_key_nothing_is_asked(self):
        verifier = self.verifier([], key='')
        self.assertFalse(verifier._check_virustotal(HASHES[0])['checked'])
        self.assertEqual(self.requests, [])


class TestRefusals(_VerifierCase):

    def test_a_refused_key_stops_lookups_and_is_never_logged(self):
        verifier = self.verifier([http_error(401)])
        with self.assertLogs('NetSentinel.Verify', level='WARNING') as logs:
            self.assertFalse(verifier._check_virustotal(HASHES[0])['checked'])
        self.assertFalse(verifier._check_virustotal(HASHES[1])['checked'])
        self.assertEqual(len(self.requests), 1)
        self.assertNotIn(FAKE_KEY, '\n'.join(logs.output))
        self.assertEqual(verifier.virustotal_status()['state'], 'failed')

    def test_a_used_up_quota_pauses_lookups(self):
        verifier = self.verifier([http_error(429)])
        first = verifier._check_virustotal(HASHES[0])
        second = verifier._check_virustotal(HASHES[1])
        self.assertTrue(first['retry'] and second['retry'])
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(verifier.virustotal_status()['state'], 'waiting')
        verifier._vt_paused_until = 0
        self.assertNotIn(HASHES[0], verifier._vt_answers)

    def test_a_program_checked_while_virustotal_could_not_answer_is_checked_again(self):
        verifier = self.verifier([http_error(503), found()])
        handle, exe = tempfile.mkstemp(suffix='.exe')
        os.close(handle)
        self.addCleanup(os.remove, exe)
        with mock.patch.object(verifier, '_check_signature',
                               return_value={'signed': False, 'valid': False}), \
                mock.patch.object(verifier, '_check_location', return_value={}), \
                mock.patch.object(verifier, '_get_file_metadata', return_value={'age_days': 30}):
            first = verifier.verify_process(exe_path=exe)
            second = verifier.verify_process(exe_path=exe)
        self.assertFalse(first['checks']['virustotal']['checked'])
        self.assertTrue(second['checks']['virustotal']['checked'])


class TestWhereTheOwnerSeesIt(_VerifierCase):

    def test_the_threat_data_page_has_a_row(self):
        from types import SimpleNamespace
        from src import data_sources
        verifier = self.verifier([], key='')
        rows = {r['name']: r for r in data_sources.collect(
            SimpleNamespace(threat_intel=None, vulns=None, ids_engine=None,
                            process_verifier=verifier))}
        self.assertEqual(rows['virustotal']['state'], 'needs key')
        keyed = self.verifier([])
        self.assertEqual(keyed.virustotal_status()['state'], 'ok')
        self.assertNotIn(FAKE_KEY, json.dumps(keyed.virustotal_status()))

    def test_settings_has_a_field_for_the_key(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, 'src', 'gui.py'), encoding='utf-8') as f:
            self.assertIn("_add_setting_secret(\n            intel_card, "
                          "'verification.virustotal_api_key'", f.read())


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = b'MZ' + b'\x90' * 1000
EXE_SHA = __import__('hashlib').sha256(EXE).hexdigest()
UPLOAD = 'https://www.virustotal.com/_ah/upload/abc'


def release_check():
    if os.path.join(ROOT, 'tools') not in sys.path:
        sys.path.insert(0, os.path.join(ROOT, 'tools'))
    import virustotal_check
    return virustotal_check


class _Site:
    """GitHub and VirusTotal, as the release check sees them."""

    def __init__(self, vt_file=None, exe=EXE, scans=('queued', 'completed'), key_ok=True,
                 upload_url=UPLOAD):
        self.vt_file, self.exe, self.scans, self.key_ok = vt_file, exe, list(scans), key_ok
        self.upload_url = upload_url
        self.calls = []

    def __call__(self, method, url, headers=None, body=None, limit=None, timeout=None):
        self.calls.append((method, url, headers or {}))
        if url == 'https://api.github.com/repos/jamesccupps/NetSentinel/releases/latest':
            return 200, b'{"tag_name": "v1.17.0"}'
        if url.endswith('/NetSentinel.exe.sha256'):
            return 200, f'{EXE_SHA}  NetSentinel.exe\n'.encode()
        if url.endswith('/NetSentinel.exe'):
            return 200, self.exe
        if 'virustotal.com' in url and not self.key_ok:
            return 401, b'{}'
        if url.endswith('/files/' + EXE_SHA):
            if self.vt_file is None:
                return 404, b'{}'
            return 200, json.dumps({'data': {'attributes': self.vt_file}}).encode()
        if url.endswith('/files/upload_url'):
            return 200, json.dumps({'data': self.upload_url}).encode()
        if url == UPLOAD:
            self.uploaded = body
            return 200, b'{"data": {"type": "analysis", "id": "an-1"}}'
        if url.endswith('/analyses/an-1'):
            state = self.scans.pop(0)
            return 200, json.dumps({'data': {'attributes': {
                'status': state, 'date': 1790000000,
                'stats': {'malicious': 2, 'undetected': 62, 'type-unsupported': 4},
                'results': {'Bkav': {'category': 'malicious', 'result': 'W32.AIDetect\n::stop'},
                            'Other': {'category': 'undetected', 'result': None}}}}}).encode()
        return 500, b''


class TestReleaseCheck(unittest.TestCase):

    def run_check(self, site, **env):
        out = io.StringIO()
        summary = os.path.join(tempfile.mkdtemp(prefix='ns_vt_'), 'summary.md')
        env = dict({'VT_API_KEY': FAKE_KEY, 'GITHUB_STEP_SUMMARY': summary}, **env)
        code = release_check().main([], env=env, transport=site, sleep=lambda s: None, out=out)
        text = out.getvalue()
        if os.path.exists(summary):
            with open(summary, encoding='utf-8') as f:
                text += f.read()
        self.assertNotIn(FAKE_KEY, text)
        return code, text

    def test_a_new_release_is_uploaded_and_its_scan_reported(self):
        site = _Site()
        code, text = self.run_check(site)
        self.assertEqual(code, 0)
        self.assertIn('2 of 64 engines flag it', text)
        self.assertIn('uploaded and scanned now', text)
        self.assertIn('::warning title=VirusTotal::2 of 64 engines flag NetSentinel.exe v1.17.0', text)
        self.assertIn(EXE, site.uploaded)
        vt_calls = [c for c in site.calls if 'virustotal.com' in c[1]]
        self.assertTrue(all(c[2].get('x-apikey') == FAKE_KEY for c in vt_calls))
        self.assertFalse([c for c in site.calls if FAKE_KEY in c[1]])
        self.assertFalse([c for c in site.calls if 'virustotal.com' not in c[1]
                          and 'x-apikey' in c[2]], 'the key went to GitHub')

    def test_text_from_virustotal_cannot_start_a_workflow_command(self):
        code, text = self.run_check(_Site())
        self.assertIn('W32.AIDetect', text)
        self.assertNotIn('\n::stop', text)
        self.assertFalse([line for line in text.splitlines()
                          if line.startswith('::') and not line.startswith('::warning title=Virus')])

    def test_an_http_upload_address_is_used_over_https(self):
        """VirusTotal hands out http:// addresses; the 1.17.1 check refused one,
        and sending the key over plain HTTP is not the answer either."""
        site = _Site(upload_url=UPLOAD.replace('https://', 'http://'))
        code, text = self.run_check(site)
        self.assertEqual(code, 0, text)
        posts = [c for c in site.calls if c[0] == 'POST']
        self.assertEqual([c[1] for c in posts], [UPLOAD])
        self.assertFalse([c for c in site.calls if c[1].startswith('http://')])

    def test_an_upload_address_off_virustotal_is_refused(self):
        for address in ('https://uploads.example.net/_ah/upload/TOKEN123',
                        'https://www.virustotal.com.example.net/TOKEN123',
                        'https://user:pw@www.virustotal.com/TOKEN123',
                        'ftp://www.virustotal.com/TOKEN123'):
            site = _Site(upload_url=address)
            code, text = self.run_check(site)
            self.assertEqual(code, 1, address)
            self.assertFalse(hasattr(site, 'uploaded'), address)
            self.assertNotIn('TOKEN123', text, address)      # a one-time upload token
        self.assertIn('https://uploads.example.net', self.run_check(
            _Site(upload_url='https://uploads.example.net/_ah/upload/abc'))[1])

    def test_a_known_file_is_not_uploaded_again(self):
        site = _Site(vt_file={'last_analysis_stats': {'malicious': 0, 'undetected': 70},
                              'last_analysis_date': 1790000000})
        code, text = self.run_check(site, TAG='v1.17.0')
        self.assertEqual(code, 0)
        self.assertIn('0 of 70 engines flag it', text)
        self.assertIn('last scanned 2026-', text)
        self.assertNotIn('::warning', text)
        self.assertFalse([c for c in site.calls if c[1].endswith('/NetSentinel.exe')])

    def test_an_exe_that_does_not_match_its_checksum_is_not_uploaded(self):
        site = _Site(exe=EXE + b'tampered')
        code, text = self.run_check(site)
        self.assertEqual(code, 1)
        self.assertIn('does not match', text)
        self.assertFalse(hasattr(site, 'uploaded'))

    def test_a_refused_or_missing_key_is_a_failed_check(self):
        self.assertEqual(self.run_check(_Site(key_ok=False))[0], 1)
        code, text = self.run_check(_Site(), VT_API_KEY='')
        self.assertEqual(code, 1)
        self.assertIn('VT_API_KEY secret is not set', text)

    def test_only_a_release_tag_is_accepted(self):
        for tag in ('v1.17.0; curl evil.example', 'main', 'v1.17.0-signtest.1', '../x'):
            site = _Site()
            code, text = self.run_check(site, TAG=tag)
            self.assertEqual(code, 1, tag)
            self.assertEqual(site.calls, [], tag)


class TestReleaseCheckWorkflow(unittest.TestCase):

    def setUp(self):
        try:
            import yaml
        except ImportError:
            self.skipTest('needs pyyaml')
        self.flows = {}
        folder = os.path.join(ROOT, '.github', 'workflows')
        for name in os.listdir(folder):
            with open(os.path.join(folder, name), encoding='utf-8') as f:
                text = f.read()
            self.flows[name] = (text, yaml.safe_load(text))

    def test_only_the_check_sees_the_virustotal_key(self):
        holders = [name for name, (text, _) in self.flows.items() if 'VT_API_KEY' in text]
        self.assertEqual(holders, ['virustotal.yml'])
        text, flow = self.flows['virustotal.yml']
        for secret in ('NETSENTINEL_SIGNING_KEY', 'AZURE_'):
            self.assertNotIn(secret, text)
        self.assertEqual(flow['permissions'], {})
        job = flow['jobs']['check']
        self.assertEqual(job['permissions'], {'contents': 'read'})
        self.assertNotIn('environment', job)

    def test_it_installs_nothing_and_runs_only_the_check(self):
        _, flow = self.flows['virustotal.yml']
        steps = flow['jobs']['check']['steps']
        self.assertEqual([s['uses'].split('@')[0] for s in steps if 'uses' in s],
                         ['actions/checkout'])
        runs = [s['run'] for s in steps if 'run' in s]
        self.assertEqual(runs, ['python3 tools/virustotal_check.py'])

    def test_it_follows_successful_tag_releases_only(self):
        _, flow = self.flows['virustotal.yml']
        on = flow.get('on', flow.get(True))
        self.assertEqual(on['workflow_run'], {'workflows': ['release'], 'types': ['completed']})
        condition = flow['jobs']['check']['if']
        for part in ("workflow_run.conclusion == 'success'", "workflow_run.event == 'push'",
                     "!contains(github.event.workflow_run.head_branch, '-signtest')"):
            self.assertIn(part, condition)


if __name__ == '__main__':
    unittest.main()
