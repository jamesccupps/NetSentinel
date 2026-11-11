"""The release workflow's Authenticode signing keeps to its rules.

authenticode is the one job that can sign in to Azure Artifact Signing as James
Cupps. Anything running in it could sign whatever it liked, so it runs only
pinned actions and tools/authenticode.ps1: nothing from PyPI, and never the
program. The exe is tested, hashed and given the updater's signature after
Authenticode signing, since signing changes the file. A -signtest tag never
reaches the updater's key or a release. See the comment at the top of
release.yml; TestReleaseWorkflow in test_outside_review.py covers the key.
"""
import os
import re
import unittest


class TestAuthenticode(unittest.TestCase):

    def setUp(self):
        try:
            import yaml
        except ImportError:
            self.skipTest('needs pyyaml')
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, '.github', 'workflows', 'release.yml'),
                  encoding='utf-8') as f:
            self.jobs = yaml.safe_load(f)['jobs']

    def runs(self, job):
        return '\n'.join(s.get('run', '') for s in self.jobs[job]['steps'])

    def test_only_authenticode_can_sign_in_to_azure(self):
        with_identity = [name for name, job in self.jobs.items()
                         if (job.get('permissions') or {}).get('id-token') == 'write']
        self.assertEqual(with_identity, ['authenticode'])
        with_azure = [name for name, job in self.jobs.items() if 'AZURE_' in str(job)]
        self.assertEqual(with_azure, ['authenticode'])
        job = self.jobs['authenticode']
        self.assertEqual(job.get('environment'), 'release')
        self.assertEqual(job.get('if'), "startsWith(github.ref, 'refs/tags/v')")

    def test_authenticode_runs_no_pypi_code_and_never_the_program(self):
        job = self.jobs['authenticode']
        uses = [s['uses'].split('@')[0] for s in job['steps'] if 'uses' in s]
        self.assertNotIn('actions/setup-python', uses)
        runs = self.runs('authenticode')
        self.assertEqual(re.findall(r'\bpip\b|\bpython\b|Start-Process|--version', runs), [])
        self.assertIn('./tools/authenticode.ps1 -File dist\\NetSentinel.exe', runs)

    def test_the_signed_exe_is_checked_then_hashed_then_signed_for_the_updater(self):
        self.assertEqual(self.jobs['verify']['needs'], ['build', 'authenticode'])
        runs = self.runs('verify')
        order = [runs.index(s) for s in ("check_signatures.ps1 -Publisher 'CN=James Cupps, O=James Cupps'",
                                         "-ArgumentList '--version'",
                                         'NetSentinel.exe.sha256')]
        self.assertEqual(order, sorted(order))
        self.assertNotIn('.sha256', self.runs('build'))
        self.assertEqual(self.jobs['sign']['needs'], 'verify')
        downloads = [s['with']['name'] for s in self.jobs['sign']['steps']
                     if s.get('uses', '').startswith('actions/download-artifact@')]
        self.assertEqual(downloads, ['verified'])

    def test_a_signtest_tag_never_reaches_the_key_or_a_release(self):
        for job in ('sign', 'publish'):
            self.assertIn("!contains(github.ref_name, '-signtest')", self.jobs[job]['if'])


if __name__ == '__main__':
    unittest.main()
