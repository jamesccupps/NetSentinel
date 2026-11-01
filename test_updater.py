"""
The updater: finding a release, checking it, and handing over to it.
Nothing here touches the network: every download goes through a fake.
"""

import base64
import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src import updater as up  # noqa: E402

EXE = b'MZ' + bytes(range(256)) * 64           # stands in for NetSentinel.exe
SHA = hashlib.sha256(EXE).hexdigest()
DL = 'https://github.com/jamesccupps/NetSentinel/releases/download/v1.9.3/'


def keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw,
                                        serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode(), base64.b64encode(pub).decode()


PRIVATE, PUBLIC = keypair()


def release(tag='v1.9.3', assets=('NetSentinel.exe', 'NetSentinel.exe.sig',
                                  'NetSentinel.exe.sha256'), **extra):
    data = {'tag_name': tag, 'draft': False, 'prerelease': False,
            'html_url': f'https://github.com/jamesccupps/NetSentinel/releases/tag/{tag}',
            'body': 'What changed.',
            'assets': [{'name': n, 'size': len(EXE), 'browser_download_url': DL + n}
                       for n in assets]}
    data.update(extra)
    return data


class Fake:
    """GitHub, as the updater sees it: url -> bytes."""

    def __init__(self, files):
        self.files = files
        self.asked = []

    def __call__(self, url, limit, out=None):
        self.asked.append(url)
        body = self.files[url]
        if isinstance(body, Exception):
            raise body
        if len(body) > limit:
            raise up.UpdateError('too large')
        if out is None:
            return body
        out.write(body)
        return None


def github(rel=None, exe=EXE, manifest=None, sha=SHA):
    manifest = manifest or up.sign_manifest(PRIVATE, '1.9.3', SHA)
    return Fake({up.LATEST_URL: json.dumps(rel or release()).encode(),
                 DL + 'NetSentinel.exe': exe,
                 DL + 'NetSentinel.exe.sig': json.dumps(manifest).encode(),
                 DL + 'NetSentinel.exe.sha256': f'{sha}  NetSentinel.exe\n'.encode()})


class _Folder(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='ns_update_')
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.exe = os.path.join(self.dir, 'NetSentinel.exe')
        with open(self.exe, 'wb') as f:
            f.write(b'MZ old')

    def updater(self, fake, current='1.9.2'):
        return up.Updater(current, fetch=fake, public_key=PUBLIC, exe_path=self.exe, frozen=True)

    def left(self):
        return sorted(os.listdir(self.dir))


class TestVersions(unittest.TestCase):

    def test_tags_parse_and_compare_as_numbers(self):
        self.assertEqual(up.parse_version('v1.9.2'), (1, 9, 2))
        self.assertGreater(up.parse_version('v1.10.0'), up.parse_version('1.9.2'))
        for bad in ('', 'latest', 'v1', 'v1.9.2-rc1', '1.9.x', None):
            self.assertIsNone(up.parse_version(bad), bad)


class TestChecking(_Folder):

    def test_a_newer_release_is_found(self):
        info = self.updater(github()).check()
        self.assertEqual((info.version, info.installable), ('1.9.3', True))
        self.assertTrue(info.page_url.startswith(up.RELEASES_PAGE))

    def test_the_same_or_an_older_one_is_not(self):
        for tag in ('v1.9.2', 'v1.9.1', 'nightly'):
            self.assertIsNone(self.updater(github(release(tag))).check(), tag)

    def test_drafts_prereleases_and_foreign_links_are_ignored(self):
        self.assertIsNone(self.updater(github(release(prerelease=True))).check())
        rel = release()
        rel['assets'][0]['browser_download_url'] = 'https://evil.example/NetSentinel.exe'
        rel['html_url'] = 'https://evil.example/release'
        info = self.updater(github(rel)).check()
        self.assertFalse(info.installable)
        self.assertTrue(info.page_url.startswith(up.RELEASES_PAGE))

    def test_offline_is_an_error_noted_not_raised(self):
        u = self.updater(Fake({up.LATEST_URL: OSError('no route to host')}))
        self.assertIsNone(u.check())
        self.assertIn('no route', u.last_error)

    def test_only_https_to_github_is_fetched(self):
        for url in ('http://github.com/x', 'https://github.com.evil.example/x',
                    'https://example.com/x', 'file:///c:/x'):
            with self.assertRaises(up.UpdateError, msg=url):
                up._http_fetch(url, 10)


class TestSignatures(unittest.TestCase):

    def test_a_signed_manifest_verifies(self):
        manifest = up.sign_manifest(PRIVATE, '1.9.3', SHA)
        self.assertEqual(up.verify_manifest(manifest, PUBLIC), ('1.9.3', SHA))

    def test_changing_anything_fails(self):
        manifest = up.sign_manifest(PRIVATE, '1.9.3', SHA)
        for change in ({'version': '1.9.4'}, {'sha256': '0' * 64},
                       {'signature': base64.b64encode(b'\0' * 64).decode()},
                       {'signature': 'not base64!'}, {'sha256': 'ABC'}):
            with self.assertRaises(up.UpdateError, msg=change):
                up.verify_manifest(dict(manifest, **change), PUBLIC)

    def test_another_key_fails(self):
        _other, other_public = keypair()
        with self.assertRaises(up.UpdateError):
            up.verify_manifest(up.sign_manifest(PRIVATE, '1.9.3', SHA), other_public)

    def test_the_built_in_key_is_a_real_one(self):
        """An empty or malformed PUBLIC_KEY would refuse every update."""
        self.assertEqual(len(base64.b64decode(up.PUBLIC_KEY, validate=True)), 32)


class TestDownloading(_Folder):

    def test_a_checked_download_is_put_beside_the_exe(self):
        u = self.updater(github())
        path = u.download(u.check())
        self.assertEqual(path, os.path.join(self.dir, up.UPDATE_NAME))
        with open(path, 'rb') as f:
            self.assertEqual(f.read(), EXE)

    def test_a_download_that_is_not_the_signed_one_is_not_kept(self):
        u = self.updater(github(exe=EXE + b'tampered'))
        with self.assertRaises(up.UpdateError):
            u.download(u.check())
        self.assertEqual(self.left(), ['NetSentinel.exe'])

    def test_the_published_checksum_has_to_agree(self):
        u = self.updater(github(sha='0' * 64))
        with self.assertRaises(up.UpdateError):
            u.download(u.check())

    def test_a_signature_for_another_or_older_version_is_refused(self):
        for version in ('1.9.4', '1.9.1'):
            fake = github(manifest=up.sign_manifest(PRIVATE, version, SHA))
            u = self.updater(fake)
            info = u.check()
            with self.assertRaises(up.UpdateError, msg=version):
                u.download(info)
            self.assertNotIn(DL + 'NetSentinel.exe', fake.asked,
                             'the exe was downloaded before its signature was checked')

    def test_a_signature_from_another_key_is_refused(self):
        other, _ = keypair()
        u = self.updater(github(manifest=up.sign_manifest(other, '1.9.3', SHA)))
        with self.assertRaises(up.UpdateError):
            u.download(u.check())

    def test_a_release_without_a_signature_is_not_installable(self):
        u = self.updater(github(release(assets=('NetSentinel.exe', 'NetSentinel.exe.sha256'))))
        info = u.check()
        self.assertFalse(info.installable)
        with self.assertRaises(up.UpdateError):
            u.download(info)

    def test_from_source_there_is_nothing_to_replace(self):
        u = up.Updater('1.9.2', fetch=github(), public_key=PUBLIC, exe_path=self.exe,
                       frozen=False)
        self.assertFalse(u.can_install)


class TestHandingOver(_Folder):

    def test_the_new_exe_is_started_to_finish_with_the_same_arguments(self):
        started = []
        u = self.updater(github())
        u.hand_over(os.path.join(self.dir, up.UPDATE_NAME), monitor=True,
                    argv=[self.exe, '--review', 'D:\\review', '--monitor'],
                    popen=lambda cmd, **kw: started.append(cmd))
        cmd = started[0]
        self.assertEqual(cmd[:3], [os.path.join(self.dir, up.UPDATE_NAME), '--finish-update',
                                   os.path.abspath(self.exe)])
        self.assertIn(str(os.getpid()), cmd[3].split(','))
        self.assertEqual(cmd[4:], ['--review', 'D:\\review', '--monitor'])

    def test_finishing_puts_the_new_exe_in_place_and_starts_it(self):
        new = os.path.join(self.dir, up.UPDATE_NAME)
        with open(new, 'wb') as f:
            f.write(EXE)
        started = []
        code = up.finish_update(self.exe, '', ['--monitor'], source=new,
                                popen=lambda cmd, **kw: started.append(cmd), timeout=1)
        self.assertEqual(code, 0)
        with open(self.exe, 'rb') as f:
            self.assertEqual(f.read(), EXE)
        with open(self.exe + '.old', 'rb') as f:
            self.assertEqual(f.read(), b'MZ old')
        self.assertEqual(started, [[self.exe, '--monitor']])

    def test_a_failed_install_still_starts_the_old_one(self):
        started = []
        up.finish_update(self.exe, '', [], source=os.path.join(self.dir, 'missing.exe'),
                         popen=lambda cmd, **kw: started.append(cmd), timeout=1)
        with open(self.exe, 'rb') as f:
            self.assertEqual(f.read(), b'MZ old')
        self.assertEqual(started, [[self.exe]])
        self.assertEqual(self.left(), ['NetSentinel.exe'])

    def test_the_next_start_removes_the_leftovers(self):
        for name in ('NetSentinel.exe.old', up.UPDATE_NAME, up.UPDATE_NAME + '.part'):
            with open(os.path.join(self.dir, name), 'wb') as f:
                f.write(b'x')
        up.cleanup_leftovers(self.exe)
        self.assertEqual(self.left(), ['NetSentinel.exe'])

    def test_main_hands_finish_update_to_the_updater_first(self):
        import main
        calls = []
        real = up.finish_update
        up.finish_update = lambda *a: calls.append(a) or 0
        try:
            self.assertEqual(main.main(['--finish-update', self.exe, '12,34', '--monitor']), 0)
        finally:
            up.finish_update = real
        self.assertEqual(calls, [(self.exe, '12,34', ['--monitor'])])


class TestReleaseSigning(_Folder):

    def test_the_tool_signs_what_the_updater_accepts(self):
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools'))
        import sign_release
        from src import __version__
        with open(self.exe, 'wb') as f:
            f.write(EXE)
        os.environ[sign_release.KEY_VARIABLE] = PRIVATE
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                sign_release.sign(self.exe, f'v{__version__}', public_key=PUBLIC)
            with self.assertRaises(SystemExit):
                sign_release.sign(self.exe, 'v0.0.1', public_key=PUBLIC)
            other, _ = keypair()
            os.environ[sign_release.KEY_VARIABLE] = other
            with self.assertRaises(SystemExit):     # not the key the app trusts
                sign_release.sign(self.exe, public_key=PUBLIC)
        finally:
            del os.environ[sign_release.KEY_VARIABLE]
        with open(self.exe + '.sig', encoding='ascii') as f:
            self.assertEqual(up.verify_manifest(json.load(f), PUBLIC), (__version__, SHA))

    def test_keygen_never_overwrites_a_key(self):
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools'))
        import sign_release
        path = os.path.join(self.dir, 'key.txt')
        with contextlib.redirect_stdout(io.StringIO()):
            sign_release.keygen(path)
        with self.assertRaises(FileExistsError):
            sign_release.keygen(path)


if __name__ == '__main__':
    unittest.main()
