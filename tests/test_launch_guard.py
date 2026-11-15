"""
An exe started by this elevated process is the one that was checked.
====================================================================
The outside review of 2026-11-14 (N2): the updater checked the download's
SHA-256, returned its path, and started that path later; the new exe put
itself in place and started the target by path; Restart started this exe by
path. In a folder the owner's ordinary programs can write, any of them could
swap the file in between and be started as Administrator with no prompt.
Now each is held (no write, rename or delete) while its hash is compared and
it is started, and this exe holds itself while it runs.
"""

import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401

from src import launch_guard as guard  # noqa: E402
from src import updater as up  # noqa: E402
from test_updater import EXE, PUBLIC, github  # noqa: E402

windows_only = unittest.skipUnless(os.name == 'nt', 'holding a file is a Windows lock')


class _Folder(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='ns_guard_')
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.exe = os.path.join(self.dir, 'NetSentinel.exe')
        with open(self.exe, 'wb') as f:
            f.write(b'MZ old')

    def write(self, name, data):
        path = os.path.join(self.dir, name)
        with open(path, 'wb') as f:
            f.write(data)
        return path


class TestHolding(_Folder):

    @windows_only
    def test_a_held_file_cannot_be_replaced_renamed_or_written(self):
        other = self.write('other.exe', b'MZ evil')
        with guard.held(self.exe) as f:
            self.assertEqual(f.read(), b'MZ old')
            for attempt in (lambda: os.replace(other, self.exe),
                            lambda: os.replace(self.exe, self.exe + '.moved'),
                            lambda: open(self.exe, 'ab').close()):
                with self.assertRaises(OSError):
                    attempt()
        os.replace(other, self.exe)                     # free again once let go

    def test_a_changed_file_is_not_started(self):
        started = []
        with self.assertRaises(guard.LaunchRefused):
            guard.start_held([self.exe], sha256='0' * 64,
                             popen=lambda cmd, **kw: started.append(cmd))
        self.assertEqual(started, [])

    def test_the_right_file_is_started_with_what_was_asked(self):
        import hashlib
        started = []
        guard.start_held([self.exe, '--monitor'], sha256=hashlib.sha256(b'MZ old').hexdigest(),
                         popen=lambda cmd, **kw: started.append((cmd, kw)), cwd=self.dir)
        self.assertEqual(started, [([self.exe, '--monitor'], {'cwd': self.dir})])


class TestTheUpdater(_Folder):

    def updater(self):
        return up.Updater('1.9.2', fetch=github(), public_key=PUBLIC, exe_path=self.exe,
                          frozen=True)

    def test_a_download_swapped_before_the_click_is_not_started(self):
        u = self.updater()
        path = u.download(u.check())
        self.write(up.UPDATE_NAME, b'MZ evil')          # another program, before the click
        started = []
        with self.assertRaises(up.UpdateError):
            u.hand_over(path, popen=lambda cmd, **kw: started.append(cmd))
        self.assertEqual(started, [])

    def test_only_a_download_it_checked_is_started(self):
        u = self.updater()
        with self.assertRaises(up.UpdateError):
            u.hand_over(self.write(up.UPDATE_NAME, EXE), popen=lambda cmd, **kw: None)

    def test_a_target_swapped_after_the_move_is_not_started(self):
        new = self.write(up.UPDATE_NAME, EXE)
        real_replace = os.replace

        def replace_then_swap(src, dst):
            real_replace(src, dst)
            if src.endswith('.new'):
                with open(dst, 'wb') as f:              # in the gap before the start
                    f.write(b'MZ evil')
        started = []
        with mock.patch.object(up.os, 'replace', replace_then_swap):
            code = up.finish_update(self.exe, '', [], source=new,
                                    popen=lambda cmd, **kw: started.append(cmd), timeout=1)
        self.assertEqual((code, started), (1, []))


class TestRestart(_Folder):

    def tearDown(self):
        guard.release_own_exe()

    def test_restart_starts_this_exe_through_its_hold(self):
        from src import restart
        hold = guard.hold_own_exe(self.exe)
        self.assertIs(guard.own_exe_hold(self.exe), hold)
        if os.name == 'nt':
            with self.assertRaises(OSError):
                os.replace(self.write('other.exe', b'MZ evil'), self.exe)
        through = []
        real = guard.start_held

        def spy(command, **kw):
            through.append(kw.get('held_file'))
            return real(command, **kw)
        started = []
        with mock.patch.object(sys, 'frozen', True, create=True), \
                mock.patch.object(sys, 'executable', self.exe), \
                mock.patch.object(sys, 'argv', [self.exe]), \
                mock.patch.object(guard, 'start_held', spy):
            restart.relaunch(popen=lambda cmd, **kw: started.append(cmd))
        self.assertEqual(started, [[self.exe]])
        self.assertIs(through[0], hold)

    def test_main_holds_the_exe_before_anything_else_runs(self):
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               'main.py'), encoding='utf-8') as f:
            source = f.read()
        self.assertLess(source.index('hold_own_exe()'), source.index('if not is_admin():'))


if __name__ == '__main__':
    unittest.main()
