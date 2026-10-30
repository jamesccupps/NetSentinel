"""
The tray icon and restart.
==========================
Closing the window used to stop monitoring and exit, and settings that apply at
start needed the process found and restarted by hand. A fake pystray and a fake
window stand in here, so nothing appears in a real tray and no copy is started.
"""

import os
import sys
import threading
import types
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

import main  # noqa: E402
from src import restart, tray  # noqa: E402


class TestRelaunch(unittest.TestCase):

    def test_from_source_it_runs_the_same_script_with_the_same_arguments(self):
        cmd = restart.relaunch_command(['main.py', '--review', 'r'], executable='py.exe',
                                       frozen=False)
        self.assertEqual(cmd, ['py.exe', os.path.abspath('main.py'), '--review', 'r'])

    def test_the_exe_runs_itself(self):
        cmd = restart.relaunch_command(['C:/x/NetSentinel.exe', '--port', '9000'],
                                       executable='C:/x/NetSentinel.exe', frozen=True)
        self.assertEqual(cmd, ['C:/x/NetSentinel.exe', '--port', '9000'])

    def test_monitoring_resumes_only_if_it_was_running(self):
        on = restart.relaunch_command(['m.py', '--monitor'], 'p', False, monitor=True)
        self.assertEqual(on.count('--monitor'), 1)
        off = restart.relaunch_command(['m.py', '--monitor'], 'p', False, monitor=False)
        self.assertNotIn('--monitor', off)

    def test_the_new_exe_unpacks_afresh(self):
        """Inheriting _MEIPASS2, it would run from this copy's folder, deleted as it exits."""
        env = restart.relaunch_environment({'_MEIPASS2': 'C:/Temp/_MEI1', 'PATH': 'p'})
        self.assertNotIn('_MEIPASS2', env)
        self.assertEqual(env['PYINSTALLER_RESET_ENVIRONMENT'], '1')
        self.assertEqual(env['PATH'], 'p')

    def test_the_command_line_takes_monitor(self):
        self.assertTrue(main.parse_args(['--monitor']).monitor)
        self.assertFalse(main.parse_args([]).monitor)


def fake_pystray():
    """Enough of pystray to build and drive the icon."""
    module = types.ModuleType('pystray')

    class MenuItem:
        def __init__(self, text, action, default=False):
            self.text, self.action, self.default = text, action, default

        def label(self):
            return self.text(self) if callable(self.text) else self.text

    class Menu:
        SEPARATOR = object()

        def __init__(self, *items):
            self.items = items

    class Icon:
        def __init__(self, name, image, title, menu):
            self.name, self.image, self.title, self.menu = name, image, title, menu
            self.notes, self.stopped, self.updates = [], False, 0
            self._done = threading.Event()

        def run(self):
            self._done.wait(5)

        def update_menu(self):
            self.updates += 1

        def notify(self, message, title):
            self.notes.append(message)

        def stop(self):
            self.stopped = True
            self._done.set()

    module.MenuItem, module.Menu, module.Icon = MenuItem, Menu, Icon
    return module


class TestTray(unittest.TestCase):

    def setUp(self):
        try:
            import PIL  # noqa: F401  the icon image is drawn with Pillow
        except ImportError:
            self.skipTest('Pillow is not installed')
        patcher = mock.patch.dict(sys.modules, {'pystray': fake_pystray()})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.posted = []
        self.monitoring = False
        self.tray = tray.Tray(self.posted.append, lambda: self.monitoring)
        self.assertTrue(self.tray.start())
        self.addCleanup(self.tray.stop)

    def items(self):
        return [i for i in self.tray._icon.menu.items if hasattr(i, 'label')]

    def test_the_menu_offers_what_the_window_does(self):
        labels = [i.label() for i in self.items()]
        self.assertEqual(labels, ['Open NetSentinel', 'Open dashboard', 'Start monitoring',
                                  'Restart', 'Quit'])
        self.assertTrue(self.items()[0].default, 'a click on the icon opens the window')
        self.monitoring = True
        self.assertEqual(self.items()[2].label(), 'Stop monitoring')

    def test_menu_actions_are_posted_not_run(self):
        """They arrive on the tray's thread, and tkinter must not be touched there."""
        for item in self.items():
            item.action(self.tray._icon, item)
        self.assertEqual(self.posted, ['show', 'dashboard', 'toggle', 'restart', 'quit'])

    def test_the_tooltip_follows_monitoring(self):
        self.tray.update(True)
        self.assertEqual(self.tray._icon.title, 'NetSentinel: monitoring')
        self.assertGreater(self.tray._icon.updates, 0)

    def test_it_uses_the_app_icon(self):
        self.assertTrue(os.path.exists(tray.icon_path()))


class _Root:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        return lambda *a, **k: self.calls.append(name)


class TestTheWindow(unittest.TestCase):

    def setUp(self):
        try:
            from src.gui import NetSentinelGUI
        except ImportError:
            self.skipTest('tkinter is not installed')
        import queue
        gui = self.gui = NetSentinelGUI.__new__(NetSentinelGUI)
        gui.root = _Root()
        gui.app = SimpleNamespace(stop_monitoring=mock.Mock(), is_monitoring=True,
                                  web_server=mock.Mock())
        gui._tray_actions = queue.Queue()
        gui._tray = mock.Mock()
        gui._told_about_tray = False
        gui._statusbar_text = mock.Mock()

    def test_closing_hides_to_the_tray_and_keeps_monitoring(self):
        """Closing used to stop monitoring and exit."""
        self.gui._on_close()
        self.gui._on_close()
        self.assertEqual(self.gui.root.calls, ['withdraw', 'withdraw'])
        self.gui.app.stop_monitoring.assert_not_called()
        self.gui._tray.notify.assert_called_once()       # said once, not every time

    def test_without_a_tray_closing_quits(self):
        self.gui._tray = None
        self.gui._on_close()
        self.gui.app.stop_monitoring.assert_called_once()
        self.assertIn('destroy', self.gui.root.calls)

    def test_quit_from_the_tray_saves_and_exits(self):
        tray_icon = self.gui._tray
        self.gui._tray_actions.put('quit')
        self.gui._poll_tray()
        tray_icon.stop.assert_called_once()
        self.gui.app.stop_monitoring.assert_called_once()
        self.gui.app.web_server.stop.assert_called_once()
        self.assertIn('destroy', self.gui.root.calls)

    def test_show_brings_the_window_back(self):
        self.gui._tray_actions.put('show')
        self.gui._poll_tray()
        self.assertEqual(self.gui.root.calls[:3], ['deiconify', 'lift', 'focus_force'])

    def test_restart_starts_the_new_copy_before_this_one_stops(self):
        order = []
        self.gui.app.stop_monitoring.side_effect = lambda: order.append('stop')
        with mock.patch('src.restart.relaunch',
                        side_effect=lambda monitor: order.append(('relaunch', monitor))):
            self.gui._restart()
        self.assertEqual(order, [('relaunch', True), 'stop'])
        self.assertIn('destroy', self.gui.root.calls)

    def test_a_restart_that_cannot_start_keeps_this_copy(self):
        with mock.patch('src.restart.relaunch', side_effect=OSError('no')), \
                mock.patch('src.gui.messagebox') as box:
            self.gui._restart()
        box.showerror.assert_called_once()
        self.gui.app.stop_monitoring.assert_not_called()
        self.assertNotIn('destroy', self.gui.root.calls)


if __name__ == '__main__':
    unittest.main(verbosity=2)
