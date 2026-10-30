"""
The system tray icon, so NetSentinel keeps running with its window closed.
==========================================================================
Closing the window used to stop monitoring and exit. With the tray, closing
hides the window and monitoring carries on; the icon's menu opens it again,
opens the dashboard, starts or stops monitoring, restarts, or quits.

pystray runs its own message loop on a thread of its own. Its menu callbacks
arrive on that thread, and tkinter must only be touched from the thread that
created it, so every action is handed to `post` (the window puts it on a queue
it drains) rather than run here.
"""

import logging
import os
import sys
import threading

logger = logging.getLogger("NetSentinel.Tray")

ACTIONS = ('show', 'dashboard', 'toggle', 'restart', 'quit')


def icon_path():
    """assets/netsentinel.ico, from a source tree or a PyInstaller bundle."""
    base = getattr(sys, '_MEIPASS', None) or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, 'assets', 'netsentinel.ico')


def available():
    try:
        import pystray  # noqa: F401
        from PIL import Image  # noqa: F401
    except Exception:          # missing, or no tray on this desktop
        return False
    return True


class Tray:
    """One icon. `post(action)` receives one of ACTIONS, on the tray's thread."""

    def __init__(self, post, is_monitoring):
        self._post = post
        self._is_monitoring = is_monitoring
        self._icon = None
        self._thread = None

    def _image(self):
        from PIL import Image, ImageDraw
        try:
            with Image.open(icon_path()) as image:
                image.load()
                return image.copy()
        except OSError:
            # A plain shield, so a missing asset does not cost the icon.
            image = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
            ImageDraw.Draw(image).polygon(
                [(32, 4), (8, 14), (8, 32), (32, 60), (56, 32), (56, 14)],
                fill=(88, 166, 255, 255))
            return image

    def _menu(self, pystray):
        def do(action):
            return lambda icon, item: self._post(action)

        def toggle_text(item):
            return 'Stop monitoring' if self._is_monitoring() else 'Start monitoring'

        return pystray.Menu(
            pystray.MenuItem('Open NetSentinel', do('show'), default=True),
            pystray.MenuItem('Open dashboard', do('dashboard')),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(toggle_text, do('toggle')),
            pystray.MenuItem('Restart', do('restart')),
            pystray.MenuItem('Quit', do('quit')),
        )

    def start(self):
        """Show the icon. Returns False if this desktop cannot have one."""
        try:
            import pystray
            self._icon = pystray.Icon('NetSentinel', self._image(), 'NetSentinel',
                                      self._menu(pystray))
        except Exception as e:
            logger.warning("No tray icon: %s", e)
            self._icon = None
            return False
        self._thread = threading.Thread(target=self._run, daemon=True, name="Tray")
        self._thread.start()
        return True

    def _run(self):
        try:
            self._icon.run()
        except Exception as e:
            logger.warning("The tray icon stopped: %s", e)

    def update(self, monitoring):
        """Reflect the monitoring state in the tooltip and the menu."""
        if self._icon is None:
            return
        try:
            self._icon.title = 'NetSentinel: monitoring' if monitoring else 'NetSentinel: stopped'
            self._icon.update_menu()
        except Exception as e:
            logger.debug("Tray update failed: %s", e)

    def notify(self, message):
        if self._icon is None:
            return
        try:
            self._icon.notify(message, 'NetSentinel')
        except Exception as e:      # notifications are a nicety
            logger.debug("Tray notification failed: %s", e)

    def stop(self):
        if self._icon is None:
            return
        try:
            self._icon.stop()
        except Exception as e:
            logger.debug("Tray stop failed: %s", e)
        self._icon = None
