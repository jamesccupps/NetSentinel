#!/usr/bin/env python3
"""
NetSentinel - Network Monitoring & Intrusion Detection System
=============================================================
A lightweight, AI-powered network security monitor for Windows.
Monitors all traffic, detects anomalies, and alerts on suspicious activity.
"""

import sys
import os
import ctypes
import logging
from datetime import datetime

# Fix blurry rendering on high-DPI Windows displays
if sys.platform == 'win32':
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

# Setup logging
LOG_DIR = os.path.join(os.path.expanduser("~"), ".netsentinel", "logs")
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, f"netsentinel_{datetime.now():%Y%m%d}.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NetSentinel")

APP_VERSION = "1.4.0"
APP_DIR = os.path.dirname(os.path.abspath(__file__))


def get_asset_path(filename):
    """Get path to an asset file, works for both dev and PyInstaller."""
    if getattr(sys, '_MEIPASS', None):
        return os.path.join(sys._MEIPASS, 'assets', filename)
    return os.path.join(APP_DIR, 'assets', filename)


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False


def request_admin():
    if sys.platform == 'win32':
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)


def show_splash():
    """Show a splash screen while the app loads. Returns the Tk root for reuse."""
    import tkinter as tk

    root = tk.Tk()
    root.withdraw()  # Hide the main window initially

    splash = tk.Toplevel(root)
    splash.overrideredirect(True)

    w, h = 520, 340
    sw = splash.winfo_screenwidth()
    sh = splash.winfo_screenheight()
    x = (sw - w) // 2
    y = (sh - h) // 2
    splash.geometry(f'{w}x{h}+{x}+{y}')
    splash.configure(bg='#0a0e1a')
    splash.attributes('-topmost', True)

    try:
        ico = get_asset_path('netsentinel.ico')
        if os.path.exists(ico):
            splash.iconbitmap(ico)
    except Exception:
        pass

    canvas = tk.Canvas(splash, width=w, height=h, bg='#0a0e1a',
                       highlightthickness=0)
    canvas.pack()

    # Border
    canvas.create_rectangle(1, 1, w-1, h-1, outline='#00b4ff', width=2)
    canvas.create_rectangle(4, 4, w-4, h-4, outline='#003366', width=1)

    # Shield
    cx, cy = w // 2, 95
    sz = 50
    shield = [
        (cx, cy - sz), (cx + sz*0.8, cy - sz*0.55),
        (cx + sz*0.7, cy + sz*0.35), (cx, cy + sz*0.85),
        (cx - sz*0.7, cy + sz*0.35), (cx - sz*0.8, cy - sz*0.55),
    ]
    canvas.create_polygon(shield, fill='#0c1220', outline='#00b4ff', width=2)

    for r in [12, 20, 28]:
        canvas.create_arc(cx-r, cy-r+5, cx+r, cy+r+5,
                         start=200, extent=140, style='arc',
                         outline='#0088cc', width=1)
    canvas.create_oval(cx-5, cy, cx+5, cy+10, fill='#00e5ff', outline='white', width=1)
    for nx, ny in [(cx-18, cy-15), (cx+18, cy-12), (cx-12, cy+18),
                   (cx+12, cy+18), (cx, cy-22)]:
        canvas.create_line(cx, cy+5, nx, ny, fill='#005588', width=1)
        canvas.create_oval(nx-3, ny-3, nx+3, ny+3, fill='#00ccff', outline='')

    # Text
    canvas.create_text(w//2, 165, text="NETSENTINEL",
                      font=('Consolas', 28, 'bold'), fill='#00ccff')
    canvas.create_text(w//2, 195, text="Network Monitor & Intrusion Detection",
                      font=('Segoe UI', 11), fill='#6688aa')
    canvas.create_text(w//2, 225, text=f"Version {APP_VERSION}",
                      font=('Consolas', 9), fill='#334466')

    # Progress bar
    bar_y, bar_w, bar_h = 270, 300, 6
    bar_x = (w - bar_w) // 2
    canvas.create_rectangle(bar_x, bar_y, bar_x + bar_w, bar_y + bar_h,
                           fill='#1a2030', outline='#223344')
    status_text = canvas.create_text(w//2, bar_y + 22, text="Initializing...",
                                     font=('Consolas', 8), fill='#446688')
    progress_bar = canvas.create_rectangle(bar_x, bar_y, bar_x, bar_y + bar_h,
                                           fill='#00b4ff', outline='')
    canvas.create_text(w//2, h - 20, text="AI-Powered Network Security",
                      font=('Segoe UI', 8), fill='#334455')

    def update_progress(pct, text=""):
        fill_w = int(bar_w * pct / 100)
        canvas.coords(progress_bar, bar_x, bar_y, bar_x + fill_w, bar_y + bar_h)
        if text:
            canvas.itemconfig(status_text, text=text)
        splash.update()

    splash.update()
    return root, splash, update_progress


def main():
    logger.info("=" * 60)
    logger.info("NetSentinel %s Starting...", APP_VERSION)
    logger.info("=" * 60)

    if not is_admin():
        if sys.platform == 'win32':
            try:
                request_admin()
            except Exception:
                logger.warning("Could not elevate. Running in limited mode.")

    # Splash screen
    splash = None
    tk_root = None
    update_progress = None
    try:
        tk_root, splash, update_progress = show_splash()
    except Exception as e:
        logger.debug("Splash screen error: %s", e)

    # ─── Run heavy initialization in a background thread ─────────
    # Scapy's import alone takes 30-120+ seconds on Windows with
    # multiple network interfaces + Npcap. Running it on the main
    # thread freezes the splash screen (tkinter needs the main thread
    # for event processing). This approach keeps the splash animated.
    import threading
    import time

    init_result = {'app': None, 'error': None, 'status': 'Loading...'}

    def _background_init():
        """Heavy initialization in background thread."""
        try:
            init_result['status'] = 'Importing Scapy (network driver)...'
            logger.info("Importing core modules (Scapy may take a while)...")
            from src.app import NetSentinelApp

            init_result['status'] = 'Configuring NetSentinel...'
            app = NetSentinelApp()
            init_result['app'] = app
            init_result['status'] = 'Ready!'
        except Exception as e:
            init_result['error'] = e
            logger.error("Failed to initialize: %s", e)

    init_thread = threading.Thread(target=_background_init, daemon=True,
                                    name="InitThread")
    init_thread.start()

    # Keep splash responsive while init runs in background
    # Poll every 100ms — tkinter update() pumps the event loop
    progress_pct = 5
    last_status = ''
    while init_thread.is_alive():
        try:
            # Animate progress bar (creep toward 95% but never reach it)
            if progress_pct < 92:
                progress_pct += 0.5
            status = init_result['status']
            if status != last_status:
                last_status = status
                logger.info("Init: %s", status)
            if update_progress:
                update_progress(int(progress_pct), status)
            if splash:
                splash.update()
            time.sleep(0.1)
        except Exception:
            break  # Splash was closed

    # Check result
    if init_result['error']:
        if splash:
            splash.destroy()
        raise init_result['error']

    app = init_result['app']
    if app is None:
        if splash:
            splash.destroy()
        logger.error("Init thread completed but app is None")
        return

    try:
        if update_progress:
            update_progress(100, "Ready!")
        if splash:
            splash.update()
            time.sleep(0.3)
    except Exception:
        pass

    if splash:
        splash.destroy()

    app.run(tk_root=tk_root)


if __name__ == "__main__":
    main()
