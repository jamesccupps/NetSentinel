"""
NetSentinel GUI Dashboard
=========================
Real-time network monitoring dashboard with traffic charts,
alert feed, flow table, ML status, and settings.
Built with tkinter + ttk for zero extra dependencies.
"""

import os
import sys
import time
import math
import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from collections import deque
from datetime import datetime

logger = logging.getLogger("NetSentinel.GUI")

# ─── Color Palette ─────────────────────────────────────────────────────────────
COLORS = {
    'bg_dark':      '#0d1117',
    'bg_panel':     '#161b22',
    'bg_card':      '#1c2333',
    'bg_input':     '#21262d',
    'border':       '#30363d',
    'text':         '#e6edf3',
    'text_dim':     '#8b949e',
    'accent':       '#58a6ff',
    'accent_hover': '#79c0ff',
    'green':        '#3fb950',
    'green_dim':    '#238636',
    'yellow':       '#d29922',
    'orange':       '#db6d28',
    'red':          '#f85149',
    'red_dim':      '#da3633',
    'purple':       '#bc8cff',
    'cyan':         '#39d2c0',
}

SEVERITY_COLORS = {
    'LOW':      COLORS['cyan'],
    'MEDIUM':   COLORS['yellow'],
    'HIGH':     COLORS['orange'],
    'CRITICAL': COLORS['red'],
}


class StyledFrame(tk.Frame):
    """A dark-themed frame."""
    def __init__(self, parent, **kwargs):
        kwargs.setdefault('bg', COLORS['bg_dark'])
        super().__init__(parent, **kwargs)


class Card(tk.Frame):
    """A card-style container with border."""
    def __init__(self, parent, title="", **kwargs):
        kwargs.setdefault('bg', COLORS['bg_card'])
        kwargs.setdefault('highlightbackground', COLORS['border'])
        kwargs.setdefault('highlightthickness', 1)
        kwargs.setdefault('padx', 12)
        kwargs.setdefault('pady', 8)
        super().__init__(parent, **kwargs)

        if title:
            lbl = tk.Label(self, text=title, font=('Segoe UI', 10, 'bold'),
                          fg=COLORS['text_dim'], bg=COLORS['bg_card'], anchor='w')
            lbl.pack(fill='x', pady=(0, 6))


class MetricWidget(tk.Frame):
    """Displays a single metric with label and value."""
    def __init__(self, parent, label, value="0", color=None, **kwargs):
        kwargs.setdefault('bg', COLORS['bg_card'])
        super().__init__(parent, **kwargs)

        self._label = tk.Label(self, text=label, font=('Segoe UI', 8),
                               fg=COLORS['text_dim'], bg=COLORS['bg_card'])
        self._label.pack(anchor='w')

        self._value = tk.Label(self, text=value,
                               font=('Segoe UI Semibold', 18),
                               fg=color or COLORS['accent'],
                               bg=COLORS['bg_card'])
        self._value.pack(anchor='w')

    def set_value(self, value, color=None):
        self._value.config(text=value)
        if color:
            self._value.config(fg=color)


class MiniChart(tk.Canvas):
    """A simple real-time line/bar chart using Canvas."""
    def __init__(self, parent, width=300, height=80, max_points=60, **kwargs):
        kwargs.setdefault('bg', COLORS['bg_card'])
        kwargs.setdefault('highlightthickness', 0)
        super().__init__(parent, width=width, height=height, **kwargs)
        self.max_points = max_points
        self.data = deque(maxlen=max_points)
        self.chart_width = width
        self.chart_height = height

    def add_point(self, value):
        self.data.append(value)
        self._redraw()

    def _redraw(self):
        self.delete('all')
        if len(self.data) < 2:
            return

        data = list(self.data)
        max_val = max(data) if max(data) > 0 else 1
        w = self.chart_width
        h = self.chart_height
        pad = 4

        # Draw grid lines
        for i in range(4):
            y = pad + (h - 2*pad) * i / 3
            self.create_line(0, y, w, y, fill=COLORS['border'], dash=(2, 4))

        # Draw filled area + line
        points = []
        for i, val in enumerate(data):
            x = pad + (w - 2*pad) * i / (self.max_points - 1)
            y = h - pad - (h - 2*pad) * (val / max_val)
            points.append((x, y))

        if len(points) >= 2:
            # Filled area
            fill_points = [(points[0][0], h - pad)]
            fill_points.extend(points)
            fill_points.append((points[-1][0], h - pad))
            flat = [coord for p in fill_points for coord in p]
            self.create_polygon(flat, fill='#1a3a5c', outline='')

            # Line
            flat_line = [coord for p in points for coord in p]
            self.create_line(flat_line, fill=COLORS['accent'], width=2, smooth=True)

            # Current value text
            self.create_text(
                w - pad, pad + 4,
                text=self._format_value(data[-1]),
                fill=COLORS['accent'], font=('Segoe UI', 8, 'bold'),
                anchor='ne'
            )

    @staticmethod
    def _format_value(val):
        if val >= 1_000_000:
            return f"{val/1_000_000:.1f}M"
        if val >= 1_000:
            return f"{val/1_000:.1f}K"
        return f"{val:.0f}"


class AlertDetailWindow:
    """Popup window showing full alert details with domain resolution and structured analysis."""

    def __init__(self, parent, alert_dict):
        self.win = tk.Toplevel(parent)
        self.win.title(f"Alert Detail — {alert_dict.get('title', '')}")
        self.win.geometry("750x700")
        self.win.configure(bg=COLORS['bg_dark'])
        self.win.transient(parent)
        self.win.grab_set()

        sev = alert_dict.get('severity', 'LOW')
        color = SEVERITY_COLORS.get(sev, COLORS['text_dim'])
        evidence = alert_dict.get('evidence') or {}

        # ─── Header ────────────────────────────────────────────
        header = tk.Frame(self.win, bg=COLORS['bg_panel'], pady=12, padx=16)
        header.pack(fill='x')

        sev_badge = tk.Label(header, text=f" {sev} ", font=('Consolas', 10, 'bold'),
                             fg=COLORS['bg_dark'], bg=color, padx=8, pady=2)
        sev_badge.pack(side='left')

        title_lbl = tk.Label(header, text=alert_dict.get('title', ''),
                             font=('Segoe UI', 13, 'bold'),
                             fg=COLORS['text'], bg=COLORS['bg_panel'])
        title_lbl.pack(side='left', padx=(12, 0))

        time_lbl = tk.Label(header, text=alert_dict.get('time_str', ''),
                            font=('Consolas', 9), fg=COLORS['text_dim'],
                            bg=COLORS['bg_panel'])
        time_lbl.pack(side='right')

        # ─── Description ────────────────────────────────────────
        desc_frame = tk.Frame(self.win, bg=COLORS['bg_dark'], padx=16, pady=8)
        desc_frame.pack(fill='x')
        tk.Label(desc_frame, text=alert_dict.get('description', ''),
                font=('Segoe UI', 10), fg=COLORS['text'], bg=COLORS['bg_dark'],
                wraplength=700, justify='left', anchor='w').pack(fill='x')

        # ─── Main scrollable content ────────────────────────────
        content_frame = tk.Frame(self.win, bg=COLORS['bg_dark'])
        content_frame.pack(fill='both', expand=True, padx=12, pady=4)

        canvas = tk.Canvas(content_frame, bg=COLORS['bg_dark'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(content_frame, orient='vertical', command=canvas.yview)
        scroll_inner = tk.Frame(canvas, bg=COLORS['bg_dark'])
        scroll_inner.bind('<Configure>',
            lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.create_window((0, 0), window=scroll_inner, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        def _mousewheel(event):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _mousewheel, add='+')

        # ─── CONNECTION section (with domain resolution) ──────
        conn_card = Card(scroll_inner, title="CONNECTION")
        conn_card.pack(fill='x', pady=(0, 6))

        src_ip = alert_dict.get('src_ip', '')
        dst_ip = alert_dict.get('dst_ip', '')
        src_port = alert_dict.get('src_port', '')
        dst_port = alert_dict.get('dst_port', '')

        # Resolve domains from evidence
        dst_domains = evidence.get('destination_domains', [])
        src_domains = evidence.get('source_domains', [])
        host = evidence.get('extra', {}).get('host', '') or evidence.get('host', '')

        conn_fields = []
        src_str = f"{src_ip}:{src_port}" if src_ip else '—'
        if src_domains:
            src_str += f"  ({', '.join(str(d) for d in src_domains[:2])})"
        conn_fields.append(('Source', src_str))

        dst_str = f"{dst_ip}:{dst_port}" if dst_ip else '—'
        if dst_domains and dst_domains != ['No domain — direct IP']:
            dst_str += f"  ({', '.join(str(d) for d in dst_domains[:2])})"
        elif host:
            dst_str += f"  ({host})"
        conn_fields.append(('Destination', dst_str))

        conn_fields.append(('Protocol', alert_dict.get('protocol', '') or evidence.get('protocol', '—')))
        conn_fields.append(('Rule ID', alert_dict.get('rule_id', '—')))
        conn_fields.append(('Category', alert_dict.get('category', '—')))

        for label, value in conn_fields:
            row = tk.Frame(conn_card, bg=COLORS['bg_card'])
            row.pack(fill='x', pady=1)
            tk.Label(row, text=f"{label}:", font=('Segoe UI', 9, 'bold'),
                    fg=COLORS['text_dim'], bg=COLORS['bg_card'],
                    width=16, anchor='w').pack(side='left')
            tk.Label(row, text=str(value), font=('Consolas', 9),
                    fg=COLORS['text'], bg=COLORS['bg_card'],
                    anchor='w', wraplength=550).pack(side='left', padx=(4, 0))

        # ─── VERIFICATION VERDICT (prominent) ────────────────
        av = evidence.get('alert_verification', {})
        if av:
            verdict = av.get('verdict', 'UNKNOWN')
            confidence = av.get('confidence', '?')
            summary = av.get('auto_assessment', '')
            reasoning = av.get('reasoning', [])

            verdict_colors = {
                'FALSE_POSITIVE': COLORS['green'],
                'LIKELY_FALSE_POSITIVE': '#66aa66',
                'INCONCLUSIVE': COLORS['yellow'],
                'LIKELY_THREAT': COLORS['orange'],
                'VERIFIED_THREAT': COLORS['red'],
            }
            v_color = verdict_colors.get(verdict, COLORS['text_dim'])

            v_card = Card(scroll_inner, title="VERDICT")
            v_card.pack(fill='x', pady=(0, 6))

            v_header = tk.Frame(v_card, bg=COLORS['bg_card'])
            v_header.pack(fill='x')
            tk.Label(v_header, text=f" {verdict} ", font=('Consolas', 11, 'bold'),
                    fg=COLORS['bg_dark'], bg=v_color, padx=8, pady=2).pack(side='left')
            tk.Label(v_header, text=f"  Confidence: {confidence}",
                    font=('Consolas', 9), fg=COLORS['text_dim'],
                    bg=COLORS['bg_card']).pack(side='left', padx=8)

            if summary:
                tk.Label(v_card, text=summary, font=('Segoe UI', 9),
                        fg=COLORS['text'], bg=COLORS['bg_card'],
                        wraplength=650, justify='left', anchor='w').pack(fill='x', pady=(4, 2))

            if reasoning:
                for reason in reasoning:
                    tk.Label(v_card, text=f"  • {reason}", font=('Segoe UI', 9),
                            fg=COLORS['text_dim'], bg=COLORS['bg_card'],
                            wraplength=620, justify='left', anchor='w').pack(fill='x')

        # ─── Structured evidence sections ─────────────────────
        # Group evidence into logical sections
        shown_keys = {'alert_verification', 'destination_domains', 'source_domains',
                      'connection', 'protocol', 'flags', 'packet_size', 'payload_size',
                      'encrypted', 'process', 'dns_query'}

        # Section: What was detected
        detect_keys = {'service', 'server', 'port', 'user_agent', 'matched_signature',
                       'method', 'url', 'attack_type', 'full_request',
                       'credential_type', 'value', 'data_type',
                       'packets_observed', 'bytes_transferred', 'clients',
                       'has_https', 'domain_entropy', 'total_dga_domains',
                       'sample_domains', 'latest_domain'}
        detect_items = [(k, v) for k, v in evidence.items()
                        if k in detect_keys and k not in shown_keys]
        if detect_items:
            det_card = Card(scroll_inner, title="WHAT WAS DETECTED")
            det_card.pack(fill='x', pady=(0, 6))
            self._render_evidence(det_card, detect_items)
            shown_keys.update(k for k, _ in detect_items)

        # Section: How this is exploited
        exploit_keys = {'how_this_is_exploited', 'how_exploited'}
        for ek in exploit_keys:
            if ek in evidence:
                exp_card = Card(scroll_inner, title="HOW THIS IS EXPLOITED")
                exp_card.pack(fill='x', pady=(0, 6))
                tk.Label(exp_card, text=str(evidence[ek]),
                        font=('Segoe UI', 9), fg=COLORS['text'],
                        bg=COLORS['bg_card'], wraplength=670,
                        justify='left', anchor='w', padx=4, pady=4).pack(fill='x')
                shown_keys.add(ek)
                break

        # Section: How to fix
        fix_keys = {'how_to_fix', 'recommendation'}
        for fk in fix_keys:
            if fk in evidence:
                fix_card = Card(scroll_inner, title="HOW TO FIX")
                fix_card.pack(fill='x', pady=(0, 6))
                fix_text = str(evidence[fk])
                tk.Label(fix_card, text=fix_text,
                        font=('Segoe UI', 9), fg=COLORS['green'],
                        bg=COLORS['bg_card'], wraplength=670,
                        justify='left', anchor='w', padx=4, pady=4).pack(fill='x')
                shown_keys.add(fk)

        # Section: Is this malicious?
        if 'is_this_malicious' in evidence:
            mal_card = Card(scroll_inner, title="IS THIS MALICIOUS?")
            mal_card.pack(fill='x', pady=(0, 6))
            tk.Label(mal_card, text=str(evidence['is_this_malicious']),
                    font=('Segoe UI', 9), fg=COLORS['yellow'],
                    bg=COLORS['bg_card'], wraplength=670,
                    justify='left', anchor='w', padx=4, pady=4).pack(fill='x')
            shown_keys.add('is_this_malicious')

        # Section: Description (if not already shown)
        if 'description' in evidence and 'description' not in shown_keys:
            desc_card = Card(scroll_inner, title="DETAILS")
            desc_card.pack(fill='x', pady=(0, 6))
            tk.Label(desc_card, text=str(evidence['description']),
                    font=('Segoe UI', 9), fg=COLORS['text_dim'],
                    bg=COLORS['bg_card'], wraplength=670,
                    justify='left', anchor='w', padx=4, pady=4).pack(fill='x')
            shown_keys.add('description')

        # Section: Extra context fields
        extra = evidence.get('extra', {})
        if extra and isinstance(extra, dict):
            for k, v in extra.items():
                if v:
                    shown_keys.add(f'extra.{k}')

        # Section: Remaining evidence (anything not in a section above)
        remaining = [(k, v) for k, v in evidence.items()
                     if k not in shown_keys and v]
        if remaining:
            rem_card = Card(scroll_inner, title="ADDITIONAL EVIDENCE")
            rem_card.pack(fill='x', pady=(0, 6))
            self._render_evidence(rem_card, remaining)

        # ─── Close Button ────────────────────────────────────────
        close_btn = tk.Button(self.win, text="Close", font=('Segoe UI', 9),
                             bg=COLORS['bg_input'], fg=COLORS['text'],
                             relief='flat', padx=16, pady=4, cursor='hand2',
                             command=self.win.destroy)
        close_btn.pack(pady=8)

    def _render_evidence(self, parent, items):
        """Render a list of (key, value) evidence pairs."""
        for key, value in items:
            display_key = key.replace('_', ' ').title()
            row = tk.Frame(parent, bg=COLORS['bg_card'])
            row.pack(fill='x', pady=1, padx=4)

            tk.Label(row, text=f"{display_key}:", font=('Segoe UI', 9, 'bold'),
                    fg=COLORS['accent'], bg=COLORS['bg_card'],
                    anchor='nw', width=20).pack(side='left', anchor='n')

            if isinstance(value, list):
                list_frame = tk.Frame(row, bg=COLORS['bg_card'])
                list_frame.pack(side='left', fill='x', expand=True)
                for item in value[:10]:
                    tk.Label(list_frame, text=f"• {item}", font=('Consolas', 9),
                            fg=COLORS['cyan'], bg=COLORS['bg_card'],
                            anchor='w', wraplength=500).pack(fill='x')
                if len(value) > 10:
                    tk.Label(list_frame, text=f"  ... and {len(value)-10} more",
                            font=('Consolas', 8), fg=COLORS['text_dim'],
                            bg=COLORS['bg_card']).pack(fill='x')
            elif isinstance(value, dict):
                dict_frame = tk.Frame(row, bg=COLORS['bg_card'])
                dict_frame.pack(side='left', fill='x', expand=True)
                for k, v in value.items():
                    if v:
                        tk.Label(dict_frame, text=f"{k}: {v}", font=('Consolas', 9),
                                fg=COLORS['text'], bg=COLORS['bg_card'],
                                anchor='w', wraplength=500).pack(fill='x')
            else:
                tk.Label(row, text=str(value), font=('Consolas', 9),
                        fg=COLORS['text'], bg=COLORS['bg_card'],
                        anchor='w', wraplength=500).pack(side='left', padx=(4, 0))


class AlertListItem(tk.Frame):
    """Single alert row in the alerts panel. Click to expand details."""
    def __init__(self, parent, alert_dict, **kwargs):
        kwargs.setdefault('bg', COLORS['bg_panel'])
        kwargs.setdefault('cursor', 'hand2')
        super().__init__(parent, **kwargs)

        self._alert_dict = alert_dict
        sev = alert_dict.get('severity', 'LOW')
        color = SEVERITY_COLORS.get(sev, COLORS['text_dim'])

        # Severity indicator bar
        bar = tk.Frame(self, bg=color, width=4)
        bar.pack(side='left', fill='y', padx=(0, 8))

        # Content
        content = tk.Frame(self, bg=COLORS['bg_panel'])
        content.pack(side='left', fill='both', expand=True)

        # Title row
        title_frame = tk.Frame(content, bg=COLORS['bg_panel'])
        title_frame.pack(fill='x')

        sev_lbl = tk.Label(title_frame, text=f"[{sev}]",
                           font=('Consolas', 8, 'bold'), fg=color,
                           bg=COLORS['bg_panel'])
        sev_lbl.pack(side='left')

        title_lbl = tk.Label(title_frame, text=alert_dict.get('title', ''),
                             font=('Segoe UI', 9, 'bold'),
                             fg=COLORS['text'], bg=COLORS['bg_panel'])
        title_lbl.pack(side='left', padx=(6, 0))

        time_str = alert_dict.get('time_str', '')
        time_lbl = tk.Label(title_frame, text=time_str,
                            font=('Segoe UI', 8), fg=COLORS['text_dim'],
                            bg=COLORS['bg_panel'])
        time_lbl.pack(side='right')

        # Click indicator
        expand_lbl = tk.Label(title_frame, text="▶ click for details",
                              font=('Segoe UI', 7), fg=COLORS['text_dim'],
                              bg=COLORS['bg_panel'])
        expand_lbl.pack(side='right', padx=(0, 8))

        # Description
        desc = alert_dict.get('description', '')
        if len(desc) > 120:
            desc = desc[:117] + "..."
        desc_lbl = tk.Label(content, text=desc, font=('Segoe UI', 8),
                            fg=COLORS['text_dim'], bg=COLORS['bg_panel'],
                            anchor='w', wraplength=500, justify='left')
        desc_lbl.pack(fill='x', pady=(2, 0))

        # Source/Dest
        src = alert_dict.get('src_ip', '')
        dst = alert_dict.get('dst_ip', '')
        if src or dst:
            addr_lbl = tk.Label(content,
                                text=f"{src}:{alert_dict.get('src_port','')} → "
                                     f"{dst}:{alert_dict.get('dst_port','')}",
                                font=('Consolas', 8), fg=COLORS['text_dim'],
                                bg=COLORS['bg_panel'], anchor='w')
            addr_lbl.pack(fill='x')

        # Evidence preview (first key-value if available)
        evidence = alert_dict.get('evidence') or {}
        if evidence:
            preview_parts = []
            for k, v in evidence.items():
                if k in ('recommendation', 'description'):
                    continue
                if isinstance(v, list):
                    preview_parts.append(f"{k}: [{len(v)} items]")
                else:
                    preview_parts.append(f"{k}: {v}")
                if len(preview_parts) >= 3:
                    break
            if preview_parts:
                preview_text = "  |  ".join(preview_parts)
                if len(preview_text) > 100:
                    preview_text = preview_text[:97] + "..."
                preview_lbl = tk.Label(content, text=f"📋 {preview_text}",
                                       font=('Consolas', 7),
                                       fg=COLORS['accent'], bg=COLORS['bg_panel'],
                                       anchor='w')
                preview_lbl.pack(fill='x')

        # Separator
        sep = tk.Frame(self, bg=COLORS['border'], height=1)
        sep.pack(fill='x', side='bottom')

        # Bind click to ALL child widgets
        self._bind_click_recursive(self)

    def _bind_click_recursive(self, widget):
        """Bind click handler to widget and all its children."""
        widget.bind('<Button-1>', self._on_click)
        for child in widget.winfo_children():
            self._bind_click_recursive(child)

    def _on_click(self, event=None):
        """Open the detail popup."""
        AlertDetailWindow(self.winfo_toplevel(), self._alert_dict)


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN GUI
# ═══════════════════════════════════════════════════════════════════════════════

class NetSentinelGUI:
    """Main application GUI."""

    def __init__(self, app, tk_root=None):
        self.app = app
        if tk_root:
            self.root = tk_root
            self.root.deiconify()  # Show if hidden from splash
        else:
            self.root = tk.Tk()
        self.root.title("NetSentinel — Network Monitor & IDS")

        # Fix DPI scaling for crisp rendering on high-DPI displays
        try:
            import ctypes
            # Tell Windows this app handles DPI itself
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            pass

        try:
            # Get actual DPI and set tkinter scaling accordingly
            dpi = self.root.winfo_fpixels('1i')
            scale_factor = dpi / 72.0
            self.root.tk.call('tk', 'scaling', scale_factor)
        except Exception:
            pass

        self.root.geometry("1280x820")
        self.root.minsize(1000, 650)
        self.root.configure(bg=COLORS['bg_dark'])

        # Try to set icon
        try:
            import sys as _sys
            _app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if getattr(_sys, '_MEIPASS', None):
                _app_dir = _sys._MEIPASS
            ico_path = os.path.join(_app_dir, 'assets', 'netsentinel.ico')
            if os.path.exists(ico_path):
                self.root.iconbitmap(ico_path)
        except Exception:
            pass

        # State
        self._monitoring = False
        self._alert_widgets = []
        self._packet_log_lines = deque(maxlen=200)

        # Build UI
        self._build_ui()

        # Register alert listener
        self.app.alert_manager.register_listener(self._on_new_alert)

        # Start update loop
        self._schedule_update()

    def _build_ui(self):
        """Construct the entire UI layout."""
        # ─── Top Bar ────────────────────────────────────────────────
        top_bar = tk.Frame(self.root, bg=COLORS['bg_panel'], height=56)
        top_bar.pack(fill='x', side='top')
        top_bar.pack_propagate(False)

        # Logo / Title
        logo_frame = tk.Frame(top_bar, bg=COLORS['bg_panel'])
        logo_frame.pack(side='left', padx=16)

        # Try to load icon image, fall back to text
        self._logo_img = None
        try:
            from PIL import Image, ImageTk
            import sys as _sys
            _app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if getattr(_sys, '_MEIPASS', None):
                _app_dir = _sys._MEIPASS
            icon_path = os.path.join(_app_dir, 'assets', 'icon_32.png')
            if os.path.exists(icon_path):
                img = Image.open(icon_path).resize((28, 28), Image.LANCZOS)
                self._logo_img = ImageTk.PhotoImage(img)
                tk.Label(logo_frame, image=self._logo_img,
                        bg=COLORS['bg_panel']).pack(side='left', padx=(0, 4))
            else:
                raise FileNotFoundError
        except Exception:
            tk.Label(logo_frame, text="🛡", font=('Segoe UI', 18),
                    fg=COLORS['accent'], bg=COLORS['bg_panel']).pack(side='left')

        tk.Label(logo_frame, text=" NETSENTINEL",
                font=('Segoe UI Semibold', 14),
                fg=COLORS['text'], bg=COLORS['bg_panel']).pack(side='left')
        tk.Label(logo_frame, text="  v1.0",
                font=('Consolas', 8),
                fg=COLORS['text_dim'], bg=COLORS['bg_panel']).pack(side='left', padx=(4,0))

        # Controls
        ctrl_frame = tk.Frame(top_bar, bg=COLORS['bg_panel'])
        ctrl_frame.pack(side='right', padx=16)

        # About button
        tk.Button(ctrl_frame, text="ℹ  About", font=('Segoe UI', 8),
                  bg=COLORS['bg_input'], fg=COLORS['text_dim'],
                  relief='flat', cursor='hand2', padx=8,
                  command=self._show_about
        ).pack(side='left', padx=(0, 12))

        self._status_dot = tk.Label(ctrl_frame, text="●", font=('Segoe UI', 12),
                                     fg=COLORS['text_dim'], bg=COLORS['bg_panel'])
        self._status_dot.pack(side='left', padx=(0, 4))

        self._status_label = tk.Label(ctrl_frame, text="STOPPED",
                                       font=('Consolas', 9, 'bold'),
                                       fg=COLORS['text_dim'], bg=COLORS['bg_panel'])
        self._status_label.pack(side='left', padx=(0, 16))

        self._start_btn = tk.Button(
            ctrl_frame, text="▶  START MONITORING",
            font=('Segoe UI', 9, 'bold'),
            bg=COLORS['green_dim'], fg=COLORS['text'],
            activebackground=COLORS['green'],
            activeforeground=COLORS['text'],
            relief='flat', padx=16, pady=4,
            cursor='hand2',
            command=self._toggle_monitoring
        )
        self._start_btn.pack(side='left', padx=4)

        # ─── Main Content (Notebook with tabs) ──────────────────────
        style = ttk.Style()
        style.theme_use('default')
        style.configure('Dark.TNotebook', background=COLORS['bg_dark'],
                        borderwidth=0)
        style.configure('Dark.TNotebook.Tab',
                        background=COLORS['bg_panel'],
                        foreground=COLORS['text_dim'],
                        padding=[16, 8],
                        font=('Segoe UI', 9))
        style.map('Dark.TNotebook.Tab',
                  background=[('selected', COLORS['bg_card'])],
                  foreground=[('selected', COLORS['accent'])])

        self.notebook = ttk.Notebook(self.root, style='Dark.TNotebook')
        self.notebook.pack(fill='both', expand=True, padx=8, pady=(4, 8))

        # Tab 1: Dashboard
        self._tab_dashboard = StyledFrame(self.notebook)
        self.notebook.add(self._tab_dashboard, text='  📊  Dashboard  ')
        self._build_dashboard(self._tab_dashboard)

        # Tab 2: Alerts
        self._tab_alerts = StyledFrame(self.notebook)
        self.notebook.add(self._tab_alerts, text='  🔔  Alerts  ')
        self._build_alerts_tab(self._tab_alerts)

        # Tab 3: Packet Log
        self._tab_packets = StyledFrame(self.notebook)
        self.notebook.add(self._tab_packets, text='  📦  Packet Log  ')
        self._build_packet_log(self._tab_packets)

        # Tab 4: Flows
        self._tab_flows = StyledFrame(self.notebook)
        self.notebook.add(self._tab_flows, text='  🔀  Active Flows  ')
        self._build_flows_tab(self._tab_flows)

        # Tab 5: ML Engine
        self._tab_ml = StyledFrame(self.notebook)
        self.notebook.add(self._tab_ml, text='  🧠  ML Engine  ')
        self._build_ml_tab(self._tab_ml)

        # Tab 6: PCAP Analyzer
        self._tab_pcap = StyledFrame(self.notebook)
        self.notebook.add(self._tab_pcap, text='  📁  PCAP Analyzer  ')
        self._build_pcap_tab(self._tab_pcap)

        # Tab 7: Forensics Vault
        self._tab_forensics = StyledFrame(self.notebook)
        self.notebook.add(self._tab_forensics, text='  🔐  Forensics Vault  ')
        self._build_forensics_tab(self._tab_forensics)

        # Tab 8: Discovered Devices
        self._tab_devices = StyledFrame(self.notebook)
        self.notebook.add(self._tab_devices, text='  📡  Devices  ')
        self._build_devices_tab(self._tab_devices)

        # Tab 9: Incidents (correlated alerts)
        self._tab_incidents = StyledFrame(self.notebook)
        self.notebook.add(self._tab_incidents, text='  🎯  Incidents  ')
        self._build_incidents_tab(self._tab_incidents)

        # Tab 10: PCAP Capture
        self._tab_capture = StyledFrame(self.notebook)
        self.notebook.add(self._tab_capture, text='  💾  Capture  ')
        self._build_capture_tab(self._tab_capture)

        # Tab 11: Settings
        self._tab_settings = StyledFrame(self.notebook)
        self.notebook.add(self._tab_settings, text='  ⚙  Settings  ')
        self._build_settings_tab(self._tab_settings)

        # ─── Bottom Status Bar ─────────────────────────────────────
        status_bar = tk.Frame(self.root, bg=COLORS['bg_panel'], height=28)
        status_bar.pack(fill='x', side='bottom')
        status_bar.pack_propagate(False)

        self._statusbar_text = tk.Label(
            status_bar, text="Ready. Click START MONITORING to begin.",
            font=('Consolas', 8), fg=COLORS['text_dim'],
            bg=COLORS['bg_panel'], anchor='w'
        )
        self._statusbar_text.pack(side='left', padx=12)

        self._statusbar_right = tk.Label(
            status_bar, text="",
            font=('Consolas', 8), fg=COLORS['text_dim'],
            bg=COLORS['bg_panel'], anchor='e'
        )
        self._statusbar_right.pack(side='right', padx=12)

    # ──────────────────────────────────────────────────────────────────────────
    # Dashboard Tab
    # ──────────────────────────────────────────────────────────────────────────
    def _build_dashboard(self, parent):
        # Top metrics row
        metrics_frame = tk.Frame(parent, bg=COLORS['bg_dark'])
        metrics_frame.pack(fill='x', padx=8, pady=8)

        # Metric cards
        self._m_packets = self._make_metric_card(metrics_frame, "Packets Captured", "0")
        self._m_bandwidth = self._make_metric_card(metrics_frame, "Bandwidth", "0 B/s",
                                                    color=COLORS['cyan'])
        self._m_flows = self._make_metric_card(metrics_frame, "Active Flows", "0",
                                                color=COLORS['purple'])
        self._m_alerts = self._make_metric_card(metrics_frame, "Alerts", "0",
                                                 color=COLORS['yellow'])
        self._m_threat = self._make_metric_card(metrics_frame, "Threat Level", "SAFE",
                                                  color=COLORS['green'])

        # Charts row
        charts_frame = tk.Frame(parent, bg=COLORS['bg_dark'])
        charts_frame.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        # Traffic chart
        traffic_card = Card(charts_frame, title="TRAFFIC RATE (packets/sec)")
        traffic_card.pack(side='left', fill='both', expand=True, padx=(0, 4))

        self._chart_traffic = MiniChart(traffic_card, width=500, height=120, max_points=60)
        self._chart_traffic.pack(fill='x', expand=True)

        # Bandwidth chart
        bw_card = Card(charts_frame, title="BANDWIDTH (KB/s)")
        bw_card.pack(side='left', fill='both', expand=True, padx=(4, 0))

        self._chart_bandwidth = MiniChart(bw_card, width=500, height=120, max_points=60)
        self._chart_bandwidth.pack(fill='x', expand=True)

        # Bottom row: protocol breakdown + recent alerts
        bottom_frame = tk.Frame(parent, bg=COLORS['bg_dark'])
        bottom_frame.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        # Protocol breakdown
        proto_card = Card(bottom_frame, title="PROTOCOL BREAKDOWN")
        proto_card.pack(side='left', fill='both', expand=True, padx=(0, 4))
        self._proto_canvas = tk.Canvas(proto_card, bg=COLORS['bg_card'],
                                       highlightthickness=0, height=150)
        self._proto_canvas.pack(fill='both', expand=True)

        # Recent alerts mini
        recent_card = Card(bottom_frame, title="RECENT ALERTS")
        recent_card.pack(side='left', fill='both', expand=True, padx=(4, 0))

        self._recent_alerts_frame = tk.Frame(recent_card, bg=COLORS['bg_card'])
        self._recent_alerts_frame.pack(fill='both', expand=True)

    def _make_metric_card(self, parent, label, value, color=None):
        card = Card(parent)
        card.pack(side='left', fill='both', expand=True, padx=3)
        widget = MetricWidget(card, label, value, color=color)
        widget.pack(fill='both', expand=True)
        return widget

    # ──────────────────────────────────────────────────────────────────────────
    # Alerts Tab
    # ──────────────────────────────────────────────────────────────────────────
    def _build_alerts_tab(self, parent):
        # Toolbar
        toolbar = tk.Frame(parent, bg=COLORS['bg_dark'])
        toolbar.pack(fill='x', padx=8, pady=8)

        tk.Label(toolbar, text="Filter:", font=('Segoe UI', 9),
                fg=COLORS['text_dim'], bg=COLORS['bg_dark']).pack(side='left')

        self._alert_filter = ttk.Combobox(toolbar, values=['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                                           state='readonly', width=12)
        self._alert_filter.set('ALL')
        self._alert_filter.pack(side='left', padx=8)
        self._alert_filter.bind('<<ComboboxSelected>>', lambda e: self._refresh_alerts_display())

        tk.Button(toolbar, text="🗑  Clear All", font=('Segoe UI', 8),
                 bg=COLORS['bg_input'], fg=COLORS['text_dim'],
                 relief='flat', cursor='hand2',
                 command=self._clear_all_alerts).pack(side='right', padx=4)

        tk.Button(toolbar, text="📤  Export", font=('Segoe UI', 8),
                 bg=COLORS['bg_input'], fg=COLORS['text_dim'],
                 relief='flat', cursor='hand2',
                 command=self._export_alerts).pack(side='right', padx=4)

        tk.Button(toolbar, text="✓  Acknowledge All", font=('Segoe UI', 8),
                 bg=COLORS['bg_input'], fg=COLORS['text_dim'],
                 relief='flat', cursor='hand2',
                 command=lambda: self.app.alert_manager.acknowledge_all()
                 ).pack(side='right', padx=4)

        # Scrollable alerts list
        container = tk.Frame(parent, bg=COLORS['bg_dark'])
        container.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        self._alerts_canvas = tk.Canvas(container, bg=COLORS['bg_dark'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient='vertical', command=self._alerts_canvas.yview)
        self._alerts_scroll_frame = tk.Frame(self._alerts_canvas, bg=COLORS['bg_dark'])

        self._alerts_scroll_frame.bind(
            '<Configure>',
            lambda e: self._alerts_canvas.configure(scrollregion=self._alerts_canvas.bbox('all'))
        )
        self._alerts_canvas_window = self._alerts_canvas.create_window(
            (0, 0), window=self._alerts_scroll_frame, anchor='nw')
        self._alerts_canvas.configure(yscrollcommand=scrollbar.set)

        # CRITICAL: Bind canvas resize to stretch the inner frame to full width
        # Without this, AlertListItems render with minimal width and appear invisible
        def _on_canvas_resize(event):
            self._alerts_canvas.itemconfig(self._alerts_canvas_window, width=event.width)
        self._alerts_canvas.bind('<Configure>', _on_canvas_resize)

        self._alerts_canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Mouse wheel scrolling
        def _on_mousewheel(event):
            self._alerts_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        self._alerts_canvas.bind_all("<MouseWheel>", _on_mousewheel, add='+')

        # ─── Load historical alerts from disk into the GUI ────────
        # These were loaded by AlertManager before the GUI existed,
        # so the listener never fired for them. Populate now.
        try:
            historical = self.app.alert_manager.get_alerts(limit=200)
            for alert in reversed(historical):  # oldest first so newest ends up on top
                item = AlertListItem(self._alerts_scroll_frame, alert.to_dict())
                item.pack(fill='x', padx=4, pady=2)
                self._alert_widgets.insert(0, item)
        except Exception as e:
            logger.debug("Failed to load historical alerts into GUI: %s", e)

    # ──────────────────────────────────────────────────────────────────────────
    # Packet Log Tab
    # ──────────────────────────────────────────────────────────────────────────
    def _build_packet_log(self, parent):
        self._packet_text = tk.Text(
            parent, bg=COLORS['bg_card'], fg=COLORS['text'],
            font=('Consolas', 9), wrap='none',
            insertbackground=COLORS['accent'],
            selectbackground=COLORS['accent'],
            relief='flat', padx=8, pady=8
        )
        self._packet_text.pack(fill='both', expand=True, padx=8, pady=8)

        # Tag colors
        self._packet_text.tag_configure('tcp', foreground=COLORS['accent'])
        self._packet_text.tag_configure('udp', foreground=COLORS['purple'])
        self._packet_text.tag_configure('icmp', foreground=COLORS['yellow'])
        self._packet_text.tag_configure('dns', foreground=COLORS['cyan'])
        self._packet_text.tag_configure('arp', foreground=COLORS['orange'])
        self._packet_text.tag_configure('other', foreground=COLORS['text_dim'])
        self._packet_text.tag_configure('timestamp', foreground=COLORS['text_dim'])

    # ──────────────────────────────────────────────────────────────────────────
    # Flows Tab
    # ──────────────────────────────────────────────────────────────────────────
    def _build_flows_tab(self, parent):
        columns = ('src_ip', 'dst_ip', 'protocol', 'packets', 'bytes',
                   'duration', 'bps', 'state')
        self._flows_tree = ttk.Treeview(parent, columns=columns, show='headings',
                                        height=20)

        headers = {
            'src_ip': ('Source IP', 140),
            'dst_ip': ('Destination IP', 140),
            'protocol': ('Proto', 60),
            'packets': ('Packets', 80),
            'bytes': ('Bytes', 90),
            'duration': ('Duration', 80),
            'bps': ('Bytes/s', 90),
            'state': ('State', 80),
        }

        for col, (heading, width) in headers.items():
            self._flows_tree.heading(col, text=heading)
            self._flows_tree.column(col, width=width, anchor='center')

        style = ttk.Style()
        style.configure('Treeview',
                       background=COLORS['bg_card'],
                       foreground=COLORS['text'],
                       fieldbackground=COLORS['bg_card'],
                       font=('Consolas', 9))
        style.configure('Treeview.Heading',
                       background=COLORS['bg_panel'],
                       foreground=COLORS['text_dim'],
                       font=('Segoe UI', 9, 'bold'))

        scrollbar = ttk.Scrollbar(parent, orient='vertical',
                                  command=self._flows_tree.yview)
        self._flows_tree.configure(yscrollcommand=scrollbar.set)

        self._flows_tree.pack(side='left', fill='both', expand=True, padx=(8,0), pady=8)
        scrollbar.pack(side='right', fill='y', padx=(0,8), pady=8)

    # ──────────────────────────────────────────────────────────────────────────
    # ML Engine Tab
    # ──────────────────────────────────────────────────────────────────────────
    def _build_ml_tab(self, parent):
        # Use a canvas for scrolling
        ml_canvas = tk.Canvas(parent, bg=COLORS['bg_dark'], highlightthickness=0)
        ml_scrollbar = ttk.Scrollbar(parent, orient='vertical', command=ml_canvas.yview)
        ml_scroll_frame = tk.Frame(ml_canvas, bg=COLORS['bg_dark'])
        ml_scroll_frame.bind('<Configure>',
                            lambda e: ml_canvas.configure(scrollregion=ml_canvas.bbox('all')))
        ml_canvas.create_window((0, 0), window=ml_scroll_frame, anchor='nw')
        ml_canvas.configure(yscrollcommand=ml_scrollbar.set)
        ml_canvas.pack(side='left', fill='both', expand=True)
        ml_scrollbar.pack(side='right', fill='y')

        # Status section
        status_card = Card(ml_scroll_frame, title="ML ENGINE STATUS")
        status_card.pack(fill='x', padx=8, pady=8)

        self._ml_status_labels = {}
        fields = [
            ('enabled', 'ML Enabled'),
            ('sklearn_available', 'scikit-learn Available'),
            ('is_trained', 'Model Trained'),
            ('training_samples', 'Training Samples'),
            ('baseline_samples', 'Baseline Samples'),
            ('threshold', 'Anomaly Threshold'),
        ]

        for key, label in fields:
            row = tk.Frame(status_card, bg=COLORS['bg_card'])
            row.pack(fill='x', pady=2)
            tk.Label(row, text=label + ":", font=('Segoe UI', 9),
                    fg=COLORS['text_dim'], bg=COLORS['bg_card'],
                    width=25, anchor='w').pack(side='left')
            val_lbl = tk.Label(row, text="—", font=('Consolas', 9, 'bold'),
                              fg=COLORS['accent'], bg=COLORS['bg_card'],
                              anchor='w')
            val_lbl.pack(side='left', padx=8)
            self._ml_status_labels[key] = val_lbl

        # Feature History Storage stats
        history_card = Card(ml_scroll_frame, title="FEATURE HISTORY STORAGE")
        history_card.pack(fill='x', padx=8, pady=(0, 8))

        self._history_status_labels = {}
        history_fields = [
            ('history_size_mb', 'Disk Usage'),
            ('history_rows', 'Total Vectors Saved'),
            ('history_oldest', 'Oldest Data'),
            ('history_newest', 'Newest Data'),
        ]
        for key, label in history_fields:
            row = tk.Frame(history_card, bg=COLORS['bg_card'])
            row.pack(fill='x', pady=2)
            tk.Label(row, text=label + ":", font=('Segoe UI', 9),
                    fg=COLORS['text_dim'], bg=COLORS['bg_card'],
                    width=25, anchor='w').pack(side='left')
            val_lbl = tk.Label(row, text="—", font=('Consolas', 9, 'bold'),
                              fg=COLORS['cyan'], bg=COLORS['bg_card'],
                              anchor='w')
            val_lbl.pack(side='left', padx=8)
            self._history_status_labels[key] = val_lbl

        desc_lbl = tk.Label(
            history_card,
            text="Feature vectors are saved every 5 seconds as lightweight CSV (~2.5 MB/day).\n"
                 "Historical data is used to retrain the ML model for better accuracy over time.\n"
                 "Files older than 90 days are automatically pruned.",
            font=('Segoe UI', 8), fg=COLORS['text_dim'], bg=COLORS['bg_card'],
            justify='left', anchor='w', wraplength=600
        )
        desc_lbl.pack(fill='x', pady=(6, 2))

        # Anomaly score history chart
        score_card = Card(ml_scroll_frame, title="ANOMALY SCORE HISTORY (last 90 minutes)")
        score_card.pack(fill='x', padx=8, pady=(0, 8))

        self._score_history_canvas = tk.Canvas(
            score_card, bg=COLORS['bg_card'], highlightthickness=0, height=140
        )
        self._score_history_canvas.pack(fill='x', expand=True)

        # Current anomaly score
        current_card = Card(ml_scroll_frame, title="CURRENT ANOMALY ANALYSIS")
        current_card.pack(fill='x', padx=8, pady=(0, 8))

        self._ml_score_label = tk.Label(current_card, text="Score: —",
                                         font=('Segoe UI Semibold', 16),
                                         fg=COLORS['green'], bg=COLORS['bg_card'])
        self._ml_score_label.pack(anchor='w', pady=4)

        self._ml_reasons_text = tk.Text(current_card, bg=COLORS['bg_card'],
                                         fg=COLORS['text'], font=('Consolas', 9),
                                         height=6, relief='flat', wrap='word')
        self._ml_reasons_text.pack(fill='x', pady=4)

        # Feature display
        feat_card = Card(ml_scroll_frame, title="EXTRACTED FEATURES (last window)")
        feat_card.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        self._ml_features_text = tk.Text(feat_card, bg=COLORS['bg_card'],
                                          fg=COLORS['text'], font=('Consolas', 9),
                                          height=10, relief='flat', wrap='word')
        self._ml_features_text.pack(fill='both', expand=True)

    # ──────────────────────────────────────────────────────────────────────────
    # PCAP Analyzer Tab
    # ──────────────────────────────────────────────────────────────────────────
    def _build_pcap_tab(self, parent):
        # Top controls
        ctrl_frame = tk.Frame(parent, bg=COLORS['bg_dark'])
        ctrl_frame.pack(fill='x', padx=8, pady=8)

        tk.Label(ctrl_frame, text="Analyze PCAP/PCAPNG capture files from Wireshark or tcpdump",
                font=('Segoe UI', 9), fg=COLORS['text_dim'],
                bg=COLORS['bg_dark']).pack(side='left')

        self._pcap_export_btn = tk.Button(
            ctrl_frame, text="📤  Export Results",
            font=('Segoe UI', 8), bg=COLORS['bg_input'],
            fg=COLORS['text_dim'], relief='flat', cursor='hand2',
            command=self._pcap_export_results
        )
        self._pcap_export_btn.pack(side='right', padx=4)

        self._pcap_cancel_btn = tk.Button(
            ctrl_frame, text="✖  Cancel",
            font=('Segoe UI', 8), bg=COLORS['red_dim'],
            fg=COLORS['text'], relief='flat', cursor='hand2',
            command=self._pcap_cancel, state='disabled'
        )
        self._pcap_cancel_btn.pack(side='right', padx=4)

        self._pcap_btn = tk.Button(
            ctrl_frame, text="📂  Open PCAP File",
            font=('Segoe UI', 10, 'bold'), bg=COLORS['accent'],
            fg=COLORS['bg_dark'], relief='flat', padx=16, pady=6,
            cursor='hand2', command=self._pcap_open_file
        )
        self._pcap_btn.pack(side='right', padx=4)

        # Progress bar
        prog_frame = tk.Frame(parent, bg=COLORS['bg_dark'])
        prog_frame.pack(fill='x', padx=8)

        self._pcap_progress_var = tk.IntVar(value=0)
        self._pcap_progress = ttk.Progressbar(prog_frame, variable=self._pcap_progress_var,
                                               maximum=100, length=400)
        self._pcap_progress.pack(side='left', fill='x', expand=True, padx=(0, 8))

        self._pcap_progress_label = tk.Label(prog_frame, text="Ready — select a PCAP file to analyze",
                                              font=('Consolas', 8), fg=COLORS['text_dim'],
                                              bg=COLORS['bg_dark'], anchor='w')
        self._pcap_progress_label.pack(side='left', fill='x', expand=True)

        # Results area (split: stats left, alerts right)
        results_frame = tk.Frame(parent, bg=COLORS['bg_dark'])
        results_frame.pack(fill='both', expand=True, padx=8, pady=(8, 8))

        # Left: Stats
        stats_card = Card(results_frame, title="ANALYSIS SUMMARY")
        stats_card.pack(side='left', fill='both', expand=True, padx=(0, 4))

        self._pcap_stats_text = tk.Text(stats_card, bg=COLORS['bg_card'],
                                         fg=COLORS['text'], font=('Consolas', 9),
                                         relief='flat', wrap='word', padx=8, pady=8)
        self._pcap_stats_text.pack(fill='both', expand=True)
        self._pcap_stats_text.tag_configure('header', foreground=COLORS['accent'],
                                             font=('Consolas', 9, 'bold'))
        self._pcap_stats_text.tag_configure('value', foreground=COLORS['text'])
        self._pcap_stats_text.tag_configure('alert_high', foreground=COLORS['red'])
        self._pcap_stats_text.tag_configure('alert_med', foreground=COLORS['yellow'])
        self._pcap_stats_text.tag_configure('safe', foreground=COLORS['green'])
        self._pcap_stats_text.insert('end', "No analysis results yet.\n\n"
            "Click 'Open PCAP File' to load a capture from Wireshark,\n"
            "tcpdump, or any other packet capture tool.\n\n"
            "Supported formats: .pcap, .pcapng, .cap\n\n"
            "The analyzer runs every packet through:\n"
            "  - IDS signature rules (port scan, brute force, etc.)\n"
            "  - Threat intelligence feeds (malicious IPs/domains)\n"
            "  - IOC scanner (TOR, DGA, suspicious processes)\n"
            "  - Alert verification (auto false-positive detection)\n")

        # Right: Alerts found
        alerts_card = Card(results_frame, title="ALERTS FOUND IN CAPTURE")
        alerts_card.pack(side='left', fill='both', expand=True, padx=(4, 0))

        alerts_inner = tk.Frame(alerts_card, bg=COLORS['bg_card'])
        alerts_inner.pack(fill='both', expand=True)

        pcap_alert_canvas = tk.Canvas(alerts_inner, bg=COLORS['bg_card'], highlightthickness=0)
        pcap_scrollbar = ttk.Scrollbar(alerts_inner, orient='vertical', command=pcap_alert_canvas.yview)
        self._pcap_alerts_frame = tk.Frame(pcap_alert_canvas, bg=COLORS['bg_card'])
        self._pcap_alerts_frame.bind('<Configure>',
            lambda e: pcap_alert_canvas.configure(scrollregion=pcap_alert_canvas.bbox('all')))
        pcap_alert_canvas.create_window((0, 0), window=self._pcap_alerts_frame, anchor='nw')
        pcap_alert_canvas.configure(yscrollcommand=pcap_scrollbar.set)
        pcap_alert_canvas.pack(side='left', fill='both', expand=True)
        pcap_scrollbar.pack(side='right', fill='y')

        def _pcap_mousewheel(event):
            pcap_alert_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        pcap_alert_canvas.bind_all("<MouseWheel>", _pcap_mousewheel, add='+')

        self._pcap_alert_widgets = []

    def _pcap_open_file(self):
        """Open file dialog and start PCAP analysis."""
        filepath = filedialog.askopenfilename(
            title="Select PCAP Capture File",
            filetypes=[
                ('Packet Captures', '*.pcap *.pcapng *.cap'),
                ('PCAP files', '*.pcap'),
                ('PCAPNG files', '*.pcapng'),
                ('All files', '*.*'),
            ]
        )
        if not filepath:
            return

        # Clear previous results
        self._pcap_stats_text.delete('1.0', 'end')
        self._pcap_stats_text.insert('end', f"Loading: {os.path.basename(filepath)}...\n")
        for w in self._pcap_alert_widgets:
            w.destroy()
        self._pcap_alert_widgets.clear()

        # Update UI state
        self._pcap_btn.config(state='disabled')
        self._pcap_cancel_btn.config(state='normal')
        self._pcap_progress_var.set(0)

        # Start analysis in background
        def on_alert(alert):
            """Add alert to GUI as it's found."""
            try:
                self.root.after(0, self._pcap_add_alert, alert)
            except Exception:
                pass

        def on_done(result):
            """Called when analysis completes."""
            try:
                self.root.after(0, self._pcap_show_results, result)
            except Exception:
                pass

        self.app.pcap_analyzer.analyze_file_async(filepath, callback=on_alert, done_callback=on_done)

        # Start progress updater
        self._pcap_update_progress()

    def _pcap_update_progress(self):
        """Update progress bar during analysis."""
        analyzer = self.app.pcap_analyzer
        if analyzer.is_analyzing:
            self._pcap_progress_var.set(analyzer.progress)
            self._pcap_progress_label.config(text=analyzer.progress_text)
            self.root.after(200, self._pcap_update_progress)
        else:
            self._pcap_progress_var.set(100)
            self._pcap_progress_label.config(text=analyzer.progress_text)
            self._pcap_btn.config(state='normal')
            self._pcap_cancel_btn.config(state='disabled')

    def _pcap_add_alert(self, alert):
        """Add a single alert to the PCAP results panel."""
        item = AlertListItem(self._pcap_alerts_frame, alert.to_dict())
        item.pack(fill='x', padx=2, pady=1)
        self._pcap_alert_widgets.append(item)

    def _pcap_show_results(self, result):
        """Display final analysis results."""
        stats = result.get('stats', {})
        alerts = result.get('alerts', [])

        self._pcap_stats_text.delete('1.0', 'end')
        st = self._pcap_stats_text

        # File info
        st.insert('end', 'FILE INFORMATION\n', 'header')
        st.insert('end', f"  File:      {stats.get('file', '?')}\n")
        st.insert('end', f"  Size:      {stats.get('file_size_mb', 0)} MB\n")
        st.insert('end', f"  Capture:   {stats.get('capture_start', '?')} to {stats.get('capture_end', '?')}\n")
        st.insert('end', f"  Duration:  {stats.get('capture_duration', '?')}\n")
        st.insert('end', f"  Analysis:  {stats.get('duration_sec', 0)} seconds "
                         f"({stats.get('packets_per_sec', 0):.0f} pkts/sec)\n\n")

        # Traffic summary
        st.insert('end', 'TRAFFIC SUMMARY\n', 'header')
        st.insert('end', f"  Packets:       {stats.get('total_packets', 0):,}\n")
        st.insert('end', f"  Total bytes:   {stats.get('total_bytes', 0):,}\n")
        st.insert('end', f"  Unique IPs:    {stats.get('unique_src_ips', 0)} sources, "
                         f"{stats.get('unique_dst_ips', 0)} destinations\n")
        st.insert('end', f"  Unique ports:  {stats.get('unique_dst_ports', 0)}\n")
        st.insert('end', f"  DNS queries:   {stats.get('unique_dns_queries', 0)} unique\n\n")

        # Protocols
        protocols = stats.get('protocols', {})
        if protocols:
            st.insert('end', 'PROTOCOLS\n', 'header')
            total_pkts = sum(protocols.values())
            for proto, count in sorted(protocols.items(), key=lambda x: -x[1]):
                pct = count / max(total_pkts, 1) * 100
                st.insert('end', f"  {proto:<10} {count:>8,}  ({pct:.1f}%)\n")
            st.insert('end', '\n')

        # Alert summary
        alert_count = stats.get('alerts_generated', 0)
        st.insert('end', 'SECURITY FINDINGS\n', 'header')
        if alert_count == 0:
            st.insert('end', '  No threats detected in this capture.\n', 'safe')
        else:
            st.insert('end', f"  Total alerts: {alert_count}\n",
                      'alert_high' if alert_count > 10 else 'alert_med')

            by_sev = stats.get('alerts_by_severity', {})
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = by_sev.get(sev, 0)
                if count:
                    tag = 'alert_high' if sev in ('CRITICAL', 'HIGH') else 'alert_med'
                    st.insert('end', f"    {sev}: {count}\n", tag)

            by_verdict = stats.get('alerts_by_verdict', {})
            if by_verdict:
                st.insert('end', '\n  Verification:\n')
                for verdict, count in sorted(by_verdict.items(), key=lambda x: -x[1]):
                    tag = 'safe' if 'FALSE' in verdict else ('alert_high' if 'THREAT' in verdict else 'value')
                    st.insert('end', f"    {verdict}: {count}\n", tag)

            by_cat = stats.get('alerts_by_category', {})
            if by_cat:
                st.insert('end', '\n  By category:\n')
                for cat, count in sorted(by_cat.items(), key=lambda x: -x[1]):
                    st.insert('end', f"    {cat}: {count}\n")

        st.insert('end', '\n')

        # Top talkers
        top_talkers = stats.get('top_talkers', [])
        if top_talkers:
            st.insert('end', 'TOP TALKERS (by bytes)\n', 'header')
            for ip, bytes_count in top_talkers[:10]:
                st.insert('end', f"  {ip:<20} {bytes_count:>12,} bytes\n")
            st.insert('end', '\n')

        # Top DNS
        top_dns = stats.get('top_dns_queries', [])
        if top_dns:
            st.insert('end', 'TOP DNS QUERIES\n', 'header')
            for domain, count in top_dns[:15]:
                st.insert('end', f"  {domain:<45} ({count}x)\n")

        st.insert('end', '\n')

        # Forensics: credentials and insecure services
        forensics = result.get('forensics', {})

        creds = forensics.get('credentials', [])
        if creds:
            st.insert('end', 'CREDENTIALS FOUND IN PLAINTEXT\n', 'header')
            for cred in creds:
                st.insert('end', f"  [{cred.get('time_str', '')}] ", 'value')
                st.insert('end', f"{cred['protocol']} {cred['credential_type']}", 'alert_high')
                st.insert('end', f" — {cred['source_ip']} → {cred['destination_ip']}:{cred['port']}\n")
                st.insert('end', f"    Value: {cred['value']}\n")
                if cred.get('extra'):
                    for k, v in cred['extra'].items():
                        if v:
                            st.insert('end', f"    {k}: {v}\n")
            st.insert('end', '\n')

        sensitive = forensics.get('sensitive_data', [])
        if sensitive:
            st.insert('end', 'SENSITIVE DATA IN TRANSIT\n', 'header')
            for item in sensitive:
                st.insert('end', f"  {item['data_type']}: ", 'alert_high')
                st.insert('end', f"{item['value']} — "
                                 f"{item['source_ip']} → {item['destination_ip']}:{item['port']}\n")
            st.insert('end', '\n')

        insecure = forensics.get('insecure_services', [])
        if insecure:
            st.insert('end', 'INSECURE (UNENCRYPTED) SERVICES\n', 'header')
            for svc in insecure:
                st.insert('end', f"  [{svc.get('risk', '?')}] ", 'alert_high')
                st.insert('end', f"{svc.get('service', '?')} at {svc.get('ip', '?')}:{svc.get('port', '?')}\n", 'alert_med')
                st.insert('end', f"    {svc.get('description', '')}\n")
                st.insert('end', f"    Packets: {svc.get('packet_count', 0)}, "
                                 f"Bytes: {svc.get('bytes', 0):,}\n")
                alt = svc.get('secure_alternative', '')
                if alt:
                    st.insert('end', f"    Fix: Use {alt}\n", 'safe')
                st.insert('end', '\n')

        # Narrative
        narrative = result.get('narrative', '')
        if narrative:
            st.insert('end', '\n')
            st.insert('end', '═' * 50 + '\n', 'header')
            st.insert('end', narrative + '\n')

        # Flow classifications
        flow_data = forensics.get('flow_classifications', {})
        if flow_data:
            st.insert('end', '\n')
            st.insert('end', 'FLOW CLASSIFICATIONS\n', 'header')
            # Group by classification type
            from collections import Counter as FCounter
            type_counts = FCounter()
            for fk, fv in flow_data.items():
                type_counts[fv.get('classification_desc', 'Unknown')] += 1
            for desc, count in type_counts.most_common():
                st.insert('end', f"  {desc}: {count} flows\n")

    def _pcap_cancel(self):
        """Cancel ongoing analysis."""
        self.app.pcap_analyzer.cancel()
        self._pcap_cancel_btn.config(state='disabled')

    def _pcap_export_results(self):
        """Export PCAP analysis results."""
        if not self.app.pcap_analyzer.alerts and not self.app.pcap_analyzer.stats:
            messagebox.showinfo("Export", "No results to export. Run an analysis first.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json'), ('CSV', '*.csv')],
            title='Export PCAP Analysis Results'
        )
        if filepath:
            fmt = 'csv' if filepath.endswith('.csv') else 'json'
            self.app.pcap_analyzer.export_results(filepath, format=fmt)
            messagebox.showinfo("Export", f"Results exported to {filepath}")

    # ──────────────────────────────────────────────────────────────────────────
    # Forensics Vault Tab
    # ──────────────────────────────────────────────────────────────────────────
    def _build_forensics_tab(self, parent):
        # Top controls
        ctrl = tk.Frame(parent, bg=COLORS['bg_dark'])
        ctrl.pack(fill='x', padx=8, pady=8)

        tk.Label(ctrl, text="Encrypted credential vault & security audit findings",
                font=('Segoe UI', 9), fg=COLORS['text_dim'],
                bg=COLORS['bg_dark']).pack(side='left')

        self._fv_clear_btn = tk.Button(ctrl, text="🗑  Clear All Data",
            font=('Segoe UI', 8), bg=COLORS['red_dim'], fg=COLORS['text'],
            relief='flat', cursor='hand2', command=self._fv_clear_all)
        self._fv_clear_btn.pack(side='right', padx=4)

        self._fv_export_btn = tk.Button(ctrl, text="📤  Export",
            font=('Segoe UI', 8), bg=COLORS['bg_input'], fg=COLORS['text_dim'],
            relief='flat', cursor='hand2', command=self._fv_export)
        self._fv_export_btn.pack(side='right', padx=4)

        self._fv_refresh_btn = tk.Button(ctrl, text="🔄  Refresh",
            font=('Segoe UI', 8), bg=COLORS['bg_input'], fg=COLORS['text_dim'],
            relief='flat', cursor='hand2', command=self._fv_refresh)
        self._fv_refresh_btn.pack(side='right', padx=4)

        # Search bar
        search_frame = tk.Frame(parent, bg=COLORS['bg_dark'])
        search_frame.pack(fill='x', padx=8, pady=(0, 4))

        tk.Label(search_frame, text="Search:", font=('Segoe UI', 9),
                fg=COLORS['text_dim'], bg=COLORS['bg_dark']).pack(side='left')
        self._fv_search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self._fv_search_var,
            bg=COLORS['bg_input'], fg=COLORS['text'], insertbackground=COLORS['text'],
            font=('Consolas', 10), relief='flat', width=30)
        search_entry.pack(side='left', padx=4, fill='x', expand=True)
        search_entry.bind('<Return>', lambda e: self._fv_search())

        tk.Label(search_frame, text="Protocol:", font=('Segoe UI', 9),
                fg=COLORS['text_dim'], bg=COLORS['bg_dark']).pack(side='left', padx=(8, 0))
        self._fv_proto_var = tk.StringVar(value='ALL')
        proto_menu = ttk.Combobox(search_frame, textvariable=self._fv_proto_var, width=12,
            values=['ALL', 'FTP', 'HTTP', 'Telnet', 'POP3', 'IMAP', 'SMTP', 'SNMP',
                    'Redis', 'MongoDB', 'RTSP', 'IRC', 'SIP', 'BACnet', 'Modbus'],
            state='readonly')
        proto_menu.pack(side='left', padx=4)

        tk.Button(search_frame, text="🔍 Search", font=('Segoe UI', 9),
            bg=COLORS['accent'], fg=COLORS['bg_dark'], relief='flat',
            cursor='hand2', command=self._fv_search).pack(side='left', padx=4)

        # Stats bar
        stats_frame = tk.Frame(parent, bg=COLORS['bg_panel'])
        stats_frame.pack(fill='x', padx=8, pady=(0, 4))
        self._fv_stats_label = tk.Label(stats_frame,
            text="Loading forensics data...",
            font=('Consolas', 8), fg=COLORS['text_dim'], bg=COLORS['bg_panel'],
            anchor='w', padx=8, pady=4)
        self._fv_stats_label.pack(fill='x')

        # Main content: three panels
        content = tk.Frame(parent, bg=COLORS['bg_dark'])
        content.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        # Left: Credentials
        left = Card(content, title="CAPTURED CREDENTIALS")
        left.pack(side='left', fill='both', expand=True, padx=(0, 4))

        cred_inner = tk.Frame(left, bg=COLORS['bg_card'])
        cred_inner.pack(fill='both', expand=True)

        # Credential list with scrollbar
        cred_canvas = tk.Canvas(cred_inner, bg=COLORS['bg_card'], highlightthickness=0)
        cred_sb = ttk.Scrollbar(cred_inner, orient='vertical', command=cred_canvas.yview)
        self._fv_cred_frame = tk.Frame(cred_canvas, bg=COLORS['bg_card'])
        self._fv_cred_frame.bind('<Configure>',
            lambda e: cred_canvas.configure(scrollregion=cred_canvas.bbox('all')))
        cred_canvas.create_window((0, 0), window=self._fv_cred_frame, anchor='nw')
        cred_canvas.configure(yscrollcommand=cred_sb.set)
        cred_canvas.pack(side='left', fill='both', expand=True)
        cred_sb.pack(side='right', fill='y')

        self._fv_cred_widgets = []

        # Right: Services + Detail
        right = tk.Frame(content, bg=COLORS['bg_dark'])
        right.pack(side='left', fill='both', expand=True, padx=(4, 0))

        # Top right: Detail view
        detail_card = Card(right, title="SELECTED ITEM DETAIL")
        detail_card.pack(fill='both', expand=True, pady=(0, 4))

        self._fv_detail_text = tk.Text(detail_card, bg=COLORS['bg_card'],
            fg=COLORS['text'], font=('Consolas', 9), relief='flat',
            wrap='word', padx=8, pady=8)
        self._fv_detail_text.pack(fill='both', expand=True)
        self._fv_detail_text.tag_configure('header', foreground=COLORS['accent'],
            font=('Consolas', 10, 'bold'))
        self._fv_detail_text.tag_configure('crit', foreground=COLORS['red'])
        self._fv_detail_text.tag_configure('warn', foreground=COLORS['yellow'])
        self._fv_detail_text.tag_configure('safe', foreground=COLORS['green'])
        self._fv_detail_text.tag_configure('key', foreground=COLORS['cyan'])
        self._fv_detail_text.tag_configure('secret', foreground=COLORS['red'],
            font=('Consolas', 10, 'bold'))
        self._fv_detail_text.insert('end',
            'Select a credential or service from the left panel to view details.\n\n'
            'Credentials are stored encrypted on disk.\n'
            'Click "Reveal" on any credential to show the full value.\n')

        # Bottom right: Insecure services
        svc_card = Card(right, title="INSECURE SERVICES FOUND")
        svc_card.pack(fill='both', expand=True, pady=(4, 0))

        svc_inner = tk.Frame(svc_card, bg=COLORS['bg_card'])
        svc_inner.pack(fill='both', expand=True)

        svc_canvas = tk.Canvas(svc_inner, bg=COLORS['bg_card'], highlightthickness=0)
        svc_sb = ttk.Scrollbar(svc_inner, orient='vertical', command=svc_canvas.yview)
        self._fv_svc_frame = tk.Frame(svc_canvas, bg=COLORS['bg_card'])
        self._fv_svc_frame.bind('<Configure>',
            lambda e: svc_canvas.configure(scrollregion=svc_canvas.bbox('all')))
        svc_canvas.create_window((0, 0), window=self._fv_svc_frame, anchor='nw')
        svc_canvas.configure(yscrollcommand=svc_sb.set)
        svc_canvas.pack(side='left', fill='both', expand=True)
        svc_sb.pack(side='right', fill='y')

        self._fv_svc_widgets = []

        # Initial load
        self.root.after(1000, self._fv_refresh)

    def _fv_refresh(self):
        """Refresh all forensics data from the database."""
        try:
            db = self.app.forensics_db
            stats = db.get_stats()

            # Update stats bar
            self._fv_stats_label.config(
                text=f"Credentials: {stats['total_credentials']}  |  "
                     f"Services: {stats['total_services']}  |  "
                     f"Sensitive Data: {stats['total_sensitive']}  |  "
                     f"Protocols: {', '.join(stats.get('protocols_seen', [])) or 'none yet'}  |  "
                     f"Encrypted: {'Yes (AES)' if stats.get('encrypted') else 'XOR fallback'}")

            # Load credentials
            self._fv_load_credentials(db.search_credentials())

            # Load services
            self._fv_load_services(db.get_all_services())

        except Exception as e:
            self._fv_stats_label.config(text=f"Error loading forensics data: {e}")

    def _fv_search(self):
        """Search credentials by query and protocol."""
        try:
            db = self.app.forensics_db
            query = self._fv_search_var.get().strip() or None
            proto = self._fv_proto_var.get()
            proto = None if proto == 'ALL' else proto

            results = db.search_credentials(query=query, protocol=proto)
            self._fv_load_credentials(results)
        except Exception as e:
            self._fv_stats_label.config(text=f"Search error: {e}")

    def _fv_load_credentials(self, credentials):
        """Populate the credential list."""
        for w in self._fv_cred_widgets:
            w.destroy()
        self._fv_cred_widgets.clear()

        if not credentials:
            lbl = tk.Label(self._fv_cred_frame, text="No credentials found yet.\n\n"
                "Credentials will appear here when NetSentinel\n"
                "captures plaintext authentication on the network\n"
                "(FTP, HTTP, Telnet, etc.)",
                font=('Segoe UI', 9), fg=COLORS['text_dim'],
                bg=COLORS['bg_card'], justify='center', pady=20)
            lbl.pack(fill='x')
            self._fv_cred_widgets.append(lbl)
            return

        for cred in credentials:
            frame = tk.Frame(self._fv_cred_frame, bg=COLORS['bg_panel'],
                            padx=6, pady=4, cursor='hand2')
            frame.pack(fill='x', padx=2, pady=1)
            self._fv_cred_widgets.append(frame)

            # Risk color
            risk_colors = {'CRITICAL': COLORS['red'], 'HIGH': '#ff6644',
                          'MEDIUM': COLORS['yellow'], 'LOW': COLORS['green']}
            risk_color = risk_colors.get(cred.get('risk', ''), COLORS['text_dim'])

            # Protocol badge
            proto_lbl = tk.Label(frame, text=f" {cred.get('protocol', '?')} ",
                font=('Consolas', 8, 'bold'), fg=COLORS['bg_dark'],
                bg=risk_color)
            proto_lbl.pack(side='left', padx=(0, 6))

            # Credential type and masked value
            info_text = f"{cred.get('credential_type', '?')}: {cred.get('value', '***')}"
            info_lbl = tk.Label(frame, text=info_text, font=('Consolas', 9),
                fg=COLORS['text'], bg=COLORS['bg_panel'], anchor='w')
            info_lbl.pack(side='left', fill='x', expand=True)

            # Connection info
            time_str = cred.get('time_str', '')
            conn = f"{cred.get('source_ip', '?')} → {cred.get('destination_ip', '?')}:{cred.get('port', '?')}"
            conn_lbl = tk.Label(frame, text=f"{conn}  {time_str}",
                font=('Consolas', 7), fg=COLORS['text_dim'], bg=COLORS['bg_panel'])
            conn_lbl.pack(side='right')

            # Reveal button
            cred_id = cred.get('id', '')
            reveal_btn = tk.Button(frame, text="🔓 Reveal",
                font=('Segoe UI', 7), bg=COLORS['bg_input'], fg=COLORS['yellow'],
                relief='flat', cursor='hand2',
                command=lambda c=cred, cid=cred_id: self._fv_show_credential_detail(c, cid))
            reveal_btn.pack(side='right', padx=4)

            # Click anywhere to show detail (without reveal)
            for widget in [frame, proto_lbl, info_lbl, conn_lbl]:
                widget.bind('<Button-1>',
                    lambda e, c=cred: self._fv_show_credential_detail(c))

    def _fv_show_credential_detail(self, cred, reveal_id=None):
        """Show detailed view of a credential, optionally revealing the raw value."""
        dt = self._fv_detail_text
        dt.delete('1.0', 'end')

        protocol = cred.get('protocol', '?')
        cred_type = cred.get('credential_type', '?')
        port = cred.get('port', 0)

        dt.insert('end', f'{protocol} CREDENTIAL\n', 'header')
        dt.insert('end', '─' * 40 + '\n\n')

        dt.insert('end', 'Type:        ', 'key')
        dt.insert('end', f'{cred_type}\n')
        dt.insert('end', 'Protocol:    ', 'key')
        dt.insert('end', f'{protocol}\n')
        dt.insert('end', 'Source:      ', 'key')
        dt.insert('end', f"{cred.get('source_ip', '?')}\n")
        dt.insert('end', 'Destination: ', 'key')
        dt.insert('end', f"{cred.get('destination_ip', '?')}:{port}\n")
        dt.insert('end', 'Captured:    ', 'key')
        dt.insert('end', f"{cred.get('time_str', '?')}\n\n")

        # Masked value
        dt.insert('end', 'Value (masked): ', 'key')
        dt.insert('end', f"{cred.get('value', '***')}\n")

        # Reveal raw value if requested
        if reveal_id:
            try:
                raw = self.app.forensics_db.get_credential_raw(reveal_id)
                if raw:
                    dt.insert('end', '\nFull Value:   ', 'key')
                    dt.insert('end', f'{raw}\n', 'secret')
                    dt.insert('end', '\n⚠ This is the actual captured credential.\n', 'warn')
                    dt.insert('end', 'Change this password immediately if still in use.\n', 'warn')
                else:
                    dt.insert('end', '\nRaw value not available for this entry.\n', 'warn')
            except Exception as e:
                dt.insert('end', f'\nCould not decrypt: {e}\n', 'crit')

        # Extra info
        extra = cred.get('extra', {})
        if extra:
            dt.insert('end', '\nAdditional Context:\n', 'key')
            for k, v in extra.items():
                if v:
                    dt.insert('end', f'  {k}: {v}\n')

        # Exploitation info
        from src.forensics import PROTOCOL_EXPLOITATION, DEFAULT_EXPLOITATION
        exploit = PROTOCOL_EXPLOITATION.get(port, DEFAULT_EXPLOITATION)

        dt.insert('end', '\n\nHOW THIS IS EXPLOITED\n', 'header')
        dt.insert('end', '─' * 40 + '\n')
        dt.insert('end', f"{exploit['how_exploited']}\n", 'crit')

        dt.insert('end', '\nHOW TO FIX\n', 'header')
        dt.insert('end', '─' * 40 + '\n')
        dt.insert('end', f"{exploit['how_to_fix']}\n", 'safe')

        dt.insert('end', '\nIS THIS CURRENTLY MALICIOUS?\n', 'header')
        dt.insert('end', '─' * 40 + '\n')
        dt.insert('end', f"{exploit['currently_malicious']}\n", 'warn')

    def _fv_load_services(self, services):
        """Populate the insecure services list."""
        for w in self._fv_svc_widgets:
            w.destroy()
        self._fv_svc_widgets.clear()

        if not services:
            lbl = tk.Label(self._fv_svc_frame, text="No insecure services detected yet.",
                font=('Segoe UI', 9), fg=COLORS['text_dim'],
                bg=COLORS['bg_card'], pady=10)
            lbl.pack(fill='x')
            self._fv_svc_widgets.append(lbl)
            return

        for svc in services:
            frame = tk.Frame(self._fv_svc_frame, bg=COLORS['bg_panel'],
                            padx=6, pady=4, cursor='hand2')
            frame.pack(fill='x', padx=2, pady=1)
            self._fv_svc_widgets.append(frame)

            risk_colors = {'CRITICAL': COLORS['red'], 'HIGH': '#ff6644',
                          'MEDIUM': COLORS['yellow'], 'LOW': COLORS['green']}
            risk_color = risk_colors.get(svc.get('risk', ''), COLORS['text_dim'])

            risk_lbl = tk.Label(frame, text=f" {svc.get('risk', '?')} ",
                font=('Consolas', 8, 'bold'), fg=COLORS['bg_dark'], bg=risk_color)
            risk_lbl.pack(side='left', padx=(0, 6))

            svc_text = f"{svc.get('service', '?')} at {svc.get('ip', '?')}:{svc.get('port', '?')}"
            svc_lbl = tk.Label(frame, text=svc_text, font=('Consolas', 9),
                fg=COLORS['text'], bg=COLORS['bg_panel'], anchor='w')
            svc_lbl.pack(side='left', fill='x', expand=True)

            count_lbl = tk.Label(frame,
                text=f"seen {svc.get('seen_count', 1)}x",
                font=('Consolas', 7), fg=COLORS['text_dim'], bg=COLORS['bg_panel'])
            count_lbl.pack(side='right')

            # Click to show detail
            for widget in [frame, risk_lbl, svc_lbl]:
                widget.bind('<Button-1>',
                    lambda e, s=svc: self._fv_show_service_detail(s))

    def _fv_show_service_detail(self, svc):
        """Show detailed view of an insecure service."""
        dt = self._fv_detail_text
        dt.delete('1.0', 'end')

        port = svc.get('port', 0)
        service = svc.get('service', '?')

        dt.insert('end', f'INSECURE SERVICE: {service}\n', 'header')
        dt.insert('end', '─' * 40 + '\n\n')

        dt.insert('end', 'Service:     ', 'key')
        dt.insert('end', f"{service}\n")
        dt.insert('end', 'Server:      ', 'key')
        dt.insert('end', f"{svc.get('ip', '?')}:{port}\n")
        dt.insert('end', 'Risk:        ', 'key')
        risk = svc.get('risk', '?')
        dt.insert('end', f"{risk}\n", 'crit' if risk in ('CRITICAL', 'HIGH') else 'warn')
        dt.insert('end', 'First Seen:  ', 'key')
        from datetime import datetime
        first = svc.get('first_seen', 0)
        dt.insert('end', f"{datetime.fromtimestamp(first).strftime('%Y-%m-%d %H:%M:%S') if first else '?'}\n")
        dt.insert('end', 'Last Seen:   ', 'key')
        last = svc.get('last_seen', 0)
        dt.insert('end', f"{datetime.fromtimestamp(last).strftime('%Y-%m-%d %H:%M:%S') if last else '?'}\n")
        dt.insert('end', 'Times Seen:  ', 'key')
        dt.insert('end', f"{svc.get('seen_count', 1)}\n\n")

        dt.insert('end', 'Description:\n', 'key')
        dt.insert('end', f"  {svc.get('description', '')}\n\n")

        from src.forensics import PROTOCOL_EXPLOITATION, DEFAULT_EXPLOITATION, SECURE_EQUIVALENTS
        exploit = PROTOCOL_EXPLOITATION.get(port, DEFAULT_EXPLOITATION)

        dt.insert('end', 'HOW THIS IS EXPLOITED\n', 'header')
        dt.insert('end', '─' * 40 + '\n')
        dt.insert('end', f"{exploit['how_exploited']}\n\n", 'crit')

        dt.insert('end', 'HOW TO FIX\n', 'header')
        dt.insert('end', '─' * 40 + '\n')
        dt.insert('end', f"{exploit['how_to_fix']}\n\n", 'safe')
        alt = SECURE_EQUIVALENTS.get(port, '')
        if alt:
            dt.insert('end', f'Secure Alternative: {alt}\n\n', 'safe')

        dt.insert('end', 'IS THIS CURRENTLY MALICIOUS?\n', 'header')
        dt.insert('end', '─' * 40 + '\n')
        dt.insert('end', f"{exploit['currently_malicious']}\n", 'warn')

    def _fv_clear_all(self):
        """Clear all forensics data after confirmation."""
        if messagebox.askyesno("Clear Forensics Data",
                "This will permanently delete ALL captured credentials,\n"
                "insecure service records, and sensitive data findings.\n\n"
                "The encrypted database files will be erased.\n\n"
                "Are you sure?"):
            try:
                self.app.forensics_db.clear_all()
                self._fv_refresh()
                messagebox.showinfo("Cleared", "All forensics data has been erased.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear data: {e}")

    def _fv_export(self):
        """Export forensics data."""
        try:
            db = self.app.forensics_db
            creds = db.search_credentials()
            services = db.get_all_services()
            sensitive = db.get_all_sensitive()

            if not creds and not services and not sensitive:
                messagebox.showinfo("Export", "No forensics data to export.")
                return

            filepath = filedialog.asksaveasfilename(
                defaultextension='.json',
                filetypes=[('JSON', '*.json')],
                title='Export Forensics Data (credentials will be masked)')
            if not filepath:
                return

            import json
            data = {
                'exported_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'note': 'Credential values are MASKED in this export. Use the app to reveal full values.',
                'credentials': creds,
                'insecure_services': services,
                'sensitive_data': sensitive,
            }
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            messagebox.showinfo("Export", f"Forensics data exported to {filepath}\n\n"
                "Note: Credential values are masked. Full values remain\n"
                "in the encrypted database only.")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Forensics Vault Tab
    # ──────────────────────────────────────────────────────────────────────────
    def _build_forensics_tab(self, parent):
        # Top controls
        ctrl_frame = tk.Frame(parent, bg=COLORS['bg_dark'])
        ctrl_frame.pack(fill='x', padx=8, pady=8)

        tk.Label(ctrl_frame, text="Encrypted credential vault & security findings",
                font=('Segoe UI', 9), fg=COLORS['text_dim'],
                bg=COLORS['bg_dark']).pack(side='left')

        tk.Button(ctrl_frame, text="🗑  Clear All Data", font=('Segoe UI', 8),
                  bg=COLORS['red_dim'], fg=COLORS['text'], relief='flat',
                  cursor='hand2', command=self._forensics_clear
        ).pack(side='right', padx=4)

        tk.Button(ctrl_frame, text="🔄  Refresh", font=('Segoe UI', 8),
                  bg=COLORS['bg_input'], fg=COLORS['text_dim'], relief='flat',
                  cursor='hand2', command=self._forensics_refresh
        ).pack(side='right', padx=4)

        # Search bar
        search_frame = tk.Frame(parent, bg=COLORS['bg_dark'])
        search_frame.pack(fill='x', padx=8, pady=(0, 8))

        tk.Label(search_frame, text="Search:", font=('Segoe UI', 9),
                fg=COLORS['text_dim'], bg=COLORS['bg_dark']).pack(side='left')

        self._forensics_search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self._forensics_search_var,
                                font=('Consolas', 10), bg=COLORS['bg_input'],
                                fg=COLORS['text'], insertbackground=COLORS['text'],
                                relief='flat', width=30)
        search_entry.pack(side='left', padx=(4, 8), fill='x', expand=True)
        search_entry.bind('<Return>', lambda e: self._forensics_search())

        tk.Label(search_frame, text="Protocol:", font=('Segoe UI', 9),
                fg=COLORS['text_dim'], bg=COLORS['bg_dark']).pack(side='left')
        self._forensics_proto_var = tk.StringVar(value='All')
        proto_menu = ttk.Combobox(search_frame, textvariable=self._forensics_proto_var,
                                   values=['All', 'FTP', 'HTTP', 'Telnet', 'POP3', 'IMAP',
                                           'SMTP', 'SNMP', 'Redis', 'MongoDB', 'RTSP/Camera',
                                           'IRC', 'SIP/VoIP', 'BACnet', 'Modbus/SCADA'],
                                   width=14, state='readonly')
        proto_menu.pack(side='left', padx=4)

        tk.Button(search_frame, text="🔍  Search", font=('Segoe UI', 9, 'bold'),
                  bg=COLORS['accent'], fg=COLORS['bg_dark'], relief='flat',
                  padx=12, cursor='hand2', command=self._forensics_search
        ).pack(side='left', padx=4)

        # Stats bar
        stats_frame = tk.Frame(parent, bg=COLORS['bg_panel'])
        stats_frame.pack(fill='x', padx=8, pady=(0, 4))
        self._forensics_stats_label = tk.Label(stats_frame,
            text="Loading...", font=('Consolas', 8),
            fg=COLORS['text_dim'], bg=COLORS['bg_panel'], anchor='w', padx=8)
        self._forensics_stats_label.pack(fill='x')

        # Main content: three panels
        content = tk.Frame(parent, bg=COLORS['bg_dark'])
        content.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        # Left: Credentials
        left_card = Card(content, title="CAPTURED CREDENTIALS")
        left_card.pack(side='left', fill='both', expand=True, padx=(0, 4))

        left_inner = tk.Frame(left_card, bg=COLORS['bg_card'])
        left_inner.pack(fill='both', expand=True)

        # Credential list with scrollbar
        cred_canvas = tk.Canvas(left_inner, bg=COLORS['bg_card'], highlightthickness=0)
        cred_sb = ttk.Scrollbar(left_inner, orient='vertical', command=cred_canvas.yview)
        self._forensics_cred_frame = tk.Frame(cred_canvas, bg=COLORS['bg_card'])
        self._forensics_cred_frame.bind('<Configure>',
            lambda e: cred_canvas.configure(scrollregion=cred_canvas.bbox('all')))
        cred_canvas.create_window((0, 0), window=self._forensics_cred_frame, anchor='nw')
        cred_canvas.configure(yscrollcommand=cred_sb.set)
        cred_canvas.pack(side='left', fill='both', expand=True)
        cred_sb.pack(side='right', fill='y')

        # Right: Services + Sensitive Data
        right_frame = tk.Frame(content, bg=COLORS['bg_dark'])
        right_frame.pack(side='left', fill='both', expand=True, padx=(4, 0))

        # Services
        svc_card = Card(right_frame, title="INSECURE SERVICES FOUND")
        svc_card.pack(fill='both', expand=True, pady=(0, 4))

        self._forensics_svc_text = tk.Text(svc_card, bg=COLORS['bg_card'],
            fg=COLORS['text'], font=('Consolas', 9), relief='flat',
            wrap='word', padx=8, pady=8, height=8)
        self._forensics_svc_text.pack(fill='both', expand=True)
        self._forensics_svc_text.tag_configure('header', foreground=COLORS['accent'],
                                                font=('Consolas', 9, 'bold'))
        self._forensics_svc_text.tag_configure('critical', foreground=COLORS['red'])
        self._forensics_svc_text.tag_configure('high', foreground='#ff8800')
        self._forensics_svc_text.tag_configure('medium', foreground=COLORS['yellow'])
        self._forensics_svc_text.tag_configure('safe', foreground=COLORS['green'])

        # Sensitive data
        sens_card = Card(right_frame, title="SENSITIVE DATA DETECTED")
        sens_card.pack(fill='both', expand=True, pady=(4, 0))

        self._forensics_sens_text = tk.Text(sens_card, bg=COLORS['bg_card'],
            fg=COLORS['text'], font=('Consolas', 9), relief='flat',
            wrap='word', padx=8, pady=8, height=8)
        self._forensics_sens_text.pack(fill='both', expand=True)
        self._forensics_sens_text.tag_configure('header', foreground=COLORS['accent'],
                                                 font=('Consolas', 9, 'bold'))
        self._forensics_sens_text.tag_configure('critical', foreground=COLORS['red'])

        self._forensics_cred_widgets = []

        # Initial load
        self.root.after(1000, self._forensics_refresh)

    def _forensics_refresh(self):
        """Reload all forensics data from the database."""
        try:
            db = self.app.forensics_db
            stats = db.get_stats()

            # Update stats bar
            self._forensics_stats_label.config(
                text=f"Credentials: {stats['total_credentials']}  |  "
                     f"Services: {stats['total_services']}  |  "
                     f"Sensitive: {stats['total_sensitive']}  |  "
                     f"Protocols: {', '.join(stats.get('protocols_seen', [])) or 'none'}  |  "
                     f"Encrypted: {'Yes (AES)' if stats.get('encrypted') else 'XOR fallback'}")

            # Load credentials (masked)
            self._forensics_show_credentials(db.search_credentials())

            # Load services
            self._forensics_show_services(db.get_all_services())

            # Load sensitive data
            self._forensics_show_sensitive(db.get_all_sensitive())

        except Exception as e:
            self._forensics_stats_label.config(text=f"Error: {e}")

    def _forensics_search(self):
        """Search credentials by query/protocol."""
        try:
            db = self.app.forensics_db
            query = self._forensics_search_var.get().strip() or None
            proto = self._forensics_proto_var.get()
            proto = None if proto == 'All' else proto

            results = db.search_credentials(query=query, protocol=proto)
            self._forensics_show_credentials(results)
        except Exception as e:
            pass

    def _forensics_show_credentials(self, credentials):
        """Display credential list."""
        for w in self._forensics_cred_widgets:
            w.destroy()
        self._forensics_cred_widgets.clear()

        if not credentials:
            lbl = tk.Label(self._forensics_cred_frame, text="No credentials found.\n\n"
                "Credentials are captured from unencrypted protocols\n"
                "(FTP, HTTP, Telnet, etc.) during live monitoring\n"
                "or PCAP analysis.",
                font=('Segoe UI', 9), fg=COLORS['text_dim'],
                bg=COLORS['bg_card'], justify='left')
            lbl.pack(padx=10, pady=20)
            self._forensics_cred_widgets.append(lbl)
            return

        for cred in credentials:
            frame = tk.Frame(self._forensics_cred_frame, bg=COLORS['bg_panel'],
                            padx=8, pady=6)
            frame.pack(fill='x', padx=2, pady=2)
            self._forensics_cred_widgets.append(frame)

            # Protocol badge + type
            proto = cred.get('protocol', '?')
            cred_type = cred.get('credential_type', '?')
            badge_color = COLORS['red'] if proto in ('FTP', 'Telnet', 'VNC') else COLORS['yellow']

            header = tk.Frame(frame, bg=COLORS['bg_panel'])
            header.pack(fill='x')

            tk.Label(header, text=f" {proto} ", font=('Consolas', 8, 'bold'),
                    fg=COLORS['bg_dark'], bg=badge_color).pack(side='left')
            tk.Label(header, text=f"  {cred_type}", font=('Consolas', 9, 'bold'),
                    fg=COLORS['text'], bg=COLORS['bg_panel']).pack(side='left')
            tk.Label(header, text=cred.get('time_str', ''),
                    font=('Consolas', 8), fg=COLORS['text_dim'],
                    bg=COLORS['bg_panel']).pack(side='right')

            # Connection info
            src = cred.get('source_ip', '?')
            dst = cred.get('destination_ip', '?')
            port = cred.get('port', '?')
            tk.Label(frame, text=f"{src} → {dst}:{port}",
                    font=('Consolas', 9), fg=COLORS['accent'],
                    bg=COLORS['bg_panel'], anchor='w').pack(fill='x')

            # Masked value
            val = cred.get('value', '?')
            tk.Label(frame, text=f"Value: {val}",
                    font=('Consolas', 9), fg=COLORS['yellow'],
                    bg=COLORS['bg_panel'], anchor='w').pack(fill='x')

            # Extra info
            extra = cred.get('extra', {})
            if extra:
                for k, v in extra.items():
                    if v:
                        tk.Label(frame, text=f"{k}: {v}",
                                font=('Consolas', 8), fg=COLORS['text_dim'],
                                bg=COLORS['bg_panel'], anchor='w').pack(fill='x')

            # Reveal button
            cred_id = cred.get('id', '')
            if cred_id:
                btn_frame = tk.Frame(frame, bg=COLORS['bg_panel'])
                btn_frame.pack(fill='x', pady=(4, 0))
                reveal_btn = tk.Button(btn_frame, text="🔓 Reveal Full Value",
                    font=('Segoe UI', 8), bg=COLORS['bg_input'],
                    fg=COLORS['yellow'], relief='flat', cursor='hand2',
                    command=lambda cid=cred_id, p=proto, d=dst, pt=port:
                        self._forensics_reveal(cid, p, d, pt))
                reveal_btn.pack(side='left')

                copy_btn = tk.Button(btn_frame, text="📋 Copy",
                    font=('Segoe UI', 8), bg=COLORS['bg_input'],
                    fg=COLORS['text_dim'], relief='flat', cursor='hand2',
                    command=lambda cid=cred_id: self._forensics_copy(cid))
                copy_btn.pack(side='left', padx=4)

    def _forensics_reveal(self, cred_id, protocol, dst, port):
        """Show the full unmasked credential value."""
        raw = self.app.forensics_db.get_credential_raw(cred_id)
        if raw:
            # Show in a popup
            popup = tk.Toplevel(self.root)
            popup.title("Credential Value")
            popup.geometry("500x200")
            popup.configure(bg=COLORS['bg_dark'])
            popup.attributes('-topmost', True)

            tk.Label(popup, text=f"{protocol} credential for {dst}:{port}",
                    font=('Segoe UI', 10, 'bold'), fg=COLORS['accent'],
                    bg=COLORS['bg_dark']).pack(padx=12, pady=(12, 4))

            tk.Label(popup, text="⚠ This is the full unmasked value",
                    font=('Segoe UI', 8), fg=COLORS['yellow'],
                    bg=COLORS['bg_dark']).pack()

            val_frame = tk.Frame(popup, bg=COLORS['bg_panel'], padx=12, pady=8)
            val_frame.pack(fill='x', padx=12, pady=8)

            val_text = tk.Text(val_frame, font=('Consolas', 12), fg=COLORS['green'],
                              bg=COLORS['bg_panel'], relief='flat', height=2, wrap='word')
            val_text.insert('1.0', raw)
            val_text.config(state='disabled')
            val_text.pack(fill='x')

            btn_frame = tk.Frame(popup, bg=COLORS['bg_dark'])
            btn_frame.pack(pady=4)

            tk.Button(btn_frame, text="📋 Copy to Clipboard",
                     font=('Segoe UI', 9), bg=COLORS['accent'],
                     fg=COLORS['bg_dark'], relief='flat', padx=12,
                     command=lambda: [self.root.clipboard_clear(),
                                      self.root.clipboard_append(raw)]
            ).pack(side='left', padx=4)

            tk.Button(btn_frame, text="Close", font=('Segoe UI', 9),
                     bg=COLORS['bg_input'], fg=COLORS['text_dim'],
                     relief='flat', padx=12, command=popup.destroy
            ).pack(side='left', padx=4)
        else:
            messagebox.showinfo("Not Found", "Raw value not available for this credential.")

    def _forensics_copy(self, cred_id):
        """Copy credential to clipboard."""
        raw = self.app.forensics_db.get_credential_raw(cred_id)
        if raw:
            self.root.clipboard_clear()
            self.root.clipboard_append(raw)

    def _forensics_show_services(self, services):
        """Display insecure services inventory."""
        st = self._forensics_svc_text
        st.config(state='normal')
        st.delete('1.0', 'end')

        if not services:
            st.insert('end', "No insecure services detected yet.\n\n"
                "Services are flagged when unencrypted protocol\n"
                "traffic is observed (FTP, Telnet, HTTP, etc.).")
            st.config(state='disabled')
            return

        from src.forensics import SECURE_EQUIVALENTS, PROTOCOL_EXPLOITATION, DEFAULT_EXPLOITATION

        for svc in services:
            risk = svc.get('risk', 'MEDIUM')
            tag = risk.lower() if risk.lower() in ('critical', 'high', 'medium') else 'medium'
            port = svc.get('port', 0)

            st.insert('end', f"[{risk}] ", tag)
            st.insert('end', f"{svc.get('service', '?')} ", 'header')
            st.insert('end', f"at {svc.get('ip', '?')}:{port}\n")
            st.insert('end', f"  {svc.get('description', '')}\n")
            st.insert('end', f"  Seen {svc.get('seen_count', 1)}x, "
                             f"last: {svc.get('last_seen', '?')}\n" if isinstance(svc.get('last_seen'), str)
                      else f"  Seen {svc.get('seen_count', 1)}x\n")

            alt = SECURE_EQUIVALENTS.get(port, '')
            if alt:
                st.insert('end', f"  Fix: ", 'header')
                st.insert('end', f"Use {alt}\n", 'safe')

            exploit = PROTOCOL_EXPLOITATION.get(port, DEFAULT_EXPLOITATION)
            st.insert('end', f"  Risk: {exploit.get('currently_malicious', '')[:100]}\n")
            st.insert('end', '\n')

        st.config(state='disabled')

    def _forensics_show_sensitive(self, items):
        """Display sensitive data findings."""
        st = self._forensics_sens_text
        st.config(state='normal')
        st.delete('1.0', 'end')

        if not items:
            st.insert('end', "No sensitive data detected in transit.\n\n"
                "This monitors for private keys, credit cards,\n"
                "SSNs, and other sensitive data in unencrypted traffic.")
            st.config(state='disabled')
            return

        for item in items[-50:]:  # Show last 50
            risk = item.get('risk', 'HIGH')
            tag = 'critical' if risk == 'CRITICAL' else 'header'

            st.insert('end', f"[{risk}] ", tag)
            st.insert('end', f"{item.get('data_type', '?')}\n", 'header')
            st.insert('end', f"  {item.get('value', '')[:80]}\n")
            st.insert('end', f"  {item.get('source_ip', '?')} → "
                             f"{item.get('destination_ip', '?')}:{item.get('port', '?')}\n")
            if item.get('time_str'):
                st.insert('end', f"  {item['time_str']}\n")
            st.insert('end', '\n')

        st.config(state='disabled')

    def _forensics_clear(self):
        """Clear all forensics data."""
        if messagebox.askyesno("Clear Forensics Data",
                "This will permanently delete all captured credentials,\n"
                "service findings, and sensitive data.\n\n"
                "Are you sure?"):
            self.app.forensics_db.clear_all()
            self._forensics_refresh()

    # ──────────────────────────────────────────────────────────────────────────
    # Settings Tab
    # ──────────────────────────────────────────────────────────────────────────
    def _build_settings_tab(self, parent):
        canvas = tk.Canvas(parent, bg=COLORS['bg_dark'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient='vertical', command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg=COLORS['bg_dark'])
        scroll_frame.bind('<Configure>',
                         lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.create_window((0, 0), window=scroll_frame, anchor='nw')
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # IDS Settings
        ids_card = Card(scroll_frame, title="INTRUSION DETECTION")
        ids_card.pack(fill='x', padx=8, pady=8)

        self._setting_widgets = {}
        ids_settings = [
            ('ids.port_scan_threshold', 'Port Scan Threshold (ports)', '15'),
            ('ids.port_scan_window_sec', 'Port Scan Window (sec)', '60'),
            ('ids.brute_force_threshold', 'Brute Force Threshold', '10'),
            ('ids.large_upload_mb', 'Large Upload Alert (MB)', '100'),
        ]
        for key, label, default in ids_settings:
            self._add_setting_row(ids_card, key, label, default)

        # ML Settings
        ml_card = Card(scroll_frame, title="MACHINE LEARNING")
        ml_card.pack(fill='x', padx=8, pady=(0, 8))

        ml_settings = [
            ('ml.anomaly_threshold', 'Anomaly Threshold (0-1)', '0.15'),
            ('ml.min_samples_for_training', 'Min Training Samples', '200'),
            ('ml.retrain_interval_min', 'Retrain Interval (min)', '60'),
            ('ml.feature_history_days', 'Feature History Retention (days)', '90'),
            ('ml.feature_history_training_days', 'History Used for Training (days)', '7'),
        ]
        for key, label, default in ml_settings:
            self._add_setting_row(ml_card, key, label, default)

        # Alert Settings
        alert_card = Card(scroll_frame, title="ALERTS")
        alert_card.pack(fill='x', padx=8, pady=(0, 8))

        alert_settings = [
            ('alerts.cooldown_sec', 'Alert Cooldown (sec)', '30'),
            ('alerts.severity_filter', 'Min Severity Filter', 'LOW'),
        ]
        for key, label, default in alert_settings:
            self._add_setting_row(alert_card, key, label, default)

        # Blacklist management
        bl_card = Card(scroll_frame, title="BLACKLISTED IPs (one per line)")
        bl_card.pack(fill='x', padx=8, pady=(0, 8))

        self._blacklist_text = tk.Text(bl_card, bg=COLORS['bg_input'],
                                        fg=COLORS['text'], font=('Consolas', 9),
                                        height=5, relief='flat')
        self._blacklist_text.pack(fill='x', pady=4)
        current_bl = self.app.config.get('blacklists', 'ips', default=[])
        self._blacklist_text.insert('1.0', '\n'.join(current_bl))

        # Save button
        save_btn = tk.Button(scroll_frame, text="💾  Save Settings",
                            font=('Segoe UI', 10, 'bold'),
                            bg=COLORS['accent'], fg=COLORS['bg_dark'],
                            relief='flat', padx=20, pady=8,
                            cursor='hand2', command=self._save_settings)
        save_btn.pack(pady=16)

    def _add_setting_row(self, parent, key, label, default):
        row = tk.Frame(parent, bg=COLORS['bg_card'])
        row.pack(fill='x', pady=3)
        tk.Label(row, text=label, font=('Segoe UI', 9),
                fg=COLORS['text_dim'], bg=COLORS['bg_card'],
                width=30, anchor='w').pack(side='left')
        entry = tk.Entry(row, bg=COLORS['bg_input'], fg=COLORS['text'],
                        font=('Consolas', 9), relief='flat',
                        insertbackground=COLORS['accent'], width=15)
        # Load current value
        parts = key.split('.')
        current = self.app.config.get(*parts, default=default)
        entry.insert(0, str(current))
        entry.pack(side='left', padx=8)
        self._setting_widgets[key] = entry

    def _save_settings(self):
        """Save all settings from the UI to config."""
        for key, entry in self._setting_widgets.items():
            parts = key.split('.')
            val = entry.get()
            try:
                # Try to cast to appropriate type
                if '.' in val:
                    val = float(val)
                else:
                    val = int(val)
            except ValueError:
                pass
            self.app.config.set(*parts, val)

        # Save blacklist
        bl_text = self._blacklist_text.get('1.0', 'end').strip()
        bl_ips = [ip.strip() for ip in bl_text.split('\n') if ip.strip()]
        self.app.config.set('blacklists', 'ips', bl_ips)

        self.app.config.save()
        messagebox.showinfo("Settings", "Settings saved successfully!")

    # ──────────────────────────────────────────────────────────────────────────
    # Actions
    # ──────────────────────────────────────────────────────────────────────────

    # ──────────────────────────────────────────────────────────────────────────
    # About Dialog
    # ──────────────────────────────────────────────────────────────────────────
    def _show_about(self):
        about = tk.Toplevel(self.root)
        about.title("About NetSentinel")
        about.geometry("600x720")
        about.configure(bg='#0a0e1a')
        about.resizable(False, False)
        about.attributes('-topmost', True)

        try:
            import sys as _sys
            _app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if getattr(_sys, '_MEIPASS', None):
                _app_dir = _sys._MEIPASS
            ico = os.path.join(_app_dir, 'assets', 'netsentinel.ico')
            if os.path.exists(ico):
                about.iconbitmap(ico)
        except Exception:
            pass

        canvas = tk.Canvas(about, bg='#0a0e1a', highlightthickness=0)
        canvas.pack(fill='both', expand=True)

        w = 600

        # Shield icon (drawn on canvas)
        cx, cy = w // 2, 65
        sz = 40
        shield = [
            (cx, cy - sz), (cx + sz*0.8, cy - sz*0.55),
            (cx + sz*0.7, cy + sz*0.35), (cx, cy + sz*0.85),
            (cx - sz*0.7, cy + sz*0.35), (cx - sz*0.8, cy - sz*0.55),
        ]
        canvas.create_polygon(shield, fill='#0c1220', outline='#00b4ff', width=2)
        for r in [10, 16, 22]:
            canvas.create_arc(cx-r, cy-r+4, cx+r, cy+r+4,
                             start=200, extent=140, style='arc',
                             outline='#0088cc', width=1)
        canvas.create_oval(cx-4, cy, cx+4, cy+8, fill='#00e5ff', outline='white', width=1)
        for nx, ny in [(cx-14, cy-12), (cx+14, cy-10), (cx-10, cy+14),
                       (cx+10, cy+14), (cx, cy-18)]:
            canvas.create_line(cx, cy+4, nx, ny, fill='#005588', width=1)
            canvas.create_oval(nx-2, ny-2, nx+2, ny+2, fill='#00ccff', outline='')

        # Title
        canvas.create_text(w//2, 125, text="NETSENTINEL",
                          font=('Consolas', 22, 'bold'), fill='#00ccff')
        canvas.create_text(w//2, 150, text="Network Monitor & Intrusion Detection System",
                          font=('Segoe UI', 10), fill='#6688aa')
        canvas.create_text(w//2, 172, text="Version 1.0.0",
                          font=('Consolas', 9), fill='#445566')

        # Separator
        canvas.create_line(60, 195, w-60, 195, fill='#1a2535', width=1)

        # What it does - scrollable text area
        y_start = 210
        info_text = tk.Text(about, bg='#0c1018', fg='#aabbcc',
                           font=('Segoe UI', 9), relief='flat',
                           wrap='word', padx=20, pady=12,
                           highlightthickness=1, highlightbackground='#1a2535')
        info_text.place(x=30, y=y_start, width=w-60, height=420)

        info_text.tag_configure('h1', foreground='#00ccff',
                                font=('Consolas', 11, 'bold'))
        info_text.tag_configure('h2', foreground='#00aadd',
                                font=('Segoe UI', 9, 'bold'))
        info_text.tag_configure('bullet', foreground='#88aacc',
                                font=('Segoe UI', 9))
        info_text.tag_configure('accent', foreground='#00e5ff')
        info_text.tag_configure('warn', foreground='#ffaa00')

        t = info_text
        t.insert('end', 'WHAT IS NETSENTINEL?\n', 'h1')
        t.insert('end', '\n')
        t.insert('end', 'NetSentinel is an AI-powered network security monitor that watches ')
        t.insert('end', 'every packet on your network in real-time. It combines signature-based ')
        t.insert('end', 'intrusion detection, machine learning anomaly detection, threat ')
        t.insert('end', 'intelligence feeds, and deep protocol forensics to catch threats that ')
        t.insert('end', 'simpler tools miss.\n\n')

        t.insert('end', 'DETECTION ENGINES\n', 'h1')
        t.insert('end', '\n')
        t.insert('end', '  IDS Engine', 'h2')
        t.insert('end', ' — 12 signature rules\n')
        t.insert('end', '  Port scans, brute force, SYN floods, DNS tunneling, ARP spoofing,\n', 'bullet')
        t.insert('end', '  data exfiltration, threat intel IP/domain matching, and more.\n\n', 'bullet')

        t.insert('end', '  ML Anomaly Detector', 'h2')
        t.insert('end', ' — Isolation Forest + statistical baseline\n')
        t.insert('end', '  Learns your network\'s normal behavior, then flags deviations.\n', 'bullet')
        t.insert('end', '  Detects beaconing, unusual port diversity, traffic spikes.\n\n', 'bullet')

        t.insert('end', '  Threat Intelligence', 'h2')
        t.insert('end', ' — 6 free feeds, auto-updated\n')
        t.insert('end', '  Feodo Tracker, SSL Blacklist, URLhaus, Emerging Threats,\n', 'bullet')
        t.insert('end', '  DShield, blocklist.de. Cloud-aware to reduce false positives.\n\n', 'bullet')

        t.insert('end', '  Network Forensics', 'h2')
        t.insert('end', ' — credential & protocol scanner\n')
        t.insert('end', '  Captures plaintext credentials from 50+ insecure protocols:\n', 'bullet')
        t.insert('end', '  FTP, HTTP, Telnet, SMTP, POP3, SNMP, Redis, MongoDB, VNC,\n', 'bullet')
        t.insert('end', '  cameras (RTSP), IoT (MQTT), SCADA (Modbus, BACnet).\n', 'bullet')
        t.insert('end', '  All saved to an AES-256 encrypted vault.\n\n', 'bullet')

        t.insert('end', '  IOC Scanner', 'h2')
        t.insert('end', ' — indicators of compromise\n')
        t.insert('end', '  TOR exit nodes, DGA domains, DoH bypass, suspicious processes.\n\n', 'bullet')

        t.insert('end', 'KEY FEATURES\n', 'h1')
        t.insert('end', '\n')
        t.insert('end', '  ✓ ', 'accent')
        t.insert('end', 'Unified Alert Verification — every alert auto-analyzed for false positives\n')
        t.insert('end', '  ✓ ', 'accent')
        t.insert('end', 'PCAP Analyzer — load Wireshark captures for offline analysis\n')
        t.insert('end', '  ✓ ', 'accent')
        t.insert('end', 'Encrypted Forensics Vault — search & retrieve captured credentials\n')
        t.insert('end', '  ✓ ', 'accent')
        t.insert('end', 'DHCP Device Inventory — auto-discovers devices joining the network\n')
        t.insert('end', '  ✓ ', 'accent')
        t.insert('end', 'SMBv1 Detection — flags EternalBlue/WannaCry vulnerable systems\n')
        t.insert('end', '  ✓ ', 'accent')
        t.insert('end', 'mDNS/LLMNR Poisoning Detection — catches Responder-style attacks\n')
        t.insert('end', '  ✓ ', 'accent')
        t.insert('end', 'HTTP Server Fingerprinting — finds outdated/leaking web servers\n')
        t.insert('end', '  ✓ ', 'accent')
        t.insert('end', 'Exploitation guides — how each vulnerability is exploited + how to fix\n')
        t.insert('end', '  ✓ ', 'accent')
        t.insert('end', 'Cloud-aware — 300+ cloud domains whitelisted to reduce noise\n')
        t.insert('end', '  ✓ ', 'accent')
        t.insert('end', 'Process Verification — digital signatures, VirusTotal, parent chain\n\n')

        t.insert('end', 'REQUIREMENTS\n', 'h1')
        t.insert('end', '\n')
        t.insert('end', '  • Run as Administrator for full packet capture\n', 'bullet')
        t.insert('end', '  • Npcap installed (npcap.com)\n', 'bullet')
        t.insert('end', '  • Wireshark for tshark PCAP parsing (optional)\n', 'bullet')
        t.insert('end', '  • Data stored at: %USERPROFILE%\\.netsentinel\\\n\n', 'bullet')

        t.insert('end', '12,000+ lines of Python', 'warn')
        t.insert('end', ' — AI-assisted development\n')

        t.config(state='disabled')

        # Close button
        tk.Button(about, text="Close", font=('Segoe UI', 10),
                 bg='#1a2535', fg='#88aacc', relief='flat',
                 padx=20, pady=6, cursor='hand2',
                 command=about.destroy
        ).place(x=w//2 - 40, y=650, width=80)

    def _toggle_monitoring(self):
        if not self._monitoring:
            self._monitoring = True
            self.app.start_monitoring()
            self._start_btn.config(text="■  STOP MONITORING",
                                   bg=COLORS['red_dim'])
            self._status_label.config(text="MONITORING", fg=COLORS['green'])
            self._status_dot.config(fg=COLORS['green'])
            self._statusbar_text.config(text="Monitoring active. Capturing packets...")
        else:
            self._monitoring = False
            self.app.stop_monitoring()
            self._start_btn.config(text="▶  START MONITORING",
                                   bg=COLORS['green_dim'])
            self._status_label.config(text="STOPPED", fg=COLORS['text_dim'])
            self._status_dot.config(fg=COLORS['text_dim'])
            self._statusbar_text.config(text="Monitoring stopped.")

    def _on_new_alert(self, alert):
        """Called from background thread when new alert arrives."""
        # Schedule GUI update on main thread
        try:
            self.root.after(0, self._add_alert_to_gui, alert)
        except Exception:
            pass

    def _add_alert_to_gui(self, alert):
        """Add an alert widget to the alerts tab."""
        # Check filter
        sev_filter = self._alert_filter.get() if hasattr(self, '_alert_filter') else 'ALL'
        if sev_filter != 'ALL' and alert.severity != sev_filter:
            # Still store the widget reference for later filter changes,
            # but don't display it now
            pass
        item = AlertListItem(self._alerts_scroll_frame, alert.to_dict())
        item.pack(fill='x', padx=4, pady=2)
        self._alert_widgets.insert(0, item)

        # If filter is active and this alert doesn't match, hide it
        if sev_filter != 'ALL' and alert.severity != sev_filter:
            item.pack_forget()

        # Limit displayed
        while len(self._alert_widgets) > 200:
            old = self._alert_widgets.pop()
            old.destroy()

    def _refresh_alerts_display(self):
        """Re-render alerts tab based on current filter selection."""
        sev_filter = self._alert_filter.get()

        # Clear existing widgets
        for w in self._alert_widgets:
            w.destroy()
        self._alert_widgets.clear()

        # Reload from alert manager with filter
        severity = None if sev_filter == 'ALL' else sev_filter
        alerts = self.app.alert_manager.get_alerts(limit=200, severity=severity)

        for alert in reversed(alerts):  # oldest first so newest on top
            item = AlertListItem(self._alerts_scroll_frame, alert.to_dict())
            item.pack(fill='x', padx=4, pady=2)
            self._alert_widgets.insert(0, item)

    def _clear_all_alerts(self):
        if messagebox.askyesno("Clear Alerts", "Clear all alerts?"):
            self.app.alert_manager.clear_alerts()
            for w in self._alert_widgets:
                w.destroy()
            self._alert_widgets.clear()

    def _export_alerts(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json'), ('CSV', '*.csv')],
            title='Export Alerts'
        )
        if filepath:
            fmt = 'csv' if filepath.endswith('.csv') else 'json'
            self.app.alert_manager.export_alerts(filepath, format=fmt)
            messagebox.showinfo("Export", f"Alerts exported to {filepath}")

    # ──────────────────────────────────────────────────────────────────────────
    # Update Loop
    # ──────────────────────────────────────────────────────────────────────────

    def _schedule_update(self):
        """Periodic GUI update."""
        self._update_dashboard()
        refresh = self.app.config.get('gui', 'refresh_rate_ms', default=1000)
        self.root.after(refresh, self._schedule_update)

    def _update_dashboard(self):
        """Refresh all dashboard data."""
        if not self._monitoring:
            return

        try:
            data = self.app.get_dashboard_data()
            cap = data.get('capture', {})
            alerts = data.get('alerts', {})
            ml = data.get('ml', {})
            ml_result = data.get('ml_result', {})

            # Metrics
            self._m_packets.set_value(self._format_number(cap.get('packets_captured', 0)))
            bw = cap.get('bytes_per_sec', 0)
            self._m_bandwidth.set_value(self._format_bytes(bw) + "/s")
            self._m_flows.set_value(str(cap.get('flows_active', 0)))
            self._m_alerts.set_value(str(alerts.get('total', 0)),
                                     color=COLORS['red'] if alerts.get('total', 0) > 0
                                     else COLORS['yellow'])

            # Threat level
            score = ml_result.get('anomaly_score', 0)
            if score > 0.7:
                threat, color = "CRITICAL", COLORS['red']
            elif score > 0.4:
                threat, color = "ELEVATED", COLORS['orange']
            elif score > 0.2:
                threat, color = "GUARDED", COLORS['yellow']
            else:
                threat, color = "SAFE", COLORS['green']
            self._m_threat.set_value(threat, color=color)

            # Charts
            self._chart_traffic.add_point(cap.get('packets_per_sec', 0))
            self._chart_bandwidth.add_point(bw / 1024)  # KB/s

            # Protocol breakdown
            self._draw_protocols(cap.get('protocols', {}))

            # Recent alerts on dashboard
            self._update_recent_alerts()

            # Update packet log
            self._update_packet_log()

            # Update flows table
            self._update_flows()

            # Update ML tab
            self._update_ml_tab(ml, ml_result)

            # Status bar
            uptime = time.time() - cap.get('start_time', time.time())
            dev_count = data.get('device_learner', {}).get('total_devices', 0)
            inc_count = data.get('correlator', {}).get('active_incidents', 0)
            pcap_buf = data.get('pcap_writer', {}).get('buffer_packets', 0)
            self._statusbar_right.config(
                text=f"Uptime: {int(uptime//3600)}h {int((uptime%3600)//60)}m  |  "
                     f"PPS: {cap.get('packets_per_sec', 0):.0f}  |  "
                     f"Flows: {cap.get('flows_active', 0)}  |  "
                     f"Devices: {dev_count}  |  "
                     f"Incidents: {inc_count}  |  "
                     f"PCAP buf: {pcap_buf}"
            )

        except Exception as e:
            logger.debug("Dashboard update error: %s", e)

    def _draw_protocols(self, protocols):
        """Draw protocol distribution as horizontal bars."""
        canvas = self._proto_canvas
        canvas.delete('all')
        if not protocols:
            return

        w = canvas.winfo_width() or 300
        h = canvas.winfo_height() or 150

        total = sum(protocols.values()) or 1
        sorted_protos = sorted(protocols.items(), key=lambda x: -x[1])[:8]

        colors = [COLORS['accent'], COLORS['purple'], COLORS['cyan'],
                  COLORS['green'], COLORS['yellow'], COLORS['orange'],
                  COLORS['red'], COLORS['text_dim']]

        bar_h = max(14, (h - 20) // max(len(sorted_protos), 1))
        y = 10

        for i, (proto, count) in enumerate(sorted_protos):
            pct = count / total
            bar_w = max(4, (w - 120) * pct)
            color = colors[i % len(colors)]

            canvas.create_rectangle(80, y, 80 + bar_w, y + bar_h - 2,
                                   fill=color, outline='')
            canvas.create_text(75, y + bar_h//2, text=proto,
                              fill=COLORS['text'], font=('Consolas', 8),
                              anchor='e')
            canvas.create_text(85 + bar_w, y + bar_h//2,
                              text=f"{pct:.1%}", fill=COLORS['text_dim'],
                              font=('Consolas', 8), anchor='w')
            y += bar_h

    def _update_recent_alerts(self):
        """Update the mini alerts on the dashboard — only when new alerts arrive."""
        alerts = self.app.alert_manager.get_alerts(limit=5)

        # Only rebuild if the latest alert changed (prevents flashing)
        latest_id = alerts[0].id if alerts else None
        if hasattr(self, '_last_alert_id') and self._last_alert_id == latest_id:
            return
        self._last_alert_id = latest_id

        for w in self._recent_alerts_frame.winfo_children():
            w.destroy()

        if not alerts:
            tk.Label(self._recent_alerts_frame, text="No alerts yet",
                    font=('Segoe UI', 9), fg=COLORS['text_dim'],
                    bg=COLORS['bg_card']).pack(pady=20)
            return

        for alert in alerts[:5]:
            AlertListItem(self._recent_alerts_frame, alert.to_dict()).pack(fill='x', pady=1)

    def _update_packet_log(self):
        """Update the packet log text widget."""
        if not hasattr(self, '_last_pkt_update'):
            self._last_pkt_update = 0

        # Rate limit updates
        now = time.time()
        if now - self._last_pkt_update < 0.5:
            return
        self._last_pkt_update = now

        # Get recent packets from the capture buffer
        try:
            packets = list(self.app._packet_window)[-20:]  # Last 20
            self._packet_text.delete('1.0', 'end')
            for p in packets:
                ts = datetime.fromtimestamp(p.timestamp).strftime('%H:%M:%S.%f')[:-3]
                proto_tag = p.protocol.lower() if p.protocol.lower() in \
                    ('tcp', 'udp', 'icmp', 'dns', 'arp') else 'other'
                line = (f"{ts}  {p.protocol:<6} {p.src_ip}:{p.src_port} → "
                        f"{p.dst_ip}:{p.dst_port}  len={p.length}")
                if p.dns_query:
                    line += f"  DNS:{p.dns_query}"
                if p.process_name:
                    line += f"  [{p.process_name}]"
                line += "\n"
                self._packet_text.insert('end', line, proto_tag)
        except Exception:
            pass

    def _update_flows(self):
        """Update the flows treeview."""
        if not hasattr(self, '_last_flow_update'):
            self._last_flow_update = 0
        now = time.time()
        if now - self._last_flow_update < 2:
            return
        self._last_flow_update = now

        try:
            self._flows_tree.delete(*self._flows_tree.get_children())
            flows = self.app.capture_engine.get_flows_snapshot()
            sorted_flows = sorted(flows.values(), key=lambda f: -f.byte_count)[:100]

            for flow in sorted_flows:
                state = "EST" if flow.is_established else "NEW"
                if flow.fin_count > 0:
                    state = "FIN"
                if flow.rst_count > 0:
                    state = "RST"

                self._flows_tree.insert('', 'end', values=(
                    flow.flow_key[0],
                    flow.flow_key[1],
                    flow.flow_key[4],
                    flow.packet_count,
                    self._format_bytes(flow.byte_count),
                    f"{flow.duration:.1f}s",
                    self._format_bytes(flow.bytes_per_sec),
                    state,
                ))
        except Exception:
            pass

    def _update_ml_tab(self, ml_status, ml_result):
        """Update ML engine tab."""
        for key, label in self._ml_status_labels.items():
            val = ml_status.get(key, '—')
            if isinstance(val, bool):
                label.config(text="Yes" if val else "No",
                           fg=COLORS['green'] if val else COLORS['red'])
            else:
                label.config(text=str(val))

        # Feature history storage stats
        hist_vals = {
            'history_size_mb': f"{ml_status.get('history_size_mb', 0)} MB",
            'history_rows': str(ml_status.get('history_rows', 0)),
            'history_oldest': ml_status.get('history_oldest', '—'),
            'history_newest': ml_status.get('history_newest', '—'),
        }
        for key, label in self._history_status_labels.items():
            label.config(text=hist_vals.get(key, '—'))

        # Score
        score = ml_result.get('anomaly_score', 0)
        if score > 0.5:
            color = COLORS['red']
        elif score > 0.2:
            color = COLORS['yellow']
        else:
            color = COLORS['green']
        self._ml_score_label.config(text=f"Anomaly Score: {score:.4f}", fg=color)

        # Reasons
        self._ml_reasons_text.delete('1.0', 'end')
        reasons = ml_result.get('reasons', [])
        if reasons:
            for r in reasons:
                self._ml_reasons_text.insert('end', f"⚠ {r}\n")
        else:
            self._ml_reasons_text.insert('end', "✓ No anomalies detected")

        # Features
        self._ml_features_text.delete('1.0', 'end')
        features = ml_result.get('features', {})
        if features:
            for name, val in features.items():
                self._ml_features_text.insert('end', f"{name:<25} {val:.4f}\n")

        # Draw score history chart
        self._draw_score_history()

    def _draw_score_history(self):
        """Draw the anomaly score timeline chart."""
        canvas = self._score_history_canvas
        canvas.delete('all')

        try:
            data = self.app.get_dashboard_data()
            score_history = data.get('score_history', [])
        except Exception:
            score_history = []

        if len(score_history) < 2:
            canvas.create_text(
                canvas.winfo_width() // 2 or 300, 70,
                text="Collecting data...", fill=COLORS['text_dim'],
                font=('Segoe UI', 10)
            )
            return

        w = canvas.winfo_width() or 700
        h = 140
        pad = 20

        scores = [s['anomaly_score'] for s in score_history]
        max_score = max(max(scores), 0.3)  # At least 0.3 for scale
        threshold = self.app.ml_engine.threshold

        # Background grid
        for i in range(5):
            y = pad + (h - 2 * pad) * i / 4
            val = max_score * (1 - i / 4)
            canvas.create_line(pad, y, w - pad, y, fill=COLORS['border'], dash=(2, 4))
            canvas.create_text(pad - 4, y, text=f"{val:.2f}",
                              fill=COLORS['text_dim'], font=('Consolas', 7), anchor='e')

        # Threshold line
        thresh_y = pad + (h - 2 * pad) * (1 - threshold / max_score)
        canvas.create_line(pad, thresh_y, w - pad, thresh_y,
                          fill=COLORS['red_dim'], dash=(6, 3), width=1)
        canvas.create_text(w - pad + 4, thresh_y, text="threshold",
                          fill=COLORS['red_dim'], font=('Consolas', 7), anchor='w')

        # Plot points
        n = len(scores)
        points = []
        for i, s in enumerate(scores):
            x = pad + (w - 2 * pad) * i / max(n - 1, 1)
            y = pad + (h - 2 * pad) * (1 - s / max_score)
            y = max(pad, min(h - pad, y))
            points.append((x, y))

        # Filled area under curve
        fill_pts = [(points[0][0], h - pad)]
        fill_pts.extend(points)
        fill_pts.append((points[-1][0], h - pad))
        flat_fill = [c for p in fill_pts for c in p]
        canvas.create_polygon(flat_fill, fill='#1a2a3a', outline='')

        # Line
        flat_line = [c for p in points for c in p]
        canvas.create_line(flat_line, fill=COLORS['accent'], width=2, smooth=True)

        # Highlight anomalous points in red
        for i, s in enumerate(score_history):
            if s.get('is_anomalous'):
                x, y = points[i]
                canvas.create_oval(x - 3, y - 3, x + 3, y + 3,
                                  fill=COLORS['red'], outline='')

        # Current value label
        canvas.create_text(
            w - pad, pad + 4,
            text=f"Current: {scores[-1]:.4f}",
            fill=COLORS['accent'], font=('Consolas', 8, 'bold'), anchor='ne'
        )

        # Time labels
        if score_history:
            from datetime import datetime
            first_ts = score_history[0]['timestamp']
            last_ts = score_history[-1]['timestamp']
            t0 = datetime.fromtimestamp(first_ts).strftime('%H:%M')
            t1 = datetime.fromtimestamp(last_ts).strftime('%H:%M')
            canvas.create_text(pad, h - 4, text=t0,
                              fill=COLORS['text_dim'], font=('Consolas', 7), anchor='sw')
            canvas.create_text(w - pad, h - 4, text=t1,
                              fill=COLORS['text_dim'], font=('Consolas', 7), anchor='se')

    # ──────────────────────────────────────────────────────────────────────────
    # Tab: Discovered Devices (passive device inventory)
    # ──────────────────────────────────────────────────────────────────────────

    def _build_devices_tab(self, parent):
        """Build the passively-learned device inventory tab."""
        top = tk.Frame(parent, bg=COLORS['bg_dark'])
        top.pack(fill='x', padx=8, pady=(8, 4))

        tk.Label(top, text="Discovered Devices",
                font=('Segoe UI', 12, 'bold'), fg=COLORS['accent'],
                bg=COLORS['bg_dark']).pack(side='left')

        self._devices_summary = tk.Label(
            top, text="0 devices", font=('Segoe UI', 9),
            fg=COLORS['text_dim'], bg=COLORS['bg_dark'])
        self._devices_summary.pack(side='left', padx=16)

        btn_frame = tk.Frame(top, bg=COLORS['bg_dark'])
        btn_frame.pack(side='right')
        tk.Button(btn_frame, text="Refresh", command=self._devices_refresh,
                 bg=COLORS['bg_input'], fg=COLORS['text'],
                 font=('Segoe UI', 9), relief='flat').pack(side='left', padx=4)

        # Device table using Treeview
        cols = ('ip', 'mac', 'hostname', 'type', 'confidence', 'packets', 'last_seen', 'services')
        self._devices_tree = ttk.Treeview(parent, columns=cols, show='headings', height=20)
        for col, width, label in [
            ('ip', 120, 'IP Address'), ('mac', 140, 'MAC'), ('hostname', 130, 'Hostname'),
            ('type', 100, 'Type'), ('confidence', 80, 'Confidence'),
            ('packets', 80, 'Packets'), ('last_seen', 90, 'Last Seen'),
            ('services', 180, 'Services'),
        ]:
            self._devices_tree.heading(col, text=label)
            self._devices_tree.column(col, width=width, minwidth=60)
        self._devices_tree.pack(fill='both', expand=True, padx=8, pady=4)

        # Baseline whitelist status bar
        self._baseline_status = tk.Label(
            parent, text="Baseline: learning...",
            font=('Consolas', 8), fg=COLORS['yellow'], bg=COLORS['bg_dark'], anchor='w')
        self._baseline_status.pack(fill='x', padx=8, pady=(0, 4))

        # Auto-refresh
        self.root.after(3000, self._devices_refresh)

    def _devices_refresh(self):
        """Refresh the device inventory display."""
        try:
            data = self.app.device_learner.get_summary()
            bl = self.app.baseline_whitelist.get_stats()

            self._devices_summary.config(
                text=f"{data['total_devices']} devices ({data['active_last_hour']} active)")

            # Update baseline status
            if bl['is_learning']:
                self._baseline_status.config(
                    text=f"Baseline learning: {bl['learning_elapsed_min']}min / "
                         f"{bl['learning_hours'] * 60}min — "
                         f"{bl['learned_domains']} domains, {bl['learned_ips']} IPs learned",
                    fg=COLORS['yellow'])
            else:
                self._baseline_status.config(
                    text=f"Baseline complete: {bl['learned_domains']} domains, "
                         f"{bl['learned_ips']} IPs, {bl['learned_beacons']} beacon patterns",
                    fg=COLORS['green'])

            # Update device table
            self._devices_tree.delete(*self._devices_tree.get_children())
            for dev in data.get('devices', []):
                svcs = ', '.join(str(p) for p in dev.get('services', [])[:5])
                self._devices_tree.insert('', 'end', values=(
                    dev['ip'], dev.get('mac', ''), dev.get('hostname', '—'),
                    dev.get('type', '?'), dev.get('confidence', ''),
                    dev.get('packets', 0), dev.get('last_seen', ''),
                    svcs or '—',
                ))
        except Exception as e:
            logger.debug("Devices refresh error: %s", e)

        if self._monitoring:
            self.root.after(5000, self._devices_refresh)

    # ──────────────────────────────────────────────────────────────────────────
    # Tab: Incidents (correlated alerts)
    # ──────────────────────────────────────────────────────────────────────────

    def _build_incidents_tab(self, parent):
        """Build the incident correlation tab."""
        top = tk.Frame(parent, bg=COLORS['bg_dark'])
        top.pack(fill='x', padx=8, pady=(8, 4))

        tk.Label(top, text="Security Incidents",
                font=('Segoe UI', 12, 'bold'), fg=COLORS['accent'],
                bg=COLORS['bg_dark']).pack(side='left')

        self._incidents_summary = tk.Label(
            top, text="0 incidents", font=('Segoe UI', 9),
            fg=COLORS['text_dim'], bg=COLORS['bg_dark'])
        self._incidents_summary.pack(side='left', padx=16)

        tk.Button(top, text="Refresh", command=self._incidents_refresh,
                 bg=COLORS['bg_input'], fg=COLORS['text'],
                 font=('Segoe UI', 9), relief='flat').pack(side='right', padx=4)

        # Info label
        tk.Label(parent,
                text="Related alerts are automatically grouped into incidents. "
                     "Escalation chains (e.g. Recon → Attack) are highlighted.",
                font=('Segoe UI', 8), fg=COLORS['text_dim'],
                bg=COLORS['bg_dark'], anchor='w').pack(fill='x', padx=12, pady=(0, 4))

        # Incidents list
        self._incidents_frame = tk.Frame(parent, bg=COLORS['bg_dark'])
        self._incidents_frame.pack(fill='both', expand=True, padx=8, pady=4)

        # Scrollable frame
        self._incidents_canvas = tk.Canvas(self._incidents_frame, bg=COLORS['bg_dark'],
                          highlightthickness=0)
        scrollbar = ttk.Scrollbar(self._incidents_frame, orient='vertical',
                                  command=self._incidents_canvas.yview)
        self._incidents_scroll = tk.Frame(self._incidents_canvas, bg=COLORS['bg_dark'])
        self._incidents_scroll.bind('<Configure>',
            lambda e: self._incidents_canvas.configure(scrollregion=self._incidents_canvas.bbox('all')))
        self._incidents_canvas_window = self._incidents_canvas.create_window(
            (0, 0), window=self._incidents_scroll, anchor='nw')
        self._incidents_canvas.configure(yscrollcommand=scrollbar.set)

        # Bind canvas resize to stretch inner frame width
        def _on_inc_canvas_resize(event):
            self._incidents_canvas.itemconfig(self._incidents_canvas_window, width=event.width)
        self._incidents_canvas.bind('<Configure>', _on_inc_canvas_resize)

        self._incidents_canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        self.root.after(3000, self._incidents_refresh)

    def _incidents_refresh(self):
        """Refresh the incidents display."""
        try:
            stats = self.app.alert_correlator.get_stats()
            incidents = self.app.alert_correlator.get_incidents(limit=30)

            self._incidents_summary.config(
                text=f"{stats['total_incidents']} total, "
                     f"{stats['active_incidents']} active, "
                     f"{stats['escalation_incidents']} escalations")

            # Clear existing
            for child in self._incidents_scroll.winfo_children():
                child.destroy()

            if not incidents:
                tk.Label(self._incidents_scroll,
                        text="No incidents yet. Alerts will be grouped as they arrive.",
                        font=('Segoe UI', 10), fg=COLORS['text_dim'],
                        bg=COLORS['bg_dark']).pack(pady=20)
            else:
                for inc in incidents:
                    inc_data = inc.to_dict()
                    sev_color = SEVERITY_COLORS.get(inc_data['severity'], COLORS['text'])
                    esc_marker = " ⚡ ESCALATION" if inc_data.get('is_escalation') else ""

                    frame = tk.Frame(self._incidents_scroll, bg=COLORS['bg_card'],
                                    highlightbackground=sev_color,
                                    highlightthickness=2, padx=10, pady=6)
                    frame.pack(fill='x', pady=3, padx=4)

                    header = tk.Frame(frame, bg=COLORS['bg_card'])
                    header.pack(fill='x')

                    tk.Label(header, text=f"[{inc_data['severity']}]",
                            font=('Consolas', 9, 'bold'), fg=sev_color,
                            bg=COLORS['bg_card']).pack(side='left')
                    tk.Label(header, text=f"  {inc_data['title']}{esc_marker}",
                            font=('Segoe UI', 10, 'bold'), fg=COLORS['text'],
                            bg=COLORS['bg_card']).pack(side='left')
                    tk.Label(header, text=f"{inc_data['alert_count']} alerts",
                            font=('Segoe UI', 9), fg=COLORS['text_dim'],
                            bg=COLORS['bg_card']).pack(side='right')
                    tk.Label(header, text=inc_data.get('created_str', ''),
                            font=('Consolas', 8), fg=COLORS['text_dim'],
                            bg=COLORS['bg_card']).pack(side='right', padx=8)

                    tk.Label(frame, text=inc_data.get('narrative', ''),
                            font=('Segoe UI', 9), fg=COLORS['text_dim'],
                            bg=COLORS['bg_card'], anchor='w', wraplength=900,
                            justify='left').pack(fill='x', pady=(2, 0))

        except Exception as e:
            logger.debug("Incidents refresh error: %s", e)

        if self._monitoring:
            self.root.after(5000, self._incidents_refresh)

    # ──────────────────────────────────────────────────────────────────────────
    # Tab: PCAP Capture (live capture export)
    # ──────────────────────────────────────────────────────────────────────────

    def _build_capture_tab(self, parent):
        """Build the PCAP capture and export tab."""
        top = tk.Frame(parent, bg=COLORS['bg_dark'])
        top.pack(fill='x', padx=8, pady=(8, 4))

        tk.Label(top, text="Packet Capture & Export",
                font=('Segoe UI', 12, 'bold'), fg=COLORS['accent'],
                bg=COLORS['bg_dark']).pack(side='left')

        # Controls
        ctrl = Card(parent, title="Capture Controls")
        ctrl.pack(fill='x', padx=8, pady=4)

        btn_row = tk.Frame(ctrl, bg=COLORS['bg_card'])
        btn_row.pack(fill='x', pady=4)

        self._capture_export_btn = tk.Button(
            btn_row, text="Export Last 5 Min", command=self._pcap_export_buffer,
            bg=COLORS['accent'], fg='white', font=('Segoe UI', 10, 'bold'),
            relief='flat', padx=16, pady=4)
        self._capture_export_btn.pack(side='left', padx=4)

        self._capture_record_btn = tk.Button(
            btn_row, text="Start Recording", command=self._pcap_toggle_recording,
            bg=COLORS['green_dim'], fg='white', font=('Segoe UI', 10, 'bold'),
            relief='flat', padx=16, pady=4)
        self._capture_record_btn.pack(side='left', padx=4)

        self._capture_status = tk.Label(
            ctrl, text="Ring buffer: collecting packets...",
            font=('Consolas', 9), fg=COLORS['text_dim'], bg=COLORS['bg_card'])
        self._capture_status.pack(fill='x', pady=4)

        # Saved captures list
        saved = Card(parent, title="Saved Captures")
        saved.pack(fill='both', expand=True, padx=8, pady=4)

        cols = ('filename', 'size', 'modified')
        self._captures_tree = ttk.Treeview(saved, columns=cols, show='headings', height=12)
        for col, width, label in [
            ('filename', 350, 'Filename'), ('size', 100, 'Size (MB)'),
            ('modified', 180, 'Modified'),
        ]:
            self._captures_tree.heading(col, text=label)
            self._captures_tree.column(col, width=width)
        self._captures_tree.pack(fill='both', expand=True)

        self.root.after(3000, self._capture_refresh)

    def _pcap_export_buffer(self):
        """Export the ring buffer to a PCAP file."""
        try:
            path = self.app.pcap_writer.export_buffer(last_minutes=5)
            if path:
                messagebox.showinfo("Export Complete",
                    f"Saved capture to:\n{path}")
                self._capture_refresh()
            else:
                messagebox.showwarning("No Data", "No packets in buffer to export.")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")

    def _pcap_toggle_recording(self):
        """Toggle continuous PCAP recording."""
        try:
            if self.app.pcap_writer.is_recording:
                stats = self.app.pcap_writer.stop_recording()
                self._capture_record_btn.config(text="Start Recording",
                                                bg=COLORS['green_dim'])
                if stats:
                    messagebox.showinfo("Recording Stopped",
                        f"Saved {stats['packets']} packets in {stats['duration_sec']}s\n"
                        f"File: {stats['filepath']}")
                self._capture_refresh()
            else:
                path = self.app.pcap_writer.start_recording()
                if path:
                    self._capture_record_btn.config(text="Stop Recording",
                                                    bg=COLORS['red_dim'])
        except Exception as e:
            messagebox.showerror("Error", f"Recording error: {e}")

    def _capture_refresh(self):
        """Refresh capture status and file list."""
        try:
            stats = self.app.pcap_writer.get_buffer_stats()
            status = f"Ring buffer: {stats['buffer_packets']} packets ({stats['buffer_span_sec']}s)"
            if stats['is_recording']:
                status += f"  |  RECORDING: {stats['recording_packets']} packets"
            self._capture_status.config(text=status)

            # Update file list
            self._captures_tree.delete(*self._captures_tree.get_children())
            for f in self.app.pcap_writer.get_capture_files()[:20]:
                self._captures_tree.insert('', 'end', values=(
                    f['filename'], f['size_mb'], f['modified']
                ))
        except Exception as e:
            logger.debug("Capture refresh error: %s", e)

        if self._monitoring:
            self.root.after(5000, self._capture_refresh)

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _format_bytes(b):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if abs(b) < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} PB"

    @staticmethod
    def _format_number(n):
        if n >= 1_000_000:
            return f"{n/1_000_000:.1f}M"
        if n >= 1_000:
            return f"{n/1_000:.1f}K"
        return str(n)

    def run(self):
        """Start the GUI main loop."""
        logger.info("GUI started.")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        """Clean shutdown."""
        if self._monitoring:
            self.app.stop_monitoring()
        self.root.destroy()
