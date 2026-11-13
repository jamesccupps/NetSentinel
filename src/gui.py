"""
NetSentinel GUI Dashboard
=========================
Real-time network monitoring dashboard with traffic charts,
alert feed, flow table, ML status, and settings.
Built with tkinter + ttk for zero extra dependencies.
"""

import os
import queue
import threading
import time
import logging
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from collections import deque
from datetime import datetime

from src import presentation, __version__

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

# Rows the Alerts tab shows, newest first; the alert store keeps more
# (alerts.max_stored), and Export has them all.
ALERTS_SHOWN = 1000
# The File Analyzer's list of what a capture raised.
PCAP_ALERTS_SHOWN = 2000
# How often alerts heard from other threads are added to the window (ms).
ALERT_BATCH_MS = 500

# The Forensics Vault's services list shows at most this many.
SERVICES_SHOWN = 300

# Settings' choices for bacnet.mode (config.BACNET_MODES), as (value, shown).
BACNET_CHOICES = (
    ('watch', 'Watch it'),
    ('workstation', "This PC runs the building's controls"),
    ('off', 'Off'),
)


class _Choice:
    """A Settings drop-down: shows the text, gives back the value."""

    def __init__(self, var, choices):
        self._var = var
        self._values = {text: value for value, text in choices}

    def get(self):
        return self._values.get(self._var.get(), self._var.get())


# ─── Mouse wheel ───────────────────────────────────────────────────────────────
# A canvas has no wheel binding of its own, so the scrolling pages built on one
# each bound the wheel for the whole application. One turn scrolled all three of
# them at once, on whichever tabs they were, and the other six pages did not
# scroll at all; every alert window opened added another binding, never removed.
# Now one handler scrolls the innermost area under the pointer that has further
# to go. Text, lists, tables and scrollbars scroll themselves.

_SCROLLS_ITSELF = {'Text', 'Listbox', 'Treeview'}
_ACTS_ON_WHEEL = {'TScrollbar', 'Scrollbar', 'TCombobox'}


def wheel_steps(event):
    """Lines to scroll: positive is down. Windows gives 120 a notch, X11 buttons 4/5."""
    if getattr(event, 'num', None) == 4:
        return -1
    if getattr(event, 'num', None) == 5:
        return 1
    delta = getattr(event, 'delta', 0) or 0
    return -round(delta / 120) or (-1 if delta > 0 else 1 if delta < 0 else 0)


def _has_further_to_go(widget):
    try:
        first, last = (float(v) for v in widget.yview())
    except (tk.TclError, TypeError, ValueError):
        return False
    return first > 0 or last < 1


def on_mousewheel(event):
    origin = event.widget
    if isinstance(origin, str):              # Tk's own, e.g. a drop-down's list
        return
    try:
        widget = origin.winfo_containing(event.x_root, event.y_root) or origin
    except (KeyError, tk.TclError):
        widget = origin
    steps = wheel_steps(event)
    while widget is not None and steps:
        kind = widget.winfo_class()
        if kind in _ACTS_ON_WHEEL and widget is origin:
            return
        if (kind in _SCROLLS_ITSELF or getattr(widget, 'wheel_scrolls', False)) \
                and _has_further_to_go(widget):
            if not (widget is origin and kind in _SCROLLS_ITSELF):
                widget.yview_scroll(steps, 'units')
            return
        widget = widget.master


def wheel_scrollable(canvas):
    """Let the wheel scroll this canvas when the pointer is over it."""
    canvas.wheel_scrolls = True
    root = canvas._root()
    if not getattr(root, '_wheel_router', False):
        root.bind_all('<MouseWheel>', on_mousewheel)
        if root.tk.call('tk', 'windowingsystem') == 'x11':
            root.bind_all('<Button-4>', on_mousewheel)
            root.bind_all('<Button-5>', on_mousewheel)
        root._wheel_router = True
    return canvas


def settings_from_form(raw):
    """
    The Settings form's values, typed: ({key: value}, [keys that are not numbers]).

    A setting whose default is a number must be one. The form used to keep '15x'
    or '5,514' as a string, which then stopped NetSentinel starting (int() in a
    constructor) or silently switched IDS rules off (a threshold compared as a
    string). Other fields keep the old guess: a number if it parses as one.
    """
    from src.config import DEFAULT_CONFIG, as_float, as_int
    values, bad = {}, []
    for key, val in raw.items():
        if isinstance(val, bool):
            values[key] = val
            continue
        default = DEFAULT_CONFIG
        for part in key.split('.'):
            default = default.get(part) if isinstance(default, dict) else None
        if isinstance(default, (int, float)) and not isinstance(default, bool):
            parse = as_int if isinstance(default, int) else as_float
            number = parse(val, None)
            if number is None:
                bad.append(key)
            else:
                values[key] = number
            continue
        try:
            values[key] = float(val) if '.' in val else int(val)
        except (TypeError, ValueError):
            values[key] = val
    return values, bad


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

    def __init__(self, parent, alert_dict, actions=None):
        self._actions = actions
        self._alert_dict = alert_dict
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
        wheel_scrollable(canvas)

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
        src_str = presentation.endpoint(src_ip, src_port) or '—'
        if src_domains:
            src_str += f"  ({', '.join(str(d) for d in src_domains[:2])})"
        conn_fields.append(('Source', src_str))

        dst_str = presentation.endpoint(dst_ip, dst_port) or '—'
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

        # ─── Judge it, acknowledge it, close ─────────────────────
        buttons = tk.Frame(self.win, bg=COLORS['bg_dark'])
        buttons.pack(pady=8)
        self._judgement = tk.Label(buttons, text='', font=('Segoe UI', 9),
                                   fg=COLORS['text_dim'], bg=COLORS['bg_dark'])
        self._judgement.pack(side='left', padx=8)
        self._judge_buttons = []
        if actions is not None and alert_dict.get('id') is not None:
            mine = evidence.get('your_verdict')
            if mine:
                self._judgement.config(
                    text=f"You marked this {'a false positive' if mine == 'false_positive' else 'real'}.")
            else:
                for text, verdict, tip in (
                        ("Real", 'real', None),
                        ("False positive", 'false_positive', None),
                        ("Acknowledge", None, None)):
                    b = tk.Button(buttons, text=text, font=('Segoe UI', 9),
                                  bg=COLORS['bg_input'], fg=COLORS['text'], relief='flat',
                                  padx=12, pady=4, cursor='hand2',
                                  command=lambda v=verdict: self._judge(v))
                    b.pack(side='left', padx=4)
                    self._judge_buttons.append(b)
        # A credential alert says only that one was seen; the vault shows what.
        open_vault = getattr(actions, 'open_vault', None)
        if open_vault is not None and alert_dict.get('rule_id') == 'FORENSICS-CREDENTIAL':
            tk.Button(buttons, text="Open in vault", font=('Segoe UI', 9),
                      bg=COLORS['bg_input'], fg=COLORS['text'], relief='flat',
                      padx=12, pady=4, cursor='hand2',
                      command=lambda: open_vault(alert_dict)).pack(side='left', padx=4)
        close_btn = tk.Button(buttons, text="Close", font=('Segoe UI', 9),
                             bg=COLORS['bg_input'], fg=COLORS['text'],
                             relief='flat', padx=16, pady=4, cursor='hand2',
                             command=self.win.destroy)
        close_btn.pack(side='left', padx=4)

    def _judge(self, verdict):
        """Real or false positive (which also acknowledge it), or only acknowledge."""
        alert_id = self._alert_dict.get('id')
        if verdict == 'false_positive' and not messagebox.askyesno(
                "False positive",
                f"Never alert on {self._alert_dict.get('rule_id', 'this rule')} for this "
                f"host or domain again?", parent=self.win):
            return
        try:
            if verdict is None:
                self._actions.acknowledge(alert_id)
                said = "Acknowledged."
            else:
                self._actions.verdict(alert_id, verdict)
                said = ("Marked a false positive and acknowledged."
                        if verdict == 'false_positive' else "Marked real and acknowledged.")
        except LookupError as e:
            said = str(e)
        except Exception as e:
            logger.debug("Alert judgement failed: %s", e)
            said = f"Could not record that: {e}"
        self._judgement.config(text=said)
        for b in self._judge_buttons:
            b.config(state='disabled')

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


class AlertTable(tk.Frame):
    """
    Alerts as a table, newest first, opened with a click. Each alert used to be
    a block of a dozen widgets in one long scrolling frame, and every new one
    made Tk lay out all of them again: 0.15 to 0.4 seconds of frozen window per
    alert with 200 listed, and the dashboard's five rebuilt for each alert added
    as much again. A building network's few hundred alerts froze the window for
    minutes. A table row costs a fraction of a millisecond.
    """
    COLUMNS = (('time', 'Time', 135), ('severity', 'Severity', 75), ('title', 'Alert', 380),
               ('route', 'From → to', 270), ('rule', 'Rule', 160), ('ack', 'Ack', 40))

    def __init__(self, parent, actions=None, lookup=None, limit=ALERTS_SHOWN, height=20,
                 columns=('time', 'severity', 'title', 'route', 'rule', 'ack'), **kwargs):
        kwargs.setdefault('bg', COLORS['bg_card'])
        super().__init__(parent, **kwargs)
        self._actions = actions
        self._lookup = lookup           # alert id -> its current dict, or None
        self._limit = limit
        self._rows = {}                 # table row -> alert dict
        shown = [c for c in self.COLUMNS if c[0] in columns]
        tree = ttk.Treeview(self, columns=[c[0] for c in shown], show='headings',
                            height=height, selectmode='browse')
        for col, label, width in shown:
            tree.heading(col, text=label)
            tree.column(col, width=width, minwidth=35, anchor='w',
                        stretch=col in ('title', 'route'))
        for sev, colour in SEVERITY_COLORS.items():
            tree.tag_configure(sev, foreground=colour)
        bar = ttk.Scrollbar(self, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=bar.set)
        tree.pack(side='left', fill='both', expand=True)
        bar.pack(side='right', fill='y')
        tree.bind('<ButtonRelease-1>', self._clicked)
        tree.bind('<Return>', lambda e: self._open(tree.focus()))
        self.tree = tree

    @staticmethod
    def values(alert):
        """One alert dict's row."""
        return {
            'time': alert.get('time_str', ''),
            'severity': alert.get('severity', ''),
            'title': alert.get('title', ''),
            'route': (f"{presentation.endpoint(alert.get('src_ip'), alert.get('src_port')) or '—'} → "
                      f"{presentation.endpoint(alert.get('dst_ip'), alert.get('dst_port')) or '—'}"),
            'rule': alert.get('rule_id', ''),
            'ack': '✓' if alert.get('acknowledged') else '',
        }

    def _insert(self, alert, index):
        row = self.values(alert)
        item = self.tree.insert('', index, values=[row[c] for c in self.tree['columns']],
                                tags=(str(alert.get('severity', '')),))
        self._rows[item] = alert

    def show(self, alerts):
        """Replace the rows: alerts newest first, at most the limit."""
        self.clear()
        for alert in list(alerts)[:self._limit]:
            self._insert(alert, 'end')

    def add(self, alerts, at_top=True):
        """Add alerts in the order they came, oldest first: at the top, newest
        uppermost, or at the bottom. Past the limit the oldest go."""
        alerts = list(alerts)[-self._limit:]
        for alert in alerts:
            self._insert(alert, 0 if at_top else 'end')
        children = self.tree.get_children()
        if len(children) > self._limit:
            extra = children[self._limit:] if at_top else children[:len(children) - self._limit]
            self.tree.delete(*extra)
            for item in extra:
                self._rows.pop(item, None)

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self._rows = {}

    def __len__(self):
        return len(self._rows)

    def _clicked(self, event):
        if self.tree.identify_region(event.x, event.y) == 'cell':
            self._open(self.tree.identify_row(event.y))

    def _open(self, item):
        alert = self._rows.get(item)
        if alert is None:
            return
        if self._lookup is not None and alert.get('id') is not None:
            # Its current state: verification can finish, and verdicts be given,
            # after the row was drawn.
            alert = self._lookup(alert['id']) or alert
        AlertDetailWindow(self.winfo_toplevel(), alert, actions=self._actions)


class AlertActions:
    """What the alert detail window may do to a stored alert, through the app."""

    def __init__(self, app, open_vault=None):
        self.app = app
        # Opens the Forensics Vault at a credential alert's entry (the main window's).
        self.open_vault = open_vault

    def acknowledge(self, alert_id):
        return self.app.alert_manager.acknowledge_alert(alert_id)

    def verdict(self, alert_id, verdict):
        """Real or false_positive; NetSentinelApp.record_verdict acknowledges it too."""
        return self.app.record_verdict(alert_id, verdict)


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
        self._lifecycle_thread = None
        self._lifecycle_was_start = False
        # Alerts from other threads wait here; _drain_alerts adds them a batch at a time.
        self._pending_alerts = deque()
        self._alert_actions = AlertActions(app, open_vault=self._open_alert_in_vault)
        # gui.max_log_lines was declared in config but never read.
        self._max_log_lines = max(20, int(
            self.app.config.get('gui', 'max_log_lines', default=500)))
        self._packet_log_lines = deque(maxlen=self._max_log_lines)

        # Build UI
        self._build_ui()

        # Register alert listener
        self.app.alert_manager.register_listener(self._on_new_alert)
        self.root.after(ALERT_BATCH_MS, self._drain_alerts)

        # The tray icon. With it, closing the window hides it and monitoring
        # carries on; without one (no library, no tray on this desktop), closing
        # quits as it always did.
        self._tray_actions = queue.Queue()
        self._tray = None
        self._told_about_tray = False
        if self.app.config.get('gui', 'close_to_tray', default=True):
            from src import tray
            if tray.available():
                icon = tray.Tray(self._tray_actions.put, lambda: self._monitoring)
                if icon.start():
                    self._tray = icon
                    self.root.after(150, self._poll_tray)

        # --monitor, which a restart passes when it was monitoring.
        if getattr(self.app, 'start_on_launch', False):
            self.root.after(300, self._toggle_monitoring)

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
        tk.Label(logo_frame, text=f"  v{__version__}",
                font=('Consolas', 8),
                fg=COLORS['text_dim'], bg=COLORS['bg_panel']).pack(side='left', padx=(4,0))

        # Controls
        ctrl_frame = tk.Frame(top_bar, bg=COLORS['bg_panel'])
        ctrl_frame.pack(side='right', padx=16)

        tk.Button(ctrl_frame, text="🌐  Open in Browser", font=('Segoe UI', 9, 'bold'),
                  bg=COLORS['bg_input'], fg=COLORS['accent'],
                  relief='flat', cursor='hand2', padx=10,
                  command=self._open_dashboard
        ).pack(side='left', padx=(0, 8))

        review_btn = tk.Menubutton(ctrl_frame, text="🧾  Review", font=('Segoe UI', 9),
                                   bg=COLORS['bg_input'], fg=COLORS['text'],
                                   relief='flat', cursor='hand2', padx=10)
        review_menu = tk.Menu(review_btn, tearoff=0)
        review_menu.add_command(label="Build review bundle", command=self._review_build)
        review_menu.add_command(label="Import verdicts…", command=self._review_import)
        review_menu.add_command(label="Open review folder", command=self._review_open_folder)
        review_btn.config(menu=review_menu)
        review_btn.pack(side='left', padx=(0, 8))

        tk.Button(ctrl_frame, text="🔍  Audit", font=('Segoe UI', 9),
                  bg=COLORS['bg_input'], fg=COLORS['text'],
                  relief='flat', cursor='hand2', padx=10,
                  command=lambda: self._open_dashboard('#audit')
        ).pack(side='left', padx=(0, 8))

        tk.Button(ctrl_frame, text="⟳  Restart", font=('Segoe UI', 8),
                  bg=COLORS['bg_input'], fg=COLORS['text_dim'],
                  relief='flat', cursor='hand2', padx=8,
                  command=self._restart
        ).pack(side='left', padx=(0, 8))

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

        # Tab 2b: Exposures (standing conditions, one per device and issue)
        self._tab_exposures = StyledFrame(self.notebook)
        self.notebook.add(self._tab_exposures, text='  🛡  Exposures  ')
        self._build_exposures_tab(self._tab_exposures)

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
        self.notebook.add(self._tab_pcap, text='  📁  File Analyzer  ')
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
        self.notebook.bind('<<NotebookTabChanged>>', lambda e: self._on_tab_changed())

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

        # Shown once the updater finds a newer release (_sync_update_notice).
        self._update_button = tk.Button(
            status_bar, text="", font=('Segoe UI', 8, 'bold'),
            bg=COLORS['accent'], fg=COLORS['bg_dark'], relief='flat', padx=8,
            cursor='hand2', command=self._show_update)
        self._update_shown = None

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

        # This PC's address and the network around it (presentation.network_rows)
        network_card = Card(bottom_frame, title="THIS NETWORK")
        network_card.pack(side='left', fill='both', expand=True, padx=4)
        self._network_rows = tk.Frame(network_card, bg=COLORS['bg_card'])
        self._network_rows.pack(fill='both', expand=True)
        self._network_shown = None
        self.root.after(500, self._refresh_network)

        # Recent alerts mini
        recent_card = Card(bottom_frame, title="RECENT ALERTS")
        recent_card.pack(side='left', fill='both', expand=True, padx=(4, 0))

        self._recent_alerts = AlertTable(recent_card, actions=self._alert_actions,
                                         lookup=self._current_alert, limit=5, height=5,
                                         columns=('time', 'severity', 'title'))
        self._recent_alerts.pack(fill='both', expand=True)

    def _refresh_network(self):
        """Fill THIS NETWORK, and again every 30 seconds, monitoring or not: the
        address can change (DHCP, a VPN coming up)."""
        try:
            rows = self.app.network_rows()
            if rows != self._network_shown:
                self._network_shown = rows
                for widget in self._network_rows.winfo_children():
                    widget.destroy()
                for i, (label, value) in enumerate(rows):
                    tk.Label(self._network_rows, text=label, font=('Segoe UI', 9),
                             fg=COLORS['text_dim'], bg=COLORS['bg_card'], anchor='nw'
                             ).grid(row=i, column=0, sticky='nw', padx=(4, 12), pady=1)
                    tk.Label(self._network_rows, text=value, font=('Consolas', 9),
                             fg=COLORS['text'], bg=COLORS['bg_card'], anchor='w',
                             justify='left', wraplength=300
                             ).grid(row=i, column=1, sticky='w', pady=1)
        except Exception as e:
            logger.debug("Network panel refresh failed: %s", e)
        self.root.after(30000, self._refresh_network)

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
                 command=lambda: (self.app.alert_manager.acknowledge_all(),
                                  self._refresh_alerts_display())
                 ).pack(side='right', padx=4)

        tk.Button(toolbar, text="📊  Rule record", font=('Segoe UI', 8),
                 bg=COLORS['bg_input'], fg=COLORS['text_dim'],
                 relief='flat', cursor='hand2',
                 command=self._show_rule_record).pack(side='right', padx=4)

        tk.Label(toolbar, text="Open an alert to mark it real or a false positive.",
                 font=('Segoe UI', 8), fg=COLORS['text_dim'],
                 bg=COLORS['bg_dark']).pack(side='left', padx=12)

        self._alerts_table = AlertTable(parent, actions=self._alert_actions,
                                        lookup=self._current_alert)
        self._alerts_table.pack(fill='both', expand=True, padx=8, pady=(0, 8))

        # The alerts stored before this window existed: the listener never heard them.
        try:
            self._alerts_table.show(
                a.to_dict() for a in self.app.alert_manager.get_alerts(limit=ALERTS_SHOWN))
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
        wheel_scrollable(ml_canvas)

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
        ctrl_frame.pack(fill='x', padx=8, pady=(8, 0))
        # The buttons get the row to themselves so a narrow or scaled window
        # cannot squeeze them out; the description sits underneath.
        tk.Label(parent, text="Scan any files, folders or zips for IP addresses, domains, "
                              "emails and leaked passwords or keys. Packet captures "
                              "(.pcap, .pcapng) get the full traffic analysis.",
                 font=('Segoe UI', 9), fg=COLORS['text_dim'], bg=COLORS['bg_dark'],
                 anchor='w', justify='left').pack(fill='x', padx=10, pady=(4, 6))

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

        self._pcap_many_btn = tk.Button(
            ctrl_frame, text="📦  Scan Files / Zips",
            font=('Segoe UI', 10, 'bold'), bg=COLORS['accent'],
            fg=COLORS['bg_dark'], relief='flat', padx=16, pady=6,
            cursor='hand2', command=self._pcap_open_many
        )
        self._pcap_many_btn.pack(side='left', padx=4)

        self._pcap_folder_btn = tk.Button(
            ctrl_frame, text="📁  Scan Folder",
            font=('Segoe UI', 10, 'bold'), bg=COLORS['accent'],
            fg=COLORS['bg_dark'], relief='flat', padx=16, pady=6,
            cursor='hand2', command=self._pcap_open_folder
        )
        self._pcap_folder_btn.pack(side='left', padx=4)

        self._pcap_btn = tk.Button(
            ctrl_frame, text="📂  Open One Capture",
            font=('Segoe UI', 9), bg=COLORS['bg_input'],
            fg=COLORS['text'], relief='flat', padx=10, pady=6,
            cursor='hand2', command=self._pcap_open_file
        )
        self._pcap_btn.pack(side='left', padx=4)

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

        stats_scroll = ttk.Scrollbar(stats_card, orient='vertical')
        stats_scroll.pack(side='right', fill='y')
        self._pcap_stats_text = tk.Text(stats_card, bg=COLORS['bg_card'],
                                         fg=COLORS['text'], font=('Consolas', 9),
                                         relief='flat', wrap='word', padx=8, pady=8,
                                         yscrollcommand=stats_scroll.set)
        self._pcap_stats_text.pack(fill='both', expand=True)
        stats_scroll.config(command=self._pcap_stats_text.yview)
        self._pcap_stats_text.tag_configure('header', foreground=COLORS['accent'],
                                             font=('Consolas', 9, 'bold'))
        self._pcap_stats_text.tag_configure('value', foreground=COLORS['text'])
        self._pcap_stats_text.tag_configure('alert_high', foreground=COLORS['red'])
        self._pcap_stats_text.tag_configure('alert_med', foreground=COLORS['yellow'])
        self._pcap_stats_text.tag_configure('safe', foreground=COLORS['green'])
        self._pcap_stats_text.insert('end', "No analysis results yet.\n\n"
            "Click 'Open PCAP File' to load a capture from Wireshark,\n"
            "tcpdump, or any other packet capture tool.\n\n"
            "Supported formats: .pcap, .pcapng, .cap\n"
            "'Scan Files / Zips' and 'Scan Folder' take anything: logs, configs,\n"
            "documents, exports, zips. They list every IP address, domain, URL,\n"
            "email and MAC address found, and every password, key or token that\n"
            "looks leaked (masked), with the file and line it was on.\n\n"
            "The analyzer runs every packet through:\n"
            "  - IDS signature rules (port scan, brute force, etc.)\n"
            "  - Threat intelligence feeds (malicious IPs/domains)\n"
            "  - IOC scanner (TOR, DGA, suspicious processes)\n"
            "  - Alert verification (auto false-positive detection)\n")

        # Right: Alerts found
        alerts_card = Card(results_frame, title="ALERTS FOUND IN CAPTURE")
        alerts_card.pack(side='left', fill='both', expand=True, padx=(4, 0))

        # In the order the capture raised them. Not stored, so nothing to judge.
        self._pcap_alerts = AlertTable(alerts_card, limit=PCAP_ALERTS_SHOWN,
                                       columns=('time', 'severity', 'title', 'route', 'rule'))
        self._pcap_alerts.pack(fill='both', expand=True)
        self._pcap_batch = None

    def _open_dashboard(self, page=''):
        """Open the browser dashboard served alongside this window, at page (#audit)."""
        import webbrowser
        server = getattr(self.app, 'web_server', None)
        if server is None:
            messagebox.showinfo(
                "Browser Dashboard",
                "The dashboard is not running. It starts with NetSentinel unless "
                "--no-api was given; check the log for why it could not start.")
            return
        webbrowser.open(server.url + page)

    # ─── Review mode ─────────────────────────────────────────────────────

    def _review_folder(self):
        from src.review import default_directory
        review = self.app.review
        return review.directory if review is not None else default_directory()

    def _review_build(self):
        """Build in the background; a big review folder takes a few seconds."""
        result = {}

        def work():
            try:
                result['ok'] = self.app.build_review_bundle()
            except Exception as e:      # shown to the user, whatever it was
                result['error'] = e

        thread = threading.Thread(target=work, daemon=True, name="ReviewBundle")
        thread.start()
        self._statusbar_text.config(text="Building the review bundle...")

        def poll():
            if thread.is_alive():
                self.root.after(200, poll)
                return
            if 'error' in result:
                self._statusbar_text.config(text="The review bundle was not built.")
                messagebox.showwarning("Review bundle", str(result['error']))
                return
            r = result['ok']
            self._statusbar_text.config(text=f"Review bundle: {r['zip']}")
            if messagebox.askyesno(
                    "Review bundle",
                    f"{r['alerts']} alerts in {r['groups']} groups, {r['digests']} traffic "
                    f"digests, {r['bytes'] // 1024} KB. {r['masked']} values were masked.\n\n"
                    f"{r['zip']}\n\nUpload the zip to Claude and ask it which alerts are "
                    "real; its README says how to answer.\n\nOpen the folder?"):
                self._open_path(os.path.dirname(r['zip']))
        poll()

    def _review_import(self):
        from src.review import import_verdicts
        path = filedialog.askopenfilename(
            title="Open the answer (the JSON the bundle's README asks for)",
            filetypes=[('Answer', '*.json *.txt *.md'), ('All files', '*.*')])
        if not path:
            return
        try:
            with open(path, encoding='utf-8-sig') as f:
                result = import_verdicts(self._review_folder(), f.read(),
                                         self.app.baseline_whitelist.confirmed)
        except (OSError, ValueError) as e:
            messagebox.showerror("Import verdicts", f"Could not import it: {e}")
            return
        lines = [f"{result['false_positive']} false positives (no longer alerted on), "
                 f"{result['real']} real."]
        if result['unknown_ids']:
            lines.append(f"{len(result['unknown_ids'])} ids were not found in this review folder.")
        if result['no_subject']:
            lines.append(f"{len(result['no_subject'])} false positives name no host or "
                         "domain, so nothing is suppressed for them.")
        messagebox.showinfo("Import verdicts", "\n".join(lines))

    def _review_open_folder(self):
        folder = self._review_folder()
        os.makedirs(folder, exist_ok=True)
        self._open_path(folder)

    @staticmethod
    def _open_path(path):
        import subprocess
        import sys as _sys
        if _sys.platform == 'win32':
            os.startfile(path)
        elif _sys.platform == 'darwin':
            subprocess.Popen(['open', path])
        else:
            subprocess.Popen(['xdg-open', path])

    def _scan_ignore_link(self, text, finding):
        """An "[ignore]" link after a finding; clicked, later scans leave it out."""
        self._ignore_links = getattr(self, '_ignore_links', 0) + 1
        tag = f'ignore{self._ignore_links}'
        text.insert('end', '[ignore]', ('link', tag))
        text.tag_configure('link', foreground=COLORS['accent'], underline=True)
        text.tag_bind(tag, '<Enter>', lambda e: text.config(cursor='hand2'))
        text.tag_bind(tag, '<Leave>', lambda e: text.config(cursor=''))
        text.tag_bind(tag, '<Button-1>',
                      lambda e, f=finding, t=tag: self._scan_ignore(text, f, t))

    def _scan_ignore(self, text, finding, tag):
        from src.scan_ignore import IgnoreList
        try:
            IgnoreList().add_finding(finding)
        except (OSError, ValueError) as e:
            messagebox.showerror("Ignore", f"Could not add it to the ignore list: {e}")
            return
        ranges = text.tag_ranges(tag)
        if ranges:
            state = text.cget('state')
            text.config(state='normal')
            text.delete(ranges[0], ranges[1])
            text.insert(ranges[0], '(ignored from now on)', 'value')
            text.config(state=state)
        self._statusbar_text.config(
            text="Ignored. Later scans leave it out; the browser's Scan Files page lists "
                 "and removes ignored items.")

    def _pcap_set_busy(self, busy):
        state = 'disabled' if busy else 'normal'
        for btn in (self._pcap_btn, self._pcap_folder_btn, self._pcap_many_btn):
            btn.config(state=state)
        self._pcap_cancel_btn.config(state='normal' if busy else 'disabled')

    def _pcap_open_many(self):
        """Pick zips and/or capture files to scan together."""
        paths = filedialog.askopenfilenames(
            title="Select Files or Zips to Scan",
            filetypes=[
                ('All files', '*.*'),
                ('Zip archives', '*.zip'),
                ('Packet Captures', '*.pcap *.pcapng *.cap'),
            ]
        )
        if paths:
            self._pcap_start_batch(list(paths))

    def _pcap_open_folder(self):
        """Pick a folder; every capture and zip under it is scanned."""
        folder = filedialog.askdirectory(title="Select a Folder to Scan")
        if folder:
            self._pcap_start_batch([folder])

    def _pcap_start_batch(self, paths):
        """Scan many captures in the background and show one combined report."""
        from src.batch_scan import scan

        self._pcap_stats_text.delete('1.0', 'end')
        self._pcap_stats_text.insert('end', "Collecting files...\n")
        self._pcap_alerts.clear()
        self._pcap_set_busy(True)
        self._pcap_progress_var.set(0)

        batch = {'running': True, 'cancel': False, 'index': 0, 'total': 0, 'name': ''}
        self._pcap_batch = batch

        def on_alert(alert):
            try:
                self.root.after(0, self._pcap_add_alert, alert)
            except Exception:
                pass

        def on_progress(index, total, name):
            batch.update(index=index, total=total, name=name)

        def run():
            try:
                report = scan(paths, self.app.pcap_analyzer, on_alert=on_alert,
                              on_progress=on_progress, cancelled=lambda: batch['cancel'])
            except Exception as e:
                logger.error("Batch scan failed: %s", e)
                report = {'error': str(e)}
            batch['running'] = False
            try:
                self.root.after(0, self._pcap_show_batch, report)
            except Exception:
                pass

        threading.Thread(target=run, daemon=True, name="PcapBatchScan").start()
        self._pcap_update_progress()

    def _pcap_show_batch(self, report):
        """Display the combined report from a folder or zip scan."""
        st = self._pcap_stats_text
        st.delete('1.0', 'end')
        if 'error' in report:
            st.insert('end', f"Scan failed: {report['error']}\n", 'alert_high')
            return
        s = report['summary']
        st.insert('end', 'SCAN SUMMARY\n', 'header')
        st.insert('end', f"  Scanned:   {s['scanned']} of {s['items']} files "
                         f"({s['captures']} packet captures)"
                         f"{' (cancelled)' if report.get('cancelled') else ''}\n")
        st.insert('end', f"  Found:     {s['ipv4'] + s['ipv6']} IP addresses, {s['domain']} domains, "
                         f"{s['url']} URLs, {s['email']} emails, {s['mac']} MAC addresses\n")
        exposed = s['credentials'] + s['secrets']
        st.insert('end', f"  Exposed:   {exposed} passwords, keys or tokens\n",
                  'alert_high' if exposed else 'safe')
        if s['threats']:
            st.insert('end', f"  Known bad: {s['threats']} indicators on threat feeds\n", 'alert_high')
        if s['failed']:
            st.insert('end', f"  Failed:    {s['failed']}\n", 'alert_med')
        if s['skipped']:
            st.insert('end', f"  Skipped:   {s['skipped']}\n")

        if report.get('malware'):
            st.insert('end', '\nKNOWN-BAD FILES (on your hash lists)\n', 'header')
            for m in report['malware']:
                st.insert('end', f"  {m['file']}\n      sha256 {m['sha256']}  "
                                 f"({m.get('feed', '')})\n", 'alert_high')

        if report['threats']:
            st.insert('end', '\nON THREAT FEEDS\n', 'header')
            for t in report['threats']:
                st.insert('end', f"  {t['value']}  ({t.get('feed', '')} {t.get('category', '')})\n"
                                 f"      in {', '.join(t['files'][:5])}\n", 'alert_high')

        if report.get('suspicious'):
            st.insert('end', '\nSUSPICIOUS (weak feed matches, not known-bad)\n', 'header')
            for t in report['suspicious'][:100]:
                st.insert('end', f"  {t['value']}  ({t.get('category') or t.get('description', '')})\n"
                                 f"      in {', '.join(t['files'][:5])}\n", 'alert_med')

        st.insert('end', '\nEXPOSED PASSWORDS, KEYS AND TOKENS\n', 'header')
        if not exposed:
            st.insert('end', "  None found.\n", 'safe')
        for cred in report['credentials']:
            st.insert('end', f"  {cred['protocol']} {cred['credential_type']}: "
                             f"{cred['value']}\n", 'alert_high')
            st.insert('end', f"      {cred['source']}\n"
                             f"      in {', '.join(cred['captures'])}\n")
        for sec in report['secrets'][:1000]:
            st.insert('end', f"  {sec['label']}: {sec['value']}  ", 'alert_high')
            self._scan_ignore_link(st, sec)
            st.insert('end', f"\n      {sec['file']}, line {sec['line']}\n")

        if report.get('findings'):
            st.insert('end', '\nSUSPICIOUS SCRIPTS AND MACROS\n', 'header')
            for f in report['findings'][:500]:
                st.insert('end', f"  {f['label']}: {f['value']}  ", 'alert_med')
                self._scan_ignore_link(st, f)
                st.insert('end', f"\n      {f['file']}, line {f['line']}\n")

        titles = {'ipv4': 'IPv4 ADDRESSES', 'ipv6': 'IPv6 ADDRESSES', 'domain': 'DOMAINS',
                  'url': 'URLS', 'email': 'EMAIL ADDRESSES', 'mac': 'MAC ADDRESSES',
                  'host': 'HOST NAMES', 'unc': 'UNC PATHS'}
        for kind, title in titles.items():
            entries = report['indicators'].get(kind, [])
            if not entries:
                continue
            st.insert('end', f"\n{title} ({len(entries)})\n", 'header')
            for e in entries[:100]:
                scope = f"  [{e['scope']}]" if e.get('scope') else ''
                where = ', '.join(e['files'][:3]) + (' ...' if len(e['files']) > 3 else '')
                st.insert('end', f"  {e['value']}{scope}  x{e['count']}  ", 'value')
                st.insert('end', f"{where}\n")
            if len(entries) > 100:
                st.insert('end', f"  ... and {len(entries) - 100} more (Export Results has them all)\n")

        st.insert('end', '\nFILES\n', 'header')
        files = [f for f in report['files'] if 'error' in f] + \
                [f for f in report['files'] if 'error' not in f]
        for f in files[:500]:
            if 'error' in f:
                st.insert('end', f"  {f['file']}: failed ({f['error']})\n", 'alert_med')
            elif f.get('type') == 'capture':
                st.insert('end', f"  {f['file']}: {f['packets']} packets, "
                                 f"{f['alerts']} alerts, {f['credentials']} credentials\n")
            else:
                st.insert('end', f"  {f['file']}: {f['indicators']} indicators, "
                                 f"{f['secrets']} secrets{'  (' + f['note'] + ')' if f.get('note') else ''}\n")
        for f in report['skipped'][:200]:
            st.insert('end', f"  {f['file']}: skipped ({f['reason']})\n")
        hidden = max(0, len(files) - 500) + max(0, len(report['skipped']) - 200)
        if hidden:
            st.insert('end', f"  ... and {hidden} more (Export Results has them all)\n")

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
        self._pcap_alerts.clear()

        # Update UI state
        self._pcap_batch = None
        self._pcap_set_busy(True)
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
        batch = self._pcap_batch
        if batch and batch['running']:
            total = max(batch['total'], 1)
            done = batch['index'] + (analyzer.progress / 100 if analyzer.is_analyzing else 0)
            self._pcap_progress_var.set(min(done / total * 100, 100))
            self._pcap_progress_label.config(
                text=f"File {batch['index'] + 1} of {batch['total']}: {batch['name']}"
                if batch['total'] else "Collecting files...")
            self.root.after(200, self._pcap_update_progress)
        elif analyzer.is_analyzing:
            self._pcap_progress_var.set(analyzer.progress)
            self._pcap_progress_label.config(text=analyzer.progress_text)
            self.root.after(200, self._pcap_update_progress)
        else:
            self._pcap_progress_var.set(100)
            self._pcap_progress_label.config(
                text="Scan complete" if batch else analyzer.progress_text)
            self._pcap_set_busy(False)

    def _pcap_add_alert(self, alert):
        """Add a single alert to the PCAP results panel."""
        # A big folder can raise thousands. The table keeps the first
        # PCAP_ALERTS_SHOWN; the report and Export Results have every one.
        if len(self._pcap_alerts) < PCAP_ALERTS_SHOWN:
            self._pcap_alerts.add([alert.to_dict()], at_top=False)

    def _pcap_show_results(self, result):
        """Display final analysis results."""
        stats = result.get('stats', {})

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
        if self._pcap_batch:
            self._pcap_batch['cancel'] = True
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

        # A table, newest first (presentation.VAULT_ROWS_SHOWN). It was a row of
        # widgets per entry, and a building network's thousands of BACnet
        # entries left the window barely able to open or scroll.
        table = tk.Frame(left_card, bg=COLORS['bg_card'])
        table.pack(fill='both', expand=True)
        cols = ('time', 'protocol', 'kind', 'connection', 'value')
        tree = ttk.Treeview(table, columns=cols, show='headings', height=12,
                            selectmode='browse')
        for col, label, width in (('time', 'Last seen', 130), ('protocol', 'Protocol', 110),
                                  ('kind', 'Kind', 110), ('connection', 'Client → server', 230),
                                  ('value', 'Value (masked)', 220)):
            tree.heading(col, text=label)
            tree.column(col, width=width, minwidth=60, anchor='w')
        tree_sb = ttk.Scrollbar(table, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=tree_sb.set)
        tree.pack(side='left', fill='both', expand=True)
        tree_sb.pack(side='right', fill='y')
        tree.bind('<<TreeviewSelect>>', lambda e: self._forensics_show_selected())
        self._forensics_tree = tree
        self._forensics_rows = {}           # table row -> vault entry

        self._forensics_cred_detail = tk.Text(
            left_card, bg=COLORS['bg_card'], fg=COLORS['text'], font=('Consolas', 9),
            relief='flat', wrap='word', padx=8, pady=6, height=8, state='disabled')
        self._forensics_cred_detail.pack(fill='x', pady=(4, 0))
        cred_buttons = tk.Frame(left_card, bg=COLORS['bg_card'])
        cred_buttons.pack(fill='x', pady=(4, 0))
        self._forensics_reveal_btn = tk.Button(
            cred_buttons, text="🔓 Reveal Full Value", font=('Segoe UI', 8),
            bg=COLORS['bg_input'], fg=COLORS['yellow'], relief='flat', cursor='hand2',
            state='disabled', command=self._forensics_reveal_selected)
        self._forensics_reveal_btn.pack(side='left')
        self._forensics_copy_btn = tk.Button(
            cred_buttons, text="📋 Copy", font=('Segoe UI', 8),
            bg=COLORS['bg_input'], fg=COLORS['text_dim'], relief='flat', cursor='hand2',
            state='disabled', command=self._forensics_copy_selected)
        self._forensics_copy_btn.pack(side='left', padx=4)

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

        # Loaded whenever the tab is shown (_on_tab_changed), not a second after
        # the window opens, whether anyone looks or not. show_in_vault leaves
        # (protocol, server, port, client, kind) here for that load to select.
        self._forensics_focus = None

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

            # Load credentials (masked), at the entry show_in_vault asked for
            credentials = db.search_credentials()
            focus, self._forensics_focus = self._forensics_focus, None
            if focus is None:
                self._forensics_show_credentials(credentials)
            else:
                self._forensics_search_var.set('')
                self._forensics_proto_var.set('All')
                protocol, server, port, client, kind = focus
                entry = presentation.find_vault_entry(credentials, protocol, server, port,
                                                      client=client, credential_type=kind)
                self._forensics_show_credentials(credentials, select=entry)
                if entry is None:
                    self._forensics_detail(
                        f"The vault has no {protocol} entry for "
                        f"{presentation.endpoint(server, port)}. It is kept only while "
                        "forensics.save_credentials is on, and Clear All Data removes it.")

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
        except Exception:
            pass

    def _forensics_show_credentials(self, credentials, select=None):
        """Fill the table, newest first; select (a vault entry) is selected and shown."""
        tree = self._forensics_tree
        tree.delete(*tree.get_children())
        self._forensics_rows = {}
        rows, total = presentation.vault_rows(credentials)
        if select is not None and select not in rows:
            rows = [select] + rows[:-1] if len(rows) >= presentation.VAULT_ROWS_SHOWN else [select] + rows
        chosen = None
        for cred in rows:
            item = tree.insert('', 'end', values=(
                cred.get('time_str', ''), cred.get('protocol', '?'),
                cred.get('credential_type', '?'),
                f"{cred.get('source_ip', '?')} → "
                f"{presentation.endpoint(cred.get('destination_ip', '?'), cred.get('port'))}",
                cred.get('value', '')))
            self._forensics_rows[item] = cred
            if cred is select:
                chosen = item
        if chosen is not None:
            tree.selection_set(chosen)
            tree.see(chosen)
            self._forensics_show_selected()     # now, not when the select event comes round
        if total > len(rows):
            note = (f"Showing the newest {len(rows):,} of {total:,}. Search to find the others.")
        elif not total:
            note = ("No credentials found. They are captured from unencrypted protocols "
                    "(FTP, HTTP, Telnet and the like) while monitoring or analyzing a capture.")
        else:
            note = "Select one to see what was found."
        if chosen is None:
            self._forensics_detail(note)

    def _forensics_selected(self):
        selected = self._forensics_tree.selection()
        return self._forensics_rows.get(selected[0]) if selected else None

    def _forensics_detail(self, text):
        box = self._forensics_cred_detail
        box.config(state='normal')
        box.delete('1.0', 'end')
        box.insert('end', text)
        box.config(state='disabled')
        has_id = bool((self._forensics_selected() or {}).get('id'))
        for button in (self._forensics_reveal_btn, self._forensics_copy_btn):
            button.config(state='normal' if has_id else 'disabled')

    def _forensics_show_selected(self):
        cred = self._forensics_selected()
        if cred is None:
            return
        lines = [
            f"{cred.get('protocol', '?')} {cred.get('credential_type', '?')}, "
            f"last seen {cred.get('time_str', '') or '?'}",
            f"From {cred.get('source_ip', '?')} to "
            f"{presentation.endpoint(cred.get('destination_ip', '?'), cred.get('port'))}",
            f"Value (masked): {cred.get('value', '')}",
        ]
        for key, value in (cred.get('extra') or {}).items():
            if value:
                lines.append(f"{key}: {value}")
        self._forensics_detail('\n'.join(lines))

    def _forensics_reveal_selected(self):
        cred = self._forensics_selected()
        if cred and cred.get('id'):
            self._forensics_reveal(cred['id'], cred.get('protocol', '?'),
                                   cred.get('destination_ip', '?'), cred.get('port', '?'))

    def _forensics_copy_selected(self):
        cred = self._forensics_selected()
        if cred and cred.get('id'):
            self._forensics_copy(cred['id'])

    def show_in_vault(self, protocol, server, port, client='', credential_type=''):
        """
        Open the vault at the entry an alert or exposure is about, so what it
        found can be checked: an alert says only that a credential was seen.
        """
        # Switching tabs refreshes the vault (_on_tab_changed), whenever Tk gets
        # round to it; that refresh finds the entry, so it is not overwritten.
        self._forensics_focus = (protocol, server, port, client, credential_type)
        if self.notebook.select() == str(self._tab_forensics):
            self._forensics_refresh()
        else:
            self.notebook.select(self._tab_forensics)

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
            # By default only the masked value is kept (forensics_db.store_credential).
            messagebox.showinfo(
                "Not kept", "Only the masked value was kept. The vault stores full values "
                "only when forensics.store_raw_credentials is on in config.json.")

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

        # The riskiest first, and a few hundred at most: a building network lists
        # one service per controller.
        shown = sorted(services, key=lambda s: -presentation.severity_rank(s.get('risk')))
        if len(shown) > SERVICES_SHOWN:
            st.insert('end', f"The {SERVICES_SHOWN} riskiest of {len(shown):,}.\n\n", 'header')
            shown = shown[:SERVICES_SHOWN]
        for svc in shown:
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
                st.insert('end', "  Fix: ", 'header')
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
        wheel_scrollable(canvas)

        # IDS Settings
        ids_card = Card(scroll_frame, title="INTRUSION DETECTION")
        ids_card.pack(fill='x', padx=8, pady=8)

        self._setting_widgets = {}
        self._secret_widgets = {}
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
            # alert_threshold, not the pre-1.5 anomaly_threshold this used to
            # write: the engine prefers alert_threshold, so edits here did nothing.
            ('ml.alert_threshold', 'Anomaly Threshold (0-1)', '0.25'),
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

        perf_card = Card(scroll_frame, title="PERFORMANCE (applies at next start)")
        perf_card.pack(fill='x', padx=8, pady=(0, 8))
        self._add_setting_toggle(
            perf_card, 'performance.low_priority',
            'Run at lower priority, so your work comes first', False)
        self._add_setting_toggle(
            perf_card, 'gui.close_to_tray',
            'Closing the window keeps NetSentinel running in the tray', True)

        review_card = Card(scroll_frame, title="REVIEW MODE (applies at next start)")
        review_card.pack(fill='x', padx=8, pady=(0, 8))
        self._add_setting_toggle(
            review_card, 'review.enabled',
            'Save the traffic behind every alert, for a review bundle', False)
        self._add_setting_toggle(
            review_card, 'review.pseudonymise_lan',
            'Bundles replace LAN addresses with labels', False)
        self._add_setting_row(review_card, 'review.directory',
                              'Folder (blank: ~/.netsentinel/review)', '')
        self._add_setting_row(review_card, 'review.capture_budget_mb',
                              'Rolling capture budget (MB)', '2048')

        intel_card = Card(scroll_frame, title="THREAT DATA (applies at next start)")
        intel_card.pack(fill='x', padx=8, pady=(0, 8))
        self._add_setting_secret(
            intel_card, 'threat_intel.abuse_ch_auth_key', 'abuse.ch Auth-Key')
        tk.Label(intel_card, text=(
            "Free from auth.abuse.ch. Turns on URLhaus, ThreatFox and MalwareBazaar's "
            "hash list. It is sent only to abuse.ch, with each download."),
            font=('Segoe UI', 8), fg=COLORS['text_dim'], bg=COLORS['bg_card'],
            anchor='w', justify='left', wraplength=560).pack(fill='x')
        self._add_setting_toggle(
            intel_card, 'vulns.enabled',
            "Check devices' software against CISA's known exploited vulnerabilities "
            "(downloads the list daily)", True)
        tk.Button(intel_card, text="Threat data status", font=('Segoe UI', 9),
                  bg=COLORS['bg_input'], fg=COLORS['text'], relief='flat', padx=12,
                  cursor='hand2', command=self._show_threat_data
                  ).pack(anchor='w', pady=4)

        unifi_card = Card(scroll_frame, title="UNIFI (applies at next start)")
        unifi_card.pack(fill='x', padx=8, pady=(0, 8))
        self._add_setting_toggle(
            unifi_card, 'unifi.enabled',
            "Name devices from my UniFi console (read only, on this network)", False)
        self._add_setting_row(unifi_card, 'unifi.host', 'Console address (e.g. 192.168.1.1)', '')
        self._add_setting_row(unifi_card, 'unifi.site', 'Site', 'default')
        self._add_setting_secret(unifi_card, 'unifi.api_key', 'UniFi API key')
        tk.Label(unifi_card, text=(
            "Make the key in UniFi's Integrations settings. NetSentinel "
            "only reads the client list with it, never changes anything, and sends it "
            "only to this console."),
            font=('Segoe UI', 8), fg=COLORS['text_dim'], bg=COLORS['bg_card'],
            anchor='w', justify='left', wraplength=560).pack(fill='x')

        syslog_card = Card(scroll_frame, title="UNIFI TRAFFIC LOG OVER SYSLOG (applies at next start)")
        syslog_card.pack(fill='x', padx=8, pady=(0, 8))
        self._add_setting_toggle(
            syslog_card, 'syslog.enabled',
            "Receive my gateway's log, keep it by day, and show what each device was blocked from",
            False)
        self._add_setting_row(syslog_card, 'syslog.bind', "This PC's LAN address", '')
        self._add_setting_row(syslog_card, 'syslog.port', 'Port (UDP)', '5514')
        self._add_setting_row(syslog_card, 'syslog.allowed_senders', "Gateway's address", '')
        self._add_setting_row(syslog_card, 'syslog.keep_days', 'Days kept', '30')
        tk.Label(syslog_card, text=(
            "In UniFi (CyberSecure, Traffic Logging), choose SIEM Server with this PC's address "
            "and port; tick Gateway to be able to add Firewall Default Policy. UniFi sends the "
            "connections its firewall blocks, not the ones it allows. Windows Firewall must let "
            "the gateway in on that UDP port. Only the gateway's address is accepted, and "
            "nothing is ever sent back."),
            font=('Segoe UI', 8), fg=COLORS['text_dim'], bg=COLORS['bg_card'],
            anchor='w', justify='left', wraplength=560).pack(fill='x')

        geo_card = Card(scroll_frame, title="GEOIP (applies at next start)")
        geo_card.pack(fill='x', padx=8, pady=(0, 8))
        self._add_setting_toggle(
            geo_card, 'geoip.enabled',
            'Show the country and network of destinations (downloads DB-IP Lite monthly)',
            False)
        from src.geoip import ATTRIBUTION
        tk.Label(geo_card, text=ATTRIBUTION, font=('Segoe UI', 8),
                 fg=COLORS['text_dim'], bg=COLORS['bg_card'], anchor='w'
                 ).pack(fill='x')

        bacnet_card = Card(scroll_frame, title="BUILDING AUTOMATION, BACNET (applies at next start)")
        bacnet_card.pack(fill='x', padx=8, pady=(0, 8))
        self._add_setting_choice(bacnet_card, 'bacnet.mode', 'BACnet traffic', BACNET_CHOICES,
                                 'watch')
        tk.Label(bacnet_card, text=(
            "Watch: discovery from another computer, writes and device resets are alerts. "
            "This PC runs the building's controls: its own discovery, polling and writes are "
            "expected, and BACnet is not listed as an unencrypted service; resets, and writes "
            "from any other computer, are still alerts. Off: BACnet is left out of the "
            "capture altogether."),
            font=('Segoe UI', 8), fg=COLORS['text_dim'], bg=COLORS['bg_card'],
            anchor='w', justify='left', wraplength=560).pack(fill='x')

        audit_card = Card(scroll_frame, title="NETWORK AUDIT")
        audit_card.pack(fill='x', padx=8, pady=(0, 8))
        self._add_setting_toggle(
            audit_card, 'audit.enabled',
            'Allow audits of my own networks, run only when I ask (Audit button)', False)

        updates_card = Card(scroll_frame, title="UPDATES")
        updates_card.pack(fill='x', padx=8, pady=(0, 8))
        self._add_setting_toggle(
            updates_card, 'updates.check',
            'Check GitHub for a new version at start and daily (sends only the version)',
            True)
        tk.Button(updates_card, text="Check now", font=('Segoe UI', 9),
                  bg=COLORS['bg_input'], fg=COLORS['text'], relief='flat', padx=12,
                  cursor='hand2', command=self._check_for_update_now
                  ).pack(anchor='w', pady=4)

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

    def _add_setting_secret(self, parent, key, label):
        """A key, shown as dots and saved as text: the number cast in
        _save_settings would turn an all-digit key into an int."""
        row = tk.Frame(parent, bg=COLORS['bg_card'])
        row.pack(fill='x', pady=3)
        tk.Label(row, text=label, font=('Segoe UI', 9),
                 fg=COLORS['text_dim'], bg=COLORS['bg_card'],
                 width=30, anchor='w').pack(side='left')
        entry = tk.Entry(row, bg=COLORS['bg_input'], fg=COLORS['text'],
                         font=('Consolas', 9), relief='flat', show='•',
                         insertbackground=COLORS['accent'], width=40)
        entry.insert(0, str(self.app.config.get(*key.split('.'), default='') or ''))
        entry.pack(side='left', padx=8)
        self._secret_widgets[key] = entry

    def _show_threat_data(self):
        """Each source: in use or not, and why not (src/data_sources.py)."""
        from src import data_sources
        win = tk.Toplevel(self.root)
        win.title("Threat data")
        win.geometry("820x460")
        win.configure(bg=COLORS['bg_dark'])
        tree = ttk.Treeview(win, columns=('source', 'state', 'updated', 'entries', 'note'),
                            show='headings')
        for col, title, width in (('source', 'Source', 230), ('state', 'State', 80),
                                  ('updated', 'Updated', 120), ('entries', 'Entries', 80),
                                  ('note', 'Note', 300)):
            tree.heading(col, text=title)
            tree.column(col, width=width, anchor='w')
        tree.pack(fill='both', expand=True, padx=8, pady=8)
        for row in data_sources.collect(self.app):
            tree.insert('', 'end', values=(
                row['description'], row['state'], data_sources.when(row.get('updated')),
                f"{row['entries']:,}" if row.get('entries') else '', row.get('note', '')))

    def _add_setting_choice(self, parent, key, label, choices, default):
        """A drop-down of (value, text) pairs; the form reads back the value."""
        row = tk.Frame(parent, bg=COLORS['bg_card'])
        row.pack(fill='x', pady=3)
        tk.Label(row, text=label, font=('Segoe UI', 9), fg=COLORS['text_dim'],
                 bg=COLORS['bg_card'], width=30, anchor='w').pack(side='left')
        current = self.app.config.get(*key.split('.'), default=default)
        texts = dict(choices)
        var = tk.StringVar(value=texts.get(current, texts[default]))
        ttk.Combobox(row, textvariable=var, values=[t for _, t in choices], state='readonly',
                     width=36).pack(side='left', padx=8)
        self._setting_widgets[key] = _Choice(var, choices)

    def _add_setting_toggle(self, parent, key, label, default):
        # A checkbox, because a text box saved "False" as a string, which is true.
        var = tk.BooleanVar(value=bool(self.app.config.get(*key.split('.'), default=default)))
        tk.Checkbutton(parent, text=label, variable=var, font=('Segoe UI', 9),
                       fg=COLORS['text'], bg=COLORS['bg_card'],
                       activebackground=COLORS['bg_card'], activeforeground=COLORS['text'],
                       selectcolor=COLORS['bg_input'], anchor='w'
                       ).pack(fill='x', pady=3)
        self._setting_widgets[key] = var

    def _save_settings(self):
        """Save all settings from the UI to config."""
        raw = {key: (bool(entry.get()) if isinstance(entry, tk.BooleanVar) else entry.get())
               for key, entry in self._setting_widgets.items()}
        values, bad = settings_from_form(raw)
        if bad:
            messagebox.showerror(
                "Settings", "These need a number, so nothing was saved:\n\n" +
                "\n".join(f"  {key}: {raw[key]!r}" for key in bad))
            return
        for key, val in values.items():
            self.app.config.set(*key.split('.'), val)
        for key, entry in self._secret_widgets.items():
            self.app.config.set(*key.split('.'), entry.get().strip())

        # Save blacklist
        bl_text = self._blacklist_text.get('1.0', 'end').strip()
        bl_ips = [ip.strip() for ip in bl_text.split('\n') if ip.strip()]
        self.app.config.set('blacklists', 'ips', bl_ips)

        self.app.config.save()
        # Several settings (priority, review mode, GeoIP, thresholds) are read when
        # NetSentinel starts, so offer the restart that applies them.
        if messagebox.askyesno(
                "Settings",
                "Settings saved. Some take effect when NetSentinel starts.\n\n"
                "Restart now? Monitoring resumes if it is running."):
            self._restart()

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
        canvas.create_text(w//2, 172, text=f"Version {__version__}",
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
        t.insert('end', ' — signature and behaviour rules\n')
        t.insert('end', '  Port scans, brute force, SYN floods, DNS tunneling, ARP spoofing,\n', 'bullet')
        t.insert('end', '  data exfiltration, threat intel IP/domain matching, and more.\n\n', 'bullet')

        t.insert('end', '  ML Anomaly Detector', 'h2')
        t.insert('end', ' — Isolation Forest + statistical baseline\n')
        t.insert('end', '  Learns your network\'s normal behavior, then flags deviations.\n', 'bullet')
        t.insert('end', '  Detects beaconing, unusual port diversity, traffic spikes.\n\n', 'bullet')

        t.insert('end', '  Threat Intelligence', 'h2')
        t.insert('end', ' — free feeds, downloaded and matched here\n')
        t.insert('end', '  Feodo Tracker, SSL Blacklist, URLhaus, Emerging Threats, DShield,\n', 'bullet')
        t.insert('end', '  blocklist.de and more (the Threat data page lists them all).\n\n', 'bullet')

        t.insert('end', '  Network Forensics', 'h2')
        t.insert('end', ' — credential & protocol scanner\n')
        t.insert('end', '  Captures plaintext credentials from 50+ insecure protocols:\n', 'bullet')
        t.insert('end', '  FTP, HTTP, Telnet, SMTP, POP3, SNMP, Redis, MongoDB, VNC,\n', 'bullet')
        t.insert('end', '  cameras (RTSP), IoT (MQTT), SCADA (Modbus, BACnet).\n', 'bullet')
        t.insert('end', '  Masked values are saved to an encrypted vault\n', 'bullet')
        t.insert('end', '  (Fernet / AES-128-CBC). Raw secrets are stored only if\n', 'bullet')
        t.insert('end', '  forensics.store_raw_credentials is enabled.\n\n', 'bullet')

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
        # Off the Tk thread: starting runs the IOC scan and may wait for the last
        # capture to exit, and the window froze for all of it.
        if self._lifecycle_thread is not None:
            return
        stopping = self._monitoring
        self._lifecycle_was_start = not stopping
        self._start_btn.config(text="…  STOPPING" if stopping else "…  STARTING",
                               state='disabled')
        self._lifecycle_thread = threading.Thread(
            target=self.app.stop_monitoring if stopping else self.app.start_monitoring,
            daemon=True, name="MonitoringToggle")
        self._lifecycle_thread.start()

    def _sync_monitoring(self):
        """
        Show what the engine is doing, not what the button last asked for.

        The browser dashboard can start and stop monitoring too, and a start that
        failed used to leave the window saying it was monitoring.
        """
        finished = False
        if self._lifecycle_thread is not None:
            if self._lifecycle_thread.is_alive():
                return
            self._lifecycle_thread = None
            finished = True
        running = self.app.is_monitoring
        if running == self._monitoring and not finished:
            return
        self._monitoring = running
        if getattr(self, '_tray', None) is not None:
            self._tray.update(running)
        if running:
            self._start_btn.config(text="■  STOP MONITORING",
                                   bg=COLORS['red_dim'], state='normal')
            self._status_label.config(text="MONITORING", fg=COLORS['green'])
            self._status_dot.config(fg=COLORS['green'])
            self._statusbar_text.config(text="Monitoring active. Capturing packets...")
        else:
            self._start_btn.config(text="▶  START MONITORING",
                                   bg=COLORS['green_dim'], state='normal')
            self._status_label.config(text="STOPPED", fg=COLORS['text_dim'])
            self._status_dot.config(fg=COLORS['text_dim'])
            error = (self.app.last_start_error
                     if finished and self._lifecycle_was_start else '')
            self._statusbar_text.config(text=error or "Monitoring stopped.")
            if error:
                messagebox.showwarning("Monitoring did not start", error)

    def _on_new_alert(self, alert):
        """Called from a background thread when an alert arrives. No Tk here:
        _drain_alerts picks it up on the main thread."""
        self._pending_alerts.append(alert)

    def _drain_alerts(self):
        """
        Add the alerts that arrived since the last call, in one go, twice a second.
        Each used to be drawn as it came, so a burst of a few hundred was as many
        redraws in a row.
        """
        batch = []
        while self._pending_alerts:
            try:
                batch.append(self._pending_alerts.popleft())
            except IndexError:
                break
        if batch:
            try:
                self._add_alerts_to_gui(batch)
            except Exception as e:
                logger.debug("Adding alerts to the window failed: %s", e)
        self.root.after(ALERT_BATCH_MS, self._drain_alerts)

    def _add_alerts_to_gui(self, alerts):
        """Alerts in the order they came: to the Alerts tab (as its filter
        allows) and the dashboard's most recent."""
        sev_filter = self._alert_filter.get() if hasattr(self, '_alert_filter') else 'ALL'
        shown = [a.to_dict() for a in alerts
                 if sev_filter in ('ALL', '') or a.severity == sev_filter]
        if shown:
            self._alerts_table.add(shown)
        self._update_recent_alerts()

    def _current_alert(self, alert_id):
        """A stored alert as it is now, for its detail window; None if it is gone."""
        alert = self.app.alert_manager.get_alert(alert_id)
        return alert.to_dict() if alert is not None else None

    def _refresh_alerts_display(self):
        """Re-render alerts tab based on current filter selection."""
        sev_filter = self._alert_filter.get()

        # Reload from the alert manager (newest first), then apply the display filter
        alerts = presentation.filter_alerts(
            self.app.alert_manager.get_alerts(limit=self.app.alert_manager.max_stored),
            severity=sev_filter)
        self._alerts_table.show(a.to_dict() for a in alerts[:ALERTS_SHOWN])

    def _clear_all_alerts(self):
        if messagebox.askyesno("Clear Alerts", "Clear all alerts?"):
            self.app.alert_manager.clear_alerts()
            self._alerts_table.clear()
            self._update_recent_alerts()

    def _show_rule_record(self):
        """Per rule: alerts, and how many were judged real or a false positive."""
        win = tk.Toplevel(self.root)
        win.title("Rule record")
        win.geometry("760x420")
        win.configure(bg=COLORS['bg_dark'])
        tk.Label(win, text="Real and False positive (in an alert's window) acknowledge it and "
                           "record what it was. A rule with many false positives is where "
                           "detection needs work.",
                 font=('Segoe UI', 9), fg=COLORS['text_dim'], bg=COLORS['bg_dark'],
                 wraplength=720, justify='left', anchor='w').pack(fill='x', padx=12, pady=8)
        cols = ('rule', 'alerts', 'real', 'fp', 'acked', 'open', 'rate')
        tree = ttk.Treeview(win, columns=cols, show='headings')
        for col, width, label in (('rule', 220, 'Rule'), ('alerts', 70, 'Alerts'),
                                  ('real', 60, 'Real'), ('fp', 100, 'False positive'),
                                  ('acked', 120, 'Only acknowledged'), ('open', 60, 'Open'),
                                  ('rate', 120, 'False positive rate')):
            tree.heading(col, text=label)
            tree.column(col, width=width, minwidth=40, anchor='w' if col == 'rule' else 'e')
        tree.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        for r in self.app.alert_manager.rule_record():
            rate = r['false_positive_rate']
            tree.insert('', 'end', values=(
                r['rule_id'], r['alerts'], r['real'], r['false_positive'],
                r['acknowledged_only'], r['open'], '—' if rate is None else f"{rate:.0%}"))

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
        self._sync_monitoring()
        self._sync_update_notice()
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
            threat, colour_key = presentation.threat_level(
                ml_result.get('anomaly_score', 0))
            self._m_threat.set_value(threat, color=COLORS[colour_key])

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
            uptime_str = presentation.format_duration(uptime)
            dev_count = data.get('device_learner', {}).get('total_devices', 0)
            inc_count = data.get('correlator', {}).get('active_incidents', 0)
            pcap_buf = data.get('pcap_writer', {}).get('buffer_packets', 0)
            self._statusbar_right.config(
                text=f"Uptime: {uptime_str}  |  "
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

        breakdown = presentation.protocol_breakdown(protocols, limit=8)
        if not breakdown:
            return

        colors = [COLORS['accent'], COLORS['purple'], COLORS['cyan'],
                  COLORS['green'], COLORS['yellow'], COLORS['orange'],
                  COLORS['red'], COLORS['text_dim']]

        bar_h = max(14, (h - 20) // max(len(breakdown), 1))
        y = 10

        for i, (proto, _count, pct) in enumerate(breakdown):
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

        self._recent_alerts.show(alert.to_dict() for alert in alerts[:5])

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
            packets = list(self.app._packet_window)[-self._max_log_lines:]
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

    def _devices_refresh(self, once=False):
        """Refresh the device inventory display, while its tab is on screen."""
        if not (once or self._tab_shown(self._tab_devices)):
            self.root.after(5000, self._devices_refresh)
            return
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

        # Always rescheduled: gated on monitoring, the loop ran once at startup,
        # before anyone pressed Start, and never again.
        if not once:
            self.root.after(5000, self._devices_refresh)

    # ──────────────────────────────────────────────────────────────────────────
    # Tab: Exposures (src/exposures.py)
    # ──────────────────────────────────────────────────────────────────────────

    _EXPOSURE_SHOWN = {'Open': ('open',), 'Accepted': ('accepted',), 'Fixed': ('fixed',),
                       'All': ('open', 'accepted', 'fixed')}

    def _build_exposures_tab(self, parent):
        """Standing conditions, one row per device and issue, alerted on once."""
        top = tk.Frame(parent, bg=COLORS['bg_dark'])
        top.pack(fill='x', padx=8, pady=(8, 4))
        tk.Label(top, text="Exposures", font=('Segoe UI', 12, 'bold'),
                 fg=COLORS['accent'], bg=COLORS['bg_dark']).pack(side='left')
        self._exposures_summary = tk.Label(top, text="", font=('Segoe UI', 9),
                                           fg=COLORS['text_dim'], bg=COLORS['bg_dark'])
        self._exposures_summary.pack(side='left', padx=16)

        buttons = tk.Frame(top, bg=COLORS['bg_dark'])
        buttons.pack(side='right')
        self._exposures_show = tk.StringVar(value='Open')
        ttk.Combobox(buttons, textvariable=self._exposures_show, state='readonly', width=9,
                     values=list(self._EXPOSURE_SHOWN)).pack(side='left', padx=4)
        self._exposures_show.trace_add('write', lambda *_: self._exposures_refresh(once=True))
        for text, state in (('Mark fixed', 'fixed'), ('Accept', 'accepted'), ('Reopen', 'open')):
            tk.Button(buttons, text=text, command=lambda s=state: self._exposure_set(s),
                      bg=COLORS['bg_input'], fg=COLORS['text'], font=('Segoe UI', 9),
                      relief='flat').pack(side='left', padx=4)
        # For a plaintext login: the vault entry behind it, to see what was found.
        self._exposure_vault_btn = tk.Button(
            buttons, text='Open in vault', command=self._exposure_open_in_vault,
            bg=COLORS['bg_input'], fg=COLORS['text'], font=('Segoe UI', 9), relief='flat',
            state='disabled')
        self._exposure_vault_btn.pack(side='left', padx=4)

        tk.Label(parent,
                 text="What is set up unsafely: plaintext logins, unencrypted services, software "
                      "with known exploited flaws. Each is alerted once, and again only if it "
                      "gets worse or comes back after you mark it fixed. Accept one you have "
                      "decided to live with.",
                 font=('Segoe UI', 8), fg=COLORS['text_dim'], bg=COLORS['bg_dark'],
                 anchor='w', justify='left', wraplength=1100).pack(fill='x', padx=12, pady=(0, 4))

        cols = ('severity', 'title', 'device', 'count', 'last_seen', 'state')
        self._exposures_tree = ttk.Treeview(parent, columns=cols, show='headings', height=16)
        for col, width, label in (('severity', 80, 'Severity'), ('title', 380, 'Exposure'),
                                  ('device', 220, 'Device'), ('count', 70, 'Seen'),
                                  ('last_seen', 130, 'Last seen'), ('state', 80, 'State')):
            self._exposures_tree.heading(col, text=label)
            self._exposures_tree.column(col, width=width, minwidth=50)
        for sev, colour in SEVERITY_COLORS.items():
            self._exposures_tree.tag_configure(sev, foreground=colour)
        self._exposures_tree.pack(fill='both', expand=True, padx=8, pady=4)
        self._exposures_tree.bind('<<TreeviewSelect>>', lambda e: self._exposure_details())

        self._exposures_detail = tk.Label(parent, text="", font=('Segoe UI', 9),
                                          fg=COLORS['text'], bg=COLORS['bg_dark'], anchor='w',
                                          justify='left', wraplength=1100)
        self._exposures_detail.pack(fill='x', padx=12, pady=(0, 8))
        self._exposures_by_id = {}
        self.root.after(3000, self._exposures_refresh)

    def _exposures_refresh(self, once=False):
        if not (once or self._tab_shown(self._tab_exposures)):
            self.root.after(5000, self._exposures_refresh)
            return
        try:
            registry = self.app.exposures
            counts = registry.counts()
            sev = counts['open_by_severity']
            self._exposures_summary.config(
                text=f"{counts['open']} open ({sev.get('HIGH', 0)} high, "
                     f"{sev.get('MEDIUM', 0)} medium) · {counts['accepted']} accepted · "
                     f"{counts['fixed']} fixed · {counts['repeats_folded']} repeats folded in")
            shown = self._EXPOSURE_SHOWN.get(self._exposures_show.get(), ('open',))
            entries = [e for e in registry.entries() if e['state'] in shown]
            self._exposures_by_id = {e['id']: e for e in entries}
            tree = self._exposures_tree
            selected = set(tree.selection())
            tree.delete(*tree.get_children())
            for e in entries:
                device = e['device'] + (f" ({e['device_name']})" if e.get('device_name') else '')
                if e.get('port'):
                    device += f":{e['port']}"
                tree.insert('', 'end', iid=e['id'], tags=(e['severity'],), values=(
                    e['severity'], e['title'], device, e['count'],
                    time.strftime('%Y-%m-%d %H:%M', time.localtime(e['last_seen'])), e['state']))
            keep = [i for i in selected if tree.exists(i)]
            if keep:
                tree.selection_set(keep)
            self._exposure_details()
        except Exception as e:
            logger.debug("Exposures refresh error: %s", e)
        if not once:
            self.root.after(5000, self._exposures_refresh)   # see _devices_refresh

    def _exposure_details(self):
        selected = self._exposures_tree.selection()
        entry = self._exposures_by_id.get(selected[0]) if selected else None
        self._exposure_vault_btn.config(
            state='normal' if entry is not None and entry.get('kind') == 'credential'
            else 'disabled')
        if entry is None:
            self._exposures_detail.config(text="Select an exposure to see what to do about it.")
            return
        clients = ', '.join(entry.get('clients') or []) or '—'
        self._exposures_detail.config(text=(
            f"{entry['description']}\n\nWhat to do: {entry.get('recommendation') or '—'}\n"
            f"Seen from: {clients} · first seen {entry.get('time_first', '')}"))

    def _exposure_open_in_vault(self):
        """The vault entry behind a plaintext-login exposure. Its key is
        ('credential', protocol, kind, server, port) (exposures.exposure_key)."""
        selected = self._exposures_tree.selection()
        entry = self._exposures_by_id.get(selected[0]) if selected else None
        if entry is None or entry.get('kind') != 'credential':
            return
        key = list(entry.get('key') or []) + [''] * 5
        clients = entry.get('clients') or ['']
        self.show_in_vault(key[1], entry.get('device', ''), entry.get('port', 0),
                           client=clients[-1], credential_type=key[2])

    def _open_alert_in_vault(self, alert_dict):
        """AlertActions.open_vault: a credential alert's vault entry."""
        ev = alert_dict.get('evidence') or {}
        self.show_in_vault(ev.get('protocol', ''), alert_dict.get('dst_ip', ''),
                           alert_dict.get('dst_port', 0), client=alert_dict.get('src_ip', ''),
                           credential_type=ev.get('credential_type', ''))
        self.root.lift()

    def _exposure_set(self, state):
        selected = self._exposures_tree.selection()
        if not selected:
            return
        if state == 'accepted' and not messagebox.askyesno(
                "Accept exposure",
                "Accept this and never be alerted about it again unless it gets worse?"):
            return
        for ident in selected:
            try:
                self.app.exposures.set_state(ident, state)
            except (KeyError, ValueError) as e:
                logger.debug("Exposure %s: %s", ident, e)
        self._exposures_refresh(once=True)

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
        wheel_scrollable(self._incidents_canvas)

        self.root.after(3000, self._incidents_refresh)

    def _incidents_refresh(self, once=False):
        """Refresh the incidents display, while its tab is on screen."""
        if not (once or self._tab_shown(self._tab_incidents)):
            self.root.after(5000, self._incidents_refresh)
            return
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

        if not once:
            self.root.after(5000, self._incidents_refresh)   # see _devices_refresh

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

    def _capture_refresh(self, once=False):
        """Refresh capture status and file list, while its tab is on screen."""
        if not (once or self._tab_shown(self._tab_capture)):
            self.root.after(5000, self._capture_refresh)
            return
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

        if not once:
            self.root.after(5000, self._capture_refresh)   # see _devices_refresh

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _tab_shown(self, tab):
        """
        Is this tab the one on screen? The Devices, Exposures, Incidents and
        Capture tabs each rebuilt their whole page every five seconds, seen or
        not and monitoring or not. On a building network, with hundreds of
        controllers in the device list and on the Exposures page, the window
        stalled every few seconds even with monitoring stopped.
        """
        try:
            return (self.root.state() not in ('withdrawn', 'iconic')
                    and self.notebook.select() == str(tab))
        except tk.TclError:
            return False

    def _on_tab_changed(self):
        """Draw the tab just opened now, not at its next five-second turn."""
        try:
            shown = self.notebook.select()
        except tk.TclError:
            return
        refresh = {
            str(self._tab_devices): self._devices_refresh,
            str(self._tab_exposures): self._exposures_refresh,
            str(self._tab_incidents): self._incidents_refresh,
            str(self._tab_capture): self._capture_refresh,
        }.get(shown)
        if refresh is not None:
            refresh(once=True)
        elif shown == str(self._tab_forensics):
            self._forensics_refresh()

    _format_bytes = staticmethod(presentation.format_bytes)

    _format_number = staticmethod(presentation.format_number)

    def run(self):
        """Start the GUI main loop."""
        logger.info("GUI started.")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        """The window's close button: hide to the tray if there is one, else quit."""
        if self._tray is not None:
            self.root.withdraw()
            if not self._told_about_tray:
                self._told_about_tray = True
                self._tray.notify("NetSentinel is still running. Its tray icon opens "
                                  "it again, or quits.")
            return
        self._quit()

    # ─── Tray, restart and quit ──────────────────────────────────────────

    def _poll_tray(self):
        """Run the tray's menu actions here, on the Tk thread."""
        handlers = {'show': self._show_window, 'dashboard': self._open_dashboard,
                    'toggle': self._toggle_monitoring, 'restart': self._restart,
                    'quit': self._quit}
        while True:
            try:
                action = self._tray_actions.get_nowait()
            except queue.Empty:
                break
            handler = handlers.get(action)
            if handler is not None:
                handler()
            if action in ('restart', 'quit') and self._tray is None:
                return              # the window is gone
        self.root.after(150, self._poll_tray)

    def _show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _shutdown(self):
        # Unconditionally: monitoring may have been started from the browser, and
        # stopping saves alerts and learned data either way.
        if self._tray is not None:
            self._tray.stop()
            self._tray = None
        self.app.stop_monitoring()
        server = getattr(self.app, 'web_server', None)
        if server is not None:
            server.stop()           # free the port for the next copy

    def _quit(self):
        self._shutdown()
        self.root.destroy()

    # ─── Updates (src/updater.py) ────────────────────────────────────────

    def _sync_update_notice(self):
        """Show the status bar's update button once a newer release is known."""
        updater = getattr(self.app, 'updater', None)
        info = updater.available if updater is not None else None
        version = info.version if info else None
        if version == self._update_shown:
            return
        self._update_shown = version
        if version:
            self._update_button.config(text=f"⬆  Update to {version}")
            self._update_button.pack(side='right', padx=4, pady=3)
        else:
            self._update_button.pack_forget()

    def _check_for_update_now(self):
        updater = getattr(self.app, 'updater', None)
        if updater is None:
            return

        def work():
            info = updater.check()
            self.root.after(0, done, info)

        def done(info):
            self._sync_update_notice()
            if info:
                self._show_update()
            elif updater.last_error:
                messagebox.showwarning("Updates", f"Could not reach GitHub: {updater.last_error}")
            else:
                messagebox.showinfo("Updates", f"NetSentinel {__version__} is the latest version.")

        threading.Thread(target=work, name='update-check-now', daemon=True).start()

    def _show_update(self):
        """The release's notes, and Install for the exe."""
        import webbrowser
        updater = getattr(self.app, 'updater', None)
        info = updater.available if updater is not None else None
        if info is None:
            return
        win = tk.Toplevel(self.root)
        win.title(f"NetSentinel {info.version}")
        win.geometry("640x520")
        win.configure(bg=COLORS['bg_dark'])
        tk.Label(win, text=f"NetSentinel {info.version} is available. This is {__version__}.",
                 font=('Segoe UI', 11, 'bold'), fg=COLORS['text'], bg=COLORS['bg_dark'],
                 anchor='w').pack(fill='x', padx=12, pady=(12, 6))
        notes = tk.Text(win, bg=COLORS['bg_input'], fg=COLORS['text'], font=('Segoe UI', 9),
                        relief='flat', wrap='word', height=18)
        notes.insert('1.0', info.notes or 'No release notes.')
        notes.config(state='disabled')
        notes.pack(fill='both', expand=True, padx=12)

        if not updater.can_install:
            why = "Running from source: update with git pull, or download the exe."
        elif not info.installable:
            why = "This release has no signature to check. Download it from the release page."
        else:
            why = ("Install downloads the exe, checks its signature and checksum, and "
                   "restarts into it. Monitoring resumes if it is running.")
        status = tk.Label(win, text=why, font=('Segoe UI', 9), fg=COLORS['text_dim'],
                          bg=COLORS['bg_dark'], anchor='w', justify='left', wraplength=600)
        status.pack(fill='x', padx=12, pady=6)

        buttons = tk.Frame(win, bg=COLORS['bg_dark'])
        buttons.pack(fill='x', padx=12, pady=(0, 12))
        install = tk.Button(buttons, text="Install and restart", font=('Segoe UI', 9, 'bold'),
                            bg=COLORS['accent'], fg=COLORS['bg_dark'], relief='flat',
                            padx=12, cursor='hand2')
        if updater.can_install and info.installable:
            install.pack(side='left')
        tk.Button(buttons, text="Release page", font=('Segoe UI', 9), relief='flat', padx=12,
                  command=lambda: webbrowser.open(info.page_url)).pack(side='left', padx=8)
        tk.Button(buttons, text="Later", font=('Segoe UI', 9), relief='flat', padx=12,
                  command=win.destroy).pack(side='right')

        def say(text):
            self.root.after(0, lambda: status.config(text=text))

        def work():
            try:
                path = updater.download(info, progress=say)
            except Exception as e:
                self.root.after(0, failed, str(e) or e.__class__.__name__)
                return
            self.root.after(0, finish, path)

        def failed(message):
            status.config(text=message, fg=COLORS['red'])
            install.config(state='normal')

        def finish(path):
            try:
                updater.hand_over(path, monitor=self.app.is_monitoring)
            except OSError as e:
                failed(f"Could not start the new version: {e}")
                return
            self._statusbar_text.config(text=f"Updating to {info.version}...")
            self._shutdown()
            self.root.destroy()

        def start():
            install.config(state='disabled')
            size = f" ({info.exe_size / 1e6:.0f} MB)" if info.exe_size else ''
            status.config(text=f"Downloading NetSentinel {info.version}{size}...",
                          fg=COLORS['text_dim'])
            threading.Thread(target=work, name='update-download', daemon=True).start()

        install.config(command=start)

    def _restart(self):
        """Start a new copy with the same arguments, monitoring if this one was, and exit."""
        from src.restart import relaunch
        try:
            relaunch(monitor=self.app.is_monitoring)
        except OSError as e:
            messagebox.showerror("Restart", f"Could not start NetSentinel again: {e}")
            return
        self._statusbar_text.config(text="Restarting...")
        self._shutdown()
        self.root.destroy()
