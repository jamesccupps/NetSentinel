"""
Alerts in the desktop window.
=============================
Each alert was a block of a dozen widgets in one long scrolling frame, and every
new one made Tk lay all of them out again: 0.15 to 0.4 seconds of frozen window
per alert with 200 listed, plus as much again to rebuild the dashboard's five
most recent. A building network's few hundred BACnet alerts froze the window for
minutes. Alerts are rows in a table now, and arrive in batches twice a second.
Addresses are made-up LAN examples.
"""

import os
import sys
import unittest
from collections import deque
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401

from src import gui  # noqa: E402

CONTROLLER = '192.168.50.31'


def alert(i, severity='HIGH', **fields):
    a = {'id': i, 'time_str': f'2026-11-13 05:{i // 60 % 60:02d}:{i % 60:02d}',
         'severity': severity, 'title': f'Alert {i}', 'rule_id': 'FORENSICS-SENSITIVE-DATA',
         'src_ip': f'192.168.50.{i % 250 + 1}', 'src_port': 0,
         'dst_ip': CONTROLLER, 'dst_port': 47808, 'acknowledged': False, 'evidence': {}}
    a.update(fields)
    return a


class _WithTk(unittest.TestCase):

    def setUp(self):
        import tkinter as tk
        try:
            self.root = tk.Tk()
        except tk.TclError as e:           # no display (GitHub's Linux runners)
            self.skipTest(f'no display for Tk: {e}')
        self.root.withdraw()

    def tearDown(self):
        self.root.destroy()

    def titles(self, table):
        return [table.tree.set(item, 'title') for item in table.tree.get_children()]


class TestAlertTable(_WithTk):

    def test_newest_first_and_the_oldest_go_past_the_limit(self):
        table = gui.AlertTable(self.root, limit=3)
        table.show([alert(2), alert(1)])
        table.add([alert(3), alert(4)])        # in the order they came
        self.assertEqual(self.titles(table), ['Alert 4', 'Alert 3', 'Alert 2'])
        self.assertEqual(len(table), 3)

    def test_a_capture_lists_in_order(self):
        table = gui.AlertTable(self.root, limit=5)
        for i in range(3):
            table.add([alert(i)], at_top=False)
        self.assertEqual(self.titles(table), ['Alert 0', 'Alert 1', 'Alert 2'])

    def test_rows_are_not_widgets(self):
        """A burst of alerts adds rows, not a dozen widgets each."""
        table = gui.AlertTable(self.root)
        before = len(table.winfo_children())
        table.add(alert(i) for i in range(300))
        self.assertEqual(len(table.winfo_children()), before)
        self.assertEqual(len(table), 300)

    def test_a_row_says_where_without_an_unknown_port(self):
        row = gui.AlertTable.values(alert(7, acknowledged=True))
        self.assertEqual(row['route'], f'192.168.50.8 → {CONTROLLER}:47808')
        self.assertEqual((row['severity'], row['ack']), ('HIGH', '✓'))

    def test_a_click_opens_the_alert_as_it_is_now(self):
        opened = []
        real = gui.AlertDetailWindow
        gui.AlertDetailWindow = lambda parent, a, actions=None: opened.append((a, actions))
        try:
            actions = object()
            later = alert(5, title='Alert 5, verified')
            table = gui.AlertTable(self.root, actions=actions,
                                   lookup=lambda i: later if i == 5 else None)
            table.show([alert(5), alert(6)])
            first, second = table.tree.get_children()
            table._open(first)
            table._open(second)               # gone from the store: the row's own
        finally:
            gui.AlertDetailWindow = real
        self.assertEqual([(a['title'], act) for a, act in opened],
                         [('Alert 5, verified', actions), ('Alert 6', actions)])


class TestAlertsArriveInBatches(unittest.TestCase):
    """No Tk from the threads that raise alerts; the window takes them twice a second."""

    def window(self):
        w = gui.NetSentinelGUI.__new__(gui.NetSentinelGUI)
        w._pending_alerts = deque()
        w.after_calls = []
        w.root = SimpleNamespace(after=lambda ms, fn, *a: w.after_calls.append(ms))
        w.batches = []
        w._add_alerts_to_gui = w.batches.append
        return w

    def test_a_new_alert_is_only_queued(self):
        w = self.window()
        w.root = None                      # any Tk call would fail
        w._on_new_alert('first')
        self.assertEqual(list(w._pending_alerts), ['first'])

    def test_a_burst_is_one_batch_in_the_order_it_came(self):
        w = self.window()
        for i in range(250):
            w._on_new_alert(i)
        w._drain_alerts()
        w._drain_alerts()                  # nothing new: nothing drawn
        self.assertEqual(w.batches, [list(range(250))])
        self.assertEqual(w.after_calls, [gui.ALERT_BATCH_MS] * 2)

    def test_every_stored_alert_list_can_judge_and_look_up(self):
        """The Alerts tab and the dashboard's recent alerts carry the actions
        (Real, False positive, Acknowledge, Open in vault) and the lookup."""
        import inspect
        source = inspect.getsource(gui.NetSentinelGUI)
        self.assertEqual(source.count('AlertTable('), 3)
        self.assertEqual(source.count('actions=self._alert_actions'), 2)
        self.assertEqual(source.count('lookup=self._current_alert'), 2)


if __name__ == '__main__':
    unittest.main()
