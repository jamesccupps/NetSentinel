"""
The mouse wheel in the desktop window.
=======================================
Three of the scrolling pages bound the wheel for the whole application, so one
turn scrolled all three, on whatever tab each was, and the other six pages did
not scroll at all. Fake widgets stand in for Tk here, so no window opens.
"""

import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

try:
    from src import gui
except ImportError:                 # no tkinter
    gui = None


class Widget:
    def __init__(self, kind='Frame', master=None, view=(0.0, 1.0), wheel=False):
        self.kind, self.master, self.view, self.scrolled = kind, master, view, []
        if wheel:
            self.wheel_scrolls = True
        self.under_pointer = None

    def winfo_class(self):
        return self.kind

    def winfo_containing(self, x, y):
        return self.under_pointer

    def yview(self):
        return self.view

    def yview_scroll(self, n, what):
        self.scrolled.append((n, what))


def wheel(widget, delta=-120, under=None):
    widget.under_pointer = under
    gui.on_mousewheel(SimpleNamespace(widget=widget, delta=delta, num='??',
                                      x_root=10, y_root=10))


@unittest.skipIf(gui is None, 'tkinter is not installed')
class TestWheel(unittest.TestCase):

    def setUp(self):
        # A page of the window, with a card holding a label, and a second page.
        self.page = Widget('Canvas', view=(0.0, 0.4), wheel=True)
        self.card = Widget('Frame', self.page)
        self.label = Widget('Label', self.card)
        self.other_page = Widget('Canvas', view=(0.0, 0.4), wheel=True)

    def test_only_the_page_under_the_pointer_scrolls(self):
        wheel(self.label)
        self.assertEqual(self.page.scrolled, [(1, 'units')])
        self.assertEqual(self.other_page.scrolled, [], 'a page on another tab scrolled too')

    def test_up_is_up(self):
        wheel(self.label, delta=240)
        self.assertEqual(self.page.scrolled, [(-2, 'units')])

    def test_a_touchpads_small_steps_still_scroll(self):
        wheel(self.label, delta=-30)
        self.assertEqual(self.page.scrolled, [(1, 'units')])

    def test_x11_buttons(self):
        self.assertEqual(gui.wheel_steps(SimpleNamespace(num=4, delta=0)), -1)
        self.assertEqual(gui.wheel_steps(SimpleNamespace(num=5, delta=0)), 1)

    def test_a_text_box_with_more_scrolls_itself_and_not_the_page(self):
        """Its own binding has scrolled it; scrolling the page as well moved both."""
        text = Widget('Text', self.card, view=(0.2, 0.6))
        wheel(text)
        self.assertEqual(text.scrolled, [])
        self.assertEqual(self.page.scrolled, [])

    def test_a_text_box_that_fits_passes_the_wheel_to_the_page(self):
        text = Widget('Text', self.card, view=(0.0, 1.0))
        wheel(text)
        self.assertEqual(self.page.scrolled, [(1, 'units')])

    def test_an_inner_list_that_fits_passes_it_on_too(self):
        inner = Widget('Canvas', self.card, view=(0.0, 1.0), wheel=True)
        wheel(Widget('Label', inner))
        self.assertEqual(inner.scrolled, [])
        self.assertEqual(self.page.scrolled, [(1, 'units')])

    def test_the_widget_under_the_pointer_wins_over_the_one_with_focus(self):
        focused = Widget('Entry', Widget('Frame', self.other_page))
        wheel(focused, under=self.label)
        self.assertEqual(self.page.scrolled, [(1, 'units')])
        self.assertEqual(self.other_page.scrolled, [])

    def test_a_scrollbar_is_left_to_its_own_binding(self):
        wheel(Widget('TScrollbar', self.card))
        self.assertEqual(self.page.scrolled, [])

    def test_a_canvas_that_is_only_a_chart_is_not_scrolled(self):
        chart = Widget('Canvas', self.card, view=(0.0, 0.5))
        wheel(chart)
        self.assertEqual(chart.scrolled, [])
        self.assertEqual(self.page.scrolled, [(1, 'units')])

    def test_nothing_under_a_page_does_nothing(self):
        wheel(Widget('Label', Widget('Frame')))      # must not raise

    def test_no_page_binds_the_wheel_for_the_whole_app_any_more(self):
        with open(gui.__file__, encoding='utf-8') as f:
            source = f.read()
        self.assertEqual(source.count('bind_all('), 3, 'only wheel_scrollable binds it')
        self.assertEqual(source.count('wheel_scrollable('), 10)


if __name__ == '__main__':
    unittest.main(verbosity=2)
