"""
Judging an alert acknowledges it, and each rule keeps a record.
===============================================================
In a week of the owner's alerts 274 were acknowledged by hand and not one was
judged: acknowledging was one click and judging another, and the desktop app
had no way to judge at all. So NetSentinel learnt nothing from a week of
attention, and nothing said which rules were wrong most often.
Addresses here are made up.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_headless import _ApiTestCase  # noqa: E402

PC, SITE = '192.168.10.32', '203.0.113.50'


def stored(rule, acknowledged=False, verdict=None):
    from src.ids_engine import Alert
    a = Alert(rule, 'HIGH', rule, 'd', src_ip=PC, dst_ip=SITE)
    a.acknowledged = acknowledged
    if verdict:
        a.evidence['your_verdict'] = verdict
    return a


class TestAVerdictAcknowledges(unittest.TestCase):

    def app(self, alert):
        from src.app import NetSentinelApp

        class _Manager:
            def get_alert(self, alert_id):
                return alert if alert_id == alert.id else None

            def acknowledge_alert(self, alert_id):
                alert.acknowledged = True
                return True

        class _Confirmed:
            def add(self, record, note='', review_id=''):
                return {'rule_id': record['rule_id'], 'kind': 'dst_ip', 'value': SITE}

        class _Baseline:
            confirmed = _Confirmed()

        app = NetSentinelApp.__new__(NetSentinelApp)
        app.alert_manager, app.review, app.ids_engine = _Manager(), None, None
        app.baseline_whitelist = _Baseline()
        return app

    def test_real_and_false_positive_both_acknowledge(self):
        for verdict in ('real', 'false_positive'):
            with self.subTest(verdict):
                alert = stored('PORT-SCAN')
                self.app(alert).record_verdict(alert.id, verdict)
                self.assertTrue(alert.acknowledged)
                self.assertEqual(alert.evidence['your_verdict'], verdict)

    def test_a_refused_verdict_acknowledges_nothing(self):
        alert = stored('PORT-SCAN')
        with self.assertRaises(ValueError):
            self.app(alert).record_verdict(alert.id, 'maybe')
        self.assertFalse(alert.acknowledged)


class TestTheRuleRecord(unittest.TestCase):

    def manager(self, alerts):
        from src.alerts import AlertManager
        m = AlertManager(reset_config())
        m._alerts.clear()
        m._alerts.extend(alerts)
        return m

    def test_counts_and_rate(self):
        m = self.manager([
            stored('DATA-EXFIL', verdict='false_positive'),
            stored('DATA-EXFIL', verdict='false_positive'),
            stored('DATA-EXFIL', verdict='real'),
            stored('DATA-EXFIL', acknowledged=True),
            stored('PORT-SCAN'),
        ])
        rows = {r['rule_id']: r for r in m.rule_record()}
        self.assertEqual(rows['DATA-EXFIL'], {
            'rule_id': 'DATA-EXFIL', 'alerts': 4, 'real': 1, 'false_positive': 2,
            'acknowledged_only': 1, 'open': 0, 'false_positive_rate': 0.667})
        self.assertIsNone(rows['PORT-SCAN']['false_positive_rate'])
        self.assertEqual([r['rule_id'] for r in m.rule_record()], ['DATA-EXFIL', 'PORT-SCAN'])


class TestTheDashboardRoute(_ApiTestCase):

    def test_rules_page(self):
        self.app.alert_manager.rule_record = lambda: [
            {'rule_id': 'PORT-SCAN', 'alerts': 3, 'real': 1, 'false_positive': 1,
             'acknowledged_only': 0, 'open': 1, 'false_positive_rate': 0.5}]
        self.assertEqual(self.get_json('/api/rules')['rules'][0]['false_positive_rate'], 0.5)

    def test_without_a_record_it_is_empty(self):
        self.assertEqual(self.get_json('/api/rules'), {'rules': []})

    def test_the_verdict_buttons_say_they_acknowledge(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(here, 'src', 'webui', 'app.js'), encoding='utf-8') as f:
            script = f.read()
        start = script.index('function verdictButtons')
        self.assertIn('Acknowledge it', script[start:script.index('\n}\n', start)])


class TestTheDesktopApp(unittest.TestCase):

    def test_the_actions_go_through_the_app(self):
        from src.gui import AlertActions
        calls = []

        class _App:
            class alert_manager:
                @staticmethod
                def acknowledge_alert(alert_id):
                    calls.append(('ack', alert_id))
                    return True

            def record_verdict(self, alert_id, verdict):
                calls.append((verdict, alert_id))

        actions = AlertActions(_App())
        actions.acknowledge(4)
        actions.verdict(5, 'real')
        self.assertEqual(calls, [('ack', 4), ('real', 5)])

    def test_a_stored_alert_row_carries_them(self):
        import inspect
        from src import gui
        source = inspect.getsource(gui.NetSentinelGUI)
        # The Alerts tab's table and the dashboard's recent alerts (test_alert_table).
        self.assertEqual(source.count('AlertTable(parent, actions=self._alert_actions,'), 1)
        self.assertEqual(source.count('actions=self._alert_actions'), 2)
        self.assertIn(json.dumps('Rule record')[1:-1], source)


if __name__ == '__main__':
    unittest.main()
