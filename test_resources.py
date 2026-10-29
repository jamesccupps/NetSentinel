"""
What NetSentinel costs, and what it keeps in memory.
=====================================================
The handoff asked whether NetSentinel takes the machine's resources. These cover
the numbers the dashboard now shows, the lower-priority option, and structures
that grew for as long as the program ran.
"""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src.alert_correlator import AlertCorrelator, Incident, MAX_ALERTS_PER_INCIDENT  # noqa: E402
from src.config import CONFIG_FILE, Config  # noqa: E402
from src.ids_engine import Alert  # noqa: E402
from src.resources import ResourceMonitor  # noqa: E402

ROOT = os.path.dirname(os.path.abspath(__file__))


class TestResourceMonitor(unittest.TestCase):

    def test_a_snapshot_reads_this_process(self):
        snap = ResourceMonitor().snapshot()
        self.assertTrue(snap['available'])
        self.assertGreater(snap['rss_bytes'], 1 << 20)
        self.assertGreaterEqual(snap['threads'], 1)
        self.assertGreaterEqual(snap['cpu_percent'], 0)
        self.assertLessEqual(snap['cpu_percent'], 100)

    def test_lower_priority_takes_effect(self):
        """In a child process, so the test run itself keeps its priority."""
        script = ("from src.resources import ResourceMonitor, set_low_priority\n"
                  "ok = set_low_priority()\n"
                  "print(ok, ResourceMonitor().snapshot()['low_priority'])\n")
        done = subprocess.run([sys.executable, '-c', script], cwd=ROOT,
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.split(), ['True', 'True'])


class TestIncidentsStayBounded(unittest.TestCase):

    def alert(self, n):
        return Alert('PORT-SCAN', 'HIGH', 'Scan', f'scan {n}', src_ip='10.0.0.9',
                     category='Reconnaissance')

    def test_one_incident_keeps_a_bounded_list_and_the_full_count(self):
        """An incident active through an alert storm kept every alert it absorbed."""
        incident = Incident()
        for n in range(MAX_ALERTS_PER_INCIDENT + 100):
            incident.add_alert(self.alert(n))
        self.assertEqual(len(incident.alerts), MAX_ALERTS_PER_INCIDENT)
        self.assertEqual(incident.alert_count, MAX_ALERTS_PER_INCIDENT + 100)
        self.assertEqual(incident.to_dict()['alert_count'], MAX_ALERTS_PER_INCIDENT + 100)
        self.assertIn(str(MAX_ALERTS_PER_INCIDENT + 100), incident.title)

    def test_a_reloaded_incident_keeps_its_count(self):
        """The count was saved but not read back, so history said '0 alerts'."""
        correlator = AlertCorrelator(Config().load())
        for n in range(7):
            correlator.process_alert(self.alert(n))
        correlator.save()
        self.addCleanup(lambda: os.path.exists(correlator._db_path)
                        and os.remove(correlator._db_path))
        reloaded = AlertCorrelator(Config().load())
        self.assertEqual(reloaded._all_incidents[-1].to_dict()['alert_count'], 7)


class TestConfigFile(unittest.TestCase):

    def setUp(self):
        Config().load()                      # writes the file if this run has none yet
        with open(CONFIG_FILE, 'rb') as f:
            original = f.read()

        def restore():
            with open(CONFIG_FILE, 'wb') as f:
                f.write(original)
            Config().load()
        self.addCleanup(restore)

    def test_an_edited_config_with_a_bom_and_non_ascii_names_loads(self):
        """
        Notepad saves UTF-8 with a BOM. Read in the Windows code page the file
        failed to load, and every setting was silently replaced by defaults.
        """
        data = json.loads(json.dumps(Config().load().data))
        data['known_devices']['devices'] = [{'name': 'Кухня Küche', 'ip': '192.168.1.40'}]
        data['alerts']['cooldown_sec'] = 77
        with open(CONFIG_FILE, 'w', encoding='utf-8-sig') as f:
            json.dump(data, f, ensure_ascii=False)
        cfg = Config().load()
        self.assertEqual(cfg.get('alerts', 'cooldown_sec'), 77)
        self.assertEqual(cfg.get('known_devices', 'devices')[0]['name'], 'Кухня Küche')


class TestSettingsTab(unittest.TestCase):

    def test_the_threshold_row_edits_the_threshold_the_engine_reads(self):
        """It wrote ml.anomaly_threshold, which the engine ignores for alert_threshold."""
        with open(os.path.join(ROOT, 'src', 'gui.py'), encoding='utf-8') as f:
            source = f.read()
        self.assertIn("('ml.alert_threshold'", source)
        self.assertNotIn("('ml.anomaly_threshold'", source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
