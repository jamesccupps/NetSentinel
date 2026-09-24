"""
Regression tests for the v1.5.0 audit fixes.
=============================================
One test (or small group) per finding in AUDIT.md. Each asserts the *corrected*
behaviour and carries the finding ID so a future change that reintroduces the bug
points straight back at the write-up.

Run with the rest of the suite:
    python -m unittest discover
"""

import os
import sys
import time
import json
import types
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Isolated HOME + real Scapy where available. Must precede any src import.
import _test_support  # noqa: E402,F401
from _test_support import SCAPY_REAL  # noqa: E402


import numpy as np  # noqa: E402

from src.capture import PacketInfo, CaptureEngine  # noqa: E402
from src.config import Config  # noqa: E402
from src.ids_engine import IDSEngine, Alert, SlidingPortWindow, _tld_of  # noqa: E402
from src.ml_engine import TrafficFeatureExtractor  # noqa: E402
from src.baseline_whitelist import BaselineWhitelist  # noqa: E402
from src.device_learner import DeviceLearner  # noqa: E402
from src.threat_intel import ThreatIntelEngine, tld_of  # noqa: E402
from src.alerts import AlertManager  # noqa: E402
from src.forensics_db import ForensicsDB, KEY_SOURCE_PASSPHRASE  # noqa: E402
from src.forensics import is_private_address  # noqa: E402


# NOTE: _TMP_HOME is deliberately not removed at teardown. src.config resolves
# APP_DIR once at import time, so every test module in the same process shares this
# directory; deleting it here would break whichever module runs next. The OS reclaims
# /tmp, and each test class clears the state it owns.


def pkt(**kw):
    p = PacketInfo()
    for k, v in kw.items():
        setattr(p, k, v)
    return p


def fresh_config():
    cfg = Config().load()
    cfg.set('threat_intel', 'auto_update', False)
    return cfg


# ══════════════════════════════════════════════════════════════════════
# D1 — the baseline whitelist must stop learning
# ══════════════════════════════════════════════════════════════════════
class TestBaselineLearningWindow(unittest.TestCase):
    """
    D1: app._on_packet fed observe_dns/observe_connection unconditionally, so the
    whitelist never stopped learning. Three sightings mark a domain "normal", which
    suppresses DNS-TUNNEL and DNS-BAD-TLD — an attacker's own domain whitelisted
    itself after four packets.
    """

    def setUp(self):
        self.cfg = fresh_config()
        self.bl = BaselineWhitelist(self.cfg)

    def test_learning_flag_clears_after_the_window(self):
        self.bl.learning_start = time.time() - (self.bl.learning_hours * 3600) - 60
        self.bl.check_learning_complete()
        self.assertFalse(self.bl.is_learning)

    def test_app_only_observes_while_learning(self):
        """The gate lives in app._on_packet, so assert on the source of truth."""
        import inspect
        from src.app import NetSentinelApp
        src = inspect.getsource(NetSentinelApp._on_packet)
        gate = src.index('if self.baseline_whitelist.is_learning:')
        self.assertLess(gate, src.index('observe_dns'),
                        "observe_dns must be inside the is_learning gate")
        self.assertLess(gate, src.index('observe_connection'),
                        "observe_connection must be inside the is_learning gate")

    def test_post_baseline_domain_is_not_whitelisted(self):
        self.bl.learning_start = time.time() - 10 * 3600
        self.bl.check_learning_complete()
        bad = 'kj4h3kj2h4kj23h4kj2h34kj2h34kj2h34k2j3h4kj23h4k2j3h4kj23h4kj.evil.xyz'

        alerts = []
        ids = IDSEngine(self.cfg, alert_callback=alerts.append)
        ids.baseline_whitelist = self.bl

        query = pkt(src_ip='10.0.0.5', dst_ip='10.0.0.1', protocol='UDP',
                    dst_port=53, dns_query=bad)
        ids.inspect_packet(query)
        self.assertTrue([a for a in alerts if a.rule_id == 'DNS-TUNNEL'])

        # Simulate the app's (now gated) observation path being skipped post-baseline
        alerts.clear()
        ids._alert_cooldowns.clear()
        ids.inspect_packet(query)
        self.assertTrue([a for a in alerts if a.rule_id == 'DNS-TUNNEL'],
                        "Detector must keep firing after the baseline window")


# ══════════════════════════════════════════════════════════════════════
# D2/D3 — ML feature correctness
# ══════════════════════════════════════════════════════════════════════
class TestMLFeatures(unittest.TestCase):

    def setUp(self):
        self.fx = TrafficFeatureExtractor()

    def test_rate_features_use_the_observed_span(self):
        """
        D2: _packet_window is a rolling deque that is never cleared, but the caller
        passed window_sec=5, pinning packets_per_sec at maxlen/5 (1000.0) forever.
        """
        t0 = time.time()
        packets = [pkt(src_ip='10.0.0.1', dst_ip='8.8.8.8', length=200,
                       flags='PA', timestamp=t0 + i / 10.0)
                   for i in range(5000)]  # 10 pps over 500 s
        v = self.fx.extract_from_window({}, packets, 5)
        pps = v[self.fx.feature_names.index('packets_per_sec')]
        self.assertAlmostEqual(pps, 10.0, delta=0.1,
                               msg=f"expected ~10 pkts/s, got {pps}")

    def test_direction_asymmetry_responds_to_direction(self):
        """D3: the feature computed abs(N - N) and was identically zero."""
        local = {'192.168.1.10'}
        idx = self.fx.feature_names.index('direction_asymmetry')

        up_only = [pkt(src_ip='192.168.1.10', dst_ip='8.8.8.8', length=1500)
                   for _ in range(50)]
        balanced = ([pkt(src_ip='192.168.1.10', dst_ip='8.8.8.8', length=1000)
                     for _ in range(25)] +
                    [pkt(src_ip='8.8.8.8', dst_ip='192.168.1.10', length=1000)
                     for _ in range(25)])

        a = self.fx.extract_from_window({}, up_only, 5, local_ips=local)[idx]
        b = self.fx.extract_from_window({}, balanced, 5, local_ips=local)[idx]
        self.assertAlmostEqual(a, 1.0, places=6)
        self.assertAlmostEqual(b, 0.0, places=6)

    def test_direction_asymmetry_without_local_ip_hint(self):
        """Falls back to RFC1918 heuristics rather than flatlining."""
        idx = self.fx.feature_names.index('direction_asymmetry')
        up = [pkt(src_ip='192.168.1.10', dst_ip='8.8.8.8', length=1500)
              for _ in range(20)]
        self.assertAlmostEqual(self.fx.extract_from_window({}, up, 5)[idx], 1.0, places=6)

    def test_empty_window_is_all_zeros(self):
        v = self.fx.extract_from_window({}, [], 5)
        self.assertEqual(len(v), len(self.fx.feature_names))
        self.assertTrue(np.all(v == 0))


# ══════════════════════════════════════════════════════════════════════
# D4 — exfiltration direction
# ══════════════════════════════════════════════════════════════════════
class TestExfilDirection(unittest.TestCase):
    """D4: inbound bytes accumulated against the local host, so downloads raised
    HIGH "data sent to <your own IP>"."""

    def setUp(self):
        self.cfg = fresh_config()
        self.cfg.set('ids', 'large_upload_mb', 1)
        self.alerts = []
        self.ids = IDSEngine(self.cfg, alert_callback=self.alerts.append)

    def _pump(self, src, dst, n=1500):
        for _ in range(n):
            self.ids.inspect_packet(pkt(src_ip=src, dst_ip=dst, src_port=50000,
                                        dst_port=443, protocol='TCP',
                                        payload_size=1460, flags='PA', length=1514))

    def test_download_raises_no_exfil_alert(self):
        self._pump('93.184.216.34', '192.168.1.50')
        self.assertFalse([a for a in self.alerts if a.rule_id == 'DATA-EXFIL'])

    def test_upload_still_raises_exfil_alert(self):
        self._pump('192.168.1.50', '93.184.216.34')
        exfil = [a for a in self.alerts if a.rule_id == 'DATA-EXFIL']
        self.assertTrue(exfil)
        self.assertEqual(exfil[0].evidence['destination_ip'], '93.184.216.34')


# ══════════════════════════════════════════════════════════════════════
# D5 — TLD matching
# ══════════════════════════════════════════════════════════════════════
class TestTldMatching(unittest.TestCase):
    """D5: `query.endswith(tld.lstrip('.'))` matched raw trailing letters, so
    'laptop', 'desktop', 'network' and 'forest' were flagged."""

    BENIGN = ['laptop', 'desktop', 'my-laptop', 'rooftop', 'network',
              'forest', 'webcam', 'uplink', 'homework', 'oneclick']

    def setUp(self):
        self.cfg = fresh_config()
        self.alerts = []
        self.ids = IDSEngine(self.cfg, alert_callback=self.alerts.append)
        self.ti = ThreatIntelEngine(self.cfg)

    def _fires(self, query):
        self.alerts.clear()
        self.ids._alert_cooldowns.clear()
        self.ids.inspect_packet(pkt(src_ip='10.0.0.5', dst_ip='10.0.0.1',
                                    protocol='UDP', dst_port=53, dns_query=query))
        return bool([a for a in self.alerts if a.rule_id == 'DNS-BAD-TLD'])

    def test_single_label_hostnames_do_not_fire(self):
        for name in self.BENIGN:
            with self.subTest(query=name):
                self.assertFalse(self._fires(name))

    def test_real_high_abuse_tlds_still_fire(self):
        for name in ['evil.top', 'malware.xyz', 'bad.tk']:
            with self.subTest(query=name):
                self.assertTrue(self._fires(name))

    def test_threat_intel_tld_check_is_label_based(self):
        for name in self.BENIGN:
            with self.subTest(query=name):
                result = self.ti.check_domain(name)
                self.assertNotEqual(
                    (result or {}).get('category'), 'Suspicious TLD',
                    f"{name} must not be treated as a high-abuse TLD")
        self.assertEqual(self.ti.check_domain('evil.xyz')['category'], 'Suspicious TLD')

    def test_tld_helpers_agree(self):
        for domain, expected in [('a.b.example.com', 'com'), ('evil.xyz', 'xyz'),
                                 ('laptop', ''), ('trailing.dot.net.', 'net')]:
            self.assertEqual(_tld_of(domain), expected)
            self.assertEqual(tld_of(domain), expected)


# ══════════════════════════════════════════════════════════════════════
# D6 — long-lived suppressions
# ══════════════════════════════════════════════════════════════════════
class TestOddHoursSuppression(unittest.TestCase):
    """D6: ODD-HOURS stored its hourly marker in _alert_cooldowns, which the pruner
    clears at cooldown_sec*5 (150 s), so it fired ~24x/hour instead of once."""

    def test_suppression_survives_cooldown_pruning(self):
        cfg = fresh_config()
        ids = IDSEngine(cfg)
        key = 'ODD-HOURS:10.0.0.9:h3'
        ids._long_suppressions[key] = time.time() - 200
        ids._last_cleanup = 0
        ids._periodic_cleanup(force=True)
        self.assertIn(key, ids._long_suppressions,
                      "An hour-scale suppression must outlive the 150 s cooldown prune")

    def test_expired_suppressions_are_eventually_dropped(self):
        cfg = fresh_config()
        ids = IDSEngine(cfg)
        ids._long_suppressions['ODD-HOURS:10.0.0.9:h3'] = time.time() - 8000
        ids._last_cleanup = 0
        ids._periodic_cleanup(force=True)
        self.assertNotIn('ODD-HOURS:10.0.0.9:h3', ids._long_suppressions)


# ══════════════════════════════════════════════════════════════════════
# D8/D10 — config split and rule pack
# ══════════════════════════════════════════════════════════════════════
class TestConfigAndRules(unittest.TestCase):

    def test_contamination_and_alert_threshold_are_independent(self):
        """D8: one value served as both IsolationForest contamination and the
        score gate, so raising it moved the two in opposite directions."""
        from src.ml_engine import AnomalyDetector
        cfg = fresh_config()
        cfg.set('ml', 'contamination', 0.10)
        cfg.set('ml', 'alert_threshold', 0.60)
        det = AnomalyDetector(cfg)
        self.assertAlmostEqual(det.contamination, 0.10)
        self.assertAlmostEqual(det.threshold, 0.60)

    def test_rule_pack_is_actually_loaded(self):
        """D10: rules/default_rules.json was shipped and documented but never read."""
        from src.ids_engine import _RULE_PACK_PORTS, _PORT_NAMES
        self.assertTrue(_RULE_PACK_PORTS, "rule pack produced no ports")
        # 3127 exists only in the JSON, never in the hardcoded table.
        self.assertIn(3127, _PORT_NAMES)

    def test_every_default_config_key_is_read_somewhere(self):
        """S5: 16 of 56 keys were dead, including forensics.save_credentials."""
        import ast
        import re
        import glob
        root = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(root, 'src', 'config.py')) as f:
            cfg_src = f.read()
        default = next(ast.literal_eval(n.value) for n in ast.parse(cfg_src).body
                       if isinstance(n, ast.Assign)
                       and getattr(n.targets[0], 'id', '') == 'DEFAULT_CONFIG')
        sources = glob.glob(os.path.join(root, 'src', '*.py')) + [os.path.join(root, 'main.py')]
        code = ''
        for path in sources:
            with open(path) as f:
                code += f.read()

        dead = []
        for section, values in default.items():
            if not isinstance(values, dict):
                continue
            for key in values:
                pattern = r"get\(\s*['\"]%s['\"]\s*,\s*['\"]%s['\"]" % (
                    re.escape(section), re.escape(key))
                if not re.search(pattern, code):
                    dead.append(f"{section}.{key}")
        self.assertEqual(dead, [], f"config keys declared but never read: {dead}")


# ══════════════════════════════════════════════════════════════════════
# S1 — no shell/PowerShell interpolation
# ══════════════════════════════════════════════════════════════════════
class TestSignatureCheckInjection(unittest.TestCase):
    """S1: exe_path (from psutil) was interpolated into a PowerShell -Command
    string. PowerShell expands $(...) in double-quoted strings and '$', '(' and ')'
    are legal in Windows filenames, so this was user -> Administrator RCE."""

    def test_command_string_is_a_constant(self):
        from src.process_verify import ProcessVerifier
        ps = ProcessVerifier._SIGNATURE_PS
        self.assertIsInstance(ps, str)
        self.assertIn('$env:NETSENTINEL_TARGET_PATH', ps)
        self.assertIn('-LiteralPath', ps)
        self.assertNotIn('-FilePath', ps)

    def test_attacker_path_cannot_reach_the_command(self):
        import src.process_verify as pv
        captured = {}

        def fake_run(cmd, **kwargs):
            captured['cmd'] = cmd
            captured['env'] = kwargs.get('env', {})
            raise RuntimeError('stop here')

        original, pv.subprocess.run = pv.subprocess.run, fake_run
        original_name, os.name = os.name, 'nt'
        try:
            verifier = ProcessVerifierFactory()
            evil = r'C:\Users\Public\a$(Start-Process calc).exe'
            verifier._check_signature(evil)
        finally:
            pv.subprocess.run = original
            os.name = original_name

        joined = ' '.join(captured.get('cmd', []))
        self.assertNotIn('Start-Process calc', joined,
                         "attacker-controlled path leaked into the command line")
        self.assertEqual(captured['env'].get('NETSENTINEL_TARGET_PATH'), evil)


def ProcessVerifierFactory():
    from src.process_verify import ProcessVerifier
    return ProcessVerifier(fresh_config())


# ══════════════════════════════════════════════════════════════════════
# S2/S3 — vault storage policy
# ══════════════════════════════════════════════════════════════════════
class TestForensicsVault(unittest.TestCase):

    def setUp(self):
        # Config is a process-wide singleton that persists to disk, and the vault
        # files outlive a single test. Without clearing both, a test that enables a
        # passphrase leaves later tests unable to decrypt (correctly refusing to
        # write), which shows up as a confusing unrelated failure.
        self.cfg = fresh_config()
        self.cfg.set('forensics', 'store_raw_credentials', False)
        self.cfg.set('forensics', 'vault_passphrase', '')
        self.cfg.set('forensics', 'save_credentials', True)
        self.cfg.set('forensics', 'retention_days', 365)
        self._wipe_vault()

    tearDown = setUp

    @staticmethod
    def _wipe_vault():
        from src.config import DB_DIR
        vault = os.path.join(DB_DIR, 'forensics')
        shutil.rmtree(vault, ignore_errors=True)

    def _store(self, db):
        return db.store_credential('FTP', 'password', 'hunter2-REAL', 'hun*****',
                                   '192.168.1.10', '192.168.1.99', 21, time.time())

    def test_raw_secrets_are_not_persisted_by_default(self):
        """S2: full plaintext passwords were written for 20+ protocols."""
        from src.forensics_db import _decrypt
        db = ForensicsDB(self.cfg)
        self.assertTrue(self._store(db))
        with open(db._creds_file) as f:
            on_disk = f.read()
        self.assertNotIn('hunter2-REAL', on_disk)
        stored = json.loads(_decrypt(on_disk, db._key))
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]['value_raw'], '')
        self.assertEqual(stored[0]['value_masked'], 'hun*****')

    def test_opt_in_restores_raw_storage(self):
        self.cfg.set('forensics', 'store_raw_credentials', True)
        db = ForensicsDB(self.cfg)
        self._store(db)
        self.assertIsNotNone(db.get_credential_raw(db._credentials[-1]['id']))

    def test_save_credentials_false_is_honoured(self):
        """S5: the switch existed but nothing consulted it."""
        self.cfg.set('forensics', 'save_credentials', False)
        db = ForensicsDB(self.cfg)
        before = len(db._credentials)
        self.assertFalse(self._store(db))
        self.assertEqual(len(db._credentials), before)

    def test_log_contains_no_credential_material(self):
        """S3: forensics_log.json claimed 'metadata only' but stored the masked
        value, which reveals the first characters of short secrets."""
        db = ForensicsDB(self.cfg)
        self._store(db)
        with open(db._log_file) as f:
            entries = json.load(f)
        cred_entries = [e for e in entries if e['type'] == 'credential']
        self.assertTrue(cred_entries)
        for entry in cred_entries:
            self.assertNotIn('value_masked', entry['metadata'])
            self.assertNotIn('value_raw', entry['metadata'])

    def test_files_are_owner_only(self):
        if os.name == 'nt':
            self.skipTest('POSIX permission model only')
        db = ForensicsDB(self.cfg)
        self._store(db)
        self.assertEqual(os.stat(db._creds_file).st_mode & 0o077, 0,
                         "vault must not be group/world readable")

    def test_passphrase_switches_to_a_real_kdf(self):
        self.cfg.set('forensics', 'vault_passphrase', 'correct horse battery staple')
        db = ForensicsDB(self.cfg)
        self.assertEqual(db.key_source, KEY_SOURCE_PASSPHRASE)
        self.assertTrue(os.path.exists(db._salt_file))

    def test_duplicate_does_not_rewrite_the_vault(self):
        """R1: every duplicate re-encrypted and rewrote the whole file."""
        db = ForensicsDB(self.cfg)
        self._store(db)
        mtime = os.stat(db._creds_file).st_mtime_ns
        for _ in range(5):
            self.assertFalse(self._store(db))
        self.assertEqual(os.stat(db._creds_file).st_mtime_ns, mtime)

    def test_retention_prunes_old_findings(self):
        """S5: retention_days was declared but nothing ever expired."""
        self.cfg.set('forensics', 'retention_days', 30)
        db = ForensicsDB(self.cfg)
        db.store_credential('FTP', 'password', '', 'old***', '10.0.0.1', '10.0.0.2',
                            21, time.time() - (60 * 86400))
        db2 = ForensicsDB(self.cfg)
        self.assertFalse([c for c in db2._credentials if c['value_masked'] == 'old***'])


# ══════════════════════════════════════════════════════════════════════
# S4 — authenticated model files
# ══════════════════════════════════════════════════════════════════════
class TestModelIntegrity(unittest.TestCase):
    """S4: pickle.load() from a user-writable directory in an elevated process."""

    def test_tampered_model_is_refused(self):
        from src.ml_engine import AnomalyDetector
        import pickle
        det = AnomalyDetector(fresh_config())

        class Evil:
            def __reduce__(self):
                return (os.system, ('echo pwned',))

        os.makedirs(os.path.dirname(det.model_path), exist_ok=True)
        with open(det.model_path, 'wb') as f:
            f.write(b'\x00' * 32 + pickle.dumps(Evil()))
        with open(det.scaler_path, 'wb') as f:
            f.write(b'\x00' * 32 + pickle.dumps(Evil()))

        det.isolation_forest = None
        det.is_trained = False
        det._load_model()
        self.assertFalse(det.is_trained, "unauthenticated pickle must not be loaded")
        self.assertIsNone(det.isolation_forest)


# ══════════════════════════════════════════════════════════════════════
# R5 — device inventory scope
# ══════════════════════════════════════════════════════════════════════
class TestDeviceLearnerScope(unittest.TestCase):
    """R5: every remote internet IP became a "device on your network" — one
    browsing session produced thousands of profiles and a 1.2 MB JSON file."""

    def test_remote_addresses_are_not_devices(self):
        dl = DeviceLearner(fresh_config())
        for i in range(500):
            dl.observe_packet(pkt(src_ip='192.168.1.50',
                                  dst_ip=f'93.184.{i // 256}.{i % 256}',
                                  src_port=51000, dst_port=443,
                                  protocol='TCP', length=1200))
        self.assertEqual(set(dl.devices), {'192.168.1.50'})

    def test_lan_peers_are_still_discovered(self):
        dl = DeviceLearner(fresh_config())
        dl.observe_packet(pkt(src_ip='192.168.1.50', dst_ip='192.168.1.1',
                              dst_port=53, protocol='UDP', length=90))
        self.assertIn('192.168.1.1', dl.devices)
        self.assertIn('192.168.1.50', dl.devices)

    def test_broadcast_and_multicast_excluded(self):
        dl = DeviceLearner(fresh_config())
        for addr in ('255.255.255.255', '224.0.0.251', '239.255.255.250'):
            dl.observe_packet(pkt(src_ip='192.168.1.50', dst_ip=addr,
                                  dst_port=5353, protocol='UDP', length=90))
        self.assertNotIn('255.255.255.255', dl.devices)
        self.assertNotIn('224.0.0.251', dl.devices)


# ══════════════════════════════════════════════════════════════════════
# R6 — alert persistence
# ══════════════════════════════════════════════════════════════════════
class TestAlertPersistence(unittest.TestCase):

    def setUp(self):
        self.cfg = fresh_config()
        self.am = AlertManager(self.cfg)
        self.am.clear_alerts()
        if os.path.exists(self.am.db_path):
            os.remove(self.am.db_path)

    def test_all_stored_alerts_are_saved(self):
        """R6: save_alerts() hardcoded [:500] while max_stored defaults to 5000."""
        am = AlertManager(self.cfg)
        am.clear_alerts()
        for i in range(600):
            am.add_alert(Alert(f'R{i}', 'HIGH', f'alert-{i}', 'd'))
        am.save_alerts()
        with open(am.db_path) as f:
            self.assertEqual(len(json.load(f)), 600)

    def test_restored_order_is_newest_first(self):
        """R6: _load_alerts used appendleft over a newest-first file, inverting it."""
        am = AlertManager(self.cfg)
        am.clear_alerts()
        for i in range(10):
            am.add_alert(Alert(f'R{i}', 'HIGH', f'alert-{i}', 'd'))
        am.save_alerts()

        restored = AlertManager(self.cfg)
        restored._alerts.clear()
        restored._load_alerts()
        self.assertEqual(restored._alerts[0].title, 'alert-9')

    def test_writes_are_atomic(self):
        """R8: a truncated write used to leave unparseable JSON behind."""
        am = AlertManager(self.cfg)
        am.add_alert(Alert('R1', 'HIGH', 'a', 'd'))
        am.save_alerts()
        with open(am.db_path) as f:
            json.load(f)  # must parse
        self.assertFalse(os.path.exists(am.db_path + '.tmp'))


# ══════════════════════════════════════════════════════════════════════
# R7 — notification batching
# ══════════════════════════════════════════════════════════════════════
class TestNotificationBatching(unittest.TestCase):
    """R7: the batch only flushed when the *next* alert arrived, so a burst
    followed by silence — what an incident looks like — was never delivered."""

    def test_batch_flushes_without_further_alerts(self):
        cfg = fresh_config()
        am = AlertManager(cfg)
        am._notify_batch_interval = 0.1
        sent = []
        am._desktop_notify = lambda a: sent.append(a)
        am._desktop_notify_text = lambda t, m: sent.append(m)

        am._batch_notification(Alert('R1', 'HIGH', 'burst', 'd'))
        am._batch_notification(Alert('R2', 'HIGH', 'burst', 'd'))
        deadline = time.time() + 3
        while not sent and time.time() < deadline:
            time.sleep(0.05)
        self.assertTrue(sent, "pending notifications must flush on their own")


# ══════════════════════════════════════════════════════════════════════
# R9 — stats snapshots
# ══════════════════════════════════════════════════════════════════════
class TestStatsSnapshot(unittest.TestCase):
    """R9: get_stats() was documented as a thread-safe snapshot but dict() is
    shallow, so callers received the live containers the worker keeps mutating."""

    def test_snapshot_does_not_alias_live_state(self):
        ce = CaptureEngine(fresh_config())
        ce.stats['protocols']['TCP'] = 1
        ce.stats['top_talkers']['10.0.0.1'] = 100
        ce.stats['dns_queries'].append((time.time(), 'example.com'))

        snap = ce.get_stats()
        self.assertIsNot(snap['protocols'], ce.stats['protocols'])
        self.assertIsNot(snap['top_talkers'], ce.stats['top_talkers'])
        self.assertIsNot(snap['dns_queries'], ce.stats['dns_queries'])

        ce.stats['protocols']['UDP'] = 5
        self.assertNotIn('UDP', snap['protocols'])


# ══════════════════════════════════════════════════════════════════════
# Private-address handling (the 172/8 bug)
# ══════════════════════════════════════════════════════════════════════
class TestPrivateAddressChecks(unittest.TestCase):
    """startswith('172.') covers 172.0.0.0/8; only 172.16.0.0/12 is private."""

    def test_only_the_real_rfc1918_range_is_private(self):
        for ip, expected in [('172.16.0.1', True), ('172.31.255.254', True),
                             ('172.15.0.1', False), ('172.32.0.1', False),
                             ('10.1.1.1', True), ('192.168.1.1', True),
                             ('8.8.8.8', False), ('127.0.0.1', True)]:
            with self.subTest(ip=ip):
                self.assertEqual(is_private_address(ip), expected)

    def test_ids_agrees(self):
        ids = IDSEngine(fresh_config())
        self.assertTrue(ids._is_local_ip('172.16.5.5'))
        self.assertFalse(ids._is_local_ip('172.15.5.5'))


# ══════════════════════════════════════════════════════════════════════
# Port-scan sliding window (optimised in v1.5.0 — behaviour must not drift)
# ══════════════════════════════════════════════════════════════════════
class TestSlidingPortWindow(unittest.TestCase):
    """
    The distinct-port count is needed on every packet. It used to be rebuilt from a
    500-entry history each time (~1000 set operations per packet). The replacement
    keeps a refcount, so these tests pin the semantics that optimisation must preserve.
    """

    def test_counts_distinct_ports(self):
        w = SlidingPortWindow(60)
        t = 1000.0
        for port in (80, 443, 80, 22, 443, 8080):
            w.add(t, port, '10.0.0.1')
            t += 1
        self.assertEqual(w.unique_ports, 4)
        self.assertEqual(w.ports(), [22, 80, 443, 8080])

    def test_entries_expire_with_the_window(self):
        w = SlidingPortWindow(10)
        w.add(100.0, 1, 'a')
        w.add(105.0, 2, 'b')
        w.add(112.0, 3, 'c')     # t=100 is now outside the 10s window
        self.assertEqual(w.ports(), [2, 3])

    def test_repeated_port_refcounts_correctly(self):
        """A port stays live until its most recent sighting ages out, not its first."""
        w = SlidingPortWindow(10)
        w.add(100.0, 5, 'a')
        w.add(108.0, 5, 'a')
        w.add(109.0, 6, 'b')
        w.add(115.0, 7, 'c')     # drops the t=100 copy of port 5, not the t=108 one
        self.assertEqual(w.ports(), [5, 6, 7])
        w.add(120.0, 8, 'd')     # now both copies of 5 are gone
        self.assertNotIn(5, w.ports())

    def test_hard_cap_bounds_memory(self):
        w = SlidingPortWindow(3600, max_events=100)
        for i in range(500):
            w.add(1000.0 + i * 0.001, i, 'a')
        self.assertLessEqual(len(w), 101)

    def test_destinations_are_reported(self):
        w = SlidingPortWindow(60)
        w.add(1000.0, 80, '10.0.0.1')
        w.add(1001.0, 81, '10.0.0.2')
        self.assertEqual(w.destinations(), {'10.0.0.1', '10.0.0.2'})


class TestPortScanDetection(unittest.TestCase):
    """The optimisation must not change which traffic is treated as a scan."""

    def setUp(self):
        self.alerts = []
        self.ids = IDSEngine(fresh_config(), alert_callback=self.alerts.append)

    def _probe(self, port):
        return pkt(src_ip='203.0.113.9', dst_ip='192.168.1.50', src_port=44444,
                   dst_port=port, protocol='TCP', flags='S', length=60)

    def _fired(self):
        return bool([a for a in self.alerts if a.rule_id == 'PORT-SCAN'])

    def test_many_low_ports_is_a_scan(self):
        for port in range(20, 45):
            self.ids.inspect_packet(self._probe(port))
        self.assertTrue(self._fired())

    def test_ephemeral_only_is_not_a_scan(self):
        """A server answering many clients hits only high ports."""
        for port in range(40000, 40030):
            self.ids.inspect_packet(self._probe(port))
        self.assertFalse(self._fired())

    def test_high_volume_on_few_ports_is_not_a_scan(self):
        for port in [80, 443] * 40:
            self.ids.inspect_packet(self._probe(port))
        self.assertFalse(self._fired())


# ══════════════════════════════════════════════════════════════════════
# Reverse DNS must not block the packet path
# ══════════════════════════════════════════════════════════════════════
class TestReverseDnsNonBlocking(unittest.TestCase):
    """
    socket.gethostbyaddr() has no timeout and honours the resolver's. Verification
    runs on the packet worker for most rules, so one unresolvable address used to
    stall the whole pipeline — measured at 12 seconds in a profile run.
    """

    def test_lookup_returns_immediately(self):
        import src.alert_verify as av
        from src.alert_verify import AlertVerifier

        verifier = AlertVerifier(fresh_config())
        slow_calls = []

        def slow_gethostbyaddr(ip):
            slow_calls.append(ip)
            time.sleep(2)
            return ('slow.example.com', [], [ip])

        original = av.socket.gethostbyaddr
        av.socket.gethostbyaddr = slow_gethostbyaddr
        try:
            start = time.time()
            result = verifier._reverse_dns('198.51.100.7')
            elapsed = time.time() - start
        finally:
            av.socket.gethostbyaddr = original

        self.assertIsNone(result, "first lookup should return None, not block")
        self.assertLess(elapsed, 0.5, f"call took {elapsed:.2f}s — it must not block")

    def test_result_is_cached_for_next_time(self):
        import src.alert_verify as av
        from src.alert_verify import AlertVerifier

        verifier = AlertVerifier(fresh_config())
        original = av.socket.gethostbyaddr
        av.socket.gethostbyaddr = lambda ip: ('host.example.com', [], [ip])
        try:
            verifier._reverse_dns('198.51.100.8')
            deadline = time.time() + 3
            while verifier._reverse_dns('198.51.100.8') is None and time.time() < deadline:
                time.sleep(0.05)
        finally:
            av.socket.gethostbyaddr = original
        self.assertEqual(verifier._reverse_dns('198.51.100.8'), 'host.example.com')


# ══════════════════════════════════════════════════════════════════════
# Verification verdicts must reach the alert
# ══════════════════════════════════════════════════════════════════════
class TestVerificationReachesTheAlert(unittest.TestCase):
    """
    verify_alert() did `evidence = alert.evidence if alert.evidence else {}`, which
    rebinds to a *new* local dict whenever the alert has no evidence yet. The verdict
    was then written to that local and thrown away, so any alert raised without
    evidence silently lost its verification — despite the docstring promising it is
    modified in place.
    """

    def test_verdict_is_attached_to_an_evidence_free_alert(self):
        from src.alert_verify import AlertVerifier
        verifier = AlertVerifier(fresh_config())
        alert = Alert(rule_id='PORT-SCAN', severity='HIGH', title='t', description='d')
        self.assertEqual(alert.evidence, {})
        verifier.verify_alert(alert)
        self.assertIn('alert_verification', alert.evidence)
        self.assertIn('verdict', alert.evidence['alert_verification'])

    def test_existing_evidence_is_preserved(self):
        from src.alert_verify import AlertVerifier
        verifier = AlertVerifier(fresh_config())
        alert = Alert(rule_id='PORT-SCAN', severity='HIGH', title='t', description='d',
                      evidence={'scanner_ip': '203.0.113.9'})
        verifier.verify_alert(alert)
        self.assertEqual(alert.evidence['scanner_ip'], '203.0.113.9')
        self.assertIn('alert_verification', alert.evidence)


# ══════════════════════════════════════════════════════════════════════
# R10 — dead state actually removed
# ══════════════════════════════════════════════════════════════════════
class TestDeadStateRemoved(unittest.TestCase):

    def test_ids_no_longer_carries_write_only_buffers(self):
        ids = IDSEngine(fresh_config())
        for name in ('_recent_connections', '_recent_dns', '_dhcp_devices',
                     '_smb_versions', '_mdns_responders', '_llmnr_responders'):
            self.assertFalse(hasattr(ids, name), f"{name} should have been removed")

    def test_ml_no_longer_carries_unused_history(self):
        from src.ml_engine import AnomalyDetector
        det = AnomalyDetector(fresh_config())
        self.assertFalse(hasattr(det, '_connection_timings'))
        self.assertFalse(hasattr(det.baseline, '_history'))

    def test_whitelist_dropped_write_only_pairs(self):
        bl = BaselineWhitelist(fresh_config())
        self.assertFalse(hasattr(bl, '_dns_pairs'))


if __name__ == '__main__':
    unittest.main(verbosity=2)


# ══════════════════════════════════════════════════════════════════════
# Capture thread must not re-serialise packets
# ══════════════════════════════════════════════════════════════════════
class TestNoPacketRebuild(unittest.TestCase):
    """
    len(packet) and bytes(packet) both run Scapy's build(), re-serialising every
    layer. A packet dissected from the wire already carries its bytes in .original,
    and each build costs ~11 us on a fresh object — paid twice per packet, on the
    capture thread, which is the one that must never stall.
    """

    def setUp(self):
        if not SCAPY_REAL:
            self.skipTest('real scapy unavailable')
        from src.capture import CaptureEngine
        self.engine = CaptureEngine(fresh_config())

    def _dissected(self):
        from scapy.all import Ether, IP, TCP, Raw
        wire = bytes(Ether() / IP(src='1.2.3.4', dst='5.6.7.8') /
                     TCP(sport=1, dport=8000, flags='PA') / Raw(load=b'hello' * 50))
        return Ether(wire), wire

    def test_raw_bytes_uses_the_original_buffer(self):
        packet, wire = self._dissected()
        self.assertIs(self.engine._raw_bytes(packet), packet.original)
        self.assertEqual(self.engine._raw_bytes(packet), wire)

    def test_raw_bytes_falls_back_for_constructed_packets(self):
        """A packet built in memory has no .original, so it must still work."""
        from scapy.all import Ether, IP, TCP
        built = Ether() / IP(src='1.2.3.4', dst='5.6.7.8') / TCP()
        self.assertEqual(self.engine._raw_bytes(built), bytes(built))

    def test_length_still_matches_scapy(self):
        packet, wire = self._dissected()
        info = self.engine._extract_packet_info(packet)
        self.assertEqual(info.length, len(packet))
        self.assertEqual(info.length, len(wire))

    def test_extraction_does_not_call_build(self):
        """The direct guard: if build() runs, this fails."""
        packet, _ = self._dissected()
        calls = []
        original_build = type(packet).build

        def counting_build(self, *a, **kw):
            calls.append(1)
            return original_build(self, *a, **kw)

        type(packet).build = counting_build
        try:
            self.engine._extract_packet_info(packet)
        finally:
            type(packet).build = original_build
        self.assertEqual(calls, [], "capture path must not re-serialise the packet")


# ══════════════════════════════════════════════════════════════════════
# Payload extraction must not depend on how Scapy dissected the packet
# ══════════════════════════════════════════════════════════════════════
class TestPayloadExtraction(unittest.TestCase):
    """
    Extraction keyed off packet.haslayer(Raw), which is only true when Scapy had
    no dissector for the payload. `from scapy.all import *` loads the TLS and DNS
    layers, so on a real capture port-443 and port-53 traffic dissects into TLS
    and DNS layers instead — and payload_size silently read 0 for both, which is
    most of a real capture.

    Only dissected packets show this. Packets built in memory keep a Raw layer,
    which is why the unit tests never caught it and an end-to-end run did.
    """

    def setUp(self):
        if not SCAPY_REAL:
            self.skipTest('real scapy unavailable')
        from src.capture import CaptureEngine
        self.engine = CaptureEngine(fresh_config())

    @staticmethod
    def _dissect(built):
        from scapy.all import Ether
        return Ether(bytes(built))

    def _client_hello(self, host=b'secure.example.com'):
        from scapy.layers.tls.record import TLS
        from scapy.layers.tls.handshake import TLSClientHello
        from scapy.layers.tls.extensions import (
            TLS_Ext_ServerName, ServerName, TLS_Ext_SupportedVersion_CH)
        ch = TLSClientHello(ciphers=[0x1301, 0xc02f], ext=[
            TLS_Ext_ServerName(servernames=[ServerName(servername=host)]),
            TLS_Ext_SupportedVersion_CH(versions=['TLS 1.3'])])
        return bytes(TLS(msg=[ch]))

    def test_tls_payload_size_is_not_zero_when_dissected(self):
        from scapy.all import Ether, IP, TCP, Raw
        built = Ether() / IP() / TCP(sport=5, dport=443, flags='PA') / Raw(
            load=self._client_hello())
        dissected = self._dissect(built)
        self.assertFalse(dissected.haslayer(Raw),
                         "precondition: scapy should dissect this into TLS")
        info = self.engine._extract_packet_info(dissected)
        self.assertGreater(info.payload_size, 0)

    def test_dns_payload_size_is_not_zero_when_dissected(self):
        from scapy.all import Ether, IP, UDP, DNS, DNSQR
        built = Ether() / IP() / UDP(sport=5, dport=53) / DNS(rd=1, qd=DNSQR(qname='a.com'))
        info = self.engine._extract_packet_info(self._dissect(built))
        self.assertGreater(info.payload_size, 0)

    def test_sni_is_extracted_from_a_dissected_packet(self):
        """The end-to-end case: this is how capture actually delivers packets."""
        from scapy.all import Ether, IP, TCP, Raw
        built = Ether() / IP() / TCP(sport=5, dport=443, flags='PA') / Raw(
            load=self._client_hello())
        info = self.engine._extract_packet_info(self._dissect(built))
        self.assertEqual(info.tls_sni, 'secure.example.com')
        self.assertTrue(info.tls_ja4)

    def test_both_dissection_modes_agree(self):
        from scapy.all import Ether, IP, TCP, Raw
        built = Ether() / IP() / TCP(sport=5, dport=443, flags='PA') / Raw(
            load=self._client_hello())
        a = self.engine._extract_packet_info(built)
        b = self.engine._extract_packet_info(self._dissect(built))
        self.assertEqual(a.payload_size, b.payload_size)
        self.assertEqual(a.tls_sni, b.tls_sni)
        self.assertEqual(a.tls_ja4, b.tls_ja4)

    def test_credential_payload_still_reaches_forensics(self):
        from scapy.all import Ether, IP, TCP, Raw
        built = Ether() / IP() / TCP(sport=5, dport=21, flags='PA') / Raw(
            load=b'PASS hunter2\r\n')
        info = self.engine._extract_packet_info(self._dissect(built))
        self.assertEqual(info._raw_payload, b'PASS hunter2\r\n')

    def test_packet_with_no_payload_reports_zero(self):
        from scapy.all import Ether, IP, TCP
        built = Ether() / IP() / TCP(sport=5, dport=443, flags='A')
        info = self.engine._extract_packet_info(self._dissect(built))
        self.assertEqual(info.payload_size, 0)
        self.assertIsNone(info._raw_payload)

    def test_non_transport_packets_are_safe(self):
        from scapy.all import Ether, IP, ICMP, ARP
        for built in (Ether() / IP() / ICMP(), Ether() / ARP()):
            info = self.engine._extract_packet_info(self._dissect(built))
            self.assertEqual(info.payload_size, 0)


# ══════════════════════════════════════════════════════════════════════
# sniff() options must be ones the socket actually accepts
# ══════════════════════════════════════════════════════════════════════
class TestSniffOptionsAreSupported(unittest.TestCase):
    """
    Wiring up capture.snap_length passed `snaplen=` to sniff(). sniff() takes
    **kwargs and forwards anything it does not recognise straight to the socket
    constructor, where Linux's L2ListenSocket raised:

        TypeError: L2Socket.__init__() got an unexpected keyword argument 'snaplen'

    That killed the capture thread on every start, and the watchdog then retried
    it ten times. Packet capture — the entire point of the program — was broken,
    and no test caught it because none of them call sniff(): that needs a live
    interface. A real headless launch found it in one line of log output.
    """

    def setUp(self):
        if not SCAPY_REAL:
            self.skipTest('real scapy unavailable')
        from src.capture import CaptureEngine
        self.engine = CaptureEngine(fresh_config())

    def test_unsupported_options_are_dropped(self):
        supported = self.engine._supported_sniff_kwargs(
            {'promisc': True, 'snaplen': 65535, 'not_a_real_option': 1})
        self.assertNotIn('not_a_real_option', supported)

    def test_supported_options_survive(self):
        import inspect
        from scapy.all import conf
        accepted = set(inspect.signature(conf.L2listen.__init__).parameters)
        supported = self.engine._supported_sniff_kwargs({'promisc': True})
        if 'promisc' in accepted:
            self.assertEqual(supported, {'promisc': True})
        else:
            self.assertEqual(supported, {})

    def test_every_option_we_would_pass_is_accepted_by_the_socket(self):
        """The direct guard: whatever the engine builds must be constructible."""
        import inspect
        from scapy.all import conf
        accepted = set(inspect.signature(conf.L2listen.__init__).parameters)
        options = self.engine._supported_sniff_kwargs({
            'promisc': fresh_config().get('capture', 'promiscuous', default=True),
            'snaplen': fresh_config().get('capture', 'snap_length', default=65535),
        })
        for name in options:
            self.assertIn(name, accepted,
                          f"{name} would be forwarded to the socket and rejected")

    def test_introspection_failure_degrades_to_no_options(self):
        """A Scapy build we cannot introspect must not take capture down."""
        import src.capture as capture_module
        original = capture_module.conf
        try:
            capture_module.conf = object()      # no L2listen attribute
            self.assertEqual(
                self.engine._supported_sniff_kwargs({'promisc': True}), {})
        finally:
            capture_module.conf = original

    def test_a_rejected_option_stops_the_watchdog_retrying(self):
        """Restarting cannot fix a TypeError, so it must not be retried."""
        self.assertFalse(self.engine._fatal_capture_error)
        import inspect
        source = inspect.getsource(type(self.engine)._watchdog_loop)
        self.assertIn('_fatal_capture_error', source)
