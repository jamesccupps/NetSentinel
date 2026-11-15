"""
Files something other than NetSentinel changed.
===============================================
The outside review of 2026-11-14 (N5): ~/.netsentinel is in the owner's
profile and chmod does nothing on Windows, so any program running as the
owner could turn detection off in config.json, add itself to the known-good
hashes (counted in a program's favour), or add confirmed false positives.
NetSentinel now records what it wrote, where only administrators can write,
and notices a file changed behind its back. The tests keep the record in
memory; one test drives the registry store over a fake.
"""

import json
import os
import sys
import tempfile
import shutil
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from src import outside_edits  # noqa: E402


class _Fresh(unittest.TestCase):

    def setUp(self):
        self.addCleanup(setattr, outside_edits, '_store', outside_edits._store)
        outside_edits._store = outside_edits._MemoryStore()
        self.dir = tempfile.mkdtemp(prefix='ns_outside_')
        self.addCleanup(shutil.rmtree, self.dir, True)

    def scribble(self, path, change):
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        change(data)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f)


class TestTheRecord(_Fresh):

    def test_a_file_seen_first_is_adopted_and_a_later_change_is_noticed_once(self):
        path = os.path.join(self.dir, 'x.json')
        with open(path, 'w', encoding='utf-8') as f:
            f.write('{}')
        self.assertFalse(outside_edits.changed_outside(path))
        with open(path, 'w', encoding='utf-8') as f:
            f.write('{"a": 1}')
        with self.assertLogs('NetSentinel.OutsideEdits', level='WARNING'):
            self.assertTrue(outside_edits.changed_outside(path))
        self.assertFalse(outside_edits.changed_outside(path))

    def test_what_netsentinel_wrote_is_not_a_change(self):
        path = os.path.join(self.dir, 'x.json')
        with open(path, 'w', encoding='utf-8') as f:
            f.write('{"b": 2}')
        outside_edits.record(path)
        self.assertFalse(outside_edits.changed_outside(path))

    def test_the_registry_store(self):
        class FakeWinreg:
            HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_SZ = 'HKLM', 2, 1

            def __init__(self):
                self.values = {}

            class _Key:
                def __enter__(self):
                    return self

                def __exit__(self, *exc):
                    return False

            def CreateKeyEx(self, root, path, reserved, access):
                assert (root, path) == ('HKLM', outside_edits.KEY)
                return self._Key()

            def OpenKey(self, root, path):
                if not self.values:
                    raise FileNotFoundError(path)
                return self._Key()

            def SetValueEx(self, key, name, reserved, kind, value):
                self.values[name] = value

            def QueryValueEx(self, key, name):
                if name not in self.values:
                    raise FileNotFoundError(name)
                return self.values[name], 1

        store = outside_edits._RegistryStore(FakeWinreg())
        self.assertIsNone(store.get('config.json'))
        store.put('config.json', 'ab' * 32)
        self.assertEqual(store.get('config.json'), 'ab' * 32)


class TestTheThreeFiles(_Fresh):

    def test_config_edited_behind_its_back_is_logged(self):
        from src import config
        path = os.path.join(self.dir, 'config.json')
        with mock.patch.object(config, 'CONFIG_FILE', path):
            config.Config().load()                      # creates and records it
            self.scribble(path, lambda d: d['ids'].update(enabled=False))
            with self.assertLogs('NetSentinel.OutsideEdits', level='WARNING') as logs:
                config.Config().load()
        self.addCleanup(reset_config)
        self.assertIn('config.json', logs.output[0])

    def test_known_good_hashes_added_by_another_program_are_not_trusted(self):
        from src import config as cfg_module
        from src.process_verify import ProcessVerifier
        with mock.patch.object(cfg_module, 'DB_DIR', self.dir):
            verifier = ProcessVerifier(reset_config())
            verifier._known_good_path = os.path.join(self.dir, 'known_good_hashes.json')
            verifier._add_known_good('a' * 64, r'C:\Program Files\Real\real.exe')
            self.scribble(verifier._known_good_path,
                          lambda d: d.update({'e' * 64: {'path': r'C:\Users\me\evil.exe'}}))
            again = ProcessVerifier.__new__(ProcessVerifier)
            again._known_good_path = verifier._known_good_path
            with self.assertLogs('NetSentinel', level='WARNING'):
                self.assertEqual(again._load_known_good(), {})

    def test_known_good_hashes_netsentinel_wrote_are_trusted(self):
        from src.process_verify import ProcessVerifier
        verifier = ProcessVerifier(reset_config())
        verifier._known_good_path = os.path.join(self.dir, 'known_good_hashes.json')
        verifier._add_known_good('a' * 64, r'C:\Program Files\Real\real.exe')
        again = ProcessVerifier.__new__(ProcessVerifier)
        again._known_good_path = verifier._known_good_path
        self.assertIn('a' * 64, again._load_known_good())

    def test_a_verdict_added_behind_its_back_is_logged(self):
        from src.baseline_whitelist import ConfirmedFalsePositives
        from src.ids_engine import Alert
        path = os.path.join(self.dir, 'confirmed_false_positives.json')
        fps = ConfirmedFalsePositives(path, local_addresses=lambda: frozenset())
        fps.add(Alert('PORT-SCAN', 'MEDIUM', 't', 'd', src_ip='192.168.10.66'))
        self.assertEqual(len(fps.entries()), 1)
        self.scribble(path, lambda d: d.append({'rule_id': 'THREAT-INTEL-IP', 'kind': 'dst_ip',
                                                'value': '198.51.100.66', 'added': 0}))
        os.utime(path, (1, 1))                           # a new mtime, as a write gives
        with self.assertLogs('NetSentinel.OutsideEdits', level='WARNING'):
            self.assertEqual(len(fps.entries()), 2)


if __name__ == '__main__':
    unittest.main()
