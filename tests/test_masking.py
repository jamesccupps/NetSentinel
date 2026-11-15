"""
Secrets found in traffic are masked, and session cookies are not kept.
=======================================================================
The outside review of 2026-11-14 (N4): forensics' own _mask showed the first
3 characters (8 of a token, 20 of a SIP header) and the exact length, so a
4-character password was three quarters shown, in alerts.json, on
/api/alerts and in the alert window. And a session cookie's header, the
session itself, went into sensitive_data.enc and the File Analyzer whole,
whatever forensics.store_raw_credentials said. CLAUDE.md: secrets are masked
where they are found. Every value here is made up.
"""

import json
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_third_review import T0, tcp  # noqa: E402

PC, NAS = '192.168.10.32', '192.168.10.21'
# Public: the cookie check skips private destinations, and Python counts the
# documentation ranges as private.
SITE, VISITOR = '93.184.216.34', '93.184.216.35'
SESSION = 'SESSIONVALUE-not-a-real-one-0123456789'


def vault_config():
    from src.config import DB_DIR
    shutil.rmtree(os.path.join(DB_DIR, 'forensics'), ignore_errors=True)
    return reset_config(**{'forensics.save_credentials': True,
                           'forensics.store_raw_credentials': False,
                           'forensics.vault_passphrase': '',
                           'forensics.retention_days': 365})


def on_disk(db, path):
    from src.forensics_db import _decrypt
    with open(path, encoding='utf-8') as f:
        return _decrypt(f.read(), db._key)


class TestTheRule(unittest.TestCase):

    def test_nothing_of_a_short_secret_and_never_its_length(self):
        from src.file_scan import mask
        self.assertEqual(mask('password', 'abcd'), '********')
        self.assertEqual(mask('password', 'abcdefg'), '********')
        self.assertEqual(mask('password', 'abcdefgh'), 'ab********')
        self.assertEqual(mask('password', 'abcdefghijklm'), 'ab********')
        self.assertEqual(mask('password', 'abcdefghijklmnop' * 3), 'abcd********')

    def test_old_masks_are_masked_again(self):
        from src.file_scan import remask
        self.assertEqual(remask('abc*'), '********')                  # a 4-letter password
        self.assertEqual(remask('pas*****'), 'pa********')
        self.assertEqual(remask('ftpuser:sec*****'), 'ftpuser:se********')
        self.assertEqual(remask('eyJhbGci************ via api.example.com'),
                         'eyJh******** via api.example.com')

    def test_today_masks_and_plain_text_are_left_alone(self):
        from src.file_scan import mask, remask
        for value in (mask('password', 'abcdefghij'), mask('password', 'x' * 20),
                      '********', 'Method: PLAIN', 'public', 'Visa ****1111 (ticket 7)', 42):
            with self.subTest(value=value):
                self.assertEqual(remask(value), value)


class TestTraffic(unittest.TestCase):

    def setUp(self):
        from src.forensics import NetworkForensics
        from src.forensics_db import ForensicsDB
        self.addCleanup(vault_config)
        self.db = ForensicsDB(vault_config())
        self.f = NetworkForensics(forensics_db=self.db)

    def feed(self, *packets):
        for p in packets:
            self.f.analyze_packet(p)

    def test_a_four_character_ftp_password_shows_nothing(self):
        self.feed(tcp(PC, 50000, NAS, 21, b'USER demo\r\n', server=21),
                  tcp(PC, 50000, NAS, 21, b'PASS abcd\r\n', server=21, ts=T0 + 1))
        [password] = [c for c in self.f.credentials_found if c['credential_type'] == 'password']
        self.assertEqual(password['value'], '********')
        from src.forensics import credential_alert
        self.assertEqual(credential_alert(password).evidence['value'], '********')

    def test_a_token_shows_four_characters(self):
        token = 'tok_' + 'q' * 28
        request = (f'GET /api HTTP/1.1\r\nHost: api.example.com\r\n'
                   f'Authorization: Bearer {token}\r\n\r\n').encode()
        self.feed(tcp(PC, 50001, SITE, 80, request, server=80))
        [found] = [c for c in self.f.credentials_found if c['credential_type'] == 'token']
        self.assertEqual(found['value'], 'Bearer tok_********')

    def test_a_session_cookie_is_kept_as_its_names(self):
        request = (f'GET / HTTP/1.1\r\nHost: shop.example\r\n'
                   f'Cookie: theme=dark; sessionid={SESSION}; csrftoken=abc123\r\n\r\n').encode()
        # A server on this network answering someone outside it.
        reply = (f'HTTP/1.1 200 OK\r\nSet-Cookie: SID={SESSION}; Path=/; HttpOnly\r\n'
                 f'Content-Length: 0\r\n\r\n').encode()
        self.feed(tcp(PC, 50002, SITE, 80, request, server=80),
                  tcp(NAS, 80, VISITOR, 50003, reply, server=80, ts=T0 + 1))
        cookies = [d for d in self.f.sensitive_data if d['data_type'] == 'Session Cookie']
        self.assertEqual([d['value'] for d in cookies],
                         ['names: sessionid, csrftoken (values not kept)',
                          'names: SID (values not kept)'])
        self.assertEqual(cookies[0]['evidence']['cookie_names'], 'sessionid, csrftoken')
        self.assertNotIn(SESSION, json.dumps(list(self.f.sensitive_data)))
        self.assertNotIn(SESSION, on_disk(self.db, self.db._sensitive_file))
        self.assertNotIn('abc123', on_disk(self.db, self.db._sensitive_file))

    def test_an_attribute_of_a_set_cookie_is_not_a_cookie(self):
        from src.forensics import session_cookie_names
        self.assertEqual(session_cookie_names('pref=1; Path=/auth; SameSite=Lax', True), [])
        self.assertEqual(session_cookie_names('auth_token=x; Path=/', True), ['auth_token'])


class TestWhatWasStoredBefore(unittest.TestCase):

    def test_the_vault_masks_old_values_again_and_drops_cookies(self):
        from src.forensics_db import ForensicsDB
        cfg = vault_config()
        self.addCleanup(vault_config)
        db = ForensicsDB(cfg)
        db.store_credential('FTP', 'password', '', 'abc*', PC, NAS, 21, T0)
        db.store_credential('IMAP', 'credentials', '', 'ftpuser:sec*****', PC, NAS, 143, T0)
        db.store_sensitive_data('Session Cookie', f'sessionid={SESSION}; theme=dark',
                                PC, SITE, 80, T0)
        db.store_sensitive_data('Session Cookie', 'theme=dark; lang=en', PC, SITE, 80, T0)
        db.flush()

        reopened = ForensicsDB(cfg)
        self.assertEqual(sorted(c['value'] for c in reopened.search_credentials()),
                         ['********', 'ftpuser:se********'])
        self.assertEqual([s['value'] for s in reopened.get_all_sensitive()],
                         ['names: sessionid (values not kept)', 'value not kept'])
        self.assertNotIn(SESSION, on_disk(reopened, reopened._sensitive_file))
        self.assertNotIn('abc*', on_disk(reopened, reopened._creds_file))

    def test_alert_history_masks_old_values_again(self):
        from src.alerts import AlertManager
        cfg = reset_config()
        manager = AlertManager(cfg)
        manager.clear_alerts()
        self.addCleanup(lambda: os.path.exists(manager.db_path) and os.remove(manager.db_path))
        old = [{'rule_id': 'FORENSICS-CREDENTIAL', 'severity': 'CRITICAL', 'title': 't',
                'description': 'd', 'timestamp': T0,
                'evidence': {'protocol': 'FTP', 'value': 'abc*'}},
               {'rule_id': 'OTHER', 'severity': 'LOW', 'title': 't', 'description': 'd',
                'timestamp': T0, 'evidence': {'value': 'abc*'}}]
        with open(manager.db_path, 'w', encoding='utf-8') as f:
            json.dump(old, f)
        loaded = AlertManager(cfg).get_alerts(limit=10)
        self.assertEqual(sorted(a.evidence['value'] for a in loaded), ['********', 'abc*'])


if __name__ == '__main__':
    unittest.main()
