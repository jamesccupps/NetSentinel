"""
File scans: secrets hidden in URLs and password exports, the secret shapes
added in 1.9, Windows leaks, high-entropy strings, and internal names.

Every secret here is made up at run time, so nothing in this file is, or
looks like, a real credential in the source.
"""

import base64
import json
import os
import random
import string
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401

from src import file_scan  # noqa: E402

ALNUM = string.ascii_letters + string.digits
URLSAFE = ALNUM + '_-'
HEX = '0123456789abcdef'
B = chr(92)   # a backslash, so UNC paths read the same here as in a file


def rand(n, alphabet=ALNUM, seed=None):
    rng = random.Random(f'{seed}-{n}-{alphabet[:3]}')
    return ''.join(rng.choice(alphabet) for _ in range(n))


def guid(seed):
    h = rand(32, HEX, seed)
    return f'{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}'


def scan(text, name='notes.txt', **options):
    data = text if isinstance(text, bytes) else text.encode('utf-8')
    if options:
        return file_scan.scan_bytes(name, data, file_scan.ScanOptions(**options))
    return file_scan.scan_bytes(name, data)


def kinds(result):
    return [s['kind'] for s in result['secrets']]


class TestUrlsKeepNoSecrets(unittest.TestCase):
    """H2: URL indicators kept every token but user:password."""

    def assertHidden(self, result, *raw):
        dumped = json.dumps(result)
        for value in raw:
            self.assertNotIn(value, dumped)

    def test_query_values_are_masked(self):
        key = rand(24, seed='q')
        jwt = 'eyJ' + rand(20, URLSAFE, 'h') + '.eyJ' + rand(30, URLSAFE, 'p') + '.' + rand(30, URLSAFE, 's')
        r = scan(f'GET https://api.example.com/v2/items?api_key={key}&access_token={jwt}&page=3\n')
        self.assertHidden(r, key, jwt[8:])
        (url,) = r['indicators']['url']
        self.assertTrue(url.startswith('https://api.example.com/v2/items?api_key='), url)
        self.assertTrue(url.endswith('&page=3'), url)

    def test_a_token_before_the_at_sign_is_masked(self):
        token = 'ghp_' + rand(36, seed='gh')
        r = scan(f'git clone https://{token}@github.com/acme/tools.git\n')
        self.assertHidden(r, token[4:])
        (url,) = r['indicators']['url']
        self.assertTrue(url.endswith('@github.com/acme/tools.git'), url)
        self.assertEqual(r['indicators']['email'], {})

    def test_webhook_urls_are_masked(self):
        slack_secret = rand(24, seed='sl')
        slack = ('https://hooks.slack.' + 'com/services/T' + rand(8, string.ascii_uppercase, 't') +
                 '/B' + rand(10, string.ascii_uppercase, 'b') + '/' + slack_secret)
        discord_secret = rand(68, URLSAFE, 'dc')
        discord = 'https://discord.' + 'com/api/webhooks/' + '123456789012345678/' + discord_secret
        bot_secret = 'AA' + rand(33, URLSAFE, 'tg')
        telegram = 'https://api.telegram.' + 'org/bot' + '123456789:' + bot_secret + '/sendMessage'
        teams_secret = rand(32, HEX, 'tm')
        teams = ('https://acme.webhook.office.' + 'com/webhookb2/' + guid(1) + '@' + guid(2) +
                 '/IncomingWebhook/' + teams_secret + '/' + guid(3))
        r = scan('\n'.join([slack, discord, telegram, teams]) + '\n')
        self.assertHidden(r, slack_secret, discord_secret, bot_secret, teams_secret, guid(3))
        hosts = sorted(u.split('/')[2] for u in r['indicators']['url'])
        self.assertEqual(hosts, ['acme.webhook.office.com', 'api.telegram.org', 'discord.com',
                                 'hooks.slack.com'])
        self.assertTrue({'slack_webhook', 'discord_webhook', 'telegram_bot_token'} <= set(kinds(r)))

    def test_an_azure_sas_signature_is_masked(self):
        sig = rand(43, ALNUM + '%', 'sig') + '%3D'
        r = scan('https://acct.blob.core.windows.net/c/backup.bak?sv=2022-11-02&sr=b&sp=r'
                 f'&se=2030-01-01T00%3A00%3A00Z&sig={sig}\n')
        self.assertHidden(r, sig[:20])
        self.assertIn('azure_sas', kinds(r))
        (url,) = r['indicators']['url']
        self.assertIn('sv=2022-11-02', url)

    def test_a_url_ends_at_a_comma(self):
        r = scan('example,https://example.com/login,alice,Hunter22!\n')
        self.assertEqual(list(r['indicators']['url']), ['https://example.com/login'])
        self.assertHidden(r, 'Hunter22')

    def test_tokens_in_the_path_or_fragment_are_masked(self):
        share = rand(32, seed='share')
        after_key = rand(12, seed='key')
        fragment = rand(40, seed='frag')
        r = scan(f'https://files.example.net/share/{share}/report.pdf\n'
                 f'https://api.example.net/key/{after_key}/status\n'
                 f'https://app.example.com/callback#access_token={fragment}&state=x1\n')
        self.assertHidden(r, share, after_key, fragment)
        self.assertEqual(len(r['indicators']['url']), 3)

    def test_ordinary_urls_are_left_alone(self):
        url = 'https://docs.example.com/guide/install?lang=en&page=2#setup'
        r = scan(f'see {url} and https://bob:Pa55word@site.example.com/a\n')
        self.assertIn(url, r['indicators']['url'])
        self.assertIn('https://bob:****@site.example.com/a', r['indicators']['url'])


class TestPasswordExports(unittest.TestCase):
    """H2: a browser password export put every saved password in clear."""

    def check(self, text, passwords, name='passwords.csv'):
        r = scan(text, name)
        dumped = json.dumps(r)
        for p in passwords:
            self.assertNotIn(p, dumped)
        found = [s for s in r['secrets'] if s['kind'] == 'export_password']
        self.assertEqual(len(found), len(passwords))
        self.assertTrue(all(s['severity'] == 'CRITICAL' for s in found))
        return r, found

    def test_a_chrome_or_edge_export(self):
        pw = ['Hunter22!x', 'S3cret-' + rand(8, seed=1)]
        r, found = self.check('name,url,username,password,note\n'
                              f'example,https://example.com/login,alice@example.com,{pw[0]},\n'
                              f'shop,https://shop.example.org/,bob,{pw[1]},gift card\n', pw)
        self.assertEqual([s['line'] for s in found], [2, 3])
        self.assertEqual(sorted(r['indicators']['url']),
                         ['https://example.com/login', 'https://shop.example.org/'])
        self.assertIn('alice@example.com', r['indicators']['email'])

    def test_a_firefox_export_with_quotes_and_commas(self):
        pw = ['pa,ss"word' + rand(4, seed=2), 'plain' + rand(8, seed=3)]
        quoted = pw[0].replace('"', '""')
        self.check('"url","username","password","httpRealm","formActionOrigin","guid",'
                   '"timeCreated","timeLastUsed","timePasswordChanged"\n'
                   f'"https://a.example.com","carol","{quoted}",,"https://a.example.com",'
                   '"{x}","1","2","3"\n'
                   f'"https://b.example.com","dave","{pw[1]}",,"","{{y}}","1","2","3"\n', pw)

    def test_a_bitwarden_export(self):
        pw = ['Bw-' + rand(12, seed=4)]
        self.check('folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,'
                   'login_password,login_totp\n'
                   f',,login,Mail,,,0,https://mail.example.com,erin,{pw[0]},\n', pw)

    def test_a_password_shaped_like_an_address_is_not_an_indicator(self):
        r, _ = self.check('name,url,username,password\n'
                          'x,https://x.example.com/,frank,ops@evil-example.net\n',
                          ['ops@evil-example.net'])
        self.assertNotIn('evil-example.net', r['indicators']['domain'])
        self.assertEqual(list(r['indicators']['email']), [])


class TestSecretShapes(unittest.TestCase):

    def test_new_token_kinds(self):
        account_key = base64.b64encode(rand(64, seed='az').encode()).decode()
        npmrc = guid('npm')
        cases = {
            'azure_storage_key': ('DefaultEndpointsProtocol=https;AccountName=acct;AccountKey='
                                  f'{account_key};EndpointSuffix=core.windows.net', account_key[:40]),
            'twilio_api_key': ('SK' + rand(32, HEX, 'tw'), rand(32, HEX, 'tw')),
            'twilio_auth_token': ('TWILIO_AUTH_TOKEN=' + rand(32, HEX, 'ta'), rand(32, HEX, 'ta')),
            'sendgrid_key': ('SG.' + rand(22, URLSAFE, 'sg1') + '.' + rand(43, URLSAFE, 'sg2'),
                             rand(43, URLSAFE, 'sg2')),
            'mailgun_key': ('key-' + rand(32, seed='mg'), rand(32, seed='mg')),
            'npm_token': ('npm_' + rand(36, seed='npm'), rand(36, seed='npm')),
            'npm_auth': (f'//registry.npmjs.org/:_authToken={npmrc}', npmrc),
            'pypi_token': ('pypi-AgEIcHlwaS5vcmc' + rand(60, URLSAFE, 'py'), rand(60, URLSAFE, 'py')),
            'gitlab_token': ('glpat-' + rand(20, seed='gl'), rand(20, seed='gl')),
            'docker_auth': ('{"auths": {"registry.example.com": {"auth": "' +
                            base64.b64encode(b'ci:' + rand(16, seed='dk').encode()).decode() + '"}}}',
                            base64.b64encode(b'ci:' + rand(16, seed='dk').encode()).decode()),
        }
        for kind, (text, raw) in cases.items():
            with self.subTest(kind=kind):
                r = scan(text + '\n')
                self.assertIn(kind, kinds(r))
                self.assertNotIn(raw, json.dumps(r))

    def test_a_gcp_service_account_is_one_labelled_finding(self):
        body = '\\n'.join(rand(64, ALNUM + '+/', f'pem{i}') for i in range(4))
        sa = json.dumps({'type': 'service_account', 'project_id': 'demo',
                         'private_key_id': rand(40, HEX, 'kid'),
                         'private_key': '-----BEGIN PRIVATE KEY-----\n' + body +
                                        '\n-----END PRIVATE KEY-----\n',
                         'client_email': 'svc@demo.iam.gserviceaccount.com'})
        r = scan(sa, 'demo-sa.json')
        self.assertEqual(kinds(r), ['gcp_service_account'])
        self.assertEqual(r['secrets'][0]['value'], '(service-account private key)')

    def test_settings_named_with_a_prefix(self):
        """DB_PASSWORD= and friends: '_' is a word character, so \\bpassword missed them."""
        values = ['Pg-' + rand(10, seed=i) for i in range(4)]
        text = (f'DB_PASSWORD={values[0]}\nSECRET_KEY={values[1]}\n'
                f'GITHUB_TOKEN={values[2]}\nJWT_SECRET="{values[3]}"\n')
        r = scan(text, 'config.txt')
        self.assertEqual(kinds(r), ['password'] * 4)
        self.assertEqual([s['line'] for s in r['secrets']], [1, 2, 3, 4])
        dumped = json.dumps(r)
        for v in values:
            self.assertNotIn(v, dumped)

    def test_env_files_are_read_by_name(self):
        text = (f'ENCRYPTION_KEY={rand(24, seed="ek")}\nSESSION_SALT={rand(16, seed="ss")}\n'
                f'NEXT_PUBLIC_SITE_KEY={rand(20, seed="pk")}\nAPP_PORT=8080\n'
                'MAIL_PASSWORD=${MAIL_PASSWORD}\n')
        self.assertEqual(kinds(scan(text, 'deploy/.env.production')), ['env_secret'] * 2)
        # elsewhere the names alone are not enough (the random key still
        # reads as a high-entropy string)
        self.assertNotIn('env_secret', kinds(scan(text, 'deploy/settings.txt')))

    def test_camel_case_settings(self):
        r = scan('{"dbPassword": "' + rand(14, seed='db') + '", "nextPageToken": "' +
                 rand(30, seed='np') + '"}\nAdminPassword="' + rand(12, seed='ad') + '"\n')
        self.assertEqual(kinds(r), ['password', 'password'])

    def test_code_is_still_not_a_password(self):
        r = scan('self.api_key = api_key\ntoken = handle.read().strip()\n'
                 'run(secret=True)\nInvalidToken = Exception\n'
                 "headers = {'X-Netmon-Token': TOKEN}\npassword_hint = 'your pet'\n"
                 "if kind == 'private_key':\n    return mask(value)\n")
        self.assertEqual(r['secrets'], [])

    def test_passwords_in_scripts(self):
        a, b = 'Synth-' + rand(8, seed='a'), 'Synth-' + rand(8, seed='b')
        r = scan(f"$pw = ConvertTo-SecureString '{a}' -AsPlainText -Force\n"
                 f'net user svc_backup {b} /add\n', 'setup.ps1')
        self.assertEqual(kinds(r), ['password', 'password'])
        self.assertNotIn(a, json.dumps(r))
        self.assertNotIn(b, json.dumps(r))


class TestWindowsLeaks(unittest.TestCase):

    def test_unattend_passwords_are_decoded_then_masked(self):
        user = 'Synth3tic-' + rand(6, seed='u')
        admin = 'Adm1n-' + rand(6, seed='a')
        enc = {k: base64.b64encode((v + suffix).encode('utf-16-le')).decode()
               for k, v, suffix in (('user', user, 'Password'), ('admin', admin, 'AdministratorPassword'))}
        xml = ('<unattend xmlns="urn:schemas-microsoft-com:unattend"><settings><component>'
               '<UserAccounts><AdministratorPassword><Value>' + enc['admin'] + '</Value>'
               '<PlainText>false</PlainText></AdministratorPassword>\n<LocalAccounts><LocalAccount>'
               '<Password><Value>' + enc['user'] + '</Value><PlainText>false</PlainText></Password>'
               '</LocalAccount></LocalAccounts></UserAccounts>\n<AutoLogon><Password><Value>'
               '*SENSITIVE*DATA*DELETED*</Value></Password></AutoLogon></component></settings></unattend>')
        r = scan(xml, 'Panther/unattend.xml')
        self.assertEqual(kinds(r), ['unattend_password', 'unattend_password'])
        # the mask shows the start of the password, not of its base64
        self.assertEqual(sorted(s['value'][:2] for s in r['secrets']), sorted([admin[:2], user[:2]]))
        dumped = json.dumps(r)
        for raw in (user, admin, enc['user'], enc['admin']):
            self.assertNotIn(raw, dumped)

    def test_group_policy_cpassword_is_decrypted_and_masked(self):
        try:
            from cryptography.hazmat.primitives import padding
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError:
            self.skipTest('needs cryptography')
        clear = 'Gpp-' + rand(10, seed='gpp')
        padder = padding.PKCS7(128).padder()
        data = padder.update(clear.encode('utf-16-le')) + padder.finalize()
        enc = Cipher(algorithms.AES(file_scan._GPP_KEY), modes.CBC(b'\x00' * 16)).encryptor()
        cpassword = base64.b64encode(enc.update(data) + enc.finalize()).decode().rstrip('=')
        xml = ('<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User name="Administrator">'
               f'<Properties action="U" newName="" cpassword="{cpassword}" userName="Administrator"/>'
               '</User></Groups>')
        r = scan(xml, 'Machine/Preferences/Groups/Groups.xml')
        self.assertEqual(kinds(r), ['gpp_cpassword'])
        self.assertEqual(r['secrets'][0]['value'][:2], clear[:2])
        dumped = json.dumps(r)
        self.assertNotIn(clear, dumped)
        self.assertNotIn(cpassword[:16], dumped)

    def test_wifi_profiles(self):
        key = 'Wifi-' + rand(10, seed='w')
        profile = ('<WLANProfile><name>Office</name><MSM><security><sharedKey>'
                   '<keyType>passPhrase</keyType><protected>{p}</protected>'
                   '<keyMaterial>{k}</keyMaterial></sharedKey></security></MSM></WLANProfile>')
        clear = scan(profile.format(p='false', k=key), 'Wi-Fi-Office.xml')
        self.assertEqual([(s['kind'], s['severity']) for s in clear['secrets']], [('wifi_key', 'HIGH')])
        self.assertNotIn(key, json.dumps(clear))
        sealed = scan(profile.format(p='true', k='01000000D08C9DDF' + rand(64, HEX, 'd')), 'w.xml')
        self.assertEqual([(s['kind'], s['severity']) for s in sealed['secrets']],
                         [('wifi_key_protected', 'LOW')])

    def test_keepass_databases_are_flagged(self):
        magic = b'\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5' + os.urandom(64)
        for name, data in (('vault.bin', magic), ('Passwords.kdbx', b'\x00' * 32)):
            with self.subTest(name=name):
                r = file_scan.scan_bytes(name, data)
                self.assertEqual(kinds(r), ['keepass_db'])
                self.assertEqual(r['secrets'][0]['value'], '(KeePass database file)')

    def test_putty_private_keys(self):
        key = ('PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: demo\n'
               'Public-Lines: 2\n' + rand(64, ALNUM + '+/', 'pub') + '\n' + rand(20, seed='pub2') +
               '\nPrivate-Lines: 1\n' + rand(44, ALNUM + '+/', 'priv') + '\nPrivate-MAC: ' +
               rand(64, HEX, 'mac') + '\n')
        r = scan(key, 'id_ed25519.ppk')
        self.assertEqual(kinds(r), ['private_key'])


class TestHighEntropy(unittest.TestCase):

    def test_a_random_value_is_flagged(self):
        value = rand(40, seed='blob')
        r = scan(f'session_blob = "{value}"\n', 'settings.ini')
        self.assertEqual(kinds(r), ['high_entropy'])
        self.assertEqual(r['secrets'][0]['severity'], 'MEDIUM')
        self.assertNotIn(value, json.dumps(r))

    def test_quiet_on_the_usual_noise(self):
        b64 = base64.b64encode(os.urandom(64)).decode()
        png = base64.b64encode(b'\x89PNG' + os.urandom(400)).decode()
        minified = 'var ' + ','.join(f'k{i}="{rand(30, seed=i)}"' for i in range(80)) + ';\n'
        cases = [
            ('package-lock.json', f'"integrity": "sha512-{b64}",\n"version": "4.17.21"\n'),
            ('app.log', f'request_id = {guid("r")}\ncommit = {rand(40, HEX, "c")}\n'
                        f'checksum: {rand(64, HEX, "s")}\n'),
            ('page.html', f'icon = "data:image/png;base64,{png}"\n'),
            ('style.css', f'src: url(data:font/woff2;base64,{png}) format("woff2");\n'),
            ('bundle.js', minified),
            ('names.py', 'handler = getElementsByTagNameNS2\nlabel = SomeLongCamelCaseIdentifier1\n'
                         'chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"\n'),
        ]
        for name, text in cases:
            with self.subTest(name=name):
                self.assertNotIn('high_entropy', kinds(scan(text, name)))
        binary = bytes(range(256)) * 8 + f'key={rand(30, seed="bin")}\n'.encode()
        self.assertNotIn('high_entropy', kinds(file_scan.scan_bytes('blob.dat', binary)))


class TestInternalNames(unittest.TestCase):

    def test_domains_carry_a_scope(self):
        r = scan('fs01.corp.local printer.lan build.internal nas.home.arpa svc.example.com '
                 'login.acme-intranet.net\n', internal_domains=('acme-intranet.net',))
        scopes = {d: info['scope'] for d, info in r['indicators']['domain'].items()}
        self.assertEqual(scopes, {'fs01.corp.local': 'internal', 'printer.lan': 'internal',
                                  'build.internal': 'internal', 'nas.home.arpa': 'internal',
                                  'svc.example.com': 'public', 'login.acme-intranet.net': 'internal'})

    def test_domain_scope(self):
        self.assertEqual(file_scan.domain_scope('wpad'), 'internal')
        self.assertEqual(file_scan.domain_scope('host.test'), 'reserved')
        self.assertEqual(file_scan.domain_scope('4.3.2.1.in-addr.arpa'), 'reserved')
        self.assertEqual(file_scan.domain_scope('Example.COM.'), 'public')

    def test_unc_paths_and_their_hosts(self):
        text = (f'copy {B * 2}fs01{B}finance${B}q3.xlsx and {B * 2}nas.corp.local{B}backups\n'
                f'"path": "{B * 4}printsrv{B * 2}queue1"\n'
                f'not paths: C:{B * 2}Users{B * 2}bob {B * 2}?{B}C:{B}x "{B * 2}nfoo{B * 2}tbar"\n')
        r = scan(text)
        self.assertEqual(sorted(r['indicators']['unc']),
                         sorted([f'{B * 2}fs01{B}finance$', f'{B * 2}nas.corp.local{B}backups',
                                 f'{B * 2}printsrv{B}queue1']))
        self.assertEqual(sorted(r['indicators']['host']), ['fs01', 'printsrv'])
        self.assertEqual(r['indicators']['host']['fs01']['scope'], 'internal')

    def test_single_label_hosts_in_settings_and_urls(self):
        r = scan('Server=SQLPROD01;Database=x;\nData Source=fileserver01;\nsmtp_host: mailrelay\n'
                 'see http://intranet/wiki and http://localhost:8080/\nServer: nginx\n'
                 'self.server = WebServer(port)\n')
        self.assertEqual(sorted(r['indicators']['host']),
                         ['fileserver01', 'intranet', 'mailrelay', 'sqlprod01'])

    def test_code_objects_are_not_domains(self):
        r = scan('if (window.top !== window.self) { parent.top.location = x; }\n', 'frame.js')
        self.assertEqual(r['indicators']['domain'], {})


class TestVolume(unittest.TestCase):

    def test_secrets_per_kind_are_capped_but_counted(self):
        text = ''.join(f'password = Synth{i:03d}x!\n' for i in range(120))
        r = scan(text, 'dump.txt')
        self.assertEqual(len(r['secrets']), file_scan.MAX_SECRETS_PER_KIND)
        self.assertEqual(r['secret_counts'], {'password': 120})

    def test_one_secret_is_reported_once(self):
        token = 'ghp_' + rand(36, seed='once')
        r = scan(f'GITHUB_TOKEN={token}\n', '.env')
        self.assertEqual(kinds(r), ['github_token'])


if __name__ == '__main__':
    unittest.main()
