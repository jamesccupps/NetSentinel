"""
NetSentinel - File Content Scan
Pulls network indicators (IP addresses, domains, internal host names, UNC
paths, URLs, email and MAC addresses) and anything that looks like a leaked
secret (keys, tokens, passwords, card numbers) out of ordinary files: logs,
configs, exports, documents, event logs, macros, and the readable strings of
binaries. Scripts and command lines are also checked for the patterns of
downloaders and encoded PowerShell (src.script_rules).

Secrets are masked the moment they are found. The raw value never leaves
scan_bytes(): not in the findings, the indicators, the logs, or an export.
That includes the parts of a URL that carry a credential: query values,
tokens in the path, webhook paths and user:password. Where a value must be
recognised again (the ignore list), only a keyed hash of it goes out.
"""

import base64
import binascii
import csv
import heapq
import html
import ipaddress
import math
import os
import re
import zipfile
import zlib
from bisect import bisect_left, bisect_right
from collections import Counter
from io import BytesIO

from src import script_rules

MAX_TEXT_BYTES = 64 * 1024 * 1024
MAX_PER_KIND = 5000          # distinct indicators of one kind kept per file
MAX_SECRETS_PER_KIND = 50    # secrets of one kind listed per file; the rest are counted
MAX_PDF_BYTES = MAX_TEXT_BYTES   # inflated from all of one PDF's streams together
MAX_MACRO_BYTES = 8 * 1024 * 1024
MAX_EVTX_RECORDS = 200_000
MAX_DECODE_DEPTH = 2         # encoded PowerShell inside encoded PowerShell, and no deeper

INDICATOR_KINDS = ('ipv4', 'ipv6', 'domain', 'host', 'unc', 'url', 'email', 'mac')
LOCATION_ONLY = frozenset({'card_number', 'ssn'})   # never hashed, even for the ignore list

OFFICE_EXTS = ('.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm', '.dotx', '.dotm',
               '.xltx', '.xltm', '.xlam', '.potx', '.potm', '.ppsx', '.ppsm',
               '.odt', '.ods', '.odp')
MEDIA_EXTS = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.webp', '.mp3', '.mp4',
              '.m4a', '.wav', '.avi', '.mov', '.mkv', '.flac', '.ogg', '.woff', '.woff2',
              '.ttf', '.otf')
_OLE_MAGIC = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'
_KEEPASS_MAGIC = (b'\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5', b'\x03\xd9\xa2\x9a\x65\xfb\x4b\xb5')
_EVTX_MAGIC = b'ElfFile\x00'

# Generic TLDs worth recognising, plus every two-letter ccTLD except the ones
# that are far more often a file extension (foo.py, run.sh, notes.md). Generic
# TLDs that are also common attribute names (.name, .page, .host) are left out:
# in code and logs they are almost never domains.
_GENERIC_TLDS = set('''
com net org edu gov mil int info biz mobi asia io co ai app dev cloud online site top
xyz club tech blog local lan internal intranet corp arpa onion localdomain
'''.split())
_NOT_CCTLDS = {'py', 'sh', 'md', 'rs', 'pl', 'cs', 'js', 'ts', 'db', 'so', 'pm', 'rb',
               'go', 'ps', 'mk', 'cc', 'hh', 'el', 'ml', 'as', 'am', 'do', 'or'}

# Names that only ever mean this network. They are reported as internal and
# never looked up in a threat feed: that would say nothing and leak the name.
_INTERNAL_SUFFIXES = ('local', 'lan', 'internal', 'intranet', 'corp', 'home', 'localdomain',
                      'private', 'home.arpa', 'workgroup')
_RESERVED_SUFFIXES = ('localhost', 'test', 'example', 'invalid', 'arpa')

# window.top and self.app are code, not domains: two-label names whose first
# label is one of these are left out.
_CODE_OBJECTS = frozenset('''
window document self this parent top console navigator location history screen frames
event math json object array string number promise reflect globalthis module exports
process e el obj ctx err args opts props state elem
'''.split())

_IPV4 = re.compile(r'(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
                   r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])')
_IPV6 = re.compile(r'(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])')
_MAC = re.compile(r'(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}(?:([:-])[0-9A-Fa-f]{2})(?:\1[0-9A-Fa-f]{2}){4}'
                  r'(?![0-9A-Fa-f:-])')
_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]{1,64}@((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})\b')
# A comma ends a URL: in a CSV row the next field (a username, a password) is
# not part of it.
_URL = re.compile(r'\b(?:https?|ftp|wss?)://[^\s"\'<>()\[\]{}\\,]{3,2000}')
_DOMAIN = re.compile(r'(?<![@\w.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'
                     r'([A-Za-z]{2,24}))(?![\w-]|\.\w)')
_LABEL = r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
_UNC_HOST = r'(' + _LABEL + r'(?:\.' + _LABEL + r')*)'
_UNC_SHARE = r'([A-Za-z0-9$_][^\\/\s:*?"<>|,;\'()\[\]{}]{0,79})'
# \\server\share, or \\\\server\\share as it appears escaped in JSON and code;
# the separators must match the prefix, so "\\n\\t" in a string is not a path.
_UNC = re.compile(r'(?<![\\\w:/.$%])(?:\\\\' + _UNC_HOST + r'\\' + _UNC_SHARE +
                  r'|\\\\\\\\' + _UNC_HOST + r'\\\\' + _UNC_SHARE + r')')
_HOST_SETTING = re.compile(
    r'(?i)(?<![A-Za-z0-9_])((?:db|sql|smtp|mail|ldap|ftp|proxy|nas|file|print)?[_.-]?'
    r'(?:host(?:name)?|server(?:name)?|data[ _]?source|computer[ _]?name|machine[ _]?name|'
    r'domain[ _]?controller))["\']?[ \t]*([:=])[ \t]*["\']?([A-Za-z][A-Za-z0-9-]{1,62})'
    r'(?=[\s;,"\'&>]|\Z)')
_NOT_HOSTS = frozenset('''
localhost true false none null nil auto any all default yes no on off enabled disabled port
server host hostname name value string example test local unknown required optional
'''.split())

_VALUE = r'(?:"([^"\r\n]{4,128})"|\'([^\'\r\n]{4,128})\'|["\']?([^\s"\'<>,;]{4,128}))'
# The key of a setting: an optional prefix such as DB_, GITHUB_ or app. (so
# DB_PASSWORD and JWT_SECRET count; '_' is a word character, so \b missed them)
# then the word itself, then an optional _KEY / _BASE style suffix.
_PASSWORD_SETTING = re.compile(
    r'(?i)(?<![A-Za-z0-9])((?:[A-Za-z0-9]{1,40}[_.-]){0,4}'
    r'(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|access[_-]?token|'
    r'auth[_-]?token|client[_-]?secret|private[_-]?key)'
    r'(?:[_.-](?:key|base|value|token|secret|str|string|hash|salt)){0,2})'
    r'(?![A-Za-z0-9])["\']?[ \t]*[:=][ \t]*' + _VALUE)
_PASSWORD_CAMEL = re.compile(
    r'(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9]{0,30}?(?:Password|Passwd|Passphrase|Secret|'
    r'AccessKey|PrivateKey|AccessToken|AuthToken|RefreshToken|ClientSecret|Token)(?:Key|Value)?)'
    r'(?![A-Za-z0-9_])["\']?[ \t]*[:=][ \t]*' + _VALUE)
_SECURESTRING = re.compile(r'(?i)convertto-securestring\s+(?:-string\s+)?["\']([^"\'\r\n]{4,128})["\']'
                           r'\s+-asplaintext')
_NET_USER = re.compile(r'(?i)\bnet(?:\.exe)?\s+user\s+\S{1,64}\s+([^\s*/][^\s]{3,127})\s+/add\b')
_NOISE_WORDS = frozenset('''
page next prev previous continuation cursor csrf xsrf sync cancel max min num count show hide
toggle label placeholder hint policy expiry expires length type format field input regex
pattern validation required file path name public publishable
'''.split())

_PLACEHOLDERS = re.compile(r'^(?:\*+|x+|\.+|none|null|nil|true|false|undefined|password|'
                           r'secret|changeme_?later|your[_-]?\w*|<[^>]*>|\$.*|%\w+%|'
                           r'%\(?\w+\)?s?|\{\{?[^}]*\}?\}|env\[.*|os\.environ.*|getenv.*|'
                           r'\w+\(.*|.*[\[(]|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+|-----BEGIN.*|'
                           r'[A-Za-z_][\w.]*[\[\](){}].*|.*\.\.\..*|'
                           r'\[?redacted\]?|masked|hidden|removed|'
                           r'str|string|int|bool|text|varchar.*|optional.*)$', re.I)

# (kind, label, severity, pattern, group(s) holding the secret). Specific
# shapes come first: where two patterns cover the same text the first wins,
# so a GitHub token in GITHUB_TOKEN= is reported as a GitHub token.
_SPECIFIC = [
    ('aws_access_key', 'AWS access key', 'CRITICAL',
     re.compile(r'\b((?:AKIA|ASIA)[0-9A-Z]{16})\b'), 1),
    ('aws_secret_key', 'AWS secret key', 'CRITICAL',
     re.compile(r'(?i)aws_?secret_?access_?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})'), 1),
    ('github_token', 'GitHub token', 'CRITICAL',
     re.compile(r'\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b'), 1),
    ('gitlab_token', 'GitLab token', 'CRITICAL', re.compile(r'\b(glpat-[A-Za-z0-9_-]{20,})'), 1),
    ('slack_webhook', 'Slack webhook URL', 'HIGH',
     re.compile(r'https://hooks\.slack\.com/(?:services|workflows|triggers)/([A-Za-z0-9_/+-]{20,})'), 1),
    ('slack_token', 'Slack token', 'HIGH', re.compile(r'\b(xox[baprse]-[A-Za-z0-9-]{10,})'), 1),
    ('discord_webhook', 'Discord webhook URL', 'HIGH',
     re.compile(r'https://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/(?:v\d+/)?webhooks/'
                r'\d{15,22}/([A-Za-z0-9_-]{50,100})'), 1),
    ('telegram_bot_token', 'Telegram bot token', 'HIGH',
     re.compile(r'(?:(?<=bot)|(?<![A-Za-z0-9_]))(\d{6,12}:AA[A-Za-z0-9_-]{33})(?![A-Za-z0-9_-])'), 1),
    ('stripe_key', 'Stripe live key', 'CRITICAL', re.compile(r'\b([sr]k_live_[A-Za-z0-9]{16,})'), 1),
    ('google_api_key', 'Google API key', 'HIGH', re.compile(r'\b(AIza[0-9A-Za-z_-]{35})(?![\w-])'), 1),
    ('sendgrid_key', 'SendGrid API key', 'HIGH',
     re.compile(r'\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])'), 1),
    ('twilio_api_key', 'Twilio API key', 'HIGH', re.compile(r'\b(SK[0-9a-f]{32})\b'), 1),
    ('twilio_auth_token', 'Twilio auth token', 'HIGH',
     re.compile(r'(?i)twilio[A-Za-z0-9_.-]{0,30}?(?:auth)?[_.-]?token["\']?\s*[:=]\s*["\']?'
                r'([0-9a-f]{32})\b'), 1),
    ('mailgun_key', 'Mailgun API key', 'HIGH',
     re.compile(r'\b(key-[0-9a-zA-Z]{32})\b|(?<![0-9a-f-])([0-9a-f]{32}-[0-9a-f]{8}-[0-9a-f]{8})'
                r'(?![0-9a-f-])'), (1, 2)),
    ('npm_token', 'npm access token', 'HIGH', re.compile(r'\b(npm_[A-Za-z0-9]{36})\b'), 1),
    ('pypi_token', 'PyPI upload token', 'HIGH', re.compile(r'\b(pypi-Ag[A-Za-z0-9_-]{50,})'), 1),
    ('azure_storage_key', 'Azure storage or shared access key', 'CRITICAL',
     re.compile(r'(?i)\b(?:AccountKey|SharedAccessKey)\s*=\s*([A-Za-z0-9+/]{40,90}={0,2})'), 1),
    ('azure_sas', 'Azure SAS token signature', 'HIGH',
     re.compile(r'(?i)[?&;]sig=([A-Za-z0-9%+/=]{30,})'), 1),
    ('api_key', 'API key (sk-)', 'HIGH', re.compile(r'\b(sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,})'), 1),
    ('jwt', 'JSON Web Token', 'HIGH',
     re.compile(r'\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})'), 1),
]

_GENERIC = [
    ('url_password', 'Password in a URL', 'HIGH',
     re.compile(r'\b[a-z][a-z0-9+.-]{1,15}://[^\s:/@"\']{1,64}:([^\s@/"\']{1,128})@[^\s/"\']+'), 1),
    ('basic_auth', 'HTTP Basic credentials', 'HIGH',
     re.compile(r'(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{8,})'), 1),
    ('bearer_token', 'Bearer token', 'HIGH',
     re.compile(r'(?i)\bauthorization["\']?\s*[:=]\s*["\']?bearer\s+([A-Za-z0-9._~+/=-]{16,})'), 1),
    ('password', 'Password in a script', 'HIGH', _SECURESTRING, 1),
    ('password', 'Password in a script', 'HIGH', _NET_USER, 1),
    ('password', 'Password or secret in a setting', 'HIGH', _PASSWORD_SETTING, (2, 3, 4)),
    ('password', 'Password or secret in a setting', 'HIGH', _PASSWORD_CAMEL, (2, 3, 4)),
]

_PII = [
    ('card_number', 'Payment card number', 'CRITICAL',
     re.compile(r'(?<![\d-])([3-6]\d{3}(?:[ -]?\d{2,4}){3,4})(?![\d-])'), 1),
    ('ssn', 'US Social Security number', 'HIGH',
     re.compile(r'(?<![\d-])((?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4})(?![\d-])'), 1),
]

# Literals each pattern cannot match without. `in` finds them at memory
# speed, and most files hold no Slack, Twilio or PyPI token at all, so a
# pattern whose literals are absent skips its regex pass. For patterns that
# ignore case the literals are lowercase and looked for in lowercased text.
_KIND_TRIGGERS = {
    'aws_access_key': ('AKIA', 'ASIA'), 'aws_secret_key': ('secret',),
    'github_token': ('ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_', 'github_pat_'),
    'gitlab_token': ('glpat-',), 'slack_webhook': ('hooks.slack.com',), 'slack_token': ('xox',),
    'discord_webhook': ('discord',), 'telegram_bot_token': (':AA',), 'stripe_key': ('k_live_',),
    'google_api_key': ('AIza',), 'sendgrid_key': ('SG.',), 'twilio_api_key': ('SK',),
    'twilio_auth_token': ('twilio',), 'npm_token': ('npm_',), 'pypi_token': ('pypi-',),
    'azure_storage_key': ('accountkey', 'sharedaccesskey'), 'azure_sas': ('sig=',),
    'api_key': ('sk-',), 'jwt': ('eyJ',), 'url_password': ('://',), 'basic_auth': ('basic',),
    'bearer_token': ('bearer',),
}
_TRIGGERS = {p: _KIND_TRIGGERS[k] for k, _, _, p, _ in _SPECIFIC + _GENERIC if k in _KIND_TRIGGERS}
_TRIGGERS.update({
    _SECURESTRING: ('-asplaintext',), _NET_USER: ('/add',),
    _PASSWORD_SETTING: ('pass', 'pwd', 'secret', 'token', 'key'),
    _PASSWORD_CAMEL: ('Pass', 'Secret', 'Key', 'Token'),
})

# ─── Structured secrets ─────────────────────────────────────────────────

_PEM_KEY = re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----'
                      r'(?:[\s\S]{0,12000}?-----END [A-Z ]{0,40}-----)?')
_PUTTY_KEY = re.compile(r'PuTTY-User-Key-File-\d+:[^\r\n]{0,200}(?:[\s\S]{0,12000}?Private-MAC:[^\r\n]*)?')
_GCP_MARKER = re.compile(r'"type"\s*:\s*"service_account"')
_GCP_KEY = re.compile(r'"private_key"\s*:\s*"(-----BEGIN[^"]{0,12000})"')
_CPASSWORD = re.compile(r'(?i)\bcpassword\s*=\s*"([A-Za-z0-9+/=]{8,})"')
# Microsoft published this AES-256 key (MS-GPPREF 2.2.1.1.4), so every
# cpassword in a Group Policy Preferences file is readable by anyone in the
# domain. It is not a secret of ours; it is why cpassword is a leak.
_GPP_KEY = bytes.fromhex('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b')
_UNATTEND_MARK = re.compile(r'(?i)urn:schemas-microsoft-com:unattend|<unattend\b')
_XML_PASSWORD = re.compile(r'(?is)<((?:[\w-]+:)?(?:AdministratorPassword|AdminPassword|Password|'
                           r'Passwd|Pass|Pwd))(\s[^>]{0,500})?>(.{0,4000}?)</\1\s*>')
_XML_VALUE = re.compile(r'(?is)<(?:[\w-]+:)?Value(?:\s[^>]{0,200})?>([^<]{1,2048})</(?:[\w-]+:)?Value\s*>')
_XML_PLAIN = re.compile(r'(?is)<(?:[\w-]+:)?PlainText\s*>\s*(true|false)\s*<')
_WIFI_KEY = re.compile(r'(?is)<keyMaterial>\s*([^<\s][^<]{0,511}?)\s*</keyMaterial>')
_WIFI_PROTECTED = re.compile(r'(?is)<protected>\s*(true|false)\s*</protected>')
_DOCKER_AUTHS = re.compile(r'"auths"\s*:')
_DOCKER_AUTH = re.compile(r'"(?:auth|identitytoken|registrytoken)"\s*:\s*"([A-Za-z0-9+/=._-]{8,})"')
_NPMRC = re.compile(r'(?im)^[ \t]*(?:\S*:)?_(?:authToken|auth|password)[ \t]*=[ \t]*["\']?([^\s"\']{8,})')
_ENV_LINE = re.compile(r'(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.]*)[ \t]*=[ \t]*([^\r\n]*)')
_ENV_SECRET = re.compile(r'(?i)pass|pwd|secret|token|api_?key|access_?key|private_?key|auth|credential|'
                         r'salt|signing_?key|encryption_?key|master_?key|_key$|^key$|dsn|conn(?:ection)?_?str')
_ENV_NOT_SECRET = re.compile(r'(?i)public|_(?:id|name|url|uri|path|file|dir|host|port|user|username|type|'
                             r'region|enabled|ttl|expiry|expires|length|algorithm|timeout|version|mode|'
                             r'size|count|limit|email)$')
_EXPORT_HEADER = re.compile(r'(?im)^(?:\ufeff|\xef\xbb\xbf)?(?=[^\n]{0,600}pass)[^\n]{1,600}$')
_EXPORT_PASSWORD_COLS = frozenset({'password', 'login_password', 'pass', 'passwd', 'login password'})
_EXPORT_CONTEXT_COLS = frozenset({'url', 'login_uri', 'website', 'web site', 'username',
                                  'login_username', 'login name', 'user name', 'name', 'title',
                                  'hostname', 'origin', 'origin_url', 'formactionorigin', 'email',
                                  'account', 'user'})

# ─── High-entropy strings ───────────────────────────────────────────────

_ASSIGNMENT = re.compile(r'(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_.-]{1,40})["\']?[ \t]*[:=][ \t]*'
                         r'["\']?([A-Za-z0-9+/=_-]{20,128})(?![A-Za-z0-9+/=_-])')
_ENTROPY_SKIP_KEYS = re.compile(r'(?i)hash|sha\d*|md5|checksum|integrity|digest|etag|uuid|guid|commit|'
                                r'revision|^rev$|fingerprint|thumbprint|resolved|version|^id$|_id$|'
                                r'(?<=[a-z])Id$|nonce|^iv$|signature|^h\d$|^d$|^m$|^path')
_LOCKFILES = frozenset({'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml',
                        'cargo.lock', 'poetry.lock', 'pipfile.lock', 'gemfile.lock', 'composer.lock',
                        'go.sum', 'packages.lock.json', 'flake.lock', 'mix.lock', 'pubspec.lock',
                        'podfile.lock', 'uv.lock', 'bun.lockb', 'gradle.lockfile'})
_NO_ENTROPY_EXTS = ('.min.js', '.min.css', '.map', '.lock', '.sum', '.svg', '.pem', '.crt',
                    '.cer', '.exe', '.dll', '.so', '.dylib', '.bin', '.dat', '.class', '.pyc',
                    '.o', '.obj', '.lib', '.a', '.wasm', '.pdf')

_TRIGGERS.update({
    _PEM_KEY: ('PRIVATE KEY',), _PUTTY_KEY: ('PuTTY-User-Key-File',), _CPASSWORD: ('cpassword',),
    _XML_PASSWORD: ('pass', 'pwd'), _WIFI_KEY: ('keymaterial',), _NPMRC: ('_auth', '_password'),
    _EXPORT_HEADER: ('pass',), _UNC: ('\\\\',),
    _HOST_SETTING: ('host', 'server', 'source', 'computer', 'machine', 'controller'),
})


def _luhn(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def mask(kind, value):
    """The display form of a secret: enough to recognise it, not to use it."""
    if kind == 'private_key':
        return '(private key block)'
    if kind == 'gcp_service_account':
        return '(service-account private key)'
    if kind == 'keepass_db':
        return '(KeePass database file)'
    if kind == 'card_number':
        digits = re.sub(r'\D', '', value)
        return '**** **** **** ' + digits[-4:]
    if kind == 'ssn':
        return '***-**-' + value[-4:]
    show = 4 if len(value) >= 16 else 2 if len(value) >= 8 else 0
    return value[:show] + '*' * min(max(len(value) - show, 4), 12)


def ip_scope(addr):
    if addr.is_loopback:
        return 'loopback'
    if addr.is_link_local:
        return 'link-local'
    if addr.is_multicast:
        return 'multicast'
    if addr.is_unspecified or addr.is_reserved:
        return 'reserved'
    if addr.is_private:
        return 'private'
    return 'public'


def domain_scope(name, internal_suffixes=()):
    """
    'internal' for names that only mean something on this network (one label,
    .local, .lan, .corp, home.arpa, or a configured internal domain),
    'reserved' for names that resolve nowhere (.test, .invalid, .arpa), else
    'public'. Only public names are ever looked up in a threat feed.
    """
    n = (name or '').lower().rstrip('.')
    if '.' not in n:
        return 'internal'
    for suffix in tuple(internal_suffixes) + _INTERNAL_SUFFIXES:
        suffix = str(suffix).lower().strip('.')
        if suffix and (n == suffix or n.endswith('.' + suffix)):
            return 'internal'
    for suffix in _RESERVED_SUFFIXES:
        if n == suffix or n.endswith('.' + suffix):
            return 'reserved'
    return 'public'


def _is_domain(tld):
    t = tld.lower()
    return t in _GENERIC_TLDS or (len(t) == 2 and t not in _NOT_CCTLDS)


def entropy(s):
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


_WORDISH = re.compile(r'[A-Z]?[a-z]{3,}|[A-Z]{4,}')


def _wordiness(s):
    """Share of characters inside word-like runs (Name, user, HTTP): 0.7 and
    up for camelCase identifiers, under 0.6 for nearly all random base64."""
    return sum(m.end() - m.start() for m in _WORDISH.finditer(s)) / len(s)


def _ascending_run(s, limit=5):
    run = 0
    for a, b in zip(s, s[1:]):
        run = run + 1 if ord(b) - ord(a) == 1 else 0
        if run >= limit:
            return True
    return False


def looks_random(value):
    """
    Whether a string reads like a generated secret rather than a word, a
    path, a hash or an identifier. Hex strings (hashes, GUIDs) never count;
    mixed-case strings need the entropy random base64 of that length has.
    """
    n = len(value)
    if n < 20 or re.fullmatch(r'[0-9a-fA-F-]+', value) or _ascending_run(value):
        return False
    if re.match(r'(?i)sha\d+-', value) or re.search(r'(?i)[a-z]{4,}[_-][a-z]{4,}', value):
        return False
    upper = any(c.isupper() for c in value)
    lower = any(c.islower() for c in value)
    digit = any(c.isdigit() for c in value)
    h = entropy(value)
    if upper and lower and digit:
        threshold = min(4.8, 3.7 + 0.8 * (math.log2(n) - math.log2(20)))
        return h >= threshold and _wordiness(value) < 0.6
    if digit and (upper or lower) and n >= 32:
        return h >= 3.95 + 0.55 * (math.log2(n) - 5)
    return False


def _looks_binary(text):
    sample = text[:8192]
    if not sample:
        return False
    odd = sum(1 for c in sample if (c < ' ' and c not in '\t\r\n') or '\x7f' <= c <= '\x9f')
    return odd > len(sample) * 0.05


def _secret_shaped(s):
    return any(p.search(s) for _, _, _, p, _ in _SPECIFIC)


def _looks_secret(s):
    if len(s) < 16:
        return False
    if _secret_shaped(s):
        return True
    return '.' not in s and looks_random(s)


# ─── URLs ───────────────────────────────────────────────────────────────

_URL_PARTS = re.compile(r'^([A-Za-z][A-Za-z0-9+.-]*://)([^/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$', re.S)
_SAFE_PARAMS = frozenset('''
q query search lang locale hl gl page per_page pagesize limit offset sort order format fmt type
view mode tab theme region country utm_source utm_medium utm_campaign utm_term utm_content ref
source v ver version output dl raw download action
'''.split())
_SECRET_SEGMENTS = frozenset('''
token tokens key keys apikey api_key api-key secret secrets password passwd pass pwd auth session
sessions sid jwt bearer credential credentials signature sig access_token
'''.split())
_TELEGRAM_SEGMENT = re.compile(r'bot(\d{6,12}:[A-Za-z0-9_-]{30,})')
_ISO_DATE = re.compile(r'\d{4}-\d{2}-\d{2}(?:T\d{2}(?::|%3A)\d{2}(?:(?::|%3A)\d{2})?Z?)?', re.I)


def _hidden(value):
    return mask('url', value)


def _mask_value(key, value):
    if not value or set(value) <= {'*'}:
        return value
    if (value.isdigit() and len(value) < 10) or _ISO_DATE.fullmatch(value):
        return value          # page numbers, ids, dates
    if key.lower() in _SAFE_PARAMS and len(value) < 40 and not _looks_secret(value):
        return value
    return _hidden(value)


def _mask_params(qs):
    out = []
    for part in re.split(r'([&;])', qs):
        if part in ('&', ';', ''):
            out.append(part)
        elif '=' in part:
            key, value = part.split('=', 1)
            out.append(key + '=' + _mask_value(key, value))
        else:
            out.append(_hidden(part) if _looks_secret(part) or len(part) >= 16 else part)
    return ''.join(out)


def _webhook_cut(host, segments):
    """Index of the first path segment of a webhook URL that is its secret."""
    if host == 'hooks.slack.com':
        return 2
    if host.endswith('discord.com') or host.endswith('discordapp.com'):
        if 'webhooks' in segments:
            return segments.index('webhooks') + 2
    if host.endswith('.webhook.office.com') or host in ('outlook.office.com', 'outlook.office365.com'):
        return 2
    if host == 'hooks.zapier.com' and 'catch' in segments:
        return segments.index('catch') + 2
    return None


def _mask_path(host, path):
    if not path or path == '/':
        return path
    segments = path.split('/')
    cut = _webhook_cut(host, segments)
    out, after_keyword = [], False
    for i, seg in enumerate(segments):
        if not seg:
            out.append(seg)
            continue
        if (cut is not None and i >= cut) or after_keyword or _looks_secret(seg):
            out.append(_hidden(seg))
            after_keyword = False
            continue
        bot = _TELEGRAM_SEGMENT.fullmatch(seg)
        if bot:
            out.append('bot' + _hidden(bot.group(1)))
            continue
        after_keyword = seg.lower() in _SECRET_SEGMENTS
        out.append(seg)
    return '/'.join(out)


def mask_url(url):
    """
    A URL with whatever could be a credential hidden: the password (and a
    token-shaped user name) before the @, query and fragment values other
    than plain ones such as page=2, path segments that look like tokens or
    follow /token/ or /key/, and the secret part of webhook paths.
    """
    m = _URL_PARTS.match(url)
    if not m:
        return url
    scheme, authority, path, query, fragment = m.groups('')
    hostport = authority
    if '@' in authority:
        userinfo, hostport = authority.rsplit('@', 1)
        if ':' in userinfo:
            user = userinfo.split(':', 1)[0]
            userinfo = (_hidden(user) if _looks_secret(user) else user) + ':****'
        elif _looks_secret(userinfo) or len(userinfo) >= 20:
            userinfo = _hidden(userinfo)
        authority = userinfo + '@' + hostport
    host = hostport.rsplit(':', 1)[0].lower() if not hostport.startswith('[') else hostport.lower()
    path = _mask_path(host, path)
    if query:
        query = '?' + _mask_params(query[1:])
    if fragment:
        body = fragment[1:]
        if '=' in body:
            fragment = '#' + _mask_params(body)
        elif _looks_secret(body):
            fragment = '#' + _hidden(body)
    return scheme + authority + path + query + fragment


def _url_host(url):
    m = _URL_PARTS.match(url)
    if not m:
        return ''
    hostport = m.group(2).rsplit('@', 1)[-1]
    if hostport.startswith('['):
        return ''
    return hostport.rsplit(':', 1)[0].lower()


# ─── Options ────────────────────────────────────────────────────────────

class ScanOptions:
    """What a scan looks for; from_config() reads the config's file_scan section."""

    def __init__(self, entropy=True, max_secrets_per_kind=MAX_SECRETS_PER_KIND,
                 internal_domains=(), yara_rules_dir='', evtx_max_records=MAX_EVTX_RECORDS,
                 ignore=None):
        self.entropy = entropy
        self.max_secrets_per_kind = max_secrets_per_kind
        self.internal_domains = tuple(internal_domains or ())
        self.yara_rules_dir = yara_rules_dir or ''
        self.evtx_max_records = evtx_max_records
        self.ignore = ignore

    @classmethod
    def from_config(cls, config, ignore=None):
        if config is None:
            return cls(ignore=ignore)
        return cls(
            entropy=bool(config.get('file_scan', 'entropy_strings', default=True)),
            max_secrets_per_kind=int(config.get('file_scan', 'max_secrets_per_kind',
                                                default=MAX_SECRETS_PER_KIND)),
            internal_domains=config.get('file_scan', 'internal_domains', default=[]) or (),
            yara_rules_dir=config.get('file_scan', 'yara_rules_dir', default='') or '',
            evtx_max_records=int(config.get('file_scan', 'evtx_max_records',
                                            default=MAX_EVTX_RECORDS)),
            ignore=ignore)


# ─── Text extraction ────────────────────────────────────────────────────

def extract_text(name, data):
    """
    Turn a file's bytes into text worth searching.

    Office documents are zips of XML: their parts are read in memory and the
    tags dropped, and macro source is recovered from vbaProject.bin. PDF
    streams are inflated where they will inflate, within one budget for the
    whole file. Event logs (.evtx) become one line per record when
    python-evtx is installed. Anything else is read as Latin-1, which maps
    every byte, so the ASCII-shaped things searched for are found in
    binaries too.
    """
    return _extract(name, data, ScanOptions(), [])[0]


def _extract(name, data, options, notes):
    """(text, offset of recovered macro source in the text or None)."""
    lower = name.lower()
    if data[:8] == _EVTX_MAGIC:
        text = _evtx_text(data, options.evtx_max_records, notes)
        if text is not None:
            return text, None
    if lower.endswith(OFFICE_EXTS):
        parts, budget, vba = [], MAX_TEXT_BYTES, []
        try:
            with zipfile.ZipFile(BytesIO(data)) as zf:
                for info in zf.infolist():
                    if budget <= 0:
                        break
                    part = info.filename.lower()
                    if part.endswith('vbaproject.bin'):
                        with zf.open(info) as f:
                            blob = f.read(min(budget, MAX_MACRO_BYTES))
                        budget -= len(blob)
                        vba.append(script_rules.vba_source(blob, MAX_MACRO_BYTES))
                        continue
                    if not part.endswith(('.xml', '.rels')):
                        continue
                    with zf.open(info) as f:
                        chunk = f.read(budget)
                    budget -= len(chunk)
                    parts.append(re.sub(r'<[^>]{0,2000}>', ' ', chunk.decode('utf-8', 'replace')))
            text = '\n'.join(parts)
            if vba:
                return _append(text, '\n'.join(vba))
            return text, None
        except (zipfile.BadZipFile, OSError, RuntimeError):
            pass
    text = data.decode('latin-1')
    macro_at = None
    if lower.endswith('.pdf') or data[:5] == b'%PDF-':
        text += '\n' + '\n'.join(_pdf_streams(data, notes))
    if data[:8] == _OLE_MAGIC:
        # an old .doc/.xls: its strings are already in the text; only the
        # compressed macro source needs recovering
        vba = script_rules.vba_source(data, MAX_MACRO_BYTES, strings=False)
        text, macro_at = _append(text, vba)
    if '\x00' in text[:4096] and text.count('\x00') > len(text) // 4:
        # UTF-16 text (Windows exports, registry dumps) reads as letter-NUL pairs
        text += '\n' + text.replace('\x00', '')
    return text, macro_at


def _append(text, extra):
    if not extra:
        return text, None
    return text + '\n' + extra, len(text) + 1


def _pdf_streams(data, notes):
    # One budget for every stream together: a PDF of a thousand small streams
    # that each inflate to the per-file limit would otherwise cost a thousand
    # times that.
    inflated, budget = [], MAX_PDF_BYTES
    for m in re.finditer(rb'stream\r?\n(.*?)endstream', data, re.S):
        if budget <= 0:
            notes.append(f'PDF streams past the first {MAX_PDF_BYTES // 1024 ** 2} MB '
                         'inflated were not read')
            break
        try:
            out = zlib.decompressobj().decompress(m.group(1), budget)
        except zlib.error:
            continue
        budget -= len(out)
        inflated.append(out.decode('latin-1'))
    return inflated


_EVT_DATA = re.compile(r'<Data Name="([^"<>]{1,80})"\s*>([^<]*)</Data>')
_EVT_NAMED = re.compile(r'<(EventID|Computer|Channel)\b[^>]*>([^<]*)<')
_TAGS = re.compile(r'<[^>]{0,2000}>')


def _evtx_text(data, max_records, notes):
    """One line per event record, its fields written name: value;"""
    try:
        from Evtx.Evtx import FileHeader
    except ImportError:
        notes.append('event log read as raw text; install python-evtx to read its records')
        return None
    try:
        header = FileHeader(data, 0)
        chunks = header.chunks()
    except Exception as e:
        notes.append(f'event log header unreadable ({e}); read as raw text')
        return None
    lines = []
    try:
        for chunk in chunks:
            try:
                for record in chunk.records():
                    try:
                        lines.append(_flatten_event(record.xml()))
                    except Exception:
                        continue
                    if len(lines) >= max_records:
                        notes.append(f'only the first {max_records:,} event records searched')
                        return '\n'.join(lines)
            except Exception:
                notes.append('an event log chunk was unreadable and skipped')
    except Exception:
        notes.append('event log partly unreadable')
    return '\n'.join(lines)


def _flatten_event(xml):
    s = _EVT_DATA.sub(lambda m: f' {m.group(1)}: {m.group(2)};', xml)
    s = _EVT_NAMED.sub(lambda m: f' {m.group(1)}: {m.group(2)}; <', s)
    s = html.unescape(_TAGS.sub(' ', s))
    return ' '.join(s.split())


# ─── Decoding helpers for Windows leaks ─────────────────────────────────

def _b64_text(value, encoding):
    try:
        raw = base64.b64decode(value + '=' * (-len(value) % 4), validate=True)
        text = raw.decode(encoding)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return text if text and all(c.isprintable() for c in text) else None


def _unattend_password(value, tag):
    # Windows answer files store base64 of the UTF-16LE password with the
    # element name appended ("Password" or "AdministratorPassword").
    text = _b64_text(value, 'utf-16-le')
    if text is None:
        return value
    for suffix in ('AdministratorPassword', 'Password') if tag == 'administratorpassword' \
            else ('Password',):
        if text.endswith(suffix):
            return text[:-len(suffix)]
    return text


def _gpp_decrypt(value):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        raw = base64.b64decode(value + '=' * (-len(value) % 4))
        if not raw or len(raw) % 16:
            return None
        decryptor = Cipher(algorithms.AES(_GPP_KEY), modes.CBC(b'\x00' * 16)).decryptor()
        out = decryptor.update(raw) + decryptor.finalize()
        pad = out[-1]
        if 1 <= pad <= 16 and out.endswith(bytes([pad]) * pad):
            out = out[:-pad]
        return out.decode('utf-16-le')
    except Exception:
        return None


def _env_file(name):
    base = os.path.basename(name.replace('\\', '/')).lower()
    return base in ('.env', '.envrc') or base.startswith('.env.') or base.endswith('.env')


def _key_words(key):
    return [w.lower() for w in re.findall(r'[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])', key)]


# ─── The scan ───────────────────────────────────────────────────────────

def scan_bytes(name, data, options=None):
    """
    Search one file's contents.

    Returns {'indicators': {kind: {value: info}}, 'secrets': [...],
    'findings': [...], 'secret_counts': {kind: n}, 'finding_counts': {kind: n},
    'ignored': n, 'notes': [...], 'truncated': bool}. Each secret and finding
    is {kind, label, severity, value (masked), line} plus, for kinds that may
    be ignored by value, an 'ignore_key' when options carries an ignore list.
    Only the first max_secrets_per_kind of each kind are listed; the counts
    include the rest.
    """
    options = options or ScanOptions()
    truncated = len(data) > MAX_TEXT_BYTES
    data = data[:MAX_TEXT_BYTES]
    result = {'indicators': {k: {} for k in INDICATOR_KINDS}, 'secrets': [], 'findings': [],
              'secret_counts': {}, 'finding_counts': {}, 'ignored': 0, 'notes': [],
              'truncated': truncated}

    if data[:8] in _KEEPASS_MAGIC or name.lower().endswith(('.kdbx', '.kdb')):
        # encrypted: nothing inside to read, but the file is itself the finding
        _TextScan(name, '', options, result).add_secret(
            'keepass_db', 'KeePass password database', 'MEDIUM', 0, 0, name)
        return result

    text, macro_at = _extract(name, data, options, result['notes'])
    scan = _TextScan(name, text, options, result)
    scan.run()
    if macro_at is not None:
        for kind, label, severity, shown in script_rules.macro_findings(text[macro_at:]):
            # ignoring a macro finding means this file's macros, not every macro
            scan.add_finding(kind, label, severity, macro_at, shown, raw=f'{kind}:{name}')
    rules = script_rules.load_yara(options.yara_rules_dir) if options.yara_rules_dir else None
    if rules is not None:
        for rule, severity, offset, description in script_rules.yara_matches(rules, data):
            at = offset if isinstance(offset, int) and 0 <= offset < len(text) else 0
            scan.add_finding('yara', f'YARA rule {rule}' + (f': {description}' if description else ''),
                             severity, at, rule, raw=rule)
    return result


class _Spans:
    """
    The text already claimed by a secret, as disjoint [start, end) spans.

    Each pattern walks the text from the start, so its claims arrive in
    order. They go on a pending list (an append) and are merged into the
    committed list once per pattern, rather than inserted into the middle
    of one big list per claim, which is quadratic in a file of many secrets.
    """

    def __init__(self):
        self.starts, self.ends = [], []
        self._new_starts, self._new_ends = [], []

    @staticmethod
    def _hit(starts, ends, start, end):
        i = bisect_left(starts, end)
        return i > 0 and ends[i - 1] > start

    def overlaps(self, start, end):
        return (self._hit(self.starts, self.ends, start, end)
                or self._hit(self._new_starts, self._new_ends, start, end))

    def claim(self, start, end):
        end = max(end, start + 1)
        if self.overlaps(start, end):
            return False
        if self._new_starts and start < self._new_starts[-1]:
            i = bisect_right(self._new_starts, start)
            self._new_starts.insert(i, start)
            self._new_ends.insert(i, end)
        else:
            self._new_starts.append(start)
            self._new_ends.append(end)
        return True

    def commit(self):
        if not self._new_starts:
            return
        merged = list(heapq.merge(zip(self.starts, self.ends),
                                  zip(self._new_starts, self._new_ends)))
        self.starts = [a for a, _ in merged]
        self.ends = [b for _, b in merged]
        self._new_starts, self._new_ends = [], []

    def within(self, start, end):
        self.commit()
        i = bisect_left(self.starts, end)
        out = []
        while i > 0 and self.ends[i - 1] > start:
            i -= 1
            out.append((max(self.starts[i], start), min(self.ends[i], end)))
        return sorted(out)


class _TextScan:
    """One pass over one text: the file, or a command decoded out of it."""

    def __init__(self, name, text, options, result, depth=0, line=None):
        self.name = name
        self.text = text
        self.options = options
        self.result = result
        self.depth = depth
        self.fixed_line = line        # decoded text reports the line it was decoded from
        self._newlines = None
        self._spans = _Spans()
        self._ignored_values = set()
        self._lowered = None

    # ── bookkeeping ──

    @property
    def lowered(self):
        if self._lowered is None:
            self._lowered = self.text.lower()
        return self._lowered

    def _find(self, pattern):
        """pattern.finditer over the text, unless the text lacks every literal
        the pattern needs (_TRIGGERS)."""
        literals = _TRIGGERS.get(pattern)
        if literals:
            haystack = self.lowered if pattern.flags & re.IGNORECASE else self.text
            if not any(lit in haystack for lit in literals):
                return ()
        return pattern.finditer(self.text)

    def line_of(self, pos):
        if self.fixed_line is not None:
            return self.fixed_line
        if self._newlines is None:
            self._newlines = [n.start() for n in re.finditer('\n', self.text)]
        return bisect_left(self._newlines, pos) + 1

    def _claim(self, start, end):
        return self._spans.claim(start, end)

    def overlaps(self, start, end):
        return self._spans.overlaps(start, end)

    def _spans_within(self, start, end):
        return self._spans.within(start, end)

    def _record(self, bucket, kind, label, severity, start, raw, shown):
        line = self.line_of(start)
        ignore = self.options.ignore
        key = None
        if ignore is not None:
            if ignore.has_locations and ignore.ignores_location(kind, self.name, line):
                self.result['ignored'] += 1
                return
            if kind not in LOCATION_ONLY:
                key = ignore.digest(kind, raw)
                if ignore.ignores_digest(kind, key):
                    self.result['ignored'] += 1
                    return
        counts = self.result[bucket[:-1] + '_counts']
        counts[kind] = counts.get(kind, 0) + 1
        if counts[kind] > self.options.max_secrets_per_kind:
            return
        entry = {'kind': kind, 'label': label, 'severity': severity, 'value': shown, 'line': line}
        if key is not None:
            entry['ignore_key'] = key
        self.result[bucket].append(entry)

    def add_secret(self, kind, label, severity, start, end, raw, shown=None):
        """Record a secret unless an earlier one already covers this text."""
        if not self._claim(start, end):
            return False
        self._record('secrets', kind, label, severity, start, raw,
                     shown if shown is not None else mask(kind, raw))
        return True

    def add_finding(self, kind, label, severity, start, shown, raw=None):
        self._record('findings', kind, label, severity, start,
                     raw if raw is not None else kind, shown)

    # ── passes ──

    def run(self):
        if not self.text:
            return
        steps = [self._structured_before, lambda: self._table(_SPECIFIC), self._structured_after,
                 lambda: self._table(_GENERIC), lambda: self._table(_PII)]
        if self.options.entropy:
            steps.append(self._entropy)
        for step in steps:
            step()
            self._spans.commit()
        self._scripts()
        self._indicators()

    def _table(self, table):
        for kind, label, severity, pattern, groups in table:
            self._spans.commit()
            for m in self._find(pattern):
                g = next((g for g in (groups if isinstance(groups, tuple) else (groups,))
                          if m.group(g) is not None), None)
                if g is None:
                    continue
                value = m.group(g)
                if kind == 'password' and (_PLACEHOLDERS.match(value) or self._noise_key(m)):
                    continue
                if kind == 'card_number':
                    digits = re.sub(r'\D', '', value)
                    if not 13 <= len(digits) <= 19 or not _luhn(digits):
                        continue
                self.add_secret(kind, label, severity, m.start(g), m.end(g), value)

    @staticmethod
    def _noise_key(m):
        if m.re not in (_PASSWORD_SETTING, _PASSWORD_CAMEL):
            return False
        words = _key_words(m.group(1))
        value = next(v for v in m.groups()[1:] if v is not None).lower()
        # self.token = token, api_key=api_key: code passing a variable along
        key = m.group(1).lower()
        if key.endswith(value) and (len(key) == len(value) or key[-len(value) - 1] in '._-'):
            return True
        if any(w in _NOISE_WORDS for w in words[:-1]):
            return True
        # in code, a camelCase key's unquoted value is a variable or a class
        return m.re is _PASSWORD_CAMEL and m.group(4) is not None and \
            re.fullmatch(r'[A-Za-z_]+', m.group(4)) is not None

    def _structured_before(self):
        text = self.text
        if _GCP_MARKER.search(text):
            for m in _GCP_KEY.finditer(text):
                self.add_secret('gcp_service_account', 'GCP service-account key', 'CRITICAL',
                                m.start(1), m.end(1), m.group(1))
        for m in self._find(_PEM_KEY):
            self.add_secret('private_key', 'Private key', 'CRITICAL', m.start(), m.end(), m.group(0))
        for m in self._find(_PUTTY_KEY):
            self.add_secret('private_key', 'Private key (PuTTY)', 'CRITICAL', m.start(), m.end(),
                            m.group(0))
        for m in self._find(_CPASSWORD):
            # decrypted and masked in one step: the clear value is never kept
            clear = _gpp_decrypt(m.group(1))
            raw = clear if clear else m.group(1)
            self.add_secret('gpp_cpassword', 'Group Policy Preferences password (cpassword)',
                            'CRITICAL', m.start(1), m.end(1), raw, mask('gpp_cpassword', raw))
        self._xml_passwords()
        for m in self._find(_WIFI_KEY):
            protected = _WIFI_PROTECTED.search(text, max(0, m.start() - 400), m.start())
            if protected and protected.group(1).lower() == 'true':
                self.add_secret('wifi_key_protected', 'Wi-Fi key (encrypted to this PC)', 'LOW',
                                m.start(1), m.end(1), m.group(1), '(encrypted key)')
            else:
                self.add_secret('wifi_key', 'Wi-Fi password (exported profile)', 'HIGH',
                                m.start(1), m.end(1), m.group(1))
        self._spans.commit()
        self._password_exports()

    def _structured_after(self):
        text = self.text
        if _DOCKER_AUTHS.search(text):
            for m in _DOCKER_AUTH.finditer(text):
                self.add_secret('docker_auth', 'Docker registry credentials', 'HIGH',
                                m.start(1), m.end(1), m.group(1))
        for m in self._find(_NPMRC):
            if not _PLACEHOLDERS.match(m.group(1)):
                self.add_secret('npm_auth', 'npm registry credentials (.npmrc)', 'HIGH',
                                m.start(1), m.end(1), m.group(1))
        if _env_file(self.name):
            self._env_values()

    def _xml_passwords(self):
        text = self.text
        unattend = bool(_UNATTEND_MARK.search(text[:65536])) or os.path.basename(
            self.name.replace('\\', '/')).lower() in ('unattend.xml', 'autounattend.xml', 'sysprep.xml')
        for m in self._find(_XML_PASSWORD):
            tag = m.group(1).split(':')[-1].lower()
            inner, base = m.group(3), m.start(3)
            v = _XML_VALUE.search(inner)
            if v:
                raw, start = v.group(1), base + v.start(1)
            elif '<' not in inner:
                raw, start = inner, base
            else:
                continue
            stripped = raw.strip()
            if not stripped or 'SENSITIVE*DATA*DELETED' in stripped.upper() or _PLACEHOLDERS.match(stripped):
                continue
            start += len(raw) - len(raw.lstrip())
            end = start + len(stripped)
            plain = _XML_PLAIN.search(inner)
            if unattend and not (plain and plain.group(1).lower() == 'true'):
                clear = _unattend_password(stripped, tag)
                self.add_secret('unattend_password', 'Password in a Windows answer file (unattend)',
                                'CRITICAL', start, end, clear, mask('unattend_password', clear))
            else:
                clear = stripped
                if 'base64' in (m.group(2) or '').lower():
                    clear = _b64_text(stripped, 'utf-8') or stripped
                self.add_secret('password', 'Password or secret in a setting', 'HIGH', start, end,
                                clear, mask('password', clear))

    def _password_exports(self):
        """Browser and password-manager CSV exports: every row's password."""
        for n, header in enumerate(self._find(_EXPORT_HEADER)):
            if n >= 3:
                break
            line = header.group(0).lstrip('\ufeff').replace('\xef\xbb\xbf', '', 1)
            delimiter = '\t' if line.count('\t') > line.count(',') else ','
            try:
                cols = [c.strip().lower() for c in next(csv.reader([line], delimiter=delimiter))]
            except (csv.Error, StopIteration):
                continue
            wanted = [i for i, c in enumerate(cols) if c in _EXPORT_PASSWORD_COLS]
            if not wanted or not any(c in _EXPORT_CONTEXT_COLS for c in cols):
                continue
            self._export_rows(header.end() + 1, delimiter, wanted)

    def _export_rows(self, pos, delimiter, wanted):
        text = self.text
        starts = []

        def lines():
            p = pos
            while p < len(text):
                nl = text.find('\n', p)
                end = len(text) if nl < 0 else nl + 1
                starts.append((p, end))
                yield text[p:end]
                p = end

        reader = csv.reader(lines(), delimiter=delimiter)
        while True:
            before = len(starts)
            try:
                row = next(reader)
            except StopIteration:
                return
            except csv.Error:
                continue
            if not row or len(starts) == before:
                continue
            first, last = starts[before][0], starts[-1][1]
            record = text[first:last]
            for i in wanted:
                if i >= len(row) or not row[i] or _PLACEHOLDERS.match(row[i]):
                    continue
                value = row[i]
                spans = []
                for needle in {value, value.replace('"', '""')}:
                    at = record.find(needle)
                    while at >= 0:
                        spans.append((first + at, first + at + len(needle)))
                        at = record.find(needle, at + 1)
                if not spans:
                    spans = [(first, last)]   # cannot place it: keep the whole row out of indicators
                spans.sort()
                self.add_secret('export_password', 'Saved password (browser or password-manager export)',
                                'CRITICAL', spans[0][0], spans[0][1], value)
                for a, b in spans[1:]:
                    self._claim(a, b)

    def _env_values(self):
        for m in _ENV_LINE.finditer(self.text):
            key, value = m.group(1), m.group(2)
            if not _ENV_SECRET.search(key) or _ENV_NOT_SECRET.search(key):
                continue
            start = m.start(2)
            if value[:1] in ('"', "'"):
                close = value.find(value[0], 1)
                if close < 0:
                    continue
                value, start = value[1:close], start + 1
            else:
                value = re.split(r'\s+#', value, maxsplit=1)[0].rstrip()
            if len(value) < 4 or _PLACEHOLDERS.match(value):
                continue
            self.add_secret('env_secret', 'Secret in a .env file', 'HIGH', start, start + len(value), value)

    def _entropy(self):
        text, name = self.text, self.name
        base = os.path.basename(name.replace('\\', '/')).lower()
        if base in _LOCKFILES or base.endswith(_NO_ENTROPY_EXTS) or _looks_binary(text):
            return
        for m in _ASSIGNMENT.finditer(text):
            key, value = m.group(1), m.group(2)
            if _ENTROPY_SKIP_KEYS.search(key) or not looks_random(value):
                continue
            if any(w in _NOISE_WORDS for w in _key_words(key)):
                continue          # nextPageToken, NEXT_PUBLIC_SITE_KEY: random, but not secret
            line_start = text.rfind('\n', 0, m.start()) + 1
            line_end = text.find('\n', m.end())
            if (line_end if line_end >= 0 else len(text)) - line_start > 2000:
                continue          # minified code: long lines of random-looking names
            self.add_secret('high_entropy', 'High-entropy string (possible secret)', 'MEDIUM',
                            m.start(2), m.end(2), value)

    def _scripts(self):
        for start, end, kind, label, severity, shown in script_rules.find(self.text, self.lowered):
            self.add_finding(kind, label, severity, start, shown, raw=self.text[start:end])
        if self.depth >= MAX_DECODE_DEPTH:
            return
        for start, end, decoded in script_rules.encoded_powershell(self.text):
            line = self.line_of(start)
            self.add_finding('ps_encoded', 'Encoded PowerShell command', 'HIGH', start,
                             f'{len(decoded):,}-character script, decoded and scanned', raw=decoded)
            _TextScan(self.name, decoded, self.options, self.result,
                      depth=self.depth + 1, line=line).run()

    # ── indicators ──

    def _indicators(self):
        text = self.text
        indicators = self.result['indicators']
        ignore = self.options.ignore
        check_ignore = ignore is not None and ignore.has_values

        def add(kind, value, match=None, **info):
            if match is not None and self.overlaps(match.start(), match.end()):
                return
            bucket = indicators[kind]
            if value in bucket:
                bucket[value]['count'] += 1
            elif len(bucket) < MAX_PER_KIND:
                if check_ignore:
                    if (kind, value) in self._ignored_values:
                        return
                    if ignore.ignores_value(kind, value):
                        self._ignored_values.add((kind, value))
                        self.result['ignored'] += 1
                        return
                bucket[value] = dict(info, count=1)

        def add_host(name):
            name = name.lower()
            if name not in _NOT_HOSTS and not name.isdigit() and not _PLACEHOLDERS.match(name):
                add('host', name, scope='internal')

        internal = self.options.internal_domains
        for m in _IPV4.finditer(text):
            add('ipv4', m.group(0), m, scope=ip_scope(ipaddress.ip_address(m.group(0))))
        for m in _IPV6.finditer(text):
            candidate = m.group(0)
            if sum(1 for g in candidate.split(':') if g) < 2:
                continue   # 'd::' out of std::vector is valid IPv6 and never an address
            try:
                addr = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip_scope(addr) != 'reserved':   # a::b is C++, not an address
                add('ipv6', addr.compressed, m, scope=ip_scope(addr))
        for m in _MAC.finditer(text):
            add('mac', m.group(0).lower().replace('-', ':'), m)
        for m in _URL.finditer(text):
            url = self._url_text(m)
            add('url', mask_url(url))
            host = _url_host(url)
            if host and '.' not in host and not host.isdigit() and host not in ('localhost',):
                add_host(host)
        for m in _EMAIL.finditer(text):
            # icon@2x.png and obj@x.prototype are not addresses, nor is the
            # user part of https://user@host
            if text[max(0, m.start() - 3):m.start()] == '://':
                continue
            if _is_domain(m.group(1).rsplit('.', 1)[-1]):
                add('email', m.group(0).lower(), m)
        for m in _DOMAIN.finditer(text):
            # logger.info( and self.site = are code, not domains
            name, tld = m.group(1).lower(), m.group(2)
            if not _is_domain(tld) or text[m.end():m.end() + 3].lstrip()[:1] in ('(', '=', '['):
                continue
            labels = name.split('.')
            if len(labels) == 2 and labels[0] in _CODE_OBJECTS:
                continue
            add('domain', name, m, scope=domain_scope(name, internal))
        for m in self._find(_UNC):
            host = (m.group(1) or m.group(3)).lower()
            share = m.group(2) or m.group(4)
            if len(host) < 2 or self.overlaps(m.start(), m.end()):
                continue
            add('unc', f'\\\\{host}\\{share.rstrip(".")}', m)
            if '.' not in host:
                add_host(host)
        for m in self._find(_HOST_SETTING):
            key, sep, value = m.group(1).lower(), m.group(2), m.group(3)
            if sep == ':' and key.lstrip('_.-').startswith('server'):
                continue      # "Server: nginx" is an HTTP header, not a host
            if not self.overlaps(m.start(3), m.end(3)):
                add_host(value)

    def _url_text(self, m):
        """The URL as matched, with any secret already found inside it masked."""
        start, end = m.span()
        spans = self._spans_within(start, end)
        if not spans:
            return m.group(0).rstrip('.,;:!?\'"')
        out, pos = [], start
        for a, b in spans:
            out.append(self.text[pos:a])
            out.append('****')
            pos = b
        out.append(self.text[pos:end])
        return ''.join(out).rstrip('.,;:!?\'"')
