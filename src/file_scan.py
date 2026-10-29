"""
NetSentinel - File Content Scan
Pulls network indicators (IP addresses, domains, URLs, email and MAC
addresses) and anything that looks like a leaked secret (keys, tokens,
passwords, card numbers) out of ordinary files: logs, configs, exports,
documents, and the readable strings of binaries.

Secrets are masked the moment they are found. The raw value never leaves
scan_bytes(): not in the findings, the logs, or an export.
"""

import ipaddress
import re
from bisect import bisect_left
import zipfile
import zlib
from io import BytesIO

MAX_TEXT_BYTES = 64 * 1024 * 1024
MAX_PER_KIND = 5000          # distinct indicators of one kind kept per file

OFFICE_EXTS = ('.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.odt', '.ods', '.odp')
MEDIA_EXTS = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.webp', '.mp3', '.mp4',
              '.m4a', '.wav', '.avi', '.mov', '.mkv', '.flac', '.ogg', '.woff', '.woff2',
              '.ttf', '.otf')

# Generic TLDs worth recognising, plus every two-letter ccTLD except the ones
# that are far more often a file extension (foo.py, run.sh, notes.md). Generic
# TLDs that are also common attribute names (.name, .page, .host) are left out:
# in code and logs they are almost never domains.
_GENERIC_TLDS = set('''
com net org edu gov mil int info biz mobi asia io co ai app dev cloud online site top
xyz club tech blog local lan internal intranet corp arpa onion
'''.split())
_NOT_CCTLDS = {'py', 'sh', 'md', 'rs', 'pl', 'cs', 'js', 'ts', 'db', 'so', 'pm', 'rb',
               'go', 'ps', 'mk', 'cc', 'hh', 'el', 'ml', 'as', 'am', 'do', 'or'}

_IPV4 = re.compile(r'(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
                   r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])')
_IPV6 = re.compile(r'(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])')
_MAC = re.compile(r'(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}(?:([:-])[0-9A-Fa-f]{2})(?:\1[0-9A-Fa-f]{2}){4}'
                  r'(?![0-9A-Fa-f:-])')
_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]{1,64}@((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})\b')
_URL = re.compile(r'\b(?:https?|ftp|wss?)://[^\s"\'<>()\[\]{}\\]{3,2000}')
_URL_PASSWORD = re.compile(r'(//[^/:@\s]+:)[^@/\s]+@')
_DOMAIN = re.compile(r'(?<![@\w.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'
                     r'([A-Za-z]{2,24}))(?![\w-]|\.\w)')

# (kind, label, severity, pattern, group holding the secret)
_SECRETS = [
    ('private_key', 'Private key', 'CRITICAL',
     re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----'), 0),
    ('aws_access_key', 'AWS access key', 'CRITICAL',
     re.compile(r'\b((?:AKIA|ASIA)[0-9A-Z]{16})\b'), 1),
    ('aws_secret_key', 'AWS secret key', 'CRITICAL',
     re.compile(r'(?i)aws_?secret_?access_?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})'), 1),
    ('github_token', 'GitHub token', 'CRITICAL',
     re.compile(r'\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b'), 1),
    ('slack_token', 'Slack token', 'HIGH', re.compile(r'\b(xox[baprs]-[A-Za-z0-9-]{10,})'), 1),
    ('stripe_key', 'Stripe live key', 'CRITICAL', re.compile(r'\b([sr]k_live_[A-Za-z0-9]{16,})'), 1),
    ('google_api_key', 'Google API key', 'HIGH', re.compile(r'\b(AIza[0-9A-Za-z_-]{35})(?![\w-])'), 1),
    ('api_key', 'API key (sk-)', 'HIGH', re.compile(r'\b(sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,})'), 1),
    ('jwt', 'JSON Web Token', 'HIGH',
     re.compile(r'\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})'), 1),
    ('url_password', 'Password in a URL', 'HIGH',
     re.compile(r'\b[a-z][a-z0-9+.-]{1,15}://[^\s:/@"\']{1,64}:([^\s@/"\']{1,128})@[^\s/"\']+'), 1),
    ('basic_auth', 'HTTP Basic credentials', 'HIGH',
     re.compile(r'(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{8,})'), 1),
    ('password', 'Password or secret in a setting', 'HIGH',
     re.compile(r'(?i)\b(?:pass(?:word|wd|phrase)?|pwd|secret|api[_-]?key|access[_-]?token|'
                r'auth[_-]?token|client[_-]?secret|private[_-]?key)\b["\']?\s*[:=]\s*'
                r'["\']?([^\s"\'<>,;]{4,128})'), 1),
    ('card_number', 'Payment card number', 'CRITICAL',
     re.compile(r'(?<![\d-])([3-6]\d{3}(?:[ -]?\d{2,4}){3,4})(?![\d-])'), 1),
    ('ssn', 'US Social Security number', 'HIGH',
     re.compile(r'(?<![\d-])((?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4})(?![\d-])'), 1),
]

_PLACEHOLDERS = re.compile(r'^(?:\*+|x+|\.+|none|null|nil|true|false|undefined|password|'
                           r'secret|changeme_?later|your[_-]?\w*|<[^>]*>|\$\{?\w+\}?|'
                           r'%\(?\w+\)?s?|\{\{?[^}]*\}?\}|env\[.*|os\.environ.*|getenv.*|'
                           r'\w+\(.*|.*[\[(]|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+|'
                           r'str|string|int|bool|text|varchar.*|optional.*)$', re.I)


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


def _is_domain(tld):
    t = tld.lower()
    return t in _GENERIC_TLDS or (len(t) == 2 and t not in _NOT_CCTLDS)


def extract_text(name, data):
    """
    Turn a file's bytes into text worth searching.

    Office documents are zips of XML: their parts are read in memory and the
    tags dropped. PDF streams are inflated where they will inflate. Anything
    else is read as Latin-1, which maps every byte, so the ASCII-shaped things
    searched for are found in binaries too.
    """
    lower = name.lower()
    if lower.endswith(OFFICE_EXTS):
        parts, budget = [], MAX_TEXT_BYTES
        try:
            with zipfile.ZipFile(BytesIO(data)) as zf:
                for info in zf.infolist():
                    if not info.filename.endswith(('.xml', '.rels')) or budget <= 0:
                        continue
                    with zf.open(info) as f:
                        chunk = f.read(budget)
                    budget -= len(chunk)
                    parts.append(re.sub(r'<[^>]{0,2000}>', ' ', chunk.decode('utf-8', 'replace')))
            return '\n'.join(parts)
        except (zipfile.BadZipFile, OSError, RuntimeError):
            pass
    text = data.decode('latin-1')
    if lower.endswith('.pdf'):
        inflated = []
        for m in re.finditer(rb'stream\r?\n(.*?)endstream', data, re.S):
            try:
                inflated.append(zlib.decompressobj().decompress(m.group(1), MAX_TEXT_BYTES)
                                .decode('latin-1'))
            except zlib.error:
                continue
        text += '\n' + '\n'.join(inflated)
    if '\x00' in text[:4096] and text.count('\x00') > len(text) // 4:
        # UTF-16 text (Windows exports, registry dumps) reads as letter-NUL pairs
        text += '\n' + text.replace('\x00', '')
    return text


def scan_bytes(name, data):
    """
    Search one file's contents.

    Returns {'indicators': {kind: {value: info}}, 'secrets': [...], 'truncated': bool}
    where each secret is {kind, label, severity, value (masked), line}.
    """
    truncated = len(data) > MAX_TEXT_BYTES
    text = extract_text(name, data[:MAX_TEXT_BYTES])
    indicators = {k: {} for k in ('ipv4', 'ipv6', 'domain', 'url', 'email', 'mac')}

    secrets, spans = [], []
    newlines = None
    for kind, label, severity, pattern, group in _SECRETS:
        for m in pattern.finditer(text):
            value = m.group(group)
            if kind == 'password' and _PLACEHOLDERS.match(value):
                continue
            if kind == 'card_number':
                digits = re.sub(r'\D', '', value)
                if not 13 <= len(digits) <= 19 or not _luhn(digits):
                    continue
            if newlines is None:
                newlines = [n.start() for n in re.finditer('\n', text)]
            line = _line_of(newlines, m.start())
            spans.append(m.span(group))
            secrets.append({'kind': kind, 'label': label, 'severity': severity,
                            'value': mask(kind, value), 'line': line})
    spans.sort()
    starts = [a for a, _ in spans]

    def overlaps_secret(m):
        # the email in user:S3cret@db.internal is the password
        n = bisect_left(starts, m.end())
        return any(spans[x][1] > m.start() for x in range(max(0, n - 8), n))

    def add(kind, value, match=None, **info):
        if match is not None and overlaps_secret(match):
            return
        bucket = indicators[kind]
        if value in bucket:
            bucket[value]['count'] += 1
        elif len(bucket) < MAX_PER_KIND:
            bucket[value] = dict(info, count=1)

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
        add('url', _URL_PASSWORD.sub(r'\1****@', m.group(0).rstrip('.,;:!?\'"')))
    for m in _EMAIL.finditer(text):
        # icon@2x.png and obj@x.prototype are not addresses
        if _is_domain(m.group(1).rsplit('.', 1)[-1]):
            add('email', m.group(0).lower(), m)
    for m in _DOMAIN.finditer(text):
        # logger.info( and self.site = are code, not domains
        if _is_domain(m.group(2)) and text[m.end():m.end() + 3].lstrip()[:1] not in ('(', '=', '['):
            add('domain', m.group(1).lower(), m)

    return {'indicators': indicators, 'secrets': secrets, 'truncated': truncated}


def _line_of(newlines, pos):
    return bisect_left(newlines, pos) + 1
