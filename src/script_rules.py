"""
NetSentinel - Script Patterns
What src.file_scan looks for in scripts, command lines, macros and event
logs beyond secrets: PowerShell download cradles and encoded commands,
living-off-the-land binaries used to fetch or run code, Defender tampering,
and auto-run Office macros. Optional user YARA rules run too, when the
yara-python module is installed; none are bundled.

Findings carry a fixed description of what matched, never the matched text:
a command line can hold a password no pattern names, and the report must not
repeat it. What an encoded command decodes to is scanned like any other
text, so its URLs and secrets are reported, masked, in the usual way.

Several patterns spell a letter as a one-character class (i[e]x). That keeps
this file from matching itself when NetSentinel's own folder is scanned.
"""

import base64
import binascii
import logging
import os
import re

logger = logging.getLogger(__name__)

SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')

# (kind, label, severity, shown, pattern)
RULES = [
    ('ps_download_cradle', 'PowerShell download cradle', 'HIGH',
     'Invoke-Expression of downloaded code',
     re.compile(r'(?im)^(?=[^\n]{0,4000}?(?:\bi[e]x\b|invoke-[e]xpression))'
                r'(?=[^\n]{0,4000}?(?:\.download(?:strin[g]|dat[a]|fil[e])\s*\(|'
                r'invoke-(?:web[r]equest|rest[m]ethod)|\b(?:iw[r]|ir[m])\b))[^\n]{1,4000}')),
    ('ps_iex', 'PowerShell running a string as code', 'MEDIUM', 'Invoke-Expression or its alias',
     re.compile(r'(?i)(?:\|\s*(?:i[e]x|invoke-[e]xpression)\b|'
                r'\b(?:i[e]x|invoke-[e]xpression)\s*[(\$\'"])')),
    ('ps_download', 'PowerShell download', 'LOW', 'downloads a file or string',
     re.compile(r'(?i)\.download(?:strin[g]|fil[e])\s*\(|'
                r'new-object\s+(?:-typename\s+)?(?:system\.)?net\.web[c]lient\b|'
                r'\bstart-bits[t]ransfer\b')),
    ('ps_frombase64', 'PowerShell decoding base64', 'LOW', '[Convert]::FromBase64String',
     re.compile(r'(?i)\]::from[b]ase64string\s*\(')),
    ('ps_evasion', 'PowerShell started hidden or with policy bypass', 'MEDIUM',
     'hidden window or execution-policy bypass',
     re.compile(r'(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,300}?\s[-/]'
                r'(?:w(?:indowstyle)?\s+h(?:i[d]den)?\b|(?:ep|exec|executionpolicy)\s+b[y]pass\b)')),
    ('lolbin_certutil', 'certutil used to download or decode', 'HIGH',
     'certutil fetching or decoding a file',
     re.compile(r'(?i)\bcertutil(?:\.exe)?\b[^\n]{0,200}?\s[-/](?:url[c]ache|de[c]ode(?:hex)?)\b')),
    ('lolbin_mshta', 'mshta running remote or inline script', 'HIGH', 'mshta with a URL or script',
     re.compile(r'(?i)\bmshta(?:\.exe)?["\']?\s+["\']?(?:https?:|java[s]cript:|vb[s]cript:)')),
    ('lolbin_regsvr32', 'regsvr32 loading a remote scriptlet', 'HIGH',
     'regsvr32 loading a scriptlet from a URL',
     re.compile(r'(?i)\bregsvr32(?:\.exe)?\b[^\n]{0,200}?\s[-/]i:\s*["\']?ht[t]ps?:')),
    ('lolbin_rundll32', 'rundll32 running script', 'HIGH', 'rundll32 running JavaScript',
     re.compile(r'(?i)\brundll32(?:\.exe)?\b[^\n]{0,200}?java[s]cript:')),
    ('lolbin_bitsadmin', 'bitsadmin download', 'MEDIUM', 'bitsadmin download job',
     re.compile(r'(?i)\bbitsadmin(?:\.exe)?\b[^\n]{0,100}?\s/t[r]ansfer\b')),
    ('defender_tamper', 'Microsoft Defender settings weakened', 'HIGH',
     'Defender exclusion or protection turned off',
     re.compile(r'(?i)\b(?:add|set)-mp[p]reference\b[^\n]{0,200}?\s-(?:exclusion(?:path|process|extension)|'
                r'disable(?:realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning))\b')),
]

# Every unambiguous abbreviation PowerShell accepts for -EncodedCommand.
_ENC_NAMES = '|'.join(sorted({'encodedcommand'[:n] for n in range(1, 15)} | {'ec'},
                             key=len, reverse=True))
_ENCODED = re.compile(r'(?i)[-/\u2013\u2014](?:' + _ENC_NAMES + r')\s+["\']?'
                      r'([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])')
MAX_ENCODED = 1024 * 1024

# Words a rule cannot match without, looked for in the lowercased text before
# the rule's regex runs (most files mention none of them). 'i' 'ex' is split
# so this file does not match itself.
_RULE_TRIGGERS = {
    'ps_download_cradle': ('i' 'ex', 'invoke-' 'expression'),
    'ps_iex': ('i' 'ex', 'invoke-' 'expression'),
    'ps_download': ('.download', 'webclient', 'bitstransfer'),
    'ps_frombase64': ('frombase64string',),
    'ps_evasion': ('powershell', 'pwsh'),
    'lolbin_certutil': ('certutil',), 'lolbin_mshta': ('mshta',), 'lolbin_regsvr32': ('regsvr32',),
    'lolbin_rundll32': ('rundll32',), 'lolbin_bitsadmin': ('bitsadmin',),
    'defender_tamper': ('mppreference',),
}

_AUTOEXEC = re.compile(r'(?i)\b(?:auto_?open|autoexec|auto_?close|document_(?:open|close)|'
                       r'workbook_(?:open|activate)|presentation_?open)\b')
_MACRO_ACTION = re.compile(r'(?i)\b(?:shell|wscript\.shell|createobject|urldownloadtofile|'
                           r'msxml2\.(?:server)?xmlhttp|winhttp|powershell|cmd(?:\.exe)?)\b')


def find(text, lowered=None):
    """[(start, end, kind, label, severity, shown)] for each rule that matches."""
    if lowered is None:
        lowered = text.lower()
    hits = []
    for kind, label, severity, shown, pattern in RULES:
        triggers = _RULE_TRIGGERS.get(kind)
        if triggers and not any(t in lowered for t in triggers):
            continue
        for m in pattern.finditer(text):
            hits.append((m.start(), m.end(), kind, label, severity, shown))
    return hits


def encoded_powershell(text):
    """
    [(start, end, decoded)] for each -EncodedCommand argument that decodes
    to text. PowerShell's encoding is base64 of UTF-16LE; anything that does
    not decode cleanly to mostly printable text is not one.
    """
    out = []
    for m in _ENCODED.finditer(text):
        if m.start() and text[m.start() - 1] not in ' \t\r\n"\'':
            continue          # mid-word, as in "re-encode", not a command-line switch
        blob = m.group(1)
        if len(blob) > MAX_ENCODED * 4 // 3:
            continue
        try:
            raw = base64.b64decode(blob + '=' * (-len(blob) % 4), validate=True)
            decoded = raw.decode('utf-16-le')
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if decoded and _printable_share(decoded) >= 0.9:
            out.append((m.start(1), m.end(1), decoded))
    return out


def _printable_share(s):
    # ASCII only: random base64 read as UTF-16 is mostly printable CJK
    good = sum(1 for c in s if ' ' <= c <= '~' or c in '\r\n\t')
    return good / len(s)


# ─── Office macros ──────────────────────────────────────────────────────

# Compressed bytes read while looking for macros, per byte of input, over
# every module start tried: a real project reads each byte about once.
VBA_WORK_PER_BYTE = 4
VBA_WORK_FLOOR = 64 * 1024


def vba_source(blob, limit=8 * 1024 * 1024, strings=True, notes=None):
    """
    The VBA source held in a vbaProject.bin or an old-style (OLE) Office
    file, as far as it can be recovered without parsing the OLE container:
    every module's compressed source (found by its 'Attribute VB_Name'
    opening), decompressed, plus (with strings) the readable strings of the
    rest. Where a limit stopped the search, it says so in `notes`.

    Every opening found is tried, even one inside data an earlier attempt
    read: that attempt may have been a decoy decoding straight over the real
    module. But chunks decode independently, so two attempts that reach the
    same chunk header decode the same from there on, to the same end. Each
    chunk is therefore read once, and an attempt that meets an earlier one's
    chunk stops there. Restarting at every opening used to re-read the rest
    of a chain of chunks each built to look like one, then fail at its last
    token: quadratic, about 48 minutes a megabyte.
    """
    parts, total, pos, n = [], 0, 0, len(blob)
    read_at = {}            # chunk header position -> the attempt that read it
    failed = []             # per attempt: it ended in a malformed chunk
    work = min(n * VBA_WORK_PER_BYTE, limit * 2) + VBA_WORK_FLOOR
    out_of_work = False
    while total < limit and not out_of_work:
        # A compressed module opens with signature 0x01, a two-byte chunk
        # header, and a flag byte of 0 before the eight literal bytes 'Attribut'.
        i = blob.find(b'\x00Attribut', pos)
        if i < 0:
            break
        pos = i + 9
        start = i - 3
        if start < 0 or blob[start] != 1 or start + 1 in read_at:
            continue
        attempt, out, at, ok = len(failed), bytearray(), start + 1, True
        while len(out) < limit - total:
            earlier = read_at.get(at)
            if earlier is not None:
                # the rest is what that attempt decoded, already kept if it was good
                ok = not failed[earlier]
                break
            if work <= 0:
                out_of_work, ok = True, False
                break
            read_at[at] = attempt
            span = _ovba_span(blob, at)
            if span is None:
                break
            try:
                out += _ovba_chunk(blob, at, *span)
            except (ValueError, IndexError) as e:
                # charged what it read and no more: openings that fail at once
                # must not use up the work a real module after them needs
                work -= getattr(e, 'read_to', span[1]) - at
                ok = False
                break
            work -= min(span[1], n) - at
            at = span[1]
        failed.append(not ok)
        if ok and out:
            source = bytes(out[:limit - total])
            parts.append(source.decode('latin-1'))
            total += len(source)
    if notes is not None:
        if out_of_work:
            notes.append('macro search stopped at its work limit: '
                         'macros after that point were not decompressed')
        elif total >= limit:
            notes.append(f'macro source past the first {limit // 1024 ** 2} MB was not read')
    if strings:
        found = re.findall(rb'[\x20-\x7e]{6,}', blob[:limit])
        parts.append('\n'.join(s.decode('ascii') for s in found))
    return '\n'.join(parts)


def ovba_decompress(data, start, limit):
    """MS-OVBA 2.4.1 decompression of the container starting at data[start]."""
    if data[start] != 1:
        raise ValueError('not a compressed container')
    out = bytearray()
    pos = start + 1
    while len(out) < limit:
        span = _ovba_span(data, pos)
        if span is None:
            break
        out += _ovba_chunk(data, pos, *span)
        pos = span[1]
    return bytes(out[:limit])


def _ovba_span(data, pos):
    """
    (compressed, position of the next chunk header) for the chunk whose
    header is at data[pos], or None if there is no chunk header there.
    """
    if pos + 2 > len(data):
        return None
    header = data[pos] | (data[pos + 1] << 8)
    if (header >> 12) & 0x7 != 0b011:
        return None
    if not header & 0x8000:
        return False, pos + 2 + 4096
    return True, min(len(data), pos + (header & 0x0FFF) + 3)


class _BadChunk(ValueError):
    """A malformed chunk, and the input position it was read to."""

    def __init__(self, reason, read_to):
        super().__init__(reason)
        self.read_to = read_to


def _ovba_chunk(data, pos, compressed, chunk_end):
    """
    The chunk whose header is at data[pos], decompressed. Its copy tokens
    reach only within it, so it decodes the same whichever container start
    it was reached from.
    """
    pos += 2
    if not compressed:
        return data[pos:chunk_end]
    out = bytearray()
    while pos < chunk_end:
        flags = data[pos]
        pos += 1
        for bit in range(8):
            if pos >= chunk_end:
                break
            if not flags & (1 << bit):
                out.append(data[pos])
                pos += 1
                continue
            if pos + 2 > chunk_end:
                raise _BadChunk('truncated copy token', chunk_end)
            token = data[pos] | (data[pos + 1] << 8)
            pos += 2
            done = len(out)
            if done <= 0:
                raise _BadChunk('copy token before any data', pos)
            bits = min(max((done - 1).bit_length(), 4), 12)
            length = (token & (0xFFFF >> bits)) + 3
            offset = (token >> (16 - bits)) + 1
            src = done - offset
            if src < 0:
                raise _BadChunk('copy token reaches before the chunk', pos)
            # A copy may overlap what it writes ('abc' then 6 from 3 back is
            # 'abcabc'): the last `offset` bytes, repeated. Slices, not a
            # byte at a time, so a token's cost does not grow with its length.
            if offset >= length:
                out += out[src:src + length]
            else:
                out += (out[src:] * (length // offset + 1))[:length]
    return bytes(out)


def macro_findings(vba_text):
    """[(kind, label, severity, shown)] for a document's macro source."""
    if not vba_text.strip():
        return []
    if _AUTOEXEC.search(vba_text) and _MACRO_ACTION.search(vba_text):
        return [('macro_autoexec', 'Macro that runs on open and starts programs or downloads',
                 'HIGH', 'auto-run macro')]
    if 'Attribute VB_' in vba_text:
        return [('office_macro', 'Document contains VBA macros', 'LOW', 'VBA macros')]
    return []


# ─── YARA (only if the user has installed yara-python) ─────────────────

_yara_cache = {}


def load_yara(folder):
    """Compiled rules from *.yar / *.yara in `folder`, or None (no folder,
    no rules, no yara module, or rules that do not compile)."""
    if not folder or not os.path.isdir(folder):
        return None
    try:
        import yara
    except ImportError:
        return None
    paths = sorted(os.path.join(folder, n) for n in os.listdir(folder)
                   if n.lower().endswith(('.yar', '.yara')))
    signature = []
    for p in paths:
        try:
            st = os.stat(p)
        except OSError:
            continue
        signature.append((p, st.st_size, st.st_mtime_ns))
    signature = tuple(signature)
    cached = _yara_cache.get(folder)
    if cached and cached[0] == signature:
        return cached[1]
    rules = None
    if signature:
        try:
            rules = yara.compile(filepaths={f'r{i}': p for i, (p, _, _) in enumerate(signature)})
        except Exception as e:
            logger.warning("YARA rules in %s did not compile: %s", folder, e)
    _yara_cache[folder] = (signature, rules)
    return rules


def yara_matches(rules, data, timeout=60):
    """[(rule, severity, offset or None, description)] for the rules that match."""
    try:
        matches = rules.match(data=data, timeout=timeout)
    except Exception as e:
        logger.warning("YARA scan failed: %s", e)
        return []
    out = []
    for m in matches:
        meta = getattr(m, 'meta', None) or {}
        severity = str(meta.get('severity', 'MEDIUM')).upper()
        if severity not in SEVERITIES:
            severity = 'MEDIUM'
        out.append((str(m.rule)[:128], severity, _first_offset(m),
                    str(meta.get('description', ''))[:200]))
    return out


def _first_offset(match):
    strings = getattr(match, 'strings', None) or []
    for s in strings:
        instances = getattr(s, 'instances', None)       # yara-python 4.3+
        if instances:
            return getattr(instances[0], 'offset', None)
        if isinstance(s, tuple) and s and isinstance(s[0], int):   # older: (offset, id, data)
            return s[0]
    return None
