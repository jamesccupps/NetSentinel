"""
How VirusTotal's engines see a released NetSentinel.exe.
========================================================
Run by .github/workflows/virustotal.yml after each release, and by hand:

    VT_API_KEY=... python tools/virustotal_check.py [--tag vX.Y.Z]

With no tag, the latest release. It asks VirusTotal about the exe's SHA-256
(from the release's NetSentinel.exe.sha256); if VirusTotal has never seen it,
it downloads the exe from the release, checks it against that hash, uploads it
and waits for the scan. The release is public, so uploading it shares nothing
new. It reports how many engines flag the exe, and which, in the run's summary
and as a warning when any do. Report only: a release is never held for it.

Exit 0 when VirusTotal answered (flagged or not), 1 when it could not be asked.
Standard library only. The key rides in a header and is never printed.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import uuid

API = 'https://www.virustotal.com/api/v3'
REPO = 'jamesccupps/NetSentinel'
TAG_RE = re.compile(r'^v\d+\.\d+\.\d+$')
SHA_RE = re.compile(r'^[0-9a-f]{64}$')
POLL_SEC = 60              # the free API allows 4 requests a minute
WAIT_SEC = 45 * 60         # an 80 MB exe can wait a while in VirusTotal's queue
MAX_EXE = 300 * 1024 * 1024
MAX_JSON = 16 * 1024 * 1024
BUSY_RETRIES = 3
AGENT = 'NetSentinel-release-check'


class CheckFailed(Exception):
    """VirusTotal could not be asked; the message says why."""


def http(method, url, headers=None, body=None, limit=MAX_JSON, timeout=60):
    """(status, body bytes), for errors too. Redirects are followed."""
    req = urllib.request.Request(url, data=body, method=method,
                                 headers=dict(headers or {}, **{'User-Agent': AGENT}))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, _read(resp, limit)
    except urllib.error.HTTPError as e:
        return e.code, _read(e, 64 * 1024)


def _read(resp, limit):
    data = resp.read(limit + 1)
    if len(data) > limit:
        raise CheckFailed(f'More than {limit // (1024 * 1024)} MB came back; stopped.')
    return data


def _json(data):
    try:
        return json.loads(data or b'{}')
    except ValueError:
        return {}


def clean(text, limit=80):
    """Text from VirusTotal, made safe for a log line, an annotation and markdown."""
    text = re.sub(r'[^\w .:/()+@#,-]', ' ', str(text))
    return re.sub(r'\s+', ' ', text.replace('::', ': ')).strip()[:limit]


class Checker:

    def __init__(self, key, repo=REPO, transport=http, sleep=time.sleep,
                 clock=time.monotonic, gh_token=''):
        self.key = key
        self.repo = repo
        self.http = transport
        self.sleep = sleep
        self.clock = clock
        self.gh_token = gh_token

    # ── GitHub: the release's files ──────────────────────────────────────────

    def latest_tag(self):
        headers = {'Accept': 'application/vnd.github+json'}
        if self.gh_token:
            headers['Authorization'] = f'Bearer {self.gh_token}'
        status, data = self.http('GET', f'https://api.github.com/repos/{self.repo}/releases/latest',
                                 headers)
        tag = _json(data).get('tag_name', '') if status == 200 else ''
        if not TAG_RE.match(tag or ''):
            raise CheckFailed(f'Could not find the latest release (HTTP {status}).')
        return tag

    def release_file(self, tag, name, limit):
        status, data = self.http(
            'GET', f'https://github.com/{self.repo}/releases/download/{tag}/{name}',
            limit=limit, timeout=300)
        if status != 200:
            raise CheckFailed(f'Could not download {name} from {tag} (HTTP {status}).')
        return data

    def released_sha256(self, tag):
        line = self.release_file(tag, 'NetSentinel.exe.sha256', 4096).decode('ascii', 'replace')
        parts = line.split()
        if len(parts) != 2 or parts[1] != 'NetSentinel.exe' or not SHA_RE.match(parts[0]):
            raise CheckFailed(f"{tag}'s NetSentinel.exe.sha256 is not in the expected form.")
        return parts[0]

    # ── VirusTotal ───────────────────────────────────────────────────────────

    def vt(self, method, url, body=None, headers=None, limit=MAX_JSON, timeout=60):
        """A VirusTotal request, waiting out a busy quota a few times."""
        headers = dict(headers or {}, **{'x-apikey': self.key})
        for _ in range(BUSY_RETRIES + 1):
            status, data = self.http(method, url, headers, body, limit=limit, timeout=timeout)
            if status in (401, 403):
                raise CheckFailed(f'VirusTotal refused the key (HTTP {status}): check the '
                                  'VT_API_KEY secret.')
            if status != 429:
                return status, _json(data)
            self.sleep(POLL_SEC)
        raise CheckFailed('VirusTotal kept saying the API quota is used up (HTTP 429).')

    def known(self, sha256):
        """VirusTotal's last analysis of the file, or None if it has never seen it."""
        status, doc = self.vt('GET', f'{API}/files/{sha256}')
        if status == 404:
            return None
        if status != 200:
            raise CheckFailed(f'VirusTotal could not be asked about the file (HTTP {status}).')
        attributes = (doc.get('data') or {}).get('attributes') or {}
        return {'stats': attributes.get('last_analysis_stats') or {},
                'results': attributes.get('last_analysis_results') or {},
                'when': attributes.get('last_analysis_date')}

    def upload(self, exe):
        status, doc = self.vt('GET', f'{API}/files/upload_url')
        url = doc.get('data') if status == 200 else None
        if not isinstance(url, str) or not url.startswith('https://www.virustotal.com/'):
            raise CheckFailed(f'VirusTotal gave no upload address (HTTP {status}).')
        boundary = uuid.uuid4().hex
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                f'filename="NetSentinel.exe"\r\nContent-Type: application/octet-stream'
                f'\r\n\r\n').encode() + exe + f'\r\n--{boundary}--\r\n'.encode()
        status, doc = self.vt('POST', url, body, timeout=600,
                              headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})
        analysis = (doc.get('data') or {}).get('id') if status == 200 else None
        if not isinstance(analysis, str) or not analysis:
            raise CheckFailed(f'VirusTotal did not take the upload (HTTP {status}).')
        return analysis

    def wait_for(self, analysis):
        deadline = self.clock() + WAIT_SEC
        while True:
            status, doc = self.vt('GET', f'{API}/analyses/{analysis}')
            attributes = (doc.get('data') or {}).get('attributes') or {}
            if status == 200 and attributes.get('status') == 'completed':
                return {'stats': attributes.get('stats') or {},
                        'results': attributes.get('results') or {},
                        'when': attributes.get('date')}
            if status not in (200, 404):   # 404: not registered yet, just after upload
                raise CheckFailed(f'VirusTotal could not report the scan (HTTP {status}).')
            if self.clock() >= deadline:
                raise CheckFailed(f'VirusTotal had not finished the scan after '
                                  f'{WAIT_SEC // 60} minutes.')
            self.sleep(POLL_SEC)

    # ── The whole check ──────────────────────────────────────────────────────

    def check(self, tag=''):
        tag = tag or self.latest_tag()
        if not TAG_RE.match(tag):
            raise CheckFailed(f'Not a release tag: {clean(tag, 40)!r} (expected vX.Y.Z).')
        sha256 = self.released_sha256(tag)
        report = self.known(sha256)
        uploaded = report is None
        if uploaded:
            exe = self.release_file(tag, 'NetSentinel.exe', MAX_EXE)
            if hashlib.sha256(exe).hexdigest() != sha256:
                raise CheckFailed(f"{tag}'s NetSentinel.exe does not match its "
                                  'NetSentinel.exe.sha256; nothing was uploaded.')
            report = self.wait_for(self.upload(exe))
        return dict(report, tag=tag, sha256=sha256, uploaded=uploaded)


def flagged_by(results):
    """[(engine, what it calls the file)] for every engine that flags it."""
    out = []
    for engine, result in sorted((results or {}).items()):
        if isinstance(result, dict) and result.get('category') in ('malicious', 'suspicious'):
            out.append((clean(engine, 40), clean(result.get('result') or result['category'])))
    return out


def summary(report):
    """(markdown lines, the warning or None)."""
    stats = {k: v for k, v in (report.get('stats') or {}).items() if isinstance(v, int)}
    flagged = stats.get('malicious', 0) + stats.get('suspicious', 0)
    # Engines that could not read the file are not counted, as on VirusTotal's page.
    total = sum(v for k, v in stats.items()
                if k in ('malicious', 'suspicious', 'undetected', 'harmless'))
    engines = flagged_by(report.get('results'))
    tag, sha256 = report['tag'], report['sha256']
    how = 'uploaded and scanned now' if report.get('uploaded') else 'already known to VirusTotal'
    if not report.get('uploaded') and isinstance(report.get('when'), int):
        how += time.strftime('; last scanned %Y-%m-%d', time.gmtime(report['when']))
    lines = [f'## VirusTotal: NetSentinel.exe {tag}', '',
             f'**{flagged} of {total} engines flag it** ({how}).', '',
             f'SHA-256 `{sha256}`: https://www.virustotal.com/gui/file/{sha256}', '']
    lines += [f'- {engine}: {what}' for engine, what in engines]
    warning = None
    if flagged:
        names = ', '.join(f'{engine} ({what})' for engine, what in engines) or 'see the summary'
        warning = f'{flagged} of {total} engines flag NetSentinel.exe {tag}: {names}'
    return lines, warning


def main(argv=None, env=None, transport=http, sleep=time.sleep, out=sys.stdout):
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[1])
    parser.add_argument('--tag', default=env.get('TAG', ''),
                        help='release tag (default: the latest release)')
    args = parser.parse_args(argv)
    key = env.get('VT_API_KEY', '').strip()
    if not key:
        print('::error title=VirusTotal::The VT_API_KEY secret is not set, so VirusTotal '
              'was not asked.', file=out)
        return 1
    checker = Checker(key, repo=env.get('GITHUB_REPOSITORY') or REPO, transport=transport,
                      sleep=sleep, gh_token=env.get('GH_TOKEN', ''))
    try:
        report = checker.check(args.tag.strip())
    except (CheckFailed, OSError) as e:      # OSError: unreachable, timed out
        print(f'::error title=VirusTotal::{clean(e, 300)}', file=out)
        return 1
    lines, warning = summary(report)
    print('\n'.join(lines), file=out)
    if warning:
        print(f'::warning title=VirusTotal::{warning}', file=out)
    step_summary = env.get('GITHUB_STEP_SUMMARY')
    if step_summary:
        with open(step_summary, 'a', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
