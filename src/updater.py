"""
Updates: find a newer release, check it, and put it in place.
=============================================================
NetSentinel asks GitHub's releases API for the latest release, at start and
once a day while it runs (`updates.check`, on by default). The request carries
this version in its User-Agent and nothing else: nothing about the network or
the files on this machine goes out.

Installing is one click, never automatic, and only for the Windows exe:

1. The release's manifest, NetSentinel.exe.sig, is checked against the public
   key below. The release workflow signs it with Ed25519 (tools/sign_release.py)
   and it names the version and the exe's SHA-256. A manifest that does not
   verify, names another version, or an older one than this, stops the update.
   The .sha256 published beside the exe has to agree as well.
2. The exe is downloaded next to the running one, hashed as it arrives, and
   kept only if the hash is the signed one.
3. The new exe is started with --finish-update. It waits for this copy to exit,
   moves the old exe aside (NetSentinel.exe.old), copies itself into place and
   starts that, with the same arguments. The next start removes the leftovers.

Run from source, NetSentinel only says that a new version is out.
"""

import base64
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

logger = logging.getLogger("NetSentinel.Updater")

__all__ = ['Updater', 'UpdateInfo', 'UpdateError', 'parse_version', 'signed_message',
           'sign_manifest', 'verify_manifest', 'finish_update', 'cleanup_leftovers']

REPO = 'jamesccupps/NetSentinel'
LATEST_URL = f'https://api.github.com/repos/{REPO}/releases/latest'
RELEASES_PAGE = f'https://github.com/{REPO}/releases/'
EXE_ASSET = 'NetSentinel.exe'
SIG_ASSET = 'NetSentinel.exe.sig'
SHA_ASSET = 'NetSentinel.exe.sha256'
UPDATE_NAME = 'NetSentinel.update.exe'

# The release workflow's signing key, public half. Its private half is the
# NETSENTINEL_SIGNING_KEY secret of the GitHub repository and nowhere in here.
PUBLIC_KEY = '9rdeLgcoU5W1VnLbQtPhi2HgXs5HxqlTMKMwckZN/pg='

CHECK_INTERVAL = 24 * 3600
FIRST_CHECK_DELAY = 60
MAX_EXE_BYTES = 400 * 1024 * 1024
MAX_SMALL_BYTES = 2 * 1024 * 1024
TIMEOUT = 30
# Release downloads redirect from github.com to GitHub's own storage hosts.
_ALLOWED_HOSTS = ('github.com', 'githubusercontent.com')


class UpdateError(Exception):
    """Why an update was not installed, in words for the person who asked."""


def parse_version(text):
    """'v1.9.2' or '1.9.2' -> (1, 9, 2); None for anything else."""
    match = re.fullmatch(r'v?(\d{1,4}(?:\.\d{1,4}){1,3})', (text or '').strip())
    return tuple(int(p) for p in match.group(1).split('.')) if match else None


def signed_message(version, sha256):
    """The bytes a release signature covers: the version and the exe's hash."""
    return f"NetSentinel release\nversion {version}\nsha256 {sha256}\n".encode('ascii')


def _public_key(public_key_b64):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        raw = base64.b64decode(public_key_b64 or '', validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as e:
        raise UpdateError("This build has no usable key for checking updates.") from e


def sign_manifest(private_key_b64, version, sha256):
    """The manifest the release workflow publishes as NetSentinel.exe.sig."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64, validate=True))
    signature = key.sign(signed_message(version, sha256))
    return {'version': version, 'sha256': sha256,
            'signature': base64.b64encode(signature).decode('ascii')}


def verify_manifest(manifest, public_key_b64=None):
    """(version, sha256) from a manifest whose signature verifies, else UpdateError."""
    from cryptography.exceptions import InvalidSignature
    if not isinstance(manifest, dict):
        raise UpdateError("The release's signature file is not in the expected form.")
    version, sha256 = manifest.get('version'), manifest.get('sha256')
    if not isinstance(version, str) or not parse_version(version) or \
            not isinstance(sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', sha256):
        raise UpdateError("The release's signature file is not in the expected form.")
    try:
        signature = base64.b64decode(manifest.get('signature') or '', validate=True)
        _public_key(PUBLIC_KEY if public_key_b64 is None else public_key_b64).verify(
            signature, signed_message(version, sha256))
    except (InvalidSignature, ValueError, TypeError) as e:
        raise UpdateError("The release's signature does not verify. Nothing was "
                          "installed; download it from the release page if you "
                          "trust it.") from e
    return version, sha256


def _allowed(url):
    parts = urlsplit(url or '')
    host = (parts.hostname or '').lower()
    return parts.scheme == 'https' and any(
        host == h or host.endswith('.' + h) for h in _ALLOWED_HOSTS)


def _http_fetch(url, limit, out=None, agent='NetSentinel'):
    """
    GET over HTTPS from GitHub only, following its redirects. Returns the body,
    or writes it to `out` (a binary file) and returns None. At most `limit` bytes.
    """
    import urllib.request
    if not _allowed(url):
        raise UpdateError(f"Refused to download from {urlsplit(url).hostname or url}.")
    request = urllib.request.Request(url, headers={
        'User-Agent': agent, 'Accept': 'application/json, application/octet-stream'})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        if not _allowed(response.geturl()):
            raise UpdateError("The download was redirected away from GitHub.")
        chunks, total = [], 0
        while True:
            chunk = response.read(1 << 16)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise UpdateError("The download is larger than any release should be.")
            if out is None:
                chunks.append(chunk)
            else:
                out.write(chunk)
        return b''.join(chunks) if out is None else None


class UpdateInfo:
    """A release newer than this one."""

    def __init__(self, version, page_url, notes, exe_url='', exe_size=0, sig_url='',
                 sha_url=''):
        self.version = version
        self.page_url = page_url
        self.notes = notes
        self.exe_url = exe_url
        self.exe_size = exe_size
        self.sig_url = sig_url
        self.sha_url = sha_url

    @property
    def installable(self):
        """Whether the release carries what a one-click install needs."""
        return bool(self.exe_url and self.sig_url and self.sha_url)

    def to_dict(self):
        return {'version': self.version, 'page_url': self.page_url,
                'installable': self.installable}


def release_info(release, current):
    """The UpdateInfo for a releases-API answer, if it is newer than `current`."""
    if not isinstance(release, dict) or release.get('draft') or release.get('prerelease'):
        return None
    newest, mine = parse_version(release.get('tag_name')), parse_version(current)
    if not newest or not mine or newest <= mine:
        return None
    version = '.'.join(str(p) for p in newest)
    page = release.get('html_url') or ''
    if not page.startswith(RELEASES_PAGE):
        page = RELEASES_PAGE + 'latest'
    assets = {}
    for asset in release.get('assets') or []:
        if isinstance(asset, dict) and _allowed(asset.get('browser_download_url')):
            assets[asset.get('name')] = asset
    exe = assets.get(EXE_ASSET, {})
    return UpdateInfo(
        version, page, str(release.get('body') or '')[:20000],
        exe_url=exe.get('browser_download_url', ''), exe_size=int(exe.get('size') or 0),
        sig_url=assets.get(SIG_ASSET, {}).get('browser_download_url', ''),
        sha_url=assets.get(SHA_ASSET, {}).get('browser_download_url', ''))


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


class Updater:
    """
    Checks for a newer release and installs one when asked. `fetch(url, limit,
    out=None)` does the downloading; tests pass their own, so nothing here
    touches the network unless the app gives it the real one.
    """

    def __init__(self, current_version, fetch=None, public_key=None, exe_path=None,
                 frozen=None):
        self.current = current_version
        self._fetch = fetch or (lambda url, limit, out=None: _http_fetch(
            url, limit, out, agent=f'NetSentinel/{current_version}'))
        self._public_key = public_key
        self.exe_path = exe_path or sys.executable
        self.frozen = getattr(sys, 'frozen', False) if frozen is None else frozen
        self.available = None
        self.last_checked = 0.0
        self.last_error = ''
        self._lock = threading.Lock()
        self._thread = None

    @property
    def can_install(self):
        """A one-click install replaces the Windows exe; from source it cannot."""
        return bool(self.frozen) and sys.platform == 'win32'

    def check(self):
        """Ask GitHub for the latest release. Returns an UpdateInfo or None."""
        with self._lock:
            self.last_checked = time.time()
            try:
                body = self._fetch(LATEST_URL, MAX_SMALL_BYTES)
                self.available = release_info(json.loads(body.decode('utf-8')), self.current)
                self.last_error = ''
            except Exception as e:                  # offline, rate limited, odd answer
                self.last_error = str(e) or e.__class__.__name__
                logger.info("Update check failed: %s", self.last_error)
            return self.available

    def start_checking(self, enabled, on_found=None, delay=FIRST_CHECK_DELAY,
                       interval=CHECK_INTERVAL):
        """Check `delay` seconds from now and then every `interval`, in a daemon thread."""
        if not enabled or self._thread is not None:
            return
        stop = threading.Event()

        def loop():
            wait = delay
            while not stop.wait(wait):
                info = self.check()
                if info and on_found:
                    try:
                        on_found(info)
                    except Exception as e:
                        logger.debug("Update notice failed: %s", e)
                wait = interval

        self._stop = stop
        self._thread = threading.Thread(target=loop, name='update-check', daemon=True)
        self._thread.start()

    def stop_checking(self):
        stop = getattr(self, '_stop', None)
        if stop is not None:
            stop.set()

    def update_path(self):
        return os.path.join(os.path.dirname(os.path.abspath(self.exe_path)), UPDATE_NAME)

    def download(self, info, progress=None):
        """
        Fetch and check the release in `info`. Returns the path of the checked
        exe, next to the running one, or raises UpdateError. Nothing is left
        behind when a check fails.
        """
        if not info.installable:
            raise UpdateError("This release has no signature to check, so it cannot be "
                              "installed from here. Download it from the release page.")
        manifest = self._fetch(info.sig_url, MAX_SMALL_BYTES)
        try:
            manifest = json.loads(manifest.decode('utf-8'))
        except (ValueError, UnicodeDecodeError) as e:
            raise UpdateError("The release's signature file is not in the expected form.") from e
        version, sha256 = verify_manifest(manifest, self._public_key)
        if parse_version(version) != parse_version(info.version):
            raise UpdateError(f"The signature is for {version}, not {info.version}.")
        if not parse_version(self.current) or parse_version(version) <= parse_version(self.current):
            raise UpdateError(f"{version} is not newer than this copy ({self.current}).")
        published = self._fetch(info.sha_url, 4096).decode('ascii', 'replace').split()
        if not published or published[0].lower() != sha256:
            raise UpdateError("The release's .sha256 does not match its signature.")

        target = self.update_path()
        partial = target + '.part'
        try:
            with open(partial, 'wb') as out:
                self._fetch(info.exe_url, MAX_EXE_BYTES, out)
            if progress:
                progress('Checking the download...')
            if _sha256_file(partial) != sha256:
                raise UpdateError("The download does not match the signed release. "
                                  "Nothing was installed.")
            os.replace(partial, target)
        except BaseException:
            try:
                os.remove(partial)
            except OSError:
                pass
            raise
        return target

    def hand_over(self, update_exe, monitor=False, argv=None, popen=None):
        """
        Start the checked exe to finish the update once this copy exits. The
        caller then shuts down. Returns the started process.
        """
        from src.restart import relaunch_command, relaunch_environment
        args = relaunch_command(argv=argv, executable=self.exe_path, frozen=True,
                                monitor=monitor)[1:]
        command = [update_exe, '--finish-update', os.path.abspath(self.exe_path),
                   ','.join(str(p) for p in _own_pids(self.exe_path))] + args
        flags = 0
        if os.name == 'nt':
            flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        return (popen or subprocess.Popen)(
            command, cwd=os.getcwd(), env=relaunch_environment(), creationflags=flags,
            close_fds=True)


def _own_pids(exe_path):
    """
    The processes that keep the exe open: this one and, for a PyInstaller
    onefile build, the bootloader that started it from the same file.
    """
    pids = [os.getpid()]
    try:
        import psutil
        parent = psutil.Process().parent()
        if parent is not None and os.path.normcase(parent.exe()) == \
                os.path.normcase(os.path.abspath(exe_path)):
            pids.append(parent.pid)
    except Exception:
        pass
    return pids


def _wait_for_exit(pids, timeout):
    try:
        import psutil
    except ImportError:
        time.sleep(3)
        return
    deadline = time.time() + timeout
    while time.time() < deadline and any(psutil.pid_exists(p) for p in pids):
        time.sleep(0.25)


def _retry(action, attempts=40, pause=0.25):
    for i in range(attempts):
        try:
            return action()
        except OSError:
            if i == attempts - 1:
                raise
            time.sleep(pause)


def finish_update(target, pids, args, source=None, popen=None, timeout=120):
    """
    Run by the new exe (started as `NetSentinel.update.exe --finish-update
    TARGET PIDS ARGS...`): wait for the old copy to exit, put this exe in its
    place, keep the old one as TARGET.old, and start TARGET with ARGS.
    Returns a process exit code.
    """
    source = source or sys.executable
    wanted = [int(p) for p in str(pids or '').split(',') if p.strip().isdigit()]
    _wait_for_exit(wanted, timeout)
    old, staged = target + '.old', target + '.new'
    moved = False
    try:
        shutil.copyfile(source, staged)
        if os.path.exists(old):
            _retry(lambda: os.remove(old))
        # The old exe can stay locked for a moment after its process ends.
        _retry(lambda: os.replace(target, old))
        moved = True
        os.replace(staged, target)
    except OSError as e:
        logger.error("Could not install the update: %s", e)
        if moved and not os.path.exists(target):
            try:
                os.replace(old, target)
            except OSError:
                pass
        try:
            os.remove(staged)
        except OSError:
            pass
    from src.restart import relaunch_environment
    flags = 0
    if os.name == 'nt':
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    (popen or subprocess.Popen)([target] + list(args), cwd=os.path.dirname(target) or None,
                                env=relaunch_environment(), creationflags=flags,
                                close_fds=True)
    return 0


def cleanup_leftovers(exe_path=None):
    """Remove what an update left beside the exe: the old copy and the installer."""
    exe_path = os.path.abspath(exe_path or sys.executable)
    folder = os.path.dirname(exe_path)
    for leftover in (exe_path + '.old', os.path.join(folder, UPDATE_NAME),
                     os.path.join(folder, UPDATE_NAME + '.part')):
        if os.path.normcase(leftover) == os.path.normcase(exe_path):
            continue
        try:
            os.remove(leftover)
        except OSError:
            pass
