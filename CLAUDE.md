# NetSentinel — notes for Claude Code

Read `HANDOFF.md` first: it has where the work stands, the owner's decisions,
and what is left. Keep it current during long work (the owner asked for that).

## What this is

- **NetSentinel** (`main.py`, `src/`): a Windows-first network monitor and IDS with
  a Tk desktop GUI, a browser dashboard served at `http://127.0.0.1:8737/`, and a
  headless mode (`--headless`). Packet capture via Scapy + Npcap, signature IDS
  (`src/ids_engine.py`, `rules/`), LAN detections (`src/lan_threats.py`), ML anomaly
  detection, threat feeds (`src/threat_intel.py`, `src/cloud_ranges.py`; every
  source's state for the Threat data page in `src/data_sources.py`), known
  exploited vulnerabilities matched to device banners (`src/vulns.py`, CISA KEV
  with NVD's version ranges), opt-in
  GeoIP (`src/geoip.py`), forensics, PCAP analysis, and file/folder/archive scanning
  for leaked secrets, scripts and indicators (`src/file_scan.py`, `src/batch_scan.py`,
  `src/archives.py`, `src/script_rules.py`, `src/scan_ignore.py`).
- **Review mode** (`src/review.py`): saves the traffic behind alerts and builds a
  redacted text bundle for Claude chat; verdicts come back as confirmed false
  positives (`src/baseline_whitelist.py: ConfirmedFalsePositives`).
- **Network audit** (`src/audit.py`): the one active feature, opt-in, see the rules.
- **Updater** (`src/updater.py`, `tools/sign_release.py`): finds a newer GitHub
  release, checks its Ed25519-signed manifest and SHA-256, and hands over to the
  new exe (`--finish-update`), on a click.
- **netmon** (`netmon/`, tests in `netmon_tests/`): a separate site monitor for a
  Linux sensor, driven by a YAML site profile. See `netmon/README.md`. Only the
  fictional `netmon/profiles/example-site.yaml` belongs in the repo.

## Commands

```
pip install scapy psutil scikit-learn numpy cryptography pyyaml maxminddb "py7zr>=1.0" python-evtx
python -m unittest discover -s . -p "test_*.py"    # all tests (~2,400, ~1 min, ~65 skips)
python tools/integration_check.py                  # 14 integration checks
ruff check --select E9,F63,F7,F82 .                # what CI fails on
python main.py                                     # GUI + dashboard
python main.py --headless [--review DIR]           # dashboard/API only
python -m src.batch_scan PATH... [--skip GLOB] [--json]
python -m src.review build [DIR]                   # review bundle
python -m src.audit --network 192.168.1.0/24       # network audit
```

Tests never touch the network: inject fakes, and keep `threat_intel.auto_update`
off. Build test frames fully specified: `Ether(src=..., dst=...)`, and ARP with
`hwsrc`. GitHub's Windows runner has no Npcap, so Scapy's default lookups of this
machine's interfaces raise there. In Claude's sandbox on the owner's Windows PC, set `XDG_CACHE_HOME` to a
scratch folder (scapy cannot read `~\.cache` there, and ~175 tests skip silently)
and `PYTHONIOENCODING=utf-8`.

CI (`.github/workflows/test.yml`) runs the tests on Python 3.10, 3.11 and 3.12 on
Linux, and on 3.12 on Windows, where the exe runs. On Windows, pass `encoding=` to
every text `open()` and `FileHandler`, and skip tests of POSIX file modes there.
Code must work on 3.10: no multi-line expressions inside f-strings, and remember
3.10's `fromisoformat` only takes 3 or 6 fractional digits.

## Releasing

Bump the version in `main.py` (APP_VERSION), `pyproject.toml`, `setup.bat` and
`src/__init__.py`; add a `CHANGELOG.md` section; push a `vX.Y.Z` tag.
`.github/workflows/release.yml` builds `NetSentinel.exe` on Windows and attaches
it with a SHA-256 to the GitHub release. It also attaches `NetSentinel.exe.sig`,
signed with the `NETSENTINEL_SIGNING_KEY` repository secret
(`tools/sign_release.py`), which is the only thing the updater
(`src/updater.py`) installs. A tag build without that secret fails. Running
that workflow by hand (workflow_dispatch) builds the exe as an artifact without
releasing. Publishing a release is the owner's call: ask before pushing a tag.
The signing key's private half never goes in the repo, a prompt or a log;
`PUBLIC_KEY` in `src/updater.py` is its public half.

The workflow builds from `requirements-build.lock` (hash-pinned), then:
`authenticode` signs the exe for Windows (below), `verify` checks that
signature, starts the exe (`--version`) and writes the SHA-256, `sign` adds the
updater's signature in a job that installs only `tools/sign-requirements.lock`,
and `publish` releases; actions are pinned by commit. The SHA-256 and the
updater's signature are of the Authenticode-signed exe, since signing changes
the file. After changing `requirements.txt`, regenerate the lock (the command is
at the top of `release.yml`), or the exe is built without the change.

Code signing (Authenticode, from 1.14.2; earlier releases were unsigned):
Azure Artifact Signing as James Cupps, the account and certificate Slate,
NoteForge, PingerPlot, UniFi Stock Watcher, Protect Panes and HVAC Network
Scanner use (account `SlateAccount`, profile `Slate`, endpoint
`https://eus.codesigning.azure.net/`). The exe asks for elevation, so this is
what the UAC prompt shows as the verified publisher. The app registration
"Slate signing" has a federated credential for
`repo:jamesccupps/NetSentinel:environment:release`; the `release` environment
admits `v*` tags only, and the `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and
`AZURE_SUBSCRIPTION_ID` secrets name the app registration. No password or key
is stored. `authenticode` runs only pinned actions, Microsoft's ArtifactSigning
module and `tools/authenticode.ps1`: nothing from PyPI, never the program
(`test_authenticode.py` holds the rules). A tag `vX.Y.Z-signtest.N` (the version
in `src/__init__.py`) runs build, authenticode and verify only, for trying a
signing change; delete it after. Before signing, VirusTotal had the unsigned
1.14.1 exe at 2/64 (Bkav's hash-named generic and DeepInstinct's ML verdict;
Microsoft and the major engines clean; Kaspersky timed out on the 81 MB file).

NetSentinel is also in the owner's Scoop bucket (`jamesccupps/scoop-bucket`,
`bucket/netsentinel.json`). Its manifest updates itself from the latest GitHub
release every 4 hours, so a release needs no Scoop work as long as these hold:
- Tag releases `vX.Y.Z` and publish them as the latest release, never a
  pre-release.
- Keep the file names: `NetSentinel.exe`, shipped bare (not zipped), with
  `NetSentinel.exe.sha256` beside it (`<hash>  NetSentinel.exe`, which the
  bucket reads its hash from) and `NetSentinel.exe.sig` (which the updater needs).
- Sign before publishing (the workflow's sign job does), and never replace a
  file on a release that is out: Scoop (and winget, if NetSentinel goes there)
  has recorded its hash, and every install's updater has seen its signature.
  Fix a bad release with a new version. That is why the publish step uploads
  without `--clobber`: re-running it on a released tag fails instead.
- If a file name or the packaging must change, update `bucket/netsentinel.json`
  in jamesccupps/scoop-bucket in the same change.

The project page is `site/index.html` (plus `site/images/`), published to
https://jamesccupps.github.io/NetSentinel/ by `.github/workflows/pages.yml` when
`site/` changes on main (Settings → Pages → Source: GitHub Actions). It fetches
the latest version from the GitHub API and links `releases/latest/download/...`,
so a release needs no deploy. `site/images/social-preview.png` (1280x640) is also
the repository's Settings → Social preview, uploaded by hand. Keep the page's
claims in step with the README, and pictures free of real addresses, hosts and
device names (the hard rules below).

## Conventions

- The owner works on `main` and has allowed pushing to it directly.
- NetSentinel runs as Administrator: start programs by absolute path from
  `src/winpaths.py`, never by bare name (a test fails on one), and never unpickle
  or trust a file a program running as the owner could write.
- Commit messages: a plain subject, then a body that says what was wrong and why
  the change is right. Comments explain why, not what; match the file you are in.
- Every fix gets a test that would have caught it. Run the full suite before pushing.
- Changing a default in `DEFAULT_CONFIG`? Every saved `config.json` keeps the old
  one: add it to `config.STALE_DEFAULTS` if existing installs should get the new.
- Anything that came off the network or out of a scanned file is untrusted:
  the dashboard puts it on the page with `textContent`, never `innerHTML`.

## Hard rules (from the owner's site spec, still in force)

- Never put card data, card hashes, RFID credential numbers, passwords, session
  cookies or API keys in code, fixtures, logs, AI prompts or the repo. Secrets
  found by scans are masked where they are found (`src/file_scan.py: mask`).
- Real captures, the real site profile, and anything from the metadata-only VLAN
  (VLAN 12 at the owner's site) stay out of the repository. Tests that need real
  captures read a local path from an environment variable and are .gitignored.
- The `flash*` captures hold card and RFID data: never open, use or commit them.
- Output is advisory only: no inline blocking, no automatic firewall changes,
  no TLS decryption. (Live detection reads QUIC Initial packets for the server
  name. Their keys come from the public connection ID by design, RFC 9001, and they
  hold only the ClientHello; whether that sits within this rule is the owner's
  call, raised with him 2026-10-29.)
- The HTTP server binds to localhost by default and cannot change configuration.
  Its controls (start/stop monitoring, acknowledge, verdicts, review bundles,
  network audits, the scan ignore list) need the per-process token the dashboard
  page carries and are refused unless the server is bound to loopback; loopback
  binds refuse foreign Host headers. Keep it that way. (Owner's decision,
  2026-10-29; it replaced "cannot change monitoring".)
- The syslog receiver (`src/syslog_receiver.py`) is the only thing listening off
  loopback: off until `syslog.enabled`, on the configured address only, it
  accepts only `syslog.allowed_senders`, never answers, and treats every message
  as untrusted text.
- The network audit is the only active probing. It is off until `audit.enabled`,
  runs only when asked, only on private networks of /16 or smaller on a local
  interface, and never tries a credential.
- Review bundles leave the machine: by default no payloads, pcaps, query strings,
  cookies, credentials or tokens, and every file passes the secret audit.
- Threat data is downloaded and checked locally; nothing about the owner's
  traffic or files is sent out for lookups. That includes KEV and NVD: whole
  downloads, matched here. The abuse.ch Auth-Key rides in the download URL, so
  a keyed feed's URL never goes in a log line or an error message. The update check
  (`updates.check`) sends GitHub only NetSentinel's version, and an update is
  installed only when the owner clicks, after its signature verifies. (Owner's
  decision, 2026-11-01.)
