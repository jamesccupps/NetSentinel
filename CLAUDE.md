# NetSentinel — notes for Claude Code

Read `HANDOFF.md` first: it has where the work stands, the owner's decisions,
and what is left. Keep it current during long work (the owner asked for that).

## What this is

- **NetSentinel** (`main.py`, `src/`): a Windows-first network monitor and IDS with
  a Tk desktop GUI, a browser dashboard served at `http://127.0.0.1:8737/`, and a
  headless mode (`--headless`). Packet capture via Scapy + Npcap, signature IDS
  (`src/ids_engine.py`, `rules/`), LAN detections (`src/lan_threats.py`), ML anomaly
  detection, threat feeds (`src/threat_intel.py`, `src/cloud_ranges.py`), opt-in
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
python -m unittest discover -s . -p "test_*.py"    # all tests (~2,060, ~1 min, ~63 skips)
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

## Conventions

- The owner works on `main` and has allowed pushing to it directly.
- Commit messages: a plain subject, then a body that says what was wrong and why
  the change is right. Comments explain why, not what; match the file you are in.
- Every fix gets a test that would have caught it. Run the full suite before pushing.
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
- The network audit is the only active probing. It is off until `audit.enabled`,
  runs only when asked, only on private networks of /16 or smaller on a local
  interface, and never tries a credential.
- Review bundles leave the machine: by default no payloads, pcaps, query strings,
  cookies, credentials or tokens, and every file passes the secret audit.
- Threat data is downloaded and checked locally; nothing about the owner's
  traffic or files is sent out for lookups. The update check
  (`updates.check`) sends GitHub only NetSentinel's version, and an update is
  installed only when the owner clicks, after its signature verifies. (Owner's
  decision, 2026-11-01.)
