# NetSentinel — notes for Claude Code

Read `HANDOFF.md` first: it has where the work stands, the owner's open
questions with answers so far, and the task list.

## What this is

- **NetSentinel** (`main.py`, `src/`): a Windows-first network monitor and IDS with
  a Tk desktop GUI, a browser dashboard served at `http://127.0.0.1:8787/`, and a
  headless mode (`--headless`). Packet capture via Scapy + Npcap, signature IDS
  (`src/ids_engine.py`, `rules/`), ML anomaly detection, threat feeds, forensics,
  PCAP analysis, and file/folder/zip scanning for leaked secrets and indicators.
- **netmon** (`netmon/`, tests in `netmon_tests/`): a separate site monitor for a
  Linux sensor, driven by a YAML site profile. See `netmon/README.md`. Only the
  fictional `netmon/profiles/example-site.yaml` belongs in the repo.

## Commands

```
pip install scapy psutil scikit-learn numpy cryptography pyyaml   # test deps
python -m unittest discover -s . -p "test_*.py"    # all tests (~1450, ~2.5 min)
python tools/integration_check.py                  # 14 integration checks
ruff check --select E9,F63,F7,F82 .                # what CI fails on
python main.py                                     # GUI + dashboard
python main.py --headless                          # dashboard/API only
python -m src.batch_scan PATH... [--skip GLOB] [--json]
```

CI (`.github/workflows/test.yml`) runs the tests on Python 3.10, 3.11 and 3.12.
Code must work on 3.10: no multi-line expressions inside f-strings, and remember
3.10's `fromisoformat` only takes 3 or 6 fractional digits.

## Releasing

Bump the version in `main.py` (APP_VERSION), `pyproject.toml`, `setup.bat` and
`src/__init__.py`; add a `CHANGELOG.md` section; push a `vX.Y.Z` tag.
`.github/workflows/release.yml` builds `NetSentinel.exe` on Windows and attaches
it with a SHA-256 to the GitHub release. Running that workflow by hand
(workflow_dispatch) builds the exe as an artifact without releasing.
Publishing a release is the owner's call: ask before pushing a tag.

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
  no TLS decryption.
- The HTTP server binds to localhost by default and cannot change configuration
  or monitoring. Uploads need the per-process token the dashboard page carries,
  and loopback binds refuse foreign Host headers. Keep it that way.
