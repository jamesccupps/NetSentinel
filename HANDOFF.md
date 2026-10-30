# Handoff: v1.9.0 in progress

Kept current during the work so it survives a context reset. Last updated
2026-10-29 by the local Claude Code session on James's desktop. Read
`CLAUDE.md` first. The approved plan, with findings by file:line, is outside the
repo at `C:\Users\james\.claude\plans\parallel-inventing-lovelace.md`.

## What James asked for

"Do it all": every open item from the previous handoff (v1.8.0), done in this
session. Four workstreams run as agents in git worktrees; the main session does
workstream C and the integration.

## Decisions (James, 2026-10-29)

- **Browser controls:** start/stop monitoring and acknowledge alerts from the
  dashboard, token-gated like uploads and only while bound to loopback. The
  CLAUDE.md hard rule and the `src/headless.py` design notes are being updated to
  say exactly that. The same gate covers verdicts, review bundles and audits.
- **GeoIP:** DB-IP Lite (CC BY 4.0, DB-IP credited in the app), downloaded on
  opt-in, read with `maxminddb`.
- **Lookups:** downloaded lists only. Nothing about traffic or files is sent out.
- **New dependencies:** `maxminddb`, `py7zr`, `python-evtx`. `.rar` is reported
  as not opened, since opening it needs non-free UnRAR.
- **netmon summariser button:** behind `--allow-summarise`, off by default. It
  previews the redacted payload and estimated tokens, and a second click sends.
- **Release:** v1.8.0 is tagged at `7d6fc3c` when James says so. All of this is
  v1.9.0. Never push a tag without asking.
- **Port:** the dashboard moved to 8737; 8787 is James's localcast.

## Status

### Pushed

- `7d6fc3c`: the Windows fixes, port 8737 and the Windows CI job.

### On local `main`, not pushed

- `9cd7361`: browser start/stop/acknowledge, plus the monitoring lifecycle fixes:
  - idempotent start, per-run stop events, no double capture;
  - the feature store restarts with monitoring;
  - alerts autosave;
  - cooldowns for IOC and ML alerts.
- `2dfde84`: CPU, RAM, drops and sampling on the dashboard; the
  `performance.low_priority` option; incidents bounded; the config file read as
  UTF-8 with BOM; the Settings threshold row fixed.
- `f39cf4b`: review mode (`src/review.py`), verdicts, `ConfirmedFalsePositives`,
  and registrable-domain learning (`src/public_suffix.py`).
- `9d986db`: fixes found by a live run:
  - `--review` crashed at startup;
  - VLAN-tagged frames got snippets of all traffic;
  - verdicts were tied to multicast addresses;
  - mDNS digest lines were wrong.
- `204b503`: CI moved to `checkout@v5`, `setup-python@v6`, `upload-artifact@v6`
  (Node 24).
- `ae3a375`: merge of workstream E, the opt-in subnet audit (`src/audit.py`).
- `3f5609b`: the audit wired into the dashboard (Audit page) and the desktop
  app (Audit button, Settings toggle).

The full suite passed at 1,512 tests with 53 skips before E merged; E added 78
tests.

### Running as agents (worktrees under `.claude/worktrees/`, gitignored)

Each commits to its own branch, `worktree-agent-<id>`, on top of `7d6fc3c`.
Review each diff, then merge with `git merge --no-ff refs/heads/<branch>`.

- **A, live detection** (`src/ids_engine.py`, `capture.py`, `tls_inspect.py`,
  `threat_intel.py`, `pcap_analyzer.py` and more):
  - H1: analyse this PC's own traffic;
  - H4: reassemble TLS ClientHellos, QUIC SNI;
  - H5: the PCAP analyser reuses the live parser;
  - H6: wire in `check_url`;
  - the feed-noise fixes;
  - capture threads stop per run;
  - a `packets_sampled_out` counter;
  - the new detections, and `src/geoip.py`.

  It was told that the URLhaus domains feed now returns HTTP 410.
- **B, file scanning** (`src/file_scan.py`, `batch_scan.py`, `web_scan.py`, new
  modules):
  - H2, secrets leaking through URLs, done first;
  - H3;
  - more secret types and Windows leaks;
  - archives (`.7z`, `.tar`, nested), `.evtx`, script patterns;
  - MalwareBazaar from a downloaded list;
  - an ignore-list backend;
  - throttled folder scans.
- **D, netmon** (`netmon/**`):
  - Host allowlist; acknowledge/snooze buttons;
  - the summariser button;
  - the digest checklist and an email digest;
  - GeoIP;
  - inbound 443 from non-Cloudflare;
  - the packet-side VLAN leak check.

E is finished and merged. Its API is in the `src/audit.py` docstrings:
`start_audit`, `current_job`, `local_networks`, `last_report`, `diff`.

### Integration still to do, after A, B and D merge

- **Merge:** review each branch's diff before merging. They never touch
  `config.py`, so expect few conflicts; test files may need hand-merging.
- **Config:** add A's and B's new keys to `DEFAULT_CONFIG` (`src/config.py`).
  Each agent's report lists them. The test in `test_regressions.py` requires
  every key to be read literally.
- **Dependencies:** add `maxminddb`, `py7zr` and `python-evtx` to:
  - `requirements.txt` and `pyproject.toml`;
  - both CI jobs' installs and the release build;
  - PyInstaller hidden imports, if needed.

  Also check that scapy's manuf database (`conf.manufdb`) gets bundled.
- **UI:**
  - an "Ignore this" action in both scan UIs (B's API);
  - a GeoIP toggle and the DB-IP attribution (A's `geoip.ATTRIBUTION`);
  - show `packets_sampled_out` in the dashboard's Engine panel.
- **Audit and IDS together:** once H1 lands, the audit's own connects will look
  like a port scan from this PC. In `app._verified_alert_gateway`, lower and
  annotate scan-type alerts from this host while `audit.is_running()`.
- **Docs:**
  - CLAUDE.md: the new rule wording and new modules;
  - README;
  - CHANGELOG v1.9.0: draft lines are in the agent reports and the commit
    bodies above;
  - this file, rewritten for the next session.
- **Version:** 1.9.0 in `main.py`, `pyproject.toml`, `setup.bat` and
  `src/__init__.py`. No tag.
- **Verify:**
  - the full suite, `tools/integration_check.py` and ruff;
  - a live headless run with `--review`, checking the dashboard in the browser
    and a bundle grep for secrets;
  - then ask James before pushing;
  - CI on Linux and Windows;
  - a manual `release` workflow build of the exe for him to test.

## Environment (this machine)

- **Python:** bare `python` is Inkscape's MinGW build. Use
  `.venv\Scripts\python.exe` (CPython 3.12), which has the test dependencies and
  ruff.
- **Tests in Claude's sandbox:** set `XDG_CACHE_HOME` to a scratch folder, or
  scapy cannot read `~\.cache` and about 175 tests skip silently. Expect about 53
  skips. Set `PYTHONIOENCODING=utf-8` too.
- **Git:** this repo commits as `148652101+jamesccupps@users.noreply.github.com`
  (repo-local config). GitHub rejects pushes that expose his Gmail.
- **Live test:** a headless run against a throwaway home folder works without
  admin (Npcap is installed). This network delivers 802.1Q-tagged frames to the
  desktop.
- **Leftover folder:** `C:\proc` was left by an old test run. The sandbox cannot
  delete it; James can.

## Left for James

- Test a fresh exe built from `main` once this lands.
- Tag v1.8.0 at `7d6fc3c`, if he wants it released first.
- For netmon on the sensor: `netmon geoip --update`, SMTP settings in the secrets
  file, `--allow-summarise`, `netmon bpf --verify` on an unfiltered sample (then
  delete the sample), and `netmon sync`.
- Turn on GeoIP and audits (Settings), and set review mode to taste.
- Expect more alerts once H1 lands. Review mode is how to sort them.
