# Handoff: v1.9.0 released

Kept current during the work so it survives a context reset. Last updated
2026-10-30 by the local Claude Code session on James's desktop. Read `CLAUDE.md`
first. The approved plan, with its findings by file:line, is outside the repo at
`C:\Users\james\.claude\plans\parallel-inventing-lovelace.md`.

## Where it stands

**v1.9.0 is released** (James asked, 2026-10-30). The tag `v1.9.0` is at
`4344e3c`, after CI passed on all five jobs. Release run #5 built the exe and
published https://github.com/jamesccupps/NetSentinel/releases/tag/v1.9.0 as
Latest, with `NetSentinel.exe` (81.6 MB), `NetSentinel.exe.sha256` and the
CHANGELOG section as notes. v1.8.0 was never tagged (`7d6fc3c` if wanted).

Every open item from the v1.8.0 handoff is done, as version 1.9.0.
`CHANGELOG.md` has the full list. Status:
- **Commits:** pushed to `main` as `11366aa` on 2026-10-29, with James's OK. That
  is 36 commits past `7d6fc3c`, which v1.8.0 can be tagged at.
- **Tests:** 2,100 unit tests pass (63 skips), as do the 14 integration checks and
  ruff.
- **Live run:** a headless run with `--review` on real traffic was checked in the
  browser. Start/stop, acknowledge, verdicts and bundle building all worked, and
  the bundle had no secrets, cookies, tokens or query strings. That run found
  four bugs, all fixed in `9d986db`.
- **Not run against real hardware:** the network audit (loopback and fakes only),
  the GUI's new widgets (its logic is unit-tested), and netmon (synthetic data
  only).

How the work was done:
- **Workstream C, main session:** review mode, browser controls, resource
  display, lifecycle fixes.
- **Agents in git worktrees, reviewed and merged:**
  - A: live detection;
  - B: file scanning;
  - D: netmon;
  - E: network audit.

  Their worktrees under `.claude/worktrees/` (gitignored) can be removed once
  James is happy.

## Decisions (James, 2026-10-29)

- **Browser controls:** loopback only, and token-gated. The CLAUDE.md rule now
  says so.
- **GeoIP:** DB-IP Lite, opt-in, credited.
- **Lookups:** downloaded lists only.
- **New dependencies:** `maxminddb`, `py7zr`, `python-evtx`. `.rar` is not
  opened.
- **netmon summariser:** behind `--allow-summarise`, preview first.
- **Release:** this is v1.9.0. v1.8.0 can be tagged at `7d6fc3c`. No tag without
  asking.
- **Port:** the dashboard is on 8737, because 8787 is localcast.

## Since the push

- **Tray icon and Restart**, which James asked for after the first v1.9.0 exe
  (`src/tray.py`, `src/restart.py`, `--monitor`):
  - closing the window hides to the tray, and monitoring keeps running;
  - the tray menu has Open, Dashboard, Start/Stop, Restart and Quit;
  - Restart relaunches with the same arguments and `--monitor` if it was
    monitoring, and is offered after saving settings.
- **New dependencies:** pystray (LGPL-3.0) and Pillow.
- **Checked live on this PC:** the tray icon (it showed, updated and stopped)
  and the relaunch (the detached copy ran, with the arguments and the
  PyInstaller reset).
- **In a locally built exe (2026-10-30, `build_exe.bat` from `cbe6808`):**
  - Restart works. The log shows the old copy saving and exiting, then the new
    one resuming monitoring 8 seconds later.
  - Found by James: a dashboard tab opened before the restart refused every
    button with "missing or wrong token", because each process makes its own
    token. Fixed: on that refusal the page reads the new token from `/` and
    retries once (`src/webui/app.js: renewToken`). Checked in the browser
    against a server swapped underneath it.
  - Hiding to the tray, the tray menu and Quit leave nothing in the log; James
    reports on those.
  - The ML warning "isolation_forest.pkl failed integrity check" is expected.
    The model is from April, before model files were signed, and is retrained
    at 200 samples.
- **Review mode** is on in James's config (`~\.netsentinel\review`).

## First review, 2026-10-30 (6 alerts, 13:36–13:41, all false positives)

This PC is 192.168.8.32 (Gigabyte NIC d8:5e:d3:07:16:a7).
- **3× LOW "HTTP Server Info":** plain-HTTP requests to update.eset.com,
  ctldl.windowsupdate.com and clientconfig.akamai.steamstatic.com. The "sensitive
  data" was the servers' own `Server:` header.
- **HIGH "Suspicious User Agent":** `HeadlessChrome ... Edg/157` fetching
  edge.microsoft.com/browsernetworktime. It is James's own Beam perf test
  (`node test\perf\windows-rc.mjs`, Desktop\beam), which runs headless Edge with
  a throwaway profile under Temp and remote debugging on 127.0.0.1:8809.
- **HIGH NAME-POISONING:** this PC answering mDNS for 4 UUID names, 5 seconds
  after that test started Edge. Those are WebRTC's random `.local` names for its
  own addresses.
- **MEDIUM insecure HTTP service:** an Edge update download from
  msedge.b.tlu.dl.delivery.mp.microsoft.com, which is plain HTTP by design (the
  content is signed).

Two more arrived after the review, both of the first kind: Let's Encrypt
(yr1.c.lencr.org) and ESET again.

No verdicts were recorded. A false-positive verdict suppresses by IP, and here
that would hide real Responder alerts from this PC.

**NetSentinel bugs this review found.** All 7 are fixed, with tests in
`test_first_review.py` that fail on the old code. They were pushed as `62c0740`
on 2026-10-30, and CI is green on all five jobs. The real review folder now
builds a readable bundle from the command line. A local exe with the fixes was
built at 13:56 and is waiting for James to test it.

**Mouse wheel (James, 2026-10-30):** the wheel did not always scroll. Fixed in
`src/gui.py` (`on_mousewheel`, `wheel_scrollable`; tests in
`test_mouse_wheel.py`), committed locally. The exe needs rebuilding for it once
James closes the running one.
1. **The PC's own address is listed as a gateway.**
   `net_detect.detect_default_gateway` takes every address on the
   `route print 0.0.0.0` line, including the Interface column. The log shows
   `Gateways: ['192.168.8.1', '192.168.8.32']`.
2. **The command-line bundle's traffic digests are unreadable.**
   `python -m src.review build` never imports scapy's layers, so every packet
   reads "Raw". Building in the app is fine.
3. **The digest buries the alert's own connection.** When the alert involves
   this PC, the snippet holds all of its traffic, and the digest's first 400
   lines miss the alert's own flow.
4. **NAME-POISONING counts WebRTC's UUID mDNS names.**
5. **"HTTP Server Info" from internet servers** is reported as "[LIKELY THREAT]
   Sensitive Data in Transit".
6. **Plain-HTTP software updates** (Windows Update, Edge delivery) are reported
   as insecure services.
7. **The verifier calls every FORENSICS-SENSITIVE-DATA alert "LIKELY THREAT
   70%"**, whatever the data type.

## Open questions for James

- **QUIC and the "no TLS decryption" rule.** Live detection now reads QUIC
  Initial packets for the server name. Those keys come from the public
  connection ID (RFC 9001) and the packets hold only the ClientHello, which TCP
  TLS sends in the clear anyway. Is that within the rule? If not, it should be
  switched off.
- **abuse.ch.** URLhaus and MalwareBazaar now need a free Auth-Key, and the
  terms allow free use only for not-for-profit purposes. Without a key,
  URLhaus is off and file hashes are checked only against lists he provides.
- **Alert volume.** The monitoring PC's own traffic is now inspected, so alert
  volume will rise. Run review mode for a day and import the verdicts.

## Next steps

1. Released. Next, whatever James's use of 1.9.0 turns up. Review mode stays on:
   build a bundle when alerts come in, go through them, and fix detectors
   rather than suppressing by IP where a whole class is wrong.
2. The mouse-wheel fix (`4344e3c`) is in the release. James has not yet run a
   build that has it.
3. CI notes: failing tests show up as public annotations
   (`tools/ci_failures.py`), because the logs need a GitHub sign-in. GitHub's
   jobs endpoint sometimes answers 500; `commits/<sha>/check-runs` works.

## Left for James

- Test the new exe. In Settings: GeoIP, Network audit, Review mode, and lower
  priority if wanted.
- **netmon on the sensor:**
  1. Regenerate the capture filter (`netmon capture ... --command`), update
     `netmon-capture.service`, and restart it.
  2. Take an unfiltered sample and run `netmon bpf --profile ... --verify sample`,
     which must exit 0. Also run `--diagnose-untagged sample`. Delete the sample
     afterwards.
  3. `pip install maxminddb`, then `netmon geoip --update --dir
     /var/lib/netmon/geoip`, and set `geoip: directory:` in the profile. Repeat
     the update monthly.
  4. Put the `smtp_*` keys in `secrets.json` (mode 600) for the email digest.
  5. For the summariser: add `--allow-summarise` (and `--allow-edit`) to
     ExecStart, put `anthropic_api_key` in the secrets file, and
     `pip install anthropic`.
  6. List Cloudflare-published hosts under `cloudflare: origins:`. Fill in
     `router_macs` if it is empty.
  7. Check one port-forwarded flow in a UniFi export: does it record the WAN
     address or the internal one?
  8. Run `netmon sync` for the real profile, keeping it out of the repo.
- Delete `C:\proc`, left by an old test run.

## Environment (this machine)

- **Python:** bare `python` is Inkscape's MinGW build. Use
  `.venv\Scripts\python.exe` (CPython 3.12), which has all the dependencies and
  ruff.
- **Tests in Claude's sandbox:** set `XDG_CACHE_HOME` to a scratch folder (else
  about 175 tests skip silently; expect about 63 skips) and
  `PYTHONIOENCODING=utf-8`.
- **Git:** this repo commits as `148652101+jamesccupps@users.noreply.github.com`.
  GitHub rejects his Gmail on pushes.
- **Network:** delivers 802.1Q-tagged frames to the desktop. A headless run
  against a throwaway home folder works without admin.
