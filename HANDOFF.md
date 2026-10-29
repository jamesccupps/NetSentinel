# Handoff: from the cloud session to local Claude Code

Written at the end of a Claude Code cloud session that ran out of budget. The
owner is testing the Windows build and will continue the work locally.
`CLAUDE.md` has the commands, conventions and hard rules.

## Where things stand

- `main` has **v1.8.0** (see `CHANGELOG.md`). It is **not tagged or released** yet:
  the owner is testing the exe first and will say when to publish. Release =
  push tag `v1.8.0`, which runs `.github/workflows/release.yml`.
- Test builds: run the `release` workflow by hand on `main` (Actions tab →
  release → Run workflow); the exe is the `NetSentinel-exe` artifact. The last
  test build predates commit `70139cd` (big folder uploads, github.com false
  alarm, scrollbar), so build a fresh one before the owner retests those.
- All ~1450 tests and the 14 integration checks pass; CI is green on 3.10–3.12.
- Nothing has been run against real traffic on Windows by Claude. The owner is
  the first real-world tester, so treat their reports as the ground truth.

## The owner's questions, with answers so far

**1. "The exe still says v1.0, there's nowhere to upload files, and I don't see
the browser integration."** Fixed in v1.8.0. The header label was hard-coded
(`src/gui.py`, now reads `src.__version__`). File scanning now takes any files,
not just captures (`src/file_scan.py`, `src/batch_scan.py`), from the desktop
**File Analyzer** tab and the browser **Scan Files** page. The browser dashboard
did not exist before; it does now (`src/webui/`, served by `src/headless.py`,
opened by **Open in Browser** in the GUI's top bar, or `--headless` for no window).

**2. "I uploaded a folder of ~40,000 files (~100 MB) in the browser; the upload bar
disappeared and nothing was scanned."** Fixed in `70139cd`. The server capped a
scan at 5,000 files and the error was a 4-second toast. Now: small files are
batched (about 4 requests per 6,000 files), `.git`/`node_modules`/media are left
out before uploading, the limit is 100,000 files, errors stay on screen, and big
reports are capped on screen. Verified in Chromium with 6,500 files (7 seconds).
**Still to do:** have the owner retry their real folder with a fresh build.

**3. "Why is github.com an alert?"** A false alarm, fixed in `70139cd`. The
URLhaus feed lists malware *URLs*; `src/threat_intel.py` turned each URL's host
into a malicious domain, so a payload stored on GitHub made github.com
"known-bad", in scans and in live monitoring alike. Shared hosting platforms
(`SHARED_HOSTING`) are no longer listed by host; exact URLs still match.
**Worth a follow-up:** look for the same pattern elsewhere. Any feed or rule that
condemns a whole domain or IP for one bad object on shared infrastructure (CDNs,
cloud IP ranges) will cause the same kind of noise.

**4. "There's no scrollbar on the Analysis Summary."** Fixed (desktop). The
browser page scrolls normally.

**5. "Are these the only things we should scan for, in files, in the IDS, and
automated network scanning?"** No. Before adding any of these, check `rules/`,
`src/ids_engine.py`, `src/dns_analysis.py`, `src/tls_inspect.py` and
`src/beaconing.py`, because some may already exist. Candidates, roughly by value:

- *Files* (today: IPs, domains, URLs, emails, MACs, private keys, cloud/API
  tokens, JWTs, passwords in settings and URLs, Luhn-valid cards, US SSNs, and
  threat-feed lookups):
  - SHA-256 of every file checked against a malware hash feed (MalwareBazaar).
  - More secret types: Azure storage keys and SAS tokens, GCP service-account
    JSON, Twilio, SendGrid, Mailgun, npm and PyPI tokens, Discord and Slack
    webhooks, Telegram bot tokens, Docker `config.json` auths, `.env` files.
  - Windows-specific leaks: passwords in `unattend.xml` and Group Policy
    `cpassword`, exported Wi-Fi profiles with `keyMaterial`, browser password
    export CSVs, KeePass files.
  - High-entropy strings that no pattern names.
  - UNC paths and internal hostnames (a map of the network).
  - `.7z`, `.tar.gz` and `.rar` archives and nested zips (only `.zip` today).
  - Windows event logs (`.evtx`).
  - YARA rules for scripts and binaries (encoded PowerShell and the like).
  - A per-value "ignore this" list for known false positives.
- *IDS / live monitoring:*
  - DNS tunnelling (long, high-entropy labels; TXT volume).
  - ARP spoofing and gateway MAC changes.
  - Rogue DHCP.
  - LLMNR/NBT-NS poisoning (Responder).
  - Lateral movement between LAN hosts over SMB, RDP or WinRM.
  - Per-host upload anomalies (exfiltration).
  - JA3/JA4 TLS fingerprints against known-bad lists.
  - Self-signed or expired certificates on outbound TLS.
  - Newly registered domains.
  - Cryptomining (stratum) connections.
  - New devices with MAC vendor (OUI) names.
  - Country and ASN of destinations (needs a GeoIP database: owner's decision).
- *Automated network scanning* (NetSentinel is passive today): an **opt-in**
  audit of the owner's own subnet only.
  - Discover hosts with an ARP sweep.
  - Port-scan the top ports of known devices, rate-limited.
  - Flag risky open services: Telnet, SMB on workstations, RDP, VNC, UPnP,
    admin web UIs.
  - Check TLS certificate expiry on internal services.
  - Diff against the last audit, so newly opened ports stand out.
  - Never try credentials, and never scan anything but the local networks the
    owner chooses.

**6. "Is it optimized so it doesn't take all the computer's resources?"** Partly,
and it has not been measured on real traffic.

What exists:
- The capture queue is bounded at 2,000 packets (`src/capture.py`).
- Under load it samples (1 in 2, then 1 in 4 packets) rather than falling
  behind. This shows as `sample_rate` in the stats, and detection is thinner
  while it is above 1.
- The alert-verification queue is bounded at 500.
- File scans read one file at a time, read at most 64 MB of any file, and
  extract zip members to disk one at a time.
- The dashboard polls every 2–5 seconds.

The biggest known cost is the PCAP ring buffer: `capture.pcap_buffer_packets`
defaults to 150,000 packets, up to ~225 MB of RAM. Lower it if memory matters.

To do:
- Measure CPU and RSS over an hour of real traffic with psutil.
- Show process CPU, RAM, drops and `sample_rate` on the dashboard.
- Add an option to run at below-normal process priority.
- Throttle big folder scans.
- Check that in-memory alert history and device tables are bounded.

**7. "I want a test mode that captures my real traffic, so I can give the
report, the alerts and the actual traffic to Claude chat and it can judge which
alerts are real."** Not built yet; this is the most useful next feature. Pieces
that exist: continuous recording with rotation (Capture tab), `pcap_on_alert`
(saves the traffic behind alerts, narrowed to the hosts involved, at or above
`pcap_on_alert_severity`, default CRITICAL), alert export (JSON/CSV), headless mode.

Proposed **review mode** (a `--review DIR` flag and a Settings toggle):
- While it runs:
  - Save traffic for alerts of every severity, not just CRITICAL.
  - Keep a rolling full capture within a disk budget.
  - Write `alerts.jsonl` with each alert's evidence and the name of its pcap
    snippet.
- **Build review bundle**, a folder or zip small enough for a chat upload
  (under ~20 MB, ~30 files):
  - `summary.md`: counts by rule, top hosts, and rules firing repeatedly on
    the same host (the likely false positives).
  - `alerts.json`.
  - For each alert, a **text** traffic digest of its snippet: one line per
    packet with time, addresses, ports, protocol, DNS names, TLS SNI and HTTP
    host/path. Claude chat cannot read pcap files; it can read text.
- **Privacy, by default** (the bundle leaves the owner's machine):
  - No payloads and no raw pcaps unless the owner opts in.
  - Credentials and cookies masked; HTTP query strings dropped.
  - An option to pseudonymise LAN addresses.
  - The hard rules in `CLAUDE.md` apply.
- Optional: record a verdict (real / false positive) per alert, then feed
  confirmed false positives into `src/baseline_whitelist.py` or rule tuning.

Until it exists, a manual version works:
1. Set `pcap_on_alert_severity` to `LOW` in the config.
2. Run for a day.
3. Export alerts as JSON.
4. Share the alerts plus a text summary of the relevant pcaps, made with tshark.

## Other open work

- **Desktop/dashboard:**
  - Start/stop monitoring from the browser. The GUI keeps its own `_monitoring`
    state, so it needs syncing from `capture_engine.is_running`.
  - An acknowledge button for alerts in the browser.
  - The dashboard is not yet checked in the real exe on Windows; the owner is
    doing that.
- **CI:** GitHub warns that `actions/checkout@v4`, `actions/setup-python@v5` and
  `actions/upload-artifact@v4` run on deprecated Node 20. Move to the majors
  that run on Node 24.
- **netmon** (`netmon/README.md`):
  - A summariser button in its web UI. The owner has to decide how it is gated.
  - Web UI buttons for acknowledge/snooze/maintenance (API routes exist).
  - An open-items checklist in the digest, and an email digest.
  - Country/ASN for new egress destinations (GeoIP decision).
  - "Inbound 443 from non-Cloudflare above baseline".
  - The packet-side VLAN leak check.
  - Validation on real data: the owner's captures, `netmon sync` for the real
    profile, and `netmon bpf --verify` on the sensor. Keep all of it out of
    the repo.
