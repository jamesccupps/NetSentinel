# NetSentinel Changelog

## v1.5.0 — Audit remediation

A full review of the codebase (see `AUDIT.md`) found one exploitable security bug,
several defects that silently defeated the detection logic, and a set of documented
features that were not actually wired up. This release fixes all of them and adds
regression tests so they stay fixed.

**144 unit tests** (up from 100) plus 14 integration checks. CI runs the suite on
Python 3.10, 3.11 and 3.12.

### Security

- **Command injection in the Authenticode check (critical).**
  `process_verify._check_signature` interpolated an executable path into a PowerShell
  `-Command` string. The path comes from `psutil.Process(pid).exe()`, PowerShell expands
  `$(...)` inside double-quoted strings, and `$`, `(` and `)` are legal in Windows
  filenames — so an unprivileged user could get code execution in a process that ships
  with `--uac-admin`. The path is now passed in an environment variable and read with
  `-LiteralPath`; the PowerShell program is a module constant.
- **Credential vault storage policy.** Full plaintext secrets were written to disk for
  20+ protocols. Only **masked** values are stored now; raw storage is opt-in via
  `forensics.store_raw_credentials`.
- **Vault key derivation.** The key is still hostname+username by default (documented
  clearly as obfuscation, not confidentiality), but setting `forensics.vault_passphrase`
  now switches to scrypt over a random salt. The home-grown XOR fallback is gone —
  `cryptography` is required and the vault fails closed.
- **The README claimed AES-256.** Fernet is AES-128-CBC + HMAC-SHA256. Corrected
  everywhere, including in the GUI.
- **File permissions.** `~/.netsentinel/` is created `0700` and sensitive files `0600`
  where the platform supports it. Previously `0644`.
- **`forensics_log.json` no longer contains credential material.** It stored
  `value_masked` despite documenting "metadata only"; `_mask()` reveals the leading
  characters of short secrets.
- **Model files are authenticated.** `pickle.load()` from a user-writable directory in
  an elevated process was a privilege-escalation primitive. Models now carry an HMAC
  keyed outside the data directory, and a feature-count mismatch is detected on load
  instead of silently disabling scoring.
- **Threat feed downloads are bounded** (64 MB) and refuse to follow a redirect off HTTPS.

### Detection correctness

- **The baseline whitelist never stopped learning.** `app._on_packet` fed it
  unconditionally, so any domain or IP seen three times marked itself "normal" and
  permanently suppressed DNS tunnelling, bad-TLD, beaconing and full-severity exfil
  alerts for it — an attacker's own infrastructure whitelisted itself after four packets.
  Observation is now gated on `is_learning`.
- **ML rate features were pinned to constants.** The analysis loop passed a rolling
  5000-packet buffer while claiming a 5-second window, so `packets_per_sec` was
  `5000/5 = 1000.0` regardless of real traffic. The window is now time-bounded and the
  extractor divides by the span the packets actually cover.
- **`direction_asymmetry` was always 0.** It computed `abs(N - N)` by counting packets
  per source and per destination. It now measures byte imbalance relative to local hosts.
- **`DATA-EXFIL` fired on downloads.** Bytes were accumulated against `dst_ip` with no
  direction check, so a large download raised a HIGH "data sent to *your own IP*". Only
  traffic leaving the local network is counted now.
- **TLD checks matched substrings.** `query.endswith(tld.lstrip('.'))` flagged `laptop`,
  `desktop`, `rooftop`, `network`, `forest`, `webcam`, `uplink` and `homework` — all of
  which occur as single-label LLMNR/NetBIOS lookups. Matching is now label-based in both
  the IDS and the threat-intel engine.
- **`ODD-HOURS` hourly suppression lasted 150 seconds.** Its marker lived in
  `_alert_cooldowns`, which the pruner clears at `cooldown_sec * 5`, so the rule fired
  roughly 24x/hour instead of once. Long-lived suppressions have their own store.
- **`rules/default_rules.json` was never loaded.** Shipped, bundled by PyInstaller and
  documented, but nothing read it. It is now loaded at import, with a user copy in
  `~/.netsentinel/rules/` taking precedence. `.info` and `.biz` were removed from its
  TLD list as too noisy.
- **`ml.anomaly_threshold` controlled two unrelated things** — Isolation Forest
  `contamination` and the alert gate — in opposite directions. Split into
  `ml.contamination` and `ml.alert_threshold`; the old key is still honoured.
- **Process attribution was blank for almost every packet.** The throttle gated the
  lookup rather than the refresh, so roughly one packet per 5 seconds got a process name.
  The psutil enumeration now runs on a background thread and every packet reads the cache.
- **`startswith('172.')` covers 172.0.0.0/8**, not 172.16.0.0/12, so public addresses in
  172.0-15 and 172.32-255 were treated as private. Replaced with proper `ipaddress` checks.
- **BACnet service names were wrong.** Confirmed and unconfirmed services are separate
  namespaces that both start at 0; a single dict meant `Time-Synchronization` and
  `Who-Has` resolved to `CreateObject` and `DeleteObject`.

### Reliability and performance

- **Slow verification moved off the packet thread.** IOC alerts triggered file hashing,
  a PowerShell call and a VirusTotal lookup — each with a 10-second timeout — inline on
  the packet worker, so detecting something suspicious stalled the whole pipeline.
  Alerts now publish immediately and deepen asynchronously.
- **Forensics alert scanning is incremental.** It re-scanned every finding on every
  packet; it now reads from a cursor. Duplicate credentials no longer re-encrypt and
  rewrite the entire vault on each repeat packet.
- **Beaconing detection is a single pass.** It rebuilt the source set per destination by
  rescanning the whole window — O(packets x destinations) every cycle.
- **`DeviceLearner` only profiles local devices.** Every remote internet IP used to
  become a "device on your network": one browsing session produced 3000+ profiles and a
  1.2 MB JSON file. Per-device sets are now trimmed as well.
- **Alert history.** `save_alerts()` hardcoded `[:500]` while `max_stored` defaults to
  5000, and `_load_alerts` inverted the order on restore. Both fixed, plus periodic
  autosave so a crash no longer discards the session.
- **Desktop notifications flush on a timer.** The batch only flushed when the *next*
  alert arrived, so a burst followed by silence — what an incident looks like — was
  never delivered.
- **All persistence is atomic** (temp file + fsync + rename). Every save path was a
  full rewrite, so an interruption truncated the file and the loader silently started
  from empty.
- **`get_stats()` returns a real snapshot.** `dict()` is shallow, so callers received
  the live containers the worker keeps mutating.
- **PCAP writer.** A failed rotation left recording permanently dead against a closed
  handle; file I/O no longer happens under the buffer lock; the link type is
  configurable instead of hardcoded to Ethernet; and old recordings are pruned
  (`capture.pcap_max_files`) so continuous capture cannot fill the disk.
- **Dead state removed:** `_recent_connections`, `_recent_dns`, `_dhcp_devices`,
  `_smb_versions`, the IDS's never-written mDNS/LLMNR trackers, `_connection_timings`,
  `BaselineProfile._history` and `_dns_pairs`. The ARP table and the escalating exfil
  thresholds are now pruned.

### Configuration

All 56 keys in `DEFAULT_CONFIG` are now read by the code. Sixteen were dead, including
`forensics.enabled`, `forensics.save_credentials`, `forensics.retention_days`,
`verification.check_signatures`, `whitelists.domains`, `whitelists.processes` and
`blacklists.domains` — setting any of them appeared to work and did nothing. Retention
is now enforced at startup, and a new `BL-DOMAIN` rule backs the domain blacklist.

### Tests and project

- New `test_regressions.py`: 42 tests, one per audit finding.
- `test_live.py` had a failing assertion and called `sys.exit()` at import, which broke
  `unittest discover` and pytest collection. Fixed and moved to
  `tools/integration_check.py`; `test_detections.py` (which contributed 0 tests) moved
  to `tools/simulate_attacks.py`.
- Added GitHub Actions CI, `pyproject.toml`, `SECURITY.md` and a ruff configuration.
- Version strings reconciled (`main.py`, `src/__init__.py`, `setup.bat` disagreed).

---

## v1.4.0

## New: Passive Network Learning (Zero-Config)

NetSentinel now **learns your network automatically**. No hardcoded IPs, domains, or device lists.
Drop it on any network — home, office, data center — and it adapts.

### Device Discovery (`src/device_learner.py`)
- Passively discovers all devices from ARP, DHCP, mDNS, and traffic patterns
- Classifies each device as **gateway, workstation, IoT, printer, camera, server, or database**
  based purely on observed behavior (port usage, DNS patterns, traffic profiles)
- Detects gateways by observing which IPs respond to ARP for many targets
- Persists device inventory to `~/.netsentinel/data/learned_devices.json`
- New **Devices tab** in GUI with device table and auto-refresh

### Baseline Whitelist Learning (`src/baseline_whitelist.py`)
- During the ML baseline learning period (default 2 hours), records every domain,
  IP, port, and periodic beacon pattern observed as "normal for this network"
- After learning completes, the IDS and ML engine automatically suppress false positives
  for learned-normal patterns:
  - DNS tunnel and suspicious TLD rules skip learned domains
  - Beaconing detection skips learned periodic patterns
  - Data exfiltration alerts downgrade to MEDIUM for learned destinations
- Persists to `~/.netsentinel/data/baseline_whitelist.json`
- Supports user-configured additions via `config.json` → `whitelists.dga_whitelist_suffixes`
  and `whitelists.dga_whitelist_exact`

### Alert Correlation (`src/alert_correlator.py`)
- Groups related alerts into **Incidents** by source IP and time proximity (5-min window)
- Detects **escalation chains**: Recon → Attack, Threat Intel → Exfiltration,
  Credential Exposure → Brute Force
- Escalation incidents automatically bump to at least HIGH severity
- Turns 50 noisy alerts into 1 clear incident with a narrative summary
- New **Incidents tab** in GUI showing incident timeline with severity coloring

### PCAP Export (`src/pcap_writer.py`)
- **Ring buffer** of raw packets (last ~5 minutes at 500 pps)
- **"Export Last 5 Min"** button exports buffer to standard `.pcap` file
- **Continuous recording** with Start/Stop and auto-rotation at 100 MB
- **Capture file browser** in the new **Capture tab**
- Files saved to `~/.netsentinel/captures/`
- Buffer size and file rotation configurable via `config.json` → `capture.pcap_buffer_packets`
  and `capture.pcap_max_file_mb`

---

## Additional Fixes (post-test review)

- **DeviceProfile Counter trimming** — `dst_ports_used`, `dns_domains`, and `protocols_used`
  Counters are now trimmed to top-100/20 entries during periodic classification to prevent
  unbounded memory growth on long-lived devices.
- **AlertCorrelator persistence** — Incidents are now saved to `incidents.json` on shutdown
  and restored on restart (last 200 incidents preserved).
- **BaselineWhitelist `_dns_pairs` cap** — Capped at 50,000 entries to prevent unbounded growth.
- **PcapWriter configurable buffer** — Ring buffer size and max file size now configurable
  via `config.json` instead of hardcoded values.

---

## Bug Fixes (22 total)

### Critical (data corruption / incorrect behavior)
1. **Alert ID race condition** — `Alert._counter += 1` was not thread-safe.
   Replaced with `itertools.count()` (atomic in CPython).
2. **Capture stats race** — `stats['packets_captured'] += 1` ran without locks
   from the capture thread. Added dedicated atomic counters synced under lock.
3. **Forensics dedup collision** — credentials and sensitive data shared
   `_forensics_alerted_creds`. Split into separate sets.
4. **Unbounded `NetworkFlow.packet_sizes`** — plain list grew forever for long-lived flows.
   Removed entirely (was never consumed).

### Performance (hot-path optimizations)
5. **Set literals rebuilt per packet** — `CREDENTIAL_PORTS`, `COMMON_SERVICE_PORTS`,
   `STANDARD_OUTBOUND_PORTS`, `_PORT_NAMES`, `_SERVICE_NAMES` moved to module-level
   `frozenset`/dict constants. Eliminates ~500 set constructions/sec.
6. **O(n) DNS reverse scan → O(1)** — DNS-to-IP inference scanned up to 2,000 deque
   entries per packet. Replaced with `_latest_dns_by_ip` dict index.
7. **Cleanup runs every packet → every 1000** — `_periodic_cleanup()` called
   `time.time()` on every packet. Now uses a counter to skip the check.
8. **`_FEATURE_INFO` dict** — 18-entry dict rebuilt on every ML alert. Moved to module level.
9. **`top_talkers` pruned** — `defaultdict(int)` grew unbounded. Now pruned to top 500
   during flow cleanup.
10. **`dns_queries` list** — manual truncation replaced with `deque(maxlen=1000)`.

### Correctness
11. **Entropy calculation** — `entropy_dst_port` computed entropy of a unique *set*
    (always `log2(n)`). Now uses the frequency *distribution* of port usage.
12. **IPv6 blind spot** — IPv6 packets got `protocol="IPv6"` with no port extraction.
    Now extracts TCP/UDP ports, flags, and payload from IPv6 packets identically to IPv4.
13. **Data exfil counter reset** — after alerting, counter reset to 0 (lost evidence).
    Now uses escalating thresholds: 100 → 200 → 400 MB. Also baseline-aware.
14. **Time-of-day alert spam** — any 10KB+ packet at 3 AM triggered an alert.
    Now requires 50KB minimum and limits to 1 alert per source IP per hour.
15. **Config deep-merge** — `_deep_merge` used shallow copy. Override values with nested
    mutables were shared by reference. Now uses `copy.deepcopy`.
16. **Alert restore from disk** — `_load_alerts` loaded JSON but never reconstructed
    `Alert` objects. Historical alerts were silently discarded on restart. Fixed.
17. **`is_admin()` fallback** — returned `True` on unknown platforms. Now returns `False`.

### Reliability
18. **Splash screen dual-Tk** — `show_splash()` created a second `tk.Tk()` instance.
    Now uses `Toplevel` under a single root that's reused for the main GUI.
19. **Desktop notification spam** — 50 HIGH alerts in 10s = 50 notifications. Added
    batching (15s window) that summarizes: "12 new HIGH alerts in the last minute."
20. **Alert sound spam** — CRITICAL sounds had no cooldown. Added 10-second minimum.
21. **Feature store file handle** — no `__del__` or error recovery. Added safety net
    and flush error handling that resets file state on write failure.
22. **Bare `except:`** in GUI → `except Exception:` to avoid catching `SystemExit`.

---

## Architecture Improvements

- **GUI accepts reusable `tk_root`** — eliminates dual-`Tk()` bug and speeds startup
- **Capture engine accepts `raw_packet_callback`** — feeds PCAP writer without
  modifying the packet processing pipeline
- **IDS + ML engines accept `baseline_whitelist`** — injected by app after init,
  queried before raising heuristic alerts
- **Alert gateway feeds correlator** — every alert passes through correlation
  before reaching the GUI
- **Status bar** shows device count, active incidents, PCAP buffer size
- **3 new GUI tabs**: Devices, Incidents, Capture
- All learned data (devices, whitelist, alerts, incidents) saved on shutdown, restored on startup

---

## Test Suite

**100 tests total** (38 original + 62 new), all passing. Coverage includes:
- Thread safety: concurrent Alert ID creation from 4 threads (2000 IDs, zero duplicates)
- All 4 new modules: DeviceLearner, BaselineWhitelist, AlertCorrelator, PcapWriter
- All 22 bug fixes verified individually
- IDS + baseline whitelist integration (learned .xyz domains skip bad-TLD, unknown still fire)
- Edge cases: empty packets, None/empty fields, broadcast addresses, binary PCAP data
- Persistence roundtrips: save → reload → verify for devices, whitelist, alerts, incidents
- Escalation chain detection: Recon→Attack, ThreatIntel→Exfiltration
