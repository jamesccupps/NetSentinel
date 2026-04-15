# NetSentinel v1.4.0 Changelog

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
