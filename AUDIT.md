# NetSentinel — Full Repository Audit

**Audited:** v1.4.0 @ `cf7e43a` · 18,445 lines Python across 20 `src/` modules + 4 test files
**Scope:** security, detection correctness, reliability, performance, tests, docs, repo hygiene
**Method:** full source read + empirical reproduction of every finding marked *(verified)*

> ⚠️ **This document describes unfixed vulnerabilities in a public repository.**
> Reproduction payloads are withheld (see S1). Consider fixing S1, S2 and S3 before
> publicising this file further, and adding a `SECURITY.md` with a private disclosure
> channel.

---

## Executive summary

NetSentinel is an ambitious and genuinely well-structured project. The pipeline
separation (capture → queue → worker → engines → single verified alert gateway) is
sound, the alert *verification* layer that scores and downgrades findings is unusually
thoughtful, the Welford online-statistics implementation is numerically correct
(verified to 3e-10), and the evidence dictionaries attached to alerts are far more
useful than what most hobby IDS projects produce. The 100 documented tests pass.

The problems are concentrated in three places:

1. **One exploitable security bug** — a PowerShell command-injection sink reachable
   from an attacker-controlled filename, in a process that ships with `--uac-admin`.
2. **The core detection logic has several bugs that silently defeat it.** Most
   importantly, the "baseline whitelist" never stops learning, so an attacker's domain
   whitelists itself after four packets. Separately, the ML rate features are
   mathematically pinned to constants, one of the 18 features is structurally always
   zero, and the exfiltration rule fires on downloads.
3. **Claims outrun the implementation.** "AES-256" is Fernet/AES-128 with a key derived
   from hostname + username; `rules/default_rules.json` is never loaded; 16 of 56
   config keys — including `forensics.save_credentials` and `forensics.retention_days` —
   do nothing.

None of this is unfixable, and most of it is small in diff size. Priorities in
[Recommended order of work](#recommended-order-of-work).

---

## 1. Security

### S1 · Command injection in the Authenticode check → local privilege escalation
`src/process_verify.py:356-366` · **Critical**

```python
ps_cmd = (f'$sig = Get-AuthenticodeSignature -FilePath "{exe_path}"; ' ...)
subprocess.run(['powershell', '-NoProfile', '-Command', ps_cmd], ...)
```

> **Reproduction payload withheld.** This repository is public and the issue is
> unfixed. The mechanism and the fix are below, which is what a maintainer needs; the
> drop-in exploit string is deliberately not committed. Restore it here once a fix ships.

`exe_path` comes from `psutil.Process(pid).exe()` (`process_verify.py:162`) — i.e. from
whatever binary an unprivileged local user chose to run. PowerShell expands `$(...)`
subexpressions inside double-quoted strings, and `$`, `(`, `)` and backtick are all
legal characters in Windows filenames. An unprivileged user who controls the filename
therefore controls part of the `-Command` string, and the contents of a `$(...)` in that
position are executed. `build_exe.bat` passes `--uac-admin` and `main.py` requests
elevation, so the injected code runs as Administrator.
**(verified — the resulting command string was reproduced locally against a crafted path)**

The reachable path is: unprivileged process triggers any `IOC-SUSPICIOUS-PROC` /
`IOC-PROC-NAME` / `IOC-LISTEN-PORT` / `IOC-ACTIVE-THREAT` alert → `alert_verify.py:796`
→ `process_verify.verify_alert` → `_check_signature`.

**Fix:** don't interpolate into a script. Pass the path out of band:

```python
proc = subprocess.run(
    ['powershell', '-NoProfile', '-NonInteractive', '-Command',
     'Get-AuthenticodeSignature -LiteralPath $env:NS_TARGET | '
     'Select-Object Status,@{N="Publisher";E={$_.SignerCertificate.Subject}} | ConvertTo-Json'],
    env={**os.environ, 'NS_TARGET': exe_path}, capture_output=True, text=True, timeout=10)
```

Note `-LiteralPath`, not `-FilePath`, so wildcards in the name aren't globbed either.

### S2 · The credential vault provides no confidentiality
`src/forensics_db.py:39-47` · **High**

```python
machine_id = f"{socket.gethostname()}:{getpass.getuser()}:NetSentinel_Forensics_v1"
key_bytes = hashlib.sha256(machine_id.encode()).digest()
```

The key is a single SHA-256 over two public values and a constant that is in the source
tree. There is no secret, no salt, and no KDF. Anyone who obtains `credentials.enc`
almost certainly also knows the hostname and username — they are usually in the file
path, the backup name, or the machine itself. **(verified — decrypted a stored FTP
password using only `socket.gethostname()` and `getpass.getuser()`)**

Three further points:

- **The README says AES-256. It is AES-128.** Fernet is AES-128-CBC + HMAC-SHA256; the
  module's own comment says so (`forensics_db.py:31`) while the docstring three lines
  above says AES-256. For a security product this claim needs to be corrected everywhere
  (`README.md:29`, `forensics_db.py:11`).
- **Full plaintext passwords are stored**, not just masked ones — `raw_value=password`,
  `raw_value=f"{user}:{passwd}"` at 20+ call sites in `forensics.py` (lines 909-1175).
- **The XOR fallback** (`forensics_db.py:59-63`) is repeating-key XOR over JSON with a
  known plaintext prefix (`[{"id": "`). It is trivially recoverable. Since `cryptography`
  is a hard requirement, delete the fallback and fail closed instead.

**Fix:** either (a) stop storing raw values and keep only masked ones, or (b) derive the
key from a user-supplied passphrase via Argon2id/scrypt and require it to open the vault.
Option (a) is the smaller change and probably the right default.

### S3 · Vault, config and log files are world-readable
`src/forensics_db.py:88`, `src/config.py:21` · **High**

`~/.netsentinel/` and everything in it is created with the default umask — mode `0644`
observed. **(verified)** Combined with S2 this is effectively a world-readable plaintext
credential store. `config.json` additionally holds `verification.virustotal_api_key` in
plaintext.

Also: `forensics_log.json` is documented as "metadata only, no values"
(`forensics_db.py:14`) but stores `value_masked`, and `_mask()` reveals the first 3
characters (`forensics.py:2535`). For a 4-character password that is 75 % of it.
**(verified — log entry contains `"value_masked": "hun*****"`)**

**Fix:** `os.makedirs(..., mode=0o700)` plus `os.chmod(path, 0o600)` after each write of
`credentials.enc`, `sensitive_data.enc`, `forensics_log.json` and `config.json`; on
Windows set an ACL restricted to the owner SID. Drop `value_masked` from the log.

### S4 · Unpickling model files in an elevated process
`src/ml_engine.py:729-733` · **Medium**

`isolation_forest.pkl` and `scaler.pkl` are loaded with `pickle.load` from
`~/.netsentinel/models/`, a user-writable directory, by a process running as
Administrator. Any user who can write that directory gets code execution at the app's
privilege level. There is also no dimensionality check on load, so a stale model from a
different feature-vector length silently disables Isolation Forest scoring forever
(`analyze_window`'s `except` logs at DEBUG).

**Fix:** use `skops` or ONNX, or at minimum store a HMAC of the pickle keyed to a value
outside the data directory and refuse to load on mismatch. Validate `scaler.n_features_in_
== len(feature_names)` after load.

### S5 · Security switches that do nothing
`src/config.py` · **Medium**

16 of 56 config keys are never read. Several of them are the controls a user would reach
for first:

| Key | Documented meaning | Actual effect |
|---|---|---|
| `forensics.enabled` | turn credential scanning off | none — always on |
| `forensics.save_credentials` | don't write credentials to disk | none — always written |
| `forensics.retention_days` | purge after 365 days | none — kept forever |
| `verification.check_signatures` | disable Authenticode checks | none (and see S1) |
| `verification.auto_verify` | disable auto verification | none |
| `blacklists.domains` | block these domains | never consulted |
| `whitelists.domains`, `whitelists.processes` | suppression lists | never consulted |
| `capture.promiscuous`, `snap_length`, `buffer_timeout_ms` | capture tuning | never passed to Scapy |
| `gui.theme`, `max_log_lines`, `chart_history_minutes` | UI | none |
| `ml.features` | 10-feature list | ignored; 18 hardcoded in `TrafficFeatureExtractor` |

`forensics.save_credentials` and `retention_days` are the serious ones: a user who turns
credential storage off still gets passwords written to disk, and nothing ever expires
them. Either wire them up or remove them from `DEFAULT_CONFIG` and the README.

### S6 · Scope-creep code that encodes a specific target environment
`src/forensics.py:139-231, 1380-1540` · **Low, but worth a decision**

~250 lines of SKIDATA parking-system parsers (port 31769), E-ZPass agency code tables,
and BACnet/Modbus SCADA write-command detection sit in a general-purpose home-network IDS.
This reads as engagement-specific work left in place. In a public MIT repo it also
publishes the protocol details and control-channel layout of a named vendor's system.
Consider moving it behind a plugin interface or dropping it.

---

## 2. Detection correctness

These are the bugs that matter most, because they undermine the thing the tool exists to do.

### D1 · The baseline whitelist never stops learning — attackers whitelist themselves
`src/app.py:266-271` · **Critical**

`app._on_packet` calls `observe_dns()` and `observe_connection()` unconditionally, with
no `if self.baseline_whitelist.is_learning:` guard. The module docstring says learning
happens "during the initial baseline period (default 2 hours)". It never stops.

`is_learned_domain()` returns True once a base domain has been seen 3 times
(`baseline_whitelist.py:174`), and that suppresses `DNS-TUNNEL` and `DNS-BAD-TLD`
entirely. **(verified)**:

```
is_learning (baseline period ended 8 h ago): False
first sighting of the C2 domain              alerts: ['DNS-BAD-TLD', 'DNS-TUNNEL']
after the same domain is queried 3 more times  alerts: NONE
```

The same applies to destination IPs: three post-baseline connections to an exfil target
downgrade `DATA-EXFIL` from HIGH to MEDIUM and retitle it "(to known destination)"
**(verified)**. Beaconing suppression (`ml_engine.py:558`) rides on the same state.

An adversary needs four DNS queries to permanently blind the DNS detectors for their
own domain.

**Fix:** guard both calls with `is_learning`, or add an explicit "relearn" mode the user
opts into. The one-line version:

```python
if self.baseline_whitelist.is_learning:
    if pkt_info.dns_query:
        self.baseline_whitelist.observe_dns(...)
    if pkt_info.dst_ip and pkt_info.dst_port:
        self.baseline_whitelist.observe_connection(...)
self.baseline_whitelist.check_learning_complete()
```

### D2 · ML rate features are pinned to constants
`src/app.py:196, 391` + `src/ml_engine.py:117-118` · **Critical**

`self._packet_window = deque(maxlen=5000)` is appended to on every packet and **never
cleared**. `_analysis_loop` passes the whole buffer to `extract_from_window(..., window_sec=5)`,
which computes `packets_per_sec = len(packets) / 5`.

Once the deque saturates — which takes 10 seconds at 500 pps — `packets_per_sec` is
exactly `5000/5 = 1000.0` forever, regardless of real traffic, and `bytes_per_sec`
becomes `1000 × avg_packet_size`. **(verified)**:

```
actual traffic: 10 pkts/s sustained over 500 s
reported packets_per_sec = 1000.0   (100× the truth)
reported bytes_per_sec   = 200000.0
```

Two of the three headline features feeding the Isolation Forest, plus `dns_query_rate`,
are therefore near-constant. The baseline's standard deviation for them collapses toward
zero, which also inflates every z-score in the "what is unusual" evidence block.

**Fix:** either window the buffer by time —

```python
cutoff = time.time() - self._analysis_interval
packets = [p for p in self._packet_window if p.timestamp >= cutoff]
```

— or, better, derive `window_sec` from the actual span: `max(p.timestamp) - min(p.timestamp)`.

### D3 · `direction_asymmetry` is structurally always 0
`src/ml_engine.py:141-143` · **High**

```python
src_count[p.src_ip] += 1
dst_count[p.dst_ip] += 1
...
direction_asymmetry = abs(sum(src_count.values()) - sum(dst_count.values())) / max(total_dir, 1)
```

Both sums equal the packet count, so the numerator is always `abs(N - N) = 0`.
**(verified — identical output for all-one-direction, 49:1 skewed, and balanced windows.)**
One of 18 ML features carries zero information, and `app._FEATURE_INFO` advertises it to
the user as "Traffic Asymmetry — Imbalance between upload and download".

**Fix:** compare bytes by direction relative to the local host, e.g.

```python
up = sum(p.length for p in packets_window if p.src_ip in local_ips)
down = sum(p.length for p in packets_window if p.dst_ip in local_ips)
direction_asymmetry = abs(up - down) / max(up + down, 1)
```

### D4 · `DATA-EXFIL` fires on downloads and blames your own machine
`src/ids_engine.py:845-847` · **High**

```python
self._data_transfer[pkt_info.dst_ip] += pkt_info.payload_size
```

There is no direction check. For inbound traffic `dst_ip` is the local host, so bytes
you *receive* accumulate against your own address. **(verified)** — 2 MB downloaded from
`93.184.216.34` produced:

```
DATA-EXFIL [HIGH] Large Data Transfer
  description        : 1.0 MB sent to 192.168.1.50
  destination_ip     : 192.168.1.50      <- the user's own machine
```

Every large download becomes a HIGH exfiltration alert naming the victim's own IP as the
destination.

**Fix:** only accumulate when the source is local and the destination is not
(`net_env.local_ips` is already available to the engine).

### D5 · TLD checks match substrings, not TLDs
`src/ids_engine.py:768, 772` and `src/threat_intel.py:253` · **Medium**

```python
if query.endswith(tld.lstrip('.')):     # '.top' -> 'top'
```

Stripping the dot turns a label comparison into a raw suffix comparison.
**(verified)**:

| query | `DNS-BAD-TLD` fires |
|---|---|
| `laptop` | **yes** |
| `desktop` | **yes** |
| `my-laptop` | **yes** |
| `rooftop` | **yes** |
| `evil.top` | yes (correct) |
| `normal.com` | no (correct) |

`threat_intel.check_domain` has the same defect over a longer list (`.work`, `.click`,
`.link`, `.rest`, `.cam`, `.icu`, …), so `network`, `forest`, `webcam`, `uplink`,
`homework` and `oneclick` all return `Suspicious TLD` **(verified)**. Single-label
queries are routine on Windows LANs via LLMNR and NetBIOS, so this fires in practice.

**Fix:** `if domain.rsplit('.', 1)[-1] == tld.lstrip('.') and '.' in domain:` — or just
`domain.endswith(tld)` keeping the dot.

### D6 · `ODD-HOURS` hourly suppression is destroyed by the cooldown pruner
`src/ids_engine.py:896-899` vs `205-209` · **Medium**

Rule 12 stores its "one alert per IP per hour" marker in `self._alert_cooldowns` with a
3600 s horizon. `_periodic_cleanup` deletes every cooldown key older than
`cooldown_sec * 5` = 150 s by default. **(verified)** — the key is gone after 150 s, so
the rule can re-fire roughly 24× per hour instead of once. This silently undoes bug
fix #14 from the CHANGELOG (the pruner is fix #7).

**Fix:** keep long-lived suppressions in a separate dict with its own horizon.

### D7 · Two config defaults make the tool blind to bulk traffic
`src/config.py:31, 33` · **Medium — design, not a bug**

```python
"bpf_filter": "not (port 443 and tcp[tcpflags] & tcp-ack != 0 and tcp[tcpflags] & tcp-syn == 0)",
"max_pps": 500,
```

The default BPF filter drops **every established TCP/443 packet** — not just pure ACKs,
since `PSH|ACK` data segments also match `ACK set, SYN clear`. Only SYN and SYN-ACK
survive. On top of that, `max_pps: 500` drops everything above 500 pps *before* the IDS
and flow tracking see it (`capture.py:463-466`).

The consequence is that `DATA-EXFIL`, the byte-counting ML features, and the forensics
engine cannot observe the single most common exfiltration channel. That may be a
deliberate CPU trade-off, but it should be documented prominently rather than implied by
a regex in a config default — a user reading "detects data exfiltration" will not expect
HTTPS to be excluded.

### D8 · `anomaly_threshold` controls two unrelated things in opposite directions
`src/ml_engine.py:381, 470, 701` · **Medium**

The same value is used as the Isolation Forest `contamination` parameter *and* as the
decision threshold on the combined 0-1 score. Raising it makes the forest label more
points as outliers while simultaneously making the alert gate stricter. The README
documents only the first meaning. Also, `DEFAULT_CONFIG` says `0.25` while the code
default says `0.15` (`ml_engine.py:381`).

**Fix:** split into `ml.contamination` and `ml.alert_threshold`.

### D9 · Process attribution is blank for almost every packet
`src/capture.py:396-403` · **Medium**

```python
if now - self._last_process_lookup >= self._process_lookup_interval:   # 5 s
    self._last_process_lookup = now
    proc_name, proc_pid = _get_process_for_port(info.src_port)
    ...
    info.process_name = proc_name
```

The lookup is inside the throttle, so exactly one packet per 5 seconds gets a process
name; every other packet leaves `process_name` empty and alerts render
`'process': 'Unknown'`. The underlying port→process map already has its own 2-second
cache (`capture.py:150`), so the outer throttle only suppresses the cheap dict lookup.

**Fix:** move the throttle into `_refresh_port_process_map` only (it is already there)
and do the dict lookup on every packet. Better still, refresh the map from a background
thread — `psutil.net_connections()` currently blocks the capture thread.

### D10 · `rules/default_rules.json` is never loaded
**Medium**

The file is shipped, bundled by PyInstaller (`--add-data "rules;rules"`) and documented
in the README's project structure, but nothing reads it — the only reference to
`RULES_DIR` is the `makedirs` call in `config.py:15,21`. Its contents have already
drifted from the hardcoded rules (it lists ports 3127, 27374, 1080, 9999, 7777 and TLDs
`.info`, `.biz` that the code does not use). Editing it has no effect.

**Fix:** load it in `IDSEngine.__init__`, or delete it and correct the README.

---

## 3. Reliability and performance

### R1 · Forensics alert scan is O(findings) on every packet
`src/app.py:253, 278-340` · **High**

`_check_forensics_alerts()` runs per packet and iterates **all** of
`credentials_found`, `insecure_services` and `sensitive_data` each time, relying on
dedup sets to avoid re-alerting. The scan itself is never skipped. At 500 pps with a few
hundred findings this is ~10⁵ iterations/second, growing over the session.

Worse, `ForensicsDB.store_credential` is O(n) over stored credentials **and re-encrypts
and rewrites the entire vault file** on every call — including on the duplicate path
(`forensics_db.py:136-140`), which is the common case for a repeated HTTP basic-auth
session. That is a full-file encrypt + write per packet.

**Fix:** have `NetworkForensics` return only *new* findings (a counter index or a
callback), and make the vault append-only or batched.

### R2 · Blocking network and subprocess calls on the packet-processing thread
`src/alert_verify.py:796` → `src/process_verify.py:466-486` · **High**

The alert gateway is called synchronously from `ids_engine.inspect_packet`, on the
packet worker thread. For IOC alerts that chain reaches a VirusTotal HTTP request
(`timeout=10`) and a PowerShell invocation (`timeout=10`). While either is in flight the
worker stops draining the queue, which holds 2000 packets — so detecting something
suspicious is precisely when the sensor goes deaf.

**Fix:** move verification onto its own thread with a queue, or mark the expensive checks
as deferred and enrich the alert asynchronously.

### R3 · `_check_beaconing` is O(packets × destinations) every 5 seconds
`src/ml_engine.py:558, 570` · **Medium**

```python
src_ips_to_dst = set(p.src_ip for p in packets_window if p.dst_ip == dst_ip)
```

is inside a loop over every destination IP in the window. With 5000 packets and ~1000
destinations that is ~5 M comparisons per analysis cycle, repeated every 5 s over a
buffer that is mostly the same packets as last time.

**Fix:** build `dst_ip -> set(src_ip)` in the same single pass that builds `dst_times`.

### R4 · PCAP writer
`src/pcap_writer.py` · **Medium**

- `_rotate_recording` (line 176) has no error handling of its own. If the `open()` for
  the new file fails, the old handle is already closed, `self._recording` stays `True`,
  and every subsequent packet raises `ValueError: I/O operation on closed file` into the
  caller's `except Exception: logger.debug`. **Recording dies silently and never recovers.**
- `buffer_packet` holds `self._lock` while doing file writes and rotation, on the capture
  thread that the code's own comment says "must be fast".
- Default ring buffer is 150,000 packets ≈ **225 MB resident**, allocated whether or not
  the user ever exports.
- Link type is hardcoded to `PCAP_LINKTYPE_ETHERNET`; exports from non-Ethernet captures
  (loopback, some VPN adapters) will be misparsed by Wireshark.
- No cap on the `captures/` directory — continuous recording rotates at 100 MB
  indefinitely with no retention policy.

### R5 · DeviceLearner registers every remote internet IP as a "device on your network"
`src/device_learner.py:191-196` · **High**

`observe_packet` calls `_get_or_create(pkt_info.dst_ip)` with no locality check, so every
website, CDN edge and API endpoint becomes a `DeviceProfile`. **(verified)** — one
workstation, 3000 outbound connections:

```
real devices on the LAN : 1
entries in dl.devices   : 3001
of which private/LAN    : 14
learned_devices.json    : 1192 KB
```

Every entry is persisted and reloaded at startup, and the Devices tab — a headline
v1.4.0 feature — becomes a list of thousands of internet addresses classified as
`unknown`. `dev.mdns_services`, `src_ports_served` and `services_seen` are sets that are
never trimmed (only the three `Counter`s are, at `device_learner.py:226-233`).

**Fix:** only profile addresses in `net_env.local_subnets` (or `ipaddress.ip_address(ip).is_private`).

### R6 · Alert history loss
`src/alerts.py:153` · **Medium**

- `save_alerts()` writes only `list(self._alerts)[:500]` while `alerts.max_stored`
  defaults to 5000 — 90 % of history is discarded at shutdown. **(verified: 600 in
  memory → 500 on disk.)**
- `_load_alerts` uses `appendleft` over a newest-first file, so the restored order is
  **inverted** — the oldest restored alert appears at the top of the list.
  **(verified: first entry after reload is `alert-100`, not `alert-599`.)**
- `save_alerts()` is only called from `stop_monitoring()`. A crash, a kill, or a power
  loss discards the entire session's alerts.

**Fix:** drop the `[:500]` slice (or make it `max_stored`), use `append` on load, and add
a periodic flush.

### R7 · Batched desktop notifications can never be delivered
`src/alerts.py:252-266` · **Medium**

`_batch_notification` only flushes when the *next* alert arrives. If three HIGH alerts
fire and the network goes quiet, the batch sits in `self._notify_batch` indefinitely —
which is exactly the burst-then-silence pattern an incident produces. There is no timer.

**Fix:** flush from a `threading.Timer` or from the existing analysis loop.

### R8 · No atomic writes anywhere
`config.py:151`, `alerts.py:155`, `forensics_db.py:277`, `ml_engine.py:311`,
`baseline_whitelist.py`, `device_learner.py`, `alert_correlator.py` · **Medium**

Every persistence path is `open(path, 'w')` followed by a full rewrite. An interruption
mid-write truncates the file; the corresponding loader catches the exception and returns
`[]` or defaults, so the failure mode is **silent total data loss** on the next save.

**Fix:** one shared helper — write to `path + '.tmp'`, `flush()`, `os.replace()`.

### R9 · `get_stats()` is documented as a snapshot but aliases live state
`src/capture.py:648-652` · **Low (latent)**

```python
def get_stats(self):
    """Return current statistics (thread-safe snapshot)."""
    ...
    return dict(self.stats)
```

`dict()` is shallow, so `protocols`, `top_talkers` (both `defaultdict`) and `dns_queries`
(a `deque`) are handed out by reference and keep mutating. **(verified:
`snap['protocols'] is ce.stats['protocols']` → `True`.)**

In practice today's GUI consumers only touch the dicts through `sum()` and `sorted()`,
which CPython executes at C level without releasing the GIL, so I could **not** reproduce
a crash there — I'm flagging it as a broken contract rather than an active failure. The
deque is the real hazard: iterating a deque while another thread appends raises reliably
(**verified: 219 `RuntimeError: deque mutated during iteration` in 87k iterations**), and
`feature_store.get_recent_scores` does exactly that on a deque the analysis thread
appends to, once per second from `get_dashboard_data`.

Because `gui._update_dashboard` wraps the whole refresh in one
`except Exception: logger.debug`, any such failure blanks the entire dashboard tick —
metrics, charts and status bar — with no visible symptom.

**Fix:** `copy.deepcopy` the mutable members inside the lock, or return purpose-built
snapshots.

### R10 · Dead state still being maintained

| Location | Field | Status |
|---|---|---|
| `ids_engine.py:158` | `_dhcp_devices` | declared, never read or written |
| `ids_engine.py:165` | `_smb_versions` | declared, never read or written |
| `ids_engine.py:161-162` | `_mdns_responders`, `_llmnr_responders` | declared and *pruned* every cycle, never written (the real ones live in `forensics.py:712`) |
| `ids_engine.py:154` | `_recent_connections` | 5000-entry deque, written per packet, never read |
| `ids_engine.py:147` | `_recent_dns` | 2000-entry deque, written, never read |
| `ids_engine.py:130` | `_arp_table` | used, but never pruned |
| `ml_engine.py:403` | `_connection_timings` | declared, never used |
| `ml_engine.py:201, 225` | `BaselineProfile._history` | 10,000 × 18 floats written, never read (superseded by Welford) |
| `baseline_whitelist.py:56` | `_dns_pairs` | capped at 50,000, never read, not persisted |
| `baseline_whitelist.py:191, 196` | `is_learned_port`, `get_domain_confidence` | never called |
| `ids_engine.py:309-310` | `dst_domains`, `src_domains` | computed per packet, unused (`_create_alert` recomputes) |
| `alerts.py:301-317` | PowerShell toast fallback | builds a command string then `pass` |

Also: `ids_engine.py:842` creates `self._exfil_thresholds` lazily via `hasattr` on the
per-packet path, and it is never pruned.

### R11 · Shutdown is best-effort
`src/capture.py:637-642` · **Low**

`stop()` only joins the capture thread (5 s); worker, cleanup and watchdog threads are
left running. Scapy's `stop_filter` is only evaluated when a packet arrives, so on a
quiet interface `sniff()` blocks past the join. `app._analysis_loop` sleeps 5 s at the
top of its loop, so shutdown can lag by that much. All are daemon threads so the process
does exit — but in-flight work is not finished, which interacts badly with R8.

Relatedly, `main.py:60-64`: if the user declines the UAC prompt, `ShellExecuteW` returns
an error code rather than raising, and `sys.exit(0)` then runs — the app **exits silently
with no message**.

---

## 4. Tests

The 100 documented tests pass:

```
$ python -m unittest test_unit test_v140
Ran 100 tests in 0.220s — OK
```

But the suite as shipped has gaps:

- **`test_live.py` fails 1 of its 14 tests** and is not in the documented command:
  ```
  ✗ IDS memory cleanup — state dicts pruned under simulated load:
    Stale cooldowns not pruned: 5000
  ```
  The test calls `ids._periodic_cleanup()` without `force=True`; the packet-counter
  guard added by CHANGELOG fix #7 (`ids_engine.py:198-202`) returns immediately, so
  nothing is pruned. **(verified)** The shipped behaviour is probably fine — cleanup does
  run every 1000 packets — but the contract and the test have diverged and nobody notices
  because this file isn't run.
- **`test_live.py` executes at import and calls `sys.exit()`** at module level (line 691),
  which breaks `python -m unittest discover` and any `pytest` run:
  ```
  ERROR: test_live (unittest.loader._FailedTest.test_live)
  ImportError: ... SystemExit: 1
  ```
- **`test_detections.py` contributes 0 tests** to `unittest` — it is a manual traffic
  generator, but its `test_*.py` name means every collector tries to load it.
- **No CI.** No `.github/workflows`, so nothing runs any of this automatically.
- **No coverage of the modules with the worst bugs.** There is no test asserting that
  `is_learning` gates observation, that `DATA-EXFIL` is direction-aware, or that
  `packets_per_sec` reflects reality.

**Fix:** rename the two scripts to `tools/simulate_*.py`, guard them with
`if __name__ == '__main__':`, fix the `force=True` call, and add a
`.github/workflows/test.yml` running `python -m unittest discover`.

### Observability

96 of 191 exception handlers (50 %) end in `pass` or `logger.debug`:

| file | handlers | silent |
|---|---:|---:|
| `gui.py` | 26 | 16 |
| `app.py` | 18 | 16 |
| `forensics.py` | 13 | 9 |
| `capture.py` | 16 | 8 |
| `net_detect.py` | 12 | 8 |
| `pcap_analyzer.py` | 17 | 8 |
| `process_verify.py` | 13 | 7 |
| … | | |
| **total** | **191** | **96** |

For a security tool this is the wrong default: a detector that throws on every packet
looks identical to a detector that finds nothing. At minimum, log at WARNING with a
rate limiter, and surface a "detection errors" counter in the GUI.

---

## 5. Documentation and repo hygiene

| Claim | Reality |
|---|---|
| README: "Encrypted credential vault with AES-256 storage" | Fernet = AES-128-CBC, key derived from public data (S2) |
| README: "tests-100 passing" badge | true for the two documented files; `test_live.py` fails 1 of 14 |
| README project structure: "`rules/` — Detection rules (JSON)" | never loaded (D10) |
| README config table | documents `feature_history_days` correctly, but 16 other keys do nothing (S5) |
| CHANGELOG fix #14 "1 alert per source IP per hour" | undone by fix #7's pruner (D6) |
| CHANGELOG fix #17 "`is_admin()` now returns False" | correct — verified |
| CHANGELOG "Welford's online statistics" | correct — verified accurate to 3e-10 over 10,000 samples |

Version strings disagree in three places: `main.py:42` → `1.4.0`,
`src/__init__.py:2` → `1.0.0`, `setup.bat:15` → `v1.0`.

Missing for a project of this size and subject matter:

- No CI, no linter config (`ruff`/`flake8`), no formatter config
- No `pyproject.toml` / `setup.py` — not installable, `src/` is imported by path
- No `SECURITY.md` or vulnerability-disclosure policy, which a packet-capture tool that
  stores credentials really should have
- No `CONTRIBUTING.md`
- CHANGELOG starts at v1.4.0; no history for 1.0–1.3
- `requirements.txt` has no upper bounds and pins `pyinstaller` as a runtime dependency

No secrets are committed and no `__pycache__` is tracked — both clean.

---

## What is genuinely good

Worth stating plainly, because the finding list above is long:

- **The architecture is right.** Capture thread → bounded queue → worker → engines, with
  a watchdog and adaptive sampling, is the correct shape for this problem and is rarer
  than it should be in projects like this.
- **The single verified alert gateway** (`app.py:73-113`) is a strong design decision.
  Routing every detection through one enrichment + verification + correlation path is
  what keeps the alert quality up.
- **`alert_verify.py` is the best module in the repo.** Per-rule verification that can
  *downgrade* a finding, with reasoning attached, is a level of care most IDS projects
  skip entirely.
- **Welford's algorithm is implemented correctly**, including the hourly partition and
  warm-restart serialization. Verified numerically.
- **The alert evidence dictionaries** — `how_this_is_exploited`, `how_to_fix`,
  `recommendation`, the z-score explanations — are genuinely useful output, not filler.
- **The cloud/CDN-aware threat-intel severity logic** (`ids_engine.py:313-390`) shows
  real operational understanding of why threat feeds produce false positives.

---

## Recommended order of work

**Now**

1. S1 — PowerShell injection. Small diff, highest consequence.
2. D1 — gate `observe_dns`/`observe_connection` on `is_learning`. Three lines; restores
   the DNS and exfil detectors.
3. D4 — direction check on `DATA-EXFIL`. Removes a whole class of false positives.
4. S2/S3 — correct the AES-256 claim, chmod `0600`, and decide whether raw credentials
   should be stored at all.

**Next**

5. D2 — time-window the ML packet buffer; D3 — fix or drop `direction_asymmetry`.
6. R5 — restrict `DeviceLearner` to local addresses.
7. R2 — move verification off the packet thread; R1 — make the forensics scan incremental.
8. R6/R8 — fix alert persistence and make writes atomic.
9. D5, D6, D9 — TLD matching, odd-hours cooldown, process attribution.

**Then**

10. Add CI running `unittest discover`; fix `test_live.py` so it can be collected.
11. Wire up or delete the 16 dead config keys and `rules/default_rules.json`.
12. Remove the dead state in R10; replace silent `except` blocks with rate-limited WARNINGs.
13. Reconcile version strings; add `SECURITY.md` and `pyproject.toml`.
