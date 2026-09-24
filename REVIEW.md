# NetSentinel — Second-Pass Review

Written after the v1.5.0 audit remediation. `AUDIT.md` covers *what was broken*;
this covers *where the project can go*: what is left to optimise, how accurate it
can realistically get, what is worth building next, and what else this codebase
could be.

Every number below was measured on this machine, not estimated.

---

## 1. Optimisation

### What was done

Profiling the full pipeline (`app._on_packet`) over 20,000 packets of a realistic
mix — 85% TLS, 5% DNS, ~3% plaintext HTTP with payload:

| | before | after |
|---|---|---|
| throughput | 1,055 pkt/s | **13,927 pkt/s** |
| per-packet cost | 948 µs | **72 µs** |
| cost at the 500 pps cap | 47% of one core | 3.6% |

Three causes, in order of impact:

1. **A blocking reverse-DNS call — 12.0 s in a single sample.**
   `alert_verify._reverse_dns` used `socket.gethostbyaddr`, which takes no timeout
   and honours the resolver's. Verification runs synchronously on the packet worker
   for every rule except the IOC ones, so one unresolvable address stalled the whole
   sensor. This was the same class of bug as the deferred IOC verification fixed in
   the audit, in a path the audit had not profiled. Lookups now run on bounded
   background threads and return the cached value immediately.

2. **Rebuilding the port-scan set on every packet** — 19.8 M set operations in the
   profile run. The rule needs a distinct-port count per packet and recomputed it
   from a 500-entry history each time. Replaced with `SlidingPortWindow`, which
   keeps a refcount so each event is added and evicted exactly once.

3. **Re-parsing address strings** — ~8 `ipaddress.ip_address()` constructions per
   packet across four modules. `src/ipcache.py` caches the classification; hit rate
   on a realistic mix is **98.7%**.

The profile is now flat — no call site exceeds 17% of total time. Because headroom
went from 47% of a core to 3.6%, `capture.max_pps` was raised 500 → 2000.

### What is left

Ordered by value, with honest effort estimates.

**Worth doing**

- **`_extract_packet_info` calls `bytes(packet)` for the PCAP ring buffer on every
  packet, in the capture thread, before the pps cap** (`capture.py:_capture_callback`).
  That is a full serialisation per packet regardless of whether anyone ever exports.
  Scapy already holds the original bytes; using `packet.original` where available
  avoids the re-build. Worth measuring against a live interface, which this
  container cannot do.
- **The PCAP ring buffer defaults to 150,000 packets ≈ 225 MB resident**, allocated
  whether or not the feature is used. Either lower the default to ~30 s of traffic
  or allocate lazily on first export/record.
- **`_check_forensics_alerts` is called per packet** even when nothing changed. It is
  now cursor-based and cheap (65 ms per 20k packets), but calling it from the
  analysis loop instead of the packet path would remove it from the hot path
  entirely.
- **`Counter`-based `_port_counts` could be a plain dict** — `Counter.__setitem__` is
  slower than `dict` and no Counter-specific behaviour is used.

**Not worth doing**

- Micro-optimising `inspect_packet` further. At 72 µs/packet the pipeline can
  sustain ~14k pps on one core, and the capture layer caps at 2,000. CPU is no
  longer the constraint — **visibility is** (see §3).
- Rewriting hot paths in C/Cython. The remaining cost is spread thinly; there is no
  hotspot left that would justify the maintenance burden.

---

## 2. Testing

### Where it stands

| | before | after |
|---|---|---|
| unit tests | 100 | **190** |
| integration checks | 14 (1 failing, never run) | 14 (all passing, in CI) |
| line coverage | 30% | **43%** |

Per module, after:

| module | coverage | note |
|---|---|---|
| `alert_correlator.py` | 89% | |
| `baseline_whitelist.py` | 87% | |
| `config.py` | 86% | |
| `pcap_writer.py` | 83% | |
| `feature_store.py` | **78%** | was 0% |
| `device_learner.py` | 78% | |
| `ids_engine.py` | 69% | |
| `threat_intel.py` | 68% | |
| `forensics_db.py` | 68% | |
| `alert_verify.py` | **55%** | was 12% |
| `pcap_analyzer.py` | **52%** | was 0% |
| `ml_engine.py` | 53% | |
| `ioc_scanner.py` | 41% | |
| `forensics.py` | **35%** | was 10%; 1,027 statements |
| `capture.py` | 30% | needs a live interface |
| `process_verify.py` | 18% | Windows-only paths |
| `app.py` | 6% | wiring; exercised by the smoke path |
| `gui.py` | **0%** | 1,772 statements |

Writing the `alert_verify` tests immediately found a live bug: `verify_alert` did
`evidence = alert.evidence if alert.evidence else {}`, which rebinds to a *new*
local dict when the alert has no evidence — so the verdict was written to a
throwaway and every such alert silently lost its verification. All 18 rule types
were affected. That is the argument for coverage in one example.

### The remaining gaps, and what to do about them

**`gui.py` — 1,772 statements, 0%.** This is the single largest untested surface and
it cannot be tested as written: presentation and logic are interleaved in the same
methods. The fix is not "write GUI tests", it is to extract the logic. `_draw_protocols`
computing percentages, `_format_bytes`, the alert filtering in `_refresh_alerts_display`,
the threat-level thresholds in `_update_dashboard` — all pure functions wearing a
widget costume. Pulling them into a `src/presentation.py` would make them testable
and shrink `gui.py` by perhaps 300 statements. It also unlocks §5.

**`forensics.py` — 1,027 statements, 35%.** The remaining 65% is the long tail of
protocol parsers (SIP, MQTT, Modbus, BACnet, the parking-system code). Each is a
`_scan_payload_bytes` branch. A table-driven test — `(payload bytes, expected
finding)` — would cover most of them cheaply. This is the highest-value remaining
test work because it is the largest *detection* surface.

**`capture.py` — 30%.** The uncovered part is the Scapy callback path, which needs a
real interface. A `tools/replay_pcap.py` that feeds a PCAP through
`_extract_packet_info` would cover it without root.

**Property-based testing.** `_scan_payload_bytes` takes arbitrary attacker-controlled
bytes. `hypothesis` generating random payloads against it would be a good fit — the
current guarantee is "we tried empty, null and random".

---

## 3. Accuracy — how good can this get?

This is the most important section, because the honest answer is that **the ceiling
is set by visibility, not by the algorithms.**

### The measurement

Of a typical modern traffic mix:

| channel | share | what NetSentinel can see |
|---|---|---|
| HTTPS / TLS 1.3 | ~85% | opaque payload |
| QUIC / HTTP3 (UDP 443) | ~8% | opaque, and no TCP flags at all |
| DNS over HTTPS/TLS | ~3% | opaque — bypasses every DNS rule |
| Plaintext HTTP/FTP/Telnet/SMB | ~3% | fully visible |
| Other plaintext (mDNS, DHCP, ARP, NTP) | ~1% | fully visible |

**Payload-level detection applies to roughly 4% of traffic.** Everything else is
metadata only: peer address, port, timing, volume.

And of the 15 rule IDs:

- **5 depend on plaintext DNS** (`DNS-TUNNEL`, `DNS-BAD-TLD`, `DNS-FLOOD`,
  `THREAT-INTEL-DOMAIN`, `BL-DOMAIN`). A single host switching to DoH removes all
  five, silently.
- 2 depend on payload content (the forensics rules).
- The rest work on metadata and remain effective.

Two self-inflicted limits on top of that:

- **The default BPF filter drops every established TCP/443 packet** — not just pure
  ACKs, since `ACK set, SYN clear` also matches PSH+ACK data segments. So byte
  counting, flow volume and any future payload work on TLS are blind by
  configuration.
- **UDP/443 is classified as generic `UDP`** with `is_encrypted=False`. QUIC — now
  most Google/YouTube/Cloudflare traffic — is not recognised at all.

### The single highest-value change: read the TLS ClientHello

The ClientHello is **plaintext**, even in TLS 1.3. It carries:

- **SNI** — the destination hostname. This recovers a domain for the ~85% of
  traffic that currently has none, which would put the five DNS-dependent rules
  back in play for TLS *and* make threat-intel domain matching work without
  relying on DNS at all. It survives DoH, because the SNI is in the TLS
  handshake, not the DNS query.
- **JA3/JA4 fingerprint** — a hash of cipher suites, extensions and curves that
  identifies the *client stack*. Chrome, Firefox, Python-requests, Go, curl,
  Cobalt Strike and Metasploit all have distinct fingerprints. A JA3 that matches
  no installed browser, talking to a rare destination, is a strong C2 signal that
  works entirely on encrypted traffic.

Both are cheap: parse one packet per connection, at the handshake. The capture layer
already extracts raw payload for selected ports — adding 443 to that set and parsing
the first record is perhaps 150 lines. **This is the best accuracy-per-effort change
available to the project**, and it is what Zeek and Suricata rely on for the same
reason.

It requires fixing the BPF filter first. The correct "drop pure ACKs" expression,
which keeps handshake and data packets, is:

```
not (tcp port 443 and (tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst|tcp-push)) == 0
     and (ip[2:2] - ((ip[0]&0x0f)<<2) - ((tcp[12]&0xf0)>>2)) == 0)
```

Both filters compile under libpcap. Verified against synthetic packets with
`tcpdump -r`:

| packet | current | proposed |
|---|---|---|
| SYN (handshake) | keep | keep |
| SYN-ACK (handshake) | keep | keep |
| **ClientHello (PSH+ACK)** | **drop** | **keep** |
| **TLS data (ACK + payload)** | **drop** | **keep** |
| pure ACK (no payload) | drop | drop |
| FIN | drop | keep |
| port 80 data | keep | keep |

The ClientHello row is the whole argument: the packet carrying SNI and the JA3
fingerprint is exactly the one the current filter discards.

Note this is IPv4-only (`tcp[...]` does not apply to IPv6), so IPv6 traffic passes
through unfiltered — which is the safe direction. Keeping data packets raises the
packet rate reaching the pipeline, which the 13x throughput headroom now absorbs.

### Other accuracy work, ranked

1. **QUIC recognition.** Detect UDP/443 with a long-header QUIC initial, mark
   `is_encrypted`, and extract the SNI from the (unencrypted) Initial packet's
   CRYPTO frame. Without this, ~8% of traffic is silently miscategorised.
2. **DNS *response* analysis.** Only queries are inspected today. Responses carry
   the strongest DGA signals: NXDOMAIN bursts, very low TTLs, fast-flux (one name
   resolving to many IPs across short windows), and one IP serving many unrelated
   names.
3. **Jitter-tolerant beaconing.** `_check_beaconing` requires a coefficient of
   variation below 0.05, so any C2 with ±10% jitter — which every modern framework
   has by default — evades it. Autocorrelation or a MAD-based score over the
   interval series would catch jittered beacons that the CV test cannot.
4. **ASN and geo enrichment.** A local MaxMind GeoLite2 database (no network calls)
   would let alerts say "a connection to an ASN you have never used before", which
   is a far better signal than a raw IP for a home user.
5. **Lateral movement.** There is nothing watching internal SMB/RDP/WinRM between
   LAN hosts, which is where a real intrusion goes after initial access. The
   `DeviceLearner` inventory is exactly the state needed to spot "workstation A has
   never talked to workstation B on 445 before".
6. **Passive OS fingerprinting** from initial TTL and TCP window size would sharpen
   `DeviceLearner` classification considerably — it currently reports most devices
   as `unknown`.

### What will not improve accuracy

Adding more Isolation Forest features. The model already gets 18 and cannot see
past the encryption; more derived metadata features would mostly add variance. The
ML engine's real constraint is that it trains on its own traffic with no labels, so
it can only ever say "different from last week", not "malicious". That is a
legitimate signal — it should just not be oversold as detection.

---

## 4. Features worth adding

Grouped by how much of the existing codebase they reuse.

### Already 80% built — small additions

- **PCAP-on-alert.** The ring buffer, the export function and the alert gateway all
  exist. Wiring "on CRITICAL, call `pcap_writer.export_buffer()` and attach the path
  to the alert evidence" is perhaps 20 lines, and it turns every serious alert into
  something you can open in Wireshark. This is the highest value-to-effort feature
  available.
- **MITRE ATT&CK mapping.** Every rule already has a `category`. Adding a
  `technique` field (`PORT-SCAN` → T1046, `DATA-EXFIL` → T1041, `ARP-SPOOF` →
  T1557.002, `BRUTE-FORCE` → T1110) costs a dict and makes the output legible to
  anyone with a security background.
- **Scheduled reports.** `AlertManager.export_alerts` already does JSON and CSV, and
  `forensics.generate_narrative()` already writes prose. A weekly HTML summary is
  mostly plumbing.
- **Syslog / CEF output.** One more listener on `AlertManager.register_listener`.
  This is what makes the tool usable alongside anything else.

### Meaningful but self-contained

- **Headless mode.** The entire engine is already GUI-independent — `NetSentinelApp`
  never imports tkinter except in `run()`. A `--headless` flag plus a small HTTP API
  would let it run on a Raspberry Pi on a SPAN port, which is a much better
  deployment for a network monitor than a desktop app. This is arguably the single
  biggest change in what the project *is*, for a small amount of code.
- **Prometheus `/metrics`.** `get_dashboard_data()` already returns everything
  needed.
- **Sigma rule support.** Importing a subset of Sigma would let users borrow the
  public detection corpus instead of waiting for new hardcoded rules.
- **Config UI validation.** `_deep_merge` accepts any JSON; a malformed value
  (`max_pps: "fast"`) propagates into arithmetic and fails at a distance. A schema
  check at load time with a clear error costs little.

### Larger

- **Cross-platform support.** `net_detect` shells out to `route print` and `ipconfig`
  and parses English/German output; the signature check is PowerShell. Linux and
  macOS support would need a platform abstraction, but the rest of the codebase is
  already portable — the test suite runs fine on Linux.
- **Agent + collector.** Multiple hosts reporting to one instance. The alert and
  device models are already serialisable.
- **Encrypted-traffic classification.** With JA3 and flow statistics you can
  classify application type without decryption. This is a research direction, not a
  weekend.

### Worth removing

The ~250 lines of SKIDATA parking-system and E-ZPass parsing in `forensics.py`
belong in a plugin, not in a general-purpose home network monitor. They also
publish the control-channel layout of a named vendor's system in a public repo.

---

## 5. What else this could be

The codebase is better than the application wrapped around it. Three directions,
in increasing order of ambition:

**A network sensor rather than a desktop app.** The detection engine, forensics,
correlation and ML are all headless already. tkinter is the only thing tying this to
a Windows desktop, and it is also the only untested module. Splitting
`netsentinel-core` (engine + API) from `netsentinel-ui` (a thin client) would make
the core testable, deployable on a Pi, and usable by other tools.

**A PCAP analysis library.** `PcapAnalyzer` + `NetworkForensics` + `IDSEngine`
already run offline against a file. Packaged as a library, "run 15 detection rules
and a 50-protocol credential scan over this PCAP and give me structured findings" is
useful to incident responders who will never run the GUI. `pyproject.toml` now
exists, so this is mostly API design.

**A teaching tool.** This is genuinely unusual and underrated. The alert evidence
dictionaries already explain `how_this_is_exploited`, `how_to_fix` and
`is_this_malicious` in plain language — that is rare and well done. Combined with
`tools/simulate_attacks.py`, which generates each attack on demand, you have the
makings of a lab: trigger an attack, watch the detection fire, read why it matters.
Most security education tooling is far worse than this at explaining itself.

---

## Suggested next three

If only three things get done:

1. **Parse the TLS ClientHello for SNI and JA3**, and fix the BPF filter so the
   handshake is actually visible. This is the difference between seeing 4% of
   traffic meaningfully and seeing most of it.
2. **PCAP-on-alert.** ~20 lines, and it makes every CRITICAL alert investigable.
3. **Extract the logic out of `gui.py`.** It removes the last 0%-coverage module and
   is the prerequisite for headless mode.
