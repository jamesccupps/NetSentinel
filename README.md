# NetSentinel

**AI-Powered Network Monitor & Intrusion Detection System**

NetSentinel is a desktop network security application that monitors all traffic on your machine, detects anomalies using machine learning, and alerts you to suspicious activity in real time. It learns your network automatically — no configuration required.

![Python](https://img.shields.io/badge/python-3.10+-blue) ![Platform](https://img.shields.io/badge/platform-Windows-lightgrey) ![License](https://img.shields.io/badge/license-MIT-green) ![Tests](https://img.shields.io/badge/tests-218%20unit%20%2B%2014%20integration-brightgreen)

## Key Features

**Traffic Monitoring** — Full packet capture with live bandwidth charts, protocol breakdown, bidirectional flow tracking, and process identification.

**TLS Inspection** — Reads the plaintext ClientHello to recover the destination
hostname (SNI) and a JA3/JA4 client fingerprint from *encrypted* connections. The SNI
works even when the host uses DNS-over-HTTPS, because it comes from the handshake
rather than a DNS query. JA4 identifies the client software, so malware using its own
TLS stack stands out even when everything it sends is encrypted.

**Machine Learning** — Isolation Forest anomaly detection trained on your traffic baseline, with Welford's online statistics for O(1) incremental learning. Detects beaconing, DNS tunneling, and behavioral anomalies.

**Intrusion Detection** — 12 rule-based detectors: port scans, brute force, SYN/ICMP floods, ARP spoofing, suspicious DNS, data exfiltration, threat intelligence feeds, and more.

**Network Forensics** — Scans for plaintext credentials (50+ protocol patterns), insecure services, sensitive data in transit. Findings go to an encrypted vault; by default only **masked** values are stored. See [Credential storage](#credential-storage) before enabling raw storage.

**Passive Device Learning** — Automatically discovers and classifies every device on your local network (gateway, workstation, IoT, printer, camera, server) from ARP, DHCP, mDNS, and traffic patterns alone. Remote internet hosts are not treated as devices.

**Alert Correlation** — Groups related alerts into Incidents. Detects escalation chains (Reconnaissance → Attack, Threat Intel → Exfiltration) and presents them as a single narrative instead of 50 individual alerts.

**Baseline Whitelist** — During the initial learning period *only*, records every domain, IP, port, and periodic pattern as "normal for this network." Once that window closes, learning stops — so nothing an attacker does later can whitelist itself. No hardcoded whitelists.

**PCAP Export** — Ring buffer of raw packets with on-demand "save last 5 minutes" export and continuous recording with auto-rotation.

## Quick Start

### Prerequisites

- **Python 3.10+**
- **Npcap** (Windows packet capture driver) — download from [npcap.com](https://npcap.com/)
  - During install, check "Install in WinPcap API-compatible mode"
- **Administrator privileges** (required for packet capture)

### Install

```bash
git clone https://github.com/jamesccupps/NetSentinel.git
cd NetSentinel
pip install -r requirements.txt
```

Or use the setup script:

```bash
setup.bat
```

### Run

```bash
python main.py
```

Or build a standalone executable:

```bash
build_exe.bat
```

### First Launch

1. Click **START MONITORING** — NetSentinel begins capturing and learning
2. The ML engine enters **baseline learning mode** (2 hours by default)
3. During learning, it records what's normal for your specific network
4. After learning completes, anomaly detection activates automatically
5. Alerts appear in real-time in the **Alerts** tab
6. The **Devices** tab shows all discovered devices and their classifications
7. The **Incidents** tab groups related alerts into correlated events

## Screenshots

<img width="1897" height="1033" alt="image" src="https://github.com/user-attachments/assets/ced27cca-5803-4f50-b0ed-73edd7dbd627" />

## Architecture

```
Scapy Capture → Queue → Worker Thread → IDS Engine       → Alert Verifier → Alert Manager → GUI
                                       → IOC Scanner      ↗                 → Correlator
                                       → Forensics Engine                   → Desktop Notify
                                       → Device Learner
                                       → Baseline Whitelist
                           ↓
                     ML Analysis Loop → Anomaly Detector → (alerts via same gateway)
                           ↓
                     PCAP Ring Buffer → On-demand export
```

All detection engines feed through a single verified alert gateway that enriches, verifies, and deduplicates before the user sees anything.

## Configuration

Configuration lives in `~/.netsentinel/config.json` (created on first run with defaults). Key settings:

| Section | Setting | Default | Description |
|---------|---------|---------|-------------|
| `capture` | `max_pps` | 2000 | Max packets/sec handed to the analysis pipeline |
| `capture` | `pcap_buffer_packets` | 150000 | Ring buffer size for PCAP export |
| `ml` | `baseline_learning_hours` | 2 | Hours of initial baseline learning |
| `ml` | `contamination` | 0.25 | Isolation Forest contamination (shapes the model) |
| `ml` | `alert_threshold` | 0.25 | Combined anomaly score (0-1) required to alert |
| `ml` | `feature_history_days` | 90 | Days of feature vectors to retain |
| `ids` | `port_scan_threshold` | 15 | Ports in window to trigger scan alert |
| `ids` | `brute_force_threshold` | 10 | Failed connections to trigger brute force alert |
| `ids` | `blocked_ja3` | `[]` | JA3 client fingerprints to alert on |
| `ids` | `blocked_ja4` | `[]` | JA4 client fingerprints to alert on |
| `alerts` | `severity_filter` | LOW | Minimum severity to display |
| `alerts` | `cooldown_sec` | 30 | Min seconds between duplicate alerts |
| `forensics` | `save_credentials` | true | Persist findings to the encrypted vault |
| `forensics` | `store_raw_credentials` | false | Keep full plaintext secrets (opt-in) |
| `forensics` | `vault_passphrase` | `""` | Set for real vault confidentiality (scrypt) |
| `forensics` | `retention_days` | 365 | Findings older than this are pruned at startup |
| `capture` | `pcap_max_files` | 20 | Recordings kept before the oldest are pruned |

Every key in `config.json` is read by the code. If you set something, it takes effect.

You can optionally pre-configure known devices to reduce false positives, but this is entirely optional — NetSentinel learns devices automatically from traffic:

```json
{
  "known_devices": {
    "devices": [
      {"name": "NAS", "ip": "192.168.1.50", "type": "server"},
      {"name": "Printer", "ip": "192.168.1.200", "type": "printer"}
    ]
  }
}
```

## Data Storage

All runtime data is stored locally in `~/.netsentinel/`:

| Path | Contents |
|------|----------|
| `config.json` | User configuration |
| `data/alerts.json` | Alert history |
| `data/baseline.json` | ML baseline (Welford online statistics) |
| `data/baseline_whitelist.json` | Learned normal domains/IPs/patterns |
| `data/learned_devices.json` | Passive device inventory |
| `data/incidents.json` | Correlated incident history |
| `data/feature_history/` | Daily CSV feature vectors for ML training |
| `models/` | Trained Isolation Forest + scaler (pickle) |
| `captures/` | Exported PCAP files |
| `logs/` | Application logs |

## Credential storage

NetSentinel extracts credentials from unencrypted protocols. Understand what it
keeps before you run it on a network you care about.

- The vault (`~/.netsentinel/data/forensics/credentials.enc`) uses **Fernet —
  AES-128-CBC + HMAC-SHA256**. Not AES-256.
- **By default the key is derived from hostname + username.** That ties the file
  to one machine but is *not secret*: anyone holding the file can usually
  reproduce it. It protects against casual inspection, nothing more.
- **By default only masked values are stored.** Set
  `forensics.store_raw_credentials` to `true` to retain full plaintext secrets.
- For genuine confidentiality, set `forensics.vault_passphrase`. Key derivation
  then uses scrypt over a random salt, and the vault cannot be opened without it.
- Set `forensics.enabled` to `false` to turn credential scanning off entirely.

Data files are created `0700`/`0600` where the platform supports it. See
[SECURITY.md](SECURITY.md).

## Known scope limits

Worth knowing before you rely on a detector:

- **`capture.max_pps` caps processing at 2000 packets per second.** Raise it if you
  need full visibility on a busy link; the pipeline measures ~72 µs/packet, so 2000
  pps is roughly 15% of one core.
- **TLS payload stays opaque.** NetSentinel reads the handshake, not the content.
  It can tell you *who* a host talked to and *what software* did the talking, not
  what was said.
- **`DATA-EXFIL` only counts traffic leaving the local network.** Purely internal
  LAN-to-LAN transfers (a NAS backup, for example) are deliberately out of scope.
- **Process attribution needs privileges.** Without them `psutil` cannot map
  sockets to other users' processes and alerts show `process: Unknown`.

## Testing

```bash
# Everything (218 tests)
python -m unittest discover -s . -p "test_*.py"

# Regression tests for the v1.5.0 audit fixes
python -m unittest test_regressions -v

# Coverage for modules the original suite never reached
python -m unittest test_coverage -v

# TLS ClientHello parsing, fingerprinting and hostile input
python -m unittest test_tls -v

# End-to-end integration checks (real code paths, no capture required)
python tools/integration_check.py

# Generate live attack traffic against a running instance (separate terminal)
python tools/simulate_attacks.py --list
```

CI runs the suite on Python 3.10, 3.11 and 3.12 — see
[`.github/workflows/test.yml`](.github/workflows/test.yml).

## Project Structure

```
NetSentinel/
├── main.py                   # Entry point, splash screen, admin elevation
├── src/
│   ├── app.py                # Application orchestrator
│   ├── capture.py            # Packet capture engine (Scapy + queue architecture)
│   ├── ids_engine.py         # 12-rule intrusion detection system
│   ├── ml_engine.py          # Isolation Forest + Welford baseline + beaconing
│   ├── forensics.py          # Credential scanning, protocol analysis (50+ patterns)
│   ├── forensics_db.py       # Encrypted credential vault (Fernet/AES-128)
│   ├── alert_verify.py       # Multi-factor alert verification and scoring
│   ├── alerts.py             # Alert storage, filtering, notification batching
│   ├── alert_correlator.py   # Groups alerts into incidents with escalation detection
│   ├── device_learner.py     # Passive device discovery and classification
│   ├── baseline_whitelist.py # Learns normal traffic patterns automatically
│   ├── pcap_writer.py        # Ring buffer + PCAP export + continuous recording
│   ├── threat_intel.py       # Threat feed downloader and matcher
│   ├── ioc_scanner.py        # Indicators of compromise (process, port, behavior)
│   ├── net_detect.py         # Network environment auto-detection
│   ├── process_verify.py     # Deep process investigation (signatures, hashes)
│   ├── pcap_analyzer.py      # Offline PCAP file analysis
│   ├── feature_store.py      # Persistent ML feature vector storage
│   ├── tls_inspect.py        # ClientHello parsing: SNI, JA3/JA4, QUIC detection
│   ├── ipcache.py            # Cached IP address classification
│   ├── config.py             # Configuration management
│   └── gui.py                # tkinter dashboard (11 tabs)
├── test_unit.py              # Core unit tests
├── test_v140.py              # v1.4.0 module tests
├── test_regressions.py       # Regression tests for the v1.5.0 audit fixes
├── tools/
│   ├── integration_check.py  # End-to-end checks against real code paths
│   └── simulate_attacks.py   # Traffic generator for manual verification
├── rules/                    # Detection rules (JSON) — loaded at startup
├── assets/                   # Icons
├── setup.bat                 # Windows one-click setup
├── build_exe.bat             # PyInstaller build script
└── requirements.txt
```

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
NetSentinel runs with Administrator/root privileges and stores captured
credentials, so treat it as privileged software.

`AUDIT.md` documents a full review of the codebase and the fixes applied in
v1.5.0.

## License

MIT — see [LICENSE](LICENSE).
