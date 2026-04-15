# NetSentinel

**AI-Powered Network Monitor & Intrusion Detection System**

NetSentinel is a desktop network security application that monitors all traffic on your machine, detects anomalies using machine learning, and alerts you to suspicious activity in real time. It learns your network automatically — no configuration required.

![Python](https://img.shields.io/badge/python-3.10+-blue) ![Platform](https://img.shields.io/badge/platform-Windows-lightgrey) ![License](https://img.shields.io/badge/license-MIT-green) ![Tests](https://img.shields.io/badge/tests-100%20passing-brightgreen)

## Key Features

**Traffic Monitoring** — Full packet capture with live bandwidth charts, protocol breakdown, bidirectional flow tracking, and process identification.

**Machine Learning** — Isolation Forest anomaly detection trained on your traffic baseline, with Welford's online statistics for O(1) incremental learning. Detects beaconing, DNS tunneling, and behavioral anomalies.

**Intrusion Detection** — 12 rule-based detectors: port scans, brute force, SYN/ICMP floods, ARP spoofing, suspicious DNS, data exfiltration, threat intelligence feeds, and more.

**Network Forensics** — Scans for plaintext credentials (50+ protocol patterns), insecure services, sensitive data in transit. Encrypted credential vault with AES-256 storage.

**Passive Device Learning** — Automatically discovers and classifies every device on the network (gateway, workstation, IoT, printer, camera, server) from ARP, DHCP, mDNS, and traffic patterns alone.

**Alert Correlation** — Groups related alerts into Incidents. Detects escalation chains (Reconnaissance → Attack, Threat Intel → Exfiltration) and presents them as a single narrative instead of 50 individual alerts.

**Baseline Whitelist** — During the initial learning period, records every domain, IP, port, and periodic pattern as "normal for this network." After learning, suppresses false positives automatically. No hardcoded whitelists.

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
| `capture` | `max_pps` | 500 | Max packets/sec to process |
| `capture` | `pcap_buffer_packets` | 150000 | Ring buffer size for PCAP export |
| `ml` | `baseline_learning_hours` | 2 | Hours of initial baseline learning |
| `ml` | `anomaly_threshold` | 0.25 | Isolation Forest contamination parameter |
| `ml` | `feature_history_days` | 90 | Days of feature vectors to retain |
| `ids` | `port_scan_threshold` | 15 | Ports in window to trigger scan alert |
| `ids` | `brute_force_threshold` | 10 | Failed connections to trigger brute force alert |
| `alerts` | `severity_filter` | LOW | Minimum severity to display |
| `alerts` | `cooldown_sec` | 30 | Min seconds between duplicate alerts |

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

## Testing

```bash
# Run all tests (100 tests)
python -m unittest test_unit test_v140 -v

# Run only v1.4.0 tests (bug fixes + new modules)
python -m unittest test_v140 -v
```

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
│   ├── forensics_db.py       # AES-256 encrypted credential vault
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
│   ├── config.py             # Configuration management
│   └── gui.py                # tkinter dashboard (11 tabs)
├── test_unit.py              # Core unit tests (38 tests)
├── test_v140.py              # v1.4.0 comprehensive tests (62 tests)
├── test_detections.py        # Detection-specific tests (requires Scapy)
├── test_live.py              # Integration tests with live capture
├── rules/                    # Detection rules (JSON)
├── assets/                   # Icons
├── setup.bat                 # Windows one-click setup
├── build_exe.bat             # PyInstaller build script
└── requirements.txt
```

## License

MIT — see [LICENSE](LICENSE).
