"""
Configuration management for NetSentinel.
"""

import os
import json
import copy
import stat
import logging

logger = logging.getLogger("NetSentinel.Config")

APP_DIR = os.path.join(os.path.expanduser("~"), ".netsentinel")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")
DB_DIR = os.path.join(APP_DIR, "data")
RULES_DIR = os.path.join(APP_DIR, "rules")
MODELS_DIR = os.path.join(APP_DIR, "models")
ALERTS_DB = os.path.join(DB_DIR, "alerts.json")
BASELINE_DB = os.path.join(DB_DIR, "baseline.json")

# Ensure directories exist. These hold captured credentials, alert history and the
# VirusTotal API key, so restrict them to the owner where the platform supports it.
for d in [APP_DIR, DB_DIR, RULES_DIR, MODELS_DIR]:
    os.makedirs(d, exist_ok=True)
    try:
        os.chmod(d, stat.S_IRWXU)  # 0700
    except OSError:
        pass  # Windows/ACL filesystems — nothing portable to do here


def atomic_write_json(path, data, secure=True, **dump_kwargs):
    """
    Write JSON atomically: full write to a temp file, fsync, then rename.

    Every persistence path in NetSentinel used to be a bare open(path, 'w') full
    rewrite, so an interruption mid-write truncated the file and the loader then
    silently started from empty.
    """
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, **dump_kwargs)
        f.flush()
        os.fsync(f.fileno())
    if secure:
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError:
            pass
    os.replace(tmp, path)

DEFAULT_CONFIG = {
    "capture": {
        "interface": "auto",            # "auto" picks the default interface
        "promiscuous": True,            # Put the interface in promiscuous mode
        "snap_length": 65535,           # Bytes captured per packet
        # Drop only *pure* ACKs on 443 — packets with no payload and no control
        # flags. The previous filter matched "ACK set, SYN clear", which also
        # catches PSH+ACK data segments, so it discarded the entire TLS
        # conversation including the ClientHello that carries SNI and JA3/JA4.
        # IPv4-only (tcp[...] does not apply to IPv6), so IPv6 passes unfiltered.
        "bpf_filter": (
            "not (tcp port 443 "
            "and (tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst|tcp-push)) == 0 "
            "and (ip[2:2] - ((ip[0]&0x0f)<<2) - ((tcp[12]&0xf0)>>2)) == 0)"
        ),
        # Hard cap on packets/sec handed to the analysis pipeline. Measured cost is
        # ~72 us/packet after the v1.5.0 optimisations (was ~950 us), so 2000 pps is
        # roughly 15% of one core. Raise it if you need full visibility on a busy link.
        "max_pps": 2000,
        "pcap_buffer_packets": 150000,  # Ring buffer size for PCAP export (~225 MB at 1500B avg)
        "pcap_max_file_mb": 100,        # Max PCAP recording file size before rotation
        "pcap_max_files": 20,           # Recordings kept on disk before the oldest are pruned
        "pcap_max_alert_files": 50,     # Per-alert captures kept before the oldest are pruned
        "pcap_on_alert": True,          # Save the traffic behind serious alerts
        "pcap_on_alert_severity": "CRITICAL",  # Minimum severity that triggers a save
        "pcap_on_alert_seconds": 60,    # Seconds of buffered traffic to save
        "pcap_link_type": 1,            # libpcap DLT: 1=Ethernet, 101=raw IP, 0=loopback
    },
    "analysis": {
        "flow_timeout_sec": 120,        # Inactive flow expiry
        "stats_interval_sec": 5,        # How often to compute stats
        "max_flows_tracked": 50000,
    },
    "ml": {
        "enabled": True,
        "baseline_learning_hours": 2,   # Hours of initial baseline learning
        # Fraction of training data the Isolation Forest should treat as outliers.
        # This shapes the model; it is NOT the alerting threshold.
        "contamination": 0.25,
        # Combined anomaly score (0-1) above which a window is flagged.
        "alert_threshold": 0.25,
        "retrain_interval_min": 60,     # Retrain model periodically
        "min_samples_for_training": 200,
        "feature_history_days": 90,              # Days of feature vectors to retain
        "feature_history_training_days": 7,      # Days of history to use for training
    },
    "ids": {
        "enabled": True,
        "port_scan_threshold": 15,      # Ports in window = scan
        "port_scan_window_sec": 60,
        "brute_force_threshold": 10,    # Failed conns in window
        "brute_force_window_sec": 30,
        "dns_tunnel_max_subdomain_len": 50,
        "large_upload_mb": 100,
        # Combined beacon score (0-1) required to report a periodic destination.
        # Replaces beaconing_tolerance, which gated on coefficient of variation and
        # so only caught beacons with no jitter at all.
        "beaconing_score_threshold": 0.75,
        # Failed DNS lookups from one host in 60s before a DGA burst is reported.
        # Chrome probes with 3 at startup and Windows suffix search multiplies a
        # single failure, so this sits well clear of both.
        "dns_nxdomain_threshold": 15,
        # Distinct addresses for one name inside 15 minutes, with a short TTL,
        # before fast-flux is reported.
        "dns_flux_address_threshold": 8,
        "known_bad_ports": [4444, 5555, 6666, 1337, 31337, 12345, 65535],
        # JA3/JA4 client fingerprints to alert on. Public threat intel publishes
        # these for C2 frameworks; they match on encrypted traffic.
        "blocked_ja3": [],
        "blocked_ja4": [],
    },
    "threat_intel": {
        "enabled": True,
        "auto_update": True,              # Auto-download fresh threat feeds
    },
    "verification": {
        "auto_verify": True,              # Auto-verify process alerts
        "virustotal_api_key": "",         # Free VT API key (4 lookups/min)
        "check_signatures": True,         # Verify Authenticode signatures
    },
    "forensics": {
        "enabled": True,                  # Credential scanning and insecure protocol detection
        "save_credentials": True,         # Persist findings to the encrypted vault
        "store_raw_credentials": False,   # Keep FULL plaintext secrets (off by default)
        "vault_passphrase": "",           # Set this for real confidentiality (scrypt KDF)
        "retention_days": 365,            # Findings older than this are pruned at startup
    },
    "alerts": {
        "max_stored": 5000,
        "sound_enabled": True,
        "desktop_notifications": True,
        "severity_filter": "LOW",       # LOW, MEDIUM, HIGH, CRITICAL
        "cooldown_sec": 30,             # Min time between duplicate alerts
    },
    "gui": {
        "refresh_rate_ms": 1000,
        "max_log_lines": 500,           # Max rows kept in the live packet log
    },
    "whitelists": {
        "ips": [],
        "domains": [],
        "ports": [80, 443, 53, 22, 3389],
        "processes": [],
        "dga_whitelist_suffixes": [],       # Extra DGA whitelist suffixes (merged with built-in)
        "dga_whitelist_exact": [],           # Exact domain matches to skip DGA checks
    },
    "blacklists": {
        "ips": [],
        "domains": [],
        "ports": [4444, 5555, 1337, 31337],
    },
    "known_devices": {
        # Named devices on the network — reduces false positives for known infrastructure
        # Format: {"name": "...", "ip": "...", "mac": "...", "type": "...", "expected_ports": [...]}
        "devices": [],
    },
}


class Config:
    """Manages application configuration with persistence."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._data = None
        return cls._instance

    def load(self):
        """Load config from disk, merging with defaults."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE) as f:
                    saved = json.load(f)
                self._data = self._deep_merge(DEFAULT_CONFIG, saved)
                logger.info("Configuration loaded from %s", CONFIG_FILE)
            except Exception as e:
                logger.error("Failed to load config: %s. Using defaults.", e)
                self._data = copy.deepcopy(DEFAULT_CONFIG)
        else:
            self._data = copy.deepcopy(DEFAULT_CONFIG)
            self.save()
            logger.info("Default configuration created at %s", CONFIG_FILE)
        return self

    def save(self):
        """Persist current config to disk (atomically; contains the VirusTotal key)."""
        try:
            atomic_write_json(CONFIG_FILE, self._data, indent=2)
        except Exception as e:
            logger.error("Failed to save config: %s", e)

    def get(self, *keys, default=None):
        """Get a nested config value. Usage: config.get('ml', 'enabled')"""
        node = self._data
        for key in keys:
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                return default
        return node

    def set(self, *keys_and_value):
        """Set a nested config value. Last arg is the value."""
        keys = keys_and_value[:-1]
        value = keys_and_value[-1]
        node = self._data
        for key in keys[:-1]:
            node = node.setdefault(key, {})
        node[keys[-1]] = value
        self.save()

    @property
    def data(self):
        if self._data is None:
            self.load()
        return self._data

    @staticmethod
    def _deep_merge(base, override):
        """Deep merge override into base, returning new dict."""
        result = copy.deepcopy(base)
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._deep_merge(result[key], value)
            else:
                result[key] = copy.deepcopy(value)
        return result
