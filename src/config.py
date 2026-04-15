"""
Configuration management for NetSentinel.
"""

import os
import json
import copy
import logging

logger = logging.getLogger("NetSentinel.Config")

APP_DIR = os.path.join(os.path.expanduser("~"), ".netsentinel")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")
DB_DIR = os.path.join(APP_DIR, "data")
RULES_DIR = os.path.join(APP_DIR, "rules")
MODELS_DIR = os.path.join(APP_DIR, "models")
ALERTS_DB = os.path.join(DB_DIR, "alerts.json")
BASELINE_DB = os.path.join(DB_DIR, "baseline.json")

# Ensure directories exist
for d in [APP_DIR, DB_DIR, RULES_DIR, MODELS_DIR]:
    os.makedirs(d, exist_ok=True)

DEFAULT_CONFIG = {
    "capture": {
        "interface": "auto",            # "auto" picks the default interface
        "promiscuous": True,
        "snap_length": 65535,
        "buffer_timeout_ms": 100,
        "bpf_filter": "not (port 443 and tcp[tcpflags] & tcp-ack != 0 and tcp[tcpflags] & tcp-syn == 0)",
        "max_pps": 500,                 # Hard cap: max packets/sec to process
        "pcap_buffer_packets": 150000,  # Ring buffer size for PCAP export (~225 MB at 1500B avg)
        "pcap_max_file_mb": 100,        # Max PCAP recording file size before rotation
    },
    "analysis": {
        "flow_timeout_sec": 120,        # Inactive flow expiry
        "stats_interval_sec": 5,        # How often to compute stats
        "max_flows_tracked": 50000,
    },
    "ml": {
        "enabled": True,
        "baseline_learning_hours": 2,   # Hours of initial baseline learning
        "anomaly_threshold": 0.25,      # Isolation Forest contamination
        "retrain_interval_min": 60,     # Retrain model periodically
        "min_samples_for_training": 200,
        "features": [
            "bytes_per_sec",
            "packets_per_sec",
            "avg_packet_size",
            "unique_dst_ports",
            "unique_dst_ips",
            "syn_ratio",
            "dns_query_rate",
            "failed_conn_ratio",
            "entropy_dst_port",
            "protocol_distribution",
        ],
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
        "beaconing_tolerance": 0.05,     # Timing regularity threshold (lower = stricter)
        "known_bad_ports": [4444, 5555, 6666, 1337, 31337, 12345, 65535],
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
        "save_credentials": True,         # Save found credentials to encrypted DB
        "retention_days": 365,            # Keep forensics data for 1 year
    },
    "alerts": {
        "max_stored": 5000,
        "sound_enabled": True,
        "desktop_notifications": True,
        "severity_filter": "LOW",       # LOW, MEDIUM, HIGH, CRITICAL
        "auto_block": False,            # Future: auto-block via firewall rules
        "cooldown_sec": 30,             # Min time between duplicate alerts
    },
    "gui": {
        "theme": "dark",
        "refresh_rate_ms": 1000,
        "max_log_lines": 500,
        "chart_history_minutes": 30,
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
                with open(CONFIG_FILE, "r") as f:
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
        """Persist current config to disk."""
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(self._data, f, indent=2)
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
