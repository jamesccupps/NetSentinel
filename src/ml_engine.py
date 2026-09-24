"""
Machine Learning Anomaly Detection Engine
==========================================
Uses Isolation Forest, statistical baselines, and entropy analysis
to detect anomalous network behavior.
"""

import os
import hmac
import stat
import time
import json
import math
import pickle
import hashlib
import logging
import ipaddress
import numpy as np
from collections import defaultdict, deque
from datetime import datetime

from src.beaconing import MIN_OBSERVATIONS, is_expected_periodic, score_beacon
from src.ipcache import is_global

logger = logging.getLogger("NetSentinel.ML")

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available. ML features disabled.")


def _is_private_ip(ip):
    """RFC1918/loopback/link-local check that is correct for 172.16/12."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


class TrafficFeatureExtractor:
    """
    Extracts numerical feature vectors from network flow data
    for use in anomaly detection models.
    """

    def __init__(self):
        self.feature_names = [
            'bytes_per_sec',
            'packets_per_sec',
            'avg_packet_size',
            'unique_dst_ports',
            'unique_dst_ips',
            'syn_ratio',
            'dns_query_rate',
            'failed_conn_ratio',
            'entropy_dst_port',
            'avg_inter_arrival',
            'std_inter_arrival',
            'payload_ratio',
            'direction_asymmetry',
            'small_packet_ratio',
            'large_packet_ratio',
            'rst_ratio',
            'unique_protocols',
            'encrypted_ratio',
        ]

    def extract_from_window(self, flows, packets_window, window_sec=60, local_ips=None):
        """
        Extract a feature vector from a time window of traffic.

        Args:
            flows: dict of NetworkFlow objects
            packets_window: list of PacketInfo from the window
            window_sec: nominal window duration in seconds. The real span of the
                packets is used instead when it is larger, so rate features stay
                truthful even if the caller passes a stale window.
            local_ips: set of this host's addresses, used for direction features

        Returns:
            numpy array of features
        """
        if not packets_window:
            return np.zeros(len(self.feature_names))

        local_ips = local_ips or set()

        # Rates must be divided by the period the packets actually cover. Dividing a
        # rolling buffer by a fixed nominal window pins packets_per_sec at
        # len(buffer)/window_sec regardless of real traffic.
        observed_span = packets_window[-1].timestamp - packets_window[0].timestamp
        window_sec = max(window_sec, observed_span, 1e-3)

        total_bytes = sum(p.length for p in packets_window)
        total_packets = len(packets_window)
        dst_ports = set()
        dst_port_list = []  # With repeats, for entropy of frequency distribution
        dst_ips = set()
        syn_count = 0
        rst_count = 0
        dns_count = 0
        failed_count = 0
        payload_bytes = 0
        encrypted_count = 0
        protocols = set()
        small_packets = 0  # < 100 bytes
        large_packets = 0  # > 1400 bytes
        inter_arrivals = []
        # Bytes sent by vs. received by the hosts we consider local. Counting packets
        # per src_ip and per dst_ip (as this used to) always yields the same total on
        # both sides, so the asymmetry was identically zero.
        bytes_out = 0
        bytes_in = 0

        prev_time = None
        for p in packets_window:
            dst_ports.add(p.dst_port)
            dst_port_list.append(p.dst_port)
            dst_ips.add(p.dst_ip)
            protocols.add(p.protocol)
            payload_bytes += p.payload_size

            if 'S' in p.flags and 'A' not in p.flags:
                syn_count += 1
            if 'R' in p.flags:
                rst_count += 1
                failed_count += 1
            if p.dns_query:
                dns_count += 1
            if p.is_encrypted:
                encrypted_count += 1
            if p.length < 100:
                small_packets += 1
            if p.length > 1400:
                large_packets += 1

            if local_ips:
                if p.src_ip in local_ips:
                    bytes_out += p.length
                elif p.dst_ip in local_ips:
                    bytes_in += p.length
            else:
                # No local-IP hint available: fall back to RFC1918 heuristics so the
                # feature still carries signal instead of silently flatlining.
                if _is_private_ip(p.src_ip) and not _is_private_ip(p.dst_ip):
                    bytes_out += p.length
                elif _is_private_ip(p.dst_ip) and not _is_private_ip(p.src_ip):
                    bytes_in += p.length

            if prev_time is not None:
                iat = p.timestamp - prev_time
                if iat >= 0:
                    inter_arrivals.append(iat)
            prev_time = p.timestamp

        # Compute features
        bytes_per_sec = total_bytes / max(window_sec, 1)
        packets_per_sec = total_packets / max(window_sec, 1)
        avg_packet_size = total_bytes / max(total_packets, 1)
        unique_dst_ports = len(dst_ports)
        unique_dst_ips = len(dst_ips)
        syn_ratio = syn_count / max(total_packets, 1)
        dns_query_rate = dns_count / max(window_sec, 1)
        failed_conn_ratio = failed_count / max(total_packets, 1)
        entropy_dst_port = self._entropy(dst_port_list) if dst_port_list else 0
        avg_iat = np.mean(inter_arrivals) if inter_arrivals else 0
        std_iat = np.std(inter_arrivals) if inter_arrivals else 0
        payload_ratio = payload_bytes / max(total_bytes, 1)
        small_packet_ratio = small_packets / max(total_packets, 1)
        large_packet_ratio = large_packets / max(total_packets, 1)
        rst_ratio = rst_count / max(total_packets, 1)
        unique_protos = len(protocols)
        encrypted_ratio = encrypted_count / max(total_packets, 1)

        # Direction asymmetry: 0 = balanced up/down, 1 = entirely one direction.
        # Sustained high asymmetry with high volume is the shape of bulk exfiltration.
        direction_asymmetry = abs(bytes_out - bytes_in) / max(bytes_out + bytes_in, 1)

        features = np.array([
            bytes_per_sec,
            packets_per_sec,
            avg_packet_size,
            unique_dst_ports,
            unique_dst_ips,
            syn_ratio,
            dns_query_rate,
            failed_conn_ratio,
            entropy_dst_port,
            avg_iat,
            std_iat,
            payload_ratio,
            direction_asymmetry,
            small_packet_ratio,
            large_packet_ratio,
            rst_ratio,
            unique_protos,
            encrypted_ratio,
        ])

        return features

    @staticmethod
    def _entropy(values):
        """Shannon entropy of a distribution."""
        if not values:
            return 0
        total = len(values)
        counts = defaultdict(int)
        for v in values:
            counts[v] += 1
        ent = 0
        for c in counts.values():
            p = c / total
            if p > 0:
                ent -= p * math.log2(p)
        return ent


class BaselineProfile:
    """
    Maintains a statistical baseline of normal network behavior.
    Uses Welford's online algorithm for O(1) incremental mean/variance updates
    instead of recomputing from the full history on every sample.
    Tracks hourly patterns, weekly cycles, and rolling statistics.
    """

    def __init__(self, db_path):
        self.db_path = db_path
        self.hourly_means = {}     # {hour: feature_means}
        self.hourly_stds = {}      # {hour: feature_stds}
        self.global_mean = None
        self.global_std = None
        self.samples_count = 0
        self.day_of_week_factor = {}  # {dow: scaling_factor}
        self._learning = True
        self.learning_start = time.time()

        # Welford's online statistics — global
        self._welford_n = 0
        self._welford_mean = None
        self._welford_m2 = None     # Running sum of squared differences

        # Welford's online statistics — per hour
        self._hourly_welford_n = {}       # {hour: count}
        self._hourly_welford_mean = {}    # {hour: mean_array}
        self._hourly_welford_m2 = {}      # {hour: m2_array}

        self.load()

    def add_sample(self, features, timestamp=None):
        """Add a feature vector sample to the baseline using Welford's algorithm."""
        if timestamp is None:
            timestamp = time.time()
        dt = datetime.fromtimestamp(timestamp)
        hour = dt.hour

        self.samples_count += 1

        # ─── Welford update: global stats ─────────────────────
        if self._welford_mean is None:
            self._welford_n = 1
            self._welford_mean = features.copy().astype(float)
            self._welford_m2 = np.zeros_like(features, dtype=float)
        else:
            self._welford_n += 1
            delta = features - self._welford_mean
            self._welford_mean += delta / self._welford_n
            delta2 = features - self._welford_mean
            self._welford_m2 += delta * delta2

        # Expose as global_mean / global_std
        self.global_mean = self._welford_mean.copy()
        if self._welford_n > 1:
            variance = self._welford_m2 / (self._welford_n - 1)
            self.global_std = np.sqrt(np.maximum(variance, 0)) + 1e-8
        else:
            self.global_std = np.ones_like(features) * 1e-8

        # ─── Welford update: hourly stats ─────────────────────
        if hour not in self._hourly_welford_n:
            self._hourly_welford_n[hour] = 1
            self._hourly_welford_mean[hour] = features.copy().astype(float)
            self._hourly_welford_m2[hour] = np.zeros_like(features, dtype=float)
        else:
            self._hourly_welford_n[hour] += 1
            n = self._hourly_welford_n[hour]
            delta = features - self._hourly_welford_mean[hour]
            self._hourly_welford_mean[hour] += delta / n
            delta2 = features - self._hourly_welford_mean[hour]
            self._hourly_welford_m2[hour] += delta * delta2

        hn = self._hourly_welford_n[hour]
        if hn >= 5:
            self.hourly_means[hour] = self._hourly_welford_mean[hour].copy()
            if hn > 1:
                var = self._hourly_welford_m2[hour] / (hn - 1)
                self.hourly_stds[hour] = np.sqrt(np.maximum(var, 0)) + 1e-8
            else:
                self.hourly_stds[hour] = np.ones_like(features) * 1e-8

    def get_deviation_score(self, features, timestamp=None):
        """
        Compute how much the current features deviate from baseline.
        Returns a score 0-1 where higher = more anomalous.
        """
        if self.global_mean is None or self.samples_count < 10:
            return 0.0  # Not enough data yet

        if timestamp is None:
            timestamp = time.time()
        hour = datetime.fromtimestamp(timestamp).hour

        # Use hourly baseline if available, else global
        if hour in self.hourly_means:
            mean = self.hourly_means[hour]
            std = self.hourly_stds[hour]
        else:
            mean = self.global_mean
            std = self.global_std

        # Z-score based deviation
        z_scores = np.abs((features - mean) / std)
        # Average z-score, capped
        avg_z = np.clip(np.mean(z_scores), 0, 10)
        # Convert to 0-1 score using sigmoid-like transform
        score = 1 - (1 / (1 + avg_z / 3))
        return float(score)

    def save(self):
        """Persist baseline to disk (including Welford online stats)."""
        try:
            data = {
                'samples_count': self.samples_count,
                'global_mean': self.global_mean.tolist() if self.global_mean is not None else None,
                'global_std': self.global_std.tolist() if self.global_std is not None else None,
                'hourly_means': {k: v.tolist() for k, v in self.hourly_means.items()},
                'hourly_stds': {k: v.tolist() for k, v in self.hourly_stds.items()},
                'learning_start': self.learning_start,
                # Welford state for warm restart
                'welford_n': self._welford_n,
                'welford_mean': self._welford_mean.tolist() if self._welford_mean is not None else None,
                'welford_m2': self._welford_m2.tolist() if self._welford_m2 is not None else None,
                'hourly_welford_n': self._hourly_welford_n,
                'hourly_welford_mean': {str(k): v.tolist() for k, v in self._hourly_welford_mean.items()},
                'hourly_welford_m2': {str(k): v.tolist() for k, v in self._hourly_welford_m2.items()},
            }
            from src.config import atomic_write_json
            atomic_write_json(self.db_path, data)
        except Exception as e:
            logger.error("Failed to save baseline: %s", e)

    def load(self):
        """Load baseline from disk (including Welford online stats)."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path) as f:
                    data = json.load(f)
                self.samples_count = data.get('samples_count', 0)
                if data.get('global_mean'):
                    self.global_mean = np.array(data['global_mean'])
                    self.global_std = np.array(data['global_std'])
                self.hourly_means = {
                    int(k): np.array(v) for k, v in data.get('hourly_means', {}).items()
                }
                self.hourly_stds = {
                    int(k): np.array(v) for k, v in data.get('hourly_stds', {}).items()
                }
                self.learning_start = data.get('learning_start', time.time())

                # Restore Welford state for warm restart
                self._welford_n = data.get('welford_n', 0)
                if data.get('welford_mean'):
                    self._welford_mean = np.array(data['welford_mean'])
                    self._welford_m2 = np.array(data['welford_m2'])
                for k, v in data.get('hourly_welford_n', {}).items():
                    self._hourly_welford_n[int(k)] = v
                for k, v in data.get('hourly_welford_mean', {}).items():
                    self._hourly_welford_mean[int(k)] = np.array(v)
                for k, v in data.get('hourly_welford_m2', {}).items():
                    self._hourly_welford_m2[int(k)] = np.array(v)

                logger.info("Loaded baseline with %d samples (Welford n=%d)",
                            self.samples_count, self._welford_n)
            except Exception as e:
                logger.error("Failed to load baseline: %s", e)


class AnomalyDetector:
    """
    Combined ML anomaly detection using:
    1. Isolation Forest for multivariate anomaly detection
    2. Statistical baseline deviation scoring
    3. Entropy-based analysis
    4. Beaconing / periodicity detection
    """

    def __init__(self, config, feature_store=None):
        self.config = config
        self.enabled = config.get('ml', 'enabled', default=True) and SKLEARN_AVAILABLE
        # Two distinct knobs. contamination shapes the Isolation Forest (what fraction
        # of TRAINING data it should treat as outliers); alert_threshold gates the
        # combined 0-1 score. Raising one used to silently move the other the wrong way.
        # anomaly_threshold is the pre-1.5 name, still honoured as a fallback.
        legacy = config.get('ml', 'anomaly_threshold', default=None)
        self.contamination = config.get('ml', 'contamination', default=legacy or 0.25)
        self.threshold = config.get('ml', 'alert_threshold', default=legacy or 0.25)
        self.min_samples = config.get('ml', 'min_samples_for_training', default=200)
        self.retrain_interval = config.get('ml', 'retrain_interval_min', default=60) * 60

        # Feature history store (persistent feature vectors)
        self.feature_store = feature_store

        # Feature extraction (must exist before _load_model validates model shape)
        self.feature_extractor = TrafficFeatureExtractor()

        # Models
        self._hmac_key = None
        self.isolation_forest = None
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        self.is_trained = False
        self._last_train_time = 0

        # Baseline
        from src.config import BASELINE_DB
        self.baseline = BaselineProfile(BASELINE_DB)

        # Training data buffer (in-memory session data)
        self._training_buffer = deque(maxlen=5000)

        # Model persistence
        from src.config import MODELS_DIR
        self.model_path = os.path.join(MODELS_DIR, "isolation_forest.pkl")
        self.scaler_path = os.path.join(MODELS_DIR, "scaler.pkl")
        self._load_model()

        # If we have historical data and no trained model, bootstrap from history
        if self.feature_store and not self.is_trained:
            self._bootstrap_from_history()

        # Detail of the strongest beacon in the last analysed window, for alerts.
        self.last_beacon = None
        self.baseline_whitelist = None  # Set by app after init

        logger.info("Anomaly Detector initialized. ML enabled: %s, Trained: %s",
                     self.enabled, self.is_trained)

    def analyze_window(self, flows, packets_window, window_sec=60, local_ips=None):
        """
        Analyze a time window of traffic for anomalies.

        Returns:
            dict with 'anomaly_score', 'is_anomalous', 'reasons', 'features'
        """
        if not self.enabled:
            return {'anomaly_score': 0, 'is_anomalous': False, 'reasons': [], 'features': None}

        features = self.feature_extractor.extract_from_window(
            flows, packets_window, window_sec, local_ips=local_ips)

        # Add to training buffer and baseline
        self._training_buffer.append(features)
        self.baseline.add_sample(features)

        # Check if we should (re)train
        now = time.time()
        if (not self.is_trained and len(self._training_buffer) >= self.min_samples) or \
           (self.is_trained and now - self._last_train_time > self.retrain_interval):
            self._train_model()

        results = {
            'anomaly_score': 0.0,
            'is_anomalous': False,
            'reasons': [],
            # strict=True on purpose: app._build_ml_evidence walks this dict positionally
            # against the baseline mean/std vectors, so a length mismatch must be loud
            # rather than silently misattributing z-scores to the wrong feature.
            'features': dict(zip(self.feature_extractor.feature_names,
                                 features.tolist(), strict=True)),
            'baseline_deviation': 0.0,
            'isolation_score': 0.0,
        }

        # 1. Statistical baseline deviation
        baseline_score = self.baseline.get_deviation_score(features)
        results['baseline_deviation'] = baseline_score

        # 2. Isolation Forest score
        if_score = 0.0
        if self.is_trained and self.isolation_forest is not None:
            try:
                scaled = self.scaler.transform(features.reshape(1, -1))
                raw_score = self.isolation_forest.decision_function(scaled)[0]
                # Convert: negative = anomalous, positive = normal
                if_score = max(0, -raw_score)
                results['isolation_score'] = float(if_score)
            except Exception as e:
                logger.debug("IF scoring error: %s", e)

        # 3. Beaconing detection
        beaconing_score = self._check_beaconing(packets_window)

        # 4. DNS tunneling indicators
        dns_score = self._check_dns_anomalies(packets_window)

        # Combine scores (weighted)
        combined = (
            0.30 * baseline_score +
            0.35 * min(if_score, 1.0) +
            0.15 * beaconing_score +
            0.20 * dns_score
        )

        results['anomaly_score'] = round(combined, 4)
        results['is_anomalous'] = combined > self.threshold

        # Determine reasons
        if baseline_score > 0.5:
            results['reasons'].append(f"Statistical deviation from baseline ({baseline_score:.2f})")
        if if_score > 0.3:
            results['reasons'].append(f"Isolation Forest anomaly ({if_score:.2f})")
        if beaconing_score > 0:
            detail = self.last_beacon or {}
            results['beacon'] = detail
            results['reasons'].append(
                "Beaconing pattern to {} ({})".format(
                    detail.get('destination', 'an external host'),
                    detail.get('reason', 'regular check-ins')))
        if dns_score > 0.5:
            results['reasons'].append("Suspicious DNS activity")

        # Feature-specific alerts (thresholds tuned for modern browsing)
        # Chrome alone routinely uses 70-120+ ports during normal browsing
        if features[3] > 200:  # unique_dst_ports — only flag truly excessive
            results['reasons'].append(f"Very high port diversity: {int(features[3])} unique ports")
        if features[5] > 0.7:  # syn_ratio — very high SYN ratio
            results['reasons'].append(f"Elevated SYN ratio: {features[5]:.2%}")
        if features[7] > 0.5:  # failed_conn_ratio — majority failing
            results['reasons'].append(f"High connection failure rate: {features[7]:.2%}")

        # Record to persistent feature store
        if self.feature_store:
            try:
                self.feature_store.record(features, results)
            except Exception as e:
                logger.debug("Feature store record error: %s", e)

        return results

    def _check_beaconing(self, packets_window):
        """
        Score the most beacon-like external destination in this window.

        Scoring lives in src/beaconing.py; this handles which destinations are
        eligible. The previous implementation required a coefficient of variation
        below 0.05, which only ever caught a beacon with no jitter at all — every
        mainstream C2 framework enables jitter by default.
        """
        # One pass builds all three maps. Previously the set of sources per
        # destination was recomputed by rescanning the whole window inside the
        # per-destination loop, which is O(packets x destinations) every cycle.
        dst_times = defaultdict(list)
        dst_sources = defaultdict(set)
        dst_sizes = defaultdict(list)
        dst_ports = {}
        for p in packets_window:
            if p.dst_ip:
                dst_times[p.dst_ip].append(p.timestamp)
                dst_sources[p.dst_ip].add(p.src_ip)
                dst_sizes[p.dst_ip].append(p.payload_size or p.length)
                if p.dst_port:
                    dst_ports.setdefault(p.dst_ip, p.dst_port)

        max_score = 0.0
        self.last_beacon = None
        threshold = self.config.get('ids', 'beaconing_score_threshold', default=0.75)

        for dst_ip, times in dst_times.items():
            if len(times) < MIN_OBSERVATIONS:
                continue

            # C2 goes to external infrastructure. IoT devices legitimately beacon
            # to local hubs, gateways and each other.
            if not is_global(dst_ip):
                continue

            # Services whose job is to poll look exactly like a beacon, because
            # they are one. Timing cannot separate them, so do not try.
            if is_expected_periodic(dst_port=dst_ports.get(dst_ip, 0)):
                continue

            src_ips = dst_sources[dst_ip]

            # Destinations already beaconing during baseline learning are this
            # network's normal periodic services.
            if self.baseline_whitelist and src_ips:
                if all(self.baseline_whitelist.is_learned_beacon(src, dst_ip)
                       for src in src_ips):
                    continue

            result = score_beacon(times, dst_sizes.get(dst_ip))
            if not result['qualified']:
                continue

            # While learning, record the pattern instead of scoring it.
            if self.baseline_whitelist and self.baseline_whitelist.is_learning:
                if result['score'] >= threshold:
                    for src in src_ips:
                        self.baseline_whitelist.observe_beacon(
                            src, dst_ip, result['interval'])
                continue

            if result['score'] > max_score:
                max_score = result['score']
                self.last_beacon = dict(result, destination=dst_ip,
                                        sources=sorted(src_ips)[:5])

        # Below the threshold this is periodicity, not a finding. Reporting the
        # raw score would let a merely regular connection drift into the combined
        # anomaly score.
        return max_score if max_score >= threshold else 0.0

    def _check_dns_anomalies(self, packets_window):
        """Detect DNS tunneling and other DNS anomalies."""
        dns_queries = [p.dns_query for p in packets_window if p.dns_query]
        if not dns_queries:
            return 0.0

        # Separate mDNS (.local) from real DNS — mDNS is voluminous but benign
        real_dns = [q for q in dns_queries if not q.endswith('.local')]
        if not real_dns:
            return 0.0

        score = 0.0
        max_subdomain_len = self.config.get('ids', 'dns_tunnel_max_subdomain_len', default=50)

        # Check for unusually long subdomains (DNS tunneling indicator)
        # Only count truly long ones (>60 chars) — CDN hashes are typically shorter
        long_queries = [q for q in real_dns if len(q) > max_subdomain_len + 10]
        if long_queries:
            # Need multiple long queries to be confident (one-off = CDN hash)
            ratio = len(long_queries) / max(len(real_dns), 1)
            if len(long_queries) >= 3:
                score = max(score, min(ratio * 2, 1.0))

        # High entropy in DNS query names — only flag if subdomain is very long
        # AND high entropy (CDN hashes are ~20 chars, tunneling is 40-80+)
        high_entropy_count = 0
        for q in real_dns:
            parts = q.split('.')
            if parts and len(parts[0]) > 25:  # Longer threshold
                entropy = TrafficFeatureExtractor._entropy(list(parts[0]))
                if entropy > 4.0:  # Higher entropy threshold
                    high_entropy_count += 1
        if high_entropy_count >= 5:  # Need a pattern, not a one-off
            score = max(score, 0.7)

        # Unusual volume of DNS queries — modern browsing + IoT easily does 30-50/sec
        # Only flag truly extreme rates (likely DNS tunneling or DGA)
        dns_rate = len(real_dns) / 60  # per second (real DNS only, excludes mDNS)
        if dns_rate > 50:  # Raised from 30 — modern networks are chatty
            score = max(score, min(dns_rate / 150, 1.0))

        return score

    def _bootstrap_from_history(self):
        """Load historical feature vectors to seed the training buffer on startup."""
        if not self.feature_store:
            return
        try:
            history_days = self.config.get('ml', 'feature_history_training_days', default=7)
            timestamps, feature_matrix, scores = self.feature_store.load_history(
                days=history_days, max_rows=5000
            )
            if len(timestamps) >= self.min_samples:
                for i in range(len(timestamps)):
                    self._training_buffer.append(feature_matrix[i])
                    self.baseline.add_sample(feature_matrix[i], timestamps[i])
                logger.info(
                    "Bootstrapped from %d historical samples (%d days). "
                    "Training model immediately...",
                    len(timestamps), history_days
                )
                self._train_model()
            elif len(timestamps) > 0:
                for i in range(len(timestamps)):
                    self._training_buffer.append(feature_matrix[i])
                    self.baseline.add_sample(feature_matrix[i], timestamps[i])
                logger.info(
                    "Loaded %d historical samples (need %d to train). "
                    "Will train once threshold is met.",
                    len(timestamps), self.min_samples
                )
        except Exception as e:
            logger.warning("Failed to bootstrap from history: %s", e)

    def _train_model(self):
        """Train or retrain the Isolation Forest model using session + historical data."""
        if not SKLEARN_AVAILABLE:
            return

        # Start with current session buffer
        session_data = np.array(list(self._training_buffer))

        # Blend in historical data if available
        historical_data = None
        if self.feature_store:
            try:
                history_days = self.config.get('ml', 'feature_history_training_days', default=7)
                _, hist_matrix, _ = self.feature_store.load_history(
                    days=history_days, max_rows=10000
                )
                if len(hist_matrix) > 0:
                    historical_data = hist_matrix
            except Exception as e:
                logger.debug("Could not load historical data for training: %s", e)

        # Combine: session data + historical data (deduplicated by size limit)
        if historical_data is not None and len(historical_data) > 0:
            combined = np.vstack([historical_data, session_data])
            # Cap at 15000 rows, keeping most recent
            if len(combined) > 15000:
                combined = combined[-15000:]
            data = combined
            logger.info(
                "Training on %d samples (%d historical + %d session)",
                len(data), len(historical_data), len(session_data)
            )
        else:
            data = session_data

        if len(data) < self.min_samples:
            return

        try:
            logger.info("Training Isolation Forest on %d samples...", len(data))

            # Fit scaler
            self.scaler = StandardScaler()
            scaled_data = self.scaler.fit_transform(data)

            # Train Isolation Forest
            self.isolation_forest = IsolationForest(
                n_estimators=200,
                contamination=self.contamination,
                max_samples='auto',
                random_state=42,
                n_jobs=-1,
            )
            self.isolation_forest.fit(scaled_data)
            self.is_trained = True
            self._last_train_time = time.time()

            # Save model
            self._save_model()

            # Save baseline
            self.baseline.save()

            logger.info("Model training complete. Baseline samples: %d",
                         self.baseline.samples_count)
        except Exception as e:
            logger.error("Model training failed: %s", e)

    def _model_hmac_key(self):
        """
        Key for authenticating model files.

        pickle.load() executes arbitrary code. NetSentinel runs elevated and the model
        directory is user-writable, so an unauthenticated pickle there is a privilege
        escalation primitive. The key lives outside the data directory and is created
        0600, so an attacker who can only write into models/ cannot forge a valid tag.
        """
        if self._hmac_key is not None:
            return self._hmac_key
        from src.config import APP_DIR
        key_path = os.path.join(APP_DIR, ".model_key")
        try:
            if os.path.exists(key_path):
                with open(key_path, 'rb') as f:
                    key = f.read()
                if len(key) == 32:
                    self._hmac_key = key
                    return key
            key = os.urandom(32)
            with open(key_path, 'wb') as f:
                f.write(key)
            try:
                os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
            self._hmac_key = key
            return key
        except OSError as e:
            logger.warning("Could not establish model signing key: %s", e)
            return None

    def _save_model(self):
        """Persist trained model to disk with an authentication tag."""
        key = self._model_hmac_key()
        if key is None:
            logger.warning("No signing key available — not persisting model.")
            return
        try:
            for obj, path in ((self.isolation_forest, self.model_path),
                              (self.scaler, self.scaler_path)):
                if obj is None:
                    continue
                blob = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
                tag = hmac.new(key, blob, hashlib.sha256).digest()
                tmp = f"{path}.tmp"
                with open(tmp, 'wb') as f:
                    f.write(tag + blob)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, path)
        except Exception as e:
            logger.error("Failed to save model: %s", e)

    def _load_one_model(self, path, key):
        """Verify and load a single signed pickle. Returns None if it fails."""
        with open(path, 'rb') as f:
            data = f.read()
        if len(data) <= 32:
            raise ValueError(f"{os.path.basename(path)} is truncated")
        tag, blob = data[:32], data[32:]
        if not hmac.compare_digest(tag, hmac.new(key, blob, hashlib.sha256).digest()):
            raise ValueError(
                f"{os.path.basename(path)} failed integrity check — refusing to unpickle"
            )
        return pickle.loads(blob)

    def _load_model(self):
        """Load a previously trained model, if it is intact and still compatible."""
        if not (os.path.exists(self.model_path) and os.path.exists(self.scaler_path)):
            return
        key = self._model_hmac_key()
        if key is None:
            return
        try:
            forest = self._load_one_model(self.model_path, key)
            scaler = self._load_one_model(self.scaler_path, key)

            # A model trained on a different feature vector silently produces garbage
            # (or throws inside analyze_window, where the error is swallowed), so the
            # shape is checked here rather than discovered later.
            expected = len(self.feature_extractor.feature_names)
            actual = getattr(scaler, 'n_features_in_', expected)
            if actual != expected:
                logger.warning(
                    "Stored model expects %d features but this build produces %d. "
                    "Discarding it; a new model will be trained.", actual, expected)
                return

            self.isolation_forest = forest
            self.scaler = scaler
            self.is_trained = True
            logger.info("Loaded pre-trained model from disk.")
        except Exception as e:
            logger.warning("Could not load model (%s). A new one will be trained.", e)

    def get_status(self):
        """Return current ML engine status."""
        status = {
            'enabled': self.enabled,
            'sklearn_available': SKLEARN_AVAILABLE,
            'is_trained': self.is_trained,
            'training_samples': len(self._training_buffer),
            'min_samples_needed': self.min_samples,
            'baseline_samples': self.baseline.samples_count,
            'threshold': self.threshold,
            'contamination': self.contamination,
        }
        if self.feature_store:
            fs_stats = self.feature_store.get_storage_stats()
            status['feature_store'] = fs_stats
            status['history_size_mb'] = fs_stats.get('total_size_mb', 0)
            status['history_rows'] = fs_stats.get('total_rows_written', 0)
            status['history_oldest'] = fs_stats.get('oldest_date', '—')
            status['history_newest'] = fs_stats.get('newest_date', '—')
        return status
