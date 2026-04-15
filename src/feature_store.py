"""
Feature History Store
=====================
Persists extracted feature vectors to disk in lightweight CSV format.
Supports automatic file rotation, historical loading for ML training,
and anomaly score tracking over time.

Storage format: CSV with timestamp + 18 features + anomaly_score per row
~220 bytes per row → ~2.5 MB per day at 5-second intervals → ~75 MB/month

Automatic rotation keeps individual files manageable and allows
pruning old data by simply deleting old files.
"""

import os
import csv
import glob
import time
import logging
import threading
import numpy as np
from datetime import datetime, timedelta
from collections import deque

logger = logging.getLogger("NetSentinel.FeatureStore")

# Feature column names (must match TrafficFeatureExtractor output order)
FEATURE_COLUMNS = [
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

ALL_COLUMNS = ['timestamp', 'datetime'] + FEATURE_COLUMNS + [
    'anomaly_score', 'baseline_deviation', 'isolation_score', 'is_anomalous'
]


class FeatureStore:
    """
    Persistent storage for extracted feature vectors.
    Saves to daily CSV files with automatic rotation and cleanup.
    """

    def __init__(self, config):
        from src.config import DB_DIR
        self.store_dir = os.path.join(DB_DIR, "feature_history")
        os.makedirs(self.store_dir, exist_ok=True)

        self.config = config
        self.enabled = True
        self.max_days = config.get('ml', 'feature_history_days', default=90)

        # Write buffer to reduce disk I/O
        self._buffer = deque(maxlen=100)
        self._buffer_lock = threading.Lock()
        self._current_file = None
        self._current_date = None
        self._writer = None
        self._file_handle = None

        # In-memory recent history for quick dashboard access
        self._recent_scores = deque(maxlen=1080)  # 90 min at 5-sec intervals

        # Stats
        self.total_rows_written = 0
        self.total_rows_loaded = 0

        # Start background flush thread
        self._running = True
        self._flush_thread = threading.Thread(
            target=self._flush_loop, daemon=True, name="FeatureFlush"
        )
        self._flush_thread.start()

        # Cleanup old files on startup
        self._cleanup_old_files()

        logger.info(
            "Feature store initialized at %s (retaining %d days)",
            self.store_dir, self.max_days
        )

    def record(self, features, ml_result):
        """
        Record a feature vector and its analysis results.

        Args:
            features: numpy array of 18 feature values
            ml_result: dict with anomaly_score, baseline_deviation, etc.
        """
        if not self.enabled:
            return

        now = time.time()
        dt_str = datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')

        row = {
            'timestamp': now,
            'datetime': dt_str,
            'anomaly_score': round(ml_result.get('anomaly_score', 0), 6),
            'baseline_deviation': round(ml_result.get('baseline_deviation', 0), 6),
            'isolation_score': round(ml_result.get('isolation_score', 0), 6),
            'is_anomalous': int(ml_result.get('is_anomalous', False)),
        }

        # Add feature values
        for i, col in enumerate(FEATURE_COLUMNS):
            row[col] = round(float(features[i]), 6) if i < len(features) else 0

        with self._buffer_lock:
            self._buffer.append(row)

        # Track recent scores for dashboard
        self._recent_scores.append({
            'timestamp': now,
            'anomaly_score': row['anomaly_score'],
            'baseline_deviation': row['baseline_deviation'],
            'isolation_score': row['isolation_score'],
            'is_anomalous': row['is_anomalous'],
        })

    def _get_file_for_date(self, date_str):
        """Get or create the CSV file for a given date."""
        if date_str != self._current_date:
            # Close previous file
            self._close_current_file()

            filepath = os.path.join(self.store_dir, f"features_{date_str}.csv")
            file_exists = os.path.exists(filepath)

            self._file_handle = open(filepath, 'a', newline='', buffering=8192)
            self._writer = csv.DictWriter(self._file_handle, fieldnames=ALL_COLUMNS)

            if not file_exists:
                self._writer.writeheader()
                logger.info("Created new feature history file: %s", filepath)

            self._current_date = date_str
            self._current_file = filepath

        return self._writer

    def _flush_buffer(self):
        """Write buffered rows to disk."""
        with self._buffer_lock:
            if not self._buffer:
                return
            rows = list(self._buffer)
            self._buffer.clear()

        try:
            for row in rows:
                date_str = datetime.fromtimestamp(row['timestamp']).strftime('%Y-%m-%d')
                writer = self._get_file_for_date(date_str)
                writer.writerow(row)
                self.total_rows_written += 1

            if self._file_handle:
                self._file_handle.flush()
        except Exception as e:
            logger.error("Failed to flush feature buffer: %s", e)
            # Ensure file handle is in a sane state after error
            try:
                if self._file_handle:
                    self._file_handle.flush()
            except Exception:
                self._close_current_file()

    def _flush_loop(self):
        """Background thread that flushes the buffer periodically."""
        while self._running:
            time.sleep(10)  # Flush every 10 seconds
            self._flush_buffer()

    def _close_current_file(self):
        """Close the current file handle."""
        if self._file_handle:
            try:
                self._file_handle.close()
            except Exception:
                pass
            self._file_handle = None
            self._writer = None
            self._current_date = None

    def load_history(self, days=None, max_rows=None):
        """
        Load historical feature vectors from disk.

        Args:
            days: Number of days of history to load (None = all available)
            max_rows: Maximum rows to return (None = unlimited)

        Returns:
            tuple: (timestamps, feature_matrix, scores)
                - timestamps: list of float timestamps
                - feature_matrix: numpy array of shape (n, 18)
                - scores: list of dicts with score fields
        """
        # Flush any pending data first
        self._flush_buffer()

        files = sorted(glob.glob(os.path.join(self.store_dir, "features_*.csv")))

        if days is not None:
            cutoff = datetime.now() - timedelta(days=days)
            cutoff_str = cutoff.strftime('%Y-%m-%d')
            files = [f for f in files
                     if os.path.basename(f).replace('features_', '').replace('.csv', '') >= cutoff_str]

        timestamps = []
        features_list = []
        scores = []

        for filepath in files:
            try:
                with open(filepath, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        ts = float(row.get('timestamp', 0))
                        timestamps.append(ts)

                        fv = []
                        for col in FEATURE_COLUMNS:
                            fv.append(float(row.get(col, 0)))
                        features_list.append(fv)

                        scores.append({
                            'anomaly_score': float(row.get('anomaly_score', 0)),
                            'baseline_deviation': float(row.get('baseline_deviation', 0)),
                            'isolation_score': float(row.get('isolation_score', 0)),
                            'is_anomalous': int(row.get('is_anomalous', 0)),
                        })
            except Exception as e:
                logger.warning("Error reading %s: %s", filepath, e)
                continue

        self.total_rows_loaded = len(timestamps)

        # Apply max_rows (take most recent)
        if max_rows and len(timestamps) > max_rows:
            timestamps = timestamps[-max_rows:]
            features_list = features_list[-max_rows:]
            scores = scores[-max_rows:]

        feature_matrix = np.array(features_list) if features_list else np.empty((0, 18))

        logger.info(
            "Loaded %d feature vectors from %d files (%d days)",
            len(timestamps), len(files),
            days if days else len(files)
        )

        return timestamps, feature_matrix, scores

    def get_recent_scores(self, minutes=90):
        """Get recent anomaly scores from memory for dashboard display."""
        cutoff = time.time() - (minutes * 60)
        return [s for s in self._recent_scores if s['timestamp'] >= cutoff]

    def get_daily_summary(self, days=30):
        """
        Compute daily summary statistics from stored history.

        Returns:
            list of dicts: [{date, avg_score, max_score, anomaly_count, total_samples}, ...]
        """
        self._flush_buffer()
        files = sorted(glob.glob(os.path.join(self.store_dir, "features_*.csv")))

        cutoff = datetime.now() - timedelta(days=days)
        cutoff_str = cutoff.strftime('%Y-%m-%d')
        files = [f for f in files
                 if os.path.basename(f).replace('features_', '').replace('.csv', '') >= cutoff_str]

        summaries = []
        for filepath in files:
            date_str = os.path.basename(filepath).replace('features_', '').replace('.csv', '')
            scores = []
            anomaly_count = 0
            try:
                with open(filepath, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        s = float(row.get('anomaly_score', 0))
                        scores.append(s)
                        if int(row.get('is_anomalous', 0)):
                            anomaly_count += 1
            except Exception:
                continue

            if scores:
                summaries.append({
                    'date': date_str,
                    'avg_score': round(np.mean(scores), 4),
                    'max_score': round(max(scores), 4),
                    'min_score': round(min(scores), 4),
                    'anomaly_count': anomaly_count,
                    'total_samples': len(scores),
                    'anomaly_pct': round(100 * anomaly_count / len(scores), 2),
                })

        return summaries

    def get_storage_stats(self):
        """Return storage usage information."""
        files = glob.glob(os.path.join(self.store_dir, "features_*.csv"))
        total_size = sum(os.path.getsize(f) for f in files)
        oldest = None
        newest = None
        if files:
            dates = [os.path.basename(f).replace('features_', '').replace('.csv', '')
                     for f in sorted(files)]
            oldest = dates[0]
            newest = dates[-1]

        return {
            'enabled': self.enabled,
            'file_count': len(files),
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'total_rows_written': self.total_rows_written,
            'total_rows_loaded': self.total_rows_loaded,
            'oldest_date': oldest,
            'newest_date': newest,
            'max_days_retention': self.max_days,
            'store_dir': self.store_dir,
        }

    def _cleanup_old_files(self):
        """Delete feature files older than max_days."""
        cutoff = datetime.now() - timedelta(days=self.max_days)
        cutoff_str = cutoff.strftime('%Y-%m-%d')

        files = glob.glob(os.path.join(self.store_dir, "features_*.csv"))
        removed = 0
        for filepath in files:
            date_str = os.path.basename(filepath).replace('features_', '').replace('.csv', '')
            if date_str < cutoff_str:
                try:
                    os.remove(filepath)
                    removed += 1
                except Exception as e:
                    logger.warning("Could not remove old file %s: %s", filepath, e)

        if removed:
            logger.info("Cleaned up %d feature files older than %d days", removed, self.max_days)

    def shutdown(self):
        """Flush remaining data and close files."""
        self._running = False
        self._flush_buffer()
        self._close_current_file()
        logger.info("Feature store shut down. Total rows written: %d", self.total_rows_written)

    def __del__(self):
        """Safety net: close file handle if shutdown() wasn't called."""
        try:
            if self._file_handle and not self._file_handle.closed:
                self._file_handle.close()
        except Exception:
            pass
