"""
Alert Management System
=======================
Stores, filters, and manages security alerts.
Supports desktop notifications and sound alerts.
"""

import os
import json
import time
import logging
import threading
from collections import deque
from datetime import datetime

logger = logging.getLogger("NetSentinel.Alerts")


class AlertManager:
    """Manages alert storage, filtering, and notifications."""

    def __init__(self, config):
        self.config = config
        self.max_stored = config.get('alerts', 'max_stored', default=5000)
        self.severity_filter = config.get('alerts', 'severity_filter', default='LOW')
        self.sound_enabled = config.get('alerts', 'sound_enabled', default=True)
        self.desktop_notify = config.get('alerts', 'desktop_notifications', default=True)

        self._alerts = deque(maxlen=self.max_stored)
        self._lock = threading.Lock()
        self._listeners = []  # GUI callbacks

        # Stats
        self.stats = {
            'total': 0,
            'by_severity': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0},
            'by_category': {},
            'last_alert_time': 0,
            'rate_history': deque(maxlen=360),  # (timestamp, count) per 10-second bucket
        }
        self._rate_bucket_start = time.time()
        self._rate_bucket_count = 0

        from src.config import ALERTS_DB
        self.db_path = ALERTS_DB
        self._load_alerts()

        # Notification batching: collect HIGH/CRITICAL alerts and send
        # a single desktop notification summarizing them
        self._notify_batch = []
        self._notify_batch_start = 0
        self._notify_batch_interval = 15  # Batch notifications over 15 seconds
        self._last_sound_time = 0
        self._sound_cooldown = 10  # Min seconds between alert sounds

    def add_alert(self, alert):
        """Add a new alert to the store."""
        severity_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        min_level = severity_order.get(self.severity_filter, 0)
        alert_level = severity_order.get(alert.severity, 0)

        if alert_level < min_level:
            return  # Below filter threshold

        with self._lock:
            self._alerts.appendleft(alert)
            self.stats['total'] += 1
            self.stats['by_severity'][alert.severity] = \
                self.stats['by_severity'].get(alert.severity, 0) + 1
            self.stats['by_category'][alert.category] = \
                self.stats['by_category'].get(alert.category, 0) + 1
            self.stats['last_alert_time'] = alert.timestamp

            # Alert rate tracking (10-second buckets for trend display)
            now = time.time()
            self._rate_bucket_count += 1
            if now - self._rate_bucket_start >= 10:
                self.stats['rate_history'].append(
                    (self._rate_bucket_start, self._rate_bucket_count))
                self._rate_bucket_start = now
                self._rate_bucket_count = 0

        # Notify listeners (GUI)
        for listener in self._listeners:
            try:
                listener(alert)
            except Exception as e:
                logger.debug("Listener error: %s", e)

        # Desktop notification for HIGH/CRITICAL (batched)
        if alert_level >= 2 and self.desktop_notify:
            self._batch_notification(alert)

        # Sound for CRITICAL (with cooldown to prevent spam)
        if alert.severity == 'CRITICAL' and self.sound_enabled:
            now = time.time()
            if now - self._last_sound_time >= self._sound_cooldown:
                self._last_sound_time = now
                self._play_sound()

    def register_listener(self, callback):
        """Register a callback for new alerts."""
        self._listeners.append(callback)

    def get_alerts(self, limit=100, severity=None, category=None,
                   since=None, acknowledged=None):
        """Query alerts with filters."""
        with self._lock:
            results = list(self._alerts)

        if severity:
            results = [a for a in results if a.severity == severity]
        if category:
            results = [a for a in results if a.category == category]
        if since:
            results = [a for a in results if a.timestamp >= since]
        if acknowledged is not None:
            results = [a for a in results if a.acknowledged == acknowledged]

        return results[:limit]

    def acknowledge_alert(self, alert_id):
        """Mark an alert as acknowledged."""
        with self._lock:
            for alert in self._alerts:
                if alert.id == alert_id:
                    alert.acknowledged = True
                    return True
        return False

    def acknowledge_all(self):
        """Mark all alerts as acknowledged."""
        with self._lock:
            for alert in self._alerts:
                alert.acknowledged = True

    def clear_alerts(self):
        """Clear all stored alerts."""
        with self._lock:
            self._alerts.clear()
            self.stats = {
                'total': 0,
                'by_severity': {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0},
                'by_category': {},
                'last_alert_time': 0,
                'rate_history': self.stats.get('rate_history', deque(maxlen=360)),
            }

    def save_alerts(self):
        """Persist alerts to disk."""
        try:
            with self._lock:
                data = [a.to_dict() for a in list(self._alerts)[:500]]
            with open(self.db_path, 'w') as f:
                json.dump(data, f, indent=1)
        except Exception as e:
            logger.error("Failed to save alerts: %s", e)

    def _load_alerts(self):
        """Load alerts from disk and reconstruct Alert objects."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                from src.ids_engine import Alert
                for item in data:
                    alert = Alert(
                        rule_id=item.get('rule_id', ''),
                        severity=item.get('severity', 'LOW'),
                        title=item.get('title', ''),
                        description=item.get('description', ''),
                        src_ip=item.get('src_ip', ''),
                        dst_ip=item.get('dst_ip', ''),
                        src_port=item.get('src_port', 0),
                        dst_port=item.get('dst_port', 0),
                        protocol=item.get('protocol', ''),
                        evidence=item.get('evidence', {}),
                        category=item.get('category', ''),
                    )
                    alert.timestamp = item.get('timestamp', time.time())
                    alert.acknowledged = item.get('acknowledged', False)
                    self._alerts.appendleft(alert)
                    self.stats['total'] += 1
                    self.stats['by_severity'][alert.severity] = \
                        self.stats['by_severity'].get(alert.severity, 0) + 1
                    self.stats['by_category'][alert.category] = \
                        self.stats['by_category'].get(alert.category, 0) + 1
                logger.info("Loaded %d historical alerts", len(data))
            except Exception as e:
                logger.error("Failed to load alerts: %s", e)

    def export_alerts(self, filepath, format='json', severity=None,
                     category=None, since=None, until=None):
        """Export alerts to a file with optional filters. Returns number exported."""
        with self._lock:
            data = [a.to_dict() for a in self._alerts]

        # Apply filters
        if severity:
            data = [a for a in data if a['severity'] == severity]
        if category:
            data = [a for a in data if a['category'] == category]
        if since:
            data = [a for a in data if a['timestamp'] >= since]
        if until:
            data = [a for a in data if a['timestamp'] <= until]

        if not data:
            return 0

        if format == 'json':
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        elif format == 'csv':
            import csv
            # Flatten evidence dict into top-level columns for CSV
            flat_rows = []
            for row in data:
                flat = {k: v for k, v in row.items() if k != 'evidence'}
                evidence = row.get('evidence', {})
                if isinstance(evidence, dict):
                    for ek, ev in evidence.items():
                        # Stringify complex values
                        if isinstance(ev, (list, dict)):
                            flat[f'evidence_{ek}'] = json.dumps(ev, default=str)
                        else:
                            flat[f'evidence_{ek}'] = ev
                flat_rows.append(flat)

            # Collect all keys across all rows
            all_keys = []
            seen = set()
            for row in flat_rows:
                for k in row.keys():
                    if k not in seen:
                        all_keys.append(k)
                        seen.add(k)

            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(flat_rows)

        return len(data)

    def get_alert_rate(self, minutes=60):
        """Return alert rate history as list of (timestamp, count) for the given window."""
        cutoff = time.time() - (minutes * 60)
        with self._lock:
            return [(ts, count) for ts, count in self.stats['rate_history']
                    if ts >= cutoff]

    def _batch_notification(self, alert):
        """Batch desktop notifications to avoid spam."""
        now = time.time()
        self._notify_batch.append(alert)

        if not self._notify_batch_start:
            self._notify_batch_start = now

        # Flush batch after the interval
        if now - self._notify_batch_start >= self._notify_batch_interval:
            batch = self._notify_batch
            self._notify_batch = []
            self._notify_batch_start = 0

            if len(batch) == 1:
                self._desktop_notify(batch[0])
            elif len(batch) > 1:
                # Summarize the batch
                crit = sum(1 for a in batch if a.severity == 'CRITICAL')
                high = sum(1 for a in batch if a.severity == 'HIGH')
                summary = f"{len(batch)} alerts"
                parts = []
                if crit:
                    parts.append(f"{crit} CRITICAL")
                if high:
                    parts.append(f"{high} HIGH")
                if parts:
                    summary += f" ({', '.join(parts)})"
                self._desktop_notify_text("NetSentinel Alert Batch", summary)

    def _desktop_notify_text(self, title, message):
        """Send a desktop notification with custom text."""
        try:
            from plyer import notification
            notification.notify(
                title=title,
                message=message[:200],
                app_name="NetSentinel",
                timeout=10,
            )
        except Exception:
            pass

    def _desktop_notify(self, alert):
        """Send a desktop notification (Windows)."""
        try:
            from plyer import notification
            notification.notify(
                title=f"[{alert.severity}] {alert.title}",
                message=alert.description[:200],
                app_name="NetSentinel",
                timeout=10,
            )
        except ImportError:
            # Fallback: Windows toast via PowerShell
            try:
                if os.name == 'nt':
                    import subprocess
                    ps_cmd = (
                        f'[Windows.UI.Notifications.ToastNotificationManager, '
                        f'Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; '
                        f'$template = [Windows.UI.Notifications.ToastNotificationManager]::'
                        f'GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::'
                        f'ToastText02); '
                        f'$textNodes = $template.GetElementsByTagName("text"); '
                        f'$textNodes.Item(0).AppendChild($template.CreateTextNode('
                        f'"NetSentinel: {alert.severity}")) | Out-Null; '
                        f'$textNodes.Item(1).AppendChild($template.CreateTextNode('
                        f'"{alert.title}")) | Out-Null; '
                    )
                    # Simple fallback - just log it
                    pass
            except Exception:
                pass

    def _play_sound(self):
        """Play an alert sound."""
        try:
            if os.name == 'nt':
                import winsound
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            else:
                print('\a')  # Terminal bell
        except Exception:
            pass

    def get_stats(self):
        """Return alert statistics with rate trend."""
        with self._lock:
            unack = sum(1 for a in self._alerts if not a.acknowledged)
            # Current rate: alerts in last 60 seconds
            now = time.time()
            recent = sum(1 for a in self._alerts if now - a.timestamp < 60)
        return {
            **{k: v for k, v in self.stats.items() if k != 'rate_history'},
            'unacknowledged': unack,
            'stored': len(self._alerts),
            'alerts_per_minute': recent,
            'rate_history': list(self.stats['rate_history'])[-60:],  # Last 10 min of buckets
        }
