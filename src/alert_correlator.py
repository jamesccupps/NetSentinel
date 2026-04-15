"""
Alert Correlation Engine
==========================
Groups related security alerts into unified Incidents.

Correlation rules:
- Same source IP within a time window → single incident
- Port scan + brute force from same IP → "Reconnaissance then Attack"
- Threat intel hit + data exfil to same IP → "Active Compromise"
- Multiple forensics findings for same service → single service alert

Each incident has:
- A severity (highest of member alerts)
- A narrative summary
- A list of member alerts
- A recommended action

This dramatically reduces alert fatigue by presenting 50 related alerts
as a single "Port scan from 10.0.0.5 targeting 15 ports, followed by
brute force on SSH" instead of 50 individual entries.
"""

import time
import logging
import threading
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("NetSentinel.Correlator")

# Time window for correlating alerts (seconds)
_CORRELATION_WINDOW = 300  # 5 minutes

# Alert categories that indicate escalation when seen together
_ESCALATION_CHAINS = [
    # Recon → Attack
    (['Reconnaissance', 'Suspicious Port'], ['Brute Force', 'DoS']),
    # Threat Intel → Exfiltration
    (['Threat Intelligence'], ['Exfiltration', 'Data Exposure']),
    # Credential exposure → Suspicious activity
    (['Credential Exposure'], ['Brute Force', 'Threat Intelligence']),
]


class Incident:
    """A group of correlated alerts forming a single security incident."""

    _id_counter = 0
    _lock = threading.Lock()

    def __init__(self):
        with Incident._lock:
            Incident._id_counter += 1
            self.id = Incident._id_counter
        self.created = time.time()
        self.updated = self.created
        self.alerts = []
        self.severity = "LOW"
        self.title = ""
        self.narrative = ""
        self.source_ips = set()
        self.dest_ips = set()
        self.categories = set()
        self.rule_ids = set()
        self.is_escalation = False
        self.acknowledged = False

    def add_alert(self, alert):
        """Add an alert to this incident."""
        self.alerts.append(alert)
        self.updated = time.time()
        if alert.src_ip:
            self.source_ips.add(alert.src_ip)
        if alert.dst_ip:
            self.dest_ips.add(alert.dst_ip)
        self.categories.add(alert.category)
        self.rule_ids.add(alert.rule_id)

        # Severity is the highest of any member
        severity_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
        if severity_order.get(alert.severity, 0) > severity_order.get(self.severity, 0):
            self.severity = alert.severity

        self._update_narrative()

    def _update_narrative(self):
        """Generate a human-readable summary of this incident."""
        n = len(self.alerts)
        cats = sorted(self.categories)
        src_list = sorted(self.source_ips)[:3]
        dst_list = sorted(self.dest_ips)[:3]

        src_str = ', '.join(src_list)
        if len(self.source_ips) > 3:
            src_str += f" (+{len(self.source_ips) - 3} more)"

        if self.is_escalation:
            self.title = f"Escalation: {' → '.join(cats)}"
            self.narrative = (
                f"{n} related alerts from {src_str} showing escalating behavior: "
                f"{' then '.join(cats)}. This pattern suggests a coordinated attack."
            )
        elif len(cats) == 1:
            self.title = f"{cats[0]} ({n} alerts)"
            self.narrative = (
                f"{n} {cats[0]} alerts from {src_str} within "
                f"{int(self.updated - self.created)}s."
            )
        else:
            self.title = f"Multi-vector incident ({n} alerts)"
            self.narrative = (
                f"{n} alerts across {len(cats)} categories ({', '.join(cats)}) "
                f"from {src_str}."
            )

    def to_dict(self):
        return {
            'id': self.id,
            'created': self.created,
            'created_str': datetime.fromtimestamp(self.created).strftime('%Y-%m-%d %H:%M:%S'),
            'updated': self.updated,
            'severity': self.severity,
            'title': self.title,
            'narrative': self.narrative,
            'alert_count': len(self.alerts),
            'source_ips': sorted(self.source_ips),
            'dest_ips': sorted(self.dest_ips),
            'categories': sorted(self.categories),
            'rule_ids': sorted(self.rule_ids),
            'is_escalation': self.is_escalation,
            'acknowledged': self.acknowledged,
            'alerts': [a.to_dict() for a in self.alerts[-20:]],  # Last 20 for display
        }


class AlertCorrelator:
    """
    Correlates incoming alerts into incidents based on source IP,
    time proximity, and category escalation patterns.
    """

    def __init__(self, config):
        self.config = config
        self._lock = threading.Lock()

        # Active incidents: {correlation_key: Incident}
        self._active_incidents = {}

        # All incidents (including closed): deque for bounded storage
        from collections import deque
        self._all_incidents = deque(maxlen=1000)

        # Callbacks for new/updated incidents
        self._listeners = []

        # Cleanup interval
        self._last_cleanup = time.time()

        # Persistence
        from src.config import DB_DIR
        import os
        self._db_path = os.path.join(DB_DIR, "incidents.json")
        self._load()

        logger.info("Alert correlator initialized (%d historical incidents)",
                    len(self._all_incidents))

    def register_listener(self, callback):
        """Register a callback for incident updates."""
        self._listeners.append(callback)

    def process_alert(self, alert):
        """
        Process an incoming alert. Either adds it to an existing incident
        or creates a new one. Returns the Incident it was added to.
        """
        with self._lock:
            # Find a matching active incident
            incident = self._find_matching_incident(alert)

            if incident is None:
                # Create new incident
                incident = Incident()
                key = self._correlation_key(alert)
                self._active_incidents[key] = incident
                self._all_incidents.append(incident)

            incident.add_alert(alert)

            # Check for escalation patterns
            self._check_escalation(incident)

            # Re-generate narrative after escalation check may have changed state
            incident._update_narrative()

            # Cleanup stale incidents
            self._periodic_cleanup()

        # Notify listeners (outside lock)
        for listener in self._listeners:
            try:
                listener(incident)
            except Exception as e:
                logger.debug("Correlator listener error: %s", e)

        return incident

    def _correlation_key(self, alert):
        """Generate a key for grouping alerts into the same incident."""
        # Group by source IP primarily
        return f"{alert.src_ip}:{alert.category}"

    def _find_matching_incident(self, alert):
        """Find an active incident this alert belongs to. Must hold lock."""
        now = time.time()
        key = self._correlation_key(alert)

        # Exact key match within time window
        if key in self._active_incidents:
            incident = self._active_incidents[key]
            if now - incident.updated < _CORRELATION_WINDOW:
                return incident

        # Also check if same source IP has a recent incident (cross-category)
        for ikey, incident in self._active_incidents.items():
            if now - incident.updated > _CORRELATION_WINDOW:
                continue
            if alert.src_ip and alert.src_ip in incident.source_ips:
                return incident

        return None

    def _check_escalation(self, incident):
        """Check if the incident's categories match an escalation chain."""
        cats = incident.categories
        for stage1_cats, stage2_cats in _ESCALATION_CHAINS:
            has_stage1 = any(c in cats for c in stage1_cats)
            has_stage2 = any(c in cats for c in stage2_cats)
            if has_stage1 and has_stage2:
                incident.is_escalation = True
                # Escalation always bumps to at least HIGH
                severity_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
                if severity_order.get(incident.severity, 0) < 2:
                    incident.severity = "HIGH"
                return

    def _periodic_cleanup(self):
        """Remove stale incidents from the active set."""
        now = time.time()
        if now - self._last_cleanup < 60:
            return
        self._last_cleanup = now

        stale_keys = [
            k for k, inc in self._active_incidents.items()
            if now - inc.updated > _CORRELATION_WINDOW * 2
        ]
        for k in stale_keys:
            del self._active_incidents[k]

    def get_incidents(self, limit=50, severity=None, active_only=False):
        """Query incidents with optional filters."""
        with self._lock:
            results = list(self._all_incidents)

        if active_only:
            now = time.time()
            results = [i for i in results if now - i.updated < _CORRELATION_WINDOW]
        if severity:
            results = [i for i in results if i.severity == severity]

        # Most recent first
        results.sort(key=lambda i: i.updated, reverse=True)
        return results[:limit]

    def get_stats(self):
        """Return correlator statistics."""
        with self._lock:
            active = sum(1 for i in self._active_incidents.values()
                        if time.time() - i.updated < _CORRELATION_WINDOW)
            escalations = sum(1 for i in self._all_incidents if i.is_escalation)
        return {
            'total_incidents': len(self._all_incidents),
            'active_incidents': active,
            'escalation_incidents': escalations,
        }

    def save(self):
        """Persist incident summaries to disk (last 200 incidents)."""
        import json, os
        with self._lock:
            data = []
            for inc in list(self._all_incidents)[-200:]:
                data.append({
                    'created': inc.created,
                    'updated': inc.updated,
                    'severity': inc.severity,
                    'title': inc.title,
                    'narrative': inc.narrative,
                    'alert_count': len(inc.alerts),
                    'source_ips': sorted(inc.source_ips),
                    'dest_ips': sorted(inc.dest_ips),
                    'categories': sorted(inc.categories),
                    'rule_ids': sorted(inc.rule_ids),
                    'is_escalation': inc.is_escalation,
                    'acknowledged': inc.acknowledged,
                })
        try:
            with open(self._db_path, 'w') as f:
                json.dump(data, f, indent=1)
            logger.info("Saved %d incident summaries", len(data))
        except Exception as e:
            logger.error("Failed to save incidents: %s", e)

    def _load(self):
        """Load incident summaries from disk (read-only history)."""
        import json, os
        if not os.path.exists(self._db_path):
            return
        try:
            with open(self._db_path, 'r') as f:
                data = json.load(f)
            for item in data:
                inc = Incident()
                inc.created = item.get('created', time.time())
                inc.updated = item.get('updated', inc.created)
                inc.severity = item.get('severity', 'LOW')
                inc.title = item.get('title', '')
                inc.narrative = item.get('narrative', '')
                inc.source_ips = set(item.get('source_ips', []))
                inc.dest_ips = set(item.get('dest_ips', []))
                inc.categories = set(item.get('categories', []))
                inc.rule_ids = set(item.get('rule_ids', []))
                inc.is_escalation = item.get('is_escalation', False)
                inc.acknowledged = item.get('acknowledged', False)
                self._all_incidents.append(inc)
            logger.info("Loaded %d historical incidents", len(data))
        except Exception as e:
            logger.error("Failed to load incidents: %s", e)
