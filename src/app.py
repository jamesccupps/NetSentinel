"""
NetSentinel Application Orchestrator
=====================================
Ties together all components: capture, analysis, ML, IDS, alerts, and GUI.
"""

import time
import logging
import threading
from collections import deque

from src.ids_engine import Severity

logger = logging.getLogger("NetSentinel.App")

# How long a restart waits for the last run's capture threads to exit.
CAPTURE_EXIT_WAIT = 6

# Rules whose verification does file hashing, PowerShell and VirusTotal lookups.
# Those run with 10-second timeouts, so doing them inline on the packet worker
# stalls the whole capture pipeline exactly when something interesting happens.
_SLOW_VERIFY_RULES = frozenset({
    'IOC-SUSPICIOUS-PROC', 'IOC-PROC-NAME', 'IOC-LISTEN-PORT', 'IOC-ACTIVE-THREAT',
})


def _note_severity_change(alert, before):
    """
    Keep the severity an alert had before verification changed it.

    The verifier lowers likely false positives to LOW. Those are what a reviewer
    most needs to see, with what the detection itself thought.
    """
    if alert.severity != before:
        alert.evidence['severity_before_verification'] = before

# Human-readable names and units for ML feature vector elements.
# Defined at module level to avoid rebuilding on every alert.
_FEATURE_INFO = {
    'bytes_per_sec':       ('Bandwidth',           '{:.0f} bytes/sec',  'How much data is flowing per second'),
    'packets_per_sec':     ('Packet Rate',         '{:.0f} pkts/sec',   'Number of packets per second'),
    'avg_packet_size':     ('Avg Packet Size',     '{:.0f} bytes',      'Average size of each packet'),
    'unique_dst_ports':    ('Unique Dest Ports',   '{:.0f} ports',      'Number of different ports being contacted'),
    'unique_dst_ips':      ('Unique Dest IPs',     '{:.0f} IPs',        'Number of different IPs being contacted'),
    'syn_ratio':           ('SYN Ratio',           '{:.1%}',            'Percentage of packets that are new connection requests'),
    'dns_query_rate':      ('DNS Query Rate',      '{:.1f} queries/sec','DNS lookups per second'),
    'failed_conn_ratio':   ('Failed Connections',  '{:.1%}',            'Percentage of connections that were rejected'),
    'entropy_dst_port':    ('Port Entropy',        '{:.2f} bits',       'Randomness of destination ports (high = scanning)'),
    'avg_inter_arrival':   ('Avg Time Between Pkts', '{:.4f} sec',      'Average gap between consecutive packets'),
    'std_inter_arrival':   ('Timing Variability',  '{:.4f} sec',        'How irregular the packet timing is'),
    'payload_ratio':       ('Payload Ratio',       '{:.1%}',            'Proportion of packets carrying actual data'),
    'direction_asymmetry': ('Traffic Asymmetry',   '{:.1%}',            'Imbalance between upload and download'),
    'small_packet_ratio':  ('Small Packets',       '{:.1%}',            'Proportion of very small packets (<100 bytes)'),
    'large_packet_ratio':  ('Large Packets',       '{:.1%}',            'Proportion of large packets (>1400 bytes)'),
    'rst_ratio':           ('Reset Ratio',         '{:.1%}',            'Percentage of TCP reset/rejected packets'),
    'unique_protocols':    ('Protocol Count',      '{:.0f}',            'Number of different protocols in use'),
    'encrypted_ratio':     ('Encrypted Traffic',   '{:.1%}',            'Proportion of encrypted (HTTPS/TLS) traffic'),
}


class NetSentinelApp:
    """Main application class that orchestrates all components."""

    def __init__(self, review_dir=None):
        from src.config import Config
        self.config = Config().load()

        from src.resources import ResourceMonitor, set_low_priority
        self.resources = ResourceMonitor()
        if self.config.get('performance', 'low_priority', default=False):
            set_low_priority()

        # Detect network environment (gateway, DNS, local IPs, etc.)
        from src.net_detect import NetworkEnvironment
        self.net_env = NetworkEnvironment().detect()

        # Load known devices from config into network environment
        known_devices = self.config.get('known_devices', 'devices', default=[])
        self.net_env.load_known_devices(known_devices)

        # Initialize components
        from src.alerts import AlertManager
        self.alert_manager = AlertManager(self.config)

        # Threat Intelligence Engine (downloads and caches threat feeds)
        from src.threat_intel import ThreatIntelEngine
        self.threat_intel = ThreatIntelEngine(self.config)

        # Process Verifier: deep process investigation
        from src.process_verify import ProcessVerifier
        self.process_verifier = ProcessVerifier(self.config)

        # ─── Unified Alert Verifier ──────────────────────────────
        # This is the SINGLE GATEWAY for all alerts. Every alert from
        # every detection engine passes through here before reaching
        # the user. It verifies, scores, and may adjust severity.
        from src.alert_verify import AlertVerifier
        self.alert_verifier = AlertVerifier(
            self.config,
            net_env=self.net_env,
            threat_intel=self.threat_intel,
            process_verifier=self.process_verifier,
        )

        # The single gateway every alert passes through; see _verified_alert_gateway.
        self._alert_gateway = self._verified_alert_gateway
        self.suppressed_alerts = 0

        # Bounded so a burst cannot grow without limit; dropping deep verification is
        # survivable because the alert itself has already been delivered.
        import queue
        self._verify_queue = queue.Queue(maxsize=500)
        self._verify_thread = None

        # IDS Engine — uses the verified gateway
        from src.ids_engine import IDSEngine
        self.ids_engine = IDSEngine(
            self.config,
            alert_callback=self._alert_gateway,
            threat_intel=self.threat_intel,
            net_env=self.net_env,
        )

        # Feature history store (persistent feature vectors for ML training)
        from src.feature_store import FeatureStore
        self.feature_store = FeatureStore(self.config)

        from src.ml_engine import AnomalyDetector
        self.ml_engine = AnomalyDetector(self.config, feature_store=self.feature_store)

        from src.capture import CaptureEngine
        self.capture_engine = CaptureEngine(
            self.config,
            packet_callback=self._on_packet,
            raw_packet_callback=self._on_raw_packet,
        )

        # IOC Scanner — also uses the verified gateway
        from src.ioc_scanner import IOCScanner
        self.ioc_scanner = IOCScanner(
            self.config,
            threat_intel=self.threat_intel,
            alert_callback=self._alert_gateway,
        )

        # Forensics database: encrypted credential storage
        from src.forensics_db import ForensicsDB
        self.forensics_db = ForensicsDB(self.config)

        # Live forensics engine: credential scanning, insecure protocol detection
        from src.forensics import NetworkForensics
        self.forensics = NetworkForensics(forensics_db=self.forensics_db)

        # PCAP File Analyzer
        from src.pcap_analyzer import PcapAnalyzer
        self.pcap_analyzer = PcapAnalyzer(
            self.config,
            ids_engine=self.ids_engine,
            threat_intel=self.threat_intel,
            ioc_scanner=self.ioc_scanner,
            alert_verifier=self.alert_verifier,
            net_env=self.net_env,
            forensics_db=self.forensics_db,
        )

        # ─── New learning & correlation systems ──────────────────

        # Passive device learner: discovers and profiles devices from traffic
        from src.device_learner import DeviceLearner
        self.device_learner = DeviceLearner(self.config, net_env=self.net_env)

        # Baseline whitelist: learns normal domains/IPs/ports automatically
        from src.baseline_whitelist import BaselineWhitelist
        self.baseline_whitelist = BaselineWhitelist(self.config)

        # Alert correlator: groups related alerts into incidents
        from src.alert_correlator import AlertCorrelator
        self.alert_correlator = AlertCorrelator(self.config)

        # PCAP writer: ring buffer + on-demand export + continuous recording
        from src.pcap_writer import PcapWriter
        self.pcap_writer = PcapWriter(self.config)

        # Pass baseline whitelist to IDS engine for learned-domain suppression
        self.ids_engine.baseline_whitelist = self.baseline_whitelist
        # Pass baseline whitelist to ML engine for learned-beacon suppression
        self.ml_engine.baseline_whitelist = self.baseline_whitelist

        # Review mode: --review DIR for this run, or the Settings toggle.
        self.review = None
        if not review_dir and self.config.get('review', 'enabled', default=False):
            review_dir = self.config.get('review', 'directory', default='') or True
        if review_dir:
            self.enable_review(None if review_dir is True else review_dir)

        self.forensics_enabled = self.config.get('forensics', 'enabled', default=True)

        # Track which insecure services we've already alerted on (avoid spam)
        self._forensics_alerted_services = set()
        self._forensics_alerted_sensitive = set()

        # High-water marks into the forensics result lists. _check_forensics_alerts runs
        # once per packet; rescanning every finding each time was O(findings) per packet
        # and grew for the whole session.
        self._forensics_cred_cursor = 0
        self._forensics_sensitive_cursor = 0

        # PCAP-on-alert: automatically save the traffic behind serious alerts
        self._pcap_on_alert = self.config.get('capture', 'pcap_on_alert', default=True)
        self._pcap_on_alert_severity = self.config.get(
            'capture', 'pcap_on_alert_severity', default='CRITICAL')
        self._pcap_on_alert_seconds = self.config.get(
            'capture', 'pcap_on_alert_seconds', default=60)
        self._pcap_alert_cooldown = 60
        self._pcap_alert_cooldowns = {}
        # In review mode, alerts inside the cooldown share the capture that was saved.
        self._pcap_alert_last = {}

        # Alerts raised outside the IDS engine (IOC, ML) skip its cooldown, so a rule
        # that matches every packet of a connection alerted on every packet.
        self._alert_cooldown = self.config.get('alerts', 'cooldown_sec', default=30)
        self._alert_cooldowns = {}

        # Packet window for ML analysis
        self._packet_window = deque(maxlen=5000)
        self._analysis_interval = self.config.get('analysis', 'stats_interval_sec', default=5)
        self._running = False
        # The desktop window and the browser dashboard can both start and stop
        # monitoring, from different threads; one change at a time.
        self._lifecycle_lock = threading.Lock()
        # Each run's threads wait on their own event. A shared flag let a quick
        # stop-then-start leave the last run's loops going beside the new ones.
        self._stop_event = threading.Event()
        self._stop_event.set()
        self.last_start_error = ''

        # ML analysis results
        self.last_ml_result = {}

        logger.info("NetSentinel App initialized.")

    def _capture_alert_evidence(self, alert):
        """
        Save the traffic around a serious alert so it can be examined later.

        The ring buffer already holds recent packets, so the evidence is usually
        still in memory when the alert fires — this writes it out before it ages
        away. Without it, a CRITICAL alert names an IP and a rule and leaves the
        user with nothing to actually look at.
        """
        review = self.review
        if review is None:
            if not self._pcap_on_alert:
                return
            if not Severity.gte(alert.severity, self._pcap_on_alert_severity):
                return
        # In review mode, every alert, whatever its severity: the ones verification
        # lowered to LOW are the ones a reviewer most needs to see.

        now = time.time()
        # One capture per rule+source per cooldown, so an alert storm cannot fill
        # the disk with near-identical files.
        key = f"{alert.rule_id}:{alert.src_ip}"
        if now - self._pcap_alert_cooldowns.get(key, 0) < self._pcap_alert_cooldown:
            shared = self._pcap_alert_last.get(key) if review is not None else None
            if shared:
                alert.evidence['packet_capture'] = shared
            return
        self._pcap_alert_cooldowns[key] = now
        if len(self._pcap_alert_cooldowns) > 500:
            cutoff = now - self._pcap_alert_cooldown
            self._pcap_alert_cooldowns = {
                k: t for k, t in self._pcap_alert_cooldowns.items() if t >= cutoff}
            self._pcap_alert_last = {
                k: p for k, p in self._pcap_alert_last.items() if k in self._pcap_alert_cooldowns}

        try:
            if review is not None:
                path = review.snippet(alert, referenced=self._referenced_captures)
                if path:
                    self._pcap_alert_last[key] = path
            else:
                path = self.pcap_writer.export_for_alert(
                    alert, seconds=self._pcap_on_alert_seconds)
            if path:
                alert.evidence['packet_capture'] = path
                alert.evidence['packet_capture_note'] = (
                    'Traffic around this alert was saved. Open it in Wireshark to '
                    'see exactly what triggered the detection.')
        except Exception as e:
            logger.debug("Alert capture error: %s", e)

    def _verified_alert_gateway(self, alert):
        """Universal alert gateway — enriches and verifies ALL alerts before emitting."""
        # Someone already judged this rule for this host or domain a false positive.
        whitelist = getattr(self, 'baseline_whitelist', None)
        if whitelist is not None and whitelist.suppresses(alert):
            self.suppressed_alerts += 1
            return

        # Enrich with domain resolution from IDS engine's DNS tracker
        try:
            if self.ids_engine and alert.dst_ip:
                domains = self.ids_engine._get_domains_for_ip(alert.dst_ip)
                if domains and 'destination_domains' not in alert.evidence:
                    alert.evidence['destination_domains'] = list(domains)[:5]
            if self.ids_engine and alert.src_ip:
                domains = self.ids_engine._get_domains_for_ip(alert.src_ip)
                if domains and 'source_domains' not in alert.evidence:
                    alert.evidence['source_domains'] = list(domains)[:5]
        except Exception:
            pass

        # Enrich with forensics domain map
        try:
            forensics = getattr(self, 'forensics', None)
            if forensics and alert.dst_ip:
                f_domains = forensics._ip_to_domains.get(alert.dst_ip, set())
                if f_domains:
                    existing = set(alert.evidence.get('destination_domains', []))
                    alert.evidence['destination_domains'] = list(existing | f_domains)[:5]
        except Exception:
            pass

        if alert.rule_id in _SLOW_VERIFY_RULES:
            # Publish now, deepen later: the user sees the alert immediately and the
            # verification verdict is merged into its evidence when it completes.
            alert.evidence.setdefault('alert_verification', {
                'verdict': 'PENDING',
                'confidence': '—',
                'reasoning': ['Deep process verification queued'],
            })
            self._emit_alert(alert)
            try:
                self._verify_queue.put_nowait(alert)
            except Exception:
                logger.debug("Verification queue full; skipping deep verify for %s",
                             alert.rule_id)
            return

        before = alert.severity
        try:
            self.alert_verifier.verify_alert(alert, ids_engine=self.ids_engine)
        except Exception as e:
            logger.debug("Alert verification error: %s", e)
        _note_severity_change(alert, before)
        self._emit_alert(alert)

    def _cooldown_ok(self, alert):
        """
        The IDS engine's cooldown, for alerts that are raised outside it.

        Keyed the same way (rule, source, destination), so one connection that keeps
        matching alerts once per cooldown rather than once per packet.
        """
        now = time.time()
        key = f"{alert.rule_id}:{alert.src_ip}:{alert.dst_ip}"
        if now - self._alert_cooldowns.get(key, 0) < self._alert_cooldown:
            return False
        self._alert_cooldowns[key] = now
        if len(self._alert_cooldowns) > 2000:
            cutoff = now - self._alert_cooldown
            self._alert_cooldowns = {
                k: t for k, t in self._alert_cooldowns.items() if t >= cutoff}
        return True

    def _referenced_captures(self):
        return {a.evidence.get('packet_capture')
                for a in self.alert_manager.get_alerts(limit=self.alert_manager.max_stored)}

    def _emit_alert(self, alert):
        """Deliver a finished alert to storage, the GUI and the correlator."""
        self._capture_alert_evidence(alert)
        alert.stored = self.alert_manager.add_alert(alert)
        review = self.review
        verdict = alert.evidence.get('alert_verification', {}).get('verdict')
        if review is not None and alert.stored and verdict != 'PENDING':
            review.record(alert)       # deferred ones are recorded once verified
        try:
            self.alert_correlator.process_alert(alert)
        except Exception as e:
            logger.debug("Alert correlation error: %s", e)

    # ─── Review mode ─────────────────────────────────────────────────────

    def enable_review(self, directory=None):
        """Turn review mode on, recording to directory (default ~/.netsentinel/review)."""
        from src.review import ReviewRecorder
        if self.review is None:
            self.review = ReviewRecorder(directory, self.pcap_writer, config=self.config)
            logger.info("Review mode on, recording to %s", self.review.directory)
            if self._running:
                self.review.start()
        return self.review

    def build_review_bundle(self, **options):
        """Build a bundle from this run's review folder. See src.review.build_bundle."""
        from src import __version__
        from src.review import build_bundle, default_directory
        options.setdefault('pseudonymise',
                           self.config.get('review', 'pseudonymise_lan', default=False))
        directory = self.review.directory if self.review is not None else default_directory()
        return build_bundle(directory, version=__version__, **options)

    def record_verdict(self, alert_id, verdict, note=''):
        """
        A person's verdict on a stored alert. A false positive stops that rule for
        that alert's host or domain. Returns the confirmed entry (None for 'real').
        Raises KeyError for an unknown alert, ValueError for a verdict that is not
        one, and LookupError for a false positive with nothing to tie it to.
        """
        from src.review import normalise_verdict, record_verdict, review_id
        alert = self.alert_manager.get_alert(alert_id)
        if alert is None:
            raise KeyError(alert_id)
        normalised = normalise_verdict(verdict)
        if normalised is None:
            raise ValueError(verdict)
        record = alert.to_dict()
        record['review_id'] = review_id(alert)
        directory = self.review.directory if self.review is not None else None
        entry = record_verdict(directory, record, normalised,
                               self.baseline_whitelist.confirmed, note=note)
        if normalised == 'false_positive' and entry is None:
            raise LookupError('This alert names no host or domain to tie a verdict to.')
        alert.evidence['your_verdict'] = normalised
        return entry

    def _verification_loop(self, stop):
        """Run slow verification off the packet path and update alerts in place."""
        import queue
        while not stop.is_set():
            try:
                alert = self._verify_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            before = alert.severity
            try:
                self.alert_verifier.verify_alert(alert, ids_engine=self.ids_engine)
            except Exception as e:
                logger.debug("Deferred verification error: %s", e)
                alert.evidence['alert_verification'] = {
                    'verdict': 'INCONCLUSIVE',
                    'confidence': '0%',
                    'reasoning': [f'Verification error: {e}'],
                }
            _note_severity_change(alert, before)
            review = self.review
            if review is not None and getattr(alert, 'stored', True):
                review.record(alert)

    def _on_raw_packet(self, raw_bytes):
        """Called for each raw packet (from capture thread). Feeds PCAP writer."""
        try:
            if hasattr(self, 'pcap_writer'):
                self.pcap_writer.buffer_packet(raw_bytes)
        except Exception:
            pass

    def _on_packet(self, pkt_info):
        """Called for each captured packet (from worker thread)."""
        try:
            # Feed to IDS (alerts go through _alert_gateway automatically)
            self.ids_engine.inspect_packet(pkt_info)
        except Exception as e:
            logger.debug("IDS inspection error: %s", e)

        # IOC checks (absolute rules, baseline-independent)
        try:
            ioc_findings = self.ioc_scanner.check_packet_ioc(pkt_info)
            if ioc_findings:
                from src.ids_engine import Alert
                for f in ioc_findings:
                    alert = Alert(
                        rule_id=f['rule_id'],
                        severity=f['severity'],
                        title=f['title'],
                        description=f['description'],
                        src_ip=pkt_info.src_ip,
                        dst_ip=pkt_info.dst_ip,
                        src_port=pkt_info.src_port,
                        dst_port=pkt_info.dst_port,
                        protocol=pkt_info.protocol,
                        evidence=f.get('evidence', {}),
                        category="IOC",
                    )
                    if self._cooldown_ok(alert):
                        self._alert_gateway(alert)
        except Exception as e:
            logger.debug("IOC check error: %s", e)

        # Live forensics: credential and insecure protocol scanning
        if self.forensics_enabled:
            try:
                raw_payload = pkt_info._raw_payload
                if raw_payload:
                    self.forensics.analyze_packet_with_payload(pkt_info, raw_payload)
                else:
                    self.forensics.analyze_packet(pkt_info)

                # Generate alerts for new credential findings
                self._check_forensics_alerts()
            except Exception as e:
                logger.debug("Forensics error: %s", e)

        # ─── Learning systems (lightweight, always run) ────────────
        # Device learner: profile all devices from traffic patterns
        try:
            self.device_learner.observe_packet(pkt_info)
        except Exception as e:
            logger.debug("Device learner error: %s", e)

        # Baseline whitelist: learn normal domains/IPs during the baseline period ONLY.
        # Without this gate the whitelist keeps learning forever, so any domain or IP an
        # attacker touches three times marks itself "normal" and permanently suppresses
        # DNS-TUNNEL, DNS-BAD-TLD, beaconing and full-severity DATA-EXFIL for it.
        try:
            if self.baseline_whitelist.is_learning:
                # pkt_info.domain is the SNI when there is one, else the DNS query,
                # so encrypted destinations are learned as normal too.
                if pkt_info.domain:
                    self.baseline_whitelist.observe_dns(pkt_info.src_ip, pkt_info.domain)
                if pkt_info.dst_ip and pkt_info.dst_port:
                    self.baseline_whitelist.observe_connection(
                        pkt_info.src_ip, pkt_info.dst_ip, pkt_info.dst_port)
                self.baseline_whitelist.check_learning_complete()
        except Exception as e:
            logger.debug("Baseline whitelist error: %s", e)

        # Buffer for ML (always, even if IDS errored)
        self._packet_window.append(pkt_info)

    def _check_forensics_alerts(self):
        """Generate alerts for new forensics findings (credentials, insecure services)."""
        from src.ids_engine import Alert

        # Check for new credentials — only entries appended since the last call.
        creds = self.forensics.credentials_found
        if self._forensics_cred_cursor < len(creds):
            new_creds = creds[self._forensics_cred_cursor:]
            self._forensics_cred_cursor = len(creds)
        else:
            new_creds = ()
        for cred in new_creds:
            # Use risk from the finding (LOW for known update services, CRITICAL otherwise)
            severity = cred.get('risk', 'CRITICAL')
            is_digest = 'digest' in cred.get('credential_type', '').lower()
            title_prefix = "Hashed Credential" if is_digest else "Plaintext Credential"
            desc_suffix = (" (hashed response, not plaintext password)" if is_digest
                           else ". Anyone on the same network can capture this credential.")
            alert = Alert(
                rule_id='FORENSICS-CREDENTIAL',
                severity=severity,
                title=f"{title_prefix} ({cred['protocol']})",
                description=(f"{cred['protocol']} {cred['credential_type']} "
                             f"transmitted over unencrypted HTTP{desc_suffix}"),
                src_ip=cred.get('source_ip', ''),
                dst_ip=cred.get('destination_ip', ''),
                dst_port=cred.get('port', 0),
                category="Credential Exposure",
                evidence={
                    'protocol': cred['protocol'],
                    'credential_type': cred['credential_type'],
                    'value': cred['value'],
                    'connection': f"{cred['source_ip']} → "
                                  f"{cred['destination_ip']}:{cred['port']}",
                    'extra': cred.get('extra', {}),
                    'description': (
                        f"A {cred['credential_type']} for {cred['protocol']} "
                        f"was found in network traffic{desc_suffix}"
                    ),
                    'recommendation': (
                        'Switch to the encrypted version of this protocol.'
                        if is_digest else
                        'Change this password immediately. Switch to the '
                        'encrypted version of this protocol.'
                    ),
                },
            )
            self._alert_gateway(alert)

        # Check for new insecure services. Small and bounded by (ip, port) pairs on
        # the LAN, so a full pass is fine — but skip it entirely when nothing is new.
        pending_services = [
            (k, v) for k, v in self.forensics.insecure_services.items()
            if k not in self._forensics_alerted_services
        ]
        for key, svc in pending_services:
            # Only alert after seeing some traffic (not a single SYN)
            if svc['packet_count'] >= 5:
                self._forensics_alerted_services.add(key)
                from src.forensics import SECURE_EQUIVALENTS, PROTOCOL_EXPLOITATION, DEFAULT_EXPLOITATION
                exploit_info = PROTOCOL_EXPLOITATION.get(svc['port'], DEFAULT_EXPLOITATION)
                alert = Alert(
                    rule_id='FORENSICS-INSECURE-SVC',
                    severity=svc['risk'],
                    title=f"Unencrypted {svc['service']} Service",
                    description=svc['description'],
                    dst_ip=svc['ip'],
                    dst_port=svc['port'],
                    category="Insecure Service",
                    evidence={
                        'service': svc['service'],
                        'server': f"{svc['ip']}:{svc['port']}",
                        'port': svc['port'],
                        'packets_observed': svc['packet_count'],
                        'bytes_transferred': svc['bytes'],
                        'clients': list(svc['src_ips'])[:10],
                        'description': svc['description'],
                        'has_https': svc.get('has_https', False),
                        'how_this_is_exploited': exploit_info['how_exploited'],
                        'how_to_fix': exploit_info['how_to_fix'],
                        'is_this_malicious': exploit_info['currently_malicious'],
                        'recommendation': (
                            f"Replace {svc['service']} with "
                            f"{SECURE_EQUIVALENTS.get(svc['port'], 'encrypted alternative')}. "
                            f"All data on this service is visible to anyone on the network."
                        ),
                    },
                )
                self._alert_gateway(alert)

        # Check for new sensitive data — likewise cursor-based.
        sens = self.forensics.sensitive_data
        if self._forensics_sensitive_cursor < len(sens):
            new_sensitive = sens[self._forensics_sensitive_cursor:]
            self._forensics_sensitive_cursor = len(sens)
        else:
            new_sensitive = ()
        for item in new_sensitive:
            item_key = (item['data_type'], item.get('source_ip', ''),
                       item.get('destination_ip', ''), item.get('port', 0))
            if item_key not in self._forensics_alerted_sensitive:
                self._forensics_alerted_sensitive.add(item_key)
                alert = Alert(
                    rule_id='FORENSICS-SENSITIVE-DATA',
                    severity=item.get('risk', 'HIGH'),
                    title=f"Sensitive Data in Transit ({item['data_type']})",
                    description=f"{item['data_type']} found in unencrypted traffic",
                    src_ip=item.get('source_ip', ''),
                    dst_ip=item.get('destination_ip', ''),
                    dst_port=item.get('port', 0),
                    category="Data Exposure",
                    evidence={
                        'data_type': item['data_type'],
                        'connection': f"{item.get('source_ip', '')} → "
                                      f"{item.get('destination_ip', '')}:{item.get('port', '')}",
                        'recommendation': 'Ensure all sensitive data is transmitted over encrypted connections.',
                    },
                )
                self._alert_gateway(alert)

    def _analysis_loop(self, stop):
        """Periodic ML analysis of traffic windows."""
        while not stop.wait(self._analysis_interval):
            # Alerts reached disk only when monitoring stopped cleanly, so a crash
            # or a killed process lost the whole session. At most once a minute.
            self.alert_manager.maybe_autosave()
            try:
                # Only packets from the interval just elapsed. _packet_window is a
                # rolling buffer that is never cleared, so passing all of it while
                # claiming a 5-second window pinned packets_per_sec at maxlen/5.
                cutoff = time.time() - self._analysis_interval
                packets = [p for p in list(self._packet_window) if p.timestamp >= cutoff]
                flows = self.capture_engine.get_flows_snapshot()
                if packets:
                    result = self.ml_engine.analyze_window(
                        flows, packets, self._analysis_interval,
                        local_ips=getattr(self.net_env, 'local_ips', None),
                    )
                    self.last_ml_result = result

                    if result.get('is_anomalous') and result.get('reasons'):
                        # Don't alert if the ML model hasn't trained yet —
                        # without the Isolation Forest, we only have statistical
                        # baseline and DNS heuristics, which are too noisy alone
                        if not self.ml_engine.is_trained:
                            continue

                        # Require at least 2 independent reasons to alert
                        # (prevents single-factor false positives like "just DNS")
                        reasons = result.get('reasons', [])
                        if len(reasons) < 2:
                            continue

                        from src.ids_engine import Alert, Severity
                        severity = Severity.MEDIUM
                        score = result.get('anomaly_score', 0)
                        if score > 0.5:
                            severity = Severity.HIGH
                        if score > 0.8:
                            severity = Severity.CRITICAL

                        # Build human-readable evidence
                        features = result.get('features', {})
                        evidence = self._build_ml_evidence(result, features)

                        alert = Alert(
                            rule_id="ML-ANOMALY",
                            severity=severity,
                            title="ML Anomaly Detected",
                            description="; ".join(result['reasons']),
                            category="ML Anomaly",
                            evidence=evidence,
                        )
                        if self._cooldown_ok(alert):
                            self._alert_gateway(alert)
            except Exception as e:
                logger.debug("Analysis error: %s", e)

    def _build_ml_evidence(self, result, features):
        """
        Build human-readable evidence for ML anomaly alerts.
        Compares current features against baseline and explains what's unusual.
        """

        evidence = {}

        # Overall scores
        evidence['anomaly_score'] = f"{result.get('anomaly_score', 0):.4f} (threshold: {self.ml_engine.threshold})"
        evidence['baseline_deviation'] = f"{result.get('baseline_deviation', 0):.4f}"
        evidence['isolation_forest_score'] = f"{result.get('isolation_score', 0):.4f}"

        # Compare to baseline and find what's unusual
        baseline = self.ml_engine.baseline
        deviations = []

        if baseline.global_mean is not None and features:
            from datetime import datetime
            hour = datetime.now().hour

            # Pick the right baseline (hourly if available)
            if hour in baseline.hourly_means:
                mean = baseline.hourly_means[hour]
                std = baseline.hourly_stds[hour]
                baseline_type = f"hourly baseline (hour {hour}:00)"
            else:
                mean = baseline.global_mean
                std = baseline.global_std
                baseline_type = "global baseline"

            evidence['compared_against'] = f"{baseline_type} built from {baseline.samples_count} samples"

            feature_names = list(features.keys())
            for i, fname in enumerate(feature_names):
                if i >= len(mean):
                    break
                current_val = features[fname]
                baseline_val = mean[i]
                std_val = std[i] if i < len(std) else 1

                if std_val > 0:
                    z_score = abs(current_val - baseline_val) / std_val
                else:
                    z_score = 0

                if z_score > 2.0:  # More than 2 standard deviations = notable
                    info = _FEATURE_INFO.get(fname, (fname, '{:.4f}', ''))
                    readable_name, fmt, explanation = info
                    direction = "above" if current_val > baseline_val else "below"

                    deviations.append({
                        'feature': readable_name,
                        'z_score': z_score,
                        'current': fmt.format(current_val),
                        'baseline': fmt.format(baseline_val),
                        'direction': direction,
                        'explanation': explanation,
                    })

            # Sort by most deviant first
            deviations.sort(key=lambda d: d['z_score'], reverse=True)

        # Format the deviations as the key evidence
        if deviations:
            unusual_features = []
            for d in deviations[:8]:  # Top 8 most unusual
                unusual_features.append(
                    f"{d['feature']}: {d['current']} ({d['direction']} normal baseline of {d['baseline']}, "
                    f"z-score: {d['z_score']:.1f}σ) — {d['explanation']}"
                )
            evidence['what_is_unusual'] = unusual_features
        else:
            evidence['what_is_unusual'] = ["Could not determine specific deviations (baseline still learning)"]

        # Format current traffic snapshot readably
        if features:
            snapshot = []
            for fname, val in features.items():
                info = _FEATURE_INFO.get(fname, (fname, '{:.4f}', ''))
                readable_name, fmt, _ = info
                try:
                    snapshot.append(f"{readable_name}: {fmt.format(val)}")
                except (ValueError, TypeError):
                    snapshot.append(f"{readable_name}: {val}")
            evidence['current_traffic_snapshot'] = snapshot

        # Reasons from ML engine
        reasons = result.get('reasons', [])
        if reasons:
            evidence['detection_reasons'] = reasons

        evidence['description'] = (
            "The ML engine detected that your current network traffic pattern differs "
            "significantly from what it has learned as your normal baseline. The baseline "
            "is built from your historical traffic patterns, broken down by time of day. "
            "The 'what is unusual' section above shows exactly which metrics deviated "
            "and by how much."
        )

        evidence['recommendation'] = (
            "Check the unusual features listed above. High port diversity or SYN ratios "
            "may indicate scanning. Sudden bandwidth spikes could mean large transfers "
            "or streaming. If the deviations match your current activity (e.g., you just "
            "started a download), this is likely a false positive. If you don't recognize "
            "the activity, investigate which process is generating the traffic."
        )

        return evidence

    @property
    def is_monitoring(self):
        return self._running and self.capture_engine.is_running

    def start_monitoring(self):
        """
        Start all monitoring components. Calling it while running does nothing.

        Returns whether monitoring is running afterwards; when it is not,
        last_start_error says why, in words fit for the user.
        """
        with self._lifecycle_lock:
            if self._running:
                return self.capture_engine.is_running

            # Scapy checks its stop condition only when a packet arrives, so on a
            # quiet interface the last run's capture thread can still be waiting,
            # and its watchdog sleeps for 5 seconds. Starting beside them would put
            # two captures on the interface.
            for name in ('_thread', '_watchdog_thread'):
                previous = getattr(self.capture_engine, name, None)
                if previous is not None and previous.is_alive():
                    previous.join(timeout=CAPTURE_EXIT_WAIT)
                    if previous.is_alive():
                        self.last_start_error = (
                            'The previous capture is still shutting down. '
                            'Try again in a few seconds.')
                        logger.warning(self.last_start_error)
                        return False

            # Prune stale learned data on startup
            try:
                self.device_learner.prune_stale(max_age_days=30)
                self.baseline_whitelist.prune_stale(max_age_days=30)
            except Exception as e:
                logger.debug("Stale data pruning error: %s", e)

            # Run IOC scan BEFORE starting capture and ML baseline training
            # This catches pre-existing compromise indicators
            logger.info("Running pre-monitoring IOC scan...")
            try:
                findings = self.ioc_scanner.run_startup_scan()
                if findings:
                    logger.warning(
                        "IOC scan found %d indicators BEFORE monitoring started. "
                        "ML baseline may be compromised — review alerts.",
                        len(findings)
                    )
            except Exception as e:
                logger.error("IOC startup scan failed: %s", e)

            if not self.capture_engine.start():
                self.last_start_error = (
                    'Packet capture failed to start. Check that Npcap is installed '
                    'and that NetSentinel has permission to capture.')
                logger.warning("Capture engine failed to start.")
                return False

            self.last_start_error = ''
            self._running = True
            stop = self._stop_event = threading.Event()
            self.feature_store.start()
            if self.review is not None:
                self.review.start()
            self._analysis_thread = threading.Thread(
                target=self._analysis_loop, args=(stop,), daemon=True,
                name="AnalysisThread")
            self._analysis_thread.start()
            self._verify_thread = threading.Thread(
                target=self._verification_loop, args=(stop,), daemon=True,
                name="VerifyThread")
            self._verify_thread.start()
            logger.info("Monitoring started.")
            return True

    def stop_monitoring(self):
        """Stop all monitoring and save what was learned. Safe to call twice."""
        with self._lifecycle_lock:
            self._stop_monitoring()

    def _stop_monitoring(self):
        self._running = False
        self._stop_event.set()
        self.capture_engine.stop()
        if self.review is not None:
            self.review.stop()
        self.alert_manager.save_alerts()
        self.ml_engine.baseline.save()
        self.feature_store.shutdown()
        # Save learned data from new modules
        try:
            self.device_learner.save()
        except Exception as e:
            logger.debug("Device learner save error: %s", e)
        try:
            self.baseline_whitelist.save()
        except Exception as e:
            logger.debug("Baseline whitelist save error: %s", e)
        try:
            self.alert_correlator.save()
        except Exception as e:
            logger.debug("Alert correlator save error: %s", e)
        try:
            self.pcap_writer.cleanup()
        except Exception as e:
            logger.debug("PCAP writer cleanup error: %s", e)
        try:
            self.forensics_db.flush()
        except Exception as e:
            logger.debug("Forensics DB flush error: %s", e)
        logger.info("Monitoring stopped. Data saved.")

    def get_dashboard_data(self):
        """Aggregate data for the GUI dashboard."""
        cap_stats = self.capture_engine.get_stats()
        ids_stats = self.ids_engine.get_stats()
        ml_status = self.ml_engine.get_status()
        alert_stats = self.alert_manager.get_stats()

        return {
            'capture': cap_stats,
            'ids': ids_stats,
            'ml': ml_status,
            'alerts': alert_stats,
            'ml_result': self.last_ml_result,
            'is_monitoring': self.capture_engine.is_running,
            'feature_store': self.feature_store.get_storage_stats(),
            'score_history': self.feature_store.get_recent_scores(minutes=90),
            'network_env': self.net_env.get_summary(),
            'device_learner': self.device_learner.get_summary(),
            'baseline_whitelist': self.baseline_whitelist.get_stats(),
            'correlator': self.alert_correlator.get_stats(),
            'pcap_writer': self.pcap_writer.get_buffer_stats(),
            'resources': self.resources.snapshot(),
            'review': ({'enabled': True, 'directory': self.review.directory}
                       if self.review is not None else {'enabled': False}),
            'suppressed_alerts': self.suppressed_alerts,
        }

    def run(self, tk_root=None):
        """Launch the GUI."""
        from src.gui import NetSentinelGUI
        gui = NetSentinelGUI(self, tk_root=tk_root)
        gui.run()
