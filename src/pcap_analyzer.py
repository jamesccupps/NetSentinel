"""
PCAP Capture File Analyzer
===========================
Loads PCAP/PCAPNG files and runs every packet through the full
NetSentinel detection pipeline: IDS rules, threat intel, IOC scanner,
and ML anomaly detection.

Supports:
- .pcap files (standard tcpdump/Wireshark format)
- .pcapng files (next-gen Wireshark format)
- .cap files (various capture tools)

Packets are read with Scapy, one at a time, through the same parser live
capture uses (CaptureEngine._extract_packet_info in offline mode), so a file
gets TLS SNI and fingerprints, the full DNS answer section and IPv6 ports just
as live traffic does. It used to run an older parser of its own — no SNI, no
DNS answers, IPv6 with no ports — and to prefer tshark for big files, whose
field output had even less. tshark is now only the fallback without Scapy.
"""

import os
import time
import json
import csv
import logging
import threading
from collections import Counter
from datetime import datetime

logger = logging.getLogger("NetSentinel.PCAP")

try:
    from scapy.all import PcapReader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import subprocess

# Forensics security-finding types -> (rule id, alert category).
_FINDING_RULES = {
    'insecure_protocol': ('FORENSICS-INSECURE-SVC', 'Insecure Service'),
    'malicious_user_agent': ('FORENSICS-USER-AGENT', 'Suspicious HTTP'),
    'http_attack': ('FORENSICS-HTTP-ATTACK', 'Web Attack'),
    'http_info_leak': ('FORENSICS-SERVER-INFO', 'Information Disclosure'),
}


def find_tshark():
    """Locate tshark (Wireshark CLI) on the system."""
    common_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
    ]
    for path in common_paths:
        if os.path.exists(path):
            return path
    # Try PATH
    try:
        result = subprocess.run(
            ['tshark', '--version'],
            capture_output=True, text=True, timeout=5,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        if result.returncode == 0:
            return 'tshark'
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


class PcapAnalyzer:
    """
    Analyzes PCAP files through the full detection pipeline.
    """

    def __init__(self, config, ids_engine=None, threat_intel=None,
                 ioc_scanner=None, alert_verifier=None, net_env=None,
                 forensics_db=None):
        self.config = config
        self.ids_engine = ids_engine
        self.threat_intel = threat_intel
        self.ioc_scanner = ioc_scanner
        self.alert_verifier = alert_verifier
        self.net_env = net_env
        self.forensics_db = forensics_db

        self.tshark_path = find_tshark()

        # Analysis state
        self.is_analyzing = False
        self.progress = 0          # 0-100
        self.progress_text = ""
        self.total_packets = 0
        self.packets_processed = 0
        self.alerts = []
        self.stats = {}
        self._cancel = False

        logger.info("PCAP Analyzer initialized. tshark: %s, scapy: %s",
                     self.tshark_path or "not found", SCAPY_AVAILABLE)

    def analyze_file(self, filepath, callback=None):
        """
        Analyze a PCAP file. Runs in calling thread.
        Use analyze_file_async for background processing.

        Args:
            filepath: Path to .pcap/.pcapng/.cap file
            callback: Optional function called with each alert

        Returns:
            dict with analysis results
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")

        file_size = os.path.getsize(filepath)
        file_ext = os.path.splitext(filepath)[1].lower()

        if file_ext not in ('.pcap', '.pcapng', '.cap', '.dmp'):
            raise ValueError(f"Unsupported file type: {file_ext}. "
                           f"Supported: .pcap, .pcapng, .cap")

        self.is_analyzing = True
        self.progress = 0
        self.progress_text = "Loading capture file..."
        self.alerts = []
        self._cancel = False
        start_time = time.time()

        # Stats tracking
        stats = {
            'file': os.path.basename(filepath),
            'file_size_mb': round(file_size / (1024*1024), 2),
            'total_packets': 0,
            'packets_analyzed': 0,
            'duration_sec': 0,
            'capture_start': None,
            'capture_end': None,
            'capture_duration': None,
            'protocols': Counter(),
            'unique_src_ips': set(),
            'unique_dst_ips': set(),
            'unique_src_ports': set(),
            'unique_dst_ports': set(),
            'dns_queries': [],
            'total_bytes': 0,
            'alerts_generated': 0,
            'alerts_by_severity': Counter(),
            'alerts_by_category': Counter(),
            'alerts_by_verdict': Counter(),
            'top_talkers': Counter(),
            'top_destinations': Counter(),
        }

        alert_list = []

        def on_alert(alert):
            """Called for each alert generated during analysis."""
            # Run through verifier if available
            if self.alert_verifier:
                try:
                    self.alert_verifier.verify_alert(alert, ids_engine=self.ids_engine)
                except Exception:
                    pass

            alert_list.append(alert)
            stats['alerts_generated'] += 1
            stats['alerts_by_severity'][alert.severity] += 1
            stats['alerts_by_category'][alert.category] += 1

            # Track verification verdict
            av = alert.evidence.get('alert_verification', {})
            if av:
                stats['alerts_by_verdict'][av.get('verdict', 'UNVERIFIED')] += 1

            if callback:
                callback(alert)

        # Create a temporary IDS engine for this analysis
        # (so we don't pollute the live engine's state). Offline: windows and
        # alert times run on packet time, and nothing about this network's own
        # history (pinned gateway MAC, known devices) is read or written.
        from src.ids_engine import IDSEngine
        analysis_ids = IDSEngine(
            self.config,
            alert_callback=on_alert,
            threat_intel=self.threat_intel,
            net_env=self.net_env,
            offline=True,
        )

        # Forensics engine for credential/security scanning
        from src.forensics import NetworkForensics
        forensics = NetworkForensics(forensics_db=self.forensics_db)

        first_ts = last_ts = None
        try:
            # Parse packets
            self.progress_text = "Parsing packets..."

            if SCAPY_AVAILABLE:
                packets = self._iter_with_scapy(filepath, file_size)
            elif self.tshark_path:
                packets = iter(self._parse_with_tshark(filepath, stats))
            else:
                raise RuntimeError("No packet parser available. Install Scapy or Wireshark.")

            # Analyze each packet as it is read: the whole file is never in memory.
            self.progress_text = "Running detection engines..."
            for i, pkt_info in enumerate(packets):
                if self._cancel:
                    self.progress_text = "Analysis cancelled."
                    break

                self.packets_processed = i + 1
                self.total_packets = i + 1
                if pkt_info.timestamp > 0:
                    first_ts = pkt_info.timestamp if first_ts is None else min(first_ts, pkt_info.timestamp)
                    last_ts = pkt_info.timestamp if last_ts is None else max(last_ts, pkt_info.timestamp)

                if i % 100 == 0:
                    self.progress_text = (
                        f"Analyzing packet {i+1} "
                        f"({self.progress}%) — {len(alert_list)} alerts"
                    )

                # Collect stats
                stats['packets_analyzed'] += 1
                stats['protocols'][pkt_info.protocol] += 1
                stats['total_bytes'] += pkt_info.length
                if pkt_info.src_ip:
                    stats['unique_src_ips'].add(pkt_info.src_ip)
                    stats['top_talkers'][pkt_info.src_ip] += pkt_info.length
                if pkt_info.dst_ip:
                    stats['unique_dst_ips'].add(pkt_info.dst_ip)
                    stats['top_destinations'][pkt_info.dst_ip] += pkt_info.length
                if pkt_info.src_port:
                    stats['unique_src_ports'].add(pkt_info.src_port)
                if pkt_info.dst_port:
                    stats['unique_dst_ports'].add(pkt_info.dst_port)
                if pkt_info.dns_query:
                    stats['dns_queries'].append(pkt_info.dns_query)

                # Run through IDS
                try:
                    analysis_ids.inspect_packet(pkt_info)
                except Exception as e:
                    logger.debug("IDS error on packet %d: %s", i, e)

                # Run IOC checks
                if self.ioc_scanner:
                    try:
                        findings = self.ioc_scanner.check_packet_ioc(pkt_info)
                        if findings:
                            from src.ids_engine import Alert
                            for f in findings:
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
                                on_alert(alert)
                    except Exception:
                        pass

                # Forensics: credential scanning, insecure protocol detection
                try:
                    raw_payload = pkt_info._raw_payload
                    if raw_payload:
                        forensics.analyze_packet_with_payload(pkt_info, raw_payload)
                    else:
                        forensics.analyze_packet(pkt_info)
                except Exception:
                    pass

        except Exception as e:
            logger.error("PCAP analysis error: %s", e)
            stats['error'] = str(e)

        stats['total_packets'] = stats['packets_analyzed']
        if first_ts is not None:
            stats['capture_start'] = datetime.fromtimestamp(first_ts).strftime('%Y-%m-%d %H:%M:%S')
            stats['capture_end'] = datetime.fromtimestamp(last_ts).strftime('%Y-%m-%d %H:%M:%S')
            stats['capture_duration'] = f"{last_ts - first_ts:.1f} seconds"

        # Finalize forensics
        try:
            forensics_results = forensics.finalize()
            narrative = forensics.generate_narrative()
        except Exception as e:
            logger.error("Forensics finalization error: %s", e)
            forensics_results = {}
            narrative = "Forensics report generation failed."

        # Generate alerts from forensics findings
        from src.ids_engine import Alert
        for cred in forensics.credentials_found:
            alert = Alert(
                rule_id='FORENSICS-CREDENTIAL',
                severity='CRITICAL',
                title=f"Plaintext Credential Found ({cred['protocol']})",
                description=(f"{cred['protocol']} {cred['credential_type']} "
                             f"transmitted in plaintext"),
                src_ip=cred.get('source_ip', ''),
                dst_ip=cred.get('destination_ip', ''),
                dst_port=cred.get('port', 0),
                category="Credential Exposure",
                evidence={
                    'protocol': cred['protocol'],
                    'credential_type': cred['credential_type'],
                    'value': cred['value'],
                    'source': f"{cred['source_ip']} → {cred['destination_ip']}:{cred['port']}",
                    'extra': cred.get('extra', {}),
                    'description': (f"A {cred['credential_type']} for {cred['protocol']} was "
                        f"found in plaintext network traffic. Anyone on the same network "
                        f"could have captured this credential."),
                    'recommendation': ('Change this password immediately. Switch to the '
                        'encrypted version of this protocol.'),
                },
            )
            on_alert(alert)

        for svc_finding in forensics.security_findings:
            kind = svc_finding.get('type', 'insecure_protocol')
            if kind == 'name_poisoning':
                continue    # the IDS engine's NAME-POISONING covers it, with more context
            # Each kind under its own rule and an honest category: everything used
            # to be filed as an "Insecure Service", user agents and server banners
            # included.
            rule_id, category = _FINDING_RULES.get(
                kind, ('FORENSICS-INSECURE-SVC', 'Insecure Service'))
            alert = Alert(
                rule_id=rule_id,
                severity=svc_finding['risk'],
                title=svc_finding['title'],
                description=svc_finding['description'],
                category=category,
                evidence=svc_finding.get('details', {}),
            )
            alert.evidence['recommendation'] = svc_finding.get('recommendation', '')
            on_alert(alert)

        for sensitive in forensics.sensitive_data:
            alert = Alert(
                rule_id='FORENSICS-SENSITIVE-DATA',
                severity=sensitive.get('risk', 'HIGH'),
                title=f"Sensitive Data in Transit ({sensitive['data_type']})",
                description=f"{sensitive['data_type']} found in unencrypted traffic",
                src_ip=sensitive.get('source_ip', ''),
                dst_ip=sensitive.get('destination_ip', ''),
                dst_port=sensitive.get('port', 0),
                category="Data Exposure",
                evidence={
                    'data_type': sensitive['data_type'],
                    'source': f"{sensitive['source_ip']} → {sensitive['destination_ip']}:{sensitive['port']}",
                },
            )
            on_alert(alert)

        # Finalize
        elapsed = time.time() - start_time
        stats['duration_sec'] = round(elapsed, 2)
        stats['packets_per_sec'] = round(stats['packets_analyzed'] / max(elapsed, 0.1), 0)

        # Convert sets to counts for JSON serialization
        stats['unique_src_ips'] = len(stats['unique_src_ips'])
        stats['unique_dst_ips'] = len(stats['unique_dst_ips'])
        stats['unique_src_ports'] = len(stats['unique_src_ports'])
        stats['unique_dst_ports'] = len(stats['unique_dst_ports'])
        stats['unique_dns_queries'] = len(set(stats['dns_queries']))
        stats['top_dns_queries'] = Counter(stats['dns_queries']).most_common(20)
        stats['top_talkers'] = stats['top_talkers'].most_common(20)
        stats['top_destinations'] = stats['top_destinations'].most_common(20)
        stats['protocols'] = dict(stats['protocols'])
        stats['alerts_by_severity'] = dict(stats['alerts_by_severity'])
        stats['alerts_by_category'] = dict(stats['alerts_by_category'])
        stats['alerts_by_verdict'] = dict(stats['alerts_by_verdict'])
        del stats['dns_queries']  # Too large to keep

        self.alerts = alert_list
        self.stats = stats
        self.forensics_results = forensics_results
        self.narrative = narrative
        self.is_analyzing = False
        self.progress = 100
        self.progress_text = (
            f"Complete: {stats['packets_analyzed']} packets, "
            f"{stats['alerts_generated']} alerts in {elapsed:.1f}s"
        )

        logger.info("PCAP analysis complete: %s", self.progress_text)
        return {
            'stats': stats,
            'alerts': [a.to_dict() for a in alert_list],
            'forensics': forensics_results,
            'narrative': narrative,
        }

    def analyze_file_async(self, filepath, callback=None, done_callback=None):
        """Run analysis in a background thread."""
        def _run():
            result = self.analyze_file(filepath, callback=callback)
            if done_callback:
                done_callback(result)

        thread = threading.Thread(target=_run, daemon=True, name="PcapAnalysis")
        thread.start()
        return thread

    def cancel(self):
        """Cancel an ongoing analysis."""
        self._cancel = True

    def export_results(self, filepath, format='json'):
        """Export analysis results to a file."""
        if format == 'json':
            data = {
                'analysis_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'stats': self.stats,
                'alerts': [a.to_dict() for a in self.alerts],
            }
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)

        elif format == 'csv':
            if self.alerts:
                # As the alert export does: the Windows default code page cannot
                # hold every domain or file name an alert can carry.
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=self.alerts[0].to_dict().keys())
                    writer.writeheader()
                    for alert in self.alerts:
                        row = alert.to_dict()
                        # Flatten evidence for CSV
                        row['evidence'] = json.dumps(row.get('evidence', {}))
                        writer.writerow(row)

        logger.info("Results exported to %s", filepath)

    # ─── Parsers ─────────────────────────────────────────────────

    def _extractor(self):
        """A capture engine used only for its parser (never started), so its
        handshake reassembly state belongs to this one file."""
        from src.capture import CaptureEngine
        return CaptureEngine(self.config)

    def _iter_with_scapy(self, filepath, file_size=0):
        """
        Yield a PacketInfo per packet, read with PcapReader (one at a time — rdpcap
        held the whole file as Scapy objects) and parsed by the live capture's own
        extractor in offline mode.
        """
        self.progress_text = "Reading with Scapy..."
        extractor = self._extractor()
        try:
            reader = PcapReader(filepath)
        except Exception as e:
            logger.error("Scapy could not open %s: %s", filepath, e)
            raise
        try:
            handle = getattr(reader, 'f', None)
            for i, packet in enumerate(reader):
                if self._cancel:
                    break
                if file_size and handle is not None and i % 200 == 0:
                    try:
                        self.progress = min(99, int(handle.tell() / file_size * 100))
                    except (OSError, ValueError):
                        pass
                try:
                    yield extractor._extract_packet_info(packet, offline=True)
                except Exception as e:
                    logger.debug("Packet %d not parsed: %s", i, e)
        finally:
            try:
                reader.close()
            except Exception:
                pass

    def _parse_with_scapy(self, filepath, stats=None):
        """Every packet of a file as PacketInfo. Kept for callers that want a list."""
        try:
            size = os.path.getsize(filepath)
        except OSError:
            size = 0
        return list(self._iter_with_scapy(filepath, size))

    def _parse_with_tshark(self, filepath, stats):
        """Parse PCAP with tshark for better performance on large files."""
        from src.capture import PacketInfo

        self.progress_text = "Parsing with tshark (fast mode)..."

        # Extract fields we need via tshark
        fields = [
            'frame.time_epoch', 'frame.len',
            'eth.src', 'eth.dst',
            'ip.src', 'ip.dst', 'ip.ttl',
            'ipv6.src', 'ipv6.dst',
            'tcp.srcport', 'tcp.dstport', 'tcp.flags',
            'udp.srcport', 'udp.dstport',
            'dns.qry.name', 'dns.resp.addr',
            'frame.protocols',
        ]

        cmd = [
            self.tshark_path,
            '-r', filepath,
            '-T', 'fields',
            '-E', 'separator=|',
            '-E', 'quote=n',
        ]
        for field in fields:
            cmd.extend(['-e', field])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            )
            if result.returncode != 0:
                logger.warning("tshark error, falling back to scapy: %s", result.stderr[:200])
                return self._parse_with_scapy(filepath, stats)
        except subprocess.TimeoutExpired:
            logger.warning("tshark timed out, falling back to scapy")
            return self._parse_with_scapy(filepath, stats)

        packets = []
        lines = result.stdout.strip().split('\n')

        for i, line in enumerate(lines):
            if self._cancel:
                break
            if not line.strip():
                continue

            if i % 1000 == 0:
                self.progress_text = f"Processing tshark output: {i+1}/{len(lines)}..."

            parts = line.split('|')
            if len(parts) < len(fields):
                parts.extend([''] * (len(fields) - len(parts)))

            info = PacketInfo()

            try:
                info.timestamp = float(parts[0]) if parts[0] else time.time()
            except ValueError:
                info.timestamp = time.time()

            try:
                info.length = int(parts[1]) if parts[1] else 0
            except ValueError:
                info.length = 0

            info.src_mac = parts[2]
            info.dst_mac = parts[3]
            info.src_ip = parts[4] or parts[7]  # IPv4 or IPv6
            info.dst_ip = parts[5] or parts[8]

            try:
                info.ttl = int(parts[6]) if parts[6] else 0
            except ValueError:
                info.ttl = 0

            # Determine protocol and ports
            protocols = parts[16].lower() if len(parts) > 16 else ''

            if parts[9]:  # TCP src port
                info.protocol = "TCP"
                try:
                    info.src_port = int(parts[9])
                    info.dst_port = int(parts[10])
                except ValueError:
                    pass
                info.flags = parts[11]
                if info.dst_port == 443 or info.src_port == 443:
                    info.is_encrypted = True
            elif parts[12]:  # UDP src port
                info.protocol = "UDP"
                try:
                    info.src_port = int(parts[12])
                    info.dst_port = int(parts[13])
                except ValueError:
                    pass
            elif 'icmp' in protocols:
                info.protocol = "ICMP"
            elif 'arp' in protocols:
                info.protocol = "ARP"
            elif 'ipv6' in protocols:
                info.protocol = "IPv6"
            elif info.src_ip:
                info.protocol = "IP/Other"
            else:
                info.protocol = "Other"

            # DNS
            info.dns_query = parts[14] if len(parts) > 14 else ''
            info.dns_response = parts[15] if len(parts) > 15 else ''

            info.payload_size = max(0, info.length - 54)  # Estimate
            info.process_name = ""
            info.process_pid = 0
            info.raw_summary = ""

            packets.append(info)

        return packets

    def get_status(self):
        return {
            'is_analyzing': self.is_analyzing,
            'progress': self.progress,
            'progress_text': self.progress_text,
            'total_packets': self.total_packets,
            'packets_processed': self.packets_processed,
            'alerts_found': len(self.alerts),
            'tshark_available': self.tshark_path is not None,
            'scapy_available': SCAPY_AVAILABLE,
        }
