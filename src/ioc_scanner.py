"""
Indicators of Compromise (IOC) Scanner
========================================
Detects signs that a system may ALREADY be compromised, which would
poison the ML baseline if not caught.

This runs independently of the ML engine using static, absolute rules
that fire regardless of what the baseline looks like. The idea is:
certain behaviors are NEVER normal, no matter how long they've been
happening.

Checks:
1. Connections to TOR exit nodes / anonymizing proxies
2. Active connections to known C2 ports
3. Processes with suspicious network behavior
4. Scheduled tasks / persistence mechanisms making network calls
5. Connections to IPs in threat feeds that are already established
6. Unusual listening ports
7. DNS over HTTPS to non-standard providers (potential DNS bypass)
8. Connections during times the user is idle
9. High-entropy domain connections (DGA indicators)
10. Outbound connections on non-standard protocols
"""

import os
import re
import time
import math
import socket
import logging
import threading
import subprocess
from collections import Counter, defaultdict
from datetime import datetime

logger = logging.getLogger("NetSentinel.IOC")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# ─── Known Suspicious Patterns (absolute rules, not baseline-relative) ──────

# Ports that are almost never used legitimately by desktop software
SUSPICIOUS_LISTENING_PORTS = {
    4444, 5555, 6666, 6667, 1337, 31337, 12345, 27374, 3127, 9999,
    7777, 65535, 1234, 8888, 9090, 2222, 3333,
}

# Known TOR directory authorities and common TOR ports
TOR_PORTS = {9001, 9030, 9050, 9051, 9150}

# DNS over HTTPS providers (non-system, potential DNS bypass)
DOH_ENDPOINTS = {
    '1.1.1.1', '1.0.0.1',       # Cloudflare (if not configured as system DNS)
    '8.8.8.8', '8.8.4.4',       # Google
    '9.9.9.9', '149.112.112.112', # Quad9
    '208.67.222.222', '208.67.220.220',  # OpenDNS
    '94.140.14.14', '94.140.15.15',      # AdGuard
}

# Processes commonly associated with malware or hacking tools.
# EXACT filename matches only — never substring match these against paths or cmdlines.
SUSPICIOUS_PROCESS_NAMES_EXACT = {
    # Netcat variants
    'nc.exe', 'nc64.exe', 'ncat.exe', 'netcat.exe',
    # Metasploit
    'meterpreter.exe', 'metsrv.dll', 'msfconsole.exe', 'msfvenom.exe',
    # Credential theft
    'mimikatz.exe', 'sekurlsa.exe', 'lazagne.exe', 'procdump64.exe',
    # Remote execution / lateral movement
    'psexec.exe', 'psexec64.exe', 'psexesvc.exe', 'paexec.exe',
    # Cobalt Strike
    'beacon.exe', 'cobaltstrike.exe',
    # RATs and trojans
    'darkcomet.exe', 'poisonivy.exe', 'njrat.exe', 'quasar.exe',
    'asyncrat.exe', 'remcos.exe', 'warzone.exe', 'orcusrat.exe',
    # Crypto miners
    'xmrig.exe', 'cpuminer.exe', 'cryptominer.exe', 'minerd.exe',
    'minergate.exe', 'nicehash.exe', 'ethminer.exe', 'phoenixminer.exe',
    # Network scanners
    'masscan.exe', 'nmap.exe', 'zenmap.exe', 'angry_ip_scanner.exe',
    # Brute force tools
    'hydra.exe', 'medusa.exe', 'thc-hydra.exe',
    # Password crackers
    'hashcat.exe', 'hashcat64.exe', 'john.exe',
    # TOR (standalone, not the Tor Browser bundle)
    'tor.exe',
    # Proxy / tunnel tools
    'proxychains.exe', 'chisel.exe', 'ligolo.exe', 'ngrok.exe',
    'frpc.exe', 'frps.exe', 'socat.exe', 'plink.exe',
    # Reverse shells / implants
    'powercat.exe', 'reverseshell.exe', 'bind_shell.exe',
    # Exfiltration tools
    'rclone.exe', 'winscp_portable.exe',
}

# Known safe Windows processes that should NEVER be flagged.
# These often have names that could false-positive on substring matching.
WINDOWS_SYSTEM_PROCESSES = {
    'csrss.exe', 'svchost.exe', 'lsass.exe', 'services.exe',
    'smss.exe', 'winlogon.exe', 'wininit.exe', 'dwm.exe',
    'explorer.exe', 'taskhostw.exe', 'taskhost.exe',
    'runtimebroker.exe', 'shellexperiencehost.exe', 'shellhost.exe',
    'startmenuexperiencehost.exe', 'searchhost.exe', 'searchui.exe',
    'sihost.exe', 'ctfmon.exe', 'fontdrvhost.exe', 'dllhost.exe',
    'conhost.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe',
    'wudfhost.exe', 'dashost.exe', 'wmiprvse.exe',
    'spoolsv.exe', 'msiexec.exe', 'trustedinstaller.exe',
    'tiworker.exe', 'audiodg.exe', 'searchindexer.exe',
    'securityhealthservice.exe', 'securityhealthsystray.exe',
    'sgrmbroker.exe', 'mpcmdrun.exe', 'msmpeng.exe',
    'smartscreen.exe', 'applicationframehost.exe',
    'systemsettings.exe', 'settingssynchost.exe',
    'backgroundtaskhost.exe', 'backgroundtransferhost.exe',
    'aggregatorhost.exe', 'monotificationux.exe',
    'officeclicktorun.exe', 'appvshnotify.exe',
    'msedge.exe', 'msedgewebview2.exe', 'widgets.exe',
    'lockapp.exe', 'logonui.exe', 'consent.exe',
    'lsaiso.exe', 'registry.exe', 'memory compression',
    # Common legitimate software
    'chrome.exe', 'firefox.exe', 'brave.exe', 'opera.exe',
    'code.exe', 'devenv.exe', 'rider64.exe',
    'spotify.exe', 'discord.exe', 'slack.exe', 'teams.exe',
    'onedrive.exe', 'dropbox.exe',
    'steam.exe', 'steamwebhelper.exe',
    'epicgameslauncher.exe', 'unrealcefsubprocess.exe',
    'acrobat.exe', 'acrord32.exe',
    'outlook.exe', 'winword.exe', 'excel.exe', 'powerpnt.exe',
    'onenote.exe', 'msteams.exe',
    # Adobe
    'creative cloud.exe', 'creative cloud ui helper.exe',
    'adobeipcbroker.exe', 'coresync.exe', 'ccxprocess.exe',
    'node.exe', 'adobecollabsync.exe', 'adobenotificationclient.exe',
    # Antivirus / security
    'eraagent.exe', 'ekrn.exe', 'egui.exe',  # ESET
    'mbam.exe', 'mbamservice.exe',            # Malwarebytes
    'savservice.exe',                          # Sophos
    # Drivers / hardware services
    'intelcphdcpsvc.exe', 'ipf_helper.exe', 'ipf_uf.exe',
    'ipfsvc.exe', 'lms.exe', 'jhi_service.exe',
    'logi_lamparray_service.exe', 'wmiregistrationservice.exe',
    'igfxem.exe', 'igfxhk.exe', 'igfxcuiservice.exe',
    'nahimicservice.exe', 'raikiservice.exe',
}

# Maximum entropy for a "normal" domain's longest label
# DGA domains tend to have entropy > 3.5 for labels > 10 chars
DGA_ENTROPY_THRESHOLD = 3.8
DGA_MIN_LABEL_LENGTH = 10

# Domains/patterns that look like DGA but are legitimate.
# These generate high-entropy subdomains by design.
DGA_WHITELIST_SUFFIXES = {
    # mDNS / local network discovery (never DGA)
    '.local',
    '._tcp.local',
    '._udp.local',

    # Home Assistant cloud
    '.nabu.casa',
    '.ui.nabu.casa',

    # ESET antivirus cloud scanning
    '.ecaserver.eset.com',
    '.eset.com',

    # Google Cast / Chromecast (UUIDs in mDNS names)
    '._googlecast._tcp.local',
    '._googlezone._tcp.local',
    '._googlerpc._tcp.local',

    # Apple / Bonjour
    '._airplay._tcp.local',
    '._raop._tcp.local',
    '._homekit._tcp.local',
    '._hap._tcp.local',
    '._companion-link._tcp.local',

    # Spotify Connect
    '._spotify-connect._tcp.local',

    # Amazon / Alexa
    '.amazonaws.com',
    '.amazon-dss.com',
    '.arcus-uswest.amazon.com',

    # CDN / cloud hashes (tracking IDs in subdomains)
    '.cloudfront.net',
    '.akamaized.net',
    '.fastly.net',
    '.azureedge.net',
    '.edgekey.net',
    '.edgesuite.net',

    # Telemetry / analytics (hashed identifiers)
    '.datadoghq.com',
    '.browser-intake-datadoghq.com',
    '.gvt2.com',
    '.gvt1.com',
    '.1e100.net',

    # Steam
    '.steamserver.net',
    '.steamcontent.com',

    # Samsung SmartThings
    '.samsungcloudsolution.com',
    '.samsungelectronics.com',

    # Microsoft telemetry
    '.events.data.microsoft.com',
    '.microsoft.com',

    # Let's Encrypt / ACME
    '.letsencrypt.org',

    # UniFi
    '.ubnt.com',
    '.ui.com',
}

# Full domain exact matches that are legitimate
DGA_WHITELIST_EXACT = set()

# Patterns in domain that indicate mDNS service records (not DGA)
DGA_WHITELIST_PATTERNS = [
    '_tcp.local',
    '_udp.local',
    '.in-addr.arpa',
    '.ip6.arpa',
    '_services._dns-sd.',
]

# Known services with high-entropy second-level domains (hyphenated names)
# These won't match the suffix list because the entropy is in the base domain itself
DGA_WHITELIST_REGISTERED_KEYWORDS = {
    'datadoghq', 'cloudflare', 'akamai', 'fastly', 'amazonaws',
    'googleusercontent', 'googlevideo', 'gstatic', 'googleapis',
    'azurewebsites', 'cloudfront', 'samsungcloudsolution',
    'steamserver', 'steamcontent', 'steampowered',
}


class IOCScanner:
    """
    Scans for indicators of compromise that are suspicious regardless
    of baseline. Designed to catch pre-existing infections.
    """

    def __init__(self, config, threat_intel=None, alert_callback=None):
        self.config = config
        self.threat_intel = threat_intel
        self.alert_callback = alert_callback
        self.enabled = True

        # Track findings
        self.findings = []
        self.scan_count = 0
        self.last_scan_time = 0

        # DGA tracking: domains seen in traffic, checked for entropy
        self._high_entropy_domains = defaultdict(int)  # {domain: count}

        # Merge config-driven DGA whitelist with built-in defaults
        extra_suffixes = config.get('whitelists', 'dga_whitelist_suffixes', default=[])
        self._dga_whitelist_suffixes = DGA_WHITELIST_SUFFIXES | set(extra_suffixes)
        extra_exact = config.get('whitelists', 'dga_whitelist_exact', default=[])
        self._dga_whitelist_exact = DGA_WHITELIST_EXACT | set(extra_exact)

        # Build known device IP/MAC sets for fast lookup
        self._known_device_ips = set()
        self._known_device_macs = set()
        self._known_devices = {}
        devices = config.get('known_devices', 'devices', default=[])
        for dev in devices:
            if dev.get('ip'):
                self._known_device_ips.add(dev['ip'])
                self._known_devices[dev['ip']] = dev
            if dev.get('mac'):
                self._known_device_macs.add(dev['mac'].lower())

        logger.info("IOC Scanner initialized. DGA whitelist: %d suffixes, %d exact, %d known devices.",
                     len(self._dga_whitelist_suffixes), len(self._dga_whitelist_exact),
                     len(self._known_devices))

    def run_startup_scan(self):
        """
        Run a comprehensive scan at startup before ML baseline training.
        Checks current system state for signs of compromise.
        """
        logger.info("Running startup IOC scan...")
        self.findings = []
        self.scan_count += 1

        if PSUTIL_AVAILABLE:
            self._scan_listening_ports()
            self._scan_active_connections()
            self._scan_suspicious_processes()

        self._scan_established_threat_intel()

        if self.findings:
            logger.warning("IOC scan found %d potential indicators of compromise!",
                          len(self.findings))
            for f in self.findings:
                logger.warning("  IOC: [%s] %s", f['severity'], f['title'])
                if self.alert_callback:
                    from src.ids_engine import Alert
                    alert = Alert(
                        rule_id=f['rule_id'],
                        severity=f['severity'],
                        title=f['title'],
                        description=f['description'],
                        category="IOC - Pre-existing Compromise",
                        evidence=f.get('evidence', {}),
                    )
                    self.alert_callback(alert)
        else:
            logger.info("IOC startup scan clean — no indicators found.")

        self.last_scan_time = time.time()
        return self.findings

    def check_packet_ioc(self, pkt_info):
        """
        Check a single packet against absolute IOC rules.
        These fire regardless of ML baseline.
        Called from the IDS engine for every packet.

        Returns list of finding dicts (may be empty).
        """
        findings = []

        # ─── TOR / Anonymizer Detection ──────────────────────
        if pkt_info.dst_port in TOR_PORTS:
            findings.append({
                'rule_id': 'IOC-TOR',
                'severity': 'HIGH',
                'title': 'Possible TOR Connection',
                'description': f'Connection to TOR-associated port {pkt_info.dst_port} '
                               f'on {pkt_info.dst_ip}',
                'evidence': {
                    'destination': f'{pkt_info.dst_ip}:{pkt_info.dst_port}',
                    'port_association': 'TOR network (anonymizing proxy)',
                    'process': pkt_info.process_name or 'Unknown',
                    'description': 'TOR connections from a regular workstation may indicate '
                        'malware using TOR for anonymous C2 communication, or data '
                        'exfiltration through anonymizing networks.',
                    'recommendation': 'If you are intentionally using TOR, this is expected. '
                        'If not, investigate which process is connecting to this port. '
                        'Malware commonly uses TOR to hide C2 traffic.',
                },
            })

        # ─── DGA Detection (high-entropy domains) ────────────
        if pkt_info.dns_query:
            domain = pkt_info.dns_query.lower()

            # Skip whitelisted domains (known-good high-entropy patterns)
            is_whitelisted = False

            # Check suffix whitelist (instance-level, includes config overrides)
            for suffix in self._dga_whitelist_suffixes:
                if domain.endswith(suffix):
                    is_whitelisted = True
                    break

            # Check pattern whitelist
            if not is_whitelisted:
                for pattern in DGA_WHITELIST_PATTERNS:
                    if pattern in domain:
                        is_whitelisted = True
                        break

            # Check exact whitelist (instance-level, includes config overrides)
            if not is_whitelisted and domain in self._dga_whitelist_exact:
                is_whitelisted = True

            # Check if registered domain (last 2 labels) contains a known service keyword
            # Catches cases like "browser-intake-us5-datadoghq.com"
            if not is_whitelisted:
                parts = domain.rsplit('.', 1)
                if len(parts) >= 2:
                    base_label = parts[0].rsplit('.', 1)[-1]  # rightmost subdomain label
                    for keyword in DGA_WHITELIST_REGISTERED_KEYWORDS:
                        if keyword in base_label:
                            is_whitelisted = True
                            break

            if not is_whitelisted:
                labels = domain.split('.')
                # Check longest non-TLD label
                for label in labels[:-1]:  # Skip TLD
                    if len(label) >= DGA_MIN_LABEL_LENGTH:
                        ent = self._label_entropy(label)
                        if ent >= DGA_ENTROPY_THRESHOLD:
                            self._high_entropy_domains[domain] += 1
                            # Only alert if we've seen multiple high-entropy domains
                            # (one-off could be a CDN hash, but a pattern = DGA)
                            total_dga = len(self._high_entropy_domains)
                            if total_dga >= 5:
                                findings.append({
                                    'rule_id': 'IOC-DGA',
                                    'severity': 'HIGH',
                                    'title': 'Domain Generation Algorithm Detected',
                                    'description': f'{total_dga} high-entropy domains detected — '
                                                   f'possible DGA malware',
                                    'evidence': {
                                        'latest_domain': domain,
                                        'domain_entropy': round(ent, 2),
                                        'total_dga_domains': total_dga,
                                        'sample_domains': list(self._high_entropy_domains.keys())[:15],
                                        'description': 'Domain Generation Algorithms (DGA) are used by '
                                            'malware to generate random-looking domain names for C2 '
                                            'communication. A high number of high-entropy domains is '
                                            'a strong indicator of an active DGA-based infection.',
                                        'recommendation': 'This is a strong malware indicator. '
                                            'Check running processes, scan with anti-malware tools, '
                                            'and consider isolating this machine from the network.',
                                    },
                                })

        # ─── DNS bypass (DoH to non-configured providers) ─────
        if pkt_info.dst_port == 443 and pkt_info.dst_ip in DOH_ENDPOINTS:
            # Only flag if this IP isn't our configured DNS
            findings.append({
                'rule_id': 'IOC-DOH-BYPASS',
                'severity': 'LOW',
                'title': 'DNS-over-HTTPS Detected',
                'description': f'HTTPS connection to known DoH provider {pkt_info.dst_ip}',
                'evidence': {
                    'destination': pkt_info.dst_ip,
                    'process': pkt_info.process_name or 'Unknown',
                    'description': 'DNS over HTTPS bypasses your local DNS configuration. '
                        'This is used legitimately by browsers for privacy, but malware '
                        'also uses it to bypass DNS-based security monitoring.',
                    'recommendation': 'If your browser has DoH enabled, this is normal. '
                        'If you see an unknown process making DoH connections, investigate.',
                },
            })

        # ─── Suspicious process making network connections ────
        if pkt_info.process_name:
            proc_lower = pkt_info.process_name.lower().strip()
            # Exact match on process filename only — never substring match
            if proc_lower in SUSPICIOUS_PROCESS_NAMES_EXACT and \
               proc_lower not in WINDOWS_SYSTEM_PROCESSES:
                findings.append({
                    'rule_id': 'IOC-SUSPICIOUS-PROC',
                    'severity': 'CRITICAL',
                    'title': f'Suspicious Process: {pkt_info.process_name}',
                    'description': f'Known hacking/malware tool "{pkt_info.process_name}" '
                                   f'is making network connections',
                    'evidence': {
                        'process_name': pkt_info.process_name,
                        'connection': f'{pkt_info.src_ip}:{pkt_info.src_port} → '
                                      f'{pkt_info.dst_ip}:{pkt_info.dst_port}',
                        'description': f'The process "{pkt_info.process_name}" matches '
                            f'a known hacking tool, remote access trojan, or malware. '
                            f'This should never appear on a normal workstation.',
                        'recommendation': 'Immediately investigate this process. '
                            'Kill the process, check how it got on the system, '
                            'and run a full malware scan.',
                    },
                })

        return findings

    # ─── Startup Scan Methods ────────────────────────────────

    def _scan_listening_ports(self):
        """Check for processes listening on suspicious ports."""
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr:
                    port = conn.laddr.port
                    if port in SUSPICIOUS_LISTENING_PORTS:
                        proc_name = "Unknown"
                        try:
                            if conn.pid:
                                proc_name = psutil.Process(conn.pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                        self.findings.append({
                            'rule_id': 'IOC-LISTEN-PORT',
                            'severity': 'HIGH',
                            'title': f'Suspicious Listening Port: {port}',
                            'description': f'Process "{proc_name}" (PID {conn.pid}) '
                                           f'is listening on suspicious port {port}',
                            'evidence': {
                                'port': port,
                                'process': proc_name,
                                'pid': conn.pid,
                                'address': f"{conn.laddr.ip}:{conn.laddr.port}",
                                'description': f'Port {port} is commonly used by malware, '
                                    f'backdoors, or hacking tools. Legitimate software '
                                    f'rarely listens on this port.',
                                'recommendation': f'Investigate process "{proc_name}" (PID {conn.pid}). '
                                    f'Check its file location, digital signature, and when it was installed.',
                            },
                        })
        except (psutil.AccessDenied, PermissionError):
            logger.debug("Insufficient permissions for port scan")

    def _scan_active_connections(self):
        """Check active connections against threat intel."""
        if not self.threat_intel:
            return

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    remote_ip = conn.raddr.ip
                    result = self.threat_intel.check_ip(remote_ip)
                    if result:
                        proc_name = "Unknown"
                        try:
                            if conn.pid:
                                proc_name = psutil.Process(conn.pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                        self.findings.append({
                            'rule_id': 'IOC-ACTIVE-THREAT',
                            'severity': 'CRITICAL',
                            'title': f'Active Connection to Threat Intel IP',
                            'description': f'"{proc_name}" has an ESTABLISHED connection to '
                                           f'{remote_ip} ({result["category"]})',
                            'evidence': {
                                'remote_ip': remote_ip,
                                'remote_port': conn.raddr.port,
                                'local_port': conn.laddr.port,
                                'process': proc_name,
                                'pid': conn.pid,
                                'threat_feed': result['feed'],
                                'threat_category': result['category'],
                                'connection_state': 'ESTABLISHED (active)',
                                'description': 'This machine currently has an active connection '
                                    'to an IP in a threat intelligence feed. This is the '
                                    'strongest possible indicator of compromise.',
                                'recommendation': 'IMMEDIATE ACTION: Identify this process, '
                                    'kill it, disconnect from network if possible, and run '
                                    'a full malware scan. This connection was already active '
                                    'before NetSentinel started monitoring.',
                            },
                        })
        except (psutil.AccessDenied, PermissionError):
            logger.debug("Insufficient permissions for connection scan")

    def _scan_suspicious_processes(self):
        """Check running processes against known malware/tool names."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    info = proc.info
                    proc_name = (info.get('name') or '').lower().strip()

                    # Skip known safe Windows processes
                    if proc_name in WINDOWS_SYSTEM_PROCESSES:
                        continue

                    # Exact match on process filename
                    if proc_name in SUSPICIOUS_PROCESS_NAMES_EXACT:
                        self.findings.append({
                            'rule_id': 'IOC-PROC-NAME',
                            'severity': 'CRITICAL',
                            'title': f'Suspicious Process Running: {info.get("name", "?")}',
                            'description': f'Process matching known malware/tool '
                                           f'"{proc_name}" is currently running',
                            'evidence': {
                                'process_name': info.get('name', 'Unknown'),
                                'pid': info.get('pid'),
                                'executable': info.get('exe', 'Unknown'),
                                'description': 'This process name exactly matches a known '
                                    'hacking tool, RAT, or malware component.',
                                'recommendation': 'Investigate immediately. Check the '
                                    'executable path, digital signature, and how it was '
                                    'installed on the system.',
                            },
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.debug("Process scan error: %s", e)

    def _scan_established_threat_intel(self):
        """Check if threat intel feeds loaded, warn if not."""
        if not self.threat_intel:
            self.findings.append({
                'rule_id': 'IOC-NO-THREAT-INTEL',
                'severity': 'MEDIUM',
                'title': 'Threat Intelligence Not Available',
                'description': 'Threat intel feeds did not load. IOC scanning is limited.',
                'evidence': {
                    'description': 'Without threat intelligence feeds, the IOC scanner '
                        'cannot check active connections against known malicious IPs.',
                    'recommendation': 'Ensure internet connectivity for feed downloads. '
                        'Feeds are cached and will work offline after first download.',
                },
            })

    @staticmethod
    def _label_entropy(label):
        """Shannon entropy of a DNS label."""
        if not label:
            return 0
        freq = Counter(label.lower())
        length = len(label)
        return -sum((c/length) * math.log2(c/length) for c in freq.values())

    def get_stats(self):
        return {
            'enabled': self.enabled,
            'scan_count': self.scan_count,
            'last_scan_time': self.last_scan_time,
            'findings_count': len(self.findings),
            'dga_domains_tracked': len(self._high_entropy_domains),
        }
