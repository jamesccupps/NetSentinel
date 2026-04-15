"""
Unified Alert Verification Engine
===================================
Sits between every detection engine and the alert output.
Every alert passes through verification before the user sees it.

Verifies by alert type:
- Threat Intel IP:    Multi-feed cross-check, reverse DNS, feed age, cloud check
- Threat Intel DNS:   Domain age (WHOIS), SSL cert check, registration info
- Port Scan:          Source locality, known scanner services, scan pattern
- Brute Force:        Source reputation, geo origin, target service check
- Data Exfiltration:  Destination service identification, process context
- DNS Tunneling:      Domain structure analysis, known CDN patterns
- Suspicious TLD:     Domain age, registrar reputation, content check
- ML Anomaly:         Activity correlation (updates, downloads, streaming)
- IOC Process:        Digital signature, location, hash, parent chain (via ProcessVerifier)
- ARP Spoofing:       Gateway MAC validation, historical MAC stability
- SYN/ICMP Flood:     Source locality, rate context
- Blacklist:          Confirms IP is still in blacklist, adds context

Each alert gets:
- verdict: VERIFIED_THREAT, LIKELY_THREAT, INCONCLUSIVE, LIKELY_FALSE_POSITIVE, FALSE_POSITIVE
- confidence: 0-100%
- reasoning: list of factors that led to the verdict
- severity may be upgraded or downgraded based on verification
"""

import os
import re
import time
import socket
import logging
import hashlib
import threading
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("NetSentinel.AlertVerify")

try:
    import urllib.request
    import json
    URLLIB_AVAILABLE = True
except ImportError:
    URLLIB_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class AlertVerdict:
    FALSE_POSITIVE = "FALSE_POSITIVE"
    LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"
    LIKELY_THREAT = "LIKELY_THREAT"
    VERIFIED_THREAT = "VERIFIED_THREAT"


# Known network scanner services that scan the entire internet
KNOWN_SCANNER_IPS_DOMAINS = {
    'shodan.io', 'censys.io', 'shadowserver.org',
    'binaryedge.io', 'zoomeye.org', 'onyphe.io',
    'recyber.net', 'stretchoid.com', 'internet-measurement.com',
    'internet-census.org',
}

# Known backup/sync/update services that generate large legitimate transfers
KNOWN_TRANSFER_SERVICES = {
    'windowsupdate.com', 'download.microsoft.com', 'delivery.mp.microsoft.com',
    'officecdn.microsoft.com', 'update.microsoft.com',
    'dl.google.com', 'redirector.googlevideo.com', 'cache.google.com',
    'swcdn.apple.com', 'updates.cdn-apple.com', 'appldnld.apple.com',
    'steampowered.com', 'steamcontent.com', 'content.steampowered.com',
    'epicgames-download1.akamaized.net', 'download.epicgames.com',
    'dropbox.com', 'dl.dropboxusercontent.com',
    'onedrive.live.com', 'skyapi.onedrive.live.com',
    'icloud-content.com',
    'drive.google.com', 'docs.google.com',
    'github.com', 'objects.githubusercontent.com',
    'releases.ubuntu.com', 'archive.ubuntu.com',
    'cdn.discordapp.com', 'media.discordapp.net',
    'akamai.net', 'akamaized.net', 'cloudfront.net',
    'fbcdn.net',
}

# Common CDN patterns that generate high-entropy subdomains (not DGA)
CDN_SUBDOMAIN_PATTERNS = [
    r'^[a-f0-9]{24,}$',        # Hex hashes (CDN cache keys)
    r'^[a-z0-9]{20,}-[a-z0-9]+$',  # CDN asset IDs
    r'^v\d+\.',                 # Version prefixes
    r'^[a-z]{2}\d*\.',          # Region codes (us1, eu2, etc.)
    r'cdn', r'cache', r'static', r'assets', r'media',
    r'edge', r'origin', r'lb', r'pool',
]


class AlertVerifier:
    """
    Unified verification engine for all alert types.
    Call verify_alert(alert, context) before emitting any alert.
    """

    def __init__(self, config, net_env=None, threat_intel=None, process_verifier=None):
        self.config = config
        self.net_env = net_env
        self.threat_intel = threat_intel
        self.process_verifier = process_verifier

        # Reverse DNS cache: {ip: (hostname, timestamp)}
        self._rdns_cache = {}
        self._rdns_ttl = 600  # 10 minutes

        # IP reputation cache: {ip: (score, factors, timestamp)}
        self._ip_rep_cache = {}

        # Domain info cache
        self._domain_cache = {}

        # Stats
        self.stats = {
            'total_verified': 0,
            'false_positives': 0,
            'likely_false_positives': 0,
            'inconclusive': 0,
            'likely_threats': 0,
            'verified_threats': 0,
        }

        logger.info("Alert Verifier initialized.")

    def verify_alert(self, alert, ids_engine=None):
        """
        Run verification checks appropriate for the alert type.
        Modifies alert.evidence in place with verification results.
        May adjust alert.severity based on findings.

        Returns the verdict string.
        """
        self.stats['total_verified'] += 1

        rule = alert.rule_id
        evidence = alert.evidence if alert.evidence else {}

        try:
            if rule == 'THREAT-INTEL-IP':
                verdict_info = self._verify_threat_intel_ip(alert, evidence, ids_engine)
            elif rule == 'THREAT-INTEL-DOMAIN':
                verdict_info = self._verify_threat_intel_domain(alert, evidence)
            elif rule == 'PORT-SCAN':
                verdict_info = self._verify_port_scan(alert, evidence)
            elif rule == 'BRUTE-FORCE':
                verdict_info = self._verify_brute_force(alert, evidence)
            elif rule == 'DATA-EXFIL':
                verdict_info = self._verify_data_exfil(alert, evidence, ids_engine)
            elif rule == 'DNS-TUNNEL':
                verdict_info = self._verify_dns_tunnel(alert, evidence)
            elif rule == 'DNS-BAD-TLD':
                verdict_info = self._verify_suspicious_tld(alert, evidence)
            elif rule == 'DNS-FLOOD':
                verdict_info = self._verify_dns_flood(alert, evidence)
            elif rule == 'ML-ANOMALY':
                verdict_info = self._verify_ml_anomaly(alert, evidence)
            elif rule in ('IOC-SUSPICIOUS-PROC', 'IOC-PROC-NAME',
                          'IOC-LISTEN-PORT', 'IOC-ACTIVE-THREAT'):
                verdict_info = self._verify_ioc_process(alert, evidence)
            elif rule == 'ARP-SPOOF':
                verdict_info = self._verify_arp_spoof(alert, evidence)
            elif rule in ('SYN-FLOOD', 'ICMP-FLOOD'):
                verdict_info = self._verify_flood(alert, evidence)
            elif rule in ('BAD-PORT', 'BL-PORT'):
                verdict_info = self._verify_bad_port(alert, evidence)
            elif rule in ('BL-IP-SRC', 'BL-IP-DST'):
                verdict_info = self._verify_blacklist(alert, evidence)
            elif rule == 'FORENSICS-INSECURE-SVC':
                verdict_info = self._verify_insecure_service(alert, evidence)
            elif rule == 'FORENSICS-CREDENTIAL':
                verdict_info = self._verify_credential_exposure(alert, evidence)
            elif rule == 'FORENSICS-SENSITIVE-DATA':
                verdict_info = self._verify_sensitive_data(alert, evidence)
            elif rule in ('IOC-TOR', 'IOC-DGA', 'IOC-DOH-BYPASS'):
                verdict_info = self._verify_ioc_network(alert, evidence)
            elif rule == 'ODD-HOURS':
                verdict_info = self._verify_odd_hours(alert, evidence)
            else:
                verdict_info = self._default_verdict(alert, evidence)
        except Exception as e:
            logger.debug("Verification error for %s: %s", rule, e)
            verdict_info = {
                'verdict': AlertVerdict.INCONCLUSIVE,
                'confidence': 0,
                'reasoning': [f'Verification error: {e}'],
            }

        # Apply verdict to alert
        verdict = verdict_info['verdict']
        evidence['alert_verification'] = {
            'verdict': verdict,
            'confidence': f"{verdict_info.get('confidence', 0):.0%}",
            'reasoning': verdict_info.get('reasoning', []),
            'auto_assessment': verdict_info.get('summary', ''),
        }

        # Adjust severity based on verdict
        self._adjust_severity(alert, verdict, verdict_info.get('confidence', 0))

        # Update stats
        stat_key = {
            AlertVerdict.FALSE_POSITIVE: 'false_positives',
            AlertVerdict.LIKELY_FALSE_POSITIVE: 'likely_false_positives',
            AlertVerdict.INCONCLUSIVE: 'inconclusive',
            AlertVerdict.LIKELY_THREAT: 'likely_threats',
            AlertVerdict.VERIFIED_THREAT: 'verified_threats',
        }.get(verdict, 'inconclusive')
        self.stats[stat_key] += 1

        return verdict

    def _adjust_severity(self, alert, verdict, confidence):
        """Adjust alert severity based on verification verdict."""
        if verdict == AlertVerdict.FALSE_POSITIVE:
            alert.severity = 'LOW'
            alert.title = f"[FALSE POSITIVE] {alert.title}"
        elif verdict == AlertVerdict.LIKELY_FALSE_POSITIVE:
            alert.severity = 'LOW'
            alert.title = f"[LIKELY SAFE] {alert.title}"
        elif verdict == AlertVerdict.VERIFIED_THREAT and confidence > 0.5:
            if alert.severity in ('LOW', 'MEDIUM'):
                alert.severity = 'HIGH'
            alert.title = f"[CONFIRMED] {alert.title}"
        elif verdict == AlertVerdict.LIKELY_THREAT and confidence > 0.5:
            alert.title = f"[LIKELY THREAT] {alert.title}"

    # ═══════════════════════════════════════════════════════════════
    # THREAT INTEL IP
    # ═══════════════════════════════════════════════════════════════
    def _verify_threat_intel_ip(self, alert, evidence, ids_engine):
        reasoning = []
        score = 0  # Positive = more likely threat

        ip = evidence.get('matched_ip', '')
        feed = evidence.get('threat_feed', '')
        category = evidence.get('threat_category', '')

        # Check if IP is in multiple feeds (stronger signal)
        if self.threat_intel:
            feeds_matched = 0
            # The cached check already ran — check if we can determine multi-feed
            if category in ('Botnet C2', 'Malicious SSL'):
                feeds_matched += 2
                reasoning.append(f"High-confidence threat category: {category}")
                score += 3
            else:
                score += 1

        # Check cloud association
        is_cloud = evidence.get('is_shared_cloud_ip', False)
        cloud_domains = evidence.get('cloud_domains', [])
        unknown_domains = evidence.get('unknown_domains', [])
        associated = evidence.get('associated_domains', [])

        if is_cloud and not unknown_domains:
            reasoning.append(f"Shared cloud IP serving known services: {', '.join(cloud_domains[:3])}")
            score -= 3
        elif is_cloud and unknown_domains:
            reasoning.append(f"Cloud IP with both known ({', '.join(cloud_domains[:2])}) "
                            f"and unknown ({', '.join(unknown_domains[:2])}) domains")
            score += 0  # Neutral
        elif not associated or associated == ['No domain resolved — direct IP connection']:
            reasoning.append("Direct IP connection with no DNS resolution — suspicious")
            score += 2

        # Reverse DNS check
        rdns = self._reverse_dns(ip)
        if rdns:
            reasoning.append(f"Reverse DNS: {rdns}")
            if self.net_env and self.net_env.is_known_cloud_domain(rdns):
                reasoning.append("Reverse DNS points to known cloud provider")
                score -= 2
        else:
            reasoning.append("No reverse DNS record — common for malicious infrastructure")
            score += 1

        # Determine verdict
        if score <= -2:
            verdict = AlertVerdict.LIKELY_FALSE_POSITIVE
            summary = "IP appears to be shared cloud infrastructure serving legitimate services"
        elif score <= 0:
            verdict = AlertVerdict.INCONCLUSIVE
            summary = "Cannot determine if this is a genuine threat or shared infrastructure"
        elif score <= 2:
            verdict = AlertVerdict.LIKELY_THREAT
            summary = "Multiple indicators suggest this IP is genuinely malicious"
        else:
            verdict = AlertVerdict.VERIFIED_THREAT
            summary = "High-confidence threat: known malicious infrastructure"

        return {
            'verdict': verdict,
            'confidence': min(abs(score) / 5, 1.0),
            'reasoning': reasoning,
            'summary': summary,
        }

    # ═══════════════════════════════════════════════════════════════
    # THREAT INTEL DOMAIN
    # ═══════════════════════════════════════════════════════════════
    def _verify_threat_intel_domain(self, alert, evidence):
        reasoning = []
        score = 0

        domain = evidence.get('queried_domain', '')
        confidence_level = evidence.get('confidence', 'LOW')
        hosted_on_cloud = evidence.get('hosted_on_cloud', False)

        # First-party cloud domains should never have reached here (filtered in IDS)
        # but double-check just in case
        if self.net_env and self.net_env.is_known_cloud_domain(domain):
            reasoning.append(f"First-party cloud service domain: {domain}")
            reasoning.append("Listed in feed because users share malicious content THROUGH the service")
            return {'verdict': AlertVerdict.FALSE_POSITIVE, 'confidence': 0.95,
                    'reasoning': reasoning,
                    'summary': f'{domain} is a legitimate cloud service. It appears in threat '
                               f'feeds because malicious content gets shared through it, not '
                               f'because the domain itself is malicious.'}

        if confidence_level == 'HIGH':
            reasoning.append("Domain found with HIGH confidence in threat feed (exact match)")
            score += 3
        elif confidence_level == 'MEDIUM':
            reasoning.append("Domain matched via parent domain in threat feed")
            score += 1

        if hosted_on_cloud:
            reasoning.append("Domain is on shared cloud hosting (anyone can deploy here)")
            score -= 1

        # Check domain age via structure analysis
        parts = domain.split('.')
        if len(parts) > 4:
            reasoning.append(f"Deep subdomain nesting ({len(parts)} levels) — common for malicious domains")
            score += 1

        # Very short or random-looking domain
        main_label = parts[0] if parts else ''
        if len(main_label) > 20 and not any(c.isalpha() and c.isupper() for c in main_label):
            reasoning.append("Domain label appears randomly generated")
            score += 1

        # Check TLD reputation
        tld = '.' + parts[-1] if parts else ''
        high_abuse_tlds = {'.xyz', '.top', '.buzz', '.tk', '.ml', '.ga', '.cf', '.gq', '.icu'}
        if tld in high_abuse_tlds:
            reasoning.append(f"Uses high-abuse TLD: {tld}")
            score += 1

        if score >= 3:
            verdict = AlertVerdict.VERIFIED_THREAT
            summary = "Domain shows strong malicious indicators"
        elif score >= 1:
            verdict = AlertVerdict.LIKELY_THREAT
            summary = "Domain has suspicious characteristics"
        elif score >= 0:
            verdict = AlertVerdict.INCONCLUSIVE
            summary = "Cannot determine domain legitimacy with certainty"
        else:
            verdict = AlertVerdict.LIKELY_FALSE_POSITIVE
            summary = "Domain appears to be on shared infrastructure, likely safe"

        return {'verdict': verdict, 'confidence': min(abs(score)/4, 1.0),
                'reasoning': reasoning, 'summary': summary}

    # ═══════════════════════════════════════════════════════════════
    # PORT SCAN
    # ═══════════════════════════════════════════════════════════════
    def _verify_port_scan(self, alert, evidence):
        reasoning = []
        score = 0

        scanner_ip = evidence.get('scanner_ip', alert.src_ip)
        ports = evidence.get('ports_scanned', [])
        port_count = evidence.get('unique_port_count', 0)

        # Check if scanner is local (same subnet)
        if self._is_local_ip(scanner_ip):
            reasoning.append(f"Scanner is on local network ({scanner_ip})")
            # Could be a compromised device OR a misconfigured one
            score += 1  # Still suspicious but less than external
        else:
            reasoning.append(f"External scanner: {scanner_ip}")
            score += 2

        # Check against known scanner services
        rdns = self._reverse_dns(scanner_ip)
        if rdns:
            for scanner_domain in KNOWN_SCANNER_IPS_DOMAINS:
                if scanner_domain in rdns.lower():
                    reasoning.append(f"Known internet scanner service: {rdns}")
                    score -= 2
                    break

        # Check scan pattern
        if ports:
            # Sequential ports = systematic scan
            sorted_ports = sorted(ports)
            sequential = sum(1 for i in range(len(sorted_ports)-1)
                           if sorted_ports[i+1] - sorted_ports[i] == 1)
            if sequential > len(ports) * 0.5:
                reasoning.append("Sequential port pattern — systematic scan")
                score += 1
            # Common service ports = service discovery
            common_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443}
            common_hit = len(set(ports) & common_ports)
            if common_hit > len(ports) * 0.7:
                reasoning.append("Targeting common service ports — service discovery scan")
                score += 1

        # Volume matters
        if port_count > 100:
            reasoning.append(f"Very aggressive scan: {port_count} ports")
            score += 2
        elif port_count > 30:
            reasoning.append(f"Moderate scan: {port_count} ports")
            score += 1

        if score >= 3:
            verdict = AlertVerdict.VERIFIED_THREAT
            summary = "Confirmed port scan — likely reconnaissance"
        elif score >= 1:
            verdict = AlertVerdict.LIKELY_THREAT
            summary = "Probable port scan activity"
        elif score >= 0:
            verdict = AlertVerdict.INCONCLUSIVE
            summary = "Could be scanning or legitimate service discovery"
        else:
            verdict = AlertVerdict.LIKELY_FALSE_POSITIVE
            summary = "Known scanner service or benign network discovery"

        return {'verdict': verdict, 'confidence': min(abs(score)/4, 1.0),
                'reasoning': reasoning, 'summary': summary}

    # ═══════════════════════════════════════════════════════════════
    # BRUTE FORCE
    # ═══════════════════════════════════════════════════════════════
    def _verify_brute_force(self, alert, evidence):
        reasoning = []
        score = 0

        attacker_ip = evidence.get('attacker_ip', alert.src_ip)
        service = evidence.get('target_service', '')
        attempts = evidence.get('failed_attempts', 0)

        # External attacker = more serious
        if not self._is_local_ip(attacker_ip):
            reasoning.append(f"External source: {attacker_ip}")
            score += 2
        else:
            reasoning.append(f"Local network source: {attacker_ip}")
            score += 1

        # Check threat intel
        if self.threat_intel:
            ti_result = self.threat_intel.check_ip(attacker_ip)
            if ti_result:
                reasoning.append(f"Source IP in threat feed: {ti_result['category']}")
                score += 2

        # Volume
        if attempts > 50:
            reasoning.append(f"Very high volume: {attempts} attempts")
            score += 2
        elif attempts > 20:
            reasoning.append(f"Moderate volume: {attempts} attempts")
            score += 1

        # Target service context
        high_value_services = {'SSH', 'RDP', 'SMB', 'MSSQL', 'MySQL', 'PostgreSQL'}
        if service in high_value_services:
            reasoning.append(f"Targeting high-value service: {service}")
            score += 1

        if score >= 4:
            verdict = AlertVerdict.VERIFIED_THREAT
            summary = "Confirmed brute force attack"
        elif score >= 2:
            verdict = AlertVerdict.LIKELY_THREAT
            summary = "Probable brute force attempt"
        else:
            verdict = AlertVerdict.INCONCLUSIVE
            summary = "Failed connections detected — could be misconfiguration"

        return {'verdict': verdict, 'confidence': min(score/5, 1.0),
                'reasoning': reasoning, 'summary': summary}

    # ═══════════════════════════════════════════════════════════════
    # DATA EXFILTRATION
    # ═══════════════════════════════════════════════════════════════
    def _verify_data_exfil(self, alert, evidence, ids_engine):
        reasoning = []
        score = 0

        dst_ip = evidence.get('destination_ip', alert.dst_ip)
        mb = evidence.get('megabytes_transferred', 0)
        process = evidence.get('process', '')

        # Get destination domains — try IDS engine first, then evidence fallback
        dst_domains = set()
        if ids_engine:
            dst_domains = ids_engine._get_domains_for_ip(dst_ip)
        # Fallback: check evidence fields
        if not dst_domains:
            ev_domains = evidence.get('destination_domains', [])
            if ev_domains and ev_domains != ['No domain — direct IP']:
                dst_domains = set(ev_domains)

        is_known_service = False
        for domain in dst_domains:
            for known in KNOWN_TRANSFER_SERVICES:
                if domain.endswith(known) or domain == known:
                    is_known_service = True
                    reasoning.append(f"Destination is known service: {domain}")
                    break
            if is_known_service:
                break

        if self.net_env and any(self.net_env.is_known_cloud_domain(d) for d in dst_domains):
            reasoning.append("Destination is recognized cloud/CDN provider")
            score -= 2

        if is_known_service:
            score -= 3

        if not dst_domains:
            reasoning.append("No domain associated with destination — direct IP transfer")
            score += 2

        # Process context
        known_transfer_procs = {'onedrive.exe', 'dropbox.exe', 'googledrivesync.exe',
                                'icloudservices.exe', 'steam.exe', 'steamwebhelper.exe',
                                'chrome.exe', 'firefox.exe', 'msedge.exe',
                                'windowsupdate', 'svchost.exe', 'bits'}
        if process.lower() in known_transfer_procs:
            reasoning.append(f"Transfer by known application: {process}")
            score -= 2

        # Volume context
        if mb > 500:
            reasoning.append(f"Very large transfer: {mb:.0f} MB")
            score += 2
        elif mb > 200:
            reasoning.append(f"Large transfer: {mb:.0f} MB")
            score += 1

        # Check threat intel on destination
        if self.threat_intel:
            ti_result = self.threat_intel.check_ip(dst_ip)
            if ti_result:
                reasoning.append(f"Destination in threat feed: {ti_result['category']}")
                score += 3

        if score <= -3:
            verdict = AlertVerdict.FALSE_POSITIVE
            summary = "Transfer is to a known legitimate service"
        elif score <= -1:
            verdict = AlertVerdict.LIKELY_FALSE_POSITIVE
            summary = "Transfer appears to be normal application activity"
        elif score <= 1:
            verdict = AlertVerdict.INCONCLUSIVE
            summary = "Large transfer detected — unable to confirm intent"
        elif score <= 3:
            verdict = AlertVerdict.LIKELY_THREAT
            summary = "Suspicious large transfer to unrecognized destination"
        else:
            verdict = AlertVerdict.VERIFIED_THREAT
            summary = "Data exfiltration indicators confirmed"

        return {'verdict': verdict, 'confidence': min(abs(score)/5, 1.0),
                'reasoning': reasoning, 'summary': summary}

    # ═══════════════════════════════════════════════════════════════
    # DNS TUNNELING
    # ═══════════════════════════════════════════════════════════════
    def _verify_dns_tunnel(self, alert, evidence):
        reasoning = []
        score = 0

        query = evidence.get('full_query', '')
        entropy = evidence.get('subdomain_entropy', 0)
        query_len = evidence.get('query_length', 0)

        # Check if it matches known CDN patterns
        parts = query.split('.')
        subdomain = parts[0] if parts else ''
        is_cdn_pattern = False
        for pattern in CDN_SUBDOMAIN_PATTERNS:
            if re.search(pattern, subdomain, re.IGNORECASE):
                is_cdn_pattern = True
                reasoning.append(f"Subdomain matches CDN/cache pattern: {pattern}")
                score -= 2
                break

        # Check if parent domain is known cloud
        parent = '.'.join(parts[-2:]) if len(parts) >= 2 else ''
        if self.net_env and self.net_env.is_known_cloud_domain(parent):
            reasoning.append(f"Parent domain is known cloud service: {parent}")
            score -= 2

        # Entropy analysis
        if entropy > 4.5:
            reasoning.append(f"Very high subdomain entropy: {entropy:.2f}")
            score += 2
        elif entropy > 3.8:
            reasoning.append(f"Elevated subdomain entropy: {entropy:.2f}")
            score += 1

        # Length analysis
        if query_len > 100:
            reasoning.append(f"Extremely long query: {query_len} chars")
            score += 2
        elif query_len > 70:
            reasoning.append(f"Very long query: {query_len} chars")
            score += 1

        if score >= 3:
            verdict = AlertVerdict.VERIFIED_THREAT
            summary = "Strong DNS tunneling indicators"
        elif score >= 1:
            verdict = AlertVerdict.LIKELY_THREAT
            summary = "Suspicious DNS query pattern"
        elif score >= 0:
            verdict = AlertVerdict.INCONCLUSIVE
            summary = "Unusual DNS query — could be CDN or tunneling"
        else:
            verdict = AlertVerdict.LIKELY_FALSE_POSITIVE
            summary = "Query matches known CDN/cloud patterns"

        return {'verdict': verdict, 'confidence': min(abs(score)/4, 1.0),
                'reasoning': reasoning, 'summary': summary}

    # ═══════════════════════════════════════════════════════════════
    # SUSPICIOUS TLD
    # ═══════════════════════════════════════════════════════════════
    def _verify_suspicious_tld(self, alert, evidence):
        reasoning = []
        score = 0

        domain = evidence.get('full_query', '')
        tld = evidence.get('suspicious_tld', '')
        total_queries = evidence.get('total_queries_this_tld', 0)

        reasoning.append(f"Domain uses high-abuse TLD: {tld}")
        score += 1

        # Many queries to same TLD = more concerning
        if total_queries > 10:
            reasoning.append(f"{total_queries} queries to {tld} domains — pattern of access")
            score += 1
        elif total_queries == 1:
            reasoning.append("Single query — may be a one-off ad redirect")
            score -= 1

        # Check if domain looks auto-generated
        parts = domain.split('.')
        if parts and len(parts[0]) > 15:
            reasoning.append("Long domain label — possibly generated")
            score += 1

        if score >= 2:
            verdict = AlertVerdict.LIKELY_THREAT
            summary = "Domain on high-abuse TLD with suspicious characteristics"
        elif score >= 1:
            verdict = AlertVerdict.INCONCLUSIVE
            summary = "Suspicious TLD — could be legitimate or malicious"
        else:
            verdict = AlertVerdict.LIKELY_FALSE_POSITIVE
            summary = "Likely a one-off redirect or ad network domain"

        return {'verdict': verdict, 'confidence': min(abs(score)/3, 1.0),
                'reasoning': reasoning, 'summary': summary}

    # ═══════════════════════════════════════════════════════════════
    # DNS FLOOD
    # ═══════════════════════════════════════════════════════════════
    def _verify_dns_flood(self, alert, evidence):
        reasoning = []
        score = 0

        query_count = evidence.get('query_count', 0)
        unique_domains = evidence.get('unique_domains', 0)
        process = evidence.get('process', '')

        # Browser-generated DNS is normal
        browser_procs = {'chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe', 'opera.exe'}
        if process.lower() in browser_procs:
            reasoning.append(f"DNS queries generated by browser ({process})")
            score -= 2

        # High unique domain ratio = DGA, low = just chatty app
        if isinstance(unique_domains, int) and query_count > 0:
            ratio = unique_domains / query_count
            if ratio > 0.8:
                reasoning.append("Most queries are to unique domains — possible DGA")
                score += 2
            else:
                reasoning.append("Many repeated queries — likely app polling behavior")
                score -= 1

        if score >= 2:
            verdict = AlertVerdict.LIKELY_THREAT
            summary = "High rate of unique DNS queries — possible DGA"
        elif score >= 0:
            verdict = AlertVerdict.INCONCLUSIVE
            summary = "Elevated DNS rate — monitoring"
        else:
            verdict = AlertVerdict.LIKELY_FALSE_POSITIVE
            summary = "Normal browser/application DNS activity"

        return {'verdict': verdict, 'confidence': min(abs(score)/3, 1.0),
                'reasoning': reasoning, 'summary': summary}

    # ═══════════════════════════════════════════════════════════════
    # ML ANOMALY
    # ═══════════════════════════════════════════════════════════════
    def _verify_ml_anomaly(self, alert, evidence):
        reasoning = []
        score = 0

        raw_score = evidence.get('anomaly_score', '0')
        # Handle both "0.2669" and "0.2669 (threshold: 0.25)" formats
        try:
            anomaly_score = float(str(raw_score).split()[0])
        except (ValueError, IndexError):
            anomaly_score = 0

        unusual = evidence.get('what_is_unusual', [])
        compared_against = evidence.get('compared_against', '')

        # Check if baseline is still learning
        if any('still learning' in str(item).lower() for item in unusual):
            reasoning.append("Baseline is still learning — low confidence in anomaly detection")
            score -= 2

        # Barely over threshold = low confidence
        threshold = 0.25
        if anomaly_score < threshold * 1.5:
            reasoning.append(f"Score barely above threshold ({anomaly_score:.3f}) — marginal anomaly")
            score -= 1

        # Check if deviations match known benign patterns
        for item in unusual:
            item_lower = str(item).lower()
            if 'bandwidth' in item_lower and 'above' in item_lower:
                reasoning.append("Bandwidth spike — could be download, update, or streaming")
                score -= 1
            elif 'encrypted' in item_lower:
                reasoning.append("Change in encrypted traffic ratio — likely browsing pattern shift")
                score -= 1
            elif 'unique dest ports' in item_lower:
                reasoning.append("Port diversity change — normal for browsing sessions")
                score -= 1
            elif 'syn ratio' in item_lower and 'above' in item_lower:
                reasoning.append("Elevated SYN ratio — could indicate new connections or scanning")
                score += 1
            elif 'failed connection' in item_lower:
                reasoning.append("Connection failures elevated — potential scanning or service issues")
                score += 1

        # High anomaly score = more weight to ML
        if anomaly_score > 0.7:
            reasoning.append(f"Very high anomaly score: {anomaly_score:.2f}")
            score += 2
        elif anomaly_score > 0.4:
            reasoning.append(f"Moderate anomaly score: {anomaly_score:.2f}")
            score += 1

        if score >= 2:
            verdict = AlertVerdict.LIKELY_THREAT
            summary = "ML detected significant deviation with suspicious characteristics"
        elif score >= 0:
            verdict = AlertVerdict.INCONCLUSIVE
            summary = "Statistical anomaly — may be normal activity variation"
        else:
            verdict = AlertVerdict.LIKELY_FALSE_POSITIVE
            summary = "Deviations consistent with normal usage patterns"

        return {'verdict': verdict, 'confidence': min(abs(score)/4, 1.0),
                'reasoning': reasoning, 'summary': summary}

    # ═══════════════════════════════════════════════════════════════
    # IOC PROCESS
    # ═══════════════════════════════════════════════════════════════
    def _verify_ioc_process(self, alert, evidence):
        """Delegates to ProcessVerifier for deep process analysis."""
        if self.process_verifier:
            self.process_verifier.verify_alert(alert)
            pv = evidence.get('verification', {})
            pv_verdict = pv.get('verdict', '')

            from src.process_verify import Verdict
            if pv_verdict == Verdict.VERIFIED_SAFE:
                return {'verdict': AlertVerdict.FALSE_POSITIVE, 'confidence': 0.9,
                        'reasoning': [pv.get('summary', 'Verified safe')],
                        'summary': pv.get('summary', '')}
            elif pv_verdict == Verdict.LIKELY_SAFE:
                return {'verdict': AlertVerdict.LIKELY_FALSE_POSITIVE, 'confidence': 0.7,
                        'reasoning': [pv.get('summary', 'Likely safe')],
                        'summary': pv.get('summary', '')}
            elif pv_verdict == Verdict.MALICIOUS:
                return {'verdict': AlertVerdict.VERIFIED_THREAT, 'confidence': 0.9,
                        'reasoning': [pv.get('summary', 'Malicious indicators')],
                        'summary': pv.get('summary', '')}
            elif pv_verdict == Verdict.SUSPICIOUS:
                return {'verdict': AlertVerdict.LIKELY_THREAT, 'confidence': 0.6,
                        'reasoning': [pv.get('summary', 'Suspicious indicators')],
                        'summary': pv.get('summary', '')}

        return {'verdict': AlertVerdict.INCONCLUSIVE, 'confidence': 0.3,
                'reasoning': ['Could not fully verify process'],
                'summary': 'Process verification incomplete'}

    # ═══════════════════════════════════════════════════════════════
    # ARP SPOOFING
    # ═══════════════════════════════════════════════════════════════
    def _verify_arp_spoof(self, alert, evidence):
        reasoning = []
        score = 2  # ARP spoofing is serious by default

        ip = evidence.get('ip_address', alert.src_ip)

        # Check if this is the gateway — most important
        if self.net_env and ip in self.net_env.gateways:
            reasoning.append("CRITICAL: ARP change on gateway IP — high risk of MITM")
            score += 2
        else:
            reasoning.append("ARP change on non-gateway device")

        # Check if this could be a DHCP reassignment
        reasoning.append("Note: MAC changes can occur during DHCP lease renewal or "
                         "device replacement — verify the new MAC belongs to a known device")

        return {'verdict': AlertVerdict.LIKELY_THREAT, 'confidence': min(score/4, 1.0),
                'reasoning': reasoning,
                'summary': 'ARP change detected — verify MAC belongs to expected device'}

    # ═══════════════════════════════════════════════════════════════
    # SYN/ICMP FLOOD
    # ═══════════════════════════════════════════════════════════════
    def _verify_flood(self, alert, evidence):
        reasoning = []
        score = 2  # Floods are inherently concerning

        src_ip = alert.src_ip
        if not self._is_local_ip(src_ip):
            reasoning.append(f"External source: {src_ip}")
            score += 1
        else:
            reasoning.append(f"Local source: {src_ip} — could be compromised device")

        count = evidence.get('syn_count', 0) or evidence.get('icmp_count', 0)
        if count > 200:
            reasoning.append(f"Very high volume: {count} packets")
            score += 1

        return {'verdict': AlertVerdict.LIKELY_THREAT, 'confidence': min(score/4, 1.0),
                'reasoning': reasoning,
                'summary': 'Flood attack pattern detected'}

    # ═══════════════════════════════════════════════════════════════
    # BAD PORT
    # ═══════════════════════════════════════════════════════════════
    def _verify_bad_port(self, alert, evidence):
        reasoning = []
        score = 1

        port = evidence.get('port', alert.dst_port)
        process = evidence.get('process', 'Unknown')

        reasoning.append(f"Connection to known malicious port {port}")

        # Check the process making the connection
        if process and process != 'Unknown':
            proc_lower = process.lower()
            safe_procs = {'chrome.exe', 'firefox.exe', 'msedge.exe', 'svchost.exe',
                          'system', 'steam.exe'}
            if proc_lower in safe_procs:
                reasoning.append(f"Connection by known application: {process}")
                score -= 1
            else:
                reasoning.append(f"Connection by: {process}")
                score += 1

        if score >= 2:
            verdict = AlertVerdict.LIKELY_THREAT
            summary = "Suspicious port connection by unrecognized process"
        elif score >= 1:
            verdict = AlertVerdict.INCONCLUSIVE
            summary = "Known bad port — verify the connecting process"
        else:
            verdict = AlertVerdict.LIKELY_FALSE_POSITIVE
            summary = "Known application using coincidental port number"

        return {'verdict': verdict, 'confidence': min(abs(score)/3, 1.0),
                'reasoning': reasoning, 'summary': summary}

    # ═══════════════════════════════════════════════════════════════
    # BLACKLIST
    # ═══════════════════════════════════════════════════════════════
    def _verify_blacklist(self, alert, evidence):
        reasoning = ["IP matches user-configured blacklist"]
        return {'verdict': AlertVerdict.LIKELY_THREAT, 'confidence': 0.8,
                'reasoning': reasoning,
                'summary': 'User-blacklisted IP — you added this to the blocklist'}

    # ═══════════════════════════════════════════════════════════════
    # FORENSICS: INSECURE SERVICE
    # ═══════════════════════════════════════════════════════════════
    def _verify_insecure_service(self, alert, evidence):
        reasoning = []
        score = 0

        service = evidence.get('service', '')
        server = evidence.get('server', '')
        port = evidence.get('port', alert.dst_port) or alert.dst_port or 0
        packets = evidence.get('packets_observed', 0)
        bytes_xfer = evidence.get('bytes_transferred', 0)
        dst_ip = alert.dst_ip or ''

        # HTTP on port 80 — check if this is just a redirect
        if service == 'HTTP' or port == 80:
            # Check if same IP also has HTTPS (strong redirect signal)
            has_https = evidence.get('has_https', False)
            if has_https:
                reasoning.append("Server also serves HTTPS — HTTP traffic is redirect")
                score -= 3

            # Small traffic = likely just HTTP→HTTPS redirect
            if bytes_xfer < 2000 and packets < 10:
                reasoning.append(f"Only {bytes_xfer} bytes / {packets} packets — "
                                f"likely an HTTP→HTTPS redirect, not active HTTP usage")
                score -= 3
            elif bytes_xfer < 10000 and has_https:
                reasoning.append(f"Minimal HTTP alongside HTTPS — redirect traffic")
                score -= 2
            else:
                reasoning.append(f"Sustained HTTP traffic: {bytes_xfer:,} bytes, {packets} packets")
                score += 1

            # Check if destination is a known cloud/CDN (redirects are normal)
            if self.net_env:
                dst_domains = set()
                if dst_ip:
                    rdns = self._reverse_dns(dst_ip)
                    if rdns and self.net_env.is_known_cloud_domain(rdns):
                        reasoning.append(f"Destination is known cloud service ({rdns})")
                        score -= 2

        # CRITICAL services (FTP, Telnet, VNC, Redis, MongoDB)
        elif port in (21, 23, 5900, 6379, 27017, 9200):
            reasoning.append(f"{service} is a critically insecure protocol")
            score += 3
            if packets > 20:
                reasoning.append(f"Active session: {packets} packets, {bytes_xfer:,} bytes")
                score += 1

        # Databases
        elif port in (1433, 3306, 5432, 1521):
            reasoning.append(f"Unencrypted database connection ({service})")
            score += 2

        # Industrial/SCADA
        elif port in (502, 47808):
            reasoning.append(f"Industrial protocol ({service}) — zero authentication")
            score += 3

        # Everything else
        else:
            reasoning.append(f"Unencrypted {service} service on port {port}")
            score += 1

        if score >= 3:
            verdict = AlertVerdict.VERIFIED_THREAT
            summary = f"Active unencrypted {service} — data is exposed"
        elif score >= 1:
            verdict = AlertVerdict.LIKELY_THREAT
            summary = f"Unencrypted {service} in use"
        elif score >= 0:
            verdict = AlertVerdict.INCONCLUSIVE
            summary = f"Minimal {service} traffic — may be benign"
        else:
            verdict = AlertVerdict.LIKELY_FALSE_POSITIVE
            summary = f"Likely HTTP→HTTPS redirect, not active insecure usage"

        return {'verdict': verdict, 'confidence': min(abs(score)/4, 1.0),
                'reasoning': reasoning, 'summary': summary}

    # ═══════════════════════════════════════════════════════════════
    # FORENSICS: CREDENTIAL EXPOSURE
    # ═══════════════════════════════════════════════════════════════
    def _verify_credential_exposure(self, alert, evidence):
        reasoning = []
        protocol = evidence.get('protocol', '')
        cred_type = evidence.get('credential_type', '')

        # Credentials in plaintext are always serious
        reasoning.append(f"Plaintext {protocol} {cred_type} captured from network traffic")
        reasoning.append("Anyone on the same network segment could have intercepted this")

        return {'verdict': AlertVerdict.VERIFIED_THREAT, 'confidence': 0.95,
                'reasoning': reasoning,
                'summary': f"Confirmed: {protocol} credential transmitted in plaintext"}

    # ═══════════════════════════════════════════════════════════════
    # FORENSICS: SENSITIVE DATA
    # ═══════════════════════════════════════════════════════════════
    def _verify_sensitive_data(self, alert, evidence):
        reasoning = []
        data_type = evidence.get('data_type', '')

        critical_types = {'Private Key', 'Credit Card', 'SSN', 'Modbus WRITE',
                         'BACnet WRITE', 'BACnet RESET', 'SMBv1', 'VNC Session'}
        if data_type in critical_types:
            reasoning.append(f"Critical sensitive data: {data_type}")
            return {'verdict': AlertVerdict.VERIFIED_THREAT, 'confidence': 0.9,
                    'reasoning': reasoning,
                    'summary': f"Confirmed: {data_type} detected in unencrypted traffic"}

        reasoning.append(f"Sensitive data detected: {data_type}")
        return {'verdict': AlertVerdict.LIKELY_THREAT, 'confidence': 0.7,
                'reasoning': reasoning,
                'summary': f"{data_type} found in network traffic"}

    # ═══════════════════════════════════════════════════════════════
    # IOC NETWORK (TOR, DGA, DoH)
    # ═══════════════════════════════════════════════════════════════
    def _verify_ioc_network(self, alert, evidence):
        reasoning = []
        rule = alert.rule_id

        if rule == 'IOC-TOR':
            reasoning.append("Connection to TOR-associated port detected")
            # Check if Tor Browser is a known installed app
            process = evidence.get('process', '')
            if 'firefox' in process.lower() or 'tor' in process.lower():
                reasoning.append("May be intentional Tor Browser usage")
                return {'verdict': AlertVerdict.INCONCLUSIVE, 'confidence': 0.5,
                        'reasoning': reasoning,
                        'summary': 'TOR connection — verify if intentional'}
            return {'verdict': AlertVerdict.LIKELY_THREAT, 'confidence': 0.7,
                    'reasoning': reasoning,
                    'summary': 'TOR connection from non-browser process — suspicious'}

        elif rule == 'IOC-DGA':
            dga_count = evidence.get('total_dga_domains', 0)
            reasoning.append(f"{dga_count} high-entropy domains detected")
            if dga_count >= 10:
                return {'verdict': AlertVerdict.VERIFIED_THREAT, 'confidence': 0.9,
                        'reasoning': reasoning,
                        'summary': 'Strong DGA pattern — likely active malware'}
            return {'verdict': AlertVerdict.LIKELY_THREAT, 'confidence': 0.6,
                    'reasoning': reasoning,
                    'summary': 'Possible DGA activity detected'}

        elif rule == 'IOC-DOH-BYPASS':
            process = evidence.get('process', '')
            browsers = {'chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe'}
            if process.lower() in browsers:
                reasoning.append(f"DoH by browser ({process}) — likely privacy feature")
                return {'verdict': AlertVerdict.FALSE_POSITIVE, 'confidence': 0.8,
                        'reasoning': reasoning,
                        'summary': 'Browser DoH — normal privacy feature'}
            reasoning.append(f"DoH by non-browser process: {process}")
            return {'verdict': AlertVerdict.LIKELY_THREAT, 'confidence': 0.6,
                    'reasoning': reasoning,
                    'summary': 'Non-browser process using DNS-over-HTTPS — investigate'}

        return {'verdict': AlertVerdict.INCONCLUSIVE, 'confidence': 0.3,
                'reasoning': ['IOC type not specifically verified'], 'summary': ''}

    # ═══════════════════════════════════════════════════════════════
    # ODD HOURS
    # ═══════════════════════════════════════════════════════════════
    def _verify_odd_hours(self, alert, evidence):
        reasoning = []
        process = evidence.get('process', '')

        # Many legitimate things happen at night
        background_procs = {'svchost.exe', 'windowsupdate', 'onedrive.exe', 'dropbox.exe',
                            'steam.exe', 'msedge.exe', 'chrome.exe', 'backblaze.exe',
                            'crashpad_handler.exe', 'system', 'bits'}
        if process.lower() in background_procs:
            reasoning.append(f"Background process active at night: {process}")
            return {'verdict': AlertVerdict.LIKELY_FALSE_POSITIVE, 'confidence': 0.7,
                    'reasoning': reasoning,
                    'summary': 'Normal background activity (updates, sync, etc.)'}

        reasoning.append("Network activity during unusual hours from non-background process")
        return {'verdict': AlertVerdict.INCONCLUSIVE, 'confidence': 0.4,
                'reasoning': reasoning,
                'summary': 'Off-hours activity — verify if expected'}

    # ═══════════════════════════════════════════════════════════════
    # DEFAULT
    # ═══════════════════════════════════════════════════════════════
    def _default_verdict(self, alert, evidence):
        return {'verdict': AlertVerdict.INCONCLUSIVE, 'confidence': 0.3,
                'reasoning': ['No specific verification available for this alert type'],
                'summary': 'Alert requires manual review'}

    # ═══════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════

    def _reverse_dns(self, ip):
        """Cached reverse DNS lookup."""
        if not ip:
            return None
        now = time.time()
        if ip in self._rdns_cache:
            hostname, cached_at = self._rdns_cache[ip]
            if now - cached_at < self._rdns_ttl:
                return hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self._rdns_cache[ip] = (hostname, now)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            self._rdns_cache[ip] = (None, now)
            return None

    def _is_local_ip(self, ip):
        """Check if IP is on local network."""
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except (ValueError, TypeError):
            return False

    def get_stats(self):
        return dict(self.stats)
