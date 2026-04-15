"""
Process & Alert Verification Engine
=====================================
Automatically investigates flagged processes and connections to determine
whether an alert is a genuine threat or a false positive.

Verification checks:
1. Digital signature validation (Authenticode)
2. File location analysis (expected paths vs suspicious locations)
3. File hash computation + optional VirusTotal lookup
4. File metadata (creation date, size, company name)
5. Parent process chain validation
6. Known-good hash database (built over time)
7. Verdict: VERIFIED_SAFE, LIKELY_SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN

The goal: every alert should include a machine-generated assessment
so the user doesn't have to manually investigate each one.
"""

import os
import time
import hashlib
import logging
import subprocess
import json
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger("NetSentinel.Verify")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import urllib.request
    URLLIB_AVAILABLE = True
except ImportError:
    URLLIB_AVAILABLE = False


# ─── Verdict Levels ──────────────────────────────────────────────────────────

class Verdict:
    VERIFIED_SAFE = "VERIFIED_SAFE"     # Signed by known publisher + correct location
    LIKELY_SAFE = "LIKELY_SAFE"         # Some positive signals but not fully verified
    UNKNOWN = "UNKNOWN"                 # Can't determine — manual review needed
    SUSPICIOUS = "SUSPICIOUS"           # Multiple concerning signals
    MALICIOUS = "MALICIOUS"             # VirusTotal hit or strong malware indicators


# ─── Known Safe Publishers (Authenticode signers) ────────────────────────────

TRUSTED_PUBLISHERS = {
    'microsoft corporation', 'microsoft windows',
    'google llc', 'google inc',
    'apple inc',
    'mozilla corporation',
    'adobe inc', 'adobe systems incorporated',
    'valve corp', 'valve',
    'discord inc',
    'slack technologies',
    'zoom video communications',
    'spotify ab',
    'intel corporation', 'intel(r) corporation',
    'nvidia corporation',
    'advanced micro devices', 'amd',
    'logitech', 'logitech inc',
    'realtek semiconductor',
    'eset, spol. s r.o.', 'eset',
    'malwarebytes inc',
    'norton lifelock', 'symantec corporation',
    'crowdstrike inc',
    'dell inc', 'dell technologies',
    'hp inc', 'hewlett-packard',
    'lenovo',
    'oracle corporation',
    'dropbox inc',
    'github inc',
    'brave software inc',
    'opera software',
    'epic games inc',
    'riot games',
    'electronic arts',
    'ubisoft',
    'blizzard entertainment',
    'cloudflare inc',
}

# ─── Expected Process Locations ──────────────────────────────────────────────

SYSTEM_DIRS = {
    os.environ.get('SystemRoot', r'C:\Windows'),
    os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32'),
    os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'SysWOW64'),
    os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'SystemApps'),
}

PROGRAM_DIRS = {
    os.environ.get('ProgramFiles', r'C:\Program Files'),
    os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'),
    os.environ.get('ProgramW6432', r'C:\Program Files'),
}

# Suspicious locations where malware commonly hides
SUSPICIOUS_LOCATIONS = {
    'temp', 'tmp', 'appdata\\local\\temp',
    'downloads', 'recycle.bin', '$recycle.bin',
    'programdata',  # Sometimes legitimate, but malware uses it
    'public', 'users\\public',
}


class ProcessVerifier:
    """
    Verifies whether a process or file is legitimate.
    Called automatically when alerts are generated.
    """

    def __init__(self, config):
        self.config = config

        # Cache verified files: {filepath_lower: (verdict, details, timestamp)}
        self._cache = {}
        self._cache_ttl = 3600  # Cache for 1 hour
        self._cache_max = 5000

        # Known-good hashes (built over time from verified-safe files)
        from src.config import DB_DIR
        self._known_good_path = os.path.join(DB_DIR, "known_good_hashes.json")
        self._known_good = self._load_known_good()

        # VirusTotal API (free tier: 4 requests/min)
        self._vt_api_key = config.get('verification', 'virustotal_api_key', default='')
        self._vt_last_request = 0
        self._vt_min_interval = 15  # seconds between VT requests

        logger.info("Process Verifier initialized. Known-good hashes: %d",
                     len(self._known_good))

    def verify_process(self, process_name=None, pid=None, exe_path=None):
        """
        Verify whether a process is legitimate.

        Returns:
            dict with 'verdict', 'confidence', 'details', 'checks'
        """
        result = {
            'verdict': Verdict.UNKNOWN,
            'confidence': 0,
            'summary': '',
            'checks': {},
            'recommendation': '',
        }

        # Resolve process info
        if pid and PSUTIL_AVAILABLE:
            try:
                proc = psutil.Process(pid)
                if not exe_path:
                    exe_path = proc.exe()
                if not process_name:
                    process_name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        if not exe_path:
            result['summary'] = 'Could not determine executable path'
            result['recommendation'] = 'Unable to verify — process may have exited'
            return result

        # Check cache
        cache_key = exe_path.lower()
        if cache_key in self._cache:
            cached_verdict, cached_details, cached_time = self._cache[cache_key]
            if time.time() - cached_time < self._cache_ttl:
                return cached_details

        # Run verification checks
        checks = {}
        score = 0  # Positive = safe signals, negative = threat signals

        # 1. File existence
        if os.path.exists(exe_path):
            checks['file_exists'] = True
        else:
            checks['file_exists'] = False
            result['summary'] = f'Executable not found at {exe_path}'
            result['verdict'] = Verdict.SUSPICIOUS
            result['checks'] = checks
            return result

        # 2. Digital signature verification
        sig_result = self._check_signature(exe_path)
        checks['digital_signature'] = sig_result
        if sig_result.get('signed'):
            publisher = sig_result.get('publisher', '').lower()
            if any(trusted in publisher for trusted in TRUSTED_PUBLISHERS):
                score += 3  # Strong safe signal
                checks['trusted_publisher'] = True
            else:
                score += 1  # Signed but unknown publisher
                checks['trusted_publisher'] = False
        else:
            score -= 1  # Unsigned

        # 3. File location analysis
        loc_result = self._check_location(exe_path)
        checks['file_location'] = loc_result
        if loc_result.get('is_system_dir'):
            score += 2
        elif loc_result.get('is_program_dir'):
            score += 1
        elif loc_result.get('is_suspicious_dir'):
            score -= 2

        # 4. File metadata
        meta = self._get_file_metadata(exe_path)
        checks['file_metadata'] = meta

        # Recently created files in system dirs are suspicious
        if meta.get('age_days') is not None and meta['age_days'] < 1:
            if loc_result.get('is_system_dir'):
                score -= 2  # Very new file in system dir = suspicious
                checks['recently_created_in_system_dir'] = True

        # 5. File hash
        file_hash = self._compute_hash(exe_path)
        checks['sha256'] = file_hash

        # Check against known-good
        if file_hash and file_hash in self._known_good:
            score += 3
            checks['known_good_hash'] = True
        else:
            checks['known_good_hash'] = False

        # 6. VirusTotal lookup (if API key configured and not rate-limited)
        if file_hash and self._vt_api_key:
            vt_result = self._check_virustotal(file_hash)
            checks['virustotal'] = vt_result
            if vt_result.get('found'):
                detections = vt_result.get('detections', 0)
                total = vt_result.get('total', 0)
                if detections == 0:
                    score += 2
                elif detections <= 2:
                    score -= 1  # Low detection = possibly PUP
                elif detections <= 5:
                    score -= 3
                else:
                    score -= 5  # Many detections = definitely malicious

        # 7. Parent process check
        if pid and PSUTIL_AVAILABLE:
            parent_result = self._check_parent_process(pid)
            checks['parent_process'] = parent_result
            if parent_result.get('suspicious_parent'):
                score -= 2

        # ─── Determine verdict ────────────────────────────────────
        if score >= 4:
            result['verdict'] = Verdict.VERIFIED_SAFE
            result['summary'] = self._build_summary(checks, 'safe')
            result['recommendation'] = 'This process has been verified as legitimate. No action needed.'
        elif score >= 2:
            result['verdict'] = Verdict.LIKELY_SAFE
            result['summary'] = self._build_summary(checks, 'likely_safe')
            result['recommendation'] = 'This process appears legitimate but could not be fully verified.'
        elif score >= -1:
            result['verdict'] = Verdict.UNKNOWN
            result['summary'] = self._build_summary(checks, 'unknown')
            result['recommendation'] = ('Unable to fully verify this process. '
                'Check the executable path and digital signature manually.')
        elif score >= -3:
            result['verdict'] = Verdict.SUSPICIOUS
            result['summary'] = self._build_summary(checks, 'suspicious')
            result['recommendation'] = ('This process has suspicious characteristics. '
                'Investigate its origin, check VirusTotal manually, and consider '
                'running a full malware scan.')
        else:
            result['verdict'] = Verdict.MALICIOUS
            result['summary'] = self._build_summary(checks, 'malicious')
            result['recommendation'] = ('This process shows strong indicators of being malicious. '
                'Kill the process, quarantine the file, and run a full system scan immediately.')

        result['confidence'] = min(abs(score) / 5, 1.0)
        result['score'] = score
        result['checks'] = checks

        # Cache the result
        if len(self._cache) >= self._cache_max:
            oldest_key = min(self._cache, key=lambda k: self._cache[k][2])
            del self._cache[oldest_key]
        self._cache[cache_key] = (result['verdict'], result, time.time())

        # If verified safe, add to known-good for future
        if result['verdict'] == Verdict.VERIFIED_SAFE and file_hash:
            self._add_known_good(file_hash, exe_path)

        return result

    def verify_alert(self, alert):
        """
        Automatically verify an alert and enrich its evidence with the verdict.
        Modifies the alert's evidence dict in place.
        """
        evidence = alert.evidence or {}

        # Try to find process info from evidence
        exe_path = evidence.get('executable', '')
        pid = evidence.get('pid', 0)
        proc_name = evidence.get('process_name', '') or evidence.get('process', '')

        # Also check the 'process' field which many alerts use
        if not proc_name and not exe_path:
            proc_name = evidence.get('process', '')

        if not exe_path and not pid and proc_name == 'Unknown':
            evidence['verification'] = {
                'verdict': Verdict.UNKNOWN,
                'summary': 'No process information available to verify',
            }
            return

        verification = self.verify_process(
            process_name=proc_name,
            pid=pid if isinstance(pid, int) and pid > 0 else None,
            exe_path=exe_path if exe_path else None,
        )

        # Add verdict to evidence
        evidence['verification'] = {
            'verdict': verification['verdict'],
            'summary': verification['summary'],
            'confidence': f"{verification.get('confidence', 0):.0%}",
            'recommendation': verification['recommendation'],
        }

        # Add key check results
        checks = verification.get('checks', {})
        if checks.get('digital_signature', {}).get('signed'):
            evidence['verification']['signer'] = checks['digital_signature'].get('publisher', 'Unknown')
        if checks.get('sha256'):
            evidence['verification']['sha256'] = checks['sha256']
        if checks.get('virustotal', {}).get('found'):
            vt = checks['virustotal']
            evidence['verification']['virustotal'] = (
                f"{vt.get('detections', '?')}/{vt.get('total', '?')} engines detected"
            )

    # ─── Check Methods ────────────────────────────────────────────

    def _check_signature(self, exe_path):
        """Check Authenticode digital signature using PowerShell."""
        result = {'signed': False, 'publisher': '', 'valid': False}
        try:
            ps_cmd = (
                f'$sig = Get-AuthenticodeSignature -FilePath "{exe_path}"; '
                f'$sig | Select-Object Status, '
                f'@{{N="Publisher";E={{$_.SignerCertificate.Subject}}}} | '
                f'ConvertTo-Json'
            )
            proc = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_cmd],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            )
            if proc.returncode == 0 and proc.stdout.strip():
                data = json.loads(proc.stdout.strip())
                status = data.get('Status', 99)
                publisher_raw = data.get('Publisher', '')

                # Status 0 = Valid
                if status == 0:
                    result['signed'] = True
                    result['valid'] = True
                elif publisher_raw:
                    result['signed'] = True
                    result['valid'] = False

                # Extract CN from publisher subject
                if publisher_raw:
                    import re
                    cn_match = re.search(r'CN=([^,]+)', publisher_raw)
                    if cn_match:
                        result['publisher'] = cn_match.group(1).strip('"')
                    else:
                        result['publisher'] = publisher_raw[:100]
        except subprocess.TimeoutExpired:
            logger.debug("Signature check timed out for %s", exe_path)
        except Exception as e:
            logger.debug("Signature check error: %s", e)

        return result

    def _check_location(self, exe_path):
        """Analyze whether the file is in an expected location."""
        result = {
            'path': exe_path,
            'is_system_dir': False,
            'is_program_dir': False,
            'is_suspicious_dir': False,
            'is_user_dir': False,
        }

        path_lower = exe_path.lower()

        # Check system directories
        for sys_dir in SYSTEM_DIRS:
            if path_lower.startswith(sys_dir.lower()):
                result['is_system_dir'] = True
                break

        # Check program directories
        for prog_dir in PROGRAM_DIRS:
            if path_lower.startswith(prog_dir.lower()):
                result['is_program_dir'] = True
                break

        # Check suspicious locations
        for suspicious in SUSPICIOUS_LOCATIONS:
            if suspicious in path_lower:
                result['is_suspicious_dir'] = True
                result['suspicious_reason'] = f'File is in {suspicious} directory'
                break

        # User directory (AppData, etc.) — common for user-installed apps
        user_profile = os.environ.get('USERPROFILE', '').lower()
        if user_profile and path_lower.startswith(user_profile):
            result['is_user_dir'] = True

        return result

    def _get_file_metadata(self, exe_path):
        """Get file metadata: size, dates, etc."""
        result = {}
        try:
            stat = os.stat(exe_path)
            result['size_bytes'] = stat.st_size
            result['size_readable'] = self._format_size(stat.st_size)
            result['created'] = datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
            result['modified'] = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            result['age_days'] = (time.time() - stat.st_ctime) / 86400
        except Exception as e:
            logger.debug("Metadata error: %s", e)
        return result

    def _compute_hash(self, exe_path):
        """Compute SHA256 hash of a file."""
        try:
            h = hashlib.sha256()
            with open(exe_path, 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            logger.debug("Hash error: %s", e)
            return None

    def _check_virustotal(self, file_hash):
        """Check file hash against VirusTotal API (free tier)."""
        if not self._vt_api_key or not URLLIB_AVAILABLE:
            return {'checked': False, 'reason': 'No API key configured'}

        # Rate limiting
        now = time.time()
        if now - self._vt_last_request < self._vt_min_interval:
            return {'checked': False, 'reason': 'Rate limited'}

        try:
            self._vt_last_request = now
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            req = urllib.request.Request(url, headers={
                'x-apikey': self._vt_api_key,
                'User-Agent': 'NetSentinel/1.0',
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                stats = data.get('data', {}).get('attributes', {}).get(
                    'last_analysis_stats', {})
                result = {
                    'found': True,
                    'checked': True,
                    'detections': stats.get('malicious', 0) + stats.get('suspicious', 0),
                    'total': sum(stats.values()),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                }
                return result
        except urllib.request.HTTPError as e:
            if e.code == 404:
                return {'found': False, 'checked': True,
                        'note': 'File not in VirusTotal database (never submitted)'}
            return {'checked': False, 'reason': f'HTTP {e.code}'}
        except Exception as e:
            return {'checked': False, 'reason': str(e)}

    def _check_parent_process(self, pid):
        """Check the parent process chain for anomalies."""
        result = {'chain': [], 'suspicious_parent': False}
        try:
            proc = psutil.Process(pid)
            # Walk up the parent chain (max 10 levels)
            current = proc
            for _ in range(10):
                parent = current.parent()
                if parent is None:
                    break
                result['chain'].append({
                    'name': parent.name(),
                    'pid': parent.pid,
                    'exe': parent.exe() if hasattr(parent, 'exe') else '',
                })
                current = parent

            # Check for suspicious parent chains
            chain_names = [p['name'].lower() for p in result['chain']]

            # cmd.exe or powershell spawning system processes is suspicious
            if chain_names and chain_names[0] in ('cmd.exe', 'powershell.exe', 'pwsh.exe'):
                proc_name = proc.name().lower()
                if proc_name in ('svchost.exe', 'lsass.exe', 'csrss.exe'):
                    result['suspicious_parent'] = True
                    result['reason'] = (f'{proc.name()} launched by {chain_names[0]} — '
                                         f'system processes should be launched by services.exe')

            # wscript/cscript launching network-active processes
            if any(p in chain_names for p in ('wscript.exe', 'cscript.exe', 'mshta.exe')):
                result['suspicious_parent'] = True
                result['reason'] = 'Process launched by Windows scripting host — common malware technique'

        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            result['error'] = str(e)

        return result

    # ─── Known Good Database ────────────────────────────────────

    def _load_known_good(self):
        """Load known-good file hashes."""
        if os.path.exists(self._known_good_path):
            try:
                with open(self._known_good_path, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _add_known_good(self, file_hash, exe_path):
        """Add a verified-safe hash to the known-good database."""
        self._known_good[file_hash] = {
            'path': exe_path,
            'verified_at': time.time(),
        }
        try:
            with open(self._known_good_path, 'w') as f:
                json.dump(self._known_good, f, indent=1)
        except Exception as e:
            logger.debug("Failed to save known-good: %s", e)

    def _save_known_good(self):
        """Persist the known-good database."""
        try:
            with open(self._known_good_path, 'w') as f:
                json.dump(self._known_good, f, indent=1)
        except Exception:
            pass

    # ─── Helpers ────────────────────────────────────────────────

    @staticmethod
    def _format_size(size_bytes):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if abs(size_bytes) < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    def _build_summary(self, checks, verdict_type):
        """Build a human-readable summary of verification results."""
        parts = []
        sig = checks.get('digital_signature', {})
        loc = checks.get('file_location', {})

        if verdict_type == 'safe':
            if sig.get('signed') and sig.get('publisher'):
                parts.append(f"Digitally signed by {sig['publisher']}")
            if loc.get('is_system_dir'):
                parts.append("Located in Windows system directory")
            elif loc.get('is_program_dir'):
                parts.append("Located in Program Files")
            if checks.get('known_good_hash'):
                parts.append("Hash matches known-good database")
            vt = checks.get('virustotal', {})
            if vt.get('found') and vt.get('detections', 0) == 0:
                parts.append(f"VirusTotal: 0/{vt.get('total', '?')} detections")
            return ". ".join(parts) + "." if parts else "Verified safe."

        elif verdict_type == 'likely_safe':
            if sig.get('signed'):
                parts.append(f"Signed by {sig.get('publisher', 'unknown publisher')}")
            if loc.get('is_program_dir') or loc.get('is_user_dir'):
                parts.append("In expected location")
            return ". ".join(parts) + "." if parts else "Appears legitimate."

        elif verdict_type == 'suspicious':
            if not sig.get('signed'):
                parts.append("NOT digitally signed")
            if loc.get('is_suspicious_dir'):
                parts.append(f"In suspicious location: {loc.get('suspicious_reason', '')}")
            if checks.get('recently_created_in_system_dir'):
                parts.append("Recently created in system directory")
            parent = checks.get('parent_process', {})
            if parent.get('suspicious_parent'):
                parts.append(parent.get('reason', 'Unusual parent process'))
            vt = checks.get('virustotal', {})
            if vt.get('detections', 0) > 0:
                parts.append(f"VirusTotal: {vt['detections']}/{vt.get('total', '?')} detections")
            return ". ".join(parts) + "." if parts else "Multiple suspicious indicators."

        elif verdict_type == 'malicious':
            vt = checks.get('virustotal', {})
            if vt.get('detections', 0) > 5:
                parts.append(f"VirusTotal: {vt['detections']}/{vt.get('total', '?')} engines flagged as malicious")
            if not sig.get('signed'):
                parts.append("No digital signature")
            if loc.get('is_suspicious_dir'):
                parts.append(f"Running from suspicious location")
            return ". ".join(parts) + "." if parts else "Strong malware indicators detected."

        return "Unable to determine safety."

    def get_stats(self):
        return {
            'cached_verifications': len(self._cache),
            'known_good_hashes': len(self._known_good),
            'virustotal_configured': bool(self._vt_api_key),
        }
