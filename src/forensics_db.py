"""
Forensics Persistent Storage
==============================
Stores all forensics findings (credentials, insecure services, sensitive data)
to an encrypted database on disk so they can be searched and retrieved later.

Storage:
- credentials.enc     — encrypted credential store (AES-256 key derived from machine ID)
- services.json       — insecure service findings (not sensitive, plain JSON)
- sensitive_data.enc  — encrypted sensitive data findings
- forensics_log.json  — timeline of all findings (metadata only, no values)

The encryption key is derived from the machine's hostname + username + a salt,
so the data is only readable on the same machine by the same user. This isn't
meant to be military-grade encryption — it's to prevent casual exposure if
someone copies the files. The data was already plaintext on the network.
"""

import os
import json
import time
import hashlib
import logging
import getpass
import socket
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger("NetSentinel.ForensicsDB")

# Use Fernet (AES-128-CBC) from cryptography if available, otherwise basic XOR
try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def _derive_key():
    """
    Derive an encryption key from machine-specific data.
    This ties the encrypted data to this specific machine + user.
    """
    machine_id = f"{socket.gethostname()}:{getpass.getuser()}:NetSentinel_Forensics_v1"
    key_bytes = hashlib.sha256(machine_id.encode()).digest()
    if CRYPTO_AVAILABLE:
        # Fernet requires base64-encoded 32-byte key
        import base64
        return base64.urlsafe_b64encode(key_bytes)
    return key_bytes


def _encrypt(data_str, key):
    """Encrypt a string."""
    if CRYPTO_AVAILABLE:
        f = Fernet(key)
        return f.encrypt(data_str.encode('utf-8')).decode('utf-8')
    else:
        # Simple XOR fallback (not secure, but better than plaintext)
        data_bytes = data_str.encode('utf-8')
        key_bytes = key
        encrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data_bytes))
        import base64
        return base64.b64encode(encrypted).decode('utf-8')


def _decrypt(encrypted_str, key):
    """Decrypt a string."""
    if CRYPTO_AVAILABLE:
        f = Fernet(key)
        return f.decrypt(encrypted_str.encode('utf-8')).decode('utf-8')
    else:
        import base64
        encrypted_bytes = base64.b64decode(encrypted_str.encode('utf-8'))
        key_bytes = key
        decrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(encrypted_bytes))
        return decrypted.decode('utf-8')


class ForensicsDB:
    """
    Persistent storage for forensics findings.
    Credentials are encrypted; metadata is searchable in plaintext.
    """

    def __init__(self, config):
        from src.config import DB_DIR
        self.db_dir = os.path.join(DB_DIR, "forensics")
        os.makedirs(self.db_dir, exist_ok=True)

        self._key = _derive_key()

        # File paths
        self._creds_file = os.path.join(self.db_dir, "credentials.enc")
        self._services_file = os.path.join(self.db_dir, "services.json")
        self._sensitive_file = os.path.join(self.db_dir, "sensitive_data.enc")
        self._log_file = os.path.join(self.db_dir, "forensics_log.json")

        # Load existing data
        self._credentials = self._load_encrypted(self._creds_file)
        self._services = self._load_json(self._services_file)
        self._sensitive = self._load_encrypted(self._sensitive_file)
        self._log = self._load_json(self._log_file)

        logger.info("ForensicsDB initialized: %d credentials, %d services, %d sensitive items",
                     len(self._credentials), len(self._services), len(self._sensitive))

    # ─── Store Methods ────────────────────────────────────────

    def store_credential(self, protocol, cred_type, value_raw, value_masked,
                        src_ip, dst_ip, port, timestamp, extra=None):
        """
        Store a found credential. The raw value is encrypted on disk.
        The masked value is stored in the searchable log.
        """
        entry = {
            'id': hashlib.md5(f"{protocol}:{src_ip}:{dst_ip}:{port}:{time.time()}".encode()).hexdigest()[:12],
            'timestamp': timestamp,
            'time_str': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') if timestamp else '',
            'protocol': protocol,
            'credential_type': cred_type,
            'value_raw': value_raw,      # Full value (will be encrypted)
            'value_masked': value_masked, # Masked for display
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'port': port,
            'extra': extra or {},
        }

        # Check for duplicates (same protocol + IPs + port + value)
        dedup_key = f"{protocol}:{src_ip}:{dst_ip}:{port}:{value_raw}"
        for existing in self._credentials:
            existing_key = (f"{existing['protocol']}:{existing['source_ip']}:"
                          f"{existing['destination_ip']}:{existing['port']}:"
                          f"{existing.get('value_raw', '')}")
            if existing_key == dedup_key:
                # Update timestamp only
                existing['timestamp'] = timestamp
                existing['time_str'] = entry['time_str']
                self._save_encrypted(self._creds_file, self._credentials)
                return False  # Not new

        self._credentials.append(entry)
        self._save_encrypted(self._creds_file, self._credentials)

        # Also log metadata (no raw value)
        self._add_log('credential', {
            'protocol': protocol,
            'credential_type': cred_type,
            'value_masked': value_masked,
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'port': port,
        }, timestamp)

        return True  # New credential

    def store_service(self, ip, port, service_name, risk, description, details=None):
        """Store an insecure service finding."""
        key = f"{ip}:{port}"
        if key in {f"{s['ip']}:{s['port']}" for s in self._services}:
            # Update packet count
            for s in self._services:
                if f"{s['ip']}:{s['port']}" == key:
                    s['last_seen'] = time.time()
                    s['seen_count'] = s.get('seen_count', 0) + 1
                    break
        else:
            self._services.append({
                'ip': ip,
                'port': port,
                'service': service_name,
                'risk': risk,
                'description': description,
                'details': details or {},
                'first_seen': time.time(),
                'last_seen': time.time(),
                'seen_count': 1,
            })

        self._save_json(self._services_file, self._services)

    def store_sensitive_data(self, data_type, value, src_ip, dst_ip, port, timestamp, risk='HIGH'):
        """Store sensitive data finding (encrypted)."""
        entry = {
            'timestamp': timestamp,
            'time_str': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') if timestamp else '',
            'data_type': data_type,
            'value': value,
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'port': port,
            'risk': risk,
        }
        self._sensitive.append(entry)
        self._save_encrypted(self._sensitive_file, self._sensitive)

        self._add_log('sensitive_data', {
            'data_type': data_type,
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'port': port,
        }, timestamp)

    # ─── Search Methods ───────────────────────────────────────

    def search_credentials(self, query=None, protocol=None, ip=None, port=None):
        """
        Search stored credentials.
        Returns entries with MASKED values. Use get_credential_raw() for full value.
        """
        results = []
        for cred in self._credentials:
            if protocol and cred['protocol'].lower() != protocol.lower():
                continue
            if ip and ip not in (cred['source_ip'], cred['destination_ip']):
                continue
            if port and cred['port'] != port:
                continue
            if query:
                q = query.lower()
                searchable = (f"{cred['protocol']} {cred['credential_type']} "
                             f"{cred['source_ip']} {cred['destination_ip']} "
                             f"{cred.get('extra', {})}").lower()
                if q not in searchable:
                    continue

            # Return with masked value (safe for display)
            safe_entry = dict(cred)
            safe_entry['value'] = cred['value_masked']
            del safe_entry['value_raw']
            results.append(safe_entry)

        return results

    def get_credential_raw(self, credential_id):
        """
        Get the full unmasked value of a specific credential by ID.
        Use sparingly — this returns the actual password/token.
        """
        for cred in self._credentials:
            if cred.get('id') == credential_id:
                return cred.get('value_raw', '')
        return None

    def get_all_services(self):
        """Get all discovered insecure services."""
        return list(self._services)

    def get_all_sensitive(self):
        """Get all sensitive data findings."""
        return list(self._sensitive)

    def get_log(self, limit=100, finding_type=None):
        """Get the forensics log (most recent first)."""
        entries = self._log
        if finding_type:
            entries = [e for e in entries if e.get('type') == finding_type]
        return sorted(entries, key=lambda e: e.get('timestamp', 0), reverse=True)[:limit]

    def get_stats(self):
        """Get forensics database statistics."""
        return {
            'total_credentials': len(self._credentials),
            'total_services': len(self._services),
            'total_sensitive': len(self._sensitive),
            'total_log_entries': len(self._log),
            'protocols_seen': list(set(c['protocol'] for c in self._credentials)),
            'db_dir': self.db_dir,
            'encrypted': CRYPTO_AVAILABLE,
        }

    def clear_all(self):
        """Clear all forensics data."""
        self._credentials = []
        self._services = []
        self._sensitive = []
        self._log = []
        self._save_encrypted(self._creds_file, [])
        self._save_json(self._services_file, [])
        self._save_encrypted(self._sensitive_file, [])
        self._save_json(self._log_file, [])
        logger.info("Forensics database cleared.")

    # ─── Internal ─────────────────────────────────────────────

    def _add_log(self, finding_type, metadata, timestamp):
        """Add entry to the forensics log."""
        self._log.append({
            'timestamp': timestamp,
            'time_str': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') if timestamp else '',
            'type': finding_type,
            'metadata': metadata,
        })
        # Cap log at 10,000 entries
        if len(self._log) > 10000:
            self._log = self._log[-5000:]
        self._save_json(self._log_file, self._log)

    def _save_encrypted(self, filepath, data):
        """Save data as encrypted JSON."""
        try:
            json_str = json.dumps(data, default=str)
            encrypted = _encrypt(json_str, self._key)
            with open(filepath, 'w') as f:
                f.write(encrypted)
        except Exception as e:
            logger.error("Failed to save encrypted data: %s", e)

    def _load_encrypted(self, filepath):
        """Load encrypted JSON data."""
        if not os.path.exists(filepath):
            return []
        try:
            with open(filepath, 'r') as f:
                encrypted = f.read()
            json_str = _decrypt(encrypted, self._key)
            return json.loads(json_str)
        except Exception as e:
            logger.warning("Failed to load encrypted data from %s: %s", filepath, e)
            return []

    def _save_json(self, filepath, data):
        """Save data as plain JSON."""
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=1, default=str)
        except Exception as e:
            logger.error("Failed to save JSON: %s", e)

    def _load_json(self, filepath):
        """Load plain JSON data."""
        if not os.path.exists(filepath):
            return []
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception:
            return []
