"""
Forensics Persistent Storage
==============================
Stores forensics findings (credentials, insecure services, sensitive data)
on disk so they can be searched and retrieved later.

Storage:
- credentials.enc     — encrypted credential store
- services.json       — insecure service findings (not sensitive, plain JSON)
- sensitive_data.enc  — encrypted sensitive data findings
- forensics_log.json  — timeline of findings (metadata only, no credential material)

SECURITY MODEL — read this before trusting the vault
-----------------------------------------------------
Encryption uses Fernet, which is **AES-128-CBC + HMAC-SHA256**. It is not AES-256;
earlier versions of this file and the README claimed otherwise.

By default the key is derived from machine-specific data (hostname + username).
That is *obfuscation, not confidentiality*: anyone who obtains the file can
usually also determine the hostname and username, and can then reproduce the key.
It only protects against casual inspection of a copied file.

For real confidentiality, set a passphrase:

    config.json -> {"forensics": {"vault_passphrase": "..."}}

which switches key derivation to scrypt (n=2**15, r=8, p=1) over a random salt
stored in vault_salt.bin. Without the passphrase the vault cannot be opened.

By default NetSentinel now stores only MASKED credential values. Set
forensics.store_raw_credentials=true to retain full plaintext secrets; think
carefully before doing so, especially without a passphrase.

Files are created 0600 and the directory 0700 where the platform supports it.
"""

import os
import base64
import json
import stat
import time
import hashlib
import logging
import getpass
import socket
from datetime import datetime
import threading

logger = logging.getLogger("NetSentinel.ForensicsDB")

# Fernet = AES-128-CBC + HMAC-SHA256. Required, not optional: there is no
# home-grown fallback, because the previous XOR fallback offered no protection
# at all against anyone holding the file.
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover - dependency is declared in requirements.txt
    Fernet = None
    InvalidToken = Exception
    Scrypt = None
    CRYPTO_AVAILABLE = False


# Named so the value is obvious at the call site instead of being a bare bool.
KEY_SOURCE_PASSPHRASE = 'passphrase(scrypt)'
KEY_SOURCE_MACHINE = 'machine-derived(obfuscation only)'


def _secure_file(path):
    """Restrict a file to the current user. Best-effort on platforms without POSIX modes."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError as e:
        logger.debug("Could not restrict permissions on %s: %s", path, e)


def _secure_dir(path):
    """Restrict a directory to the current user."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)  # 0700
    except OSError as e:
        logger.debug("Could not restrict permissions on %s: %s", path, e)


def _atomic_write(path, text, secure=True):
    """Write a file atomically so an interrupted write cannot truncate the original."""
    tmp = f"{path}.tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    if secure:
        _secure_file(tmp)
    os.replace(tmp, path)


def _derive_key(passphrase=None, salt_path=None):
    """
    Derive the vault key.

    With a passphrase: scrypt over a persisted random salt. This is a real KDF and
    the vault is genuinely confidential without the passphrase.

    Without one: SHA-256 over hostname + username. This ties the file to the machine
    but is NOT secret — see the module docstring. Returns (key, source_label).
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError(
            "The 'cryptography' package is required for the forensics vault. "
            "Install it with: pip install cryptography"
        )

    if passphrase:
        salt = _load_or_create_salt(salt_path)
        kdf = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1)
        key_bytes = kdf.derive(passphrase.encode('utf-8'))
        return base64.urlsafe_b64encode(key_bytes), KEY_SOURCE_PASSPHRASE

    machine_id = f"{socket.gethostname()}:{getpass.getuser()}:NetSentinel_Forensics_v1"
    key_bytes = hashlib.sha256(machine_id.encode()).digest()
    return base64.urlsafe_b64encode(key_bytes), KEY_SOURCE_MACHINE


def _load_or_create_salt(salt_path):
    """Load the scrypt salt, creating a random one on first use."""
    if salt_path and os.path.exists(salt_path):
        with open(salt_path, 'rb') as f:
            salt = f.read()
        if len(salt) == 16:
            return salt
        logger.warning("Vault salt at %s is malformed; regenerating.", salt_path)
    salt = os.urandom(16)
    if salt_path:
        with open(salt_path, 'wb') as f:
            f.write(salt)
        _secure_file(salt_path)
    return salt


def _encrypt(data_str, key):
    """Encrypt a string with Fernet (AES-128-CBC + HMAC-SHA256)."""
    return Fernet(key).encrypt(data_str.encode('utf-8')).decode('utf-8')


def _decrypt(encrypted_str, key):
    """Decrypt a Fernet token."""
    return Fernet(key).decrypt(encrypted_str.encode('utf-8')).decode('utf-8')


class ForensicsDB:
    """
    Persistent storage for forensics findings.
    Credentials are encrypted; metadata is searchable in plaintext.
    """

    def __init__(self, config):
        from src.config import DB_DIR
        self.config = config
        self.db_dir = os.path.join(DB_DIR, "forensics")
        os.makedirs(self.db_dir, exist_ok=True)
        _secure_dir(self.db_dir)

        # Storage policy — both previously existed in config but were never consulted.
        self.save_credentials = config.get('forensics', 'save_credentials', default=True)
        self.store_raw = config.get('forensics', 'store_raw_credentials', default=False)
        self.retention_days = config.get('forensics', 'retention_days', default=365)

        self._salt_file = os.path.join(self.db_dir, "vault_salt.bin")
        passphrase = config.get('forensics', 'vault_passphrase', default='') or None
        self._key, self.key_source = _derive_key(passphrase, self._salt_file)

        # File paths
        self._creds_file = os.path.join(self.db_dir, "credentials.enc")
        self._services_file = os.path.join(self.db_dir, "services.json")
        self._sensitive_file = os.path.join(self.db_dir, "sensitive_data.enc")
        self._log_file = os.path.join(self.db_dir, "forensics_log.json")

        # Guards every mutation; store_* runs on the packet worker while the GUI searches.
        self._lock = threading.RLock()

        # Set by _load_encrypted when a file exists but will not decrypt. While true we
        # refuse to write, so a key mismatch cannot destroy recoverable data.
        self._read_only = False

        # Set when a duplicate only refreshed an in-memory timestamp. flush() persists
        # those lazily instead of re-encrypting the whole vault on every repeat packet.
        self._dirty_creds = False

        # Load existing data
        self._credentials = self._load_encrypted(self._creds_file)
        self._services = self._load_json(self._services_file)
        self._sensitive = self._load_encrypted(self._sensitive_file)
        self._log = self._load_json(self._log_file)

        # Index for O(1) duplicate detection instead of scanning every stored credential
        self._cred_index = {self._dedup_key(c): c for c in self._credentials}
        self._service_index = {f"{s['ip']}:{s['port']}": s for s in self._services}

        removed = self._enforce_retention()

        logger.info(
            "ForensicsDB initialized: %d credentials, %d services, %d sensitive items "
            "(key: %s, raw values: %s, retention: %sd%s)",
            len(self._credentials), len(self._services), len(self._sensitive),
            self.key_source, "stored" if self.store_raw else "masked only",
            self.retention_days, f", pruned {removed}" if removed else "",
        )

    @staticmethod
    def _dedup_key(entry):
        """Identity of a credential finding for duplicate detection."""
        return (entry.get('protocol', ''), entry.get('source_ip', ''),
                entry.get('destination_ip', ''), entry.get('port', 0),
                entry.get('value_raw', '') or entry.get('value_masked', ''))

    def _enforce_retention(self):
        """Drop findings older than forensics.retention_days. Returns the number removed."""
        if not self.retention_days or self.retention_days <= 0:
            return 0
        cutoff = time.time() - (self.retention_days * 86400)
        before = len(self._credentials) + len(self._sensitive) + len(self._log)

        with self._lock:
            self._credentials = [c for c in self._credentials
                                 if c.get('timestamp', 0) >= cutoff]
            self._sensitive = [s for s in self._sensitive
                               if s.get('timestamp', 0) >= cutoff]
            self._services = [s for s in self._services
                              if s.get('last_seen', 0) >= cutoff]
            self._log = [e for e in self._log if e.get('timestamp', 0) >= cutoff]
            removed = before - (len(self._credentials) + len(self._sensitive) + len(self._log))
            if removed:
                self._cred_index = {self._dedup_key(c): c for c in self._credentials}
                self._service_index = {f"{s['ip']}:{s['port']}": s for s in self._services}
                self._save_encrypted(self._creds_file, self._credentials)
                self._save_encrypted(self._sensitive_file, self._sensitive)
                self._save_json(self._services_file, self._services)
                self._save_json(self._log_file, self._log)
        return removed

    # ─── Store Methods ────────────────────────────────────────

    def store_credential(self, protocol, cred_type, value_raw, value_masked,
                        src_ip, dst_ip, port, timestamp, extra=None):
        """
        Store a found credential.

        By default only the MASKED value is persisted. The full secret is kept only
        when forensics.store_raw_credentials is explicitly enabled — writing captured
        passwords to disk should be an opt-in, not a default.

        Returns True if this is a new finding, False if it was already known.
        """
        if not self.save_credentials:
            return False

        entry = {
            'id': hashlib.sha256(
                f"{protocol}:{src_ip}:{dst_ip}:{port}:{time.time()}".encode()
            ).hexdigest()[:12],
            'timestamp': timestamp,
            'time_str': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S') if timestamp else '',
            'protocol': protocol,
            'credential_type': cred_type,
            'value_raw': value_raw if self.store_raw else '',
            'value_masked': value_masked,
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'port': port,
            'extra': extra or {},
        }

        with self._lock:
            key = self._dedup_key(entry)
            existing = self._cred_index.get(key)
            if existing is not None:
                # Already known — refresh the timestamp in memory only. Rewriting the
                # whole encrypted vault here used to happen once per duplicate packet.
                existing['timestamp'] = timestamp
                existing['time_str'] = entry['time_str']
                self._dirty_creds = True
                return False

            self._credentials.append(entry)
            self._cred_index[key] = entry
            self._save_encrypted(self._creds_file, self._credentials)

        # Log metadata only. No credential material — not even the masked value,
        # because _mask() reveals the leading characters of short secrets.
        self._add_log('credential', {
            'protocol': protocol,
            'credential_type': cred_type,
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'port': port,
        }, timestamp)

        return True

    def store_service(self, ip, port, service_name, risk, description, details=None):
        """Store an insecure service finding."""
        key = f"{ip}:{port}"
        with self._lock:
            existing = self._service_index.get(key)
            if existing is not None:
                existing['last_seen'] = time.time()
                existing['seen_count'] = existing.get('seen_count', 0) + 1
            else:
                entry = {
                    'ip': ip,
                    'port': port,
                    'service': service_name,
                    'risk': risk,
                    'description': description,
                    'details': details or {},
                    'first_seen': time.time(),
                    'last_seen': time.time(),
                    'seen_count': 1,
                }
                self._services.append(entry)
                self._service_index[key] = entry
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
        with self._lock:
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
            safe_entry.pop('value_raw', None)
            results.append(safe_entry)

        return results

    def get_credential_raw(self, credential_id):
        """
        Get the full unmasked value of a specific credential by ID.

        Returns None when raw storage is disabled (the default) — in that case the
        secret was never written to disk and cannot be recovered, by design.
        """
        with self._lock:
            for cred in self._credentials:
                if cred.get('id') == credential_id:
                    return cred.get('value_raw') or None
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
            'cipher': 'Fernet (AES-128-CBC + HMAC-SHA256)',
            'key_source': self.key_source,
            'raw_values_stored': self.store_raw,
            'retention_days': self.retention_days,
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

    def flush(self):
        """Persist deferred in-memory updates. Called on shutdown."""
        with self._lock:
            if self._dirty_creds:
                self._save_encrypted(self._creds_file, self._credentials)
                self._dirty_creds = False

    def _add_log(self, finding_type, metadata, timestamp):
        """Add entry to the forensics log. Metadata only — never credential material."""
        with self._lock:
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
        """Save data as encrypted JSON, atomically and owner-only."""
        if self._read_only:
            logger.debug("Vault is read-only (key mismatch); skipping write to %s", filepath)
            return
        try:
            json_str = json.dumps(data, default=str)
            _atomic_write(filepath, _encrypt(json_str, self._key))
        except Exception as e:
            logger.error("Failed to save encrypted data: %s", e)

    def _load_encrypted(self, filepath):
        """Load encrypted JSON data."""
        if not os.path.exists(filepath):
            return []
        try:
            with open(filepath, encoding='utf-8') as f:
                encrypted = f.read()
            return json.loads(_decrypt(encrypted, self._key))
        except InvalidToken:
            # Wrong key: a changed hostname/username, or a passphrase that was added,
            # removed or mistyped. Refusing loudly beats silently starting empty and
            # then overwriting the user's data on the next save.
            logger.error(
                "Cannot decrypt %s with the current key (source: %s). The file is NOT "
                "being overwritten. If you set or changed forensics.vault_passphrase, "
                "restore the old value; otherwise move the file aside to start fresh.",
                filepath, self.key_source,
            )
            self._read_only = True
            return []
        except Exception as e:
            logger.warning("Failed to load encrypted data from %s: %s", filepath, e)
            return []

    def _save_json(self, filepath, data):
        """Save data as plain JSON, atomically."""
        if self._read_only:
            return
        try:
            _atomic_write(filepath, json.dumps(data, indent=1, default=str))
        except Exception as e:
            logger.error("Failed to save JSON: %s", e)

    def _load_json(self, filepath):
        """Load plain JSON data."""
        if not os.path.exists(filepath):
            return []
        try:
            with open(filepath) as f:
                return json.load(f)
        except Exception:
            return []
