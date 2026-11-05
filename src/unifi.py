"""
UniFi: what the owner's console calls the devices NetSentinel sees.
====================================================================
Opt-in and read only. NetSentinel knows an address and the maker of a MAC; the
UniFi console knows "Office 3D Printer". This asks the console's Network
Integration API (UniFi Network 9 and later) for its clients every few minutes
and keeps their names in memory, for the Devices page, alerts and the Threat
data page.

- Read only: GET requests to the sites and clients endpoints and nothing else.
  The same API writes firewall policies, ACL and DNS rules; NetSentinel never
  calls those (CLAUDE.md: no automatic firewall changes).
- The key is made by the owner in UniFi (Integrations) and typed into
  Settings. It goes in a header to the console on this network, nowhere else,
  and never into a log line or an error message.
- The console's certificate is usually self-signed. Its SHA-256 is pinned on
  the first successful connection (unifi.cert_sha256), and a different
  certificate is refused after that.
- Only a console at a private address is asked: client names hold people's
  names, and so does the key's reach.
"""

import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import socket
import ssl
import threading
import time
from urllib.parse import quote

from src.config import as_int

logger = logging.getLogger("NetSentinel.UniFi")

API = '/proxy/network/integration/v1'
PAGE = 200                  # the API's largest page
MAX_CLIENTS = 5000
TIMEOUT_SEC = 15


class CertificateChanged(Exception):
    """The console presented a certificate other than the pinned one."""


class UnifiError(Exception):
    """A failure to say on the Threat data page. Never carries the key."""


def private_host(host):
    """Whether every address the host has is private. Names are resolved."""
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(info[4][0].split('%')[0])
                         for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)]
        except (OSError, ValueError):
            return False
    return bool(addresses) and all(a.is_private and not a.is_loopback for a in addresses)


def https_get(host, path, api_key, pin='', timeout=TIMEOUT_SEC):
    """
    One GET to the console: (status, body bytes, certificate SHA-256 hex).

    Consoles sign their own certificates, so the check is the caller's pin, and it
    is made after the handshake and before the request. The key went out first
    before, and a host on the LAN that answered for the console's address got it
    every refresh; the key can change firewall rules, not just read clients.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection(host, 443, timeout=timeout, context=context)
    try:
        connection.connect()                # the handshake only: nothing is sent yet
        connection.auto_open = 0            # and no silent reconnect past the check
        der = connection.sock.getpeercert(binary_form=True) if connection.sock else None
        if not der:
            raise UnifiError('The console presented no certificate.')
        fingerprint = hashlib.sha256(der).hexdigest()
        if pin and not hmac.compare_digest(fingerprint, pin):
            raise CertificateChanged()
        connection.request('GET', path, headers={'X-API-KEY': api_key, 'Accept': 'application/json',
                                                 'User-Agent': 'NetSentinel'})
        response = connection.getresponse()
        body = response.read(32 * 1024 * 1024 + 1)
        return response.status, body, fingerprint
    finally:
        connection.close()


class UnifiInventory:
    """The console's clients, refreshed in the background, looked up by IP or MAC."""

    def __init__(self, config, fetch=None, clock=time.time):
        self.config = config
        get = config.get
        self.enabled = bool(get('unifi', 'enabled', default=False))
        self.host = str(get('unifi', 'host', default='') or '').strip()
        self.site = str(get('unifi', 'site', default='default') or 'default').strip()
        self._key = str(get('unifi', 'api_key', default='') or '').strip()
        self.pin = str(get('unifi', 'cert_sha256', default='') or '').strip().lower()
        self.refresh_sec = 60 * as_int(get('unifi', 'refresh_minutes', default=5), 5,
                                       lo=1, hi=24 * 60, name='unifi.refresh_minutes')
        self._fetch = fetch or https_get
        self._clock = clock
        self._lock = threading.Lock()
        self._by_ip, self._by_mac = {}, {}
        self._macs = {}           # client id -> MAC, from the detail call, kept
        self.updated = None
        self.error = ''
        self.site_name = ''
        self._stop = threading.Event()
        self._thread = None

    # ─── Lookups ────────────────────────────────────────────────────────────

    def name_for(self, ip=None, mac=None):
        """The console's name for a device, or None."""
        with self._lock:
            client = (self._by_mac.get((mac or '').lower()) if mac else None) or \
                     (self._by_ip.get(ip) if ip else None)
        return client['name'] if client and client.get('name') else None

    def client_for(self, ip=None, mac=None):
        with self._lock:
            client = (self._by_mac.get((mac or '').lower()) if mac else None) or \
                     (self._by_ip.get(ip) if ip else None)
        return dict(client) if client else None

    @property
    def count(self):
        return len(self._by_ip)

    # ─── Refresh ────────────────────────────────────────────────────────────

    def refresh(self):
        """Read the clients once. True on success; the reason is in .error if not."""
        if not (self.enabled and self.host and self._key):
            return False
        try:
            if not private_host(self.host):
                raise UnifiError('The console must be at a private address on this network.')
            site_id = self._site_id()
            clients = self._clients(site_id)
        except CertificateChanged:
            self.error = ("The console's certificate changed. If you replaced it, clear "
                          "unifi.cert_sha256 in config.json to trust the new one.")
            logger.warning("UniFi console certificate changed; not trusted.")
            return False
        except UnifiError as e:
            self.error = str(e)
            logger.warning("UniFi: %s", self.error)
            return False
        except (OSError, ValueError, http.client.HTTPException) as e:
            # The type only: an exception's text could echo a request.
            self.error = f'The console could not be read ({type(e).__name__}).'
            logger.warning("UniFi: %s", self.error)
            return False
        by_ip, by_mac = {}, {}
        for c in clients:
            if c.get('ip'):
                by_ip[c['ip']] = c
            if c.get('mac'):
                by_mac[c['mac']] = c
        with self._lock:
            self._by_ip, self._by_mac = by_ip, by_mac
        self.updated = self._clock()
        self.error = ''
        return True

    def _get(self, path):
        status, body, fingerprint = self._fetch(self.host, path, self._key, self.pin)
        if not self.pin:
            self.pin = fingerprint
            self.config.set('unifi', 'cert_sha256', fingerprint)   # trust on first use
        elif fingerprint != self.pin:
            raise CertificateChanged()
        if status in (401, 403):
            raise UnifiError('The console refused the API key: check it in Settings.')
        if status != 200:
            raise UnifiError(f'The console answered HTTP {status}.')
        return json.loads(body)

    def _site_id(self):
        sites = self._get(f'{API}/sites?limit={PAGE}').get('data') or []
        wanted = self.site.lower()
        for s in sites:
            if wanted in (str(s.get('internalReference', '')).lower(), str(s.get('name', '')).lower()):
                self.site_name = str(s.get('name', '')) or self.site
                return s['id']
        if len(sites) == 1:
            self.site_name = str(sites[0].get('name', ''))
            return sites[0]['id']
        raise UnifiError(f'No site named "{self.site}" on the console.')

    def _clients(self, site_id):
        site = quote(str(site_id), safe='')
        out, offset, total = [], 0, None
        while (total is None or offset < total) and offset < MAX_CLIENTS:
            page = self._get(f'{API}/sites/{site}/clients?offset={offset}&limit={PAGE}')
            batch = page.get('data') or []
            total = int(page.get('totalCount', len(batch)))
            for raw in batch:
                out.append(self._client(site, raw))
            if not batch:
                break
            offset += len(batch)
        return out

    def _client(self, site, raw):
        client_id = str(raw.get('id', ''))
        mac = str(raw.get('macAddress') or self._macs.get(client_id) or '').lower()
        if not mac and client_id:
            # The list leaves the MAC out on some versions; the detail has it.
            try:
                detail = self._get(f'{API}/sites/{site}/clients/{quote(client_id, safe="")}')
                mac = str(detail.get('macAddress') or '').lower()
            except UnifiError:
                mac = ''
            self._macs[client_id] = mac
        return {'name': str(raw.get('name') or '')[:80], 'ip': str(raw.get('ipAddress') or ''),
                'mac': mac, 'connection': str(raw.get('type') or '').lower(),
                'connected_at': str(raw.get('connectedAt') or '')}

    # ─── Background ─────────────────────────────────────────────────────────

    def start(self):
        if not self.enabled or self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name='UniFi')
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while True:
            try:
                self.refresh()
            except Exception as e:
                logger.debug("UniFi refresh error: %s", type(e).__name__)
            if self._stop.wait(self.refresh_sec):
                return

    # ─── Status, for the Threat data page ───────────────────────────────────

    def status(self):
        row = {'name': 'unifi', 'description': 'UniFi console - Names of the devices on this network',
               'category': 'Device names', 'updated': self.updated, 'entries': 0,
               'refresh_hours': self.refresh_sec / 3600}
        if not self.enabled:
            return dict(row, state='off', note='Off in settings (unifi.enabled).')
        if not (self.host and self._key):
            return dict(row, state='needs key', note='Needs the console address and an API key: '
                                                     'Settings → UniFi.')
        if self.error:
            return dict(row, state='failed', note=self.error)
        if self.updated is None:
            return dict(row, state='waiting', note='Not read yet.')
        return dict(row, state='ok', entries=self.count,
                    note=f'Site {self.site_name or self.site} on {self.host}. Read only.')


_shared = None
_shared_lock = threading.Lock()


def get_inventory(config=None):
    """The process's one inventory (off unless configured)."""
    global _shared
    with _shared_lock:
        if _shared is None:
            if config is None:
                from src.config import Config
                config = Config().load()
            _shared = UnifiInventory(config)
        return _shared
