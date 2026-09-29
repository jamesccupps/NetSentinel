"""
Bootstrapping a profile from the UniFi controller.
===================================================
The profile is the hardest part of setting this up by hand — a dozen VLANs and
however many devices, each needing a MAC, an address and a role. The controller
already knows most of it.

    python -m netmon.sources.unifi_api --host https://unifi.example \
        --fingerprint AA:BB:... --out ~/.config/netmon/my-site.yaml

It writes a profile you then edit: roles, expected flows and which segments are
metadata-only are judgements the controller cannot make. What it saves is the
typing, and the typing is where the mistakes are.

Read-only, structurally
-----------------------
The client class has one method, `get`. There is no post, put or delete to call
by accident, and a future edit that wanted one would have to add it deliberately
rather than pass a different argument. The site's UniFi account should be
view-only as well — this is the second lock, not the first.

Self-signed certificates
------------------------
A UniFi gateway on your own network almost certainly presents a self-signed
certificate, and the usual advice is to turn verification off. That converts
"this is the controller" into "this is whatever answered", on the one connection
that is about to hand over an API key.

So: pin it. `--fingerprint` takes the certificate's SHA-256 and checks it on
every connection, which is stronger than a public CA would give you here and
takes one command to obtain. `--ca` takes a bundle if you run your own CA.
`--insecure` exists, prints what it is giving up, and is not the default.

Merging
-------
A re-sync keeps what you wrote. Names, roles, notes and everything the
controller does not know are preserved per device; new devices are added,
missing ones are marked rather than deleted, and the run says what changed.
A sync that clobbered hand-written roles would be run exactly once.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger("netmon.sources.unifi_api")

__all__ = ['UnifiClient', 'UnifiApiError', 'fetch_inventory', 'build_profile',
           'merge_profile', 'certificate_fingerprint']


class UnifiApiError(RuntimeError):
    """The controller could not be reached or did not answer as expected."""


#: Names the controller reports that are not really device names.
_PLACEHOLDER_NAMES = frozenset({'', 'unknown', 'n/a', 'null', 'none'})

#: What a UniFi device type maps to as a netmon role. A starting point: the
#: controller knows what a device *is*, not what it is *for*, and the difference
#: is the whole point of roles. Everything it cannot place becomes 'unknown',
#: which is honest.
_ROLE_BY_TYPE = {
    'ugw': 'network_device', 'uxg': 'network_device', 'udm': 'network_device',
    'usw': 'network_device', 'uap': 'network_device', 'usg': 'network_device',
    'ubb': 'network_device', 'uck': 'network_device',
}

#: Rough guesses from a client's own hostname. Deliberately few: a wrong role is
#: worse than none, because rules act on it.
_ROLE_HINTS = (
    (re.compile(r'\b(cam|camera|axis|hikvision|dahua)\b', re.I), 'camera'),
    (re.compile(r'\b(nvr|protect|recorder|exacq)\b', re.I), 'recorder'),
    (re.compile(r'\b(bms|bas|trane|siemens|jci|honeywell)\b', re.I),
     'automation_server'),
    (re.compile(r'\b(ahu|vav|chiller|boiler|rtu|controller)\b', re.I), 'controller'),
    (re.compile(r'\b(door|access|reader|gallagher)\b', re.I), 'door_controller'),
    (re.compile(r'\b(kiosk|parking|payment)\b', re.I), 'kiosk'),
    (re.compile(r'\b(printer|mfp)\b', re.I), 'printer'),
)


# ─── Certificate pinning ─────────────────────────────────────────────────────

def certificate_fingerprint(host, port=443, timeout=10):
    """
    The SHA-256 of the certificate a host presents, for pinning.

    Run once against the controller, check it matches what the controller's own
    UI reports, then pass it to every sync. That is a stronger guarantee than a
    public CA would give for an internal service, and it costs one command.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE       # fetching it, not trusting it
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as e:
        raise UnifiApiError(f'could not reach {host}:{port}: {e}') from e
    digest = hashlib.sha256(der).hexdigest().upper()
    return ':'.join(digest[i:i + 2] for i in range(0, len(digest), 2))


def _normalise_fingerprint(value):
    cleaned = re.sub(r'[^0-9a-fA-F]', '', str(value or '')).upper()
    if len(cleaned) != 64:
        raise UnifiApiError(
            f'a SHA-256 fingerprint is 64 hex characters; got {len(cleaned)}. '
            f'Obtain it with: python -m netmon.sources.unifi_api '
            f'--host <controller> --print-fingerprint')
    return cleaned


# ─── The client ──────────────────────────────────────────────────────────────

class UnifiClient:
    """
    A read-only connection to a UniFi controller.

    One method: `get`. There is no post, put or delete here to reach for by
    accident, and adding one would be a deliberate act rather than a different
    argument. The controller account should be view-only too; this is the second
    lock.
    """

    def __init__(self, host, api_key='', username='', password='',
                 fingerprint='', ca_bundle='', insecure=False, timeout=30,
                 site='default', opener=None):
        self.host = host.rstrip('/')
        if not self.host.startswith(('http://', 'https://')):
            self.host = 'https://' + self.host
        self.api_key = api_key
        self.username = username
        self.password = password
        self.site = site
        self.timeout = timeout
        self._cookie = ''
        self._csrf = ''
        self._opener = opener or self._build_opener(fingerprint, ca_bundle,
                                                    insecure)

    def _build_opener(self, fingerprint, ca_bundle, insecure):
        if fingerprint:
            return urllib.request.build_opener(_pinned_handler(fingerprint))
        if ca_bundle:
            context = ssl.create_default_context(cafile=ca_bundle)
            return urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=context))
        if insecure:
            logger.warning(
                'TLS verification is off. Anything on the path between here and '
                'the controller can read the API key and answer in its place. '
                'Use --fingerprint instead; it takes one command.')
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=context))
        return urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    # ─── The only verb ───────────────────────────────────────────────────

    def get(self, path):
        """
        Fetch one endpoint. Returns the decoded `data` list, or raises.

        The only method on this class, deliberately.
        """
        url = self.host + path
        headers = {'Accept': 'application/json'}
        if self.api_key:
            headers['X-API-KEY'] = self.api_key
        if self._cookie:
            headers['Cookie'] = self._cookie

        request = urllib.request.Request(url, headers=headers, method='GET')
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read()
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise UnifiApiError(
                    f'{url} refused the credentials ({e.code}). A view-only '
                    f'account is enough for this; check the key is for the '
                    f'right controller.') from e
            raise UnifiApiError(f'{url}: HTTP {e.code}') from e
        except UnifiApiError:
            raise
        except (urllib.error.URLError, OSError, ssl.SSLError) as e:
            reason = getattr(e, 'reason', e)
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise UnifiApiError(
                    f'the controller\'s certificate is not trusted. It is '
                    f'almost certainly self-signed, which is normal — pin it '
                    f'with --fingerprint rather than turning verification off.'
                ) from e
            raise UnifiApiError(f'{url}: {reason}') from e

        try:
            payload = json.loads(body.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise UnifiApiError(f'{url} did not return JSON') from e

        if isinstance(payload, dict) and 'data' in payload:
            return payload['data']
        return payload

    def login(self):
        """
        Start a session, for controllers without API-key support.

        Prefer an API key. A password session means this process holds the
        password for as long as it runs, and a key can be scoped and revoked.
        """
        if self.api_key:
            return True
        if not (self.username and self.password):
            raise UnifiApiError('no API key and no username or password')

        body = json.dumps({'username': self.username,
                           'password': self.password}).encode()
        request = urllib.request.Request(
            self.host + '/api/auth/login', data=body, method='POST',
            headers={'Content-Type': 'application/json'})
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                cookies = response.headers.get_all('Set-Cookie') or []
                self._cookie = '; '.join(c.split(';')[0] for c in cookies)
                self._csrf = response.headers.get('X-CSRF-Token', '')
        except urllib.error.HTTPError as e:
            raise UnifiApiError(f'login refused: HTTP {e.code}') from e
        except (urllib.error.URLError, OSError) as e:
            raise UnifiApiError(f'login failed: {getattr(e, "reason", e)}') from e
        if not self._cookie:
            raise UnifiApiError('login returned no session cookie')
        return True

    def describe(self):
        """For logs. Never includes the key or the password."""
        return {'host': self.host, 'site': self.site,
                'authenticated': bool(self.api_key or self._cookie),
                'method': 'api-key' if self.api_key else 'session'}


def _pinned_handler(fingerprint):
    """An HTTPS handler that checks the certificate against a pin."""
    pin = _normalise_fingerprint(fingerprint)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    class _Handler(urllib.request.HTTPSHandler):
        def __init__(self):
            super().__init__(context=context)

        def https_open(self, req):
            return self.do_open(self._make, req, context=context)

        @staticmethod
        def _make(host, **kwargs):
            import http.client
            kwargs.pop('context', None)
            connection = http.client.HTTPSConnection(host, context=context,
                                                     **kwargs)
            original = connection.connect

            def connect():
                original()
                der = connection.sock.getpeercert(binary_form=True)
                actual = hashlib.sha256(der).hexdigest().upper()
                if actual != pin:
                    connection.close()
                    raise UnifiApiError(
                        f'certificate fingerprint does not match: expected '
                        f'{pin}, got {actual}. Either the controller changed '
                        f'its certificate, or this is not the controller.')

            connection.connect = connect
            return connection

    return _Handler()


# ─── Fetching ────────────────────────────────────────────────────────────────

#: Endpoints to try, in order. UniFi OS moved everything under /proxy/network,
#: and which one answers depends on the hardware and firmware, so both are
#: attempted rather than requiring the operator to know which they have.
_ENDPOINTS = {
    'devices': ('/proxy/network/api/s/{site}/stat/device',
                '/api/s/{site}/stat/device'),
    'clients': ('/proxy/network/api/s/{site}/stat/sta',
                '/api/s/{site}/stat/sta'),
    'known_clients': ('/proxy/network/api/s/{site}/rest/user',
                      '/api/s/{site}/rest/user'),
    'networks': ('/proxy/network/api/s/{site}/rest/networkconf',
                 '/api/s/{site}/rest/networkconf'),
}


def fetch_inventory(client, want=('devices', 'clients', 'known_clients',
                                  'networks')):
    """
    Everything the controller will tell us, with per-endpoint failures noted.

    One endpoint being unavailable should not lose the rest: a controller that
    will not list its networks can still list its devices, and half a profile
    beats none.
    """
    inventory = {'errors': {}}
    for name in want:
        paths = _ENDPOINTS.get(name, ())
        for path in paths:
            try:
                inventory[name] = client.get(path.format(site=client.site))
                break
            except UnifiApiError as e:
                inventory['errors'][name] = str(e)
        inventory.setdefault(name, [])
    return inventory


# ─── Building a profile ──────────────────────────────────────────────────────

def _clean_name(value):
    """
    A device name fit to put in a YAML file and an alert.

    Names come from DHCP and from whoever set them, so they are attacker-
    influenceable. Restricted to what a hostname uses so one cannot carry a
    newline into a notification header or a quote into the profile.
    """
    text = str(value or '').strip()
    if text.lower() in _PLACEHOLDER_NAMES:
        return ''
    text = re.sub(r'[^A-Za-z0-9 ._-]', '', text)[:64].strip()
    return text


def _guess_role(name, device_type='', is_infrastructure=False):
    if is_infrastructure:
        return _ROLE_BY_TYPE.get(str(device_type).lower(), 'network_device')
    for pattern, role in _ROLE_HINTS:
        if pattern.search(name or ''):
            return role
    return 'unknown'


def build_profile(inventory, site_name='', existing=None):
    """
    Turn an inventory into a profile, keeping whatever was already written.

    Returns (profile_dict, report). The report says what was added, kept and no
    longer seen — a sync that silently rewrote a file nobody would run twice.
    """
    existing = existing or {}
    profile = {
        'site': dict(existing.get('site') or {}),
        'vlans': dict(existing.get('vlans') or {}),
        'roles': dict(existing.get('roles') or {}),
        'devices': {},
    }
    for key in ('expected_flows', 'bacnet_write_allowlist', 'services',
                'known_dead_references', 'remote_access_allowed',
                'watched_names', 'poisonable_names', 'metadata_only_vlans',
                'sensor_macs', 'router_macs', 'capture'):
        if key in existing:
            profile[key] = existing[key]

    profile['site'].setdefault('name', site_name or 'unnamed site')
    profile['site'].setdefault('timezone', 'UTC')
    profile['site'].setdefault('quiet_hours', [22, 6])

    report = {'vlans_added': [], 'devices_added': [], 'devices_kept': 0,
              'devices_not_seen': [], 'roles_guessed': 0,
              'errors': dict(inventory.get('errors') or {})}

    _merge_networks(inventory.get('networks') or [], profile, report)
    _merge_devices(inventory, profile, existing, report)

    # Roles the devices now reference but nothing defines. Added empty so the
    # profile validates; what each role may do is the operator's judgement.
    for device in profile['devices'].values():
        role = device.get('role')
        if role and role != 'unknown' and role not in profile['roles']:
            profile['roles'][role] = {'description': f'{role} (add a description)'}

    return profile, report


def _merge_networks(networks, profile, report):
    for network in networks:
        if not isinstance(network, dict):
            continue
        vlan = network.get('vlan')
        if vlan in (None, ''):
            vlan = 1 if network.get('is_nat') or network.get('purpose') == 'corporate' \
                else None
        try:
            vlan = int(vlan)
        except (TypeError, ValueError):
            continue

        entry = dict(profile['vlans'].get(vlan) or {})
        subnet = network.get('ip_subnet') or network.get('subnet') or ''
        gateway = str(network.get('gateway_ip') or '')

        entry.setdefault('name', _clean_name(network.get('name')) or f'vlan-{vlan}')
        if subnet and 'subnet' not in entry:
            entry['subnet'] = str(subnet)
        if gateway and 'gateway' not in entry:
            entry['gateway'] = gateway
        entry.setdefault('zone', '')

        if vlan not in profile['vlans']:
            report['vlans_added'].append(vlan)
        profile['vlans'][vlan] = entry


def _merge_devices(inventory, profile, existing, report):
    existing_devices = {str(k).lower(): dict(v or {})
                        for k, v in (existing.get('devices') or {}).items()}
    seen = set()

    def add(mac, name, role, ips, vlan=None, switch_port='', notes=''):
        mac = str(mac or '').strip().lower()
        if not re.match(r'^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$', mac):
            return
        mac = mac.replace('-', ':')
        seen.add(mac)

        previous = existing_devices.get(mac)
        if previous is not None:
            # Everything a person wrote wins. The controller knows addresses and
            # ports; it does not know what a device is for.
            entry = dict(previous)
            if ips and not entry.get('ips'):
                entry['ips'] = ips
            if vlan is not None and 'vlan' not in entry:
                entry['vlan'] = vlan
            if switch_port and not entry.get('switch_port'):
                entry['switch_port'] = switch_port
            report['devices_kept'] += 1
        else:
            entry = {'name': name or mac, 'role': role}
            if ips:
                entry['ips'] = ips
            if vlan is not None:
                entry['vlan'] = vlan
            if switch_port:
                entry['switch_port'] = switch_port
            if notes:
                entry['notes'] = notes
            report['devices_added'].append(f'{name or mac} ({mac})')
            if role != 'unknown':
                report['roles_guessed'] += 1
        profile['devices'][mac] = entry

    for device in inventory.get('devices') or []:
        if not isinstance(device, dict):
            continue
        name = _clean_name(device.get('name') or device.get('model'))
        address = str(device.get('ip') or '')
        add(device.get('mac'), name,
            _guess_role(name, device.get('type'), is_infrastructure=True),
            [address] if address else [],
            notes=_clean_name(device.get('model')))

    # Known clients first, then live ones: the known list carries the names
    # someone actually assigned, which are worth more than a DHCP hostname.
    for source in ('known_clients', 'clients'):
        for client in inventory.get(source) or []:
            if not isinstance(client, dict):
                continue
            name = (_clean_name(client.get('name'))
                    or _clean_name(client.get('hostname')))
            address = str(client.get('ip') or client.get('fixed_ip') or '')
            vlan = client.get('vlan')
            try:
                vlan = int(vlan) if vlan not in (None, '') else None
            except (TypeError, ValueError):
                vlan = None
            port = client.get('sw_port')
            switch_port = f'port {port}' if port not in (None, '') else ''
            add(client.get('mac'), name, _guess_role(name),
                [address] if address else [], vlan, switch_port)

    for mac, entry in existing_devices.items():
        if mac not in seen:
            # Kept, not deleted: a device that is merely switched off should not
            # vanish from the inventory, and one that has genuinely gone is a
            # decision for a person.
            profile['devices'][mac] = entry
            report['devices_not_seen'].append(
                f"{entry.get('name', mac)} ({mac})")

    return profile


def merge_profile(inventory, profile_path, site_name=''):
    """Build a profile, merging into whatever is already at `profile_path`."""
    import yaml

    existing = {}
    if profile_path and os.path.exists(profile_path):
        with open(profile_path, encoding='utf-8') as handle:
            existing = yaml.safe_load(handle) or {}
        if not isinstance(existing, dict):
            raise UnifiApiError(f'{profile_path}: top level must be a mapping')
    return build_profile(inventory, site_name, existing)


# ─── Writing it out ──────────────────────────────────────────────────────────

_HEADER = """\
# Generated by `python -m netmon.sources.unifi_api` from the UniFi controller,
# then edited by you. Re-running merges: names, roles, notes and anything the
# controller does not know are kept.
#
# The controller knows what a device *is*. It does not know what it is *for*,
# which is what the rules act on. Three things it cannot fill in, and which the
# monitor is much less useful without:
#
#   zone           on each VLAN — rules say "into the management zone", not
#                  "into VLAN 30", which is what makes them portable
#   store_payload  set it to false on any segment carrying credentials or
#                  cardholder data. Nothing from those segments is written to
#                  disk, logged, or sent anywhere.
#   expected_flows the cross-VLAN traffic you know about. Everything else
#                  crossing a boundary becomes a finding, so keep this tight.
#
# Keep this file out of version control. It is a map of your network.
"""


def write_profile(profile, path):
    """Write the profile, keeping the guidance header."""
    import yaml

    text = yaml.safe_dump(profile, sort_keys=False, default_flow_style=False,
                          allow_unicode=True, width=100)
    if os.path.exists(path):
        os.replace(path, path + '.bak')
    temporary = path + '.tmp'
    with open(temporary, 'w', encoding='utf-8') as handle:
        handle.write(_HEADER + '\n' + text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    try:
        os.chmod(path, 0o600)          # it is a map of the network
    except OSError:
        pass
    return path


def _main(argv=None):
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog='python -m netmon.sources.unifi_api',
        description='Build a netmon site profile from a UniFi controller. '
                    'Read-only: this never writes to the controller.')
    parser.add_argument('--host', required=True,
                        help='controller URL, e.g. https://unifi.example')
    parser.add_argument('--site', default='default', help='UniFi site name')
    parser.add_argument('--out', help='profile to write or merge into')
    parser.add_argument('--site-name', default='',
                        help='what to call the site in the profile')

    auth = parser.add_argument_group('credentials')
    auth.add_argument('--api-key', help='or set UNIFI_API_KEY. Preferred: a key '
                                        'can be scoped and revoked')
    auth.add_argument('--username')
    auth.add_argument('--password', help='or set UNIFI_PASSWORD')

    tls = parser.add_argument_group('certificate')
    tls.add_argument('--fingerprint',
                     help="the controller's SHA-256 certificate fingerprint. "
                          'The right answer for a self-signed certificate')
    tls.add_argument('--ca', help='a CA bundle, if you run your own CA')
    tls.add_argument('--insecure', action='store_true',
                     help='skip verification entirely. Says what it gives up')
    tls.add_argument('--print-fingerprint', action='store_true',
                     help="print the host's certificate fingerprint and exit")

    parser.add_argument('--json', action='store_true',
                        help='print the profile as JSON rather than writing it')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format='%(levelname)s: %(message)s')

    parsed = urllib.parse.urlparse(
        args.host if '://' in args.host else 'https://' + args.host)
    host, port = parsed.hostname, parsed.port or 443

    if args.print_fingerprint:
        try:
            print(certificate_fingerprint(host, port))
        except UnifiApiError as e:
            print(str(e), file=sys.stderr)
            return 1
        return 0

    if not (args.fingerprint or args.ca or args.insecure):
        # Not a refusal: a controller with a real certificate is fine, and the
        # attempt will say so clearly if it is not.
        logger.info('no --fingerprint or --ca given; the controller will need a '
                    'certificate your system already trusts')

    client = UnifiClient(
        args.host, site=args.site,
        api_key=args.api_key or os.environ.get('UNIFI_API_KEY', ''),
        username=args.username or os.environ.get('UNIFI_USERNAME', ''),
        password=args.password or os.environ.get('UNIFI_PASSWORD', ''),
        fingerprint=args.fingerprint or '', ca_bundle=args.ca or '',
        insecure=args.insecure)

    try:
        client.login()
        inventory = fetch_inventory(client)
    except UnifiApiError as e:
        print(str(e), file=sys.stderr)
        return 1

    try:
        profile, report = merge_profile(inventory, args.out, args.site_name)
    except UnifiApiError as e:
        print(str(e), file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({'profile': profile, 'report': report}, indent=2,
                         default=str))
        return 0

    print(f'{client.host} site {args.site}')
    print(f"  {len(profile['vlans'])} VLANs, {len(profile['devices'])} devices")
    if report['vlans_added']:
        print(f"  added VLANs: {', '.join(str(v) for v in report['vlans_added'])}")
    if report['devices_added']:
        print(f"  added {len(report['devices_added'])} devices"
              + (f", guessed a role for {report['roles_guessed']}"
                 if report['roles_guessed'] else ''))
        for entry in report['devices_added'][:10]:
            print(f'    + {entry}')
        if len(report['devices_added']) > 10:
            print(f"    … and {len(report['devices_added']) - 10} more")
    if report['devices_kept']:
        print(f"  kept {report['devices_kept']} existing entries unchanged")
    if report['devices_not_seen']:
        print(f"  {len(report['devices_not_seen'])} profiled devices were not "
              f"seen — kept, not removed:")
        for entry in report['devices_not_seen'][:10]:
            print(f'    ? {entry}')
    for name, error in (report['errors'] or {}).items():
        print(f'  could not read {name}: {error}')

    if not args.out:
        print()
        print('Nothing written — pass --out to save it.')
        return 0

    write_profile(profile, args.out)
    print()
    print(f'Wrote {args.out} (mode 600; previous kept as .bak)')
    print()
    print('Now fill in what the controller cannot know:')
    print('  · a zone on each VLAN, so rules mean something at a second site')
    print('  · store_payload: false on segments carrying credentials or card data')
    print('  · expected_flows for the cross-VLAN traffic you know about')
    print()
    print(f'Then check it: python -m netmon.profile {args.out}')
    return 0


if __name__ == '__main__':
    import sys
    from netmon.sources.unifi_api import _main as main
    sys.exit(main())
