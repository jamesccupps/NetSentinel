"""
Local web UI.
=============
Findings, devices, the profile, the rules, and a capture-filter builder that
verifies its output against a real capture instead of asserting it is correct.

    python -m netmon.web --profile my-site.yaml --unifi flows.csv

It binds to localhost. This page serves a complete inventory of the network —
every device, every VLAN, which segments are unencrypted, what talks to what —
which is the document an attacker would most like to be handed. There is no
login, because on a sensor reachable only from a management network a login is
a password to leak rather than a boundary; the boundary is the network. Moving
it off localhost is therefore a deliberate act that prints a warning and should
be paired with a firewall rule.

Editing
-------
Off unless `--allow-edit`. When on, the profile and rule editors validate before
they write, write atomically, and keep the previous version alongside. Writes
require a token issued with the page and a same-origin check, so another page in
the same browser cannot drive this one.

Foreign Host headers
--------------------
While bound to loopback, a request whose Host header is not a loopback name is
refused before anything is served. Without that, a page on any website can
point its own hostname at 127.0.0.1 (DNS rebinding), read `/` as same-origin,
and take the token off it — after which the token check protects nothing. A
loopback bind is the only case where the legitimate names are knowable; bound
anywhere else, the firewall is the boundary, as the warning says.

Nothing here touches the network. It reads files and shows what is in them.
"""

from __future__ import annotations

import html
import json
import logging
import os
import secrets
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import yaml

from netmon import bpf
from netmon.events import Severity, Tier
from netmon.profile import ProfileError, SiteProfile, load_profile
from netmon.rules_engine import RuleError, load_rules

logger = logging.getLogger("netmon.web")

__all__ = ['WebServer', 'run_web']

HERE = os.path.dirname(os.path.abspath(__file__))
UI_DIR = os.path.join(HERE, 'webui')

_STATIC_TYPES = {'.html': 'text/html; charset=utf-8',
                 '.css': 'text/css; charset=utf-8',
                 '.js': 'application/javascript; charset=utf-8',
                 '.svg': 'image/svg+xml'}

#: The names a browser can legitimately use for a loopback listener. Anything
#: else in the Host header, while bound to loopback, is a rebinding attempt.
LOOPBACK_NAMES = frozenset({'127.0.0.1', 'localhost', '::1'})


def _host_name(header):
    """The name part of a Host header, without the port, lowercased."""
    host = (header or '').strip().lower()
    if host.startswith('['):
        return host[1:host.find(']')] if ']' in host else host
    # One colon is host:port. More than one is a bare IPv6 address, which a
    # browser would have bracketed; it is compared as it stands.
    return host.rsplit(':', 1)[0] if host.count(':') == 1 else host


class _Handler(BaseHTTPRequestHandler):

    server_version = "netmon"
    sys_version = ""                  # do not advertise the Python version

    # The page makes half a dozen API calls on load; under HTTP/1.0 each one
    # opens and closes a connection. Safe to set because every response here
    # carries an accurate Content-Length.
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        logger.debug("%s - %s", self.address_string(), fmt % args)

    def do_HEAD(self):
        """Headers only. Monitoring tools reach for this before anything else."""
        self._head_only = True
        try:
            self.do_GET()
        finally:
            self._head_only = False

    def _host_allowed(self):
        """
        Refuse a foreign Host header while bound to loopback.

        Checked on every request, page and API alike: the page carries the
        token, so serving it to a rebound hostname hands over the one thing the
        write checks rely on.
        """
        allowed = self.server.netmon_app.allowed_hosts()
        if allowed is None or _host_name(self.headers.get('Host')) in allowed:
            return True
        self._send_json({'error': 'unexpected Host header',
                         'detail': 'this server answers only to a loopback name'},
                        421)
        return False

    # ─── GET ─────────────────────────────────────────────────────────────

    def do_GET(self):
        if not self._host_allowed():
            return
        parsed = urlparse(self.path)
        app = self.server.netmon_app

        if parsed.path in ('/', '/index.html'):
            return self._send_static('index.html')
        if parsed.path.startswith('/static/'):
            return self._send_static(parsed.path[len('/static/'):])

        route = app.routes.get(parsed.path)
        if route is None:
            return self._send_json({'error': 'not found', 'path': parsed.path}, 404)
        try:
            payload = route(parse_qs(parsed.query))
        except Exception as e:
            logger.exception("serving %s", parsed.path)
            return self._send_json({'error': 'internal error', 'detail': str(e)}, 500)
        return self._send_json(payload)

    # ─── POST ────────────────────────────────────────────────────────────

    def do_POST(self):
        parsed = urlparse(self.path)
        app = self.server.netmon_app

        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            return self._refuse({'error': 'bad content length'}, 400)

        if length > app.max_body_bytes:
            detail = f'{length} bytes exceeds the {app.max_body_bytes} limit'
            # Answering before the client has finished sending races its own
            # write: it may see a broken pipe instead of the 413 and never learn
            # why. So a merely-too-large body is drained and discarded, which
            # costs a bounded read and gives a clean answer every time.
            if length <= app.max_drain_bytes:
                self._drain(length)
                return self._refuse({'error': 'too large', 'detail': detail}, 413)
            # Beyond the drain ceiling, reading it is the bigger problem. The
            # connection is closed instead, and the client may see a reset.
            return self._refuse(
                {'error': 'too large', 'detail': detail + ' (connection closed)'},
                413)

        # Read the body before the authorisation checks. Refusing first would
        # leave an unread body in the socket and break the next request on the
        # same connection; the size limit above is what makes reading it safe.
        raw = self._read_exactly(length)
        if raw is None:
            return self._refuse({'error': 'body shorter than Content-Length'}, 400)

        if not self._host_allowed():
            return

        refusal = app.permission_refusal(parsed.path)
        if refusal is not None:
            return self._send_json(refusal, 403)

        # Another page in this browser must not be able to drive this one. The
        # token is issued with the page; the Origin check catches the
        # form-submission case, where a token would not be readable anyway.
        origin = self.headers.get('Origin')
        if origin is not None and (urlparse(origin).netloc.lower()
                                   != (self.headers.get('Host') or '').lower()):
            return self._send_json({'error': 'cross-origin request refused'}, 403)
        # Browsers label a request another site initiated, whether or not they
        # also send an Origin. A same-origin page never produces this value.
        if (self.headers.get('Sec-Fetch-Site') or '').lower() == 'cross-site':
            return self._send_json({'error': 'cross-origin request refused'}, 403)
        if not secrets.compare_digest(
                self.headers.get('X-Netmon-Token') or '', app.token):
            return self._send_json({'error': 'missing or stale token',
                                    'detail': 'reload the page'}, 403)

        route = app.post_routes.get(parsed.path)
        if route is None:
            return self._send_json({'error': 'not found', 'path': parsed.path}, 404)

        try:
            body = json.loads(raw.decode('utf-8')) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return self._send_json({'error': 'body is not JSON', 'detail': str(e)}, 400)

        try:
            payload, status = route(body)
        except Exception as e:
            logger.exception("handling %s", parsed.path)
            return self._send_json({'error': 'internal error', 'detail': str(e)}, 500)
        return self._send_json(payload, status)

    def _drain(self, length):
        """Read and discard a body we are about to refuse, so the client can
        finish writing and read our answer."""
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                return
            remaining -= len(chunk)

    def _read_exactly(self, length):
        """Read the whole body, or None if the client stopped short."""
        chunks, remaining = [], length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b''.join(chunks)

    def _refuse(self, payload, status):
        """Reject without reading the body, closing the connection behind us."""
        self.close_connection = True
        self._send_json(payload, status, close=True)

    # ─── Sending ─────────────────────────────────────────────────────────

    def _send_static(self, relative):
        # Resolve and confirm the result is still inside the UI directory, so a
        # crafted path cannot read the profile or anything else off the disk.
        path = os.path.realpath(os.path.join(UI_DIR, relative))
        if not path.startswith(os.path.realpath(UI_DIR) + os.sep):
            return self._send_json({'error': 'not found'}, 404)
        if not os.path.isfile(path):
            return self._send_json({'error': 'not found'}, 404)

        with open(path, 'rb') as f:
            data = f.read()
        content_type = _STATIC_TYPES.get(os.path.splitext(path)[1],
                                         'application/octet-stream')
        if relative == 'index.html':
            app = self.server.netmon_app
            data = data.replace(b'{{TOKEN}}', app.token.encode())
            data = data.replace(b'{{EDITABLE}}',
                                b'true' if app.allow_edit else b'false')
            data = data.replace(b'{{SILENCES}}',
                                b'true' if app.allow_edit and app.silences_path
                                else b'false')
            data = data.replace(b'{{SUMMARISE}}',
                                b'true' if app.allow_summarise else b'false')
        self._send_bytes(data, content_type, 200)

    def _send_json(self, payload, status=200, close=False):
        self._send_bytes(json.dumps(payload, default=str).encode(),
                         'application/json', status, close=close)

    def _send_bytes(self, data, content_type, status, close=False):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        if close:
            self.send_header('Connection', 'close')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        # Everything the page needs is served from here; nothing external is
        # loaded, so the policy can be this tight.
        self.send_header('Content-Security-Policy',
                         "default-src 'self'; style-src 'self'; script-src 'self'; "
                         "img-src 'self' data:; connect-src 'self'; "
                         "form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header('Referrer-Policy', 'no-referrer')
        self.end_headers()
        if getattr(self, '_head_only', False):
            return
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass                       # the browser navigated away mid-response


class WebServer:
    """The UI, its data, and the editors."""

    #: A profile or rule file larger than this is not a profile or rule file.
    max_body_bytes = 2 * 1024 * 1024

    #: How much of an over-sized body will be read and thrown away so the
    #: refusal reaches the client cleanly. Beyond it, the connection is closed.
    max_drain_bytes = 16 * 1024 * 1024

    def __init__(self, profile_path, rules_path=None, analyzer=None,
                 host='127.0.0.1', port=8788, allow_edit=False, silences_path='',
                 allow_summarise=False):
        self.profile_path = profile_path
        self.rules_path = rules_path or os.path.join(HERE, 'rules')
        self.analyzer = analyzer
        self.host = host
        self.port = port
        self.allow_edit = allow_edit
        self.allow_summarise = bool(allow_summarise)
        self.token = secrets.token_urlsafe(32)
        self.silences_path = silences_path

        self.profile = load_profile(profile_path)
        self.rules = load_rules(self.rules_path)

        self._httpd = None
        self._thread = None

        self.routes = {
            '/api/summary': self._summary,
            '/api/findings': self._findings,
            '/api/devices': self._devices,
            '/api/profile': self._profile_source,
            '/api/rules': self._rules_list,
            '/api/rule': self._rule_source,
            '/api/filter': self._build_filter,
            '/api/silences': self._silences_list,
        }
        self.post_routes = {
            '/api/filter/verify': self._verify_filter,
            '/api/profile/save': self._save_profile,
            '/api/rules/save': self._save_rules,
            '/api/reload': self._reload,
            '/api/silence': self._silence_add,
            '/api/silence/clear': self._silence_clear,
        }
        #: Which switch each POST route sits behind. Anything not listed is an
        #: editor route, so a route added without thinking about it is behind
        #: --allow-edit rather than open.
        self.post_permissions = {}

    def permission_refusal(self, path):
        """None if this POST route is switched on, else the refusal to send."""
        needs = self.post_permissions.get(path, 'edit')
        if needs == 'summarise' and not self.allow_summarise:
            return {'error': 'the summariser is off',
                    'detail': 'start with --allow-summarise to enable the button'}
        if needs == 'edit' and not self.allow_edit:
            return {'error': 'editing is off',
                    'detail': 'start with --allow-edit to enable the editors'}
        return None

    # ─── Lifecycle ───────────────────────────────────────────────────────

    def start(self):
        if self._httpd is not None:
            return self.port
        self._httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
        self._httpd.netmon_app = self
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={'poll_interval': 0.05},
            name='netmon-web', daemon=True)
        self._thread.start()
        return self.port

    def stop(self):
        if self._httpd is None:
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._httpd = self._thread = None

    def url(self):
        host = f'[{self.host}]' if ':' in self.host else self.host
        return f'http://{host}:{self.port}/'

    def allowed_hosts(self):
        """
        The Host names to accept, or None for any.

        Only a loopback bind has a knowable answer. Bound to an address on a
        management network, the names it is reached by are the site's business
        and the firewall is the boundary.
        """
        return LOOPBACK_NAMES if self.host in LOOPBACK_NAMES else None

    # ─── Read routes ─────────────────────────────────────────────────────

    def _summary(self, params):
        report = self.analyzer.report() if self.analyzer else {}
        return {
            'site': self.profile.summary(),
            'rules': self.rules.summary(),
            'analysis': report,
            'editable': self.allow_edit,
            'silences': bool(self.silences_path),
            'summarise': self.allow_summarise,
            'profile_path': self.profile_path,
            'rules_path': self.rules_path,
        }

    def _visible(self, findings, include_snoozed=False):
        """
        Findings with the silences applied as they stand now.

        Applied on every request rather than once when the finding arrived, so
        a snooze added a minute ago hides what it covers and an ack shows as
        one straight away.
        """
        store = self._silences()
        if store is None:
            return list(findings)
        shown = store.visible(findings)
        if not include_snoozed:
            return shown
        # Asked for explicitly, so a snooze can be found and cleared. The
        # snoozed ones are marked by the same pass that left them out.
        kept = {id(f) for f in shown}
        return shown + [f for f in findings if id(f) not in kept]

    def _findings(self, params):
        if self.analyzer is None:
            return {'findings': [], 'note': 'no analysis has been run'}
        floor = Severity.rank(_one(params, 'min_severity') or 'info')
        tier = _one(params, 'tier')
        rule_id = _one(params, 'rule')
        device = _one(params, 'device')
        include_snoozed = _one(params, 'snoozed') in ('1', 'true', 'yes')

        findings = [f for f in self._visible(self.analyzer.by_severity(),
                                             include_snoozed)
                    if Severity.rank(f.severity) >= floor
                    and (not tier or f.tier == tier)
                    and (not rule_id or f.rule_id == rule_id)
                    and (not device or f.device == device)]
        findings.sort(key=lambda f: (-Severity.rank(f.severity), f.ts))
        limit = _int(params, 'limit', 500, 5000)
        return {'count': len(findings),
                'findings': [f.as_dict() for f in findings[:limit]]}

    def _devices(self, params):
        """
        The profile's inventory, annotated with what the analysis saw.

        Deliberately shows devices with no findings too: "this controller has
        been quiet all week" is information, and a list that only shows problems
        cannot tell you whether something stopped reporting.
        """
        seen, findings_by_device = {}, {}
        if self.analyzer is not None:
            for finding in self._visible(self.analyzer.findings):
                findings_by_device.setdefault(finding.device, []).append(
                    {'rule_id': finding.rule_id, 'severity': finding.severity,
                     'description': finding.description, 'count': finding.count})
                event = finding.event
                if event is not None and event.src_ip:
                    seen[event.src_ip] = max(seen.get(event.src_ip, 0), event.ts)

        devices = []
        for device in sorted(self.profile.devices.values(),
                             key=lambda d: (d.vlan or 0, d.name)):
            keys = {device.name, device.mac, *device.ips}
            device_findings = [f for key in keys for f in findings_by_device.get(key, [])]
            vlan = self.profile.vlans.get(device.vlan) if device.vlan else None
            devices.append({
                'name': device.name, 'mac': device.mac, 'role': device.role,
                'ips': device.ips, 'vlan': device.vlan,
                'vlan_name': vlan.name if vlan else '',
                'zone': vlan.zone if vlan else '',
                'switch_port': device.switch_port, 'notes': device.notes,
                'metadata_only': not self.profile.may_store_payload(device.vlan),
                'findings': device_findings,
                'worst': max((f['severity'] for f in device_findings),
                             key=Severity.rank, default=''),
                'last_seen': seen.get(device.ips[0]) if device.ips else None,
            })

        unprofiled = sorted(
            {d for d in findings_by_device
             if d not in {x['name'] for x in devices}
             and d not in self.profile.devices})
        return {'devices': devices, 'unprofiled': unprofiled,
                'vlans': [{'id': v.id, 'name': v.name, 'subnet': v.subnet,
                           'zone': v.zone, 'gateway': v.gateway,
                           'metadata_only': not v.store_payload}
                          for v in sorted(self.profile.vlans.values(),
                                          key=lambda v: v.id)]}

    def _profile_source(self, params):
        with open(self.profile_path, encoding='utf-8') as f:
            return {'path': self.profile_path, 'source': f.read(),
                    'summary': self.profile.summary()}

    def _rules_list(self, params):
        return {'rules': [
            {'id': r.id, 'title': r.title, 'severity': r.severity,
             'tier': r.tier, 'enabled': r.enabled, 'type': r.type,
             'grounded_in': r.grounded_in, 'describe': r.describe,
             'when': r.when, 'unless': r.unless, 'params': r.params,
             'next_check': r.next_check}
            for r in self.rules]}

    def _rule_source(self, params):
        name = _one(params, 'file') or 'core.yaml'
        path = self._rule_file(name)
        if path is None:
            return {'error': 'no such rule file'}
        with open(path, encoding='utf-8') as f:
            return {'file': os.path.basename(path), 'source': f.read()}

    def _rule_file(self, name):
        """Resolve a rule file, refusing anything outside the rules directory."""
        if os.path.isfile(self.rules_path):
            return self.rules_path if os.path.basename(self.rules_path) == name else None
        candidate = os.path.realpath(os.path.join(self.rules_path, name))
        root = os.path.realpath(self.rules_path)
        if not candidate.startswith(root + os.sep) or not os.path.isfile(candidate):
            return None
        return candidate

    def _build_filter(self, params):
        """
        The capture-filter builder.

        Returns the BPF and the Wireshark equivalent, and says plainly that the
        BPF is unverified — the whole reason this builder exists is that filters
        which look right match the wrong frames.
        """
        vlans = [int(v) for v in (_one(params, 'vlans') or '').replace(' ', '').split(',')
                 if v.strip().lstrip('-').isdigit()]
        untagged = _one(params, 'untagged') != 'false'
        drop_hosts = [h for h in (_one(params, 'drop_hosts') or '').split(',') if h.strip()]
        drop_ports = [int(p) for p in (_one(params, 'drop_ports') or '').replace(' ', '').split(',')
                      if p.strip().isdigit()]
        protocol = _one(params, 'protocol') or None
        ports = [int(p) for p in (_one(params, 'ports') or '').replace(' ', '').split(',')
                 if p.strip().isdigit()]

        try:
            extra = bpf.protocol_filter(protocol, ports) if (protocol or ports) else ''
            capture = bpf.build_capture_filter(
                vlans=vlans, include_untagged=untagged,
                drop_hosts=[h.strip() for h in drop_hosts],
                drop_ports=drop_ports,
                extra=extra or None)
        except ValueError as e:
            return {'error': str(e)}

        return {
            'bpf': capture,
            'wireshark': bpf.display_filter(vlans=vlans, hosts=drop_hosts,
                                            ports=ports, protocol=protocol),
            'tcpdump': f"tcpdump -i <mirror> -w capture.pcap "
                       f"{json.dumps(capture) if capture else ''}".strip(),
            'unverified': True,
            'note': 'BPF VLAN handling differs between libpcap and Npcap. Verify '
                    'against a short unfiltered capture taken on the machine that '
                    'will run this.',
        }

    # ─── Write routes ────────────────────────────────────────────────────

    def _verify_filter(self, body):
        """Run a candidate filter over a capture and report what it matched."""
        pcap = str(body.get('pcap') or '').strip()
        if not pcap:
            return {'error': 'give the path to a capture taken on this machine'}, 400
        if not os.path.isfile(pcap):
            return {'error': f'no such capture: {pcap}'}, 400
        return bpf.verify_filter(str(body.get('bpf') or ''), pcap), 200

    def _save_profile(self, body):
        """
        Validate, then write atomically, keeping the previous version.

        A profile that fails to load is a monitor that will not start, and the
        person editing it is usually doing so because something is already
        wrong. So it is checked before anything is written, not after.
        """
        source = body.get('source')
        if not isinstance(source, str):
            return {'error': 'no source supplied'}, 400
        try:
            data = yaml.safe_load(source)
        except yaml.YAMLError as e:
            return {'error': 'not valid YAML', 'detail': str(e)}, 400
        if data is not None and not isinstance(data, dict):
            return {'error': 'the top level must be a mapping'}, 400
        try:
            candidate = SiteProfile(data or {}, path=self.profile_path)
        except ProfileError as e:
            return {'error': 'the profile is not valid', 'detail': str(e)}, 400

        _write_with_backup(self.profile_path, source)
        self.profile = candidate
        return {'ok': True, 'summary': candidate.summary(),
                'backup': self.profile_path + '.bak'}, 200

    def _save_rules(self, body):
        source = body.get('source')
        name = str(body.get('file') or 'core.yaml')
        if not isinstance(source, str):
            return {'error': 'no source supplied'}, 400
        path = self._rule_file(name)
        if path is None:
            return {'error': f'no such rule file: {name}'}, 400

        # Validate by loading from a temporary copy rather than by writing the
        # real file and hoping: a rule file that does not parse would take the
        # monitor down at its next restart, not now, when it could be fixed.
        import tempfile
        with tempfile.TemporaryDirectory() as scratch:
            trial = os.path.join(scratch, os.path.basename(path))
            with open(trial, 'w', encoding='utf-8') as f:
                f.write(source)
            try:
                candidate = load_rules(trial)
            except RuleError as e:
                return {'error': 'the rules are not valid', 'detail': str(e)}, 400

        _write_with_backup(path, source)
        self.rules = load_rules(self.rules_path)
        return {'ok': True, 'rules': candidate.summary(),
                'backup': path + '.bak'}, 200

    def _silences(self):
        if not self.silences_path:
            return None
        from netmon.silence import Silences
        return Silences(self.silences_path)

    def _silences_list(self, params):
        store = self._silences()
        if store is None:
            return {'silences': [], 'note': 'no state directory configured'}
        return {'silences': store.active()}

    def _silence_add(self, body):
        """Writes, so it sits behind --allow-edit and the token like the editors."""
        import time
        from netmon.silence import SilenceError
        store = self._silences()
        if store is None:
            return {'error': 'no state directory configured'}, 400
        try:
            hours = body.get('hours')
            until = time.time() + float(hours) * 3600 if hours not in (None, '') else None
            entry = store.add(str(body.get('kind') or ''),
                              rule=str(body.get('rule') or ''),
                              device=str(body.get('device') or ''),
                              key=str(body.get('key') or ''), until=until,
                              reason=str(body.get('reason') or ''))
        except (SilenceError, TypeError, ValueError) as e:
            return {'error': str(e)}, 400
        return {'ok': True, 'silence': entry}, 200

    def _silence_clear(self, body):
        store = self._silences()
        if store is None:
            return {'error': 'no state directory configured'}, 400
        if store.remove(str(body.get('id') or '')):
            return {'ok': True}, 200
        return {'error': 'no such silence'}, 404

    def _reload(self, body):
        try:
            self.profile = load_profile(self.profile_path)
            self.rules = load_rules(self.rules_path)
        except (ProfileError, RuleError) as e:
            return {'error': str(e)}, 400
        return {'ok': True, 'site': self.profile.summary(),
                'rules': self.rules.summary()}, 200


def _write_with_backup(path, source):
    """Keep the previous version, then replace atomically."""
    if os.path.exists(path):
        shutil.copy2(path, path + '.bak')
    temporary = path + '.tmp'
    with open(temporary, 'w', encoding='utf-8') as f:
        f.write(source)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)


def _one(params, name):
    values = params.get(name)
    return values[0] if values else ''


def _int(params, name, default, maximum):
    raw = _one(params, name)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(1, min(value, maximum))


def make_server(profile_path, rules_path=None, analyzer=None, host='127.0.0.1',
                port=8788, allow_edit=False, state_dir=''):
    """
    The UI as `netmon web` builds it, not yet listening.

    `state_dir` is the service's state directory. The silences live there, so
    pointing the UI at the same one shows — and, with editing on, changes — the
    acknowledgements and snoozes the running service applies.
    """
    silences_path = os.path.join(state_dir, 'silences.json') if state_dir else ''
    return WebServer(profile_path, rules_path, analyzer, host, port, allow_edit,
                     silences_path=silences_path)


def run_web(profile_path, rules_path=None, analyzer=None, host='127.0.0.1',
            port=8788, allow_edit=False, open_browser=False, state_dir=''):
    """Start the UI and block until interrupted."""
    server = make_server(profile_path, rules_path, analyzer, host, port,
                         allow_edit, state_dir)
    silences_path = server.silences_path
    server.start()

    print(f'netmon UI on {server.url()}')
    print(f'  profile: {profile_path}')
    if analyzer is not None:
        report = analyzer.report()
        print(f'  {report["events"]} events analysed, '
              f'{report["findings"]} findings')
    if allow_edit:
        print('  editing is ON — the profile and rules can be written from the browser')
        if silences_path:
            print(f'  acknowledge, snooze and maintenance write to {silences_path}')
    if silences_path and not allow_edit:
        print('  silences are shown; add --allow-edit to change them')
    if host not in ('127.0.0.1', 'localhost', '::1'):
        print()
        print(f'  WARNING: bound to {host}, not localhost.')
        print('  This page is a complete map of the network — every device, every')
        print('  VLAN, which segments are unencrypted. There is no login. Restrict')
        print('  it at the firewall to your management addresses.')
    print()
    print('Ctrl-C to stop.')

    if open_browser:
        import webbrowser
        webbrowser.open(server.url())

    try:
        while True:
            server._thread.join(timeout=1.0)
    except KeyboardInterrupt:
        print('\nstopping')
    finally:
        server.stop()
    return 0


def _parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog='python -m netmon.web',
        description='Local web UI for netmon. Reads files and shows what is in '
                    'them; nothing here touches the network.')
    parser.add_argument('--profile', required=True, help='site profile YAML')
    parser.add_argument('--rules', help='rule file or directory')
    parser.add_argument('--unifi', metavar='CSV',
                        help='analyse this export on startup so the findings '
                             'view has something in it')
    parser.add_argument('--pcap', metavar='FILE',
                        help='also analyse this capture. The protocol-aware '
                             'rules need it; a flow export carries no BACnet, '
                             'no server names and no DNS')
    parser.add_argument('--limit', type=int, help='stop after N events')
    parser.add_argument('--host', default='127.0.0.1',
                        help='default 127.0.0.1; anything else is a deliberate '
                             'decision — this page is a map of the network and '
                             'has no login')
    parser.add_argument('--port', type=int, default=8788)
    parser.add_argument('--allow-edit', action='store_true',
                        help='let the profile and rule editors write to disk, '
                             'and the acknowledge, snooze and maintenance '
                             'buttons write silences under --state')
    parser.add_argument('--state', default='', metavar='DIR',
                        help="the service's state directory (its --state), "
                             'where silences are kept')
    parser.add_argument('--open', action='store_true', help='open a browser')
    parser.add_argument('-v', '--verbose', action='store_true')
    return parser


def _main(argv=None):
    import sys

    args = _parser().parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format='%(levelname)s: %(message)s')

    analyzer = None
    if args.unifi or args.pcap:
        from netmon.analyze import Analyzer
        from netmon.sources.pcap import PcapError, read_pcap
        from netmon.sources.unifi_csv import UnifiCsvError, read_flows
        try:
            profile = load_profile(args.profile)
            analyzer = Analyzer(profile, load_rules(
                args.rules or os.path.join(HERE, 'rules')))
            if args.unifi:
                analyzer.feed(read_flows(args.unifi, limit=args.limit))
            if args.pcap:
                analyzer.feed(read_pcap(args.pcap, profile, limit=args.limit))
        except (ProfileError, RuleError, UnifiCsvError, PcapError) as e:
            print(f'{e}', file=sys.stderr)
            return 1

    try:
        return run_web(args.profile, args.rules, analyzer, args.host, args.port,
                       args.allow_edit, args.open, state_dir=args.state)
    except (ProfileError, RuleError) as e:
        print(f'{e}', file=sys.stderr)
        return 1
    except OSError as e:
        print(f'could not listen on {args.host}:{args.port}: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    import sys
    from netmon.web import _main as main
    sys.exit(main())
