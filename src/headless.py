"""
Headless mode and the browser dashboard.
=========================================
Runs the detection engine with no GUI and exposes its state over HTTP, so
NetSentinel can live on a Raspberry Pi hanging off a SPAN port instead of only
on the desktop it is watching. The desktop app starts the same server, so the
dashboard is also a browser view of a session with a window.

This needed almost no new code. `NetSentinelApp` never imported tkinter outside
`run()`, and the last piece of display logic moved to `presentation.py`, so the
engine was already headless — it simply had no way to be started or read without
a window.

Design notes
------------
**No configuration.** There is no way to change configuration through this API.
A sensor that can be reconfigured over the network is a liability, and the
failure modes of getting authentication wrong are worse than the inconvenience
of editing config.json.

**Controls on loopback only.** A POST can upload files to be scanned and, only
while the server is bound to a loopback address, start or stop monitoring,
acknowledge alerts, record verdicts, build a review bundle, run a network audit
and edit the scan ignore list. Turning audits on, like every other setting, stays
in the desktop app. Every POST needs the token embedded in the dashboard page: a
custom header no other site can send without a CORS preflight this server never
answers, so no web page can drive it. Bound to anything else, the controls are
refused, because then the token is the only thing between a network and turning
monitoring off.

**Only its own name.** Requests whose Host header is not a loopback name are
refused while bound to loopback, which stops DNS rebinding from turning a
malicious page into a reader of this API.

**Localhost by default.** The output contains captured credentials, device
inventory and alert history. Binding to 0.0.0.0 requires saying so explicitly,
and logs a warning when you do.

**stdlib only.** `http.server` rather than Flask or FastAPI, because adding a web
framework to a security tool's dependency tree to serve six JSON endpoints is a
bad trade.

Endpoints
---------
    GET /                 the dashboard
    GET /status.txt       human-readable status summary
    GET /health           liveness, for a supervisor or container probe
    GET /api/overview     what the dashboard's overview shows
    GET /api/status       capture, IDS, ML and alert counters
    GET /api/alerts       recent alerts, ?limit= and ?severity=
    GET /api/incidents    correlated incidents
    GET /api/devices      discovered devices on the local network
    GET /api/metrics      Prometheus text exposition
    GET /api/scan         a file scan's progress and report, ?id=
    POST /api/scan/new, /api/scan/upload?id=&name=, /api/scan/upload-batch?id=,
         /api/scan/start?id=, /api/scan/cancel?id=
                          upload files and scan them (token required)
    GET /api/audit        the network audit: choices, progress, last report
    POST /api/monitoring/start, /api/monitoring/stop, /api/alerts/ack?id=,
         /api/alerts/ack-all, /api/alerts/verdict?id=&verdict=, /api/review/bundle,
         /api/audit/start?network=&gentle=, /api/audit/cancel,
         /api/scan/ignore (JSON body), /api/scan/unignore?id=
                          controls (token required, loopback binds only)
    GET /api/scan/ignored the file-scan ignore list
"""

import hmac
import json
import logging
import os
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from src import presentation, __version__

WEBUI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'webui')
STATIC_FILES = {
    '/static/app.js': ('app.js', 'application/javascript; charset=utf-8'),
    '/static/style.css': ('style.css', 'text/css; charset=utf-8'),
}
LOOPBACK_NAMES = {'127.0.0.1', 'localhost', '::1'}
DASHBOARD_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; "
                 "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                 "base-uri 'none'; form-action 'none'")

logger = logging.getLogger("NetSentinel.Headless")

__all__ = ['HeadlessServer', 'run_headless']

# Anything above this is almost certainly a mistake rather than a request.
MAX_ALERT_LIMIT = 1000


class RequestRefused(Exception):
    """A POST the server understood and will not do. `status` is the HTTP code."""

    def __init__(self, message, status=403):
        super().__init__(message)
        self.status = status

# Not 8787, the first choice: localcast and RStudio Server default to it, so
# whichever started second either failed or pushed the dashboard to a random port.
DEFAULT_PORT = 8737

# How long, and how much, to read of a refused POST's body after answering it.
LINGER_SECONDS = 2.0
LINGER_BYTES = 64 * 1024 * 1024


def _drain(sock):
    """
    Finish the reply, then read and discard what the client is still sending.

    A refused POST is answered before its body is read. Closing a socket with
    unread data makes Windows reset the connection, and the reset throws away
    the reply the browser has not read yet: it showed a network error instead
    of "another scan is running". Answering first and reading afterwards also
    means a client that waits for the answer before sending is never stuck.
    """
    try:
        sock.shutdown(socket.SHUT_WR)
        deadline = time.monotonic() + LINGER_SECONDS
        received = 0
        while received < LINGER_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            chunk = sock.recv(65536)
            if not chunk:
                break
            received += len(chunk)
    except OSError:
        pass


class _Handler(BaseHTTPRequestHandler):
    """Routes are resolved against the table in HeadlessServer."""

    server_version = "NetSentinel"
    sys_version = ""          # Do not advertise the Python version.

    _body_unread = False

    # BaseHTTPRequestHandler logs every request to stderr by default.
    def log_message(self, fmt, *args):
        logger.debug("%s - %s", self.address_string(), fmt % args)

    def send_response(self, code, message=None):
        # Every refusal of a POST, from a wrong Host header to a route raising,
        # may leave the body unread, so the connection cannot be reused safely
        # and must be drained before it is closed.
        if getattr(self, 'command', None) == 'POST' and code >= 400:
            self._body_unread = True
            self.close_connection = True
        super().send_response(code, message)

    def finish(self):
        super().finish()
        if self._body_unread:
            _drain(self.connection)

    def _host_allowed(self):
        allowed = self.server.netsentinel_allowed_hosts
        if allowed is None:
            return True
        host = (self.headers.get('Host') or '').strip().lower()
        if host.startswith('['):
            host = host[1:host.find(']')] if ']' in host else host
        else:
            host = host.rsplit(':', 1)[0] if host.count(':') == 1 else host
        if host not in allowed:
            self._send_json({'error': 'unexpected Host header'}, status=421)
            return False
        return True

    def do_GET(self):
        if not self._host_allowed():
            return
        parsed = urlparse(self.path)
        static = self.server.netsentinel_static(parsed.path)
        if static is not None:
            data, content_type, headers = static
            self._send_bytes(data, content_type, 200, headers)
            return
        route = self.server.netsentinel_routes.get(parsed.path)
        if route is None:
            self._send_json({'error': 'not found', 'path': parsed.path}, status=404)
            return
        try:
            params = parse_qs(parsed.query)
            body, content_type = route(params)
        except Exception as e:
            status = getattr(e, 'status', 500)
            if status != 500:   # a ScanError: the request was wrong, not the server
                self._send_json({'error': str(e)}, status=status)
                return
            logger.exception("Error serving %s", parsed.path)
            self._send_json({'error': 'internal error', 'detail': str(e)}, status=500)
            return

        if content_type == 'application/json':
            self._send_json(body)
        else:
            self._send_text(body, content_type)

    def do_POST(self):
        if not self._host_allowed():
            return
        parsed = urlparse(self.path)
        route = self.server.netsentinel_post_routes.get(parsed.path)
        if route is None:
            known = parsed.path in self.server.netsentinel_routes
            self._send_json({'error': 'method not allowed' if known else 'not found',
                             'path': parsed.path}, status=405 if known else 404)
            return
        token = self.headers.get('X-NetSentinel-Token') or ''
        if not hmac.compare_digest(token, self.server.netsentinel_token):
            self._send_json({'error': 'missing or wrong token'}, status=403)
            return
        origin = self.headers.get('Origin')
        if origin and urlparse(origin).netloc.lower() != (self.headers.get('Host') or '').lower():
            self._send_json({'error': 'cross-origin request refused'}, status=403)
            return
        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            length = -1
        if length < 0:
            self._send_json({'error': 'bad Content-Length'}, status=400)
            return
        try:
            payload, status = route(parse_qs(parsed.query), self.rfile, length)
        except Exception as e:
            status = getattr(e, 'status', 500)
            if status == 500:
                logger.exception("Error serving POST %s", parsed.path)
            self._send_json({'error': str(e)}, status=status)
            return
        self._send_json(payload, status=status)

    def _send_json(self, payload, status=200):
        self._send_bytes(json.dumps(payload, indent=2, default=str).encode(),
                         'application/json', status)

    def _send_text(self, text, content_type='text/plain; charset=utf-8', status=200):
        self._send_bytes(text.encode('utf-8'), content_type, status)

    def _send_bytes(self, data, content_type, status, headers=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(data)))
        # This serves captured credentials and device inventory. Nothing should
        # cache it, and no page should be able to frame or script against it.
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()
        self.wfile.write(data)


class HeadlessServer:
    """Serves a running NetSentinelApp to the browser, with controls on loopback."""

    def __init__(self, app, host='127.0.0.1', port=DEFAULT_PORT):
        self.app = app
        self.host = host
        self.port = port
        self._httpd = None
        self._thread = None
        self.started_at = time.time()
        # Per process: the dashboard page carries it, nothing else can read it.
        self.token = secrets.token_urlsafe(24)
        self._scans = None

        self.routes = {
            '/status.txt': self._route_index,
            '/health': self._route_health,
            '/api/overview': self._route_overview,
            '/api/scan': self._route_scan,
            '/api/status': self._route_status,
            '/api/alerts': self._route_alerts,
            '/api/incidents': self._route_incidents,
            '/api/devices': self._route_devices,
            '/api/metrics': self._route_metrics,
            '/api/audit': self._route_audit,
            '/api/scan/ignored': self._route_scan_ignored,
        }
        self.post_routes = {
            '/api/scan/new': self._post_scan_new,
            '/api/scan/upload': self._post_scan_upload,
            '/api/scan/upload-batch': self._post_scan_upload_batch,
            '/api/scan/start': self._post_scan_start,
            '/api/scan/cancel': self._post_scan_cancel,
            '/api/monitoring/start': self._post_monitoring_start,
            '/api/monitoring/stop': self._post_monitoring_stop,
            '/api/alerts/ack': self._post_alert_ack,
            '/api/alerts/ack-all': self._post_alerts_ack_all,
            '/api/alerts/verdict': self._post_alert_verdict,
            '/api/review/bundle': self._post_review_bundle,
            '/api/audit/start': self._post_audit_start,
            '/api/audit/cancel': self._post_audit_cancel,
            '/api/scan/ignore': self._post_scan_ignore,
            '/api/scan/unignore': self._post_scan_unignore,
        }

    @property
    def controls_allowed(self):
        return self.host in LOOPBACK_NAMES

    @property
    def url(self):
        host = '127.0.0.1' if self.host in ('0.0.0.0', '::', '') else self.host
        return f"http://{'[' + host + ']' if ':' in host else host}:{self.port}/"

    # ─── Lifecycle ───────────────────────────────────────────────────────

    def start(self, fallback=False):
        """Listen; with fallback, take any free port if the configured one is in use."""
        if self._httpd is not None:
            return self.port

        if self.host not in ('127.0.0.1', 'localhost', '::1'):
            logger.warning(
                "API bound to %s — this exposes captured credentials, device "
                "inventory and alert history to anyone who can reach this host. "
                "Put it behind a firewall or a reverse proxy with authentication.",
                self.host)

        try:
            self._httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
        except OSError:
            if not fallback:
                raise
            logger.info("Port %d is in use; letting the OS choose one.", self.port)
            self._httpd = ThreadingHTTPServer((self.host, 0), _Handler)
        self._httpd.netsentinel_routes = self.routes
        self._httpd.netsentinel_post_routes = self.post_routes
        self._httpd.netsentinel_static = self._static
        self._httpd.netsentinel_token = self.token
        self._httpd.netsentinel_allowed_hosts = (
            LOOPBACK_NAMES if self.host in LOOPBACK_NAMES else None)
        self._httpd.daemon_threads = True
        # Port 0 asks the OS to choose; report what it actually gave us.
        self.port = self._httpd.server_address[1]

        # serve_forever polls for the shutdown flag every 0.5s by default, which
        # makes stop() take that long. A tighter interval costs nothing here and
        # keeps shutdown responsive.
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={'poll_interval': 0.05},
            daemon=True, name="HeadlessAPI")
        self._thread.start()
        logger.info("API listening on http://%s:%d", self.host, self.port)
        return self.port

    def stop(self):
        if self._httpd is None:
            return
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._httpd = None
        self._thread = None
        if self._scans is not None:
            self._scans.close()
        logger.info("API stopped.")

    # ─── Dashboard ───────────────────────────────────────────────────────

    def _static(self, path):
        """(bytes, content type, headers) for the dashboard's files, else None."""
        if path in ('/', '/index.html'):
            with open(os.path.join(WEBUI_DIR, 'index.html'), encoding='utf-8') as f:
                page = f.read()
            page = page.replace('__NETSENTINEL_TOKEN__', self.token)
            page = page.replace('__NETSENTINEL_VERSION__', __version__)
            return (page.encode('utf-8'), 'text/html; charset=utf-8',
                    {'Content-Security-Policy': DASHBOARD_CSP})
        entry = STATIC_FILES.get(path)
        if entry is None:
            return None
        with open(os.path.join(WEBUI_DIR, entry[0]), 'rb') as f:
            return f.read(), entry[1], {}

    def _route_overview(self, params):
        data = self.app.get_dashboard_data()
        cap = data.get('capture', {})
        alerts = data.get('alerts', {})
        ml = data.get('ml', {})
        score = (data.get('ml_result') or {}).get('anomaly_score', 0) or 0
        label, colour = presentation.threat_level(score)
        devices = data.get('device_learner', {})
        start = cap.get('start_time') or 0
        talkers = presentation.top_talkers(cap.get('top_talkers'), limit=8)
        geo = getattr(getattr(self.app, 'ids_engine', None), 'geoip', None)
        if geo is not None:
            talkers_out = geo.annotate_talkers(talkers)
        else:
            talkers_out = [{'ip': ip, 'bytes': b} for ip, b in talkers]
        return {
            'version': __version__,
            'monitoring': bool(data.get('is_monitoring')),
            'controls': self.controls_allowed,
            'uptime_sec': int(time.time() - start) if start and data.get('is_monitoring') else 0,
            'capture': {k: cap.get(k, 0) for k in (
                'packets_captured', 'bytes_captured', 'packets_per_sec', 'bytes_per_sec',
                'flows_active', 'packets_dropped', 'sample_rate', 'packets_sampled_out')},
            'resources': data.get('resources') or {'available': False},
            'review': data.get('review') or {'enabled': False},
            'suppressed_alerts': data.get('suppressed_alerts', 0),
            'alerts': {
                'total': alerts.get('total', 0),
                'unacknowledged': alerts.get('unacknowledged', 0),
                'per_minute': alerts.get('alerts_per_minute', 0),
                'by_severity': alerts.get('by_severity', {}),
            },
            'threat': {'label': label, 'colour': colour, 'score': round(float(score), 4)},
            'protocols': [{'name': n, 'count': c, 'fraction': round(f, 4)}
                          for n, c, f in presentation.protocol_breakdown(cap.get('protocols'))],
            'top_talkers': talkers_out,
            # CC BY 4.0: DB-IP must be credited wherever its data is shown.
            'geoip_attribution': geo.get_stats()['attribution'] if geo is not None else None,
            'devices': {'total': devices.get('total_devices', 0),
                        'active_last_hour': devices.get('active_last_hour', 0)},
            'incidents_active': data.get('correlator', {}).get('active_incidents', 0),
            'ml': {'is_trained': bool(ml.get('is_trained')),
                   'baseline_samples': ml.get('baseline_samples', 0)},
        }, 'application/json'

    # ─── File scans ──────────────────────────────────────────────────────

    def _scan_sessions(self):
        if self._scans is None:
            from src.web_scan import ScanSessions
            self._scans = ScanSessions(self._make_analyzer)
        return self._scans

    def _make_analyzer(self):
        """A PcapAnalyzer of the scan's own, so it never clobbers the GUI's results."""
        from src.pcap_analyzer import PcapAnalyzer
        app = self.app
        return PcapAnalyzer(
            app.config,
            **{name: getattr(app, name, None) for name in (
                'ids_engine', 'threat_intel', 'ioc_scanner', 'alert_verifier',
                'net_env', 'forensics_db')})

    def _route_scan(self, params):
        return self._scan_sessions().get(_str_param(params, 'id')), 'application/json'

    def _post_scan_new(self, params, body, length):
        return self._scan_sessions().create(), 201

    def _post_scan_upload(self, params, body, length):
        name = _str_param(params, 'name') or 'upload'
        stored = self._scan_sessions().add_file(_str_param(params, 'id'), name, body, length)
        return {'stored': stored}, 201

    def _post_scan_upload_batch(self, params, body, length):
        stored = self._scan_sessions().add_batch(_str_param(params, 'id'), body, length)
        return {'stored': stored}, 201

    def _post_scan_start(self, params, body, length):
        return self._scan_sessions().start(_str_param(params, 'id')), 202

    def _post_scan_cancel(self, params, body, length):
        return self._scan_sessions().cancel(_str_param(params, 'id')), 200

    def _route_scan_ignored(self, params):
        return {'ignored': self._scan_sessions().ignored()}, 'application/json'

    def _post_scan_ignore(self, params, body, length):
        """A JSON body, {"finding": {...from a report...}, "note": "..."}."""
        if not self.controls_allowed:
            self._control(0)                       # raises the loopback refusal
        if not 0 < length <= 64 * 1024:
            raise RequestRefused('Send the finding as a small JSON body.', 400)
        try:
            data = json.loads(body.read(length).decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            raise RequestRefused('That was not JSON.', 400) from None
        if not isinstance(data, dict):
            raise RequestRefused('Send a JSON object.', 400)
        self._scan_sessions().ignore(data.get('finding'), str(data.get('note', ''))[:200])
        return {'ignored': True}, 201

    def _post_scan_unignore(self, params, body, length):
        self._control(length)
        self._scan_sessions().unignore(_str_param(params, 'id'))
        return {'removed': True}, 200

    # ─── Controls ────────────────────────────────────────────────────────

    def _control(self, length):
        if not self.controls_allowed:
            raise RequestRefused(
                'Controls are only available while the dashboard is bound to '
                'localhost. Use the desktop app, or the machine itself.')
        if length:
            raise RequestRefused('This request takes no body.', 400)

    def _post_monitoring_start(self, params, body, length):
        self._control(length)
        if not self.app.start_monitoring():
            raise RequestRefused(
                getattr(self.app, 'last_start_error', '') or 'Monitoring did not start.',
                503)
        return {'monitoring': True}, 200

    def _post_monitoring_stop(self, params, body, length):
        self._control(length)
        self.app.stop_monitoring()
        return {'monitoring': False}, 200

    def _post_alert_ack(self, params, body, length):
        self._control(length)
        try:
            alert_id = int(_str_param(params, 'id') or '')
        except ValueError:
            raise RequestRefused('Which alert? Pass ?id=.', 400) from None
        if not self.app.alert_manager.acknowledge_alert(alert_id):
            raise RequestRefused('No alert with that id.', 404)
        return {'acknowledged': alert_id}, 200

    def _post_alerts_ack_all(self, params, body, length):
        self._control(length)
        self.app.alert_manager.acknowledge_all()
        return {'acknowledged': 'all'}, 200

    def _post_alert_verdict(self, params, body, length):
        """?id=&verdict=real|false_positive. A false positive stops that rule for that subject."""
        self._control(length)
        try:
            alert_id = int(_str_param(params, 'id') or '')
        except ValueError:
            raise RequestRefused('Which alert? Pass ?id=.', 400) from None
        verdict = _str_param(params, 'verdict')
        try:
            entry = self.app.record_verdict(alert_id, verdict)
        except KeyError:
            raise RequestRefused('No alert with that id.', 404) from None
        except ValueError:
            raise RequestRefused('verdict must be real or false_positive.', 400) from None
        except LookupError as e:
            raise RequestRefused(str(e), 409) from None
        return {'id': alert_id, 'verdict': verdict,
                'suppressing': entry and {'rule_id': entry['rule_id'], 'kind': entry['kind'],
                                          'value': entry['value']}}, 200

    # ─── Network audit ───────────────────────────────────────────────────

    def _route_audit(self, params):
        """What the Audit page needs: whether audits are on, the choices, the job."""
        from src import audit
        config = self.app.config
        job = audit.current_job()
        status = job.status() if job is not None else None
        report = job.report if job is not None and status['state'] in ('done', 'cancelled') else None
        return {
            'enabled': bool(config.get('audit', 'enabled', default=False)),
            'controls': self.controls_allowed,
            'choices': audit.local_networks(),
            'saved': audit.saved_networks(config),
            'job': status,
            'report': report,
        }, 'application/json'

    def _post_audit_start(self, params, body, length):
        """?network=CIDR (repeatable)&gentle=1. Audits are enabled in the desktop app."""
        self._control(length)
        from src import audit
        networks = [n for n in params.get('network', []) if n.strip()]
        gentle = (_str_param(params, 'gentle') or '') in ('1', 'true', 'yes')
        try:
            job = audit.start_audit(networks, gentle=gentle, config=self.app.config)
        except audit.AuditDisabled:
            raise RequestRefused(
                'Network audits are off. Turn them on in the desktop app: '
                'Settings → Network audit.', 403) from None
        except audit.AuditBusy as e:
            raise RequestRefused(str(e), 409) from None
        except audit.ScopeError as e:
            raise RequestRefused(str(e), 400) from None
        return job.status(), 202

    def _post_audit_cancel(self, params, body, length):
        self._control(length)
        from src import audit
        job = audit.current_job()
        if job is None:
            raise RequestRefused('No audit is running.', 409)
        job.cancel()
        return job.status(), 200

    def _post_review_bundle(self, params, body, length):
        self._control(length)
        try:
            result = self.app.build_review_bundle()
        except FileNotFoundError as e:
            raise RequestRefused(str(e), 409) from None
        return result, 201

    # ─── Routes ──────────────────────────────────────────────────────────

    def _route_index(self, params):
        data = self.app.get_dashboard_data()
        cap = data.get('capture', {})
        alerts = data.get('alerts', {})
        ml = data.get('ml', {})
        by_sev = alerts.get('by_severity', {})
        # Computed out of line: a multi-line expression inside an f-string needs
        # Python 3.12, and this project supports 3.10.
        threat = presentation.threat_level(
            data.get('ml_result', {}).get('anomaly_score', 0))[0]

        lines = [
            "NetSentinel — headless",
            "=" * 46,
            f"Uptime          {presentation.format_duration(time.time() - self.started_at)}",
            f"Monitoring      {'yes' if data.get('is_monitoring') else 'no'}",
            "",
            "Capture",
            f"  Packets       {presentation.format_number(cap.get('packets_captured', 0))}",
            f"  Rate          {cap.get('packets_per_sec', 0):.0f} pkt/s",
            f"  Bandwidth     {presentation.format_bytes(cap.get('bytes_per_sec', 0))}/s",
            f"  Flows         {cap.get('flows_active', 0)}",
            f"  Dropped       {presentation.format_number(cap.get('packets_dropped', 0))}",
            "",
            "Detection",
            f"  Alerts        {alerts.get('total', 0)} "
            f"(critical {by_sev.get('CRITICAL', 0)}, high {by_sev.get('HIGH', 0)})",
            f"  Unacked       {alerts.get('unacknowledged', 0)}",
            f"  Incidents     {data.get('correlator', {}).get('active_incidents', 0)}",
            f"  Devices       {data.get('device_learner', {}).get('total_devices', 0)}",
            "",
            "ML",
            f"  Trained       {'yes' if ml.get('is_trained') else 'no'}",
            f"  Baseline      {ml.get('baseline_samples', 0)} samples",
            f"  Threat level  {threat}",
            "",
            f"Dashboard: {self.url}",
            "Endpoints: " + "  ".join(sorted(self.routes)),
        ]
        return "\n".join(lines) + "\n", 'text/plain; charset=utf-8'

    def _route_health(self, params):
        running = bool(self.app.capture_engine.is_running)
        return {
            'status': 'ok' if running else 'idle',
            'monitoring': running,
            'uptime_sec': int(time.time() - self.started_at),
        }, 'application/json'

    def _route_status(self, params):
        data = self.app.get_dashboard_data()
        # score_history is a per-second time series; too large for a status call.
        data.pop('score_history', None)
        return data, 'application/json'

    def _route_alerts(self, params):
        limit = _int_param(params, 'limit', default=50, maximum=MAX_ALERT_LIMIT)
        severity = _str_param(params, 'severity')
        category = _str_param(params, 'category')

        alerts = self.app.alert_manager.get_alerts(limit=MAX_ALERT_LIMIT)
        alerts = presentation.filter_alerts(alerts, severity=severity, category=category)
        alerts = presentation.sort_alerts(alerts)[:limit]
        return {
            'count': len(alerts),
            'counts_by_severity': presentation.summarise_alert_counts(alerts),
            'alerts': [a.to_dict() for a in alerts],
        }, 'application/json'

    def _route_incidents(self, params):
        limit = _int_param(params, 'limit', default=25, maximum=200)
        correlator = self.app.alert_correlator
        incidents = []
        for incident in list(getattr(correlator, '_all_incidents', []))[-limit:]:
            to_dict = getattr(incident, 'to_dict', None)
            incidents.append(to_dict() if to_dict else str(incident))
        incidents.reverse()
        return {
            'count': len(incidents),
            'stats': correlator.get_stats(),
            'incidents': incidents,
        }, 'application/json'

    def _route_devices(self, params):
        return self.app.device_learner.get_summary(), 'application/json'

    def _route_metrics(self, params):
        """Prometheus text exposition, so this can be scraped like anything else."""
        data = self.app.get_dashboard_data()
        cap = data.get('capture', {})
        alerts = data.get('alerts', {})
        ml = data.get('ml', {})
        by_sev = alerts.get('by_severity', {})

        lines = []

        def metric(name, value, help_text, kind='gauge', labels=''):
            lines.append(f"# HELP netsentinel_{name} {help_text}")
            lines.append(f"# TYPE netsentinel_{name} {kind}")
            lines.append(f"netsentinel_{name}{labels} {value}")

        metric('up', 1 if self.app.capture_engine.is_running else 0,
               'Whether packet capture is running.')
        metric('packets_captured_total', int(cap.get('packets_captured', 0)),
               'Packets observed since start.', 'counter')
        metric('packets_dropped_total', int(cap.get('packets_dropped', 0)),
               'Packets dropped before analysis.', 'counter')
        metric('bytes_captured_total', int(cap.get('bytes_captured', 0)),
               'Bytes observed since start.', 'counter')
        metric('packets_per_second', round(cap.get('packets_per_sec', 0), 2),
               'Current packet rate.')
        metric('flows_active', int(cap.get('flows_active', 0)),
               'Flows currently tracked.')
        metric('alerts_total', int(alerts.get('total', 0)),
               'Alerts raised since start.', 'counter')
        metric('alerts_unacknowledged', int(alerts.get('unacknowledged', 0)),
               'Alerts not yet acknowledged.')

        lines.append("# HELP netsentinel_alerts_by_severity Alerts by severity.")
        lines.append("# TYPE netsentinel_alerts_by_severity counter")
        for level in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            lines.append(f'netsentinel_alerts_by_severity{{severity="{level}"}} '
                         f'{int(by_sev.get(level, 0))}')

        metric('incidents_active', int(data.get('correlator', {}).get('active_incidents', 0)),
               'Correlated incidents currently open.')
        metric('devices_known', int(data.get('device_learner', {}).get('total_devices', 0)),
               'Devices discovered on the local network.')
        metric('ml_trained', 1 if ml.get('is_trained') else 0,
               'Whether the anomaly model has been trained.')
        metric('ml_baseline_samples', int(ml.get('baseline_samples', 0)),
               'Samples in the statistical baseline.')
        metric('anomaly_score', round(data.get('ml_result', {}).get('anomaly_score', 0), 4),
               'Most recent combined anomaly score.')
        metric('uptime_seconds', int(time.time() - self.started_at),
               'Seconds since the API started.')
        metric('capture_sample_rate', int(cap.get('sample_rate', 1) or 1),
               'Under load, 1 in this many packets is analysed (1 = all).')
        res = data.get('resources') or {}
        if res.get('available'):
            metric('process_cpu_percent', res['cpu_percent'],
                   "This process's share of the machine's CPU.")
            metric('process_resident_memory_bytes', int(res['rss_bytes']),
                   'Resident memory of this process.')

        return "\n".join(lines) + "\n", 'text/plain; version=0.0.4; charset=utf-8'


def _int_param(params, name, default, maximum):
    values = params.get(name)
    if not values:
        return default
    try:
        return max(1, min(int(values[0]), maximum))
    except (TypeError, ValueError):
        return default


def _str_param(params, name):
    values = params.get(name)
    if not values or not values[0]:
        return None
    return values[0].strip().upper() if name == 'severity' else values[0].strip()


def run_headless(app, host='127.0.0.1', port=DEFAULT_PORT, serve_api=True):
    """
    Start monitoring with no GUI and block until interrupted.

    Returns the exit code the process should use.
    """
    server = None
    try:
        if not app.start_monitoring():
            logger.error(
                "%s Packet capture needs Administrator on Windows, root or "
                "CAP_NET_RAW on Linux.",
                getattr(app, 'last_start_error', '') or "Capture failed to start.")
            return 1

        if serve_api:
            server = HeadlessServer(app, host=host, port=port)
            server.start()
            logger.info("Dashboard: %s  Metrics: %sapi/metrics", server.url, server.url)

        logger.info("Running headless. Press Ctrl-C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Interrupted — shutting down.")
        return 0
    finally:
        if server is not None:
            server.stop()
        try:
            app.stop_monitoring()
        except Exception as e:
            logger.error("Error during shutdown: %s", e)
