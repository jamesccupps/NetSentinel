"""
Headless mode.
==============
Runs the detection engine with no GUI and exposes its state over HTTP, so
NetSentinel can live on a Raspberry Pi hanging off a SPAN port instead of only
on the desktop it is watching.

This needed almost no new code. `NetSentinelApp` never imported tkinter outside
`run()`, and the last piece of display logic moved to `presentation.py`, so the
engine was already headless — it simply had no way to be started or read without
a window.

Design notes
------------
**Read-only.** Every endpoint is a GET. There is no way to change configuration,
acknowledge an alert or stop monitoring through this API. A sensor that can be
reconfigured over the network is a liability, and the failure modes of getting
authentication wrong are worse than the inconvenience of editing config.json.

**Localhost by default.** The output contains captured credentials, device
inventory and alert history. Binding to 0.0.0.0 requires saying so explicitly,
and logs a warning when you do.

**stdlib only.** `http.server` rather than Flask or FastAPI, because adding a web
framework to a security tool's dependency tree to serve six JSON endpoints is a
bad trade.

Endpoints
---------
    GET /                 human-readable status summary
    GET /health           liveness, for a supervisor or container probe
    GET /api/status       capture, IDS, ML and alert counters
    GET /api/alerts       recent alerts, ?limit= and ?severity=
    GET /api/incidents    correlated incidents
    GET /api/devices      discovered devices on the local network
    GET /api/metrics      Prometheus text exposition
"""

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from src import presentation

logger = logging.getLogger("NetSentinel.Headless")

__all__ = ['HeadlessServer', 'run_headless']

# Anything above this is almost certainly a mistake rather than a request.
MAX_ALERT_LIMIT = 1000


class _Handler(BaseHTTPRequestHandler):
    """Routes are resolved against the table in HeadlessServer."""

    server_version = "NetSentinel"
    sys_version = ""          # Do not advertise the Python version.

    # BaseHTTPRequestHandler logs every request to stderr by default.
    def log_message(self, fmt, *args):
        logger.debug("%s - %s", self.address_string(), fmt % args)

    def do_GET(self):
        parsed = urlparse(self.path)
        route = self.server.netsentinel_routes.get(parsed.path)
        if route is None:
            self._send_json({'error': 'not found', 'path': parsed.path}, status=404)
            return
        try:
            params = parse_qs(parsed.query)
            body, content_type = route(params)
        except Exception as e:
            logger.exception("Error serving %s", parsed.path)
            self._send_json({'error': 'internal error', 'detail': str(e)}, status=500)
            return

        if content_type == 'application/json':
            self._send_json(body)
        else:
            self._send_text(body, content_type)

    def _send_json(self, payload, status=200):
        self._send_bytes(json.dumps(payload, indent=2, default=str).encode(),
                         'application/json', status)

    def _send_text(self, text, content_type='text/plain; charset=utf-8', status=200):
        self._send_bytes(text.encode('utf-8'), content_type, status)

    def _send_bytes(self, data, content_type, status):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        # This serves captured credentials and device inventory. Nothing should
        # cache it, and no page should be able to frame or script against it.
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()
        self.wfile.write(data)


class HeadlessServer:
    """Serves a read-only view of a running NetSentinelApp."""

    def __init__(self, app, host='127.0.0.1', port=8787):
        self.app = app
        self.host = host
        self.port = port
        self._httpd = None
        self._thread = None
        self.started_at = time.time()

        self.routes = {
            '/': self._route_index,
            '/health': self._route_health,
            '/api/status': self._route_status,
            '/api/alerts': self._route_alerts,
            '/api/incidents': self._route_incidents,
            '/api/devices': self._route_devices,
            '/api/metrics': self._route_metrics,
        }

    # ─── Lifecycle ───────────────────────────────────────────────────────

    def start(self):
        if self._httpd is not None:
            return self.port

        if self.host not in ('127.0.0.1', 'localhost', '::1'):
            logger.warning(
                "API bound to %s — this exposes captured credentials, device "
                "inventory and alert history to anyone who can reach this host. "
                "Put it behind a firewall or a reverse proxy with authentication.",
                self.host)

        self._httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
        self._httpd.netsentinel_routes = self.routes
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
        logger.info("API stopped.")

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


def run_headless(app, host='127.0.0.1', port=8787, serve_api=True):
    """
    Start monitoring with no GUI and block until interrupted.

    Returns the exit code the process should use.
    """
    server = None
    try:
        if not app.start_monitoring():
            logger.error(
                "Capture failed to start. Check that this process has the "
                "privileges required for packet capture (Administrator on "
                "Windows, root or CAP_NET_RAW on Linux).")
            return 1

        if serve_api:
            server = HeadlessServer(app, host=host, port=port)
            server.start()
            logger.info("Status: http://%s:%d/  Metrics: http://%s:%d/api/metrics",
                        host, server.port, host, server.port)

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
