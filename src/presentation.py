"""
Presentation logic.
===================
Pure functions for turning engine output into something a person reads: number
formatting, threat-level thresholds, protocol bar proportions, alert filtering and
sorting.

These lived inside `gui.py` methods, interleaved with widget calls, which meant
1,772 statements of the codebase could not be tested at all — the one module the
audit could not cover. Nothing here imports tkinter, so it is testable on a
headless machine and reusable by anything that is not the tkinter GUI: a web
dashboard, a CLI summary, a report generator.

Everything here is a pure function of its arguments. No I/O, no globals, no
widgets.
"""

from datetime import datetime

__all__ = [
    'SEVERITY_ORDER', 'THREAT_LEVELS',
    'format_bytes', 'format_number', 'format_rate', 'format_duration',
    'format_timestamp', 'threat_level', 'severity_rank', 'severity_at_least',
    'protocol_breakdown', 'filter_alerts', 'sort_alerts', 'top_talkers',
    'summarise_alert_counts', 'truncate_middle',
    'endpoint', 'vault_rows', 'find_vault_entry', 'VAULT_ROWS_SHOWN',
]

SEVERITY_ORDER = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}

# (minimum score, label, colour key). Checked high to low.
THREAT_LEVELS = (
    (0.7, 'CRITICAL', 'red'),
    (0.4, 'ELEVATED', 'orange'),
    (0.2, 'GUARDED', 'yellow'),
    (0.0, 'SAFE', 'green'),
)


# ─── Formatting ──────────────────────────────────────────────────────────────

def format_bytes(value):
    """Human-readable byte count. Handles negatives and non-numerics."""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return '—'
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if abs(value) < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def format_number(value):
    """Compact count: 1234 -> '1.2K'."""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return '—'
    if abs(value) >= 1_000_000_000:
        return f"{value / 1_000_000_000:.1f}B"
    if abs(value) >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if abs(value) >= 1_000:
        return f"{value / 1_000:.1f}K"
    return str(int(value))


def format_rate(value, unit='/s'):
    return f"{format_bytes(value)}{unit}"


def format_duration(seconds):
    """Uptime as '3d 4h 5m', '4h 5m' or '5m'."""
    try:
        seconds = max(0, int(seconds))
    except (TypeError, ValueError):
        return '—'
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def format_timestamp(ts, fmt='%H:%M:%S'):
    try:
        return datetime.fromtimestamp(float(ts)).strftime(fmt)
    except (TypeError, ValueError, OSError, OverflowError):
        return '—'


def truncate_middle(text, limit=40):
    """Shorten from the middle so both ends stay readable (paths, domains)."""
    text = str(text)
    if len(text) <= limit or limit < 5:
        return text
    keep = limit - 1
    head = (keep + 1) // 2
    tail = keep // 2
    return f"{text[:head]}…{text[-tail:]}" if tail else f"{text[:head]}…"


# ─── Severity ────────────────────────────────────────────────────────────────

def severity_rank(severity):
    return SEVERITY_ORDER.get(str(severity).upper(), 0)


def severity_at_least(severity, minimum):
    return severity_rank(severity) >= severity_rank(minimum)


def threat_level(score):
    """Map an anomaly score to (label, colour_key)."""
    try:
        score = float(score)
    except (TypeError, ValueError):
        score = 0.0
    for threshold, label, colour in THREAT_LEVELS:
        if score > threshold:
            return label, colour
    return THREAT_LEVELS[-1][1], THREAT_LEVELS[-1][2]


# ─── Aggregation ─────────────────────────────────────────────────────────────

def protocol_breakdown(protocols, limit=8):
    """
    Protocol counts to [(name, count, fraction)], largest first.

    Fractions always sum to <= 1.0 and are computed against the *full* total, not
    the truncated one, so a bar chart of the top N does not overstate them.
    """
    if not protocols:
        return []
    total = sum(protocols.values())
    if total <= 0:
        return []
    ordered = sorted(protocols.items(), key=lambda kv: (-kv[1], kv[0]))
    return [(name, count, count / total) for name, count in ordered[:limit]]


def top_talkers(talkers, limit=10):
    """Byte counts per address to [(address, bytes)], largest first."""
    if not talkers:
        return []
    return sorted(talkers.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]


def filter_alerts(alerts, severity=None, category=None, since=None,
                  acknowledged=None, search=None):
    """
    Apply display filters. `severity` is an exact match, matching the GUI dropdown;
    use severity_at_least for a threshold.
    """
    result = list(alerts)
    if severity and severity != 'ALL':
        result = [a for a in result if _get(a, 'severity') == severity]
    if category and category != 'ALL':
        result = [a for a in result if _get(a, 'category') == category]
    if since is not None:
        result = [a for a in result if (_get(a, 'timestamp') or 0) >= since]
    if acknowledged is not None:
        result = [a for a in result if bool(_get(a, 'acknowledged')) is acknowledged]
    if search:
        needle = search.lower()
        result = [a for a in result if needle in _searchable(a)]
    return result


def sort_alerts(alerts, key='time', newest_first=True):
    """Sort by 'time' or 'severity'. Severity ties break on recency."""
    if key == 'severity':
        return sorted(alerts,
                      key=lambda a: (severity_rank(_get(a, 'severity')),
                                     _get(a, 'timestamp') or 0),
                      reverse=True)
    return sorted(alerts, key=lambda a: _get(a, 'timestamp') or 0,
                  reverse=newest_first)


def summarise_alert_counts(alerts):
    """Counts by severity, always including every level so the UI shape is stable."""
    counts = {level: 0 for level in SEVERITY_ORDER}
    for alert in alerts:
        sev = str(_get(alert, 'severity') or '').upper()
        if sev in counts:
            counts[sev] += 1
    counts['TOTAL'] = len(alerts)
    return counts


def _get(alert, field):
    """Read a field from either an Alert object or its to_dict() form."""
    if isinstance(alert, dict):
        return alert.get(field)
    return getattr(alert, field, None)


def _searchable(alert):
    parts = [_get(alert, f) for f in
             ('title', 'description', 'src_ip', 'dst_ip', 'category', 'rule_id')]
    return ' '.join(str(p) for p in parts if p).lower()


# ─── Addresses and the forensics vault ───────────────────────────────────────

def endpoint(ip, port):
    """'ip:port', or the address alone when the port is not known (0 or none):
    an alert's detail showed a BACnet device's source as 'address:0'."""
    if not ip:
        return ''
    return f"{ip}:{port}" if port not in (None, '', 0, '0') else str(ip)


# The vault table shows this many, newest first; search finds the rest. It drew
# every entry as its own row of widgets, and a building network's thousands
# made the desktop window slow to open and stall on every scroll.
VAULT_ROWS_SHOWN = 2000


def vault_rows(credentials, limit=VAULT_ROWS_SHOWN):
    """(the newest `limit` vault entries, newest first; how many there are)."""
    rows = sorted(credentials, key=lambda c: c.get('timestamp') or 0, reverse=True)
    return rows[:limit], len(rows)


def find_vault_entry(credentials, protocol, server, port, client='', credential_type=''):
    """
    The vault entry an alert or exposure is about, or None: one with the same
    protocol, server and port, preferring the same client and kind of
    credential, then the newest. Matched on what the alert carries, since
    alerts never had the vault entry's id.
    """
    def same(a, b):
        return str(a or '') == str(b or '')

    def port_of(value):
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    matches = [c for c in credentials
               if same(c.get('protocol'), protocol) and same(c.get('destination_ip'), server)
               and port_of(c.get('port')) == port_of(port)]
    if not matches:
        return None
    return max(matches, key=lambda c: (
        bool(client) and same(c.get('source_ip'), client),
        bool(credential_type) and same(c.get('credential_type'), credential_type),
        c.get('timestamp') or 0))
