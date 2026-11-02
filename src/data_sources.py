"""
Threat data: every source NetSentinel matches against, and whether it is in use.
================================================================================
One list for the dashboard's Threat data page and the desktop app's Threat data
window. Downloaded feeds say when they last updated and why they are not in use
when they are not; the files that ship with the app say so, since they change
only with a release.

Row shape: name, description, category, state, note, updated (epoch seconds, a
date string, or None), entries, refresh_hours (None for bundled data).
States: ok, stale, needs key, off, failed, waiting, bundled.
"""

import json
import logging
import os
import sys
from datetime import datetime

logger = logging.getLogger("NetSentinel.DataSources")


def collect(app):
    """Every source's row, downloaded feeds first."""
    rows = []
    intel = getattr(app, 'threat_intel', None)
    if intel is not None:
        try:
            rows.extend(intel.feed_status())
        except Exception as e:
            logger.debug("Threat feed status unavailable: %s", e)
    vulns = getattr(app, 'vulns', None)
    if vulns is not None:
        try:
            rows.extend(vulns.status())
        except Exception as e:
            logger.debug("Vulnerability data status unavailable: %s", e)
    for name in ('unifi', 'syslog'):
        part = getattr(app, name, None)
        if part is not None:
            try:
                rows.append(part.status())
            except Exception as e:
                logger.debug("%s status unavailable: %s", name, e)
    rows.append(_geoip(app))
    rows.append(_hash_lists())
    rows.extend(_bundled())
    return rows


def when(updated):
    """A row's updated value for display."""
    if not updated:
        return ''
    if isinstance(updated, (int, float)):
        return datetime.fromtimestamp(updated).strftime('%Y-%m-%d %H:%M')
    return str(updated)


def _geoip(app):
    geo = getattr(getattr(app, 'ids_engine', None), 'geoip', None)
    row = {'name': 'dbip_geoip', 'description': 'DB-IP Lite - Country and network of addresses',
           'category': 'Location', 'state': 'off', 'updated': None, 'entries': 0,
           'refresh_hours': 24 * 30,
           'note': 'Off in settings (geoip.enabled). CC BY 4.0, DB-IP.'}
    if geo is None or not geo.enabled:
        return row
    stats = geo.get_stats()
    if stats.get('available'):
        try:
            row['updated'] = max(os.path.getmtime(geo._path(k)) for k in stats['databases'])
        except (OSError, ValueError):
            pass
        row.update(state='ok', note=stats.get('attribution', ''))
    else:
        row.update(state='waiting', note=stats.get('last_error') or 'Not downloaded yet.')
    return row


def _hash_lists():
    """The hash list files, named and sized but not read: MalwareBazaar's full
    list is 80 MB, and this runs on the GUI thread and every 30 seconds for the
    dashboard. The downloaded ones count their entries on their own rows."""
    from src import hash_feed
    folder = hash_feed.default_folder()
    files = []
    try:
        for name in sorted(os.listdir(folder)):
            if name.lower().endswith(hash_feed._LIST_EXTS):
                files.append((name, os.path.getsize(os.path.join(folder, name))))
    except OSError:
        pass
    total = sum(size for _, size in files)
    return {'name': 'hash_lists', 'description': 'Known-bad file hashes, for file scans',
            'category': 'Malware', 'state': 'ok' if files else 'waiting',
            'updated': None, 'entries': 0, 'refresh_hours': None,
            'note': (f"{len(files)} list{'s' if len(files) != 1 else ''}, "
                     f"{total / 1048576:.1f} MB: " + ', '.join(n for n, _ in files)
                     if files else
                     f"No lists yet: MalwareBazaar's downloads with an abuse.ch key, "
                     f"or files of SHA-256 values in {folder}.")}


def _bundled():
    """Files that ship with NetSentinel and change only with a release."""
    from src import __version__
    from src.cloud_ranges import get_cloud_ranges
    rows = []
    try:
        ranges = get_cloud_ranges()
        rows.append({'name': 'cloud_ranges', 'category': 'Shared infrastructure',
                     'description': 'Cloud and CDN address ranges (not counted as attackers)',
                     'state': 'bundled', 'updated': ranges.generated or None,
                     'entries': ranges.prefix_count, 'refresh_hours': None,
                     'note': f'Ships with NetSentinel {__version__}.'})
    except Exception as e:
        logger.debug("Cloud ranges unavailable: %s", e)
    for name, description, count_key in (
            ('mining_pools', 'Cryptocurrency mining pools and Stratum ports', 'domains'),
            ('default_rules', 'IDS rules: ports, TLDs and C2 patterns', None)):
        data = _rule_file(f'{name}.json')
        if data is None:
            continue
        entries = (len(data.get(count_key) or ()) if count_key else
                   sum(len(v) for v in data.values() if isinstance(v, (list, dict))
                       and v is not data.get('metadata')))
        meta = data.get('metadata') if isinstance(data.get('metadata'), dict) else {}
        rows.append({'name': name, 'description': description, 'category': 'Rules',
                     'state': 'bundled', 'updated': data.get('updated') or meta.get('updated'),
                     'entries': entries, 'refresh_hours': None,
                     'note': f'Ships with NetSentinel {__version__}.'})
    return rows


def _rule_file(file_name):
    from src.config import RULES_DIR
    # As ids_engine.load_mining_pools: the user's copy first, then the bundle.
    base = getattr(sys, '_MEIPASS', None) or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for folder in (RULES_DIR, os.path.join(base, 'rules')):
        path = os.path.join(folder, file_name)
        if os.path.exists(path):
            try:
                with open(path, encoding='utf-8') as f:
                    return json.load(f)
            except (OSError, ValueError) as e:
                logger.debug("Rule file %s unreadable: %s", path, e)
    return None
