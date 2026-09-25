"""
UniFi flow CSV importer.
=========================
A day of flow records from the gateway: who talked to whom, how much, and what
the firewall did about it. No payload, which makes it the safest source in the
system and the only one that can cover segments whose payload must never be
stored.

It is also the broadest. A 24-hour all-VLAN export runs to a few hundred
thousand rows and covers every device at once, where a mirror port covers one
switch port at a time.

What the format will do to you
------------------------------
**Semicolon-delimited, 40 columns.** Not comma. A comma-split gives one column
and no error.

**"Bytes Sent" is what the source downloaded; "Bytes Rec." is what it uploaded.**
Read that twice. The labels are from the gateway's point of view, not the
client's, and taking them at face value inverts every upload rule — exfiltration
reads as a download. Verified against a known 406 MB package download, which
appears under "Bytes Sent". This importer maps them to `bytes_to_dst` and
`bytes_to_src`, which say which way the bytes went and cannot be misread.

**The UTC column mixes precisions** within one file, so it is parsed as ISO8601
rather than with a fixed format string.

**"Dst. Domain" is inferred and unreliable.** It mislabels shared addresses —
one CDN name appeared against nearly every device in a sample — and is blank for
long-lived connections. Kept as `domain_hint`, never as `domain`, so no rule can
match on it by accident.

**Byte totals undercount long-lived sessions.** A 24-hour export accounted for
20.8 GB where the gateway's own activity view showed 84.9 GB. Upload rules
should treat these numbers as a floor.

**Traffic the gateway itself sends or receives is absent**, as is any VLAN the
export was not scoped to. Absence of a flow here is not evidence it did not
happen.
"""

from __future__ import annotations

import csv
import datetime
import gzip
import io
import logging
import os

from netmon.events import Event

logger = logging.getLogger("netmon.sources.unifi")

__all__ = ['read_flows', 'parse_row', 'COLUMNS', 'UnifiCsvError']

DELIMITER = ';'


class UnifiCsvError(ValueError):
    """The file is not a UniFi flow export, or is damaged."""


#: The 40 columns, in export order. Used to recognise the format and to say
#: precisely what is missing when a file does not match.
COLUMNS = [
    'UTC Date / Time', 'Date / Time', 'Action', 'Service', 'Protocol',
    'Direction', 'Risk', 'Policy', 'Policy Type', 'Other Policies', 'Category',
    'In', 'Out', 'Src. MAC', 'Src. Ip', 'Src. Port', 'Src. Name',
    'Src. Network', 'Src. Region', 'Src. Zone', 'Dst. Domain', 'Dst. MAC',
    'Dst. Ip', 'Dst. Port', 'Dst. Name', 'Dst. Network', 'Dst. Region',
    'Dst. Zone', 'Signature', 'Signature ID', 'Bytes', 'Bytes Rec.',
    'Bytes Sent', 'Packets', 'Packets Rec.', 'Packets Sent', 'Session Id',
    'Flow Count', 'Query', 'URL',
]

#: Columns whose header text differs between firmware versions. Mapped to the
#: canonical name above so one spelling change does not silently blank a field.
_ALIASES = {
    'src. ip': 'Src. Ip', 'src ip': 'Src. Ip', 'source ip': 'Src. Ip',
    'dst. ip': 'Dst. Ip', 'dst ip': 'Dst. Ip', 'destination ip': 'Dst. Ip',
    'src. mac': 'Src. MAC', 'dst. mac': 'Dst. MAC',
    'bytes rec.': 'Bytes Rec.', 'bytes recv.': 'Bytes Rec.',
    'bytes received': 'Bytes Rec.',
    'utc date / time': 'UTC Date / Time', 'utc date/time': 'UTC Date / Time',
}


def _canonical(header):
    cleaned = (header or '').strip().lstrip('﻿')
    return _ALIASES.get(cleaned.lower(), cleaned)


def _to_int(value):
    """Blank, '-' and malformed all mean zero here; none of them should raise."""
    text = str(value or '').strip().replace(',', '')
    if not text or text == '-':
        return 0
    try:
        return int(float(text))
    except ValueError:
        return 0


def _to_port(value):
    port = _to_int(value)
    return port if 0 < port <= 65535 else None


def parse_timestamp(value):
    """
    Parse the UTC column, whose precision varies within a single file.

    fromisoformat handles most of it on modern Pythons; the fallbacks cover a
    trailing Z and the space-separated form. Returns 0.0 rather than raising,
    because one unparseable row should not abandon the other four hundred
    thousand — the caller counts them and says so.
    """
    text = str(value or '').strip()
    if not text:
        return 0.0
    normalised = text.replace('Z', '+00:00').replace('/', '-')
    try:
        parsed = datetime.datetime.fromisoformat(normalised)
    except ValueError:
        for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S',
                    '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S',
                    '%m-%d-%Y %H:%M:%S', '%Y-%m-%d %H:%M'):
            try:
                parsed = datetime.datetime.strptime(normalised, fmt)
                break
            except ValueError:
                continue
        else:
            return 0.0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.timestamp()


def parse_row(row):
    """
    One CSV row to an Event.

    Returns None for a row with neither address, which is what a trailing blank
    line or a summary footer looks like.
    """
    src_ip = (row.get('Src. Ip') or '').strip()
    dst_ip = (row.get('Dst. Ip') or '').strip()
    if not src_ip and not dst_ip:
        return None

    # The inversion. "Bytes Sent" is the gateway reporting what it sent *to* the
    # source — what the source downloaded. "Bytes Rec." is what it received
    # from the source, which is the upload. Named by direction from here on so
    # nothing downstream has to remember this.
    downloaded = _to_int(row.get('Bytes Sent'))
    uploaded = _to_int(row.get('Bytes Rec.'))

    event = Event(
        kind='flow',
        ts=parse_timestamp(row.get('UTC Date / Time')) or
           parse_timestamp(row.get('Date / Time')),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_mac=(row.get('Src. MAC') or '').strip().lower(),
        dst_mac=(row.get('Dst. MAC') or '').strip().lower(),
        src_port=_to_port(row.get('Src. Port')),
        dst_port=_to_port(row.get('Dst. Port')),
        protocol=(row.get('Protocol') or '').strip().lower(),
        bytes_to_dst=uploaded,
        bytes_to_src=downloaded,
        packets=_to_int(row.get('Packets')),
        source='unifi_csv',
    )

    event.fields.update({
        'action': (row.get('Action') or '').strip().lower(),
        'service': (row.get('Service') or '').strip(),
        'risk': (row.get('Risk') or '').strip(),
        'policy': (row.get('Policy') or '').strip(),
        'policy_type': (row.get('Policy Type') or '').strip(),
        'signature': (row.get('Signature') or '').strip(),
        'signature_id': (row.get('Signature ID') or '').strip(),
        'src_name': (row.get('Src. Name') or '').strip(),
        'dst_name': (row.get('Dst. Name') or '').strip(),
        'src_network': (row.get('Src. Network') or '').strip(),
        'dst_network': (row.get('Dst. Network') or '').strip(),
        'unifi_src_zone': (row.get('Src. Zone') or '').strip(),
        'unifi_dst_zone': (row.get('Dst. Zone') or '').strip(),
        'session_id': (row.get('Session Id') or '').strip(),
        'flow_count': _to_int(row.get('Flow Count')),
        'query': (row.get('Query') or '').strip(),
        'url': (row.get('URL') or '').strip(),
        # Deliberately not `domain`: it is inferred, it mislabels shared
        # addresses, and it is blank for exactly the long-lived connections
        # worth looking at. A rule that wants a domain should use the SNI from
        # a capture. Kept because it is occasionally a useful hint to a person.
        'domain_hint': (row.get('Dst. Domain') or '').strip(),
        # The gateway's own word for direction, kept under its own name so it
        # cannot collide with the direction computed from the addresses.
        'unifi_direction': (row.get('Direction') or '').strip().lower(),
        'blocked': (row.get('Action') or '').strip().lower() == 'blocked',
        # These numbers undercount long-lived sessions by a factor of four in a
        # measured 24-hour export, so anything thresholding on them should treat
        # them as a floor.
        'byte_counts_are_a_floor': True,
    })
    return event


def _open(path):
    """Plain or gzipped, decided by content rather than by extension."""
    with open(path, 'rb') as probe:
        magic = probe.read(2)
    if magic == b'\x1f\x8b':
        return gzip.open(path, 'rt', encoding='utf-8-sig', newline='')
    return open(path, 'rt', encoding='utf-8-sig', newline='')


def read_flows(path, limit=None, on_error='count'):
    """
    Read a UniFi flow export, yielding Events.

    Args:
        path: the .csv or .csv.gz export.
        limit: stop after this many events. Useful for a preview.
        on_error: 'count' skips bad rows and logs a total at the end;
            'raise' stops at the first one.

    Yields Events in file order. A 407,000-row export is about 105 MB, so this
    is a generator: nothing is accumulated, and a caller that wants a list can
    ask for one knowingly.
    """
    if not os.path.exists(path):
        raise UnifiCsvError(f'export not found: {path}')

    skipped = emitted = 0
    with _open(path) as handle:
        reader = csv.reader(handle, delimiter=DELIMITER)
        try:
            header = next(reader)
        except StopIteration:
            raise UnifiCsvError(f'{path} is empty') from None

        header = [_canonical(name) for name in header]
        _check_header(path, header)

        for line_number, row in enumerate(reader, start=2):
            if not any(field.strip() for field in row):
                continue
            try:
                record = dict(zip(header, row))
                event = parse_row(record)
            except Exception as e:
                if on_error == 'raise':
                    raise UnifiCsvError(f'{path}:{line_number}: {e}') from e
                skipped += 1
                continue
            if event is None:
                continue
            yield event
            emitted += 1
            if limit and emitted >= limit:
                break

    if skipped:
        logger.warning('%s: skipped %d unreadable rows of %d',
                       os.path.basename(path), skipped, skipped + emitted)


def _check_header(path, header):
    """
    Refuse a file that is not this format, saying what it looked like instead.

    The likeliest mistake is a comma-delimited export, which splits into a
    single column and would otherwise yield zero events with no explanation.
    """
    present = set(header)
    if len(header) == 1:
        raise UnifiCsvError(
            f'{path}: the header is one column, so this is probably not '
            f'semicolon-delimited. UniFi exports use ";".')

    required = {'Src. Ip', 'Dst. Ip'}
    missing = required - present
    if missing:
        raise UnifiCsvError(
            f'{path}: missing required columns {sorted(missing)}; '
            f'found {len(header)} columns starting {header[:4]}')

    unexpected = present - set(COLUMNS)
    absent = set(COLUMNS) - present
    if absent:
        logger.info('%s: %d of the 40 known columns are absent (%s%s) — a '
                    'different firmware version, or a narrowed export',
                    os.path.basename(path), len(absent),
                    ', '.join(sorted(absent)[:4]),
                    ', ...' if len(absent) > 4 else '')
    if unexpected:
        logger.info('%s: %d unrecognised columns (%s) — kept out of events',
                    os.path.basename(path), len(unexpected),
                    ', '.join(sorted(unexpected)[:4]))


def summarise(path, limit=None):
    """
    Describe an export without loading it into memory — what is in it, and what
    is conspicuously not.

    The absences matter as much as the contents: a VLAN missing from the export
    is a VLAN this source cannot tell you anything about, and reading silence as
    "nothing happened there" is the mistake this function exists to prevent.
    """
    stats = {
        'rows': 0, 'blocked': 0, 'bytes_uploaded': 0, 'bytes_downloaded': 0,
        'devices': set(), 'networks': set(), 'first_ts': None, 'last_ts': None,
        'by_action': {}, 'by_protocol': {}, 'undated_rows': 0,
    }
    for event in read_flows(path, limit=limit):
        stats['rows'] += 1
        stats['bytes_uploaded'] += event.bytes_to_dst
        stats['bytes_downloaded'] += event.bytes_to_src
        if event.src_ip:
            stats['devices'].add(event.src_ip)
        network = event.fields.get('src_network')
        if network:
            stats['networks'].add(network)
        action = event.fields.get('action') or 'unknown'
        stats['by_action'][action] = stats['by_action'].get(action, 0) + 1
        if event.fields.get('blocked'):
            stats['blocked'] += 1
        if event.protocol:
            stats['by_protocol'][event.protocol] = \
                stats['by_protocol'].get(event.protocol, 0) + 1
        if event.ts:
            if stats['first_ts'] is None or event.ts < stats['first_ts']:
                stats['first_ts'] = event.ts
            if stats['last_ts'] is None or event.ts > stats['last_ts']:
                stats['last_ts'] = event.ts
        else:
            stats['undated_rows'] += 1

    stats['devices'] = len(stats['devices'])
    stats['networks'] = sorted(stats['networks'])
    stats['by_action'] = dict(sorted(stats['by_action'].items()))
    stats['by_protocol'] = dict(sorted(stats['by_protocol'].items(),
                                       key=lambda kv: -kv[1])[:8])
    if stats['first_ts'] and stats['last_ts']:
        stats['hours_covered'] = round(
            (stats['last_ts'] - stats['first_ts']) / 3600, 1)
    return stats
