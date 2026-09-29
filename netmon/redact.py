"""
What may leave the building.
=============================
Every path out of this system goes through here: a push notification, a daily
digest, a summary sent to a model. The rules differ by destination, which is why
this is one module with an audience parameter rather than a convention each
caller is trusted to remember.

Two audiences
-------------
**ALERT** — a notification to the people who run the site. It may name devices,
addresses, VLANs and what happened, because that is the alert. It may not carry
payload, credential values, cookies, card or RFID data. Metadata from a
restricted segment *is* allowed: "a door controller reached an address on the
internet at 3am" is exactly the finding those segments exist to produce, and it
contains nothing regulated.

**AI** — a summary sent to an external model. Everything above, and nothing at
all from a restricted segment: not the addresses, not the device names, not the
fact that something happened there. The site's instruction was "never send
anything from VLAN 12", and a summariser is not the place to start interpreting
that narrowly.

How it fails
------------
Closed, and loudly. An unrecognised field is dropped rather than passed, because
the list of things that are safe is short and knowable while the list of things
that are not is neither. A finding that cannot be redacted is replaced by a
placeholder saying so, not omitted — silence would let a problem disappear.

`audit()` runs the output back through a scan for anything that looks like a
secret and returns what it found. Nothing in this module calls it; the tests do,
and so should anything adding a new destination.
"""

from __future__ import annotations

import re

__all__ = ['ALERT', 'AI', 'redact_finding', 'redact_findings', 'audit',
           'SAFE_EVIDENCE_FIELDS', 'FORBIDDEN_SUBSTRINGS']

ALERT = 'alert'
AI = 'ai'


#: Evidence keys that may be transmitted. An allowlist, not a denylist: rules
#: are edited by site operators and can name any field they like, so the
#: question has to be "is this known to be safe" rather than "is this known to
#: be dangerous".
SAFE_EVIDENCE_FIELDS = frozenset({
    'src_ip', 'dst_ip', 'src_mac', 'dst_mac', 'src_port', 'dst_port',
    'protocol', 'vlan', 'src_vlan', 'dst_vlan', 'observed_vlan',
    'src_zone', 'dst_zone', 'src_role', 'dst_role', 'src_name', 'dst_name',
    'direction', 'service', 'bvlc_function', 'object', 'property', 'peer',
    'network', 'vendor', 'vendor_service', 'device_instance',
    'reinitialize_state', 'enable_disable', 'apdu_type',
    'credential_type', 'watched_name', 'poisonable_name', 'name_seen',
    'sni', 'query', 'domain', 'hostname', 'record_type', 'ttl', 'rcode',
    'answer', 'message', 'client_mac', 'arp_operation',
    'action', 'policy', 'policy_type', 'signature', 'signature_id', 'risk',
    'count', 'packets', 'bytes', 'uploaded_bytes', 'median_bytes', 'ratio',
    'interval_sec', 'score', 'observations', 'jitter_pct', 'destination',
    'known_destinations', 'days_of_history', 'quiet_hours', 'zone',
    'mac', 'ip', 'macs', 'vlans', 'search_target', 'queries', 'name',
    'destination_count', 'reason',
})

#: A name containing any of these is never transmitted, whatever the allowlist
#: says. Belt and braces: the allowlist is the mechanism, this is the check that
#: a careless addition to it is caught.
FORBIDDEN_SUBSTRINGS = (
    'payload', 'credential_value', 'password', 'passwd', 'secret', 'token',
    'cookie', 'session', 'card', 'rfid', 'badge_number', 'pin', 'hash',
    'authorization', 'auth_header', 'key', 'cert', 'private', 'raw', 'body',
)

#: Values that look like secrets regardless of what they are called. Used by
#: audit(), which is a check on this module rather than a mechanism within it.
_SECRET_SHAPES = (
    (re.compile(r'\bBasic\s+[A-Za-z0-9+/]{8,}={0,2}'), 'http basic credential'),
    (re.compile(r'\bBearer\s+[A-Za-z0-9._~+/-]{16,}'), 'bearer token'),
    (re.compile(r'\b(?:SESSION|JSESSIONID|PHPSESSID|ASP\.NET_SessionId)'
                r'\s*=\s*\S+', re.I), 'session cookie'),
    (re.compile(r'\b(?:\d[ -]?){13,19}\b'), 'possible card number'),
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'), 'private key'),
    (re.compile(r'\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b'),
     'json web token'),
    (re.compile(r'\bsnmp[^\s]*\s*[:=]\s*\S+', re.I), 'snmp community'),
)


def _forbidden(name):
    lowered = str(name).lower()
    return any(word in lowered for word in FORBIDDEN_SUBSTRINGS)


def _restricted_vlans(profile):
    return set(getattr(profile, 'metadata_only_vlans', set()) or set())


def _finding_touches_restricted(finding, profile):
    """
    Whether this finding involves a segment whose contents must not be
    transmitted to an external service.

    Checked against the event's resolved VLANs rather than the description, so
    it does not depend on how a rule happened to word itself.
    """
    restricted = _restricted_vlans(profile)
    if not restricted:
        return False
    event = finding.event
    if event is None:
        return False
    for key in ('vlan', 'observed_vlan', 'src_vlan', 'dst_vlan'):
        value = event.get(key)
        if value is not None:
            try:
                if int(value) in restricted:
                    return True
            except (TypeError, ValueError):
                continue
    return False


def redact_finding(finding, profile=None, audience=ALERT):
    """
    One finding, reduced to what this audience may receive.

    Returns a dict, or None when the whole finding must be withheld — which
    happens only for the AI audience on a restricted segment. Callers that need
    to know something was withheld should use `redact_findings`, which reports
    the count.
    """
    if audience == AI and _finding_touches_restricted(finding, profile):
        return None

    evidence = {}
    for name, value in (finding.evidence or {}).items():
        if _forbidden(name) or name not in SAFE_EVIDENCE_FIELDS:
            continue
        if value in (None, '', [], {}):
            continue
        evidence[name] = value

    out = {
        'rule': finding.rule_id,
        'title': finding.title,
        'severity': finding.severity,
        'tier': finding.tier,
        'device': finding.device,
        'description': finding.description,
        'ts': finding.ts,
        'count': finding.count,
        'evidence': evidence,
    }
    if finding.next_check:
        out['next_check'] = finding.next_check

    # The device's own context, which is what turns "10.10.20.21 did something"
    # into something a person can act on without going to look it up.
    #
    # Resolved for whichever endpoint the finding actually names. A rule may
    # name the destination — bacnet_control names the controller that was
    # written to, since that is what someone has to go and check — and
    # describing it with the *source's* role and VLAN labels a controller as a
    # workstation, which is worse than saying nothing.
    if profile is not None and finding.event is not None:
        device, vlan_id = _named_endpoint(finding, profile)
        if device is not None:
            if device.role and device.role != 'unknown':
                out['role'] = device.role
            if device.switch_port:
                out['switch_port'] = device.switch_port
        vlan = profile.vlans.get(vlan_id) if vlan_id is not None else None
        if vlan is not None:
            out['vlan'] = f'{vlan.id} ({vlan.name})' if vlan.name else str(vlan.id)
            if vlan.zone:
                out['zone'] = vlan.zone

    return out


def _named_endpoint(finding, profile):
    """
    The device the finding is about, and the VLAN it is on.

    Matched by the finding's own `device` string against each endpoint's name,
    MAC and addresses. Falls back to the source, which is what most rules name.
    """
    event = finding.event
    label = str(finding.device or '').lower()

    for mac, ip, vlan_key in ((event.dst_mac, event.dst_ip, 'dst_vlan'),
                              (event.src_mac, event.src_ip, 'src_vlan')):
        if not label:
            break
        device = profile.identify(mac=mac, ip=ip)
        candidates = {str(device.name).lower(), str(device.mac).lower(),
                      str(ip).lower()}
        candidates.update(str(a).lower() for a in device.ips)
        if label in candidates:
            return device, event.get(vlan_key)

    return (profile.identify(mac=event.src_mac, ip=event.src_ip),
            event.get('src_vlan'))


def redact_findings(findings, profile=None, audience=ALERT):
    """
    Redact a list, reporting what was withheld.

    Returns (records, withheld_count). The count matters: a summary that
    silently omits a restricted segment reads as "nothing happened there",
    which is a different and worse claim than "this was not sent".
    """
    records, withheld = [], 0
    for finding in findings:
        record = redact_finding(finding, profile, audience)
        if record is None:
            withheld += 1
        else:
            records.append(record)
    return records, withheld


def audit(payload):
    """
    Scan an outbound payload for anything that looks like a secret.

    Returns a list of (what, where) for whatever it found — empty when clean.
    Nothing in this module calls it; the tests do, over every rule's output, and
    so should anything that adds a new destination. A check that runs only in
    tests still catches the mistake before it ships, and one that runs on every
    send is a tax on every send.
    """
    import json
    text = payload if isinstance(payload, str) else json.dumps(payload, default=str)

    found = []
    for pattern, description in _SECRET_SHAPES:
        for match in pattern.finditer(text):
            found.append((description, match.group(0)[:40]))

    if not isinstance(payload, str):
        for name in _walk_keys(payload):
            if _forbidden(name):
                found.append(('forbidden field name', name))
    return found


def _walk_keys(node, depth=0):
    if depth > 12:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from _walk_keys(value, depth + 1)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _walk_keys(item, depth + 1)


def summary_for_model(analyzer, profile, max_findings=60):
    """
    The compact JSON an external model is given.

    Deliberately small and deliberately incomplete. It carries counts, roles,
    zones and rule identifiers — the shape of what happened — not a transcript.
    A model asked to prioritise findings does not need the packet, and a summary
    that would be damaging if it leaked is one nobody should be sending.

    Restricted segments are absent entirely, and the count of what was withheld
    is included so the omission cannot be read as quiet.
    """
    records, withheld = redact_findings(
        analyzer.by_severity()[:max_findings], profile, audience=AI)

    return {
        'site': profile.name,
        'window': {
            'events': analyzer.events_seen,
            'findings': len(analyzer.findings),
        },
        'profile': {
            'vlans': [{'id': v.id, 'name': v.name, 'zone': v.zone}
                      for v in sorted(profile.vlans.values(), key=lambda v: v.id)
                      if v.id not in _restricted_vlans(profile)],
            'roles': sorted(profile.roles),
            'devices': len(profile.devices),
            'expected_flows': len(profile.expected_flows),
        },
        'findings': records,
        'withheld_from_restricted_segments': withheld,
        'instructions': (
            'Advisory only. Prioritise these findings and say which are likely '
            'benign for a site of this shape. Suggest next checks. Do not '
            'recommend changes to the network itself.'),
    }
