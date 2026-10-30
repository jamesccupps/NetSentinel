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
anything from the metadata-only VLAN" (40 and 50 in the example profile), and a
summariser is not the place to start interpreting that narrowly.

A finding counts as touching a restricted segment if anything about it points
there: the VLANs enrichment resolved, the addresses and MACs on its event, the
device it names, the VLAN, zone, network or address in its evidence, or an
address in its text. Canary and drift findings never went through enrichment
— a canary hit carries addresses and no VLAN, a configuration finding carries
a VLAN list or a forward target and no packet at all — so checking only the
resolved VLAN fields let both through.

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

import ipaddress
import re

__all__ = ['ALERT', 'AI', 'redact_finding', 'redact_findings', 'audit',
           'SAFE_EVIDENCE_FIELDS', 'FORBIDDEN_SUBSTRINGS',
           'device_is_restricted']

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
    # Where an internet address is, from local GeoIP files or the gateway's
    # own Region column: a country code, a network number and its name.
    'dst_country', 'dst_asn', 'dst_as_org', 'src_country', 'src_asn',
    'src_as_org', 'dst_region', 'src_region', 'dst_asn_allowed',
    # Inbound from outside Cloudflare: who, how many, and the flags.
    'sources', 'source_count', 'src_is_cloudflare', 'dst_is_cloudflare',
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


#: Evidence keys whose value is a VLAN id, or a list of them.
_VLAN_KEYS = ('vlan', 'vlans', 'src_vlan', 'dst_vlan', 'observed_vlan')
#: Evidence and event keys whose value is a zone name.
_ZONE_KEYS = ('zone', 'src_zone', 'dst_zone')

_ADDRESS_IN_TEXT = re.compile(
    r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])'          # IPv4
    r'|(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])',  # IPv6
    re.I)
_MAC_IN_TEXT = re.compile(r'\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b', re.I)


class _Restricted:
    """
    Everything that identifies the restricted segments, worked out once.

    VLAN ids, the subnets they carry, the zones nothing else shares, the names
    of the networks, and the devices the profile places on them.
    """

    def __init__(self, profile):
        self.profile = profile
        self.vlans = _restricted_vlans(profile)
        vlans = getattr(profile, 'vlans', {}) or {}
        self.subnets = []
        for vlan in vlans.values():
            if vlan.id in self.vlans and vlan.subnet:
                try:
                    self.subnets.append(ipaddress.ip_network(vlan.subnet,
                                                             strict=False))
                except ValueError:
                    continue
        # Only zones that no unrestricted VLAN also uses. A zone shared with an
        # ordinary segment says nothing about which one a finding came from.
        inside = {v.zone.lower() for v in vlans.values()
                  if v.zone and v.id in self.vlans}
        outside = {v.zone.lower() for v in vlans.values()
                   if v.zone and v.id not in self.vlans}
        self.zones = inside - outside
        self.network_names = {v.name.lower() for v in vlans.values()
                              if v.name and v.id in self.vlans}
        devices = getattr(profile, 'devices', {}) or {}
        self.devices = [d for d in devices.values() if self._device_vlan_restricted(d)]
        self.device_names = sorted({d.name.lower() for d in self.devices if d.name},
                                   key=len, reverse=True)

    def __bool__(self):
        return bool(self.vlans)

    def _device_vlan_restricted(self, device):
        if device.vlan is not None:
            try:
                if int(device.vlan) in self.vlans:
                    return True
            except (TypeError, ValueError):
                pass
        return any(self.address(ip) for ip in device.ips)

    def vlan(self, value):
        """A VLAN id, or a list or "40 (access-control)" string of them."""
        if isinstance(value, (list, tuple, set)):
            return any(self.vlan(v) for v in value)
        if value is None or isinstance(value, bool):
            return False
        text = str(value).strip().split(' ', 1)[0]
        try:
            return int(text) in self.vlans
        except (TypeError, ValueError):
            return False

    def address(self, value):
        try:
            address = ipaddress.ip_address(str(value).strip().strip('[]'))
        except ValueError:
            return False
        return any(address in net for net in self.subnets
                   if net.version == address.version)

    def mac(self, value):
        device = self.profile.device_for_mac(value) \
            if hasattr(self.profile, 'device_for_mac') else None
        return device is not None and device in self.devices

    def text(self, value):
        """Whether free text names a restricted address, MAC or device."""
        text = str(value or '')
        if not text:
            return False
        for match in _ADDRESS_IN_TEXT.finditer(text):
            if self.address(match.group(0)):
                return True
        for match in _MAC_IN_TEXT.finditer(text):
            if self.mac(match.group(0).replace('-', ':').lower()):
                return True
        lowered = text.lower()
        for name in self.device_names:
            if re.search(r'(?<![\w-])' + re.escape(name) + r'(?![\w-])', lowered):
                return True
        return False

    def device(self, label):
        """The finding's device string: a name, a MAC or an address."""
        label = str(label or '').strip()
        if not label:
            return False
        lowered = label.lower()
        if any(d.name.lower() == lowered or d.mac == lowered for d in self.devices):
            return True
        return self.address(label) or self.text(label)

    def value(self, key, value):
        """One evidence value, judged by what its key says it is."""
        if key in _VLAN_KEYS and self.vlan(value):
            return True
        if key in _ZONE_KEYS and str(value or '').lower() in self.zones:
            return True
        if key in ('network', 'subnet', 'ip_subnet'):
            if str(value or '').lower() in self.network_names:
                return True
            try:
                network = ipaddress.ip_network(str(value), strict=False)
                if any(network.overlaps(net) for net in self.subnets
                       if net.version == network.version):
                    return True
            except ValueError:
                pass
        if isinstance(value, (list, tuple, set)):
            return any(self.value(key, item) for item in value)
        if isinstance(value, dict):
            return any(self.value(str(k), v) for k, v in value.items())
        if isinstance(value, str):
            return self.text(value)
        return False


def _finding_touches_restricted(finding, profile, restricted=None):
    """
    Whether this finding involves a segment whose contents must not be
    transmitted to an external service.

    Every route to "this came from there" is checked, because the findings
    that matter most here are the ones that never went through enrichment.
    A canary hit carries the visitor's address and no VLAN; a configuration
    finding carries a VLAN list, a network name or a forward target and no
    packet. Erring towards withholding costs the model one finding, which the
    withheld count still accounts for; erring the other way sends the one
    thing the site said must never leave.
    """
    restricted = restricted if restricted is not None else _Restricted(profile)
    if not restricted:
        return False

    event = finding.event
    if event is not None:
        for key in ('vlan', 'observed_vlan', 'src_vlan', 'dst_vlan'):
            if restricted.vlan(event.get(key)):
                return True
        for key in ('src_zone', 'dst_zone'):
            if str(event.get(key) or '').lower() in restricted.zones:
                return True
        for ip in (event.src_ip, event.dst_ip):
            if ip and restricted.address(ip):
                return True
        for mac in (event.src_mac, event.dst_mac):
            if mac and restricted.mac(mac):
                return True
        if event.fields.get('metadata_only') or \
                event.fields.get('may_store_payload') is False:
            return True

    if restricted.device(finding.device):
        return True
    for name, value in (finding.evidence or {}).items():
        if restricted.value(str(name), value):
            return True
    return any(restricted.text(text) for text in
               (finding.description, finding.title, finding.key))


def device_is_restricted(device, profile):
    """
    Whether a device named on the command line sits on a restricted segment.

    For the on-demand "investigate this device" path, which would otherwise
    send the device's name and role even when it has no findings to withhold.
    """
    restricted = _Restricted(profile)
    if not restricted:
        return False
    if restricted.device(device):
        return True
    if hasattr(profile, 'identify'):
        found = profile.identify(ip=device, mac=device)
        return restricted.vlan(found.vlan) or any(
            restricted.address(ip) for ip in found.ips)
    return False


def redact_finding(finding, profile=None, audience=ALERT, _restricted=None):
    """
    One finding, reduced to what this audience may receive.

    Returns a dict, or None when the whole finding must be withheld — which
    happens only for the AI audience on a restricted segment. Callers that need
    to know something was withheld should use `redact_findings`, which reports
    the count.
    """
    if audience == AI and _finding_touches_restricted(finding, profile,
                                                      _restricted):
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
    restricted = _Restricted(profile) if audience == AI else None
    for finding in findings:
        record = redact_finding(finding, profile, audience, restricted)
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
            'benign for a site of this shape. Describe what to check in prose; '
            'do not write commands. Do not recommend changes to the network '
            'itself.'),
    }
