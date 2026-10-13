"""
Configuration drift.
====================
The packet rules watch what the network does. This watches what it is allowed to
do — and that changes without any packet being unusual.

A port profile switched to "allow all" exposes every VLAN on that port, and
produces no odd traffic until someone plugs something in. A new port forward
opens a path from the internet and looks like nothing at all until it is used. A
firewall rule disabled "temporarily" six months ago is now the configuration.
None of these are events; they are states, and the only way to see them is to
look and compare.

    python -m netmon.drift --profile my-site.yaml --host https://unifi.example \
        --fingerprint AA:BB:... --state ~/.local/state/netmon/unifi.json

Two kinds of finding
--------------------
**Standing** — things that are wrong now, reported on every run until fixed: a
port profile allowing every VLAN, a port forward into a segment that should not
be reachable, a disabled firewall rule. These do not need a baseline; the first
run reports them.

**Drift** — what changed since the last run. These need a baseline, so the first
run records one and says so rather than reporting the entire configuration as
new, which would be true and useless.

The snapshot is sensitive
-------------------------
It is the network's defences written down: every firewall rule, every forward,
every port's VLAN membership. Written owner-only, and the findings that come out
of it carry rule names and port numbers rather than the rules themselves.
"""

from __future__ import annotations

import json
import logging
import os
import time

from netmon.events import Event, Finding, Severity, Tier

logger = logging.getLogger("netmon.drift")

__all__ = ['snapshot', 'load_state', 'save_state', 'audit', 'diff',
           'DriftError', 'CONFIG_ENDPOINTS']


class DriftError(RuntimeError):
    """The configuration could not be read or compared."""


#: What to read. Each is tried under both UniFi OS paths, as elsewhere.
CONFIG_ENDPOINTS = {
    'networks': 'rest/networkconf',
    'port_profiles': 'rest/portconf',
    'port_forwards': 'rest/portforward',
    'firewall_rules': 'rest/firewallrule',
    'firewall_groups': 'rest/firewallgroup',
    'wlans': 'rest/wlanconf',
    'devices': 'stat/device',
}

#: Fields worth keeping per object. Everything else is dropped: a snapshot is
#: for comparison, and the less of the controller's internal state it carries
#: the less of it churns for reasons nobody cares about.
_KEEP = {
    'networks': ('_id', 'name', 'vlan', 'ip_subnet', 'purpose', 'enabled',
                 'dhcpd_enabled', 'vlan_enabled', 'networkgroup'),
    'port_profiles': ('_id', 'name', 'forward', 'native_networkconf_id',
                      'tagged_networkconf_ids', 'poe_mode', 'port_security_enabled',
                      'stormctrl_bcast_enabled', 'isolation', 'autoneg'),
    'port_forwards': ('_id', 'name', 'enabled', 'src', 'dst_port', 'fwd',
                      'fwd_port', 'proto', 'log', 'pfwd_interface'),
    'firewall_rules': ('_id', 'name', 'enabled', 'action', 'ruleset',
                       'rule_index', 'protocol', 'src_address', 'dst_address',
                       'src_firewallgroup_ids', 'dst_firewallgroup_ids',
                       'logging', 'state_established', 'state_new'),
    'firewall_groups': ('_id', 'name', 'group_type', 'group_members'),
    'wlans': ('_id', 'name', 'enabled', 'security', 'networkconf_id',
              'is_guest', 'wpa_mode', 'hide_ssid'),
    'devices': ('_id', 'mac', 'name', 'model', 'type', 'ip', 'version'),
}


def _trim(rows, keep):
    out = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        out.append({k: row.get(k) for k in keep if k in row})
    return out


def _port_table(devices):
    """
    Per-port configuration, which is where a profile change actually lands.

    Kept separately from the device list because a device's statistics change
    every poll and its port assignments do not. Comparing the whole device
    object would report drift on every run.
    """
    ports = {}
    for device in devices or []:
        if not isinstance(device, dict):
            continue
        mac = str(device.get('mac') or '').lower()
        if not mac:
            continue
        for port in device.get('port_table') or []:
            if not isinstance(port, dict):
                continue
            index = port.get('port_idx')
            if index is None:
                continue
            ports[f'{mac}/{index}'] = {
                'name': port.get('name'),
                'portconf_id': port.get('portconf_id'),
                'up': bool(port.get('up')),
                'enable': bool(port.get('enable', True)),
                'is_uplink': bool(port.get('is_uplink')),
                'poe_enable': bool(port.get('poe_enable')),
            }
    # Also take the port overrides, which is where a per-port profile override
    # lives when it differs from the switch's default.
    for device in devices or []:
        if not isinstance(device, dict):
            continue
        mac = str(device.get('mac') or '').lower()
        for override in device.get('port_overrides') or []:
            if not isinstance(override, dict):
                continue
            index = override.get('port_idx')
            if index is None:
                continue
            entry = ports.setdefault(f'{mac}/{index}', {})
            entry['override_portconf_id'] = override.get('portconf_id')
            if override.get('name'):
                entry['name'] = override['name']
    return ports


def snapshot(client, now=None):
    """
    Read the controller's configuration into a comparable shape.

    One endpoint failing does not lose the rest: a controller that will not list
    its WLANs can still list its port forwards, and most of the answer beats
    none of it.
    """
    from netmon.sources.unifi_api import UnifiApiError

    data = {'taken_at': now if now is not None else time.time(),
            'site': client.site, 'host': client.host, 'errors': {}}

    for name, suffix in CONFIG_ENDPOINTS.items():
        rows = None
        for prefix in ('/proxy/network/api/s/{site}/', '/api/s/{site}/'):
            try:
                rows = client.get(prefix.format(site=client.site) + suffix)
                break
            except UnifiApiError as e:
                data['errors'][name] = str(e)
        if rows is None:
            data[name] = []
            continue
        data['errors'].pop(name, None)
        data[name] = _trim(rows, _KEEP[name])
        if name == 'devices':
            data['ports'] = _port_table(rows)

    data.setdefault('ports', {})
    return data


# ─── State on disk ───────────────────────────────────────────────────────────

def load_state(path):
    """The previous snapshot, or None on a first run."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning('could not read %s: %s — treating this as a first run',
                       path, e)
        return None


def save_state(state, path):
    """
    Write the snapshot owner-only.

    It is the network's defences written down: every firewall rule, every
    forward, every port's VLAN membership.
    """
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    temporary = path + '.tmp'
    with open(temporary, 'w', encoding='utf-8') as handle:
        json.dump(state, handle, indent=1, sort_keys=True, default=str)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


# ─── Findings ────────────────────────────────────────────────────────────────

def _finding(rule_id, title, description, severity, tier, key, device='',
             evidence=None, next_check='', ts=None):
    # A synthetic event so these travel through redaction, deduplication and the
    # UI exactly like a packet finding. There is no packet, which is the point:
    # these are states, not events.
    event = Event(kind='config', ts=ts or time.time(), source='unifi_config')
    event.fields['config_object'] = key
    return Finding(rule_id, title, severity=severity, tier=tier,
                   description=description, device=device or key, key=key,
                   event=event, evidence=dict(evidence or {}),
                   next_check=next_check, ts=ts or time.time())


def _rows(state, section):
    """
    The dict rows of a section, skipping anything else.

    `snapshot` already filters, but `audit` and `diff` also run against a state
    loaded from disk — which `--from-file` lets anyone hand over, and which a
    half-written file can leave malformed. A config check that crashes on a
    malformed cache file is a config check nobody runs nightly.
    """
    return [row for row in (state.get(section) or []) if isinstance(row, dict)]


def _network_names(state):
    return {str(n.get('_id')): (n.get('name') or f"vlan-{n.get('vlan')}")
            for n in _rows(state, 'networks')}


def _vlan_of_network(state):
    out = {}
    for network in _rows(state, 'networks'):
        try:
            out[str(network.get('_id'))] = int(network.get('vlan'))
        except (TypeError, ValueError):
            continue
    return out


def audit(state, profile=None, previous=None):
    """
    What is wrong now, reported until it is fixed.

    These need no baseline. A port profile allowing every VLAN is wrong on the
    first run and on the hundredth, and a finding that only appears the moment
    it changes would miss every site that was already misconfigured.

    `previous` only decides how loudly. A problem that was already there last
    time goes in the digest; one that is newly wrong pushes. Reported either
    way — a standing misconfiguration that stops being mentioned stops being
    fixed — but pushing the same one nightly is how push gets muted.
    """
    findings = []
    restricted = set(getattr(profile, 'metadata_only_vlans', set()) or set())
    vlan_of = _vlan_of_network(state)
    already = _known_problems(previous) if previous else set()

    def tier_for(key, when_new=Tier.PUSH, when_standing=Tier.DIGEST):
        return when_standing if key in already else when_new

    # ─── Port profiles that carry every VLAN ─────────────────────────────
    for shape in _rows(state, 'port_profiles'):
        name = shape.get('name') or shape.get('_id')
        if str(shape.get('forward') or '').lower() in ('all', 'customize_all'):
            findings.append(_finding(
                'vlan_leak', 'A switch port profile carries every VLAN',
                f'Port profile "{name}" is set to forward all networks. Any '
                f'device on a port using it reaches every VLAN on the switch.',
                Severity.HIGH,
                tier_for(f'port_profiles/{shape.get("_id") or name}'),
                key=f'port_profiles/{shape.get("_id") or name}',
                evidence={'profile': name, 'forward': shape.get('forward')},
                next_check='In the UniFi port profile, select only the networks '
                           'that port needs. "All" is the default, which is why '
                           'it is usually unintentional.'))
            continue

        tagged = [str(t) for t in (shape.get('tagged_networkconf_ids') or [])]
        exposed = sorted({vlan_of[t] for t in tagged if t in vlan_of}
                         & restricted)
        if exposed:
            findings.append(_finding(
                'vlan_leak',
                'A port profile carries a segment whose payload must not spread',
                f'Port profile "{name}" tags VLAN '
                + ', '.join(str(v) for v in exposed)
                + ', which the profile marks metadata-only.',
                Severity.HIGH,
                tier_for(f'port_profiles/{shape.get("_id") or name}'),
                key=f'port_profiles/{shape.get("_id") or name}',
                evidence={'profile': name, 'vlans': exposed},
                next_check='Remove that network from the profile unless the '
                           'ports using it genuinely need it.'))

    # ─── Port forwards ───────────────────────────────────────────────────
    for forward in _rows(state, 'port_forwards'):
        if not forward.get('enabled', True):
            continue
        name = forward.get('name') or forward.get('_id')
        source = str(forward.get('src') or 'any')
        target = f"{forward.get('fwd')}:{forward.get('fwd_port')}"
        severity = Severity.HIGH if source in ('any', '0.0.0.0/0', '') \
            else Severity.MEDIUM
        findings.append(_finding(
            'exposure_change', 'A port is forwarded in from the internet',
            f'"{name}" forwards {forward.get("proto", "tcp")}/'
            f'{forward.get("dst_port")} from {source} to {target}.',
            severity,
            tier_for(f'port_forwards/{forward.get("_id") or name}',
                     when_new=Tier.DIGEST, when_standing=Tier.DIGEST),
            key=f'port_forwards/{forward.get("_id") or name}',
            evidence={'name': name, 'source': source,
                      'dst_port': forward.get('dst_port'),
                      'forward_to': target, 'protocol': forward.get('proto'),
                      'logged': bool(forward.get('log'))},
            next_check=f'Confirm {target} is supposed to be reachable from '
                       f'{source}, and that it is patched. A forward is a path '
                       f'in that no firewall rule has to allow.'))

    # ─── Firewall rules that are off ─────────────────────────────────────
    for rule in _rows(state, 'firewall_rules'):
        if rule.get('enabled', True):
            continue
        name = rule.get('name') or rule.get('_id')
        findings.append(_finding(
            'firewall_rule_disabled', 'A firewall rule is turned off',
            f'Rule "{name}" in {rule.get("ruleset", "an unnamed ruleset")} is '
            f'disabled. A rule disabled temporarily is, after a while, the '
            f'configuration.',
            Severity.MEDIUM,
            tier_for(f'firewall_rules/{rule.get("_id") or name}',
                     when_new=Tier.PUSH, when_standing=Tier.DIGEST),
            key=f'firewall_rules/{rule.get("_id") or name}',
            evidence={'name': name, 'ruleset': rule.get('ruleset'),
                      'action': rule.get('action')},
            next_check='Either re-enable it or delete it. A disabled rule in '
                       'the list reads as protection that is not there.'))

    # ─── Open wireless ───────────────────────────────────────────────────
    for wlan in _rows(state, 'wlans'):
        if not wlan.get('enabled', True):
            continue
        if str(wlan.get('security') or '').lower() in ('open', 'none', ''):
            name = wlan.get('name') or wlan.get('_id')
            findings.append(_finding(
                'open_wireless', 'An open wireless network is enabled',
                f'"{name}" has no authentication'
                + ('' if wlan.get('is_guest') else
                   ' and is not marked as a guest network, so it may reach '
                   'internal segments'),
                Severity.HIGH if not wlan.get('is_guest') else Severity.LOW,
                tier_for(f'wlans/{wlan.get("_id") or name}',
                         when_new=Tier.PUSH if not wlan.get('is_guest')
                         else Tier.DIGEST, when_standing=Tier.DIGEST),
                key=f'wlans/{wlan.get("_id") or name}',
                evidence={'name': name, 'guest': bool(wlan.get('is_guest'))},
                next_check='If it is meant to be open, make sure it is a guest '
                           'network with client isolation.'))

    return findings


def _known_problems(state):
    """
    The keys of the standing problems a state had, so the next run can tell a
    new one from one that was already there.

    Recomputed from the snapshot rather than stored alongside it: the snapshot
    is the configuration, and deriving the problems from it means a change to
    what counts as a problem applies to the history too.
    """
    return {finding.key for finding in audit(state)}


def diff(previous, current, profile=None):
    """
    What changed since the last run.

    Needs a baseline. The first run records one and reports nothing here,
    because reporting the whole configuration as new would be true and useless.
    """
    if not previous:
        return []

    findings = []
    names = _network_names(current)
    taken = current.get('taken_at', time.time())

    def by_id(state, section):
        return {str(row.get('_id')): row for row in _rows(state, section)
                if row.get('_id')}

    # ─── Port forwards: added, removed, widened ──────────────────────────
    before, after = by_id(previous, 'port_forwards'), by_id(current, 'port_forwards')
    for key in sorted(set(after) - set(before)):
        forward = after[key]
        findings.append(_finding(
            'exposure_change', 'A new port forward appeared',
            f'"{forward.get("name")}" now forwards '
            f'{forward.get("proto", "tcp")}/{forward.get("dst_port")} from '
            f'{forward.get("src") or "any"} to {forward.get("fwd")}:'
            f'{forward.get("fwd_port")}.',
            Severity.HIGH, Tier.PUSH, key=f'port_forwards/{key}',
            evidence={'name': forward.get('name'),
                      'dst_port': forward.get('dst_port'),
                      'forward_to': f'{forward.get("fwd")}:{forward.get("fwd_port")}',
                      'source': forward.get('src') or 'any'},
            next_check='Find out who added it and why. A forward is a path in '
                       'from the internet that no firewall rule has to allow.',
            ts=taken))
    for key in sorted(set(before) - set(after)):
        findings.append(_finding(
            'exposure_change', 'A port forward was removed',
            f'"{before[key].get("name")}" is gone. Noted so the change is on '
            f'the record, not because it is a problem.',
            Severity.INFO, Tier.DIGEST, key=f'port_forwards/{key}',
            evidence={'name': before[key].get('name')}, ts=taken))

    # ─── Firewall rules ──────────────────────────────────────────────────
    before, after = by_id(previous, 'firewall_rules'), by_id(current, 'firewall_rules')
    for key in sorted(set(before) - set(after)):
        findings.append(_finding(
            'firewall_change', 'A firewall rule was deleted',
            f'Rule "{before[key].get("name")}" in '
            f'{before[key].get("ruleset", "an unnamed ruleset")} no longer '
            f'exists.',
            Severity.HIGH, Tier.PUSH, key=f'firewall_rules/{key}',
            evidence={'name': before[key].get('name'),
                      'action': before[key].get('action'),
                      'ruleset': before[key].get('ruleset')},
            next_check='Confirm the deletion was intended. Segmentation that '
                       'is not enforced is documentation.',
            ts=taken))
    for key in sorted(set(after) - set(before)):
        findings.append(_finding(
            'firewall_change', 'A firewall rule was added',
            f'Rule "{after[key].get("name")}" ({after[key].get("action")}) '
            f'appeared in {after[key].get("ruleset", "an unnamed ruleset")}.',
            Severity.MEDIUM, Tier.DIGEST, key=f'firewall_rules/{key}',
            evidence={'name': after[key].get('name'),
                      'action': after[key].get('action')}, ts=taken))
    for key in sorted(set(before) & set(after)):
        was, now = before[key], after[key]
        if was.get('enabled', True) and not now.get('enabled', True):
            findings.append(_finding(
                'firewall_change', 'A firewall rule was turned off',
                f'Rule "{now.get("name")}" was enabled and is not any more.',
                Severity.HIGH, Tier.PUSH, key=f'firewall_rules/{key}',
                evidence={'name': now.get('name'),
                          'action': now.get('action')},
                next_check='Find out what it was blocking and whether that is '
                           'now getting through.',
                ts=taken))
        elif was.get('action') != now.get('action'):
            findings.append(_finding(
                'firewall_change', 'A firewall rule changed what it does',
                f'Rule "{now.get("name")}" went from {was.get("action")} to '
                f'{now.get("action")}.',
                Severity.HIGH, Tier.PUSH, key=f'firewall_rules/{key}',
                evidence={'name': now.get('name'), 'was': was.get('action'),
                          'now': now.get('action')}, ts=taken))

    # ─── Port profiles ───────────────────────────────────────────────────
    before, after = by_id(previous, 'port_profiles'), by_id(current, 'port_profiles')
    for key in sorted(set(before) & set(after)):
        was, now = before[key], after[key]
        if was.get('forward') != now.get('forward'):
            findings.append(_finding(
                'vlan_leak', 'A port profile changed which VLANs it carries',
                f'Profile "{now.get("name")}" went from '
                f'{was.get("forward")} to {now.get("forward")}.',
                Severity.HIGH if str(now.get('forward')).lower().startswith('all')
                else Severity.MEDIUM,
                Tier.PUSH, key=f'port_profiles/{key}',
                evidence={'profile': now.get('name'), 'was': was.get('forward'),
                          'now': now.get('forward')},
                next_check='Check which switch ports use this profile; the '
                           'change applies to all of them at once.',
                ts=taken))
        was_tagged = set(str(t) for t in (was.get('tagged_networkconf_ids') or []))
        now_tagged = set(str(t) for t in (now.get('tagged_networkconf_ids') or []))
        for added in sorted(now_tagged - was_tagged):
            findings.append(_finding(
                'vlan_leak', 'A port profile gained a VLAN',
                f'Profile "{now.get("name")}" now also carries '
                f'{names.get(added, added)}.',
                Severity.MEDIUM, Tier.DIGEST, key=f'port_profiles/{key}/{added}',
                evidence={'profile': now.get('name'),
                          'network': names.get(added, added)}, ts=taken))

    # ─── Per-port assignments ────────────────────────────────────────────
    before_ports = {k: v for k, v in (previous.get('ports') or {}).items()
                    if isinstance(v, dict)}
    after_ports = {k: v for k, v in (current.get('ports') or {}).items()
                   if isinstance(v, dict)}
    profile_names = {str(p.get('_id')): p.get('name')
                     for p in _rows(current, 'port_profiles')}
    for key in sorted(set(before_ports) & set(after_ports)):
        was, now = before_ports[key], after_ports[key]
        was_conf = was.get('override_portconf_id') or was.get('portconf_id')
        now_conf = now.get('override_portconf_id') or now.get('portconf_id')
        if was_conf != now_conf:
            findings.append(_finding(
                'port_profile_change', 'A switch port changed profile',
                f'{key} ({now.get("name") or "unnamed"}) moved from '
                f'{profile_names.get(str(was_conf), was_conf or "default")} to '
                f'{profile_names.get(str(now_conf), now_conf or "default")}.',
                Severity.MEDIUM, Tier.DIGEST, key=f'port/{key}',
                evidence={'port': key, 'was': profile_names.get(str(was_conf)),
                          'now': profile_names.get(str(now_conf))},
                next_check='Confirm whatever is plugged into that port is '
                           'supposed to be on the networks the new profile '
                           'carries.',
                ts=taken))

    # ─── Networks and wireless ───────────────────────────────────────────
    before, after = by_id(previous, 'networks'), by_id(current, 'networks')
    for key in sorted(set(after) - set(before)):
        findings.append(_finding(
            'new_network', 'A new network was created',
            f'"{after[key].get("name")}" (VLAN {after[key].get("vlan")}, '
            f'{after[key].get("ip_subnet")}) did not exist before.',
            Severity.MEDIUM, Tier.DIGEST, key=f'networks/{key}',
            evidence={'name': after[key].get('name'),
                      'vlan': after[key].get('vlan'),
                      'subnet': after[key].get('ip_subnet')},
            next_check='Add it to the site profile, with a zone and a payload '
                       'policy. Until then every device on it reads as unknown.',
            ts=taken))

    before, after = by_id(previous, 'wlans'), by_id(current, 'wlans')
    for key in sorted(set(after) - set(before)):
        findings.append(_finding(
            'new_wireless', 'A new wireless network appeared',
            f'"{after[key].get("name")}" ({after[key].get("security") or "open"})'
            f' did not exist before.',
            Severity.HIGH if str(after[key].get('security') or '').lower()
            in ('open', 'none', '') else Severity.MEDIUM,
            Tier.PUSH, key=f'wlans/{key}',
            evidence={'name': after[key].get('name'),
                      'security': after[key].get('security'),
                      'guest': bool(after[key].get('is_guest'))},
            next_check='Find out who added it and which network it bridges to.',
            ts=taken))

    return findings


def check(client, profile=None, state_path='', save=True):
    """
    One run: read the configuration, report what is wrong and what changed.

    Returns (findings, report). On a first run `report['baseline']` is true and
    the drift findings are empty by construction.
    """
    current = snapshot(client)
    previous = load_state(state_path) if state_path else None

    standing = audit(current, profile, previous)
    drift_findings = diff(previous, current, profile)

    # When something is both newly wrong and a change, the change is strictly
    # more informative: "a port forward appeared" beats "a port forward
    # exists". Reporting both would be two alerts for one event.
    changed = {finding.key for finding in drift_findings}
    standing = [finding for finding in standing if finding.key not in changed]

    findings = standing + drift_findings

    if state_path and save:
        save_state(current, state_path)

    return findings, {
        'baseline': previous is None,
        'taken_at': current['taken_at'],
        'previous_at': (previous or {}).get('taken_at'),
        'standing': len(standing),
        'changed': len(drift_findings),
        'counts': {name: len(current.get(name) or [])
                   for name in CONFIG_ENDPOINTS},
        'errors': current.get('errors') or {},
    }


def format_findings(findings, report):
    """The run as text."""
    lines = []
    if report['baseline']:
        lines += [
            'First run: the configuration has been recorded as the baseline.',
            'Changes will be reported from the next run onwards. What follows is',
            'what is wrong now, which needs no baseline.',
            '']
    elif report.get('previous_at') is not None:
        hours = (report['taken_at'] - report['previous_at']) / 3600
        lines.append(f'Compared against a snapshot from {hours:.1f} hours ago.')
        lines.append('')

    lines.append(', '.join(f'{v} {k.replace("_", " ")}'
                           for k, v in report['counts'].items() if v))
    for name, error in (report['errors'] or {}).items():
        lines.append(f'  could not read {name}: {error}')
    lines.append('')

    if not findings:
        lines.append('Nothing wrong, and nothing changed.')
        return '\n'.join(lines)

    ordered = sorted(findings, key=lambda f: (-Severity.rank(f.severity), f.rule_id))
    for finding in ordered:
        mark = '!!' if finding.severity == Severity.CRITICAL else \
            '! ' if finding.severity == Severity.HIGH else '~ ' \
            if finding.severity == Severity.MEDIUM else '  '
        lines.append(f'{mark} [{finding.severity:8}] {finding.rule_id}')
        lines.append(f'      {finding.description}')
        if finding.next_check:
            lines.append(f'      next: {finding.next_check}')
        lines.append('')
    return '\n'.join(lines)


def _main(argv=None):
    import argparse
    import sys

    from netmon.profile import ProfileError, load_profile
    from netmon.sources.unifi_api import UnifiApiError, UnifiClient

    parser = argparse.ArgumentParser(
        prog='python -m netmon.drift',
        description='Check the controller configuration: what is wrong now, '
                    'and what changed since last time. Read-only.')
    parser.add_argument('--profile', required=True, help='site profile YAML')
    parser.add_argument('--host', help='controller URL. Omit with --from-file')
    parser.add_argument('--site', default='default')
    parser.add_argument('--state', help='where to keep the snapshot between runs')
    parser.add_argument('--from-file', metavar='JSON',
                        help='compare a saved snapshot instead of fetching one')
    parser.add_argument('--no-save', action='store_true',
                        help='do not update the baseline')

    auth = parser.add_argument_group('credentials')
    auth.add_argument('--api-key', help='or set UNIFI_API_KEY')
    auth.add_argument('--username')
    auth.add_argument('--password', help='or set UNIFI_PASSWORD')

    tls = parser.add_argument_group('certificate')
    tls.add_argument('--fingerprint', help="the controller's SHA-256 fingerprint")
    tls.add_argument('--ca')
    tls.add_argument('--insecure', action='store_true')

    parser.add_argument('--notify', action='store_true',
                        help='push what needs attention now')
    parser.add_argument('--secrets', metavar='FILE')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

    try:
        profile = load_profile(args.profile)
    except ProfileError as e:
        print(f'profile: {e}', file=sys.stderr)
        return 1

    if args.from_file:
        current = load_state(args.from_file)
        if current is None:
            print(f'could not read {args.from_file}', file=sys.stderr)
            return 1
        previous = load_state(args.state) if args.state else None
        standing = audit(current, profile, previous)
        changes = diff(previous, current, profile)
        changed = {f.key for f in changes}
        findings = [f for f in standing if f.key not in changed] + changes
        report = {'baseline': previous is None, 'taken_at': current.get('taken_at', 0),
                  'previous_at': (previous or {}).get('taken_at'),
                  'standing': len(findings) - len(changes),
                  'changed': len(changes),
                  'counts': {n: len(current.get(n) or []) for n in CONFIG_ENDPOINTS},
                  'errors': current.get('errors') or {}}
        if args.state and not args.no_save:
            save_state(current, args.state)
    else:
        if not args.host:
            parser.error('pass --host, or --from-file with a saved snapshot')
        client = UnifiClient(
            args.host, site=args.site,
            api_key=args.api_key or os.environ.get('UNIFI_API_KEY', ''),
            username=args.username or os.environ.get('UNIFI_USERNAME', ''),
            password=args.password or os.environ.get('UNIFI_PASSWORD', ''),
            fingerprint=args.fingerprint or '', ca_bundle=args.ca or '',
            insecure=args.insecure)
        try:
            client.login()
            findings, report = check(client, profile, args.state,
                                     save=not args.no_save)
        except UnifiApiError as e:
            print(str(e), file=sys.stderr)
            return 1

    if args.json:
        print(json.dumps({'report': report,
                          'findings': [f.as_dict() for f in findings]},
                         indent=2, default=str))
    else:
        print(format_findings(findings, report))

    if args.notify and findings:
        from netmon.alerting import AlertingError, Notifier, load_config
        try:
            config = load_config(args.secrets)
            if args.dry_run:
                config.dry_run = True
            notifier = Notifier(config, profile)
            sent, held = notifier.send(findings)
        except AlertingError as e:
            print(f'alerting: {e}', file=sys.stderr)
            return 1
        print(f'pushed {len(sent)}, held back {len(held)}')
        if config.dry_run:
            for message in notifier.sent:
                print()
                print(f'--- would POST to {message["url"]} ---')
                print(message['body'])

    return 2 if any(f.tier == Tier.PUSH for f in findings) else 0


if __name__ == '__main__':
    import sys
    from netmon.drift import _main as main
    sys.exit(main())
