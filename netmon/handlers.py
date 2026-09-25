"""
Stateful rule handlers.
=======================
The rules that cannot be expressed as a test on one event: they need to remember
what came before. Beaconing needs a series of arrival times; "new device" needs
to know what old looks like; an upload is only anomalous relative to what that
device usually sends.

Each handler is `handler(event, rule, state)` and returns a Finding, a list, or
None. `state` is a plain dict private to that rule, so nothing here reaches for a
global and two RuleSets can run side by side over different captures.

Thresholds stay in YAML (`params:`) rather than here, so tuning a rule to a site
does not mean editing Python.

What these handlers deliberately do not do
------------------------------------------
None of them retains payload. They keep addresses, names, timestamps and counts
— the things needed to say "this happened, this often, to here". A segment
marked metadata-only in the profile is never treated differently by these
handlers because there is nothing for them to treat differently: they never had
the payload to begin with.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon.events import Finding, Severity, Tier                  # noqa: E402
from netmon.rules_engine import register_handler, render           # noqa: E402

from src.beaconing import (MIN_OBSERVATIONS, is_expected_periodic,  # noqa: E402
                           score_beacon)

__all__ = ['new_device', 'overlapping_ip', 'dhcp_loop', 'unanswered_name',
           'beaconing', 'new_destination', 'upload_volume']


def _finding(rule, event, description, key='', device='', severity=None,
             tier=None, evidence=None, next_check=''):
    """Build a Finding with the rule's defaults, overridable per occurrence."""
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=Severity.normalise(severity or rule.severity),
        tier=(tier or rule.tier),
        description=description,
        ts=event.ts,
        device=str(device or event.get('src_name') or event.src_ip or event.src_mac),
        key=str(key),
        next_check=next_check or render(rule.next_check, event),
        event=event,
        evidence=dict(evidence or {}),
    )


# ─── Inventory ───────────────────────────────────────────────────────────────

@register_handler('new_device')
def new_device(event, rule, state):
    """
    Report a MAC that is not in the profile, once.

    Keyed on MAC rather than address, because an address change is a different
    event and a device that DHCPs into a new address is not a new device. A
    device with no MAC — a flow export from the gateway, say — is skipped rather
    than reported, since "not in the registry" cannot be established from an
    address alone.
    """
    mac = event.src_mac
    if not mac or event.get('src_known'):
        return None

    seen = state.setdefault('seen', set())
    if mac in seen:
        return None
    seen.add(mac)

    zones = [z.lower() for z in (rule.params.get('zones') or [])]
    zone = (event.get('src_zone') or '').lower()
    tier = rule.tier if (not zones or zone in zones) else \
        rule.params.get('quiet_zones_tier', Tier.DIGEST)

    # A flow export carries no VLAN tag, so fall back to the one the address
    # resolves to rather than printing "VLAN None" at someone.
    vlan = event.get('observed_vlan')
    if vlan is None:
        vlan = event.get('src_vlan')
    where = f'VLAN {vlan}' if vlan is not None else 'the network'

    return _finding(
        rule, event, tier=tier, key=mac, device=mac,
        description=f"{mac} appeared on {where} "
                    f"as {event.src_ip or 'no address yet'}"
                    + (f" in the {zone} zone" if zone else ''),
        evidence={'mac': mac, 'ip': event.src_ip, 'vlan': vlan, 'zone': zone},
        next_check='Identify it physically, then add it to the profile or remove it.')


@register_handler('overlapping_ip')
def overlapping_ip(event, rule, state):
    """
    One address claimed by two MACs.

    Either a duplicate-address mistake or two segments that were never meant to
    share numbering. Both make every other lookup in this system ambiguous, so
    it is worth reporting even though it is rarely an attack.
    """
    owners = state.setdefault('owners', {})
    findings = []

    for ip, mac, vlan in ((event.src_ip, event.src_mac, event.get('src_vlan')),
                          (event.dst_ip, event.dst_mac, event.get('dst_vlan'))):
        if not ip or not mac:
            continue
        if rule.params.get('ignore_gateways', True) and ip in _gateways(event):
            continue

        previous = owners.get(ip)
        if previous is None:
            owners[ip] = (mac, vlan)
            continue
        if previous[0] == mac:
            continue

        reported = state.setdefault('reported', set())
        pair = (ip, *sorted((previous[0], mac)))
        if pair in reported:
            continue
        reported.add(pair)

        findings.append(_finding(
            rule, event, key=ip, device=ip,
            description=f"{ip} is claimed by {previous[0]} (VLAN {previous[1]}) "
                        f"and {mac} (VLAN {vlan})",
            evidence={'ip': ip, 'macs': [previous[0], mac],
                      'vlans': [previous[1], vlan]},
            next_check=f"arp -a | grep {ip}; check both switch ports"))

    return findings


def _gateways(event):
    """Gateway addresses, as enrichment saw them for this event."""
    found = set()
    if event.get('src_is_gateway'):
        found.add(event.src_ip)
    if event.get('dst_is_gateway'):
        found.add(event.dst_ip)
    return found


# ─── Addressing and names ────────────────────────────────────────────────────

@register_handler('dhcp_loop')
def dhcp_loop(event, rule, state):
    """
    A device asking for an address and never being answered.

    Counts Discovers per MAC and clears the count when that MAC is offered
    anything, so a device that simply takes a while to be served never reports.
    """
    if event.kind != 'dhcp':
        return None

    message = str(event.get('message', '')).lower()
    counts = state.setdefault('counts', {})

    if message in ('offer', 'ack'):
        # The answer may be addressed to the client's MAC rather than from it.
        for mac in (event.dst_mac, event.get('client_mac')):
            counts.pop(mac, None)
        return None

    if message not in ('discover', 'request'):
        return None

    mac = event.src_mac or event.get('client_mac')
    if not mac:
        return None

    window = float(rule.params.get('window_sec', 600))
    first, count = counts.get(mac, (event.ts, 0))
    if event.ts - first > window:
        first, count = event.ts, 0
    count += 1
    counts[mac] = (first, count)

    if count != int(rule.params.get('min_discovers', 10)):
        return None            # exactly once per window, at the threshold

    return _finding(
        rule, event, key=mac, device=mac,
        description=f"{event.get('src_name') or mac} sent {count} DHCP "
                    f"{message}s in {int(event.ts - first)}s with no offer",
        evidence={'mac': mac, 'count': count, 'vlan': event.get('observed_vlan')},
        next_check='Check the VLAN reaches a DHCP server, and that the port is '
                   'in the right VLAN.')


@register_handler('unanswered_name')
def unanswered_name(event, rule, state):
    """
    A name asked for repeatedly and never answered.

    Reports the (host, name) pair once per window. A name nobody owns is how a
    decommissioned server becomes a poisoning target, so the pair matters more
    than the count.
    """
    if event.kind not in ('dns', 'llmnr', 'nbns', 'mdns'):
        return None

    name = str(event.get('query') or '').lower()
    if not name:
        return None

    answered = state.setdefault('answered', set())
    if event.get('is_answer'):
        answered.add(name)
        return None
    if name in answered:
        return None

    window = float(rule.params.get('window_sec', 3600))
    pair = (event.src_ip or event.src_mac, name)
    counts = state.setdefault('counts', {})
    first, count = counts.get(pair, (event.ts, 0))
    if event.ts - first > window:
        first, count = event.ts, 0
    counts[pair] = (first, count + 1)

    if count + 1 != int(rule.params.get('min_queries', 5)):
        return None

    return _finding(
        rule, event, key=name,
        description=f"{event.get('src_name') or pair[0]} asked for {name} "
                    f"{count + 1} times with no answer",
        evidence={'name': name, 'queries': count + 1, 'protocol': event.kind},
        next_check=f'nslookup {name}; if it should not resolve, find what is '
                   f'still configured to ask for it.')


# ─── Behaviour over time ─────────────────────────────────────────────────────

@register_handler('beaconing')
def beaconing(event, rule, state):
    """
    Regular, low-jitter contact with one destination.

    Delegates the scoring to NetSentinel's beaconing module rather than
    reimplementing it: Bowley skewness and median absolute deviation over the
    interval series, which tolerate the jitter real implants add while still
    separating them from a cron job.

    Reports each destination once. Software updaters and time sync look exactly
    like this, which is why the finding names the destination and the interval
    and leaves the judgement to a person.
    """
    if not event.dst_ip or event.dst_ip == event.src_ip:
        return None
    if is_expected_periodic(dst_port=event.dst_port or 0,
                            src_port=event.src_port or 0):
        return None

    max_interval = float(rule.params.get('max_interval_sec', 86400))
    # The scorer needs MIN_OBSERVATIONS before it will judge at all, so asking
    # for fewer here would just mean scoring nothing until it had that many.
    min_samples = max(int(rule.params.get('min_samples', MIN_OBSERVATIONS)),
                      MIN_OBSERVATIONS)

    series = state.setdefault('series', {})
    pair = (event.src_ip, event.dst_ip)
    times = series.setdefault(pair, [])
    if times and event.ts - times[-1] > max_interval:
        times.clear()                      # a gap this long is a new pattern
    times.append(event.ts)
    if len(times) > 512:
        del times[:-512]

    if len(times) < min_samples:
        return None

    reported = state.setdefault('reported', set())
    if pair in reported:
        return None

    result = score_beacon(times)
    # `qualified` means only that there were enough observations to produce a
    # meaningful score — it is not a verdict. The verdict is the score.
    if not result['qualified']:
        return None
    if result['score'] < float(rule.params.get('min_score', 0.75)):
        return None
    reported.add(pair)

    interval = result['interval']
    return _finding(
        rule, event, key=event.dst_ip,
        description=f"{event.get('src_name') or event.src_ip} contacts "
                    f"{event.get('dst_name') or event.dst_ip} every "
                    f"{interval:.0f}s ({result['reason']}), {len(times)} times",
        evidence={'dst_ip': event.dst_ip, 'interval_sec': round(interval, 1),
                  'score': round(result['score'], 3),
                  'observations': len(times),
                  'jitter_pct': round(result['deviation_pct'], 1),
                  'sni': event.get('sni', '')},
        next_check=f"Identify the process: on the device, look for a scheduled "
                   f"task or service contacting {event.dst_ip}.")


@register_handler('new_destination')
def new_destination(event, rule, state):
    """
    A device in a sensitive zone contacting somewhere it never has.

    Learns quietly for `learn_sec` before reporting anything. Without that, the
    first day of running the monitor is one alert per destination per device,
    which teaches everyone to ignore it.
    """
    zones = [z.lower() for z in (rule.params.get('zones') or [])]
    zone = (event.get('src_zone') or '').lower()
    if zones and zone not in zones:
        return None

    target = event.get('sni') or event.get('domain') or event.dst_ip
    if not target or not event.src_ip:
        return None

    started = state.setdefault('started_at', event.ts)
    known = state.setdefault('known', {}).setdefault(event.src_ip, set())
    first_time = target not in known
    known.add(target)

    learning = event.ts - started < float(rule.params.get('learn_sec', 604800))
    if learning or not first_time:
        return None

    return _finding(
        rule, event, key=str(target),
        description=f"{event.get('src_name') or event.src_ip} contacted "
                    f"{target} for the first time",
        evidence={'destination': target, 'dst_ip': event.dst_ip,
                  'dst_port': event.dst_port, 'zone': zone,
                  'known_destinations': len(known)},
        next_check=f"Check whether {event.get('src_name') or event.src_ip} "
                   f"should reach {target} at all.")


@register_handler('upload_volume')
def upload_volume(event, rule, state):
    """
    More data leaving a device than it usually sends.

    Compares against the device's own median day rather than a fixed number,
    because a video recorder and a door panel have nothing in common. Quiet
    hours get a lower bar — the same volume at 3am means something different.

    `bytes_to_dst` is the outbound direction. Sources that label their columns
    the other way round are corrected in the importer, not here.
    """
    outbound = event.bytes_to_dst or 0
    if not outbound or not event.src_ip:
        return None

    min_bytes = float(rule.params.get('min_bytes', 50 * 1024 * 1024))
    totals = state.setdefault('daily', {})
    day = int(event.ts // 86400)
    key = (event.src_ip, day)
    totals[key] = totals.get(key, 0) + outbound
    today = totals[key]

    if today < min_bytes:
        return None

    history = sorted(total for (ip, d), total in totals.items()
                     if ip == event.src_ip and d != day)
    if not history:
        return None                    # nothing to compare against yet
    median = history[len(history) // 2]
    if median <= 0:
        return None

    multiple = float(rule.params.get('quiet_hours_multiple', 2)
                     if event.get('quiet_hours')
                     else rule.params.get('multiple', 4))
    if today < median * multiple:
        return None

    reported = state.setdefault('reported', set())
    if key in reported:
        return None
    reported.add(key)

    return _finding(
        rule, event, key=str(day),
        severity=Severity.HIGH if event.get('quiet_hours') else rule.severity,
        description=f"{event.get('src_name') or event.src_ip} has uploaded "
                    f"{today / 1048576:.0f} MB today, about "
                    f"{today / median:.1f}x its usual "
                    f"{median / 1048576:.0f} MB"
                    + (' — and it is outside working hours'
                       if event.get('quiet_hours') else ''),
        evidence={'uploaded_bytes': today, 'median_bytes': median,
                  'ratio': round(today / median, 2),
                  'quiet_hours': bool(event.get('quiet_hours')),
                  'days_of_history': len(history)},
        next_check=f"Identify the destination: the beaconing and "
                   f"egress_new_destination findings for this device, same day.")
