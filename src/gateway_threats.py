"""
The gateway's own threat detections, as NetSentinel alerts.
===========================================================
A UniFi gateway with IDS/IPS on (CyberSecure) sends each detection over syslog
as a CEF "Threat Detected" or "Threat Detected and Blocked" event, which
src/syslog_receiver.py receives. They were stored with the rest of its log and
nothing more: on 2026-11-11 the gateway blocked a reply from an address on the
CINS list and said so on the owner's phone, while NetSentinel had the same
event on disk and no alert about it.

Each is now a UNIFI-IPS alert carrying what the gateway said (its signature
and number, policy, risk and action) and what NetSentinel can add:
- Which side is this network's. "Incoming" is the gateway's view; an event
  from a remote's service port to an ephemeral port here is most likely the
  reply to something sent from here, as it was then (Discord testing its
  voice servers).
- When this PC started it, that it did, and which program it was. On
  2026-11-13 an SSH client here retrying an address on another private
  network was "ET SCAN Potential SSH Scan OUTBOUND"; the alert took the
  other address for this network's and said to check what it runs.
- The alert's check (alert_verify) weighs a reputation-list hit on a shared
  edge address (Cloudflare, Akamai, Fastly) as the list's entry for someone
  else, as NetSentinel does for its own feeds.
What came over syslog is untrusted text: shown, never acted on.
"""

import ipaddress
import re

RULE_ID = 'UNIFI-IPS'
_RISK = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM', 'low': 'LOW'}
# Policies and signatures that are lists of addresses with a bad name, not a
# pattern of attack: CINS Army, ET's poor-reputation and compromised lists...
REPUTATION = re.compile(r'(?i)reputation|\bCINS\b|dshield|compromised|spamhaus|\bdrop\b|'
                        r'blocklist|block list|tor exit')
EPHEMERAL_FROM = 32768


def _private(ip):
    try:
        return ipaddress.ip_address(str(ip)).is_private
    except ValueError:
        return False


def _port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return 0
    return port if 0 < port < 65536 else 0


def sides(record, own=()):
    """
    (local ip, local port, remote ip, remote port). This PC's own address
    (own) is local; otherwise the private one. With both private (another of
    the site's networks, a VPN) or both public, the gateway's direction says:
    'outgoing' starts on this side. Taking the destination then put this PC
    on the far side of its own connection.
    """
    src, dst = record.get('src', ''), record.get('dst', '')
    sport, dport = _port(record.get('sport')), _port(record.get('dport'))
    own = own or ()
    if src in own or dst in own:
        local_is_src = src in own
    elif _private(src) != _private(dst):
        local_is_src = _private(src)
    else:
        local_is_src = str(record.get('direction', '')).lower() == 'outgoing'
    if local_is_src:
        return src, sport, dst, dport
    return dst, dport, src, sport


def started_here(record, own=()):
    """This PC (an address in own) opened the connection the gateway reported."""
    return bool(own) and record.get('src', '') in own


def looks_like_reply(record, own=()):
    """
    The gateway calls it incoming, but it comes from the remote's service port
    to an ephemeral one here: most likely the answer to something sent from here.
    """
    local, local_port, remote, remote_port = sides(record, own)
    return (str(record.get('direction', '')).lower() == 'incoming'
            and record.get('src') == remote and bool(local_port) and bool(remote_port)
            and remote_port < local_port and local_port >= EPHEMERAL_FROM)


def is_reputation_hit(record):
    return bool(REPUTATION.search(f"{record.get('rule', '')} {record.get('signature', '')}"))


def threat_alert(record, own=(), program=''):
    """
    The UNIFI-IPS alert for one gateway IDS/IPS event (see the module notes).
    own: this PC's addresses. program: what had this PC's end of the
    connection, when it started here and NetSentinel could tell.
    """
    from src.ids_engine import Alert
    blocked = record.get('action') == 'block'
    what = (record.get('signature') or record.get('rule') or record.get('event')
            or 'IPS detection')
    local, local_port, remote, remote_port = sides(record, own)
    reply = looks_like_reply(record, own)
    from_here = started_here(record, own)
    reputation = is_reputation_hit(record)
    evidence = {
        'gateway_event': record.get('event', ''),
        'gateway_action': 'blocked' if blocked else 'detected, not blocked',
        'gateway_risk': record.get('risk', ''),
        'policy': record.get('rule', ''),
        'policy_type': record.get('policy_type', ''),
        'signature': record.get('signature', ''),
        'signature_id': record.get('signature_id', ''),
        'gateway_direction': record.get('direction', ''),
        'gateway': record.get('gateway', ''),
        'connection': (f"{record.get('src', '')}:{record.get('sport', '')} → "
                       f"{record.get('dst', '')}:{record.get('dport', '')} "
                       f"({record.get('proto', '')})"),
        'local_ip': local,
        'remote_ip': remote,
        'reputation_list': reputation,
        'gateway_message': record.get('message', ''),
        'reported_by': 'The UniFi gateway, over syslog',
    }
    if from_here:
        evidence['started_here'] = (
            f"This PC opened the connection, from port {local_port or '?'} to "
            f"{remote}:{remote_port or '?'}."
            + ('' if program else " Which program could not be told: the connection "
                                  "had ended, or NetSentinel could not see it."))
        if program:
            evidence['program'] = program
    who = program or 'a program on this PC'
    if reply:
        evidence['looks_like_a_reply'] = (
            f"The gateway calls it incoming, but it came from {remote}'s port "
            f"{remote_port} to port {local_port} here, an ephemeral one: most likely the "
            f"answer to something {local} sent first.")
    if reputation and reply:
        recommendation = (
            f"{remote} is on a list of addresses with a bad name, and {local} talked to it "
            f"first. Find what on {local} did (the time is above); a program you use "
            f"explains it, and the list's entry may be for someone else sharing the address.")
    elif reputation and from_here:
        recommendation = (
            f"{remote} is on a list of addresses with a bad name, and {who} connected to "
            f"it. If you know the program, the list's entry may be about someone else "
            f"sharing the address.")
    elif reputation:
        recommendation = (f"{remote} is on a list of addresses with a bad name. Find which "
                          f"program on {local} it was talking to.")
    elif from_here:
        recommendation = (
            f"This PC started it: {who} connected to {remote} on port "
            f"{remote_port or '?'}, and the gateway matched {what}. If it is a tool or "
            f"script of yours, check what it was pointed at and how often it retries; "
            f"if you don't know the program, find out what it is.")
    else:
        recommendation = (f"Look at what {local} runs on port {local_port or 'this port'} and "
                          f"whether it is up to date: the gateway matched a known attack "
                          f"pattern.")
    evidence['recommendation'] = recommendation
    return Alert(
        RULE_ID, _RISK.get(str(record.get('risk', '')).lower(), 'MEDIUM'),
        f"UniFi {'blocked' if blocked else 'detected'}: {what}"[:160],
        record.get('message') or f"The gateway reported {what}",
        src_ip=record.get('src', ''), dst_ip=record.get('dst', ''),
        src_port=_port(record.get('sport')), dst_port=_port(record.get('dport')),
        protocol=str(record.get('proto', ''))[:10], category='Gateway IPS',
        timestamp=record.get('time') or None,
        evidence={k: v for k, v in evidence.items() if v not in ('', None)},
    )
