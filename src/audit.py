"""
Active subnet audit
===================
Everything else in NetSentinel is passive: it watches traffic and sends none of
its own. This module is the one exception, and only when the owner asks, one run
at a time, against networks the owner names. A run:

1. finds hosts: an ARP sweep where scapy, Npcap and the account's rights allow,
   otherwise a TCP connect "ping" on a few common ports (the report says which);
2. connects to a curated list of top ports, rate-limited, or a much smaller list
   at a much lower rate in gentle mode, for building and OT controllers that can
   fall over when scanned;
3. flags risky services (Telnet, FTP, SMB on workstations, RDP, VNC, UPnP, WinRM,
   exposed databases, controller protocols, admin pages without TLS), each with a
   severity, why it matters, and how to fix it;
4. reads the certificate of each TLS service, which the passive IDS cannot see
   once TLS 1.3 encrypts it, and reports expired, expiring and self-signed ones;
5. saves the result under ~/.netsentinel/data/audit/ and diffs it against the
   last audit of the same network, so newly opened ports stand out.

What it never does:
- try a password, a default credential or an exploit. The only bytes it sends
  are TCP handshakes, ARP requests, one `GET /` on web ports and a TLS handshake
  on TLS ports. A banner is read only where the server speaks first;
- touch anything outside the chosen networks, which must be RFC 1918, IPv4
  link-local or IPv6 ULA, no larger than a /16, and overlap an interface of this
  computer that is up;
- run by itself. There is no timer and no schedule: every audit is a call.

Output is advisory, like the rest of NetSentinel: nothing is blocked or changed.

API for the desktop GUI and the dashboard (all thread-safe):
    local_networks()                       the choices to offer
    validate_network(text) / validate_networks(list)
    run_audit(networks, *, gentle=False, ports=None, progress=None, cancel=None)
    start_audit(networks, ...) -> AuditJob  the same, on a background thread
    current_job(), is_running()
    last_report(network), diff(old, new)
    saved_networks()                       the owner's remembered choices (audit.networks)

CLI: python -m src.audit --network 192.168.1.0/24 [--gentle] [--ports LIST] [--json]
"""

import contextlib
import errno
import hashlib
import html
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import struct
import sys
import threading
import time
import warnings
from datetime import datetime, timedelta, timezone

import src.config as _config
from src import __version__ as _VERSION

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a hard dependency of the app
    psutil = None

try:
    from src.forensics import (
        DEFAULT_EXPLOITATION as _DEFAULT_EXPLOIT,
        INSECURE_PROTOCOLS as _INSECURE,
        PROTOCOL_EXPLOITATION as _EXPLOIT,
        SECURE_EQUIVALENTS as _SECURE,
    )
except Exception:  # pragma: no cover - keeps the audit usable if forensics moves
    _EXPLOIT, _INSECURE, _SECURE = {}, {}, {}
    _DEFAULT_EXPLOIT = {
        'how_exploited': 'This protocol transmits data without encryption.',
        'how_to_fix': 'Switch to the encrypted version of this protocol.',
    }

logger = logging.getLogger("NetSentinel.Audit")

__all__ = [
    'AuditError', 'ScopeError', 'AuditDisabled', 'AuditBusy', 'AuditJob',
    'local_networks', 'validate_network', 'validate_networks', 'parse_ports',
    'run_audit', 'start_audit', 'current_job', 'is_running',
    'last_report', 'diff', 'parse_certificate', 'LiveProber', 'RateLimiter',
    'saved_networks', 'format_report',
    'TOP_PORTS', 'GENTLE_PORTS', 'SEVERITIES', 'main',
]

SCHEMA = 1
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# A /16. Past this a sweep stops being an audit of "my network" and starts being
# a survey; for IPv6 it means nothing shorter than a /112.
MAX_ADDRESSES = 65536
# A typo in a port list must not turn into tens of thousands of probes per host.
MAX_PORTS = 1024

_ALLOWED_RANGES = (
    (ipaddress.ip_network('10.0.0.0/8'), 'rfc1918'),
    (ipaddress.ip_network('172.16.0.0/12'), 'rfc1918'),
    (ipaddress.ip_network('192.168.0.0/16'), 'rfc1918'),
    (ipaddress.ip_network('169.254.0.0/16'), 'link-local'),
    (ipaddress.ip_network('fc00::/7'), 'ula'),
)
_LOOPBACK = (ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('::1/128'))
_V6_LINK_LOCAL = ipaddress.ip_network('fe80::/10')

# ─── Port lists ──────────────────────────────────────────────────────────────
# Common risky services and admin UIs, plus what building and industrial sites
# run (Niagara Fox, Modbus, S7, DNP3, EtherNet/IP). BACnet/IP and SNMP are UDP and
# a TCP connect cannot see them; the passive IDS does.
TOP_PORTS = (
    21, 22, 23, 25, 53, 80, 81, 88, 102, 110, 111, 135, 139, 143, 389, 443, 445,
    465, 502, 512, 513, 514, 515, 548, 554, 587, 631, 636, 873, 993, 995, 1080,
    1433, 1521, 1723, 1883, 1900, 1911, 2049, 2375, 2376, 2869, 3000, 3128, 3306,
    3389, 4443, 4911, 5000, 5001, 5432, 5601, 5800, 5900, 5901, 5902, 5903, 5984,
    5985, 5986, 6379, 6443, 7547, 8000, 8008, 8080, 8081, 8086, 8443, 8883, 8888,
    9000, 9042, 9090, 9100, 9200, 9443, 10000, 11211, 15672, 20000, 27017, 44818,
)

# Gentle mode: what matters on a controls network, and little else. Old
# controllers can hang on a burst of half-open connections, so fewer ports also
# means fewer chances to knock one over.
GENTLE_PORTS = (
    21, 22, 23, 80, 102, 443, 445, 502, 1911, 3389, 4911, 5900, 8080, 8443,
    20000, 44818,
)

# A refused connect proves a host is there as surely as an accepted one, so these
# only need to be ports that most hosts either serve or actively refuse.
DISCOVERY_PORTS = (80, 443, 445, 22, 3389, 135)
GENTLE_DISCOVERY_PORTS = (80, 443)

# Servers that speak first. Reading what they say sends nothing.
BANNER_PORTS = frozenset({21, 22, 23, 25, 110, 143, 587, 3306, 5900, 5901, 5902, 5903})
HTTP_PORTS = frozenset({80, 81, 3000, 5000, 5601, 5800, 8000, 8008, 8080, 8081, 8888,
                        9000, 9090, 10000, 15672})
HTTPS_PORTS = frozenset({443, 4443, 5001, 8443, 9443})
# TLS from the first byte but not HTTP: the handshake alone gives the certificate.
TLS_PORTS = frozenset({465, 636, 993, 995, 2376, 4911, 5986, 6443, 8883})

PORT_NAMES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    81: 'HTTP-alt', 88: 'Kerberos', 102: 'Siemens S7', 110: 'POP3', 111: 'rpcbind',
    135: 'MS-RPC', 139: 'NetBIOS-SSN', 143: 'IMAP', 389: 'LDAP', 443: 'HTTPS',
    445: 'SMB', 465: 'SMTPS', 502: 'Modbus/TCP', 512: 'rexec', 513: 'rlogin',
    514: 'rsh', 515: 'LPD', 548: 'AFP', 554: 'RTSP', 587: 'SMTP submission',
    631: 'IPP', 636: 'LDAPS', 873: 'rsync', 993: 'IMAPS', 995: 'POP3S',
    1080: 'SOCKS proxy', 1433: 'MSSQL', 1521: 'Oracle DB', 1723: 'PPTP',
    1883: 'MQTT', 1900: 'UPnP/SSDP', 1911: 'Niagara Fox', 2049: 'NFS',
    2375: 'Docker API', 2376: 'Docker API (TLS)', 2869: 'UPnP (Windows SSDP)',
    3000: 'HTTP-dev', 3128: 'HTTP proxy', 3306: 'MySQL', 3389: 'RDP',
    4443: 'HTTPS-alt', 4911: 'Niagara Fox (TLS)', 5000: 'UPnP/HTTP',
    5001: 'HTTPS-alt', 5432: 'PostgreSQL', 5601: 'Kibana', 5800: 'VNC over HTTP',
    5900: 'VNC', 5901: 'VNC :1', 5902: 'VNC :2', 5903: 'VNC :3', 5984: 'CouchDB',
    5985: 'WinRM (HTTP)', 5986: 'WinRM (HTTPS)', 6379: 'Redis',
    6443: 'Kubernetes API', 7547: 'TR-069', 8000: 'HTTP-alt', 8008: 'HTTP-alt',
    8080: 'HTTP-proxy/alt', 8081: 'HTTP-alt', 8086: 'InfluxDB', 8443: 'HTTPS-alt',
    8883: 'MQTTS', 8888: 'HTTP-alt', 9000: 'HTTP-alt', 9042: 'Cassandra',
    9090: 'HTTP-admin', 9100: 'JetDirect', 9200: 'Elasticsearch',
    9443: 'HTTPS-alt', 10000: 'Webmin', 11211: 'Memcached', 15672: 'RabbitMQ UI',
    20000: 'DNP3', 27017: 'MongoDB', 44818: 'EtherNet/IP',
}


def port_name(port):
    return PORT_NAMES.get(port) or (_INSECURE.get(port) or {}).get('name') or f'tcp/{port}'


# ─── Risky services ──────────────────────────────────────────────────────────
# port -> (finding id, title, severity). Severity is for a port open on the LAN,
# which is not the same as forensics' risk for a protocol seen in use: an open
# Redis is HIGH, not CRITICAL, because a connect cannot tell whether it has a
# password, and this audit never sends a command to find out.
_PORT_RULES = {
    21: ('AUDIT-FTP', 'FTP is open', 'HIGH'),
    23: ('AUDIT-TELNET', 'Telnet is open', 'HIGH'),
    512: ('AUDIT-R-SERVICES', 'rexec is open', 'HIGH'),
    513: ('AUDIT-R-SERVICES', 'rlogin is open', 'HIGH'),
    514: ('AUDIT-R-SERVICES', 'rsh is open', 'HIGH'),
    135: ('AUDIT-RPC', 'Windows RPC endpoint mapper is reachable', 'LOW'),
    139: ('AUDIT-NETBIOS', 'NetBIOS session service is open', 'LOW'),
    3389: ('AUDIT-RDP', 'Remote Desktop is reachable', 'MEDIUM'),
    5800: ('AUDIT-VNC', 'VNC (web viewer) is open', 'HIGH'),
    5900: ('AUDIT-VNC', 'VNC remote desktop is open', 'HIGH'),
    5901: ('AUDIT-VNC', 'VNC remote desktop is open', 'HIGH'),
    5902: ('AUDIT-VNC', 'VNC remote desktop is open', 'HIGH'),
    5903: ('AUDIT-VNC', 'VNC remote desktop is open', 'HIGH'),
    1900: ('AUDIT-UPNP', 'UPnP is reachable', 'MEDIUM'),
    2869: ('AUDIT-UPNP', 'UPnP (Windows SSDP/UPnP host) is reachable', 'MEDIUM'),
    5985: ('AUDIT-WINRM', 'WinRM (PowerShell remoting) over HTTP is reachable', 'MEDIUM'),
    5986: ('AUDIT-WINRM', 'WinRM (PowerShell remoting) is reachable', 'LOW'),
    2375: ('AUDIT-DOCKER-API', 'Docker API without TLS is open', 'CRITICAL'),
    6379: ('AUDIT-DATABASE', 'Redis is reachable', 'HIGH'),
    27017: ('AUDIT-DATABASE', 'MongoDB is reachable', 'HIGH'),
    9200: ('AUDIT-DATABASE', 'Elasticsearch is reachable', 'HIGH'),
    11211: ('AUDIT-DATABASE', 'Memcached is reachable', 'HIGH'),
    5984: ('AUDIT-DATABASE', 'CouchDB is reachable', 'HIGH'),
    1433: ('AUDIT-DATABASE', 'SQL Server is reachable', 'MEDIUM'),
    1521: ('AUDIT-DATABASE', 'Oracle database is reachable', 'MEDIUM'),
    3306: ('AUDIT-DATABASE', 'MySQL is reachable', 'MEDIUM'),
    5432: ('AUDIT-DATABASE', 'PostgreSQL is reachable', 'MEDIUM'),
    9042: ('AUDIT-DATABASE', 'Cassandra is reachable', 'MEDIUM'),
    8086: ('AUDIT-DATABASE', 'InfluxDB is reachable', 'MEDIUM'),
    502: ('AUDIT-OT-PROTOCOL', 'Modbus/TCP is reachable', 'HIGH'),
    102: ('AUDIT-OT-PROTOCOL', 'Siemens S7 is reachable', 'HIGH'),
    20000: ('AUDIT-OT-PROTOCOL', 'DNP3 is reachable', 'HIGH'),
    44818: ('AUDIT-OT-PROTOCOL', 'EtherNet/IP is reachable', 'HIGH'),
    1911: ('AUDIT-NIAGARA-FOX', 'Niagara Fox without TLS is reachable', 'MEDIUM'),
    7547: ('AUDIT-TR069', 'TR-069 (CWMP) management is reachable', 'MEDIUM'),
    1723: ('AUDIT-PPTP', 'PPTP VPN is open', 'MEDIUM'),
    3128: ('AUDIT-PROXY', 'An HTTP proxy is open', 'MEDIUM'),
    1080: ('AUDIT-PROXY', 'A SOCKS proxy is open', 'MEDIUM'),
    873: ('AUDIT-FILE-SHARING', 'rsync is open', 'MEDIUM'),
    2049: ('AUDIT-FILE-SHARING', 'NFS is open', 'MEDIUM'),
    111: ('AUDIT-FILE-SHARING', 'rpcbind (NFS portmapper) is open', 'LOW'),
    554: ('AUDIT-RTSP', 'RTSP camera/stream service is open', 'MEDIUM'),
    1883: ('AUDIT-MQTT', 'MQTT without TLS is open', 'MEDIUM'),
    25: ('AUDIT-CLEARTEXT-MAIL', 'SMTP is open', 'LOW'),
    110: ('AUDIT-CLEARTEXT-MAIL', 'POP3 without TLS is open', 'LOW'),
    143: ('AUDIT-CLEARTEXT-MAIL', 'IMAP without TLS is open', 'LOW'),
    9100: ('AUDIT-PRINTER', 'Raw printing (JetDirect) is open', 'LOW'),
    515: ('AUDIT-PRINTER', 'LPD printing is open', 'LOW'),
}

# Advice for what forensics does not cover. Where forensics.PROTOCOL_EXPLOITATION
# has an entry it wins, so the passive and active sides say the same thing.
_OWN_ADVICE = {
    3389: (
        'RDP is a favourite way in for ransomware operators: it is brute-forced, and '
        'unpatched hosts have had pre-login remote code execution bugs (BlueKeep, '
        'CVE-2019-0708, and DejaBlue). Inside a LAN it is also how an intruder on one '
        'PC moves to the next.',
        '1. Require Network Level Authentication (System Properties > Remote > allow '
        'connections only with NLA).\n'
        '2. Allow inbound 3389 in Windows Defender Firewall only from the admin hosts '
        'that need it, or turn Remote Desktop off.\n'
        '3. Keep the host patched and set an account lockout policy.\n'
        '4. Reach it from outside only through a VPN or RD Gateway, never a port forward.'),
    1900: (
        'UPnP lets any program on the LAN ask a router to open inbound ports without a '
        'password, which malware and botnets use to expose themselves. UPnP stacks have '
        'a long record of remote bugs (CallStranger, CVE-2020-12695, and libupnp '
        'overflows), and SSDP is abused for DDoS reflection.',
        '1. Turn UPnP off on the router unless a specific device needs it, and never '
        'allow it on the WAN side.\n'
        '2. Turn it off on cameras, NAS boxes and printers that do not need discovery.\n'
        '3. On Windows PCs that do not share media, disable the "SSDP Discovery" and '
        '"UPnP Device Host" services.'),
    5985: (
        'WinRM is PowerShell remoting: anyone holding an admin credential, or just its '
        'NTLM hash, gets a remote shell over it, which is why intrusion tools use it '
        'to move between machines. On 5985 the transport is HTTP; Windows encrypts the '
        'payload after authentication, but Basic authentication, if enabled, sends the '
        'password in clear.',
        '1. If the host is not managed remotely, stop and disable WinRM '
        '(Stop-Service WinRM; Set-Service WinRM -StartupType Disabled) or block 5985/5986 '
        'in the firewall.\n'
        '2. Where it is needed, allow it only from management hosts, prefer HTTPS (5986), '
        'and keep Basic authentication off (winrm get winrm/config/service/auth).\n'
        '3. Watch for remote PowerShell sessions nobody started.'),
    135: (
        'The RPC endpoint mapper is how remote tools find WMI, DCOM, scheduled-task and '
        'service-control interfaces. PsExec- and WMI-style lateral movement starts here, '
        'and it has carried remote bugs before (MS03-026, exploited by Blaster). '
        'Workstations seldom need to accept it from other workstations.',
        '1. In Windows Defender Firewall, allow inbound RPC (135 and the dynamic RPC '
        'range) only from management and domain hosts.\n'
        '2. Keep the host patched.\n'
        '3. Never let 135 through to the internet.'),
    139: (
        'NetBIOS over TCP/IP is SMB\'s pre-2000 transport. Hosts that run it also answer '
        'NetBIOS name queries, which tools like Responder poison to capture NTLM hashes, '
        'and it gives host and user names to anyone who asks.',
        '1. Disable NetBIOS over TCP/IP on each adapter (IPv4 properties > Advanced > '
        'WINS > Disable NetBIOS over TCP/IP), or for everyone via DHCP.\n'
        '2. Turn off LLMNR as well (Group Policy: Turn off multicast name resolution).\n'
        '3. File sharing keeps working over 445.'),
    2375: (
        'The Docker API on 2375 has no authentication and no TLS: anyone who can reach '
        'it can start a privileged container that mounts the host\'s disk, which is root '
        'on the host. Cryptomining botnets scan for it.',
        '1. Stop exposing the daemon on TCP: remove "-H tcp://0.0.0.0:2375" or the '
        '"hosts" entry in daemon.json.\n'
        '2. If remote access is needed, use SSH (docker -H ssh://host) or TLS client '
        'certificates on 2376.\n'
        '3. Check for containers nobody started.'),
    1911: (
        'Fox is the station protocol of Niagara (Tridium JACE and Supervisor). On 1911 '
        'it runs without TLS, so station logins and every point value cross the network '
        'in clear; Niagara stations have had remote authentication bugs, and internet '
        'search engines index them by this port.',
        '1. Turn on Foxs (TLS, port 4911) in the station\'s FoxService and turn plain Fox '
        'off.\n'
        '2. Restrict 1911/4911 to the supervisor and engineering hosts.\n'
        '3. Keep Niagara at a patched release and remove default accounts.'),
    7547: (
        'TR-069 (CWMP) is how an ISP manages a router. Its connection-request service '
        'listens on 7547, and a bug there let a Mirai variant knock about 900,000 '
        'Deutsche Telekom routers offline in 2016. Nothing on the LAN needs it.',
        '1. If you manage the router yourself, turn off remote management (TR-069/CWMP), '
        'or ask the ISP to.\n'
        '2. Make sure 7547 is not reachable from the internet.\n'
        '3. Keep the router\'s firmware current.'),
    1723: (
        'PPTP\'s MS-CHAPv2 authentication can be cracked from one captured handshake, '
        'so a PPTP VPN protects neither its password nor its traffic.',
        '1. Replace PPTP with WireGuard, IKEv2/IPsec or OpenVPN.\n'
        '2. Turn the PPTP server off on the router or host.'),
    3128: (
        'An open proxy on the LAN lets any device reach the internet through it, past '
        'whatever filtering and logging the gateway does, and malware uses such proxies '
        'to hide its traffic.',
        '1. If the proxy is meant to be there, require authentication and allow only the '
        'client subnets that need it.\n'
        '2. Otherwise stop the service.'),
    9100: (
        'Raw printing accepts jobs and PJL/PostScript commands from anyone, with no '
        'login; on many printers those commands can read stored jobs, change settings '
        'or write to the printer\'s disk.',
        '1. Restrict printing to the print server or the client subnets in the printer\'s '
        'access list.\n'
        '2. Turn off unused protocols (LPD, raw 9100, FTP, Telnet) in its web settings.\n'
        '3. Keep printer firmware current.'),
}
_OWN_ADVICE[2869] = _OWN_ADVICE[1900]
_OWN_ADVICE[5000] = _OWN_ADVICE[1900]
_OWN_ADVICE[5986] = _OWN_ADVICE[5985]
_OWN_ADVICE[1080] = _OWN_ADVICE[3128]
_OWN_ADVICE[515] = _OWN_ADVICE[9100]
for _p in (5800, 5901, 5902, 5903):
    if _p not in _EXPLOIT and 5900 in _EXPLOIT:
        _OWN_ADVICE[_p] = (_EXPLOIT[5900]['how_exploited'], _EXPLOIT[5900]['how_to_fix'])
for _p, _label in ((102, 'Siemens S7'), (20000, 'DNP3'), (44818, 'EtherNet/IP')):
    _OWN_ADVICE[_p] = (
        f'{_label} has no authentication: anything that can reach the port can read and '
        'write the controller\'s values and, on many models, stop it or load new logic. '
        'Reaching it from this computer means the controls network is reachable from '
        'wherever this computer sits.',
        '1. Keep controllers on their own VLAN, reachable only from the engineering '
        'workstation and the supervisory server.\n'
        '2. Put a firewall or an OT-aware gateway between the controls VLAN and the '
        'office LAN.\n'
        '3. Audit controllers in gentle mode, and only when someone can reset them.')
for _p in (1433, 1521, 3306, 5432, 9042, 5984, 11211, 8086):
    _desc = (_INSECURE.get(_p) or {}).get('desc') or f'{port_name(_p)} database'
    _eq = _SECURE.get(_p)
    _OWN_ADVICE[_p] = (
        f'{_desc}. A database every machine on the LAN can reach is one weak or default '
        'password away from a breach, and ransomware crews dump and wipe exposed '
        'databases.',
        '1. Bind it to localhost or to the interface its applications use.\n'
        '2. Allow the port in the host firewall only from the application servers.\n'
        '3. Require authentication and change default accounts'
        + (f'; use {_eq}.' if _eq else '.'))

_SMB_WORKSTATION_WHY = (
    ' A workstation that shares nothing should not accept SMB from its neighbours: '
    'WannaCry and NotPetya spread host to host over it, and so do ransomware operators.')
_SMB_WORKSTATION_FIX = (
    'Turn off file and printer sharing on workstations that do not share folders '
    '(Advanced sharing settings), or allow inbound 445 and 139 only from admin hosts. '
    'Where SMB must stay:\n')

_ADMIN_HTTP_WHY = (
    'An admin page served over plain HTTP sends its password across the LAN in clear, '
    'where anyone running a packet capture or an ARP-spoofing tool can read it.')
_TLS_OLD = (
    'TLS 1.0 and 1.1 were retired in 2021 (RFC 8996): they depend on SHA-1 and on CBC '
    'constructions with known attacks, and current browsers refuse them, which teaches '
    'people to click through warnings or fall back to plain HTTP.',
    '1. Update the device\'s firmware and enable TLS 1.2 or 1.3.\n'
    '2. If the vendor no longer supports it, keep it on an isolated VLAN and reach its '
    'admin page only from a management host.')
_CERT_WHY_EXPIRED = (
    'Clients reject or warn about an expired certificate, so people learn to click '
    'through the warning, and a man-in-the-middle\'s fake certificate then looks no '
    'different.')
_CERT_WHY_SELF = (
    'No client can tell a self-signed certificate from an attacker\'s, so every visit '
    'starts with a warning people learn to accept, which is exactly what a '
    'man-in-the-middle needs.')
_CERT_WHY_WEAK = (
    'RSA keys under 2048 bits and SHA-1 or MD5 signatures can be broken or forged with '
    'today\'s computing, and clients increasingly refuse them.')
_CERT_FIX_RENEW = (
    'Renew it from an internal CA your computers trust (for example Active Directory '
    'Certificate Services) or by ACME for a real domain, and note the next expiry date.')

# Page titles and Server headers that mean "this is somebody's admin UI".
_ADMIN_RE = re.compile(
    r'log ?in|sign ?in|admin|router|gateway|modem|config|setup|management|manager|'
    r'dashboard|control panel|web ?ui|firmware|access point|\bnas\b|\bdsm\b|'
    r'idrac|\bilo\b|ipmi|\bbmc\b|unifi|pfsense|opnsense|mikrotik|routeros|openwrt|luci|'
    r'dd-wrt|fortigate|sonicwall|watchguard|proxmox|esxi|vsphere|portainer|grafana|'
    r'kibana|jenkins|phpmyadmin|webmin|cockpit|home assistant|node-red|octoprint|'
    r'synology|qnap|hikvision|dahua|\baxis\b|camera|printer|\bups\b|\bpdu\b', re.I)
# Building automation and industrial controller UIs: worth gentle mode next time.
_CONTROLS_RE = re.compile(
    r'niagara|\bjace\b|tridium|bacnet|desigo|siemens|metasys|johnson controls|honeywell|'
    r'webs-?ax|ecostruxure|schneider|distech|delta controls|enteliweb|automated logic|'
    r'webctrl|alerton|reliable controls|carel|danfoss|lonworks|echelon|sauter|beckhoff|'
    r'\bwago\b|phoenix contact|rockwell|allen-bradley|modicon|simatic|scada|\bhmi\b|\bplc\b',
    re.I)
_CONTROLS_PORTS = frozenset({102, 502, 1911, 4911, 20000, 44818})


# ─── Errors ──────────────────────────────────────────────────────────────────
class AuditError(Exception):
    """Base class for an audit that cannot start."""


class ScopeError(AuditError, ValueError):
    """A network, address or port list the audit refuses to touch."""

    def __init__(self, message, reason='invalid'):
        super().__init__(message)
        self.reason = reason


class AuditDisabled(AuditError):
    """audit.enabled is off: the owner has not opted in."""


class AuditBusy(AuditError):
    """Another audit is running. Two at once would double the rate on every host."""


class ArpUnavailable(Exception):
    """The ARP sweep cannot run (no scapy, no Npcap, no rights). `found` holds any
    hosts already answered and `remaining` the addresses still to try."""

    def __init__(self, reason, found=None, remaining=None):
        super().__init__(reason)
        self.reason = reason
        self.found = found or {}
        self.remaining = remaining


# ─── Interfaces and scope ────────────────────────────────────────────────────
def _v6_prefix(mask):
    # Windows reports no IPv6 netmask at all. /64 is what nearly every IPv6 LAN uses,
    # and the size limit refuses anything that big anyway, so the guess only decides
    # whether a small ULA range sits on this interface.
    if not mask:
        return 64
    try:
        return int(mask)
    except (TypeError, ValueError):
        pass
    try:
        return bin(int(ipaddress.IPv6Address(str(mask).split('/')[0]))).count('1')
    except ValueError:
        return 64


def _interface_addresses():
    """[(interface name, ipaddress interface)] for every interface that is up."""
    if psutil is None:
        return []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception as exc:
        logger.warning("Could not list network interfaces: %s", exc)
        return []
    out = []
    for name, entries in addrs.items():
        st = stats.get(name)
        # A down adapter keeps its APIPA address; scanning "its" network would send
        # packets out of whatever interface is up instead.
        if st is not None and not st.isup:
            continue
        for entry in entries:
            if entry.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            addr = str(entry.address).split('%')[0]
            try:
                if entry.family == socket.AF_INET6:
                    iface = ipaddress.ip_interface(f'{addr}/{_v6_prefix(entry.netmask)}')
                elif entry.netmask:
                    iface = ipaddress.ip_interface(f'{addr}/{entry.netmask}')
                else:
                    iface = ipaddress.ip_interface(f'{addr}/32')
            except ValueError:
                continue
            out.append((name, iface))
    return out


def _normalise_interfaces(entries):
    out = []
    for entry in entries:
        name, iface = entry[0], entry[1]
        if not isinstance(iface, (ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
            iface = ipaddress.ip_interface(str(iface))
        out.append((str(name), iface))
    return out


def _range_kind(net):
    for allowed, kind in _ALLOWED_RANGES:
        if net.version == allowed.version and net.subnet_of(allowed):
            return kind
    return None


def validate_network(text, interfaces=None):
    """
    Return the ipaddress network for `text`, or raise ScopeError saying why not.

    Host bits are allowed and dropped ("192.168.1.7/24" is 192.168.1.0/24), and a
    bare address is a /32. `interfaces` is for tests; normally this machine's own
    interfaces are read with psutil.
    """
    if isinstance(text, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        net = text
    else:
        raw = str(text if text is not None else '').strip()
        if not raw:
            raise ScopeError('No network given.', 'invalid')
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ScopeError(f'"{raw[:60]}" is not a network; use CIDR, like 192.168.1.0/24.',
                             'invalid') from None
    if any(net.version == lb.version and net.subnet_of(lb) for lb in _LOOPBACK):
        raise ScopeError(f'{net} is loopback; the audit only scans real networks.', 'loopback')
    if net.version == 6 and net.subnet_of(_V6_LINK_LOCAL):
        # Connecting to fe80:: needs an interface scope, which Windows does not
        # report; audit the IPv4 network on that interface instead.
        raise ScopeError(f'{net} is IPv6 link-local, which the audit does not scan; '
                         'audit the IPv4 network on that interface instead.', 'link-local-v6')
    kind = _range_kind(net)
    if kind is None:
        raise ScopeError(f'{net} is not a private network (RFC 1918, IPv4 link-local or '
                         'IPv6 ULA); the audit never scans public or reserved addresses.',
                         'public')
    if net.num_addresses > MAX_ADDRESSES:
        limit = '/16' if net.version == 4 else '/112'
        raise ScopeError(f'{net} has {net.num_addresses:,} addresses; the audit scans no more '
                         f'than a {limit} ({MAX_ADDRESSES:,}) at a time.', 'too-large')
    if interfaces is None:
        interfaces = _interface_addresses()
    local = [iface for _, iface in _normalise_interfaces(interfaces)
             if iface.version == net.version and not iface.ip.is_loopback
             and iface.network.overlaps(net)]
    if not local:
        raise ScopeError(f'{net} is not on any network interface of this computer that is '
                         'up; the audit only scans local networks.', 'not-local')
    return net


def validate_networks(networks, interfaces=None):
    """Validate every network, all or nothing; overlapping choices are refused so no
    host is scanned twice in one run."""
    if isinstance(networks, (str, ipaddress.IPv4Network, ipaddress.IPv6Network)):
        networks = [networks]
    networks = list(networks or [])
    if not networks:
        raise ScopeError('Choose at least one network to audit.', 'empty')
    if interfaces is None:
        interfaces = _interface_addresses()
    nets = []
    for text in networks:
        net = validate_network(text, interfaces)
        for other in nets:
            if net.version == other.version and net.overlaps(other):
                raise ScopeError(f'{net} overlaps {other}; choose one of them.', 'overlap')
        nets.append(net)
    return nets


def _targets(net, interfaces):
    """Addresses to probe: the network without its network and broadcast addresses,
    or those of any local subnet it overlaps (a /23 chosen over a /24 interface
    would otherwise include that /24's broadcast)."""
    skip = set()
    for _, iface in interfaces:
        inet = iface.network
        if inet.version == 4 and net.version == 4 and inet.overlaps(net) and inet.prefixlen < 31:
            skip.add(inet.network_address)
            skip.add(inet.broadcast_address)
    if net.version == 4:
        # /31 point-to-point links and /32 single hosts have no network or broadcast
        # address; spelled out because hosts() on these changed between versions.
        hosts = net.hosts() if net.prefixlen < 31 else iter(net)
    else:
        hosts = net.hosts() if net.prefixlen < 127 else iter(net)
    return [a for a in hosts if a not in skip]


_VIRTUAL_RE = re.compile(
    r'vethernet|wsl|hyper-v|virtualbox|vmware|vmnet|docker|^br-|^veth|virbr|tailscale|'
    r'zerotier|wireguard|openvpn|tap-|loopback', re.I)


def local_networks(interfaces=None):
    """
    The private networks of this computer's interfaces that the audit can scan: the
    choices to offer the owner. Each is a dict with network, interface, address,
    kind (rfc1918, link-local, ula), addresses (how many get probed), virtual (a
    Hyper-V, WSL, VPN or container adapter) and narrowed_from (set when the
    interface's own network is larger than a /16 and its /24 is offered instead).
    """
    if interfaces is None:
        interfaces = _interface_addresses()
    interfaces = _normalise_interfaces(interfaces)
    seen = {}
    for name, iface in interfaces:
        if iface.ip.is_loopback:
            continue
        net, narrowed = iface.network, None
        if net.num_addresses > MAX_ADDRESSES and net.version == 4:
            narrowed = str(net)
            net = ipaddress.ip_network(f'{iface.ip}/24', strict=False)
        if (net.version == 4 and net.prefixlen >= 32) or (net.version == 6 and net.prefixlen >= 128):
            continue  # a point-to-point address: nothing to audit but itself
        try:
            validate_network(net, interfaces)
        except ScopeError:
            continue
        key = str(net)
        if key in seen:
            seen[key]['interface'] += f', {name}'
            continue
        seen[key] = {
            'network': key,
            'interface': name,
            'address': str(iface.ip),
            'kind': _range_kind(net),
            'addresses': len(_targets(net, interfaces)),
            'virtual': bool(_VIRTUAL_RE.search(name)),
            'narrowed_from': narrowed,
        }
    return sorted(seen.values(), key=lambda n: (n['virtual'], ipaddress.ip_network(n['network'])))


def parse_ports(spec):
    """'22,80,8000-8010' -> sorted unique ports. Raises ScopeError for bad input."""
    if isinstance(spec, (list, tuple, set, frozenset)):
        items = [str(p) for p in spec]
    else:
        items = [p for p in re.split(r'[\s,]+', str(spec or '').strip()) if p]
    ports = set()
    for item in items:
        lo, sep, hi = item.partition('-')
        try:
            lo_n = int(lo)
            hi_n = int(hi) if sep else lo_n
        except ValueError:
            raise ScopeError(f'"{item[:20]}" is not a port or a range like 8000-8010.',
                             'ports') from None
        if not (1 <= lo_n <= 65535 and 1 <= hi_n <= 65535) or hi_n < lo_n:
            raise ScopeError(f'"{item[:20]}" is outside 1-65535.', 'ports')
        if hi_n - lo_n + 1 + len(ports) > MAX_PORTS:
            raise ScopeError(f'More than {MAX_PORTS} ports; an audit is for top ports, '
                             'not a full sweep.', 'ports')
        ports.update(range(lo_n, hi_n + 1))
    if not ports:
        raise ScopeError('No ports given.', 'ports')
    return sorted(ports)


# ─── Rate limiting ───────────────────────────────────────────────────────────
def _event_wait(seconds, cancel):
    """Sleep, waking early on cancel. True if cancelled."""
    if cancel is not None:
        return cancel.wait(seconds)
    time.sleep(seconds)
    return False


class RateLimiter:
    """
    Spaces connection attempts: at most `rate` a second across all hosts, and at
    least `host_delay` seconds between two attempts on one host. With `per_host`,
    also caps simultaneous connections to one host (gentle mode uses 1: some
    controllers handle a handful of sockets in total). Thread-safe.
    """

    def __init__(self, rate, host_delay=0.0, per_host=None, clock=time.monotonic, wait=None):
        self._interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._host_delay = max(0.0, float(host_delay or 0.0))
        self._per_host = per_host
        self._clock = clock
        self._wait = wait or _event_wait
        self._lock = threading.Lock()
        self._next_global = float('-inf')
        self._next_host = {}
        self._sems = {}

    def acquire(self, host, cancel=None):
        """Block until `host` may be probed. False if cancelled while waiting."""
        while True:
            with self._lock:
                now = self._clock()
                # With no per-host delay, tracking hosts would only make workers on
                # one host sleep a whole timer tick (15 ms on Windows) for nothing.
                ready = self._next_host.get(host, now) if self._host_delay else now
                if ready <= now:
                    # Reserve the next global slot only once this host is ready, so a
                    # slow host does not hold up every other one.
                    slot = max(now, self._next_global)
                    self._next_global = slot + self._interval
                    if self._host_delay:
                        self._next_host[host] = slot + self._host_delay
                    delay, reserved = slot - now, True
                else:
                    delay, reserved = ready - now, False
            if delay > 0 and self._wait(delay, cancel):
                return False
            if cancel is not None and cancel.is_set():
                return False
            if reserved:
                return True

    @contextlib.contextmanager
    def slot(self, host, cancel=None):
        """`with limiter.slot(ip, cancel) as ok:` holds the per-host cap for the
        length of the probe; `ok` is False if the run was cancelled."""
        sem, held = None, False
        if self._per_host:
            with self._lock:
                sem = self._sems.get(host)
                if sem is None:
                    sem = self._sems[host] = threading.BoundedSemaphore(self._per_host)
            while not held:
                held = sem.acquire(timeout=0.1)
                if not held and cancel is not None and cancel.is_set():
                    break
        try:
            if sem is not None and not held:
                yield False
            else:
                yield self.acquire(host, cancel)
        finally:
            if held:
                sem.release()


# ─── The prober: the only code here that touches the network ─────────────────
_SIO_TCP_INITIAL_RTO = 0x98000011
# TCP_INITIAL_RTO_PARAMETERS { USHORT Rtt = unspecified; UCHAR MaxSynRetransmissions
# = TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS; } padded to 4 bytes.
_RTO_PARAMS = struct.pack('<HBx', 0xFFFF, 0xFE)
_WSAIOCTL = None

# POSIX names plus their Winsock numbers (WSAENETUNREACH, WSAEHOSTDOWN, WSAEHOSTUNREACH).
_UNREACHABLE_ERRNOS = frozenset(
    e for e in (getattr(errno, n, None) for n in ('EHOSTUNREACH', 'ENETUNREACH', 'EHOSTDOWN'))
    if e) | {10051, 10064, 10065}


def _no_syn_retries(sock):
    """
    Windows answers a refused connect only after retrying the SYN twice, about two
    seconds later. With any sensible timeout every closed port would then read as
    filtered, and a host whose ping ports are all closed as down. Turning off SYN
    retransmission (SIO_TCP_INITIAL_RTO, Windows 8+) makes the RST count at once.
    Best effort; elsewhere a refusal is immediate anyway.
    """
    global _WSAIOCTL
    if os.name != 'nt' or _WSAIOCTL is False:
        return
    try:
        if _WSAIOCTL is None:
            import ctypes
            from ctypes import wintypes
            fn = ctypes.WinDLL('ws2_32').WSAIoctl
            fn.argtypes = [ctypes.c_size_t, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                           ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                           ctypes.c_void_p, ctypes.c_void_p]
            fn.restype = ctypes.c_int
            _WSAIOCTL = (ctypes, wintypes, fn)
        ctypes, wintypes, fn = _WSAIOCTL
        buf = ctypes.create_string_buffer(_RTO_PARAMS, len(_RTO_PARAMS))
        returned = wintypes.DWORD(0)
        fn(sock.fileno(), _SIO_TCP_INITIAL_RTO, buf, len(_RTO_PARAMS), None, 0,
           ctypes.byref(returned), None, None)
    except Exception:
        _WSAIOCTL = False


def _sockaddr(ip, port):
    # AI_NUMERICHOST: an address is all this ever connects to; never a name lookup.
    info = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM, 0, socket.AI_NUMERICHOST)[0]
    return info[0], info[4]


_HTTP_READ_LIMIT = 16384
_BANNER_BYTES = 256
_TEXT_JUNK_RE = re.compile('[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff\ufffd]+')


def _clean_text(value, limit=120):
    """Untrusted text from a device, made safe to show and to print: no control or
    bidi characters (a banner could otherwise drive the terminal), one line, capped."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode('utf-8', 'replace')
    text = ' '.join(_TEXT_JUNK_RE.sub(' ', str(value)).split())
    if len(text) > limit:
        text = text[:limit - 3].rstrip() + '...'
    return text or None


def _clean_banner(data):
    if not data:
        return None
    data = re.sub(rb'\xff[\xfb-\xfe][\x00-\xff]|\xff[\x00-\xff]', b' ', data)  # telnet IAC
    return _clean_text(data, 120)


def parse_http_response(raw):
    """
    Status code, Server header and <title> from the start of an HTTP response, plus
    whether it redirects to HTTPS and which auth scheme it asks for. None when
    nothing came back; {'status': None} when it was not HTTP.
    """
    if not raw:
        return None
    if not raw.startswith(b'HTTP/'):
        # 0x15/0x16: a TLS alert or handshake, i.e. a TLS port answering plain text.
        return {'status': None, 'tls_hint': raw[:1] in (b'\x15', b'\x16')}
    head, sep, body = raw.partition(b'\r\n\r\n')
    if not sep:
        head, sep, body = raw.partition(b'\n\n')
    lines = head.split(b'\n')
    m = re.match(rb'HTTP/\d(?:\.\d)?\s+(\d{3})', lines[0])
    status = int(m.group(1)) if m else None
    server = location = auth = None
    for line in lines[1:]:
        name, colon, value = line.partition(b':')
        if not colon:
            continue
        name = name.strip().lower()
        value = value.strip()
        if name == b'server' and server is None:
            server = value
        elif name == b'location' and location is None:
            location = value
        elif name == b'www-authenticate' and auth is None:
            auth = value.split(b' ', 1)[0]
    title = None
    tm = re.search(rb'<title[^>]*>(.*?)</title', body, re.I | re.S)
    if tm:
        title = html.unescape(tm.group(1).decode('utf-8', 'replace'))
    title = _clean_text(title)
    return {
        'status': status,
        'server': _clean_text(server, 80),
        'title': title,
        'redirect_https': bool(location and location.lower().startswith(b'https:')),
        'auth': (_clean_text(auth, 20) or '').lower() or None,
        # nginx answers plain HTTP on a TLS port with a 400 that says so.
        'tls_hint': bool(status == 400 and title and 'https port' in title.lower()),
    }


def _http_exchange(sock, ip, port, timeout, tls):
    host = f'[{ip}]' if ':' in ip else ip
    if port != (443 if tls else 80):
        host = f'{host}:{port}'
    # The one request this module sends: no cookies, no credentials, no path but /,
    # and Connection: close so the device can forget about us at once.
    request = ('GET / HTTP/1.1\r\n'
               f'Host: {host}\r\n'
               'User-Agent: NetSentinel-audit\r\n'
               'Accept: text/html\r\n'
               'Connection: close\r\n\r\n').encode('ascii')
    sock.sendall(request)
    buf = bytearray()
    deadline = time.monotonic() + 2 * max(timeout, 0.5)
    while len(buf) < _HTTP_READ_LIMIT and time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        buf += chunk
        if len(buf) >= 5 and not buf.startswith(b'HTTP/'):
            break
        if re.search(rb'</title', buf, re.I):
            break
    return parse_http_response(bytes(buf[:_HTTP_READ_LIMIT]))


def _insecure_context():
    # Reading a certificate, not trusting it: no verification, and old protocols
    # and ciphers allowed so a TLS 1.0-only controller still shows its certificate
    # and gets reported for the old TLS rather than silently skipped.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, AttributeError, ssl.SSLError):
            pass
    try:
        ctx.set_ciphers('ALL:@SECLEVEL=0')
    except ssl.SSLError:
        pass
    return ctx


class LiveProber:
    """Real sockets and, for ARP, scapy. Tests substitute a fake with the same methods."""

    def tcp_connect(self, ip, port, timeout, banner_wait=0.0):
        """
        One TCP connect. Returns (state, banner): state is 'open', 'closed' (refused,
        so the host is up), 'filtered' (no answer), 'unreachable' or 'error'. With
        banner_wait, reads what an open port says by itself; nothing is sent.
        """
        try:
            family, addr = _sockaddr(ip, port)
        except (OSError, UnicodeError):
            return 'error', b''
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            _no_syn_retries(sock)
            sock.settimeout(timeout)
            try:
                sock.connect(addr)
            except ConnectionRefusedError:
                return 'closed', b''
            except socket.timeout:
                return 'filtered', b''
            except OSError as exc:
                if exc.errno in _UNREACHABLE_ERRNOS or getattr(exc, 'winerror', None) in _UNREACHABLE_ERRNOS:
                    return 'unreachable', b''
                return 'error', b''
            data = b''
            if banner_wait and banner_wait > 0:
                sock.settimeout(banner_wait)
                try:
                    data = sock.recv(_BANNER_BYTES)
                except (socket.timeout, OSError):
                    data = b''
            return 'open', data
        finally:
            sock.close()

    def _connect(self, ip, port, timeout):
        family, addr = _sockaddr(ip, port)
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            _no_syn_retries(sock)
            sock.settimeout(timeout)
            sock.connect(addr)
            return sock
        except OSError:
            sock.close()
            return None

    def http_probe(self, ip, port, timeout):
        """One plain GET /: {'status', 'server', 'title', ...}, or None if the port
        would not connect or said nothing."""
        try:
            sock = self._connect(ip, port, timeout)
        except (OSError, UnicodeError):
            return None
        if sock is None:
            return None
        with sock:
            try:
                return _http_exchange(sock, ip, port, timeout, tls=False)
            except OSError:
                return None

    def tls_probe(self, ip, port, timeout, http=False):
        """TLS handshake without verification: {'cert_der', 'tls_version', 'cipher'},
        plus 'http' (one GET /) when asked, or {'error': ...}."""
        try:
            sock = self._connect(ip, port, timeout)
        except (OSError, UnicodeError):
            return {'error': 'no connection'}
        if sock is None:
            return {'error': 'no connection'}
        try:
            tls = _insecure_context().wrap_socket(sock, server_hostname=None)
        except (ssl.SSLError, OSError) as exc:
            sock.close()
            return {'error': _clean_text(f'TLS handshake failed: {exc.__class__.__name__}', 80)}
        with tls:
            cipher = tls.cipher()
            out = {
                'cert_der': tls.getpeercert(binary_form=True),
                'tls_version': tls.version(),
                'cipher': cipher[0] if cipher else None,
            }
            if http:
                try:
                    out['http'] = _http_exchange(tls, ip, port, timeout, tls=True)
                except OSError:
                    out['http'] = None
        return out

    def arp_sweep(self, ips, *, rate, cancel, tick, timeout=1.0):
        """
        Broadcast ARP who-has for each address, `rate` a second, in chunks so the run
        can report progress and stop between them. Returns {ip: {'mac', 'vendor'}}.
        Raises ArpUnavailable when scapy, Npcap or the account's rights are missing.
        """
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                from scapy.all import ARP, Ether, conf, srp
        except Exception as exc:
            raise ArpUnavailable(f'scapy could not load ({exc.__class__.__name__})',
                                 remaining=list(ips)) from None
        if _NEEDS_NPCAP and not getattr(conf, 'use_pcap', False):
            raise ArpUnavailable('Npcap is not installed', remaining=list(ips))
        try:
            iface = conf.route.route(ips[0])[0]
        except Exception:
            iface = None
        inter = 1.0 / rate if rate and rate > 0 else 0
        found = {}
        for start in range(0, len(ips), _ARP_CHUNK):
            if cancel.is_set():
                break
            chunk = ips[start:start + _ARP_CHUNK]
            wanted = set(chunk)
            try:
                answered, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=chunk), iface=iface,
                                  timeout=timeout, inter=inter, retry=0, verbose=0)
            except PermissionError:
                raise ArpUnavailable('needs administrator rights', found, ips[start:]) from None
            except Exception as exc:
                raise ArpUnavailable(f'ARP failed ({exc.__class__.__name__})', found,
                                     ips[start:]) from None
            for _, reply in answered:
                ip = getattr(reply, 'psrc', None)
                if ip in wanted:
                    found[ip] = {'mac': str(reply.hwsrc).lower(), 'vendor': None}
            tick(len(chunk))
        for info in found.values():
            info['vendor'] = _vendor(conf, info['mac'])
        return found


_ARP_CHUNK = 256
# Scapy on Windows sends layer 2 only through Npcap; without it srp fails obscurely.
_NEEDS_NPCAP = os.name == 'nt'


def _vendor(conf, mac):
    try:
        name = conf.manufdb._get_manuf(mac)
    except Exception:
        return None
    if not name or name.lower() == mac.lower():
        return None
    return _clean_text(name, 40)


class _ScopedProber:
    """Wraps any prober and refuses an address outside the validated networks: a
    second lock on the door, whatever bug might hand the prober a stray address."""

    def __init__(self, inner, networks):
        self._inner = inner
        self._nets = list(networks)

    def _check(self, ip):
        try:
            addr = ipaddress.ip_address(str(ip).split('%')[0])
        except ValueError:
            raise ScopeError(f'{ip!r} is not an address', 'out-of-scope') from None
        if not any(addr.version == n.version and addr in n for n in self._nets):
            raise ScopeError(f'{ip} is outside the audited networks', 'out-of-scope')

    def tcp_connect(self, ip, port, timeout, banner_wait=0.0):
        self._check(ip)
        return self._inner.tcp_connect(ip, port, timeout, banner_wait=banner_wait)

    def http_probe(self, ip, port, timeout):
        self._check(ip)
        return self._inner.http_probe(ip, port, timeout)

    def tls_probe(self, ip, port, timeout, http=False):
        self._check(ip)
        return self._inner.tls_probe(ip, port, timeout, http=http)

    def arp_sweep(self, ips, **kwargs):
        for ip in ips:
            self._check(ip)
        return self._inner.arp_sweep(ips, **kwargs)


# ─── Certificates ────────────────────────────────────────────────────────────
def _iso(dt):
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _now():
    return datetime.now(timezone.utc)


def _cert_time(cert, name):
    value = getattr(cert, f'{name}_utc', None)  # cryptography 42+
    if value is None:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            value = getattr(cert, name).replace(tzinfo=timezone.utc)
    return value


def _common_name(name):
    from cryptography.x509.oid import NameOID
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    except Exception:
        return None
    if attrs:
        return _clean_text(attrs[0].value, 100)
    try:
        return _clean_text(name.rfc4514_string(), 100)
    except Exception:
        return None


def parse_certificate(der, now=None, warn_days=30):
    """
    What matters about a DER certificate: subject, issuer, SANs, validity, days
    left, self-signed, key and signature strength, and the SHA-256 fingerprint the
    diff uses to notice a swapped certificate. Never raises; an unparseable
    certificate still gets its fingerprint.
    """
    fingerprint = hashlib.sha256(der or b'').hexdigest()
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return {'error': 'certificate could not be parsed', 'fingerprint_sha256': fingerprint}
    now = now or _now()
    not_before, not_after = _cert_time(cert, 'not_valid_before'), _cert_time(cert, 'not_valid_after')
    sans = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = [str(v) for v in ext.get_values_for_type(x509.DNSName)]
        sans += [str(v) for v in ext.get_values_for_type(x509.IPAddress)]
    except Exception:
        pass
    key_desc, key_bits = None, None
    try:
        key = cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            key_desc, key_bits = 'RSA', key.key_size
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key_desc, key_bits = f'EC {key.curve.name}', key.curve.key_size
        elif isinstance(key, dsa.DSAPublicKey):
            key_desc, key_bits = 'DSA', key.key_size
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key_desc, key_bits = 'Ed25519', 256
        elif isinstance(key, ed448.Ed448PublicKey):
            key_desc, key_bits = 'Ed448', 456
    except Exception:
        pass
    try:
        algo = cert.signature_hash_algorithm
        sig_hash = algo.name if algo is not None else None
    except Exception:
        sig_hash = None
    self_signed = cert.issuer == cert.subject
    if self_signed:
        try:
            cert.verify_directly_issued_by(cert)
        except AttributeError:
            pass  # cryptography < 40: matching names is the best available answer
        except Exception as exc:
            # A different key under the same name is not self-signed; an algorithm
            # this library cannot check still is, as far as we can tell.
            self_signed = exc.__class__.__name__ not in ('InvalidSignature', 'ValueError')
    # Truncated toward zero: three days and a minute ago is "expired 3 days ago".
    days_left = int((not_after - now).total_seconds() / 86400)
    expired = now > not_after
    weak = bool((key_desc in ('RSA', 'DSA') and key_bits and key_bits < 2048)
                or sig_hash in ('md5', 'sha1'))
    return {
        'subject': _common_name(cert.subject),
        'issuer': _common_name(cert.issuer),
        'sans': [_clean_text(s, 100) for s in sans[:10]],
        'not_before': _iso(not_before),
        'not_after': _iso(not_after),
        'days_left': days_left,
        'expired': expired,
        'expiring': (not expired) and days_left <= warn_days,
        'not_yet_valid': now < not_before,
        'self_signed': self_signed,
        'key': f'{key_desc} {key_bits}' if key_desc and key_bits else key_desc,
        'signature_hash': sig_hash,
        'weak': weak,
        'fingerprint_sha256': fingerprint,
    }


# ─── Findings ────────────────────────────────────────────────────────────────
def _advice(port):
    """(why, fix) for a port: forensics' text where it has one, else ours."""
    entry = _EXPLOIT.get(port)
    if entry:
        return entry['how_exploited'], entry['how_to_fix']
    if port in _OWN_ADVICE:
        return _OWN_ADVICE[port]
    desc = (_INSECURE.get(port) or {}).get('desc')
    why = (f'{desc}. ' if desc else '') + _DEFAULT_EXPLOIT['how_exploited']
    fix = _DEFAULT_EXPLOIT['how_to_fix']
    if _SECURE.get(port):
        fix = f'Use {_SECURE[port]} instead. {fix}'
    return why, fix


def _host_role(open_ports):
    """
    A guess from open ports alone (no logins, so no better source): good enough to
    tell a file server's SMB, which is its job, from a workstation's, which is a
    lateral-movement path.
    """
    ports = set(open_ports)
    if ports & _CONTROLS_PORTS:
        return 'controller'
    if ports & {88, 3268} or ({389, 445} <= ports and 53 in ports):
        return 'domain-controller'
    if ports & {9100, 515, 631} and not ports & {135, 3389}:
        return 'printer'
    if ports & {548, 2049, 111, 873, 5001}:
        return 'file-server'
    if ports & {135, 3389, 5985, 5986}:
        return 'windows'
    return 'unknown'


# Ports a role needs to do its job: flagging them on that role is noise.
_EXPECTED_BY_ROLE = {'domain-controller': frozenset({135})}


def _finding(fid, severity, host, port, title, why, fix, evidence=None):
    return {
        'id': fid, 'severity': severity, 'host': host['ip'], 'port': port,
        'service': port_name(port) if port else None,
        'title': f'{title} (this computer)' if host.get('self') else title,
        'why': why, 'fix': fix, 'evidence': evidence or {},
    }


def _host_findings(host, warn_days):
    out = []
    services = {s['port']: s for s in host['services']}
    open_ports = set(services)
    role = host['role']
    for port in sorted(open_ports):
        svc = services[port]
        rule = _PORT_RULES.get(port)
        if port in _EXPECTED_BY_ROLE.get(role, ()):
            rule = None
        if port == 5000:
            server = ((svc.get('http') or {}).get('server') or '').lower()
            if 'upnp' in server or 'miniupnpd' in server:
                rule = ('AUDIT-UPNP', 'UPnP is reachable', 'MEDIUM')
        if rule:
            fid, title, sev = rule
            why, fix = _advice(port)
            evidence = {'banner': svc['banner']} if svc.get('banner') else {}
            out.append(_finding(fid, sev, host, port, title, why, fix, evidence))
    smb_ports = sorted(open_ports & {139, 445})
    if smb_ports and role in ('windows', 'unknown'):
        why, fix = _advice(445)
        port = 445 if 445 in open_ports else 139
        if role == 'windows':
            out.append(_finding(
                'AUDIT-SMB-WORKSTATION', 'MEDIUM', host, port,
                'SMB file sharing is open on what looks like a workstation',
                why + _SMB_WORKSTATION_WHY, _SMB_WORKSTATION_FIX + fix,
                {'smb_ports': smb_ports, 'role': role}))
        else:
            out.append(_finding(
                'AUDIT-SMB', 'LOW', host, port, 'SMB file sharing is open',
                why + ' If this host is not a file server, nothing should reach it over SMB.',
                fix, {'smb_ports': smb_ports, 'role': role}))
    for port in sorted(open_ports):
        svc = services[port]
        http = svc.get('http') or {}
        tls = svc.get('tls') or {}
        if http and not tls and _looks_admin(http) and not http.get('redirect_https'):
            basic = http.get('auth') == 'basic'
            _, fix80 = _advice(80)
            out.append(_finding(
                'AUDIT-ADMIN-UI-HTTP', 'HIGH' if basic else 'MEDIUM', host, port,
                ('Admin page asks for a password over plain HTTP (Basic authentication)'
                 if basic else 'Admin page served without TLS'),
                _ADMIN_HTTP_WHY + (' Basic authentication is only base64, so the password '
                                   'is readable from a single captured request.' if basic else ''),
                fix80,
                {k: http.get(k) for k in ('status', 'server', 'title', 'auth') if http.get(k)}))
        if tls.get('version') in ('TLSv1', 'TLSv1.1'):
            out.append(_finding('AUDIT-TLS-OLD', 'MEDIUM', host, port,
                                f'Outdated {tls["version"]} is the best this service offers',
                                _TLS_OLD[0], _TLS_OLD[1], {'tls_version': tls['version']}))
        cert = tls.get('cert') or {}
        if not cert or cert.get('error'):
            continue
        ev = {k: cert.get(k) for k in ('subject', 'issuer', 'not_after', 'days_left',
                                       'fingerprint_sha256')}
        if cert.get('expired'):
            out.append(_finding('AUDIT-CERT-EXPIRED', 'MEDIUM', host, port,
                                'Certificate ' + _days_phrase(cert['days_left'], True),
                                _CERT_WHY_EXPIRED, _CERT_FIX_RENEW, ev))
        elif cert.get('not_yet_valid'):
            out.append(_finding('AUDIT-CERT-NOT-YET-VALID', 'LOW', host, port,
                                'Certificate is not valid yet (check the device clock)',
                                'A certificate dated in the future is rejected like an expired '
                                'one; it usually means the device lost its time.',
                                'Set the device\'s clock (point it at an NTP server), then '
                                'check the certificate again.', ev))
        elif cert.get('expiring'):
            out.append(_finding('AUDIT-CERT-EXPIRING', 'LOW', host, port,
                                'Certificate ' + _days_phrase(cert['days_left'], False),
                                f'When it expires on {cert["not_after"][:10]}, clients will warn '
                                'or refuse to connect. ' + _CERT_WHY_EXPIRED,
                                f'Renew it before {cert["not_after"][:10]}. ' + _CERT_FIX_RENEW, ev))
        if cert.get('self_signed'):
            out.append(_finding('AUDIT-CERT-SELF-SIGNED', 'LOW', host, port,
                                'Self-signed certificate', _CERT_WHY_SELF,
                                'Issue a certificate from an internal CA your computers trust, '
                                'or pin this fingerprint in the clients that use it: '
                                f'{cert["fingerprint_sha256"]}.', ev))
        if cert.get('weak'):
            out.append(_finding('AUDIT-CERT-WEAK', 'LOW', host, port,
                                f'Weak certificate ({cert.get("key")}, {cert.get("signature_hash")})',
                                _CERT_WHY_WEAK,
                                'Generate a new key (RSA 2048+ or ECDSA P-256) and a SHA-256 '
                                'certificate.', ev))
    return out


def _days_phrase(days, expired):
    n = abs(days)
    unit = 'day' if n == 1 else 'days'
    if expired:
        return 'expired today' if n == 0 else f'expired {n} {unit} ago'
    return 'expires today' if n == 0 else f'expires in {n} {unit}'


def _looks_admin(http):
    if http.get('status') == 401 and http.get('auth'):
        return True
    text = ' '.join(filter(None, (http.get('title'), http.get('server'))))
    return bool(text and (_ADMIN_RE.search(text) or _CONTROLS_RE.search(text)))


def _host_tags(host):
    tags = []
    if host.get('self'):
        tags.append('this-computer')
    texts = []
    for svc in host['services']:
        http = svc.get('http') or {}
        texts += [http.get('title') or '', http.get('server') or '']
        if http and _looks_admin(http):
            if 'admin-ui' not in tags:
                tags.append('admin-ui')
    if host['role'] == 'controller' or _CONTROLS_RE.search(' '.join(texts)) \
            or _CONTROLS_RE.search(host.get('vendor') or ''):
        tags.append('building-controls')
    return tags


# ─── Persistence and diff ────────────────────────────────────────────────────
def _store_dir(store_dir=None):
    # Read at call time, so the location follows src.config (and the tests' HOME).
    return store_dir or os.path.join(_config.DB_DIR, 'audit')


def _slug(net):
    return str(net).replace(':', '-').replace('/', '_')


def _record_files(network, store_dir=None):
    net = ipaddress.ip_network(str(network), strict=False)
    directory = _store_dir(store_dir)
    prefix = _slug(net) + '__'
    try:
        names = [n for n in os.listdir(directory) if n.startswith(prefix) and n.endswith('.json')]
    except OSError:
        return directory, str(net), []
    return directory, str(net), sorted(names, reverse=True)  # names sort by time


def _save_record(record, store_dir=None, keep=20):
    directory = _store_dir(store_dir)
    os.makedirs(directory, exist_ok=True)
    stamp = _now()
    while True:
        name = f'{_slug(record["network"])}__{stamp.strftime("%Y%m%dT%H%M%S%fZ")}.json'
        path = os.path.join(directory, name)
        if not os.path.exists(path):
            break
        stamp += timedelta(microseconds=1)
    _config.atomic_write_json(path, record, indent=2)
    _, _, names = _record_files(record['network'], store_dir)
    for old in names[max(1, int(keep)):]:
        try:
            os.remove(os.path.join(directory, old))
        except OSError:
            pass
    return path


def last_report(network, store_dir=None):
    """The newest saved audit of `network` (a per-network record), or None. A
    damaged file is skipped for the one before it."""
    try:
        directory, key, names = _record_files(network, store_dir)
    except ValueError:
        return None
    for name in names:
        try:
            with open(os.path.join(directory, name), encoding='utf-8') as f:
                record = json.load(f)
        except (OSError, ValueError):
            continue
        if isinstance(record, dict) and record.get('network') == key:
            return record
    return None


def _finding_key(f):
    return (f.get('id'), f.get('host'), f.get('port'))


def diff(old, new):
    """
    What changed between two audits of one network: new and gone hosts, ports
    opened and closed, certificates added, removed or replaced, and findings that
    appeared or went away. Ports count only where both audits scanned them, so a
    gentle audit after a full one does not report everything else as closed.
    Given two whole run reports, diffs each network they share.
    """
    if old is None or new is None:
        return None
    if 'networks' in old and 'networks' in new:
        olds = {n.get('network'): n for n in old['networks']}
        return {'networks': [diff(olds[n['network']], n) for n in new['networks']
                             if n.get('network') in olds]}
    old_hosts = {h['ip']: h for h in old.get('hosts', [])}
    new_hosts = {h['ip']: h for h in new.get('hosts', [])}
    both_ports = set(old.get('ports', [])) & set(new.get('ports', []))
    added = [{'ip': ip, 'mac': new_hosts[ip].get('mac'),
              'open_ports': new_hosts[ip].get('open_ports', [])}
             for ip in sorted(set(new_hosts) - set(old_hosts), key=ipaddress.ip_address)]
    gone = [{'ip': ip, 'mac': old_hosts[ip].get('mac')}
            for ip in sorted(set(old_hosts) - set(new_hosts), key=ipaddress.ip_address)]
    opened, closed, certs = [], [], []
    for ip in sorted(set(old_hosts) & set(new_hosts), key=ipaddress.ip_address):
        o, n = old_hosts[ip], new_hosts[ip]
        o_ports, n_ports = set(o.get('open_ports', [])), set(n.get('open_ports', []))
        opened += [{'host': ip, 'port': p, 'service': port_name(p)}
                   for p in sorted((n_ports - o_ports) & both_ports)]
        closed += [{'host': ip, 'port': p, 'service': port_name(p)}
                   for p in sorted((o_ports - n_ports) & both_ports)]
        o_certs = _certs_by_port(o)
        n_certs = _certs_by_port(n)
        for port in sorted(set(o_certs) | set(n_certs)):
            oc, nc = o_certs.get(port), n_certs.get(port)
            if oc and nc and oc.get('fingerprint_sha256') == nc.get('fingerprint_sha256'):
                continue
            if oc and not nc and port in n_ports:
                change = 'removed'
            elif nc and not oc and port in o_ports:
                change = 'added'
            elif oc and nc:
                change = 'replaced'
            else:
                continue  # the port itself opened or closed; that is reported above
            certs.append({
                'host': ip, 'port': port, 'change': change,
                'old_fingerprint': (oc or {}).get('fingerprint_sha256'),
                'new_fingerprint': (nc or {}).get('fingerprint_sha256'),
                'old_not_after': (oc or {}).get('not_after'),
                'new_not_after': (nc or {}).get('not_after'),
            })
    common = set(old_hosts) & set(new_hosts)
    old_keys = {_finding_key(f) for f in old.get('findings', [])}
    new_keys = {_finding_key(f) for f in new.get('findings', [])}
    new_findings = [f for f in new.get('findings', [])
                    if _finding_key(f) not in old_keys and f.get('host') in new_hosts]
    resolved = [f for f in old.get('findings', [])
                if _finding_key(f) not in new_keys and f.get('host') in common
                and (f.get('port') in both_ports or not f.get('port'))]
    old_method = (old.get('discovery') or {}).get('method')
    new_method = (new.get('discovery') or {}).get('method')
    result = {
        'network': new.get('network'),
        'previous': old.get('started'),
        'current': new.get('started'),
        'new_hosts': added,
        'gone_hosts': gone,
        'opened': opened,
        'closed': closed,
        'cert_changes': certs,
        'new_findings': new_findings,
        'resolved_findings': resolved,
        # A TCP ping misses hosts that an ARP sweep finds, so "gone" means less.
        'discovery_changed': old_method != new_method,
    }
    result['changed'] = bool(added or gone or opened or closed or certs or new_findings or resolved)
    return result


def _certs_by_port(host):
    out = {}
    for svc in host.get('services', []):
        cert = (svc.get('tls') or {}).get('cert')
        if cert and cert.get('fingerprint_sha256'):
            out[svc['port']] = cert
    return out


# ─── Running an audit ────────────────────────────────────────────────────────
class _Progress:
    """Calls the owner's callback from the thread that runs the audit and never
    concurrently, with a fraction that only goes up, at most ten times a second."""

    def __init__(self, callback):
        self._cb = callback
        self._last = 0.0
        self._last_msg = None
        self._last_time = 0.0

    def __call__(self, fraction, message, force=False):
        if self._cb is None:
            return
        fraction = min(1.0, max(self._last, float(fraction)))
        now = time.monotonic()
        if (not force and message == self._last_msg and now - self._last_time < 0.1
                and fraction < 1.0):
            return
        self._last, self._last_msg, self._last_time = fraction, message, now
        try:
            self._cb(fraction, message)
        except Exception:
            logger.debug('Audit progress callback failed', exc_info=True)


def _run_pool(tasks, fn, concurrency, cancel, on_tick, poll=0.1):
    """
    Run fn(task) on up to `concurrency` threads that pull from one list, while this
    thread reports progress. A ScopeError from a worker (the scope guard firing)
    stops everything and is raised here; other errors are logged and skipped.
    """
    total = len(tasks)
    if not total:
        return
    lock = threading.Lock()
    state = {'next': 0, 'done': 0, 'scope_error': None}

    def worker():
        while not cancel.is_set():
            with lock:
                i = state['next']
                if i >= total:
                    return
                state['next'] = i + 1
            try:
                fn(tasks[i])
            except ScopeError as exc:
                with lock:
                    state['scope_error'] = state['scope_error'] or exc
                cancel.set()
                return
            except Exception:
                logger.debug('Audit probe failed', exc_info=True)
            with lock:
                state['done'] += 1

    threads = [threading.Thread(target=worker, name=f'netsentinel-audit-{n}', daemon=True)
               for n in range(max(1, min(int(concurrency), total)))]
    for t in threads:
        t.start()
    for t in threads:
        while t.is_alive():
            t.join(poll)
            with lock:
                done = state['done']
            on_tick(done, total)
    with lock:
        done, scope_error = state['done'], state['scope_error']
    on_tick(done, total)
    if scope_error is not None:
        raise scope_error


def _bounded(value, lo, hi, default):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return default
    return min(hi, max(lo, value))


def _settings(cfg, gentle):
    """Rates for one mode, from the audit section of the config."""
    if gentle:
        concurrency = cfg.get('audit', 'gentle_concurrency', default=2)
        rate = cfg.get('audit', 'gentle_max_rate', default=5)
        delay_ms = cfg.get('audit', 'gentle_host_delay_ms', default=500)
    else:
        concurrency = cfg.get('audit', 'concurrency', default=32)
        rate = cfg.get('audit', 'max_rate', default=200)
        delay_ms = cfg.get('audit', 'host_delay_ms', default=20)
    timeout = cfg.get('audit', 'connect_timeout_sec', default=1.0)
    return {
        'concurrency': int(_bounded(concurrency, 1, 256, 2 if gentle else 32)),
        'max_rate': _bounded(rate, 0.1, 5000, 5 if gentle else 200),
        'host_delay_ms': int(_bounded(delay_ms, 0, 10000, 500 if gentle else 20)),
        'connect_timeout_sec': _bounded(timeout, 0.1, 10, 1.0),
    }


def _load_config():
    from src.config import Config
    cfg = Config()
    _ = cfg.data  # loads from disk the first time
    return cfg


_RUN_LOCK = threading.Lock()


def is_running():
    """True while an audit is running anywhere in this process."""
    return _RUN_LOCK.locked()


def _new_host(ip, found_by, mac=None, vendor=None, own=False):
    return {'ip': ip, 'mac': mac, 'vendor': vendor, 'self': own, 'found_by': found_by,
            'open_ports': [], 'services': [], 'role': 'unknown', 'tags': []}


def _audit_network(net, kind, gentle, ports, ctx):
    """Discover, scan and probe one validated network; return its record."""
    cancel, prober, progress = ctx['cancel'], ctx['prober'], ctx['progress']
    base, span = ctx['base'], ctx['span']
    s = ctx['settings_gentle'] if gentle else ctx['settings_normal']
    mode = 'gentle' if gentle else 'normal'
    timeout = s['connect_timeout_sec']
    limiter = RateLimiter(s['max_rate'], s['host_delay_ms'] / 1000.0, per_host=1 if gentle else None)
    started = _now()
    interfaces = ctx['interfaces']
    lock = threading.Lock()

    def report(phase_lo, phase_hi, done, total, message):
        frac = phase_lo + (phase_hi - phase_lo) * (done / total if total else 1.0)
        progress(base + span * frac, message)

    own = sorted({str(i.ip) for _, i in interfaces if i.version == net.version and i.ip in net},
                 key=ipaddress.ip_address)
    targets = [a for a in _targets(net, interfaces) if str(a) not in own]
    onlink = [i.network for _, i in interfaces
              if i.version == 4 and net.version == 4 and i.network.overlaps(net)
              and i.network.prefixlen < 32]
    arp_targets = [a for a in targets if a.version == 4 and any(a in n for n in onlink)]
    arp_set = set(arp_targets)
    tcp_targets = [a for a in targets if a not in arp_set]

    # ── 1. discovery ──
    alive = {ip: _new_host(ip, 'self', own=True) for ip in own}
    methods, notes = [], []
    arp_note = None
    discovered = {'n': 0}
    disc_msg = f'Finding hosts on {net}'
    progress(base, disc_msg, force=True)

    def disc_tick(n):
        discovered['n'] += n
        report(0.0, 0.35, discovered['n'], len(targets), disc_msg + ' (ARP)')

    if arp_targets and not cancel.is_set():
        try:
            found = prober.arp_sweep([str(a) for a in arp_targets], rate=s['max_rate'],
                                     cancel=cancel, tick=disc_tick)
        except ArpUnavailable as exc:
            found = exc.found
            remaining = set(exc.remaining if exc.remaining is not None else
                            [str(a) for a in arp_targets])
            tcp_targets = [a for a in targets if a not in arp_set or str(a) in remaining]
            arp_note = exc.reason
            notes.append(f'ARP sweep not available ({exc.reason}), so hosts were found with a '
                         'TCP connect ping, which misses hosts that ignore every ping port.')
        if found or arp_note is None:
            methods.append('arp')
        wanted = {str(a) for a in arp_targets}
        for ip, info in (found or {}).items():
            # Only answers for addresses we asked about: a spoofed or stray reply
            # must not add a host outside the network to the scan.
            if ip in wanted and ip not in alive:
                alive[ip] = _new_host(ip, 'arp', mac=info.get('mac'), vendor=info.get('vendor'))

    if tcp_targets and not cancel.is_set():
        methods.append('tcp-connect')
        dports = GENTLE_DISCOVERY_PORTS if gentle else DISCOVERY_PORTS
        offset = len(targets) - len(tcp_targets)

        def ping(addr):
            ip = str(addr)
            for port in dports:
                with limiter.slot(ip, cancel) as ok:
                    if not ok:
                        return
                    state, _ = prober.tcp_connect(ip, port, timeout)
                if state in ('open', 'closed'):
                    with lock:
                        alive.setdefault(ip, _new_host(ip, 'tcp-connect'))
                    return

        _run_pool(tcp_targets, ping, s['concurrency'], cancel,
                  lambda d, t: report(0.0, 0.35, offset + d, len(targets),
                                      disc_msg + ' (TCP connect ping)'))

    # ── 2. port scan ──
    hosts = sorted(alive, key=ipaddress.ip_address)
    open_map = {ip: {} for ip in hosts}
    # Port-major order spreads consecutive probes over hosts, so the per-host delay
    # costs little time while no single host takes a burst.
    tasks = [(ip, port) for port in ports for ip in hosts]
    scan_msg = f'Scanning {len(hosts)} hosts on {net}, {len(ports)} ports each'

    def scan(task):
        ip, port = task
        with limiter.slot(ip, cancel) as ok:
            if not ok:
                return
            wait = timeout if port in BANNER_PORTS else 0.0
            state, banner = prober.tcp_connect(ip, port, timeout, banner_wait=wait)
        if state == 'open':
            with lock:
                open_map[ip][port] = _clean_banner(banner)

    if not cancel.is_set():
        progress(base + span * 0.35, scan_msg, force=True)
        _run_pool(tasks, scan, s['concurrency'], cancel,
                  lambda d, t: report(0.35, 0.9, d, t, scan_msg))

    # ── 3. web pages and certificates ──
    probe_ports = HTTP_PORTS | HTTPS_PORTS | TLS_PORTS
    svc_tasks = [(ip, p) for ip in hosts for p in sorted(open_map[ip]) if p in probe_ports]
    results = {}
    svc_msg = f'Reading web pages and certificates on {net}'

    def probe(task):
        ip, port = task
        with limiter.slot(ip, cancel) as ok:
            if not ok:
                return
            if port in HTTPS_PORTS:
                res = prober.tls_probe(ip, port, timeout, http=True)
            elif port in TLS_PORTS:
                res = prober.tls_probe(ip, port, timeout, http=False)
            else:
                http = prober.http_probe(ip, port, timeout)
                res = {'http': http} if http else None
                # Some admin UIs (Cockpit, Webmin) put TLS on "HTTP" ports.
                if http and http.get('tls_hint') and limiter.acquire(ip, cancel):
                    res = prober.tls_probe(ip, port, timeout, http=True)
        with lock:
            results[(ip, port)] = res

    if svc_tasks and not cancel.is_set():
        progress(base + span * 0.9, svc_msg, force=True)
        _run_pool(svc_tasks, probe, s['concurrency'], cancel,
                  lambda d, t: report(0.9, 1.0, d, t, svc_msg))

    # ── 4. assemble ──
    warn_days = ctx['warn_days']
    now = _now()
    findings = []
    controllers = []
    for ip in hosts:
        host = alive[ip]
        services = []
        for port in sorted(open_map[ip]):
            entry = {'port': port, 'name': port_name(port)}
            if open_map[ip][port]:
                entry['banner'] = open_map[ip][port]
            res = results.get((ip, port)) or {}
            http = res.get('http')
            if http and http.get('status') is not None:
                entry['http'] = {k: v for k, v in http.items() if k != 'tls_hint'}
            if res.get('cert_der'):
                entry['tls'] = {'version': res.get('tls_version'), 'cipher': res.get('cipher'),
                                'cert': parse_certificate(res['cert_der'], now, warn_days)}
            elif res.get('error') and port in (HTTPS_PORTS | TLS_PORTS):
                entry['tls'] = {'error': res['error']}
            services.append(entry)
        host['open_ports'] = sorted(open_map[ip])
        host['services'] = services
        host['role'] = _host_role(host['open_ports'])
        host['tags'] = _host_tags(host)
        findings += _host_findings(host, warn_days)
        if 'building-controls' in host['tags']:
            controllers.append(ip)
    if controllers and not gentle:
        if len(controllers) == 1:
            what = f'{controllers[0]} looks like a building or industrial controller'
        else:
            more = f' and {len(controllers) - 5} more' if len(controllers) > 5 else ''
            what = (f'{", ".join(controllers[:5])}{more} look like building or industrial '
                    'controllers')
        notes.append(f'{what}: audit {net} in gentle mode next time, or add it to '
                     'audit.gentle_networks.')
    findings.sort(key=lambda f: (_SEV_RANK.get(f['severity'], 9),
                                 ipaddress.ip_address(f['host']), f['port'] or 0, f['id']))
    if net.version == 6:
        notes.append('IPv6 hosts were found by TCP connect ping only (no neighbour discovery).')
    notes.append('Only TCP was scanned: UDP services such as BACnet/IP (47808), SNMP (161) '
                 'and SSDP discovery are seen by the passive monitor, not by this audit.')
    return {
        'schema': SCHEMA,
        'tool': 'netsentinel-audit',
        'version': _VERSION,
        'network': str(net),
        'kind': kind,
        'mode': mode,
        'started': _iso(started),
        'finished': _iso(_now()),
        'complete': not cancel.is_set(),
        'ports': list(ports),
        'settings': s,
        'discovery': {
            'method': '+'.join(methods) or 'none',
            'arp_unavailable': arp_note,
            'addresses': len(targets) + len(own),
            'alive': len(hosts),
        },
        'hosts': [alive[ip] for ip in hosts],
        'findings': findings,
        'notes': notes,
    }


def _check_enabled(cfg):
    if not cfg.get('audit', 'enabled', default=False):
        raise AuditDisabled('The network audit is off. Turn it on in Settings (audit.enabled) '
                            'to scan your own networks.')


def run_audit(networks, *, gentle=False, ports=None, progress=None, cancel=None,
              config=None, prober=None, interfaces=None, store_dir=None, save=True,
              require_enabled=True):
    """
    Audit the given networks, one after another, and return the report.

    networks  CIDR strings the owner chose (or one string). All are validated
              before anything is sent; one refusal and nothing is scanned.
    gentle    the small port list at the gentle rates. Networks listed in
              audit.gentle_networks are always gentle.
    ports     a port list or spec ('22,80,8000-8010') instead of the default list.
    progress  progress(fraction 0..1, message), called from this thread only.
    cancel    a threading.Event; set it from any thread to stop. In-flight probes
              finish (each is bounded by the connect timeout) and the partial
              report comes back with cancelled=True. Partial audits are not saved,
              so the next diff compares against the last complete one.

    The rest are for the CLI and tests: config (anything with .get like Config),
    prober (fake network), interfaces (fake psutil), store_dir, save, and
    require_enabled (the CLI passes False: typing the command is the opt-in).

    Raises ScopeError, AuditDisabled or AuditBusy before sending anything.
    """
    cfg = config if config is not None else _load_config()
    if require_enabled:
        _check_enabled(cfg)
    ifaces = _normalise_interfaces(interfaces if interfaces is not None else _interface_addresses())
    nets = validate_networks(networks, ifaces)
    port_list = parse_ports(ports) if ports is not None else None
    gentle_nets = []
    for text in cfg.get('audit', 'gentle_networks', default=[]) or []:
        try:
            gentle_nets.append(ipaddress.ip_network(str(text), strict=False))
        except ValueError:
            logger.warning('Ignoring audit.gentle_networks entry %r', text)
    cancel = cancel if cancel is not None else threading.Event()
    keep = int(_bounded(cfg.get('audit', 'keep_reports', default=20), 1, 1000, 20))
    warn_days = int(_bounded(cfg.get('audit', 'cert_warn_days', default=30), 0, 3650, 30))

    if not _RUN_LOCK.acquire(blocking=False):
        raise AuditBusy('An audit is already running; wait for it or cancel it.')
    try:
        report_progress = _Progress(progress)
        started = _now()
        ctx = {
            'cancel': cancel,
            'prober': _ScopedProber(prober if prober is not None else LiveProber(), nets),
            'progress': report_progress,
            'interfaces': ifaces,
            'settings_normal': _settings(cfg, False),
            'settings_gentle': _settings(cfg, True),
            'warn_days': warn_days,
        }
        logger.info('Network audit started: %s%s', ', '.join(map(str, nets)),
                    ' (gentle)' if gentle else '')
        records = []
        for i, net in enumerate(nets):
            if cancel.is_set():
                break
            net_gentle = bool(gentle) or any(net.version == g.version and net.overlaps(g)
                                             for g in gentle_nets)
            net_ports = port_list or list(GENTLE_PORTS if net_gentle else TOP_PORTS)
            ctx['base'], ctx['span'] = i / len(nets), 1 / len(nets)
            record = _audit_network(net, _range_kind(net), net_gentle, net_ports, ctx)
            previous = last_report(net, store_dir)
            record_diff = diff(previous, record) if previous and record['complete'] else None
            path = None
            if save and record['complete']:
                try:
                    path = _save_record(record, store_dir, keep)
                except OSError as exc:
                    logger.error('Could not save the audit of %s: %s', net, exc)
            records.append(dict(record, diff=record_diff, saved=path,
                                first_audit=previous is None))
        cancelled = cancel.is_set()
        findings = [dict(f, network=r['network']) for r in records for f in r['findings']]
        findings.sort(key=lambda f: _SEV_RANK.get(f['severity'], 9))
        counts = {s: 0 for s in SEVERITIES}
        for f in findings:
            counts[f['severity']] = counts.get(f['severity'], 0) + 1
        diffs = [r['diff'] for r in records if r['diff']]
        report = {
            'schema': SCHEMA,
            'tool': 'netsentinel-audit',
            'version': _VERSION,
            'started': _iso(started),
            'finished': _iso(_now()),
            'mode': 'gentle' if gentle else 'normal',
            'cancelled': cancelled,
            'complete': not cancelled and len(records) == len(nets),
            'networks': records,
            'findings': findings,
            'summary': {
                'networks': len(records),
                'hosts': sum(len(r['hosts']) for r in records),
                'open_ports': sum(len(h['open_ports']) for r in records for h in r['hosts']),
                'findings': counts,
                'new_hosts': sum(len(d['new_hosts']) for d in diffs),
                'opened_ports': sum(len(d['opened']) for d in diffs),
                'closed_ports': sum(len(d['closed']) for d in diffs),
            },
        }
        report_progress(1.0 if not cancelled else 0.0, 'Cancelled' if cancelled else 'Done',
                        force=True)
        logger.info('Network audit %s: %d hosts, %d findings',
                    'cancelled' if cancelled else 'finished',
                    report['summary']['hosts'], len(findings))
        return report
    finally:
        _RUN_LOCK.release()


class AuditJob:
    """
    An audit on a background thread, for UIs. status() is safe to call from any
    thread (a Tk after() loop, the dashboard's HTTP handler) and returns
    {'state': 'running'|'done'|'cancelled'|'error', 'fraction', 'message',
     'error', 'networks', 'gentle'}. cancel() works from any thread too.
    """

    def __init__(self, networks, **kwargs):
        if isinstance(networks, (str, ipaddress.IPv4Network, ipaddress.IPv6Network)):
            networks = [networks]
        self.networks = [str(n) for n in networks]
        self.gentle = bool(kwargs.get('gentle'))
        self._kwargs = kwargs
        self._cancel = threading.Event()
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._state, self._fraction, self._message = 'running', 0.0, 'Starting'
        self._report, self._error = None, None
        self._thread = threading.Thread(target=self._run, name='netsentinel-audit', daemon=True)

    def start(self):
        self._thread.start()
        return self

    def _progress(self, fraction, message):
        with self._lock:
            self._fraction, self._message = fraction, message

    def _run(self):
        try:
            report = run_audit(self.networks, progress=self._progress, cancel=self._cancel,
                               **self._kwargs)
        except Exception as exc:
            with self._lock:
                self._state, self._error = 'error', str(exc)
        else:
            with self._lock:
                self._report = report
                self._state = 'cancelled' if report['cancelled'] else 'done'
                if not report['cancelled']:
                    self._fraction = 1.0
        finally:
            self._done.set()

    def cancel(self):
        self._cancel.set()

    def wait(self, timeout=None):
        return self._done.wait(timeout)

    @property
    def report(self):
        with self._lock:
            return self._report

    def status(self):
        with self._lock:
            return {'state': self._state, 'fraction': self._fraction, 'message': self._message,
                    'error': self._error, 'networks': list(self.networks), 'gentle': self.gentle}


_JOB_LOCK = threading.Lock()
_CURRENT_JOB = None


def start_audit(networks, **kwargs):
    """
    Check the request now, so the UI can show a refusal straight away, then run
    the audit on a background thread. Takes run_audit's keyword arguments except
    progress and cancel (the job provides them). Raises ScopeError, AuditDisabled
    or AuditBusy.
    """
    global _CURRENT_JOB
    cfg = kwargs.get('config')
    if cfg is None:
        cfg = kwargs['config'] = _load_config()
    if kwargs.get('require_enabled', True):
        _check_enabled(cfg)
    interfaces = kwargs.get('interfaces')
    validate_networks(networks, _normalise_interfaces(interfaces) if interfaces is not None else None)
    if kwargs.get('ports') is not None:
        parse_ports(kwargs['ports'])
    with _JOB_LOCK:
        if is_running() or (_CURRENT_JOB is not None and _CURRENT_JOB.status()['state'] == 'running'):
            raise AuditBusy('An audit is already running; wait for it or cancel it.')
        _CURRENT_JOB = AuditJob(networks, **kwargs).start()
        return _CURRENT_JOB


def current_job():
    """The running or most recent AuditJob started in this process, or None, so the
    desktop and the dashboard can show the same audit."""
    with _JOB_LOCK:
        return _CURRENT_JOB


def saved_networks(config=None):
    """The networks the owner chose last time (audit.networks), dropping any that
    no longer validate. Never scanned unless passed to run_audit."""
    cfg = config if config is not None else _load_config()
    out = []
    for text in cfg.get('audit', 'networks', default=[]) or []:
        try:
            out.append(str(validate_network(text)))
        except ScopeError:
            continue
    return out


# ─── CLI ─────────────────────────────────────────────────────────────────────
def _count(items, noun):
    n = len(items)
    return f'{n} {noun}' + ('' if n == 1 else 's')


def format_report(report, verbose=False):
    """The report as plain ASCII text for a terminal."""
    lines = []
    for rec in report['networks']:
        disc = rec['discovery']
        state = '' if rec['complete'] else ' (incomplete)'
        lines.append(f"Audit of {rec['network']}{state}: {rec['mode']} mode, discovery by "
                     f"{disc['method']}, {len(rec['hosts'])} hosts, "
                     f"{sum(len(h['open_ports']) for h in rec['hosts'])} open ports, "
                     f"{len(rec['findings'])} findings")
        for host in rec['hosts']:
            extra = ', '.join(filter(None, [host.get('mac'), host.get('vendor'),
                                            host['role'] if host['role'] != 'unknown' else None,
                                            'this computer' if host.get('self') else None]))
            ports = ' '.join(str(p) for p in host['open_ports']) or '-'
            lines.append(f"  {host['ip']:<16} {ports}" + (f'   ({extra})' if extra else ''))
        for f in rec['findings']:
            where = f"{f['host']}:{f['port']}" if f.get('port') else f['host']
            lines.append(f"  {f['severity']:<8} {where:<22} {f['title']}")
            if verbose:
                lines.append(f"           why: {' '.join(f['why'].split())}")
                for fix in f['fix'].splitlines():
                    lines.append(f'           {fix}')
        d = rec.get('diff')
        if d:
            if d['changed']:
                lines.append(f"  Since {d['previous']}: {_count(d['new_hosts'], 'new host')}, "
                             f"{_count(d['opened'], 'port')} opened, {len(d['closed'])} closed, "
                             f"{_count(d['cert_changes'], 'certificate change')}")
                for h in d['new_hosts']:
                    lines.append(f"    + {h['ip']} (new host)")
                for h in d['gone_hosts']:
                    lines.append(f"    - {h['ip']} (not found this time)")
                for p in d['opened']:
                    lines.append(f"    + {p['host']}:{p['port']} {p['service']}")
                for p in d['closed']:
                    lines.append(f"    - {p['host']}:{p['port']} {p['service']}")
                for c in d['cert_changes']:
                    lines.append(f"    * {c['host']}:{c['port']} certificate {c['change']}")
            else:
                lines.append(f"  No changes since {d['previous']}.")
        elif rec.get('first_audit'):
            lines.append('  First audit of this network: nothing to compare with yet.')
        for note in rec['notes']:
            lines.append(f'  note: {note}')
    if report['cancelled']:
        lines.append('Cancelled: the partial result above was not saved.')
    text = '\n'.join(lines)
    return text.encode('ascii', 'replace').decode('ascii')


def main(argv=None, *, prober=None, interfaces=None, config=None, store_dir=None):
    import argparse

    parser = argparse.ArgumentParser(
        prog='python -m src.audit',
        description='Audit your own local networks: find hosts, scan the top ports at a '
                    'limited rate, flag risky services and certificates, and compare with '
                    'the last audit. Never tries passwords; only scans networks you name.')
    parser.add_argument('--network', '-n', action='append', default=[], metavar='CIDR',
                        help='a local private network, e.g. 192.168.1.0/24 (repeatable)')
    parser.add_argument('--gentle', action='store_true',
                        help='small port list at a low rate, for building/OT controllers')
    parser.add_argument('--ports', metavar='LIST', help="ports to scan, e.g. '22,80,8000-8010'")
    parser.add_argument('--json', action='store_true', help='print the report as JSON')
    parser.add_argument('--list', action='store_true',
                        help='list the local networks that can be audited, and exit')
    parser.add_argument('--no-save', action='store_true',
                        help='do not save this audit for the next comparison')
    parser.add_argument('--verbose', '-v', action='store_true', help='include why and how to fix')
    args = parser.parse_args(argv)

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors='replace')
        except (AttributeError, ValueError):
            pass

    if args.list:
        nets = local_networks(interfaces)
        if args.json:
            print(json.dumps(nets, indent=2))
        elif not nets:
            print('No private network on an interface that is up.')
        for n in nets if not args.json else []:
            extra = ' (virtual adapter)' if n['virtual'] else ''
            if n['narrowed_from']:
                extra += f" (part of {n['narrowed_from']})"
            print(f"{n['network']:<20} {n['interface']}, this computer is {n['address']}, "
                  f"{n['addresses']} addresses{extra}")
        return 0
    if not args.network:
        parser.error('give at least one --network (see --list for the choices)')

    cancel = threading.Event()
    result = {}
    last_msg = {'m': None}

    def progress(fraction, message):
        if message != last_msg['m']:
            last_msg['m'] = message
            print(f'[{fraction * 100:3.0f}%] {message}', file=sys.stderr)

    def work():
        try:
            result['report'] = run_audit(
                args.network, gentle=args.gentle, ports=args.ports, progress=progress,
                cancel=cancel, config=config, prober=prober, interfaces=interfaces,
                store_dir=store_dir, save=not args.no_save, require_enabled=False)
        except Exception as exc:
            result['error'] = exc

    worker = threading.Thread(target=work, name='netsentinel-audit-cli', daemon=True)
    worker.start()
    try:
        while worker.is_alive():
            worker.join(0.2)
    except KeyboardInterrupt:
        print('Cancelling...', file=sys.stderr)
        cancel.set()
        worker.join()
    if 'error' in result:
        exc = result['error']
        print(f'audit: {exc}', file=sys.stderr)
        return 2 if isinstance(exc, ScopeError) else 1
    report = result['report']
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(format_report(report, verbose=args.verbose))
    return 130 if report['cancelled'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
