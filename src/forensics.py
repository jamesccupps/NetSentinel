"""
Network Forensics & Security Audit Engine
===========================================
Analyzes packet captures for:

1. CREDENTIAL EXPOSURE - Finds plaintext passwords, auth tokens, API keys
   in unencrypted protocols (FTP, HTTP, Telnet, SMTP, POP3, SNMP, etc.)

2. FLOW CLASSIFICATION - ML-based behavioral classification of network flows
   (streaming, browsing, file transfer, VoIP, etc.) using packet patterns

3. SECURITY AUDIT - Identifies insecure protocols, misconfigurations, and
   policy violations on the network

4. NARRATIVE TIMELINE - Plain-English summary of what happened in a capture

Designed for PCAP analysis but can also run on live traffic.
"""

import re
import time
import math
import logging
import base64
from collections import defaultdict, Counter, OrderedDict
from datetime import datetime

logger = logging.getLogger("NetSentinel.Forensics")


# ═══════════════════════════════════════════════════════════════════════════════
#  CREDENTIAL & SENSITIVE DATA PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════

# FTP commands that carry credentials
FTP_USER_RE = re.compile(rb'USER\s+(\S+)', re.IGNORECASE)
FTP_PASS_RE = re.compile(rb'PASS\s+(\S+)', re.IGNORECASE)

# HTTP Basic Auth (Authorization: Basic base64encoded)
HTTP_BASIC_AUTH_RE = re.compile(rb'Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)', re.IGNORECASE)

# HTTP form POST data with password-like fields
HTTP_POST_CRED_RE = re.compile(
    rb'(?:password|passwd|pass|pwd|secret|token|api_key|apikey|auth)'
    rb'\s*[=:]\s*([^\s&\r\n]{1,200})', re.IGNORECASE
)

# HTTP Cookie headers (may contain session tokens)
HTTP_COOKIE_RE = re.compile(rb'Cookie:\s*(.+?)(?:\r?\n)', re.IGNORECASE)
HTTP_SET_COOKIE_RE = re.compile(rb'Set-Cookie:\s*(.+?)(?:\r?\n)', re.IGNORECASE)

# HTTP Authorization headers (Bearer tokens, API keys)
HTTP_AUTH_RE = re.compile(rb'Authorization:\s*(\S+\s+\S+)', re.IGNORECASE)
HTTP_API_KEY_RE = re.compile(
    rb'(?:x-api-key|api-key|apikey|x-auth-token|x-access-token):\s*(\S+)',
    re.IGNORECASE
)

# HTTP Digest Auth (used by many routers, cameras, HVAC controllers)
HTTP_DIGEST_RE = re.compile(
    rb'Authorization:\s*Digest\s+(.+?)(?:\r?\n)', re.IGNORECASE
)
HTTP_DIGEST_USER_RE = re.compile(rb'username="([^"]+)"', re.IGNORECASE)
HTTP_DIGEST_REALM_RE = re.compile(rb'realm="([^"]+)"', re.IGNORECASE)
HTTP_DIGEST_URI_RE = re.compile(rb'uri="([^"]+)"', re.IGNORECASE)
HTTP_DIGEST_NONCE_RE = re.compile(rb'nonce="([^"]+)"', re.IGNORECASE)
HTTP_DIGEST_RESPONSE_RE = re.compile(rb'response="([^"]+)"', re.IGNORECASE)

# HTTP Host and URL (for context)
HTTP_HOST_RE = re.compile(rb'Host:\s*(\S+)', re.IGNORECASE)
HTTP_REQUEST_RE = re.compile(rb'^(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+HTTP', re.IGNORECASE)

# SMTP AUTH
SMTP_AUTH_RE = re.compile(rb'AUTH\s+(LOGIN|PLAIN)\s*(.*)', re.IGNORECASE)
SMTP_USER_RE = re.compile(rb'^[A-Za-z0-9+/=]{4,}$')  # base64 encoded username

# POP3/IMAP credentials
POP3_USER_RE = re.compile(rb'USER\s+(\S+)', re.IGNORECASE)
POP3_PASS_RE = re.compile(rb'PASS\s+(\S+)', re.IGNORECASE)
IMAP_LOGIN_RE = re.compile(rb'LOGIN\s+"?(\S+?)"?\s+"?(\S+?)"?', re.IGNORECASE)

# Telnet (look for login prompts followed by data)
TELNET_LOGIN_RE = re.compile(rb'(?:login|username)[\s:]+(\S+)', re.IGNORECASE)
TELNET_PASS_RE = re.compile(rb'(?:password|passwd)[\s:]+(\S+)', re.IGNORECASE)

# SNMP community strings
SNMP_COMMUNITY_RE = re.compile(rb'(public|private|community)', re.IGNORECASE)

# SQL connection strings in plaintext
SQL_CONN_RE = re.compile(
    rb'(?:password|pwd)\s*=\s*([^;\\s]{1,100})', re.IGNORECASE
)

# Redis AUTH command
REDIS_AUTH_RE = re.compile(rb'AUTH\s+(\S+)', re.IGNORECASE)

# MongoDB authentication
MONGO_AUTH_RE = re.compile(rb'(?:authenticate|createUser|pwd)\s*[=:]\s*["\']?(\S+)', re.IGNORECASE)

# VNC authentication (RFB protocol challenge-response, flag the attempt)
VNC_AUTH_RE = re.compile(rb'RFB\s+\d+\.\d+')

# MQTT CONNECT packet (username/password fields)
MQTT_USER_RE = re.compile(rb'[\x00-\x01][\x00-\xff]{0,4}([\x20-\x7e]{3,50})', re.DOTALL)

# SIP Authorization
SIP_AUTH_RE = re.compile(rb'(?:Authorization|Proxy-Authorization):\s*Digest\s+(.+?)(?:\r?\n)',
                         re.IGNORECASE)

# rsync module listing (indicates open access)
RSYNC_MODULE_RE = re.compile(rb'@RSYNCD:', re.IGNORECASE)

# IRC credentials
IRC_PASS_RE = re.compile(rb'PASS\s+(\S+)', re.IGNORECASE)
IRC_NICK_RE = re.compile(rb'NICK\s+(\S+)', re.IGNORECASE)

# Modbus/SCADA (any traffic on these ports is concerning)
# No specific credential pattern — the protocol itself has no auth

# Private keys or certificates in transit
PRIVATE_KEY_RE = re.compile(rb'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----')
CERTIFICATE_RE = re.compile(rb'-----BEGIN\s+CERTIFICATE-----')

# Credit card patterns (basic)
CC_PATTERN_RE = re.compile(rb'(?:4\d{15}|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})')

# SSN pattern
SSN_RE = re.compile(rb'\b\d{3}-\d{2}-\d{4}\b')

# Email addresses in plaintext
EMAIL_RE = re.compile(rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# ═══════════════════════════════════════════════════════════════════════════════
#  PARKING SYSTEM PROTOCOL PATTERNS
#  Cleartext XML over UDP 31769 on parking controller overlay networks
# ═══════════════════════════════════════════════════════════════════════════════

# Skidata XML command types
SKIDATA_COMMAND_RE = re.compile(
    rb'<(?:Command|CommandType)>\s*(Update(?:CreditCard|Ticket|Rfid)|'
    rb'Reset(?:Ticket|Rfid)|Remove(?:Rfid|Ticket)|'
    rb'GETEIP|GetTicket|OpenGate|CloseGate)\s*</(?:Command|CommandType)>',
    re.IGNORECASE
)
# Credit card last-four in XML
SKIDATA_LASTFOUR_RE = re.compile(rb'<LastFour>\s*(\d{4})\s*</LastFour>', re.IGNORECASE)
SKIDATA_CARDTYPE_RE = re.compile(rb'<CardType>\s*(\w+)\s*</CardType>', re.IGNORECASE)
# Ticket numbers
SKIDATA_TICKET_RE = re.compile(rb'<TicketNumber>\s*(\d+)\s*</TicketNumber>', re.IGNORECASE)
# Entry credentials (EZPass RFID, NFC, credit-card-as-ticket)
SKIDATA_ENTRY_CRED_RE = re.compile(
    rb'<EntryCredential>\s*:?(\d{1,3}:\d+)\s*</EntryCredential>', re.IGNORECASE
)
# Account IDs and pricing UUIDs
SKIDATA_ACCOUNT_RE = re.compile(rb'<AccountId>\s*([^<]+)\s*</AccountId>', re.IGNORECASE)
SKIDATA_PRICING_RE = re.compile(
    rb'<(?:PricingId|PricingUuid)>\s*([0-9a-f-]{36})\s*</(?:PricingId|PricingUuid)>',
    re.IGNORECASE
)
# Sender/Gate PC identification
SKIDATA_SENDER_RE = re.compile(rb'<SenderId>\s*([^<]+)\s*</SenderId>', re.IGNORECASE)
# GETEIP heartbeat: MAC + device ID + command + WAN IP + token
GETEIP_RE = re.compile(
    rb'([0-9a-f]{12})\s+(K\d+)\s+GETEIP\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{40})',
    re.IGNORECASE
)
# Skidata UDP command port
SKIDATA_PORT = 31769

# E-ZPass IAG Agency Codes → Issuing Authority
# Source: NIOP ICD Appendix C (National Interoperability)
EZPASS_AGENCY_CODES = {
    1:  ('NJ', 'New Jersey Highway Authority (Garden State Parkway)'),
    2:  ('NJ', 'New Jersey Highway Authority'),
    3:  ('NJ', 'New Jersey Turnpike Authority'),
    4:  ('NY', 'New York State Thruway Authority'),
    5:  ('NY', 'Port Authority of NY & NJ'),
    6:  ('PA', 'Pennsylvania Turnpike Commission'),
    7:  ('NJ', 'South Jersey Transportation Authority'),
    8:  ('NY', 'MTA Bridges & Tunnels'),
    9:  ('NJ', 'Delaware River Port Authority'),
    10: ('VA', 'Virginia DOT'),
    11: ('ON', 'Highway 407 (Ontario, Canada)'),
    12: ('DE', 'Delaware DOT'),
    13: ('NY', 'Peace Bridge Authority'),
    14: ('WV', 'West Virginia Parkways Authority'),
    15: ('IL', 'Illinois Tollway (I-PASS)'),
    16: ('MD', 'Maryland Transportation Authority'),
    17: ('NC', 'North Carolina Turnpike Authority'),
    18: ('NY', 'New York State Bridge Authority'),
    19: ('MA', 'Massachusetts DOT (MassDOT)'),
    20: ('IN', 'Indiana Finance Authority'),
    21: ('KY', 'Kentucky Public Transportation (RiverLink)'),
    22: ('VA', 'Elizabeth River Crossings'),
    23: ('VA', 'Chesapeake Bay Bridge-Tunnel'),
    24: ('MN', 'Minnesota DOT (MnPASS)'),
    25: ('FL', 'Central Florida Expressway Authority'),
    26: ('NH', 'New Hampshire DOT'),
    27: ('NJ', 'Burlington County Bridge Commission'),
    28: ('ME', 'Maine Turnpike Authority'),
    29: ('NJ', 'Delaware River Joint Toll Bridge Commission'),
    30: ('IN', 'Indiana Toll Road (ITR Concession)'),
    31: ('OH', 'Ohio Turnpike & Infrastructure Commission'),
    32: ('RI', 'Rhode Island Turnpike & Bridge Authority'),
    33: ('VA', 'Transurban (Express Lanes VA)'),
    34: ('PA', 'Delaware River Bridge (Burlington-Bristol)'),
    35: ('NC', 'Triangle Expressway (NCDOT)'),
    36: ('KY', 'RiverLink (Louisville-Southern IN Bridge)'),
    37: ('NY', 'Central NY Regional Transportation Authority'),
    38: ('VA', 'Dulles Greenway'),
    39: ('PA', 'Turnpike Commission (PA E-ZPass Flex)'),
    40: ('MI', 'Michigan DOT (Ambassador Bridge)'),
    50: ('FL', 'SunPass (Florida)'),
    64: ('--', 'Parking System / Private Facility'),
    65: ('--', 'Parking System / Private Facility'),
    66: ('--', 'Parking System / Private Facility'),
    67: ('--', 'Parking System / Private Facility'),
    # 68+ are typically NFC/contactless or parking-specific
    68: ('--', 'NFC/Contactless Credential'),
    69: ('--', 'NFC/Contactless Credential'),
}

def lookup_ezpass_agency(agency_code):
    """Look up E-ZPass agency by numeric code. Returns (state, agency_name) or None."""
    try:
        code = int(agency_code)
        return EZPASS_AGENCY_CODES.get(code)
    except (ValueError, TypeError):
        return None

# ─── Detailed exploitation/fix info per insecure protocol ─────────────────

PROTOCOL_EXPLOITATION = {
    21: {
        'how_exploited': 'An attacker on the same network runs a packet sniffer (like Wireshark or tcpdump) '
            'and sees FTP USER and PASS commands in plaintext. They now have full credentials to '
            'the FTP server. They can also see every file being uploaded or downloaded.',
        'how_to_fix': '1. Replace FTP with SFTP (SSH File Transfer, port 22) — most FTP clients support this.\n'
            '2. If SFTP is not possible, use FTPS (FTP over TLS, port 990).\n'
            '3. Never reuse FTP passwords for other services.\n'
            '4. Restrict FTP access to specific IP ranges via firewall rules.',
        'currently_malicious': 'If you did not initiate this FTP connection, it could indicate malware '
            'exfiltrating data or an unauthorized user accessing files. Check which process initiated it.',
    },
    23: {
        'how_exploited': 'The entire Telnet session (including typed commands and their output) is visible '
            'in plaintext. An attacker sees every password typed, every command run, and every response. '
            'They can also inject commands mid-session (session hijacking).',
        'how_to_fix': '1. Replace Telnet with SSH (port 22) immediately.\n'
            '2. Disable the Telnet service/daemon on the server.\n'
            '3. Block port 23 at the firewall.\n'
            '4. Change all credentials that have ever been used over Telnet.',
        'currently_malicious': 'Telnet should not exist on modern networks. If this is an IoT device '
            'or legacy equipment, it is a critical vulnerability. If unexpected, it may indicate '
            'a backdoor or reverse shell.',
    },
    80: {
        'how_exploited': 'HTTP traffic is unencrypted. Login forms, cookies, session tokens, and page '
            'content are visible to anyone on the network. Most HTTP on modern sites is just a redirect '
            'to HTTPS, but if a site serves actual content or login pages over HTTP, credentials are exposed.',
        'how_to_fix': '1. Enable HTTPS on the web server with a valid TLS certificate (free via Let\'s Encrypt).\n'
            '2. Add HSTS headers to force HTTPS.\n'
            '3. Redirect all HTTP to HTTPS.\n'
            '4. If this is a local admin panel, access it via https:// instead of http://.',
        'currently_malicious': 'Most HTTP is benign (browser redirects to HTTPS). Only concerning if '
            'you see login forms, API calls, or large data transfers over HTTP.',
    },
    445: {
        'how_exploited': 'SMB file sharing can expose NTLM hashes which can be cracked offline or '
            'relayed (NTLM relay attack) to access other systems. SMBv1 specifically is vulnerable to '
            'EternalBlue (CVE-2017-0144) which gives remote code execution without authentication.',
        'how_to_fix': '1. Disable SMBv1: PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol\n'
            '2. Require SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature $true\n'
            '3. Enable SMB encryption: Set-SmbServerConfiguration -EncryptData $true\n'
            '4. Block port 445 from the internet at your firewall.',
        'currently_malicious': 'If SMBv1 is in use, the system is vulnerable to worm-class attacks. '
            'SMBv2/3 with signing enabled is generally safe for internal use.',
    },
    5900: {
        'how_exploited': 'VNC transmits screen contents and keyboard/mouse input with weak or no encryption. '
            'An attacker can see everything on screen and capture password hashes. Many VNC servers use '
            'a single shared password with no username requirement.',
        'how_to_fix': '1. Tunnel VNC through SSH: ssh -L 5900:localhost:5900 user@server\n'
            '2. Switch to RDP with Network Level Authentication (NLA).\n'
            '3. If VNC must be used, set a strong password and restrict access by IP.\n'
            '4. Never expose VNC to the internet.',
        'currently_malicious': 'VNC from an unexpected source could indicate unauthorized remote access. '
            'Check which machine is being controlled and who initiated the session.',
    },
    6379: {
        'how_exploited': 'Redis often runs with NO authentication. Anyone who can reach port 6379 can read '
            'all data, write arbitrary data, and in many configurations execute system commands via '
            'EVAL or module loading. This is a common entry point for crypto-mining malware.',
        'how_to_fix': '1. Set a strong password: requirepass in redis.conf\n'
            '2. Enable TLS: tls-port 6380, tls-cert-file, tls-key-file\n'
            '3. Bind to localhost only: bind 127.0.0.1\n'
            '4. Use ACLs (Redis 6+) to restrict commands per user.',
        'currently_malicious': 'An exposed Redis without auth is almost certainly being scanned and '
            'potentially exploited. Check for unauthorized keys, especially SSH keys written to disk.',
    },
    27017: {
        'how_exploited': 'MongoDB with default settings has NO authentication. Anyone can connect and '
            'dump the entire database. This has caused thousands of real-world data breaches. '
            'Attackers often ransom the data after deleting it.',
        'how_to_fix': '1. Enable authentication: security.authorization: enabled in mongod.conf\n'
            '2. Create admin user: use admin; db.createUser({...})\n'
            '3. Bind to localhost: bindIp: 127.0.0.1\n'
            '4. Enable TLS: net.tls.mode: requireTLS',
        'currently_malicious': 'If this MongoDB is reachable from outside your network, assume it has '
            'already been accessed. Check for ransom notes in collections.',
    },
    9200: {
        'how_exploited': 'Elasticsearch with default settings has no authentication and exposes a REST API '
            'on port 9200. Anyone can read all indices, delete data, or use it for data exfiltration. '
            'The /_cat/indices endpoint lists all available data.',
        'how_to_fix': '1. Enable Elasticsearch security features (X-Pack).\n'
            '2. Set xpack.security.enabled: true in elasticsearch.yml\n'
            '3. Enable TLS for HTTP and transport layers.\n'
            '4. Put Elasticsearch behind a reverse proxy with authentication.',
        'currently_malicious': 'Any external access to Elasticsearch is a data breach. Check access logs '
            'for unfamiliar IPs.',
    },
    502: {
        'how_exploited': 'Modbus has ZERO authentication. Any device that can send TCP to port 502 can '
            'read sensor values, write to registers, and control physical equipment. A write command '
            'could open a valve, change a temperature setpoint, or disable safety systems.',
        'how_to_fix': '1. Segment SCADA networks from IT networks with firewalls.\n'
            '2. Use a Modbus-aware firewall/gateway that filters by function code.\n'
            '3. Implement Modbus/TCP security extensions if equipment supports it.\n'
            '4. Monitor all Modbus write commands with NetSentinel.',
        'currently_malicious': 'Any Modbus traffic from an IT network to SCADA equipment is suspicious. '
            'Write commands from unauthorized sources are critical incidents.',
    },
    47808: {
        'how_exploited': 'BACnet has no authentication or encryption. Anyone on the network can discover '
            'all building automation devices, read their properties (temperature, occupancy, schedules), '
            'and write new values (change HVAC setpoints, unlock doors, disable fire systems).',
        'how_to_fix': '1. Segment BACnet traffic to its own VLAN.\n'
            '2. Use BACnet Secure Connect (BACnet/SC) if devices support it.\n'
            '3. Deploy a BACnet firewall/gateway.\n'
            '4. Monitor all WriteProperty commands.',
        'currently_malicious': 'Unexpected BACnet discovery (Who-Is) from IT devices is suspicious. '
            'WriteProperty commands from unauthorized sources are critical.',
    },
    554: {
        'how_exploited': 'RTSP camera feeds and credentials are unencrypted. An attacker can view live '
            'camera feeds, capture login credentials, and in some cases control PTZ (pan-tilt-zoom). '
            'Many cameras use default credentials (admin/admin, admin/12345).',
        'how_to_fix': '1. Enable HTTPS/RTSPS on cameras that support it.\n'
            '2. Change default credentials on ALL cameras.\n'
            '3. Put cameras on a separate VLAN from the main network.\n'
            '4. Use a VPN for remote camera access instead of port forwarding.',
        'currently_malicious': 'If someone is accessing cameras from outside your network, assume they '
            'can see all feeds. Check for port forwarding rules on your router.',
    },
    1883: {
        'how_exploited': 'MQTT IoT devices send data without encryption. An attacker can subscribe to all '
            'topics (#) and see every message — sensor readings, device states, commands. They can also '
            'publish messages to control devices.',
        'how_to_fix': '1. Use MQTTS (port 8883) with TLS certificates.\n'
            '2. Require username/password authentication.\n'
            '3. Use ACLs to restrict which clients can publish/subscribe to which topics.\n'
            '4. Segment IoT devices on their own VLAN.',
        'currently_malicious': 'Unencrypted MQTT is common on IoT devices. It becomes malicious when '
            'unauthorized clients subscribe to topics or publish commands.',
    },
    31769: {
        'how_exploited': 'Certain parking systems transmit cleartext XML over UDP containing '
            'credit card last-four digits and card type (PCI-DSS Req 4 violation), EZPass/RFID transponder '
            'IDs (cloneable with a $30 RFID writer for toll fraud), NFC credentials, ticket numbers, gate '
            'PC identities, and full transaction metadata. The protocol has zero authentication — any device '
            'on the network can passively capture all data or actively inject commands to open gates, create '
            'fake tickets, or inject fake transactions.',
        'how_to_fix': '1. Require TLS encryption on all inter-gate communication.\n'
            '2. Implement command authentication (HMAC or similar) so only legitimate gate PCs can issue commands.\n'
            '3. Isolate the parking overlay from the parking VLAN via firewall rules.\n'
            '4. Contact the parking system vendor to remediate the PCI-DSS violation.\n'
            '5. Document findings for PCI compliance audit trail.',
        'currently_malicious': 'This is a confirmed PCI-DSS Requirement 4 violation. Cardholder data '
            '(last four + card type) is transmitted unencrypted. EZPass RFID tags are directly cloneable. '
            'The unauthenticated command protocol allows gate manipulation from any device on the network.',
    },
}

# Default for protocols without specific exploitation info
DEFAULT_EXPLOITATION = {
    'how_exploited': 'This protocol transmits data without encryption. Anyone on the same network '
        'segment can capture and read all traffic using standard packet capture tools.',
    'how_to_fix': 'Switch to the encrypted version of this protocol. '
        'Restrict access to authorized IPs via firewall rules.',
    'currently_malicious': 'Check if this connection was expected. Unexpected connections to '
        'insecure services may indicate misconfiguration or unauthorized access.',
}

# HTTP Response headers (server info leakage)
HTTP_RESPONSE_RE = re.compile(rb'^HTTP/\d\.\d\s+\d+', re.MULTILINE)
HTTP_SERVER_RE = re.compile(rb'Server:\s*(.+?)(?:\r?\n)', re.IGNORECASE)
HTTP_POWERED_BY_RE = re.compile(rb'X-Powered-By:\s*(.+?)(?:\r?\n)', re.IGNORECASE)
HTTP_ASPNET_RE = re.compile(rb'X-AspNet-Version:\s*(.+?)(?:\r?\n)', re.IGNORECASE)
HTTP_PHP_RE = re.compile(rb'X-PHP-Version:\s*(.+?)(?:\r?\n)', re.IGNORECASE)
HTTP_GENERATOR_RE = re.compile(rb'X-Generator:\s*(.+?)(?:\r?\n)', re.IGNORECASE)

# HTTP Request inspection
HTTP_USER_AGENT_RE = re.compile(rb'User-Agent:\s*(.+?)(?:\r?\n)', re.IGNORECASE)

# ─── Known suspicious/malicious user agents ──────────────────────────────────
# Based on Emerging Threats ET USER_AGENTS ruleset categories.
# These are tools, bots, and malware that identify themselves in the UA string.

# CRITICAL: Known malware, exploit tools, and attack frameworks
MALICIOUS_USER_AGENTS = [
    # Exploit tools / attack frameworks
    b'nikto', b'sqlmap', b'nmap', b'masscan', b'zmap',
    b'dirbuster', b'gobuster', b'feroxbuster', b'ffuf',
    b'wfuzz', b'burpsuite', b'burp suite', b'owasp',
    b'metasploit', b'cobalt strike', b'empire',
    # Known malicious crawlers / scanners
    b'blacksun', b'black sun', b'zmeu', b'morfeus',
    b'masscan', b'openvas', b'nessus',
    b'havij', b'acunetix', b'netsparker', b'appscan',
    b'w3af', b'arachni', b'skipfish', b'vega/',
    # Malware families that identify in UA
    b'botnet', b'mirai', b'muhstik', b'tsunami',
    b'gafgyt', b'hajime', b'satori',
    # Suspicious generic agents
    b'python-requests', b'python-urllib', b'go-http-client',
    b'libwww-perl', b'lwp-', b'wget/', b'curl/',
    b'java/', b'okhttp', b'httpclient',
    b'winhttp', b'httpie',
    # Shell / command injection markers
    b'${jndi', b'() { :',  # Log4Shell, Shellshock
]

# HIGH: Suspicious but may have legitimate uses (flag with context)
SUSPICIOUS_USER_AGENTS = [
    b'scrapy', b'mechanize', b'phantom', b'headless',
    b'selenium', b'puppeteer', b'playwright',
    b'httpclient', b'aiohttp', b'httpx',
    b'zgrab', b'censys', b'shodan',
    b'crawler', b'spider', b'bot/',
]

# Empty or very short user agents are suspicious
# (malware often forgets to set UA or uses minimal strings)

# ─── Suspicious URL patterns (SQL injection, path traversal, etc.) ────────────
# NOTE: These are matched against the HTTP REQUEST LINE ONLY (method + URL),
# not the full payload body, to avoid false positives from response content.
SUSPICIOUS_URL_PATTERNS = [
    # SQL injection — require URI context (query string indicators)
    (rb"(?:union\+select|union%20select|select\+.*\+from|insert\+into|drop\+table|'%20or%20'1'='1|%27%20or)", 'SQL Injection attempt'),
    # Path traversal
    (rb'(?:\.\./\.\./|\.\.\\\.\.\\|%2e%2e%2f|%252e%252e)', 'Path traversal attempt'),
    # Command injection — require shell metachar + command
    (rb'(?:;(?:ls|cat|id|whoami|uname|wget|curl|nc|bash|sh)\b|\|(?:ls|cat|id|whoami)\b)', 'Command injection attempt'),
    # Log4Shell
    (rb'\$\{jndi:', 'Log4Shell (CVE-2021-44228) exploit attempt'),
    # Shellshock — specifically in headers, not URL
    (rb'\(\)\s*\{\s*:', 'Shellshock (CVE-2014-6271) exploit attempt'),
    # Common webshell paths (specific filenames)
    (rb'(?:/(?:cmd|shell|c99|r57|b374k|wso)\.(php|asp|jsp))', 'Webshell access attempt'),
    # WordPress exploit paths
    (rb'(?:/wp-(?:admin|login|content/uploads)/.*\.php\?)', 'WordPress exploit probe'),
    # Admin panel probes — standalone paths only (not /api/v1/admin/settings)
    (rb'^(?:GET|POST|PUT)\s+/(?:phpmyadmin|adminer|manager/html|jenkins|solr)(?:/|\s)', 'Admin panel probe'),
]


# ═══════════════════════════════════════════════════════════════════════════════
#  INSECURE PROTOCOL DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

INSECURE_PROTOCOLS = {
    # ─── Classic Insecure ─────────────────────────────────────
    21:   {'name': 'FTP',        'risk': 'CRITICAL', 'desc': 'File Transfer Protocol — all data including credentials sent in plaintext'},
    23:   {'name': 'Telnet',     'risk': 'CRITICAL', 'desc': 'Telnet — entire session including passwords in plaintext'},
    25:   {'name': 'SMTP',       'risk': 'HIGH',     'desc': 'Email (SMTP) — may transmit credentials and emails unencrypted'},
    69:   {'name': 'TFTP',       'risk': 'HIGH',     'desc': 'Trivial FTP — no authentication at all, plaintext transfers'},
    80:   {'name': 'HTTP',       'risk': 'MEDIUM',   'desc': 'Unencrypted HTTP — forms, cookies, and content visible to anyone on the network'},
    110:  {'name': 'POP3',       'risk': 'HIGH',     'desc': 'Email retrieval (POP3) — credentials and emails in plaintext'},
    143:  {'name': 'IMAP',       'risk': 'HIGH',     'desc': 'Email retrieval (IMAP) — credentials and emails in plaintext'},
    161:  {'name': 'SNMP v1/v2', 'risk': 'HIGH',     'desc': 'Network management — community strings (passwords) in plaintext'},
    162:  {'name': 'SNMP Trap',  'risk': 'HIGH',     'desc': 'SNMP traps — network alerts with community strings in plaintext'},
    389:  {'name': 'LDAP',       'risk': 'HIGH',     'desc': 'Directory services — may transmit credentials unencrypted'},
    445:  {'name': 'SMB',        'risk': 'MEDIUM',   'desc': 'File sharing — older SMB versions transmit credentials weakly'},
    513:  {'name': 'rlogin',     'risk': 'CRITICAL', 'desc': 'Remote login — no encryption, trust-based authentication'},
    514:  {'name': 'rsh/syslog', 'risk': 'HIGH',     'desc': 'Remote shell or syslog — plaintext commands/logs'},
    587:  {'name': 'SMTP Sub',   'risk': 'MEDIUM',   'desc': 'SMTP submission — should use STARTTLS but may fall back to plaintext'},

    # ─── Databases ────────────────────────────────────────────
    1433: {'name': 'MSSQL',      'risk': 'HIGH',     'desc': 'SQL Server — may transmit queries and credentials unencrypted'},
    1521: {'name': 'Oracle DB',  'risk': 'HIGH',     'desc': 'Oracle Database — may transmit queries and credentials unencrypted'},
    3306: {'name': 'MySQL',      'risk': 'HIGH',     'desc': 'MySQL — may transmit queries and credentials unencrypted'},
    5432: {'name': 'PostgreSQL', 'risk': 'MEDIUM',   'desc': 'PostgreSQL — may transmit data unencrypted'},
    6379: {'name': 'Redis',      'risk': 'CRITICAL', 'desc': 'Redis — often deployed with NO authentication, full database access'},
    9042: {'name': 'Cassandra',  'risk': 'HIGH',     'desc': 'Cassandra — may have no authentication configured'},
    27017:{'name': 'MongoDB',    'risk': 'CRITICAL', 'desc': 'MongoDB — frequently left open with no auth, massive breach vector'},
    5984: {'name': 'CouchDB',    'risk': 'HIGH',     'desc': 'CouchDB — REST API often exposed without authentication'},

    # ─── Search / Cache / Message Queues ─────────────────────
    9200: {'name': 'Elasticsearch', 'risk': 'CRITICAL', 'desc': 'Elasticsearch — no auth by default, entire databases exposed'},
    11211:{'name': 'Memcached',  'risk': 'HIGH',     'desc': 'Memcached — no authentication, used in DDoS amplification attacks'},
    5672: {'name': 'AMQP',       'risk': 'MEDIUM',   'desc': 'RabbitMQ/AMQP — message queue, may expose credentials'},
    15672:{'name': 'RabbitMQ UI','risk': 'HIGH',     'desc': 'RabbitMQ management UI — admin interface often with default credentials'},

    # ─── Remote Access ────────────────────────────────────────
    5900: {'name': 'VNC',        'risk': 'CRITICAL', 'desc': 'VNC remote desktop — password often sent in weak encoding, screen visible'},
    5901: {'name': 'VNC-1',      'risk': 'CRITICAL', 'desc': 'VNC display :1 — unencrypted remote desktop access'},
    5800: {'name': 'VNC HTTP',   'risk': 'HIGH',     'desc': 'VNC over HTTP — web-based remote desktop, unencrypted'},

    # ─── VoIP / Streaming / IoT ──────────────────────────────
    554:  {'name': 'RTSP',       'risk': 'HIGH',     'desc': 'Security cameras/streaming — credentials and video feed unencrypted'},
    1883: {'name': 'MQTT',       'risk': 'HIGH',     'desc': 'IoT messaging — smart devices sending data without encryption'},
    5060: {'name': 'SIP',        'risk': 'HIGH',     'desc': 'VoIP signaling — call metadata and credentials in plaintext'},

    # ─── File Sharing / Sync ─────────────────────────────────
    873:  {'name': 'rsync',      'risk': 'HIGH',     'desc': 'rsync file sync — can expose entire filesystems without authentication'},
    2049: {'name': 'NFS',        'risk': 'HIGH',     'desc': 'Network File System — file shares often misconfigured, no encryption'},

    # ─── HTTP Alternatives (dev servers, admin panels) ───────
    3000: {'name': 'HTTP-Dev',   'risk': 'MEDIUM',   'desc': 'Development server (Node.js, Grafana, etc.) — likely unencrypted'},
    4200: {'name': 'HTTP-Dev',   'risk': 'MEDIUM',   'desc': 'Angular dev server — unencrypted'},
    5000: {'name': 'HTTP-Dev',   'risk': 'MEDIUM',   'desc': 'Flask/Docker Registry — likely unencrypted'},
    8000: {'name': 'HTTP-Alt',   'risk': 'MEDIUM',   'desc': 'Alternative HTTP — likely unencrypted web service'},
    8008: {'name': 'HTTP-Alt',   'risk': 'MEDIUM',   'desc': 'Alternative HTTP — likely unencrypted web service'},
    8080: {'name': 'HTTP-Proxy', 'risk': 'MEDIUM',   'desc': 'HTTP proxy/alt — unencrypted web traffic'},
    8081: {'name': 'HTTP-Alt',   'risk': 'MEDIUM',   'desc': 'Alternative HTTP — likely unencrypted web service'},
    8888: {'name': 'HTTP-Alt',   'risk': 'MEDIUM',   'desc': 'Alternative HTTP / Jupyter — likely unencrypted'},
    9090: {'name': 'HTTP-Admin', 'risk': 'HIGH',     'desc': 'Admin panel (Prometheus, Cockpit, etc.) — likely unencrypted'},

    # ─── Network Services ────────────────────────────────────
    1812: {'name': 'RADIUS',     'risk': 'HIGH',     'desc': 'RADIUS authentication — shared secrets may be weakly protected'},
    1813: {'name': 'RADIUS Acct','risk': 'MEDIUM',   'desc': 'RADIUS accounting — user activity data unencrypted'},

    # ─── Industrial / SCADA / Building ───────────────────────
    502:  {'name': 'Modbus',     'risk': 'CRITICAL', 'desc': 'Industrial control (SCADA) — NO authentication, can control physical equipment'},
    47808:{'name': 'BACnet',     'risk': 'HIGH',     'desc': 'Building automation — HVAC, elevators, access control with no encryption'},

    # ─── Printers ─────────────────────────────────────────────
    515:  {'name': 'LPD',        'risk': 'MEDIUM',   'desc': 'Line Printer Daemon — print jobs visible, may leak documents'},
    631:  {'name': 'IPP',        'risk': 'MEDIUM',   'desc': 'Internet Printing Protocol — print jobs and printer info unencrypted'},
    9100: {'name': 'JetDirect',  'risk': 'MEDIUM',   'desc': 'HP JetDirect — raw printing, can send commands to printer'},

    # ─── Chat / IRC ───────────────────────────────────────────
    6667: {'name': 'IRC',        'risk': 'MEDIUM',   'desc': 'IRC chat — unencrypted, also commonly used for malware C2'},
    6668: {'name': 'IRC-Alt',    'risk': 'MEDIUM',   'desc': 'IRC alternate — unencrypted chat'},
    6669: {'name': 'IRC-Alt',    'risk': 'MEDIUM',   'desc': 'IRC alternate — unencrypted chat'},

    # ─── Parking / Access Control ──────────────────────────────
    31769:{'name': 'Skidata/Parking', 'risk': 'CRITICAL', 'desc': 'Parking system — cleartext XML with credit card data, EZPass tags, and transaction metadata (PCI-DSS violation)'},
}

# Secure equivalents
SECURE_EQUIVALENTS = {
    21: 'SFTP (port 22) or FTPS (port 990)',
    23: 'SSH (port 22)',
    25: 'SMTPS (port 465) or SMTP+STARTTLS (port 587)',
    80: 'HTTPS (port 443)',
    110: 'POP3S (port 995)',
    143: 'IMAPS (port 993)',
    161: 'SNMP v3 with encryption',
    389: 'LDAPS (port 636)',
    445: 'SMB v3 with encryption',
    554: 'RTSPS (RTSP over TLS)',
    873: 'rsync over SSH',
    1433: 'MSSQL with TLS encryption',
    1521: 'Oracle with TLS encryption',
    1883: 'MQTTS (port 8883)',
    3306: 'MySQL with TLS encryption',
    5060: 'SIPS (port 5061) or SIP over TLS',
    5432: 'PostgreSQL with TLS (sslmode=require)',
    5672: 'AMQPS (port 5671)',
    5900: 'VNC over SSH tunnel or RDP with NLA',
    5984: 'CouchDB with TLS enabled',
    6379: 'Redis with TLS (redis:// → rediss://)',
    6667: 'IRC over TLS (port 6697)',
    8080: 'HTTPS (port 443 or 8443)',
    9042: 'Cassandra with TLS encryption',
    9200: 'Elasticsearch with TLS and authentication',
    27017: 'MongoDB with TLS and SCRAM authentication',
    31769: 'Skidata inter-gate communication with TLS + authenticated commands',
}


# ═══════════════════════════════════════════════════════════════════════════════
#  FLOW BEHAVIOR CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

class FlowClassifier:
    """Classifies network flows by behavioral patterns."""

    # Flow behavior signatures based on packet characteristics
    SIGNATURES = {
        'web_browsing': {
            'ports': {80, 443, 8080, 8443},
            'avg_pkt_size': (200, 1500),
            'direction_ratio': (0.2, 0.8),  # Bidirectional
            'desc': 'Web browsing / HTTP(S)',
        },
        'video_streaming': {
            'ports': {443, 80, 1935, 554},
            'avg_pkt_size': (1000, 1500),
            'direction_ratio': (0.05, 0.3),  # Mostly download
            'min_bytes': 1000000,  # > 1MB
            'desc': 'Video/audio streaming',
        },
        'file_transfer': {
            'ports': {20, 21, 22, 990, 443, 80},
            'avg_pkt_size': (800, 1500),
            'direction_ratio': (0.0, 0.15),  # Very one-directional
            'min_bytes': 100000,
            'desc': 'File download/upload',
        },
        'voip_video_call': {
            'ports': {3478, 3479, 5060, 5061, 16384, 32767},
            'protocol': 'UDP',
            'avg_pkt_size': (100, 300),
            'desc': 'Voice/video call (VoIP/RTP)',
        },
        'dns_lookup': {
            'ports': {53, 5353},
            'protocol': 'UDP',
            'avg_pkt_size': (40, 512),
            'desc': 'DNS resolution',
        },
        'email': {
            'ports': {25, 110, 143, 465, 587, 993, 995},
            'desc': 'Email (SMTP/POP3/IMAP)',
        },
        'ssh_terminal': {
            'ports': {22},
            'avg_pkt_size': (40, 200),
            'desc': 'SSH terminal session',
        },
        'database': {
            'ports': {1433, 3306, 5432, 6379, 27017, 9200},
            'desc': 'Database connection',
        },
        'gaming': {
            'protocol': 'UDP',
            'avg_pkt_size': (40, 200),
            'high_pps': True,
            'desc': 'Online gaming',
        },
    }

    @classmethod
    def classify_flow(cls, flow_info):
        """
        Classify a flow based on its characteristics.
        flow_info: dict with port, protocol, avg_pkt_size, bytes, packets, direction_ratio
        """
        port = flow_info.get('dst_port', 0)
        protocol = flow_info.get('protocol', 'TCP')
        avg_size = flow_info.get('avg_pkt_size', 0)
        total_bytes = flow_info.get('total_bytes', 0)
        direction = flow_info.get('direction_ratio', 0.5)

        best_match = 'unknown'
        best_score = 0

        for sig_name, sig in cls.SIGNATURES.items():
            score = 0

            if 'ports' in sig and port in sig['ports']:
                score += 3
            if 'protocol' in sig and protocol == sig['protocol']:
                score += 2
            if 'avg_pkt_size' in sig:
                low, high = sig['avg_pkt_size']
                if low <= avg_size <= high:
                    score += 2
            if 'direction_ratio' in sig:
                low, high = sig['direction_ratio']
                if low <= direction <= high:
                    score += 1
            if 'min_bytes' in sig and total_bytes >= sig['min_bytes']:
                score += 1

            if score > best_score:
                best_score = score
                best_match = sig_name

        return best_match, cls.SIGNATURES.get(best_match, {}).get('desc', 'Unknown traffic')


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN FORENSICS ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class NetworkForensics:
    """
    Comprehensive network forensics analysis.
    Feed it packets and it produces security findings, credential exposure
    alerts, flow classifications, and a narrative timeline.
    """

    def __init__(self, forensics_db=None):
        self.db = forensics_db  # ForensicsDB for persistent storage
        # Credential findings
        self.credentials_found = []
        self.sensitive_data = []

        # Security audit findings
        self.insecure_services = {}  # {(ip, port): service_info}
        self.security_findings = []

        # DHCP device inventory
        self.dhcp_devices = {}  # {mac: {ip, hostname, vendor_class, first_seen, last_seen}}

        # mDNS/LLMNR responder tracking for poisoning detection
        self._mdns_responders = defaultdict(set)  # {query: {responding_ips}}
        self._llmnr_responders = defaultdict(set)
        self._mdns_poisoning_alerts = set()  # Dedup

        # SMB version tracking
        self._smb_sessions = {}  # {(src,dst): version}

        # HTTP server info leakage
        self._http_servers = {}  # {(ip, port): {server, powered_by, ...}}

        # ═══ Session Context (for cross-referencing alerts) ═══════════
        # Tracks relationships between IPs, ports, domains, and protocols
        # so we can make smarter decisions about what's legitimate

        # IPs that have active TLS/HTTPS sessions
        self._tls_ips = set()  # {ip} — IPs we've seen on port 443

        # DNS resolution map: IP → domains
        self._ip_to_domains = defaultdict(set)  # {ip: {domain1, domain2}}

        # HTTP methods seen per (src_ip, dst_ip, dst_port)
        self._http_methods = defaultdict(set)  # {(src,dst,port): {'GET','POST',...}}

        # Track payload context per (src_ip, dst_ip) for field-name analysis
        self._http_has_form_fields = defaultdict(bool)  # {(src,dst): True/False}

        # Known CDN IP ranges (by ASN-associated prefixes)
        # We track dynamically: if an IP has served content for a known cloud domain
        self._cdn_ips = set()  # {ip} — IPs associated with known CDNs/cloud

        # IPs that have had BOTH port 80 and 443 traffic (redirect pattern)
        self._dual_port_ips = defaultdict(set)  # {ip: {80, 443, ...}}

        # HTTP request inspection: dedup to avoid spam
        self._http_ua_alerted = set()  # {(src_ip, user_agent_fragment)}
        self._http_attack_alerted = set()  # {(src_ip, dst_ip, attack_type)}

        # Parking system dedup
        self._parking_cards_seen = set()    # {last_four} — dedup card alerts
        self._parking_tags_seen = set()     # {tag_value} — dedup RFID/NFC alerts
        self._parking_geteip_seen = set()   # {mac:token} — dedup heartbeat credentials
        self._parking_geteip_alerted = set() # {mac} — dedup heartbeat alerts (one per device)

        # Flow tracking for classification
        self.flows = defaultdict(lambda: {
            'src_ip': '', 'dst_ip': '', 'dst_port': 0, 'protocol': '',
            'packets': 0, 'bytes': 0, 'payload_bytes': 0,
            'src_packets': 0, 'dst_packets': 0,
            'first_seen': 0, 'last_seen': 0,
            'packet_sizes': [], 'dns_query': '',
            'has_payload': False,
        })

        # Timeline events
        self.timeline = []

        # Stats
        self.packets_scanned = 0
        self.unencrypted_packets = 0

    def analyze_packet(self, pkt_info):
        """Analyze a single packet for all forensic indicators."""
        self.packets_scanned += 1

        # Update flow
        flow_key = (
            min(pkt_info.src_ip, pkt_info.dst_ip),
            max(pkt_info.src_ip, pkt_info.dst_ip),
            pkt_info.dst_port, pkt_info.protocol
        )
        flow = self.flows[flow_key]
        flow['src_ip'] = pkt_info.src_ip
        flow['dst_ip'] = pkt_info.dst_ip
        flow['dst_port'] = pkt_info.dst_port
        flow['protocol'] = pkt_info.protocol
        flow['packets'] += 1
        flow['bytes'] += pkt_info.length
        flow['payload_bytes'] += pkt_info.payload_size
        if len(flow['packet_sizes']) < 200:  # Cap to prevent memory growth
            flow['packet_sizes'].append(pkt_info.length)
        if not flow['first_seen']:
            flow['first_seen'] = pkt_info.timestamp
        flow['last_seen'] = pkt_info.timestamp
        if pkt_info.dns_query:
            flow['dns_query'] = pkt_info.dns_query
        if pkt_info.payload_size > 0:
            flow['has_payload'] = True
        if pkt_info.src_ip == flow['src_ip']:
            flow['src_packets'] += 1
        else:
            flow['dst_packets'] += 1

        # ─── Build session context ────────────────────────────
        # Track TLS/HTTPS IPs
        if pkt_info.dst_port == 443 or pkt_info.src_port == 443:
            if pkt_info.dst_port == 443:
                self._tls_ips.add(pkt_info.dst_ip)
            if pkt_info.src_port == 443:
                self._tls_ips.add(pkt_info.src_ip)

        # Track which ports each IP uses (for redirect detection)
        if pkt_info.dst_port in (80, 443, 8080, 8443):
            self._dual_port_ips[pkt_info.dst_ip].add(pkt_info.dst_port)
        if pkt_info.src_port in (80, 443, 8080, 8443):
            self._dual_port_ips[pkt_info.src_ip].add(pkt_info.src_port)

        # Track DNS resolutions
        if pkt_info.dns_query and pkt_info.dns_response:
            try:
                resp_ip = pkt_info.dns_response.strip()
                if resp_ip and not resp_ip.startswith(('0.', '<')):
                    self._ip_to_domains[resp_ip].add(pkt_info.dns_query)
                    # Mark CDN IPs based on resolved domain (O(k) suffix walk)
                    from src.net_detect import NetworkEnvironment, KNOWN_CLOUD_DOMAINS
                    if NetworkEnvironment._domain_in_suffix_set(
                            pkt_info.dns_query, KNOWN_CLOUD_DOMAINS):
                        self._cdn_ips.add(resp_ip)
            except Exception:
                pass

        # Check for insecure protocols
        self._check_insecure_protocol(pkt_info)

        # Scan payload for credentials and sensitive data
        if pkt_info.payload_size > 0 and pkt_info._raw_payload is not None:
            self._scan_payload_bytes(pkt_info, pkt_info._raw_payload)
        elif pkt_info.payload_size > 0:
            # Even without raw payload, flag based on port
            self._flag_unencrypted_data(pkt_info)

    def analyze_packet_with_payload(self, pkt_info, raw_payload):
        """Analyze a packet that includes raw payload bytes."""
        self.analyze_packet(pkt_info)
        if raw_payload:
            self._scan_payload_bytes(pkt_info, raw_payload)

    def _check_insecure_protocol(self, pkt_info):
        """Flag insecure protocol usage."""
        port = pkt_info.dst_port
        if port in INSECURE_PROTOCOLS and pkt_info.payload_size > 0:
            self.unencrypted_packets += 1
            key = (pkt_info.dst_ip, port)
            if key not in self.insecure_services:
                service = INSECURE_PROTOCOLS[port]
                self.insecure_services[key] = {
                    'ip': pkt_info.dst_ip,
                    'port': port,
                    'service': service['name'],
                    'risk': service['risk'],
                    'description': service['desc'],
                    'secure_alternative': SECURE_EQUIVALENTS.get(port, 'Use encrypted version'),
                    'first_seen': pkt_info.timestamp,
                    'packet_count': 0,
                    'bytes': 0,
                    'src_ips': set(),
                    'has_https': False,  # Will be True if same IP also has TLS
                }
            svc = self.insecure_services[key]
            svc['packet_count'] += 1
            svc['bytes'] += pkt_info.length
            svc['src_ips'].add(pkt_info.src_ip)

            # Session context: check if this IP also has HTTPS traffic
            if port == 80 and pkt_info.dst_ip in self._tls_ips:
                svc['has_https'] = True
                # Downgrade risk if this is clearly a redirect pattern
                if svc['bytes'] < 5000 and svc['packet_count'] < 20:
                    svc['risk'] = 'LOW'
                    svc['description'] = ('HTTP→HTTPS redirect — server also serves '
                        'HTTPS, minimal HTTP traffic indicates automatic redirect')

    def _flag_unencrypted_data(self, pkt_info):
        """Flag unencrypted data transfer even without payload access."""
        port = pkt_info.dst_port
        if port in INSECURE_PROTOCOLS and pkt_info.payload_size > 5:
            proto_info = INSECURE_PROTOCOLS[port]
            self._add_timeline_event(pkt_info.timestamp, 'security',
                f"Unencrypted {proto_info['name']} data: "
                f"{pkt_info.src_ip} → {pkt_info.dst_ip}:{port} "
                f"({pkt_info.payload_size} bytes)")

    def _scan_payload_bytes(self, pkt_info, payload):
        """Deep scan of raw payload bytes for credentials and sensitive data."""
        if not payload or len(payload) < 4:
            return

        ts = pkt_info.timestamp
        src = pkt_info.src_ip
        dst = pkt_info.dst_ip
        port = pkt_info.dst_port

        # ─── FTP Credentials ─────────────────────────────────
        if port == 21 or pkt_info.src_port == 21:
            match = FTP_USER_RE.search(payload)
            if match:
                username = match.group(1).decode('utf-8', errors='replace')
                self._add_credential('FTP', 'username', username, src, dst, port, ts,
                                      raw_value=username)

            match = FTP_PASS_RE.search(payload)
            if match:
                password = match.group(1).decode('utf-8', errors='replace')
                self._add_credential('FTP', 'password', self._mask(password), src, dst, port, ts,
                                      raw_value=password)

        # ─── HTTP Credentials ─────────────────────────────────
        HTTP_PORTS = {80, 3000, 4200, 5000, 8000, 8008, 8080, 8081, 8888, 9090}
        if port in HTTP_PORTS or pkt_info.src_port in HTTP_PORTS:
            # Track HTTP method for session context
            req_match = HTTP_REQUEST_RE.search(payload)
            if req_match:
                method = req_match.group(1).decode('utf-8', errors='replace').upper()
                self._http_methods[(src, dst, port)].add(method)
                # Track if form fields exist (credit card context)
                if method == 'POST' and any(field in payload.lower()
                    for field in [b'card', b'cc_num', b'credit', b'payment',
                                  b'pan=', b'cardnumber']):
                    self._http_has_form_fields[(src, dst)] = True

            # ─── HTTP Request Inspection ──────────────────────
            # Only inspect outbound requests (dst is HTTP port)
            if port in HTTP_PORTS:
                self._inspect_http_request(pkt_info, payload, ts, src, dst, port)
            # Basic Auth
            match = HTTP_BASIC_AUTH_RE.search(payload)
            if match:
                try:
                    decoded = base64.b64decode(match.group(1)).decode('utf-8', errors='replace')
                    if ':' in decoded:
                        user, passwd = decoded.split(':', 1)
                        host = ''
                        host_match = HTTP_HOST_RE.search(payload)
                        if host_match:
                            host = host_match.group(1).decode('utf-8', errors='replace')
                        self._add_credential('HTTP Basic Auth', 'credentials',
                            f"{user}:{self._mask(passwd)}", src, dst, port, ts,
                            extra={'host': host}, raw_value=f"{user}:{passwd}")
                except Exception:
                    pass

            # Digest Auth (routers, cameras, HVAC, older web interfaces)
            match = HTTP_DIGEST_RE.search(payload)
            if match:
                digest_data = match.group(1)
                user_match = HTTP_DIGEST_USER_RE.search(digest_data)
                realm_match = HTTP_DIGEST_REALM_RE.search(digest_data)
                uri_match = HTTP_DIGEST_URI_RE.search(digest_data)
                nonce_match = HTTP_DIGEST_NONCE_RE.search(digest_data)
                resp_match = HTTP_DIGEST_RESPONSE_RE.search(digest_data)

                username = user_match.group(1).decode('utf-8', errors='replace') if user_match else '?'
                realm = realm_match.group(1).decode('utf-8', errors='replace') if realm_match else '?'
                uri = uri_match.group(1).decode('utf-8', errors='replace') if uri_match else '?'
                nonce = nonce_match.group(1).decode('utf-8', errors='replace') if nonce_match else ''
                response = resp_match.group(1).decode('utf-8', errors='replace') if resp_match else ''

                host = ''
                host_match = HTTP_HOST_RE.search(payload)
                if host_match:
                    host = host_match.group(1).decode('utf-8', errors='replace')

                # Check if this is a known software update service using Digest Auth
                # (ESET updates use HTTP Digest Auth by design — not a real credential leak
                # since Digest Auth sends a hashed response, not the plaintext password)
                KNOWN_DIGEST_AUTH_SERVICES = {
                    'update.eset.com', 'eset.com', 'update.nod32.com',
                }
                is_known_update = any(svc in host.lower() for svc in KNOWN_DIGEST_AUTH_SERVICES)

                raw_digest = (f"username={username}, realm={realm}, uri={uri}, "
                             f"nonce={nonce}, response={response}")

                if is_known_update:
                    # Downgrade: Digest Auth is hashed, not plaintext, and this is
                    # a known update service that uses it by design
                    self._add_credential('HTTP Digest Auth (Update Service)', 'digest_hash',
                        f"{username}@{realm} via {host} (hashed, not plaintext)",
                        src, dst, port, ts,
                        extra={'host': host, 'realm': realm, 'uri': uri,
                               'note': 'Digest Auth sends a hashed response, not the actual password. '
                                       'This is a known software update service using HTTP Digest by design.'},
                        raw_value=raw_digest, risk='LOW')
                else:
                    self._add_credential('HTTP Digest Auth', 'digest_credentials',
                        f"{username}@{realm} (uri: {uri})",
                        src, dst, port, ts,
                        extra={'host': host, 'realm': realm, 'uri': uri},
                        raw_value=raw_digest)

            # Bearer / API tokens — skip known update service auth headers
            match = HTTP_AUTH_RE.search(payload)
            if match and b'Basic' not in match.group(1) and b'Digest' not in match.group(1):
                token = match.group(1).decode('utf-8', errors='replace')
                # Check if this is a known update service token
                host_for_token = ''
                hm = HTTP_HOST_RE.search(payload)
                if hm:
                    host_for_token = hm.group(1).decode('utf-8', errors='replace').lower()
                KNOWN_TOKEN_SERVICES = {'update.eset.com', 'eset.com'}
                if any(svc in host_for_token for svc in KNOWN_TOKEN_SERVICES):
                    self._add_credential('HTTP Auth Token (Update Service)', 'token',
                        self._mask(token, show=8) + f' via {host_for_token}', src, dst, port, ts,
                        raw_value=token, risk='LOW')
                else:
                    self._add_credential('HTTP Auth Token', 'token',
                        self._mask(token, show=8), src, dst, port, ts, raw_value=token)

            # API key headers
            match = HTTP_API_KEY_RE.search(payload)
            if match:
                key = match.group(1).decode('utf-8', errors='replace')
                self._add_credential('API Key', 'key',
                    self._mask(key, show=6), src, dst, port, ts, raw_value=key)

            # POST form data with passwords
            match = HTTP_POST_CRED_RE.search(payload)
            if match:
                value = match.group(1).decode('utf-8', errors='replace')
                host = ''
                host_match = HTTP_HOST_RE.search(payload)
                if host_match:
                    host = host_match.group(1).decode('utf-8', errors='replace')
                url = ''
                url_match = HTTP_REQUEST_RE.search(payload)
                if url_match:
                    url = url_match.group(2).decode('utf-8', errors='replace')
                self._add_credential('HTTP Form', 'password_field',
                    self._mask(value), src, dst, port, ts,
                    extra={'host': host, 'url': url[:100]}, raw_value=value)

            # Session cookies — only flag on external connections
            # Internal web UIs (UniFi, Pi-hole, HA) legitimately use session cookies
            is_internal_dst = (
                dst.startswith('192.168.') or dst.startswith('10.') or
                dst.startswith('172.') or dst == '127.0.0.1'
            )
            if not is_internal_dst:
                for regex in (HTTP_COOKIE_RE, HTTP_SET_COOKIE_RE):
                    match = regex.search(payload)
                    if match:
                        cookie = match.group(1).decode('utf-8', errors='replace')
                        if any(s in cookie.lower() for s in ('session', 'auth', 'token', 'sid')):
                            self._add_sensitive_data('Session Cookie', cookie[:80], src, dst, port, ts)

        # ─── Telnet ──────────────────────────────────────────
        if port == 23 or pkt_info.src_port == 23:
            match = TELNET_LOGIN_RE.search(payload)
            if match:
                username = match.group(1).decode('utf-8', errors='replace')
                self._add_credential('Telnet', 'username',
                    username, src, dst, port, ts, raw_value=username)
            match = TELNET_PASS_RE.search(payload)
            if match:
                password = match.group(1).decode('utf-8', errors='replace')
                self._add_credential('Telnet', 'password',
                    self._mask(password), src, dst, port, ts, raw_value=password)

        # ─── Email (SMTP/POP3/IMAP) ─────────────────────────
        if port in (25, 587):
            match = SMTP_AUTH_RE.search(payload)
            if match:
                self._add_credential('SMTP', 'auth_attempt',
                    f"Method: {match.group(1).decode()}", src, dst, port, ts)

        if port == 110 or pkt_info.src_port == 110:
            match = POP3_USER_RE.search(payload)
            if match:
                username = match.group(1).decode('utf-8', errors='replace')
                self._add_credential('POP3', 'username',
                    username, src, dst, port, ts, raw_value=username)
            match = POP3_PASS_RE.search(payload)
            if match:
                password = match.group(1).decode('utf-8', errors='replace')
                self._add_credential('POP3', 'password',
                    self._mask(password), src, dst, port, ts, raw_value=password)

        if port == 143:
            match = IMAP_LOGIN_RE.search(payload)
            if match:
                user = match.group(1).decode('utf-8', errors='replace')
                passwd = match.group(2).decode('utf-8', errors='replace')
                self._add_credential('IMAP', 'login',
                    f"{user}:{self._mask(passwd)}", src, dst, port, ts,
                    raw_value=f"{user}:{passwd}")

        # ─── SNMP Community Strings ──────────────────────────
        if port == 161 or port == 162:
            if b'public' in payload.lower() or b'private' in payload.lower():
                community = 'public' if b'public' in payload.lower() else 'private'
                self._add_credential('SNMP', 'community_string',
                    community, src, dst, port, ts, raw_value=community)

        # ─── Redis AUTH ──────────────────────────────────────
        if port == 6379 or pkt_info.src_port == 6379:
            match = REDIS_AUTH_RE.search(payload)
            if match:
                redis_pass = match.group(1).decode('utf-8', errors='replace')
                self._add_credential('Redis', 'auth_password',
                    self._mask(redis_pass), src, dst, port, ts, raw_value=redis_pass)
            # Redis commands without auth = open database
            if payload.startswith(b'*') and b'SET' in payload or b'GET' in payload:
                if not REDIS_AUTH_RE.search(payload):
                    self._add_sensitive_data('Redis No Auth',
                        'Redis commands without authentication — database is open',
                        src, dst, port, ts, risk='CRITICAL')

        # ─── MongoDB ─────────────────────────────────────────
        if port == 27017 or pkt_info.src_port == 27017:
            match = MONGO_AUTH_RE.search(payload)
            if match:
                mongo_val = match.group(1).decode('utf-8', errors='replace')
                self._add_credential('MongoDB', 'auth_data',
                    self._mask(mongo_val), src, dst, port, ts, raw_value=mongo_val)

        # ─── VNC ─────────────────────────────────────────────
        if port in (5900, 5901, 5800) or pkt_info.src_port in (5900, 5901):
            if VNC_AUTH_RE.search(payload):
                self._add_sensitive_data('VNC Session',
                    'VNC remote desktop connection — screen contents visible on network',
                    src, dst, port, ts, risk='CRITICAL')

        # ─── SIP (VoIP) ─────────────────────────────────────
        if port == 5060 or pkt_info.src_port == 5060:
            match = SIP_AUTH_RE.search(payload)
            if match:
                sip_auth = match.group(1).decode('utf-8', errors='replace')
                self._add_credential('SIP/VoIP', 'digest_auth',
                    self._mask(sip_auth, show=20), src, dst, port, ts, raw_value=sip_auth)

        # ─── RTSP (Cameras) ─────────────────────────────────
        if port == 554 or pkt_info.src_port == 554:
            match = HTTP_BASIC_AUTH_RE.search(payload)
            if match:
                try:
                    decoded = base64.b64decode(match.group(1)).decode('utf-8', errors='replace')
                    if ':' in decoded:
                        user, passwd = decoded.split(':', 1)
                        self._add_credential('RTSP/Camera', 'credentials',
                            f"{user}:{self._mask(passwd)}", src, dst, port, ts,
                            raw_value=f"{user}:{passwd}")
                except Exception:
                    pass

        # ─── MQTT (IoT) ─────────────────────────────────────
        if port == 1883:
            if payload and payload[0:1] == b'\x10':
                self._add_sensitive_data('MQTT/IoT',
                    'Unencrypted MQTT connection — IoT device data visible',
                    src, dst, port, ts, risk='HIGH')

        # ─── rsync ───────────────────────────────────────────
        if port == 873 or pkt_info.src_port == 873:
            if RSYNC_MODULE_RE.search(payload):
                self._add_sensitive_data('rsync',
                    'rsync server responding — file shares may be exposed',
                    src, dst, port, ts, risk='HIGH')

        # ─── IRC ─────────────────────────────────────────────
        if port in (6667, 6668, 6669) or pkt_info.src_port in (6667, 6668, 6669):
            match = IRC_PASS_RE.search(payload)
            if match:
                irc_pass = match.group(1).decode('utf-8', errors='replace')
                self._add_credential('IRC', 'password',
                    self._mask(irc_pass), src, dst, port, ts, raw_value=irc_pass)

        # ─── Modbus/SCADA ────────────────────────────────────
        if port == 502 or pkt_info.src_port == 502:
            # Modbus TCP: 7-byte MBAP header + function code
            # Byte 7 (index 7 after MBAP) is the function code
            if len(payload) >= 8:
                # MBAP header: transaction_id(2) + protocol_id(2) + length(2) + unit_id(1)
                func_code = payload[7] if len(payload) > 7 else 0

                MODBUS_FUNCTIONS = {
                    1: 'Read Coils (digital outputs)',
                    2: 'Read Discrete Inputs',
                    3: 'Read Holding Registers',
                    4: 'Read Input Registers',
                    5: 'Write Single Coil — CONTROL COMMAND',
                    6: 'Write Single Register — CONTROL COMMAND',
                    15: 'Write Multiple Coils — CONTROL COMMAND',
                    16: 'Write Multiple Registers — CONTROL COMMAND',
                    22: 'Mask Write Register — CONTROL COMMAND',
                    23: 'Read/Write Multiple Registers — CONTROL COMMAND',
                    43: 'Read Device Identification',
                }

                func_name = MODBUS_FUNCTIONS.get(func_code, f'Function {func_code}')
                is_write = func_code in (5, 6, 15, 16, 22, 23)

                if is_write:
                    # WRITE commands are critical — someone is controlling equipment
                    unit_id = payload[6] if len(payload) > 6 else 0

                    # Try to extract register address and value
                    details = f"Unit {unit_id}, Function: {func_name}"
                    if len(payload) >= 12:
                        reg_addr = int.from_bytes(payload[8:10], 'big')
                        reg_value = int.from_bytes(payload[10:12], 'big')
                        details += f", Register {reg_addr} = {reg_value}"

                    self._add_sensitive_data('Modbus WRITE',
                        f'Modbus write command to industrial equipment: {details}',
                        src, dst, port, ts, risk='CRITICAL')
                    self._add_credential('Modbus/SCADA', 'control_command',
                        details, src, dst, port, ts, raw_value=details)
                else:
                    # Read commands — still noteworthy, someone is polling
                    self._add_timeline_event(ts, 'scada',
                        f"Modbus READ: {func_name} from {src} → {dst}:{port}")
            else:
                self._add_sensitive_data('Modbus/SCADA',
                    'Modbus traffic detected — NO authentication, equipment can be controlled',
                    src, dst, port, ts, risk='CRITICAL')

        # ─── BACnet (Building Automation) ─────────────────────
        # Only trigger on actual BACnet port 47808 — exclude UniFi discovery (10001)
        # and other protocols that may share the 0x81 BVLC byte signature
        BACNET_PORT = 47808
        BACNET_FALSE_POSITIVE_PORTS = {10001, 8443}  # UniFi discovery, UniFi controller
        is_bacnet_port = (port == BACNET_PORT or pkt_info.src_port == BACNET_PORT)
        is_fp_port = (port in BACNET_FALSE_POSITIVE_PORTS or
                      pkt_info.src_port in BACNET_FALSE_POSITIVE_PORTS)
        if is_bacnet_port and not is_fp_port:
            # BACnet/IP: starts with 0x81 (BACnet Virtual Link Control)
            if payload and len(payload) >= 4:
                bvlc_type = payload[0]
                bvlc_function = payload[1] if len(payload) > 1 else 0

                BVLC_FUNCTIONS = {
                    0x00: 'BVLC-Result',
                    0x01: 'Write-Broadcast-Distribution-Table',
                    0x02: 'Read-Broadcast-Distribution-Table',
                    0x04: 'Forwarded-NPDU',
                    0x0a: 'Original-Unicast-NPDU',
                    0x0b: 'Original-Broadcast-NPDU',
                }

                if bvlc_type == 0x81:  # BACnet/IP
                    bvlc_name = BVLC_FUNCTIONS.get(bvlc_function, f'Function 0x{bvlc_function:02x}')

                    # Parse NPDU (Network Protocol Data Unit) after BVLC header
                    bvlc_len = int.from_bytes(payload[2:4], 'big') if len(payload) >= 4 else 0
                    npdu_start = 4  # After BVLC header

                    # Look for APDU (Application Protocol Data Unit)
                    if len(payload) > npdu_start + 2:
                        npdu_version = payload[npdu_start]
                        npdu_control = payload[npdu_start + 1]

                        # Skip NPDU routing info to find APDU
                        apdu_start = npdu_start + 2
                        if npdu_control & 0x20:  # DNET present
                            apdu_start += 4  # Skip DNET + DLEN + hop count
                        if npdu_control & 0x08:  # SNET present
                            apdu_start += 3  # Skip SNET + SLEN

                        if len(payload) > apdu_start:
                            apdu_type = (payload[apdu_start] >> 4) & 0x0F

                            APDU_TYPES = {
                                0: 'Confirmed-Request',
                                1: 'Unconfirmed-Request',
                                2: 'Simple-ACK',
                                3: 'Complex-ACK',
                                4: 'Segment-ACK',
                                5: 'Error',
                                6: 'Reject',
                                7: 'Abort',
                            }
                            apdu_name = APDU_TYPES.get(apdu_type, f'Type {apdu_type}')

                            # Check for specific BACnet services
                            if apdu_type in (0, 1) and len(payload) > apdu_start + 2:
                                # Get service choice
                                if apdu_type == 1:  # Unconfirmed
                                    service = payload[apdu_start + 1]
                                else:  # Confirmed
                                    service = payload[apdu_start + 2] if len(payload) > apdu_start + 2 else 0

                                BACNET_SERVICES = {
                                    # Unconfirmed services
                                    0: 'I-Am (device discovery response)',
                                    1: 'I-Have',
                                    2: 'Unconfirmed-COV-Notification',
                                    3: 'Unconfirmed-Event-Notification',
                                    4: 'Unconfirmed-Private-Transfer',
                                    5: 'Unconfirmed-Text-Message',
                                    6: 'Time-Synchronization',
                                    7: 'Who-Has',
                                    8: 'Who-Is (device discovery)',
                                    9: 'UTC-Time-Synchronization',
                                    # Confirmed services
                                    12: 'ReadProperty',
                                    14: 'ReadPropertyMultiple',
                                    15: 'WriteProperty — CONTROL COMMAND',
                                    16: 'WritePropertyMultiple — CONTROL COMMAND',
                                    6: 'CreateObject',
                                    7: 'DeleteObject',
                                    17: 'DeviceCommunicationControl',
                                    20: 'ReinitializeDevice — DEVICE RESET',
                                }

                                svc_name = BACNET_SERVICES.get(service, f'Service {service}')

                                # Discovery — someone scanning for BACnet devices
                                if service == 8:  # Who-Is
                                    self._add_timeline_event(ts, 'bacnet',
                                        f"BACnet Who-Is discovery: {src} scanning for devices")
                                    self._add_sensitive_data('BACnet Discovery',
                                        f'BACnet device discovery scan from {src}',
                                        src, dst, port, ts, risk='MEDIUM')

                                elif service == 0:  # I-Am response
                                    self._add_timeline_event(ts, 'bacnet',
                                        f"BACnet I-Am: device at {src} responded to discovery")
                                    self._add_credential('BACnet', 'device_identity',
                                        f"BACnet device at {src} responding to discovery",
                                        src, dst, port, ts,
                                        raw_value=f"BACnet device at {src}, BVLC: {bvlc_name}")

                                # Write commands — someone controlling the building
                                elif service in (15, 16):
                                    self._add_sensitive_data('BACnet WRITE',
                                        f'BACnet write command: {svc_name} — '
                                        f'building equipment being controlled by {src}',
                                        src, dst, port, ts, risk='CRITICAL')
                                    self._add_credential('BACnet', 'control_command',
                                        f'{svc_name} from {src}',
                                        src, dst, port, ts,
                                        raw_value=f'{svc_name}, payload: {payload[apdu_start:apdu_start+50].hex()}')

                                # Device reset — very dangerous
                                elif service == 20:
                                    self._add_sensitive_data('BACnet RESET',
                                        f'BACnet ReinitializeDevice command from {src} — '
                                        f'attempting to reset building automation device!',
                                        src, dst, port, ts, risk='CRITICAL')

                                # Read property — monitoring/surveillance
                                elif service in (12, 14):
                                    self._add_timeline_event(ts, 'bacnet',
                                        f"BACnet ReadProperty: {src} reading from {dst}")

                                else:
                                    self._add_timeline_event(ts, 'bacnet',
                                        f"BACnet {apdu_name}: {svc_name} — {src} → {dst}")
                else:
                    # Non-standard BACnet packet
                    self._add_sensitive_data('BACnet',
                        f'BACnet/IP traffic detected — building automation protocol, no encryption',
                        src, dst, port, ts, risk='HIGH')

        # ─── Parking System Protocol Detection ─────────
        # Cleartext XML commands on UDP 31769 (parking controller overlay)
        # Detects: credit card last-4 + type, EZPass RFID tags, NFC credentials,
        # ticket metadata, gate PC identity, and GETEIP heartbeats
        if port == SKIDATA_PORT or pkt_info.src_port == SKIDATA_PORT:
            # Identify the command type
            cmd_match = SKIDATA_COMMAND_RE.search(payload)
            cmd_type = cmd_match.group(1).decode('utf-8', errors='replace') if cmd_match else 'Unknown'
            sender_match = SKIDATA_SENDER_RE.search(payload)
            sender = sender_match.group(1).decode('utf-8', errors='replace') if sender_match else src
            ticket_match = SKIDATA_TICKET_RE.search(payload)
            ticket_num = ticket_match.group(1).decode('utf-8', errors='replace') if ticket_match else ''

            # ── Credit Card Data (PCI-DSS violation) ──────────
            last4_match = SKIDATA_LASTFOUR_RE.search(payload)
            cardtype_match = SKIDATA_CARDTYPE_RE.search(payload)
            if last4_match:
                last4 = last4_match.group(1).decode('utf-8', errors='replace')
                card_type = cardtype_match.group(1).decode('utf-8', errors='replace') if cardtype_match else 'Unknown'

                # Dedup — only alert once per unique card
                card_key = f"{last4}:{card_type}"
                if card_key not in self._parking_cards_seen:
                    self._parking_cards_seen.add(card_key)

                    raw_value = (f"Command={cmd_type}, LastFour={last4}, CardType={card_type}, "
                                 f"Ticket={ticket_num}, GatePC={sender}, Time={datetime.fromtimestamp(ts)}")

                    self._add_credential('Parking/Skidata', 'credit_card_last4',
                        f"{card_type} ****{last4} (ticket {ticket_num})",
                        src, dst, port, ts,
                        extra={
                            'command': cmd_type, 'last_four': last4,
                            'card_type': card_type, 'ticket_number': ticket_num,
                            'gate_pc': sender, 'pci_violation': True,
                        },
                        raw_value=raw_value, risk='CRITICAL')

                    self._add_sensitive_data('Parking Card Data (PCI-DSS Violation)',
                        f'{card_type} ending {last4} — cleartext over UDP, '
                        f'ticket #{ticket_num}, gate {sender}',
                        src, dst, port, ts, risk='CRITICAL')

                self._add_timeline_event(ts, 'parking_pci',
                    f"⚠ PCI-DSS VIOLATION: {card_type} ****{last4} in cleartext XML "
                    f"({cmd_type}, ticket {ticket_num}, gate {sender})")

            # ── EZPass / RFID Transponder IDs ─────────────────
            entry_cred_match = SKIDATA_ENTRY_CRED_RE.search(payload)
            if entry_cred_match:
                cred_value = entry_cred_match.group(1).decode('utf-8', errors='replace')
                # Determine credential type by agency prefix
                parts = cred_value.split(':')
                agency = parts[0] if len(parts) == 2 else ''
                tag_id = parts[1] if len(parts) == 2 else cred_value

                # Agency 28 = E-ZPass, 68 = NFC/contactless (common patterns)
                if agency == '68' or (agency and int(agency) > 60 and len(tag_id) <= 5):
                    cred_type = 'NFC/Contactless'
                    risk = 'HIGH'
                    agency_info = None
                else:
                    cred_type = 'EZPass/RFID'
                    risk = 'CRITICAL'
                    agency_info = lookup_ezpass_agency(agency)

                # Build human-readable label
                if agency_info:
                    state, agency_name = agency_info
                    display_label = f"{cred_type} tag {cred_value} ({state} — {agency_name})"
                else:
                    display_label = f"{cred_type} tag {cred_value}"

                # Dedup — only alert once per unique tag, but always log timeline
                if cred_value not in self._parking_tags_seen:
                    self._parking_tags_seen.add(cred_value)

                    raw_value = (f"Type={cred_type}, Tag={cred_value}, Command={cmd_type}, "
                                 f"Ticket={ticket_num}, GatePC={sender}, Time={datetime.fromtimestamp(ts)}"
                                 f"{f', Agency={agency_info[1]} ({agency_info[0]})' if agency_info else ''}")

                    extra_fields = {
                        'command': cmd_type, 'credential_type': cred_type,
                        'tag_value': cred_value, 'agency_code': agency,
                        'transponder_id': tag_id, 'ticket_number': ticket_num,
                        'gate_pc': sender,
                    }
                    if agency_info:
                        extra_fields['issuing_state'] = agency_info[0]
                        extra_fields['issuing_agency'] = agency_info[1]

                    self._add_credential('Parking/Skidata', cred_type.lower().replace('/', '_'),
                        f"{display_label} (ticket {ticket_num})",
                        src, dst, port, ts,
                        extra=extra_fields,
                        raw_value=raw_value, risk=risk)

                    self._add_sensitive_data(f'Parking {cred_type} in Cleartext',
                        f'{display_label} — cloneable RFID, '
                        f'ticket #{ticket_num}, gate {sender}',
                        src, dst, port, ts, risk=risk)

                self._add_timeline_event(ts, 'parking_rfid',
                    f"⚠ {cred_type} TAG EXPOSED: {display_label} in cleartext XML "
                    f"({cmd_type}, gate {sender})")

            # ── Credit-card-as-ticket (EntryCredential with :NNNN) ──
            elif not entry_cred_match and not last4_match:
                # Check for colon-prefixed last-four in EntryCredential
                cc_entry_re = re.search(rb'<EntryCredential>\s*:(\d{4})\s*</EntryCredential>',
                                         payload, re.IGNORECASE)
                if cc_entry_re:
                    last4 = cc_entry_re.group(1).decode('utf-8', errors='replace')
                    raw_value = (f"EntryCredential=:{last4}, Command={cmd_type}, "
                                 f"Ticket={ticket_num}, GatePC={sender}")
                    self._add_credential('Parking/Skidata', 'card_as_ticket',
                        f"Card entry :{last4} (ticket {ticket_num})",
                        src, dst, port, ts,
                        extra={'last_four': last4, 'command': cmd_type,
                               'ticket_number': ticket_num, 'gate_pc': sender},
                        raw_value=raw_value, risk='HIGH')

            # ── General transaction metadata logging ──────────
            if cmd_match and not last4_match and not entry_cred_match:
                account_match = SKIDATA_ACCOUNT_RE.search(payload)
                pricing_match = SKIDATA_PRICING_RE.search(payload)
                account = account_match.group(1).decode('utf-8', errors='replace') if account_match else ''
                pricing = pricing_match.group(1).decode('utf-8', errors='replace') if pricing_match else ''

                self._add_timeline_event(ts, 'parking_cmd',
                    f"Parking {cmd_type}: ticket={ticket_num}, "
                    f"gate={sender}, account={account or 'n/a'}")

        # ─── GETEIP Heartbeat (parking cloud service) ────────────────
        # Leaks device MAC, model, WAN IP, and auth token in cleartext UDP
        geteip_match = GETEIP_RE.search(payload)
        if geteip_match:
            mac = geteip_match.group(1).decode('utf-8', errors='replace')
            device_id = geteip_match.group(2).decode('utf-8', errors='replace')
            wan_ip = geteip_match.group(3).decode('utf-8', errors='replace')
            token = geteip_match.group(4).decode('utf-8', errors='replace')

            raw_value = (f"MAC={mac}, DeviceID={device_id}, WAN_IP={wan_ip}, "
                         f"Token={token}, CloudServer={dst}")

            # Always vault the token (rotates every 60s, want full history)
            # but only create a credential entry for NEW tokens
            token_key = f"{mac}:{token}"
            if token_key not in self._parking_geteip_seen:
                self._parking_geteip_seen.add(token_key)

                self._add_credential('ParkingCloud/GETEIP', 'heartbeat_token',
                    f"Device {device_id} (MAC {mac}) → WAN {wan_ip}, "
                    f"token {token[:12]}...",
                    src, dst, port, ts,
                    extra={
                        'device_mac': mac, 'device_id': device_id,
                        'wan_ip': wan_ip, 'cloud_server': dst,
                        'token_preview': token[:12],
                        'note': 'Rotating auth token for parking cloud service, '
                                'cleartext and potentially replayable within 60s window',
                    },
                    raw_value=raw_value, risk='HIGH')

            # Only one sensitive data alert per device MAC
            if mac not in self._parking_geteip_alerted:
                self._parking_geteip_alerted.add(mac)
                self._add_sensitive_data('Parking System Heartbeat',
                    f'Device {device_id} (MAC {mac}) leaking WAN IP {wan_ip} '
                    f'and auth token to {dst}',
                    src, dst, port, ts, risk='MEDIUM')

        # ─── Elasticsearch ───────────────────────────────────
        if port == 9200 or pkt_info.src_port == 9200:
            if b'/_search' in payload or b'/_cat' in payload or b'/_cluster' in payload:
                self._add_sensitive_data('Elasticsearch',
                    'Elasticsearch API access without TLS — database queries visible',
                    src, dst, port, ts, risk='CRITICAL')

        # ─── Printer ─────────────────────────────────────────
        if port in (515, 631, 9100):
            if pkt_info.payload_size > 100:
                self._add_sensitive_data('Network Printer',
                    f'Unencrypted print data ({pkt_info.payload_size} bytes) — document contents visible',
                    src, dst, port, ts, risk='MEDIUM')

        # ─── Private Keys in Transit ─────────────────────────
        if PRIVATE_KEY_RE.search(payload):
            self._add_sensitive_data('Private Key', 'PRIVATE KEY detected in transit!',
                                     src, dst, port, ts, risk='CRITICAL')

        # ─── Credit Card Numbers ─────────────────────────────
        # Full session context analysis to minimize false positives:
        # 1. Direction: only outbound (user → server)
        # 2. Luhn validation: must be a mathematically valid card number
        # 3. HTTPS coexistence: if same IP also has TLS, this is a redirect
        # 4. CDN check: known CDN IPs serve millions of sites, not card skimmers
        # 5. HTTP method: POST with card-like form fields is serious, GET is not
        # 6. Domain check: known cloud/CDN domain resolving to this IP = benign
        HTTP_SERVER_PORTS = {80, 443, 3000, 4200, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9090}
        is_server_response = pkt_info.src_port in HTTP_SERVER_PORTS

        if not is_server_response:
            match = CC_PATTERN_RE.search(payload)
            if match:
                cc = match.group(0).decode('utf-8', errors='replace')
                if self._luhn_check(cc):
                    # Build context verdict
                    cc_context = self._assess_sensitive_data_context(
                        pkt_info, payload, 'credit_card')

                    if cc_context['should_alert']:
                        self._add_sensitive_data('Credit Card',
                            f"****{cc[-4:]} ({cc_context['confidence']})",
                            src, dst, port, ts, risk=cc_context['risk'])
                    else:
                        self._add_timeline_event(ts, 'context_suppressed',
                            f"CC pattern ****{cc[-4:]} suppressed: {cc_context['reason']}")

        # ─── SSN ─────────────────────────────────────────────
        if not is_server_response:
            match = SSN_RE.search(payload)
            if match:
                ssn_context = self._assess_sensitive_data_context(
                    pkt_info, payload, 'ssn')

                if ssn_context['should_alert']:
                    self._add_sensitive_data('SSN',
                        '***-**-' + match.group(0).decode()[-4:],
                        src, dst, port, ts, risk=ssn_context['risk'])
                else:
                    self._add_timeline_event(ts, 'context_suppressed',
                        f"SSN pattern suppressed: {ssn_context['reason']}")

        # ═════════════════════════════════════════════════════
        # FEATURE 1: DHCP Device Snooping
        # ═════════════════════════════════════════════════════
        if port in (67, 68) or pkt_info.src_port in (67, 68):
            self._parse_dhcp(pkt_info, payload, ts)

        # ═════════════════════════════════════════════════════
        # FEATURE 2: mDNS / LLMNR Poisoning Detection
        # ═════════════════════════════════════════════════════
        if port == 5353 or pkt_info.src_port == 5353:
            self._check_mdns_poisoning(pkt_info, payload, ts)
        if port == 5355 or pkt_info.src_port == 5355:
            self._check_llmnr_poisoning(pkt_info, payload, ts)

        # ═════════════════════════════════════════════════════
        # FEATURE 3: SMB Version Detection (SMBv1 = critical risk)
        # ═════════════════════════════════════════════════════
        if port == 445 or pkt_info.src_port == 445:
            self._check_smb_version(pkt_info, payload, ts)

        # ═════════════════════════════════════════════════════
        # FEATURE 4: HTTP Response Header Info Leakage
        # ═════════════════════════════════════════════════════
        HTTP_PORTS = {80, 3000, 4200, 5000, 8000, 8008, 8080, 8081, 8888, 9090}
        if pkt_info.src_port in HTTP_PORTS:
            # This is a response FROM a web server
            self._check_http_response_headers(pkt_info, payload, ts)

    # ─── HTTP Request Inspection ─────────────────────────────

    def _inspect_http_request(self, pkt_info, payload, ts, src, dst, port):
        """
        Inspect outbound HTTP requests for:
        - Suspicious/malicious user agents (tools, bots, malware)
        - Attack patterns in URLs (SQLi, path traversal, command injection)
        - Exploit signatures (Log4Shell, Shellshock)
        """
        # Extract user agent
        ua_match = HTTP_USER_AGENT_RE.search(payload)
        if ua_match:
            user_agent = ua_match.group(1)
            ua_lower = user_agent.lower()
            ua_str = user_agent.decode('utf-8', errors='replace').strip()

            # Check for MALICIOUS user agents (CRITICAL)
            for bad_ua in MALICIOUS_USER_AGENTS:
                if bad_ua in ua_lower:
                    dedup_key = (src, bad_ua.decode('utf-8', errors='replace'))
                    if dedup_key not in self._http_ua_alerted:
                        self._http_ua_alerted.add(dedup_key)

                        # Get request details
                        host = ''
                        host_match = HTTP_HOST_RE.search(payload)
                        if host_match:
                            host = host_match.group(1).decode('utf-8', errors='replace')
                        url = ''
                        url_match = HTTP_REQUEST_RE.search(payload)
                        method = ''
                        if url_match:
                            method = url_match.group(1).decode('utf-8', errors='replace')
                            url = url_match.group(2).decode('utf-8', errors='replace')[:200]

                        self._add_sensitive_data('Suspicious User Agent',
                            f'Malicious user agent detected: "{ua_str[:80]}" '
                            f'({method} {host}{url[:60]})',
                            src, dst, port, ts, risk='CRITICAL')

                        self.security_findings.append({
                            'type': 'malicious_user_agent',
                            'risk': 'CRITICAL',
                            'title': f'Malicious User Agent: {bad_ua.decode()}',
                            'description': (
                                f'HTTP request from {src} to {dst}:{port} '
                                f'used user agent "{ua_str[:100]}" which matches '
                                f'known attack tool/malware signature "{bad_ua.decode()}".'
                            ),
                            'details': {
                                'user_agent': ua_str[:200],
                                'matched_signature': bad_ua.decode(),
                                'source_ip': src,
                                'destination': f'{host or dst}:{port}',
                                'method': method,
                                'url': url[:200],
                            },
                            'recommendation': (
                                'Investigate which process on the source machine sent this request. '
                                'This user agent is associated with attack tools, vulnerability '
                                'scanners, or malware. If you ran a security tool intentionally, '
                                'this is expected. If not, the machine may be compromised.'
                            ),
                        })
                    break  # Only match first

            # Check for SUSPICIOUS user agents (HIGH)
            else:
                for sus_ua in SUSPICIOUS_USER_AGENTS:
                    if sus_ua in ua_lower:
                        dedup_key = (src, sus_ua.decode('utf-8', errors='replace'))
                        if dedup_key not in self._http_ua_alerted:
                            self._http_ua_alerted.add(dedup_key)

                            host = ''
                            host_match = HTTP_HOST_RE.search(payload)
                            if host_match:
                                host = host_match.group(1).decode('utf-8', errors='replace')

                            self._add_sensitive_data('Suspicious User Agent',
                                f'Uncommon user agent: "{ua_str[:80]}" → {host or dst}:{port}',
                                src, dst, port, ts, risk='HIGH')
                        break

                # Check for empty/very short user agent (suspicious)
                else:
                    if len(ua_str.strip()) < 5 and ua_str.strip():
                        dedup_key = (src, 'short_ua')
                        if dedup_key not in self._http_ua_alerted:
                            self._http_ua_alerted.add(dedup_key)
                            self._add_sensitive_data('Suspicious User Agent',
                                f'Unusually short user agent: "{ua_str}" — '
                                f'may indicate malware or automated tool',
                                src, dst, port, ts, risk='MEDIUM')
        else:
            # No User-Agent header at all (many attack tools omit it)
            # But skip known software update services that legitimately omit UA
            if HTTP_REQUEST_RE.search(payload):
                host_for_ua = ''
                hm = HTTP_HOST_RE.search(payload)
                if hm:
                    host_for_ua = hm.group(1).decode('utf-8', errors='replace').lower()
                KNOWN_NO_UA_SERVICES = {
                    'update.eset.com', 'eset.com', 'windowsupdate.com',
                    'update.microsoft.com', 'ctldl.windowsupdate.com',
                    'download.windowsupdate.com',
                }
                is_known_service = any(svc in host_for_ua for svc in KNOWN_NO_UA_SERVICES)
                if not is_known_service:
                    dedup_key = (src, 'no_ua')
                    if dedup_key not in self._http_ua_alerted:
                        self._http_ua_alerted.add(dedup_key)
                        self._add_sensitive_data('Missing User Agent',
                            f'HTTP request with no User-Agent header from {src} → {dst}:{port}',
                            src, dst, port, ts, risk='MEDIUM')

        # ─── Check URL for attack patterns ────────────────────
        # Only scan the request line and headers, not response bodies
        # or POST data (which would cause massive false positives)
        url_match = HTTP_REQUEST_RE.search(payload)
        if url_match:
            request_line = url_match.group(0)
            url_bytes = url_match.group(2)

            # Extract just the request line + headers (up to \r\n\r\n or first 2KB)
            header_end = payload.find(b'\r\n\r\n')
            scan_region = payload[:min(header_end if header_end > 0 else 2048, 2048)]

            for pattern, attack_name in SUSPICIOUS_URL_PATTERNS:
                if re.search(pattern, scan_region, re.IGNORECASE):
                    dedup_key = (src, dst, attack_name)
                    if dedup_key not in self._http_attack_alerted:
                        self._http_attack_alerted.add(dedup_key)

                        host = ''
                        host_match = HTTP_HOST_RE.search(payload)
                        if host_match:
                            host = host_match.group(1).decode('utf-8', errors='replace')
                        url = url_bytes.decode('utf-8', errors='replace')[:200]

                        self._add_sensitive_data('HTTP Attack Pattern',
                            f'{attack_name}: {src} → {host or dst}:{port} ({url[:80]})',
                            src, dst, port, ts, risk='CRITICAL')

                        self.security_findings.append({
                            'type': 'http_attack',
                            'risk': 'CRITICAL',
                            'title': f'HTTP Attack: {attack_name}',
                            'description': (
                                f'Detected {attack_name} in HTTP request from {src} '
                                f'to {host or dst}:{port}.'
                            ),
                            'details': {
                                'attack_type': attack_name,
                                'source_ip': src,
                                'destination': f'{host or dst}:{port}',
                                'url': url,
                                'full_request': request_line.decode('utf-8', errors='replace')[:200],
                            },
                            'recommendation': (
                                'This HTTP request contains a known attack pattern. '
                                'If you are running security testing tools, this is expected. '
                                'If this originated from an unknown process, investigate immediately.'
                            ),
                        })
                    break  # One attack type per request is enough

    # ─── FEATURE 1: DHCP Device Snooping ───────────────────

    def _parse_dhcp(self, pkt_info, payload, ts):
        """
        Parse DHCP packets to build a device inventory.
        DHCP Discover/Request from clients reveal: MAC, requested hostname, vendor.
        DHCP Offer/ACK from servers reveal: assigned IP.
        """
        if len(payload) < 240:  # Minimum DHCP packet size
            return

        try:
            # DHCP message type is at byte offset 0
            op = payload[0]  # 1=request, 2=reply
            htype = payload[1]  # Hardware type (1=Ethernet)
            hlen = payload[2]   # Hardware address length

            # Client MAC at offset 28-33
            if hlen == 6 and len(payload) > 34:
                mac = ':'.join(f'{payload[28+i]:02x}' for i in range(6))
            else:
                mac = pkt_info.src_mac or ''

            if not mac or mac == '00:00:00:00:00:00':
                return

            # Client IP (ciaddr) at offset 12-15 (if renewing)
            ciaddr = '.'.join(str(payload[12+i]) for i in range(4))
            # Your IP (yiaddr) at offset 16-19 (assigned by server)
            yiaddr = '.'.join(str(payload[16+i]) for i in range(4))

            # Parse DHCP options starting at offset 240 (after magic cookie at 236)
            hostname = ''
            msg_type = 0
            vendor_class = ''
            requested_ip = ''

            if len(payload) > 240 and payload[236:240] == b'\x63\x82\x53\x63':
                i = 240
                while i < len(payload) - 1:
                    opt = payload[i]
                    if opt == 255:  # End
                        break
                    if opt == 0:  # Padding
                        i += 1
                        continue
                    if i + 1 >= len(payload):
                        break
                    opt_len = payload[i + 1]
                    opt_data = payload[i + 2:i + 2 + opt_len]

                    if opt == 53 and opt_len == 1:  # DHCP Message Type
                        msg_type = opt_data[0]
                    elif opt == 12:  # Hostname
                        hostname = opt_data.decode('utf-8', errors='replace')
                    elif opt == 60:  # Vendor Class
                        vendor_class = opt_data.decode('utf-8', errors='replace')
                    elif opt == 50 and opt_len == 4:  # Requested IP
                        requested_ip = '.'.join(str(b) for b in opt_data)

                    i += 2 + opt_len

            # Determine IP
            ip = ''
            if yiaddr and yiaddr != '0.0.0.0':
                ip = yiaddr  # Server assigned this IP
            elif ciaddr and ciaddr != '0.0.0.0':
                ip = ciaddr  # Client is renewing this IP
            elif requested_ip and requested_ip != '0.0.0.0':
                ip = requested_ip  # Client is requesting this IP

            DHCP_TYPES = {1: 'Discover', 2: 'Offer', 3: 'Request',
                         4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform'}
            type_name = DHCP_TYPES.get(msg_type, f'Type-{msg_type}')

            # Update device inventory
            if mac not in self.dhcp_devices:
                self.dhcp_devices[mac] = {
                    'mac': mac, 'ip': ip, 'hostname': hostname,
                    'vendor_class': vendor_class, 'first_seen': ts, 'last_seen': ts,
                    'dhcp_type': type_name,
                }
                self._add_timeline_event(ts, 'dhcp',
                    f"New device: {hostname or 'unknown'} ({mac}) "
                    f"{'→ ' + ip if ip else ''} [{type_name}]")
            else:
                dev = self.dhcp_devices[mac]
                dev['last_seen'] = ts
                if ip:
                    dev['ip'] = ip
                if hostname:
                    dev['hostname'] = hostname
                if vendor_class:
                    dev['vendor_class'] = vendor_class

        except Exception:
            pass

    # ─── FEATURE 2: mDNS / LLMNR Poisoning Detection ────────

    def _check_mdns_poisoning(self, pkt_info, payload, ts):
        """
        Detect mDNS poisoning. In normal mDNS, devices respond about themselves.
        Poisoning: an attacker responds to queries for OTHER devices' names,
        redirecting traffic to themselves.
        """
        if len(payload) < 12:
            return
        try:
            # DNS-like header: QR bit is in byte 2, bit 7
            flags = int.from_bytes(payload[2:4], 'big')
            is_response = (flags >> 15) & 1
            ancount = int.from_bytes(payload[6:8], 'big')

            if is_response and ancount > 0:
                responder = pkt_info.src_ip
                # Simple heuristic: if the same query gets responses from
                # different IPs, one of them might be poisoning
                # Extract query name (simplified)
                try:
                    name_parts = []
                    i = 12
                    while i < len(payload) and payload[i] > 0 and payload[i] < 64:
                        label_len = payload[i]
                        name_parts.append(payload[i+1:i+1+label_len].decode('utf-8', errors='replace'))
                        i += 1 + label_len
                    query_name = '.'.join(name_parts) if name_parts else ''
                except Exception:
                    query_name = ''

                if query_name:
                    self._mdns_responders[query_name].add(responder)

                    # If more than one IP responds for the same name → suspicious
                    if len(self._mdns_responders[query_name]) > 1:
                        alert_key = query_name
                        if alert_key not in self._mdns_poisoning_alerts:
                            self._mdns_poisoning_alerts.add(alert_key)
                            responders = list(self._mdns_responders[query_name])
                            self._add_sensitive_data('mDNS Poisoning',
                                f'Multiple devices responding for "{query_name}": '
                                f'{", ".join(responders)} — possible mDNS poisoning attack',
                                pkt_info.src_ip, pkt_info.dst_ip, 5353, ts, risk='HIGH')
        except Exception:
            pass

    def _check_llmnr_poisoning(self, pkt_info, payload, ts):
        """
        Detect LLMNR poisoning. Similar to mDNS — an attacker responds
        to name queries to redirect traffic.
        """
        if len(payload) < 12:
            return
        try:
            flags = int.from_bytes(payload[2:4], 'big')
            is_response = (flags >> 15) & 1
            ancount = int.from_bytes(payload[6:8], 'big')

            if is_response and ancount > 0:
                responder = pkt_info.src_ip
                try:
                    name_parts = []
                    i = 12
                    while i < len(payload) and payload[i] > 0 and payload[i] < 64:
                        label_len = payload[i]
                        name_parts.append(payload[i+1:i+1+label_len].decode('utf-8', errors='replace'))
                        i += 1 + label_len
                    query_name = '.'.join(name_parts) if name_parts else ''
                except Exception:
                    query_name = ''

                if query_name:
                    self._llmnr_responders[query_name].add(responder)

                    if len(self._llmnr_responders[query_name]) > 1:
                        alert_key = f"llmnr:{query_name}"
                        if alert_key not in self._mdns_poisoning_alerts:
                            self._mdns_poisoning_alerts.add(alert_key)
                            responders = list(self._llmnr_responders[query_name])
                            self._add_sensitive_data('LLMNR Poisoning',
                                f'Multiple devices responding for "{query_name}" via LLMNR: '
                                f'{", ".join(responders)} — possible LLMNR poisoning (Responder/MITM tool)',
                                pkt_info.src_ip, pkt_info.dst_ip, 5355, ts, risk='CRITICAL')
        except Exception:
            pass

    # ─── FEATURE 3: SMB Version Detection ────────────────────

    def _check_smb_version(self, pkt_info, payload, ts):
        """
        Detect SMBv1 negotiate. SMBv1 is catastrophically insecure
        (EternalBlue, WannaCry, NotPetya all exploited it).
        """
        if len(payload) < 10:
            return
        try:
            src = pkt_info.src_ip
            dst = pkt_info.dst_ip
            session_key = (min(src, dst), max(src, dst))

            # SMBv1 starts with \xFF\x53\x4D\x42 (\xFFSMB)
            smb1_marker = b'\xff\x53\x4d\x42'
            # SMBv2/3 starts with \xFE\x53\x4D\x42 (\xFESMB)
            smb2_marker = b'\xfe\x53\x4d\x42'

            # Check NetBIOS session header (4 bytes) then SMB header
            smb_offset = 0
            if len(payload) > 8:
                # NetBIOS session service: first byte 0x00, then 3 bytes length
                if payload[0] == 0x00:
                    smb_offset = 4

            if len(payload) > smb_offset + 4:
                header = payload[smb_offset:smb_offset + 4]

                if header == smb1_marker:
                    if session_key not in self._smb_sessions or self._smb_sessions[session_key] != 'SMBv1':
                        self._smb_sessions[session_key] = 'SMBv1'

                        # Get SMB command byte
                        cmd = payload[smb_offset + 4] if len(payload) > smb_offset + 4 else 0
                        SMB_CMDS = {0x72: 'Negotiate', 0x73: 'Session Setup',
                                    0x75: 'Tree Connect', 0x25: 'Transaction'}
                        cmd_name = SMB_CMDS.get(cmd, f'Cmd 0x{cmd:02x}')

                        self._add_sensitive_data('SMBv1',
                            f'SMBv1 connection detected: {src} ↔ {dst} ({cmd_name}). '
                            f'SMBv1 is CRITICALLY insecure (EternalBlue, WannaCry). '
                            f'Disable SMBv1 immediately.',
                            src, dst, 445, ts, risk='CRITICAL')

                        self.security_findings.append({
                            'type': 'smb_v1',
                            'risk': 'CRITICAL',
                            'title': f'SMBv1 Active: {src} ↔ {dst}',
                            'description': ('SMBv1 is responsible for EternalBlue, WannaCry, '
                                'NotPetya, and many other major attacks. It should be disabled '
                                'on ALL systems.'),
                            'details': {
                                'hosts': [src, dst],
                                'command': cmd_name,
                            },
                            'recommendation': ('Disable SMBv1 on both hosts: '
                                'Windows: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol. '
                                'Linux: set "min protocol = SMB2" in smb.conf.'),
                        })

                elif header == smb2_marker:
                    self._smb_sessions[session_key] = 'SMBv2/3'
                    # SMBv2/3 is fine, just track it
        except Exception:
            pass

    # ─── FEATURE 4: HTTP Response Header Info Leakage ────────

    def _check_http_response_headers(self, pkt_info, payload, ts):
        """
        Analyze HTTP responses for server information disclosure.
        Headers like Server, X-Powered-By reveal exact software versions,
        making targeted attacks trivial.
        """
        if not HTTP_RESPONSE_RE.search(payload):
            return  # Not an HTTP response

        src = pkt_info.src_ip  # Server IP (this is a response)
        sport = pkt_info.src_port
        server_key = (src, sport)

        if server_key in self._http_servers:
            return  # Already reported this server

        findings = {}

        # Server header (e.g., "Apache/2.2.3 (CentOS)")
        match = HTTP_SERVER_RE.search(payload)
        if match:
            findings['server'] = match.group(1).decode('utf-8', errors='replace').strip()

        # X-Powered-By (e.g., "PHP/5.3.3", "ASP.NET")
        match = HTTP_POWERED_BY_RE.search(payload)
        if match:
            findings['x_powered_by'] = match.group(1).decode('utf-8', errors='replace').strip()

        # ASP.NET version
        match = HTTP_ASPNET_RE.search(payload)
        if match:
            findings['aspnet_version'] = match.group(1).decode('utf-8', errors='replace').strip()

        # PHP version
        match = HTTP_PHP_RE.search(payload)
        if match:
            findings['php_version'] = match.group(1).decode('utf-8', errors='replace').strip()

        # X-Generator
        match = HTTP_GENERATOR_RE.search(payload)
        if match:
            findings['generator'] = match.group(1).decode('utf-8', errors='replace').strip()

        if not findings:
            return

        self._http_servers[server_key] = findings

        # Check for particularly dangerous disclosures
        risk = 'LOW'
        details_parts = []

        for header, value in findings.items():
            details_parts.append(f"{header}: {value}")

            # Version numbers in server headers = exploitable info
            if re.search(r'\d+\.\d+', value):
                risk = 'MEDIUM'

            # Very old/known-vulnerable versions
            old_patterns = [
                (r'Apache/2\.[0-2]\.', 'Apache 2.0-2.2 (end-of-life, known vulnerabilities)'),
                (r'PHP/[45]\.', 'PHP 4.x or 5.x (end-of-life)'),
                (r'IIS/[5-7]\.', 'IIS 5-7 (very old, many vulnerabilities)'),
                (r'nginx/1\.[0-9]\.', 'nginx 1.0-1.9 (outdated)'),
                (r'OpenSSL/0\.', 'OpenSSL 0.x (Heartbleed era)'),
                (r'ASP\.NET.*[1-3]\.', 'Old ASP.NET version'),
            ]
            for pattern, desc in old_patterns:
                if re.search(pattern, value):
                    risk = 'HIGH'
                    details_parts.append(f"  ⚠ {desc}")

        details_str = '\n'.join(details_parts)

        self._add_sensitive_data('HTTP Server Info',
            f'Server at {src}:{sport} discloses: {details_str}',
            pkt_info.dst_ip, src, sport, ts, risk=risk)

        self.security_findings.append({
            'type': 'http_info_leak',
            'risk': risk,
            'title': f'HTTP Server Info Disclosure: {src}:{sport}',
            'description': f'Server reveals software details that help attackers target specific vulnerabilities.',
            'details': findings,
            'recommendation': ('Remove or minimize server headers. '
                'Apache: ServerTokens Prod, ServerSignature Off. '
                'nginx: server_tokens off. '
                'Remove X-Powered-By header entirely.'),
        })

    def _add_credential(self, protocol, cred_type, value, src, dst, port, ts,
                         extra=None, raw_length=0, raw_value=None, risk='CRITICAL'):
        """Record a found credential. value=masked for display, raw_value=full for storage."""
        finding = {
            'timestamp': ts,
            'time_str': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if ts else '',
            'protocol': protocol,
            'credential_type': cred_type,
            'value': value,  # Masked for display
            'source_ip': src,
            'destination_ip': dst,
            'port': port,
            'risk': risk,
            'extra': extra or {},
        }
        self.credentials_found.append(finding)
        self._add_timeline_event(ts, 'credential',
            f"CREDENTIAL EXPOSED: {protocol} {cred_type} found — "
            f"{src} → {dst}:{port}")
        logger.warning("Credential found: %s %s at %s:%d", protocol, cred_type, dst, port)

        # Persist to encrypted database
        if self.db:
            try:
                self.db.store_credential(
                    protocol, cred_type,
                    raw_value or value,  # Raw if available, masked otherwise
                    value,  # Masked for search display
                    src, dst, port, ts, extra=extra
                )
            except Exception as e:
                logger.debug("ForensicsDB credential store error: %s", e)

    def _add_sensitive_data(self, data_type, value, src, dst, port, ts, risk='HIGH'):
        """Record sensitive data found in transit."""
        finding = {
            'timestamp': ts,
            'time_str': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if ts else '',
            'data_type': data_type,
            'value': value,
            'source_ip': src,
            'destination_ip': dst,
            'port': port,
            'risk': risk,
        }
        self.sensitive_data.append(finding)
        self._add_timeline_event(ts, 'sensitive_data',
            f"SENSITIVE DATA: {data_type} detected in transit — "
            f"{src} → {dst}:{port}")

        # Persist to encrypted database
        if self.db:
            try:
                self.db.store_sensitive_data(data_type, value, src, dst, port, ts, risk)
            except Exception as e:
                logger.debug("ForensicsDB sensitive store error: %s", e)

    def _add_timeline_event(self, ts, event_type, description):
        """Add an event to the narrative timeline."""
        self.timeline.append({
            'timestamp': ts,
            'time_str': datetime.fromtimestamp(ts).strftime('%H:%M:%S') if ts else '',
            'type': event_type,
            'description': description,
        })

    # ─── Finalization / Report Generation ─────────────────────

    def finalize(self):
        """
        Call after all packets are processed.
        Classifies flows and generates the narrative report.
        """
        # Classify all flows
        flow_classifications = {}
        for key, flow in self.flows.items():
            if flow['packets'] < 3:
                continue
            avg_size = flow['bytes'] / max(flow['packets'], 1)
            total = flow['src_packets'] + flow['dst_packets']
            direction = flow['src_packets'] / max(total, 1)

            flow_type, desc = FlowClassifier.classify_flow({
                'dst_port': flow['dst_port'],
                'protocol': flow['protocol'],
                'avg_pkt_size': avg_size,
                'total_bytes': flow['bytes'],
                'direction_ratio': direction,
            })

            flow_classifications[key] = {
                **flow,
                'classification': flow_type,
                'classification_desc': desc,
                'avg_packet_size': round(avg_size, 0),
                'duration': flow['last_seen'] - flow['first_seen'],
            }
            # Remove non-serializable sets
            flow_classifications[key]['packet_sizes'] = []

        # Generate insecure service findings
        for key, svc in self.insecure_services.items():
            svc['src_ips'] = list(svc['src_ips'])[:20]
            self.security_findings.append({
                'type': 'insecure_protocol',
                'risk': svc['risk'],
                'title': f"Unencrypted {svc['service']} Service ({svc['ip']}:{svc['port']})",
                'description': svc['description'],
                'details': {
                    'server_ip': svc['ip'],
                    'port': svc['port'],
                    'service': svc['service'],
                    'packets_observed': svc['packet_count'],
                    'bytes_transferred': svc['bytes'],
                    'clients': svc['src_ips'],
                    'secure_alternative': svc['secure_alternative'],
                },
                'recommendation': f"Replace {svc['service']} with {svc['secure_alternative']}. "
                    f"All data on this service is visible to anyone on the network.",
            })

        return {
            'credentials': self.credentials_found,
            'sensitive_data': self.sensitive_data,
            'insecure_services': [
                {k: v for k, v in svc.items() if k != 'src_ips' or not isinstance(v, set)}
                for svc in self.insecure_services.values()
            ],
            'security_findings': self.security_findings,
            'flow_classifications': flow_classifications,
            'dhcp_devices': self.dhcp_devices,
            'http_servers': self._http_servers,
            'smb_sessions': self._smb_sessions,
            'timeline': sorted(self.timeline, key=lambda e: e.get('timestamp', 0)),
            'stats': {
                'packets_scanned': self.packets_scanned,
                'unencrypted_packets': self.unencrypted_packets,
                'credentials_found': len(self.credentials_found),
                'sensitive_data_found': len(self.sensitive_data),
                'insecure_services_found': len(self.insecure_services),
                'total_flows': len(self.flows),
                'classified_flows': len(flow_classifications),
                'dhcp_devices_found': len(self.dhcp_devices),
                'http_servers_profiled': len(self._http_servers),
                'smb_v1_sessions': sum(1 for v in self._smb_sessions.values() if v == 'SMBv1'),
            },
        }

    def generate_narrative(self):
        """
        Generate a plain-English narrative of what happened in the capture.
        Call after finalize().
        """
        lines = []
        lines.append("NETWORK ACTIVITY NARRATIVE")
        lines.append("=" * 50)
        lines.append("")

        # Overview
        total_flows = len(self.flows)
        total_bytes = sum(f['bytes'] for f in self.flows.values())
        timestamps = [f['first_seen'] for f in self.flows.values() if f['first_seen']]

        if timestamps:
            start = datetime.fromtimestamp(min(timestamps))
            end = datetime.fromtimestamp(max(timestamps))
            duration = max(timestamps) - min(timestamps)
            lines.append(f"This capture covers {duration:.0f} seconds of network activity "
                        f"from {start.strftime('%H:%M:%S')} to {end.strftime('%H:%M:%S')}.")
        lines.append(f"A total of {self.packets_scanned:,} packets ({total_bytes:,} bytes) "
                     f"were exchanged across {total_flows} conversations.")
        lines.append("")

        # Security summary
        cred_count = len(self.credentials_found)
        insecure_count = len(self.insecure_services)
        sensitive_count = len(self.sensitive_data)

        if cred_count or insecure_count or sensitive_count:
            lines.append("SECURITY CONCERNS")
            lines.append("-" * 30)
            if cred_count:
                lines.append(f"  *** {cred_count} CREDENTIALS FOUND IN PLAINTEXT ***")
                for cred in self.credentials_found[:10]:
                    lines.append(f"    - {cred['protocol']} {cred['credential_type']}: "
                               f"{cred['source_ip']} → {cred['destination_ip']}:{cred['port']}")
            if insecure_count:
                lines.append(f"  {insecure_count} unencrypted services detected:")
                for svc in self.insecure_services.values():
                    lines.append(f"    - {svc['service']} at {svc['ip']}:{svc['port']} "
                               f"({svc['packet_count']} packets)")
            if sensitive_count:
                lines.append(f"  {sensitive_count} sensitive data items in transit")
            lines.append("")
        else:
            lines.append("No credential exposure or insecure protocols detected.")
            lines.append("")

        # DHCP device inventory
        if self.dhcp_devices:
            lines.append("DEVICES DISCOVERED (via DHCP)")
            lines.append("-" * 30)
            for mac, dev in sorted(self.dhcp_devices.items()):
                hostname = dev.get('hostname', '') or 'unknown'
                ip = dev.get('ip', '') or '?'
                vendor = dev.get('vendor_class', '')
                lines.append(f"  {hostname:<25} {ip:<16} {mac}  {vendor}")
            lines.append("")

        # SMBv1 warnings
        smb1_sessions = [(k, v) for k, v in self._smb_sessions.items() if v == 'SMBv1']
        if smb1_sessions:
            lines.append("SMBv1 DETECTED (CRITICAL RISK)")
            lines.append("-" * 30)
            for (host1, host2), ver in smb1_sessions:
                lines.append(f"  {host1} ↔ {host2} — SMBv1 active (EternalBlue/WannaCry vulnerable)")
            lines.append("  ACTION: Disable SMBv1 on all affected systems immediately.")
            lines.append("")

        # HTTP server disclosures
        if self._http_servers:
            lines.append("HTTP SERVER INFORMATION DISCLOSURE")
            lines.append("-" * 30)
            for (ip, port), info in self._http_servers.items():
                lines.append(f"  {ip}:{port}")
                for header, value in info.items():
                    lines.append(f"    {header}: {value}")
            lines.append("  ACTION: Remove version information from server headers.")
            lines.append("")

        # Activity timeline (major events)
        if self.timeline:
            lines.append("KEY EVENTS")
            lines.append("-" * 30)
            # Deduplicate and limit
            seen = set()
            for event in sorted(self.timeline, key=lambda e: e.get('timestamp', 0))[:30]:
                desc = event['description']
                if desc not in seen:
                    seen.add(desc)
                    lines.append(f"  [{event['time_str']}] {desc}")
            lines.append("")

        # Flow summary by type
        type_counts = Counter()
        type_bytes = Counter()
        for flow in self.flows.values():
            if flow['packets'] >= 3:
                avg_size = flow['bytes'] / max(flow['packets'], 1)
                total = flow['src_packets'] + flow['dst_packets']
                direction = flow['src_packets'] / max(total, 1)
                ft, _ = FlowClassifier.classify_flow({
                    'dst_port': flow['dst_port'], 'protocol': flow['protocol'],
                    'avg_pkt_size': avg_size, 'total_bytes': flow['bytes'],
                    'direction_ratio': direction,
                })
                type_counts[ft] += 1
                type_bytes[ft] += flow['bytes']

        if type_counts:
            lines.append("TRAFFIC BREAKDOWN")
            lines.append("-" * 30)
            for flow_type, count in type_counts.most_common():
                bytes_val = type_bytes[flow_type]
                desc = FlowClassifier.SIGNATURES.get(flow_type, {}).get('desc', flow_type)
                lines.append(f"  {desc}: {count} flows, "
                           f"{self._format_bytes(bytes_val)}")

        return "\n".join(lines)

    # ─── Session Context Assessment ─────────────────────────

    def _assess_sensitive_data_context(self, pkt_info, payload, data_type):
        """
        Assess whether a sensitive data detection (credit card, SSN) is
        legitimate or a false positive by cross-referencing session context.

        Returns dict with:
            should_alert: bool
            risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
            confidence: str description
            reason: str explanation
        """
        dst_ip = pkt_info.dst_ip
        src_ip = pkt_info.src_ip
        port = pkt_info.dst_port
        reasons = []
        score = 5  # Start at 5 (suspicious), subtract for benign signals

        # ─── Check 1: Does this IP also have HTTPS traffic? ──────────
        # If we've seen TLS to the same IP, this HTTP is likely a redirect
        if dst_ip in self._tls_ips:
            score -= 3
            reasons.append(f"HTTPS also active to {dst_ip} — likely HTTP redirect")

        # ─── Check 2: Does this IP serve both port 80 and 443? ───────
        dst_ports = self._dual_port_ips.get(dst_ip, set())
        if 80 in dst_ports and 443 in dst_ports:
            score -= 2
            reasons.append(f"Server {dst_ip} uses both port 80 and 443 — redirect pattern")

        # ─── Check 3: Is this a known CDN/cloud IP? ──────────────────
        if dst_ip in self._cdn_ips:
            score -= 3
            reasons.append(f"Known CDN/cloud IP — serves legitimate websites")

        # ─── Check 4: Does a known domain resolve to this IP? ────────
        domains = self._ip_to_domains.get(dst_ip, set())
        if domains:
            domain_list = list(domains)[:3]
            reasons.append(f"Resolved domains: {', '.join(domain_list)}")
            # Check if any are known cloud/CDN
            from src.net_detect import KNOWN_CLOUD_DOMAINS
            for d in domains:
                for cloud in KNOWN_CLOUD_DOMAINS:
                    if d.endswith(cloud):
                        score -= 2
                        reasons.append(f"Domain {d} is a known service")
                        break

        # ─── Check 5: HTTP method context ────────────────────────────
        methods = self._http_methods.get((src_ip, dst_ip, port), set())
        has_card_fields = self._http_has_form_fields.get((src_ip, dst_ip), False)

        if data_type == 'credit_card':
            if 'POST' in methods and has_card_fields:
                score += 3
                reasons.append("POST request with card-related form fields — likely real submission")
            elif 'GET' in methods and 'POST' not in methods:
                score -= 2
                reasons.append("Only GET requests seen — card number likely in URL/cookie, not form")

        # ─── Check 6: Is this to a private/internal IP? ──────────────
        if (dst_ip.startswith('192.168.') or dst_ip.startswith('10.') or
            dst_ip.startswith('172.') or dst_ip == '127.0.0.1'):
            score -= 2
            reasons.append("Destination is internal/private IP")

        # ─── Check 7: Payload context ────────────────────────────────
        # Look for surrounding context that suggests this is NOT a real card
        context_clues_benign = [b'order_id', b'transaction_id', b'ref=',
                                b'tracking', b'confirmation', b'"id":', b'product_id']
        context_clues_real = [b'card_number', b'cc_num', b'cardnumber', b'pan=',
                              b'credit_card', b'payment_method', b'cvv']

        for clue in context_clues_benign:
            if clue in payload.lower():
                score -= 1
                reasons.append(f"Payload contains '{clue.decode()}' — likely ID field, not card")
                break

        for clue in context_clues_real:
            if clue in payload.lower():
                score += 2
                reasons.append(f"Payload contains '{clue.decode()}' — likely real card submission")
                break

        # ─── Verdict ─────────────────────────────────────────────────
        if score >= 5:
            return {'should_alert': True, 'risk': 'CRITICAL',
                    'confidence': 'HIGH — real submission likely',
                    'reason': '; '.join(reasons) or 'No benign signals found'}
        elif score >= 3:
            return {'should_alert': True, 'risk': 'HIGH',
                    'confidence': 'MEDIUM — suspicious but inconclusive',
                    'reason': '; '.join(reasons) or 'Some benign signals but not enough'}
        elif score >= 1:
            return {'should_alert': True, 'risk': 'MEDIUM',
                    'confidence': 'LOW — likely benign but flagged for review',
                    'reason': '; '.join(reasons) or 'Multiple benign signals'}
        else:
            return {'should_alert': False, 'risk': 'LOW',
                    'confidence': 'SUPPRESSED',
                    'reason': '; '.join(reasons) or 'Strong benign signals — likely false positive'}

    @staticmethod
    def _luhn_check(number_str):
        """Luhn algorithm to validate credit card numbers. Reduces false positives."""
        try:
            digits = [int(d) for d in number_str if d.isdigit()]
            if len(digits) < 13 or len(digits) > 19:
                return False
            checksum = 0
            reverse = digits[::-1]
            for i, d in enumerate(reverse):
                if i % 2 == 1:
                    d *= 2
                    if d > 9:
                        d -= 9
                checksum += d
            return checksum % 10 == 0
        except Exception:
            return False

    @staticmethod
    def _mask(value, show=3):
        """Mask a credential value for safe display."""
        if len(value) <= show:
            return '*' * len(value)
        return value[:show] + '*' * min(len(value) - show, 20)

    @staticmethod
    def _format_bytes(b):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if abs(b) < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"
