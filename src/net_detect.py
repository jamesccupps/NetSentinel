"""
Network Environment Auto-Detection
====================================
Automatically detects local network infrastructure and builds a smart
whitelist to reduce false positives from normal network activity.

Detects and whitelists:
- Default gateway / router
- DNS servers (system-configured)
- DHCP servers
- Local machine's own IPs
- Broadcast / multicast addresses
- Known cloud infrastructure (CDNs, Microsoft, Apple, Google)
- Common Windows services (SSDP, LLMNR, mDNS, NetBIOS)

Also detects common noisy traffic patterns and adjusts alert thresholds.
"""

import os
import re
import socket
import logging
import subprocess
import ipaddress
from collections import defaultdict

logger = logging.getLogger("NetSentinel.NetDetect")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


def detect_default_gateway():
    """Detect the default gateway IP address."""
    gateways = []

    # Method 1: psutil + route table
    if PSUTIL_AVAILABLE:
        try:
            # Parse 'route print' on Windows
            result = subprocess.run(
                ['route', 'print', '0.0.0.0'],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            )
            for line in result.stdout.split('\n'):
                line = line.strip()
                if '0.0.0.0' in line:
                    parts = line.split()
                    for part in parts:
                        try:
                            addr = ipaddress.ip_address(part)
                            if not addr.is_unspecified and not addr.is_loopback:
                                gateways.append(str(addr))
                        except ValueError:
                            continue
        except Exception as e:
            logger.debug("route print failed: %s", e)

    # Method 2: ipconfig on Windows
    try:
        result = subprocess.run(
            ['ipconfig'],
            capture_output=True, text=True, timeout=5,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        for line in result.stdout.split('\n'):
            if 'Default Gateway' in line or 'Standardgateway' in line:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    gw = match.group(1)
                    if gw != '0.0.0.0':
                        gateways.append(gw)
    except Exception as e:
        logger.debug("ipconfig failed: %s", e)

    # Method 3: netifaces-style using socket
    if not gateways:
        try:
            # Connect to a public IP to find which interface is default
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            # Guess gateway as .1 on the subnet
            parts = local_ip.split('.')
            parts[3] = '1'
            gateways.append('.'.join(parts))
        except Exception:
            pass

    # Deduplicate
    seen = set()
    unique = []
    for gw in gateways:
        if gw not in seen and gw != '0.0.0.0':
            seen.add(gw)
            unique.append(gw)

    return unique


def detect_dns_servers():
    """Detect configured DNS servers."""
    dns_servers = []

    # Method 1: Parse ipconfig /all
    try:
        result = subprocess.run(
            ['ipconfig', '/all'],
            capture_output=True, text=True, timeout=5,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        in_dns_section = False
        for line in result.stdout.split('\n'):
            if 'DNS Servers' in line or 'DNS-Server' in line:
                in_dns_section = True
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    dns_servers.append(match.group(1))
            elif in_dns_section:
                match = re.search(r'^\s+(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    dns_servers.append(match.group(1))
                else:
                    in_dns_section = False
    except Exception as e:
        logger.debug("DNS detection failed: %s", e)

    # Always include common public DNS that shouldn't be flagged
    well_known_dns = [
        '8.8.8.8', '8.8.4.4',           # Google
        '1.1.1.1', '1.0.0.1',           # Cloudflare
        '9.9.9.9', '149.112.112.112',   # Quad9
        '208.67.222.222', '208.67.220.220',  # OpenDNS
    ]

    return list(set(dns_servers + well_known_dns))


def detect_local_ips():
    """Detect all IP addresses assigned to this machine."""
    local_ips = ['127.0.0.1', '::1']

    if PSUTIL_AVAILABLE:
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family in (socket.AF_INET, socket.AF_INET6):
                        local_ips.append(addr.address)
        except Exception:
            pass

    # Fallback
    try:
        hostname = socket.gethostname()
        for ip in socket.getaddrinfo(hostname, None):
            local_ips.append(ip[4][0])
    except Exception:
        pass

    return list(set(local_ips))


def detect_dhcp_server():
    """Try to detect the DHCP server IP."""
    dhcp_servers = []
    try:
        result = subprocess.run(
            ['ipconfig', '/all'],
            capture_output=True, text=True, timeout=5,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        for line in result.stdout.split('\n'):
            if 'DHCP Server' in line or 'DHCP-Server' in line:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    dhcp_servers.append(match.group(1))
    except Exception:
        pass
    return dhcp_servers


def get_local_subnet():
    """Get the local subnet in CIDR notation."""
    if PSUTIL_AVAILABLE:
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.netmask:
                        ip = addr.address
                        if ip.startswith('127.') or ip.startswith('169.254.'):
                            continue
                        net = ipaddress.IPv4Network(f"{ip}/{addr.netmask}", strict=False)
                        return str(net)
        except Exception:
            pass
    return None


# Special addresses that should never trigger alerts
SPECIAL_ADDRESSES = {
    # Broadcast
    '255.255.255.255',
    '0.0.0.0',
    # IPv6
    '::',
    '::1',
    'ff02::1',          # All nodes multicast
    'ff02::2',          # All routers multicast
    'ff02::fb',         # mDNS multicast
    'ff02::1:3',        # LLMNR multicast
}

# Multicast ranges (224.0.0.0/4)
def is_multicast(ip):
    try:
        return ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False

# Link-local (169.254.x.x)
def is_link_local(ip):
    try:
        return ipaddress.ip_address(ip).is_link_local
    except ValueError:
        return False

# Well-known noisy but benign ports
NOISY_BENIGN_PORTS = {
    5353,    # mDNS (Bonjour, Avahi)
    1900,    # SSDP / UPnP discovery
    3702,    # WS-Discovery
    5355,    # LLMNR (Link-Local Multicast Name Resolution)
    137,     # NetBIOS Name Service
    138,     # NetBIOS Datagram
    139,     # NetBIOS Session
    547,     # DHCPv6
    546,     # DHCPv6 client
    67,      # DHCP server
    68,      # DHCP client
    10001,   # UniFi device discovery / inform
    8008,    # Chromecast HTTP control API
    8443,    # UniFi controller HTTPS
}

# Known cloud/CDN domains — first-party services from major providers.
# These are used by the threat intel engine to differentiate between
# "your connection to docs.google.com hit a flagged GCP IP" (false positive)
# vs "unknown-malware.appspot.com is hosted on GCP" (real threat).
#
# NOTE: Cloud HOSTING domains (appspot.com, azurewebsites.net, herokuapp.com)
# are listed separately as CLOUD_HOSTING_DOMAINS — they get flagged at reduced
# severity because legitimate and malicious sites both live there.

KNOWN_CLOUD_DOMAINS = {
    # ─── Google ──────────────────────────────────────────────
    'google.com', 'googleapis.com', 'gstatic.com', 'googlevideo.com',
    'youtube.com', 'ytimg.com', 'googleusercontent.com', 'ggpht.com',
    'google-analytics.com', 'googleadservices.com', 'googlesyndication.com',
    'googletagmanager.com', 'gvt1.com', 'gvt2.com', 'doubleclick.net',
    'gmail.com', 'android.com', 'chromium.org', 'withgoogle.com',
    'googleplex.com', 'google.co', 'googledomains.com', 'recaptcha.net',

    # ─── Microsoft ───────────────────────────────────────────
    'microsoft.com', 'windows.com', 'windowsupdate.com', 'msftconnecttest.com',
    'office.com', 'office365.com', 'live.com', 'bing.com', 'msn.com',
    'outlook.com', 'hotmail.com', 'skype.com', 'microsoftonline.com',
    'azure.com', 'azure.net', 'azureedge.net', 'msedge.net',
    'msauth.net', 'msftauth.net', 'visualstudio.com', 'microsoft365.com',
    'onenote.com', 'sharepoint.com', 'onedrive.com', 'live.net',
    'windows.net', 'trafficmanager.net', 'msecnd.net', 'aspnetcdn.com',
    'xbox.com', 'xboxlive.com', 'linkedin.com', 'licdn.com',

    # ─── Apple ───────────────────────────────────────────────
    'apple.com', 'icloud.com', 'mzstatic.com', 'apple-dns.net',
    'cdn-apple.com', 'itunes.com', 'aaplimg.com', 'apple.news',
    'icloud-content.com', 'me.com', 'swcdn.apple.com',

    # ─── Amazon / AWS ────────────────────────────────────────
    'amazon.com', 'amazonaws.com', 'cloudfront.net', 'amazonws.com',
    'awsstatic.com', 'amazon-adsystem.com', 'media-amazon.com',
    'ssl-images-amazon.com', 'images-amazon.com', 'amazon.co.uk',
    'primevideo.com', 'twitch.tv', 'twitchcdn.net', 'twitchsvc.net',
    'alexa.com',

    # ─── CDN / Infrastructure ────────────────────────────────
    'akamai.net', 'akamaized.net', 'akamaiedge.net', 'akamaitechnologies.com',
    'cloudflare.com', 'cloudflare-dns.com', 'cloudflareinsights.com',
    'fastly.net', 'fastlylb.net', 'edgecastcdn.net', 'stackpathdns.com',
    'limelight.com', 'llnwd.net', 'edgekey.net', 'edgesuite.net',
    'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',

    # ─── Social Media ────────────────────────────────────────
    'facebook.com', 'fbcdn.net', 'fb.com', 'instagram.com', 'cdninstagram.com',
    'whatsapp.com', 'whatsapp.net',
    'twitter.com', 'x.com', 'twimg.com', 't.co',
    'tiktok.com', 'tiktokcdn.com', 'byteoversea.com', 'musical.ly',
    'snapchat.com', 'snapkit.co', 'sc-cdn.net',
    'pinterest.com', 'pinimg.com',
    'reddit.com', 'redd.it', 'redditstatic.com', 'redditmedia.com',
    'tumblr.com',

    # ─── Communication / Collaboration ───────────────────────
    'discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net',
    'slack.com', 'slack-edge.com', 'slack-imgs.com',
    'zoom.us', 'zoom.com', 'zoomgov.com',
    'teams.microsoft.com', 'teams.cdn.office.net',
    'webex.com', 'wbx2.com',
    'signal.org', 'whispersystems.org',
    'telegram.org', 't.me',

    # ─── Cloud Storage / Productivity ────────────────────────
    'dropbox.com', 'dropboxstatic.com', 'dropboxusercontent.com',
    'box.com', 'boxcdn.net',
    'notion.so', 'notion.com',
    'evernote.com',
    'airtable.com',

    # ─── Streaming / Media ───────────────────────────────────
    'netflix.com', 'nflxvideo.net', 'nflximg.net', 'nflxext.com', 'nflxso.net',
    'spotify.com', 'scdn.co', 'spotifycdn.com', 'audio-ak-spotify-com.akamaized.net',
    'hulu.com', 'hulustream.com',
    'disneyplus.com', 'disney-plus.net', 'bamgrid.com', 'dssott.com',
    'hbomax.com', 'hbonow.com',
    'pandora.com', 'soundcloud.com', 'sndcdn.com',
    'vimeo.com', 'vimeocdn.com',
    'dailymotion.com',

    # ─── Dev / Tech ──────────────────────────────────────────
    'github.com', 'githubusercontent.com', 'githubassets.com', 'github.io',
    'gitlab.com', 'bitbucket.org', 'atlassian.com', 'atlassian.net',
    'jira.com', 'confluence.com', 'trello.com',
    'stackoverflow.com', 'stackexchange.com', 'sstatic.net',
    'npmjs.com', 'npmjs.org', 'yarnpkg.com',
    'pypi.org', 'pythonhosted.org',
    'docker.com', 'docker.io',
    'vercel.com', 'vercel.app', 'now.sh',
    'netlify.com', 'netlify.app',
    'heroku.com',
    'digitalocean.com',

    # ─── Gaming ──────────────────────────────────────────────
    'steam.com', 'steampowered.com', 'steamcontent.com', 'steamstatic.com',
    'epicgames.com', 'unrealengine.com', 'epicgames.dev',
    'riotgames.com', 'riotcdn.net',
    'blizzard.com', 'battle.net', 'blzstatic.cn',
    'ea.com', 'origin.com',
    'playstation.com', 'playstation.net', 'sonyentertainmentnetwork.com',
    'nintendo.com', 'nintendo.net',
    'ubisoft.com',
    'unity3d.com', 'unity.com',
    'roblox.com', 'rbxcdn.com',

    # ─── Business / SaaS ────────────────────────────────────
    'salesforce.com', 'force.com', 'sfdc.net',
    'zendesk.com', 'zdassets.com',
    'hubspot.com', 'hsforms.com', 'hubspotusercontent.com',
    'shopify.com', 'myshopify.com', 'shopifycdn.com',
    'stripe.com', 'stripe.network',
    'paypal.com', 'paypalobjects.com',
    'squarespace.com', 'sqspcdn.com',
    'wix.com', 'wixstatic.com',
    'wordpress.com', 'wp.com',
    'godaddy.com',
    'cloudflare.com',
    'okta.com', 'oktacdn.com',
    'auth0.com',
    'sentry.io',
    'datadog.com', 'datadoghq.com',
    'newrelic.com', 'nr-data.net',
    'pagerduty.com',

    # ─── Security / Anti-virus (don't flag your own AV) ─────
    'norton.com', 'symantec.com', 'nortonlifelock.com',
    'mcafee.com',
    'avast.com', 'avcdn.net',
    'avg.com',
    'kaspersky.com',
    'bitdefender.com', 'bitdefender.net',
    'malwarebytes.com',
    'sophos.com',
    'eset.com',
    'trendmicro.com',
    'crowdstrike.com',
    'windowsdefender.com',

    # ─── Ad / Analytics (noisy but not malicious) ────────────
    'googlesyndication.com', 'googleadservices.com',
    'doubleclick.net', 'google-analytics.com',
    'googletagmanager.com', 'googletagservices.com',
    'facebook.net', 'fbsbx.com',
    'hotjar.com', 'hotjar.io',
    'segment.com', 'segment.io',
    'mixpanel.com',
    'amplitude.com',
    'fullstory.com',
    'crazyegg.com',
    'optimizely.com',

    # ─── DNS providers ───────────────────────────────────────
    'opendns.com',
    'quad9.net',
}

# Cloud HOSTING domains — anyone can deploy sites here.
# Legitimate AND malicious. Used to add context to alerts, not to whitelist.
CLOUD_HOSTING_DOMAINS = {
    'appspot.com',           # Google App Engine
    'web.app',               # Firebase Hosting
    'firebaseapp.com',       # Firebase
    'cloudfunctions.net',    # Google Cloud Functions
    'run.app',               # Google Cloud Run
    'azurewebsites.net',     # Azure App Service
    'cloudapp.net',          # Azure VMs
    'azurefd.net',           # Azure Front Door
    'blob.core.windows.net', # Azure Blob Storage
    'herokuapp.com',         # Heroku
    'netlify.app',           # Netlify
    'vercel.app',            # Vercel
    'pages.dev',             # Cloudflare Pages
    'workers.dev',           # Cloudflare Workers
    'r2.dev',                # Cloudflare R2
    'onrender.com',          # Render
    'fly.dev',               # Fly.io
    'railway.app',           # Railway
    'deno.dev',              # Deno Deploy
    's3.amazonaws.com',      # AWS S3
    'execute-api.amazonaws.com',  # AWS API Gateway
    'elasticbeanstalk.com',  # AWS Elastic Beanstalk
    'amplifyapp.com',        # AWS Amplify
    'github.io',             # GitHub Pages
    'gitlab.io',             # GitLab Pages
    'bitbucket.io',          # Bitbucket Pages
    'blogspot.com',          # Google Blogger
    'wordpress.com',         # WordPress.com hosting
    'wixsite.com',           # Wix hosted sites
    'squarespace.com',       # Squarespace
    'myshopify.com',         # Shopify stores
    'webflow.io',            # Webflow
    'carrd.co',              # Carrd
    'notion.site',           # Notion public pages
}


class NetworkEnvironment:
    """
    Detects and stores information about the local network environment.
    Provides smart whitelisting to reduce false positives.
    """

    def __init__(self):
        self.gateways = []
        self.dns_servers = []
        self.local_ips = []
        self.dhcp_servers = []
        self.local_subnet = None
        self.auto_whitelist_ips = set()
        self.auto_whitelist_ports = set()
        self.detected = False
        # Pre-built suffix sets for O(k) domain lookups (k = label count)
        self._cloud_domain_set = set()
        self._hosting_domain_set = set()
        # Known devices registry
        self.known_devices = {}       # {ip: device_info_dict}
        self.known_device_macs = {}   # {mac_lower: device_info_dict}
        self.known_device_ips = set()

    def detect(self):
        """Run full network environment detection."""
        logger.info("Detecting network environment...")

        self.gateways = detect_default_gateway()
        self.dns_servers = detect_dns_servers()
        self.local_ips = detect_local_ips()
        self.dhcp_servers = detect_dhcp_server()
        self.local_subnet = get_local_subnet()

        # Build auto-whitelist
        self.auto_whitelist_ips = set()
        self.auto_whitelist_ips.update(self.gateways)
        self.auto_whitelist_ips.update(self.dns_servers)
        self.auto_whitelist_ips.update(self.local_ips)
        self.auto_whitelist_ips.update(self.dhcp_servers)
        self.auto_whitelist_ips.update(SPECIAL_ADDRESSES)

        self.auto_whitelist_ports = set(NOISY_BENIGN_PORTS)

        # Pre-build suffix sets for fast domain matching
        # Instead of O(n) linear scan per lookup, we check O(k) suffixes
        self._cloud_domain_set = set(KNOWN_CLOUD_DOMAINS)
        self._hosting_domain_set = set(CLOUD_HOSTING_DOMAINS)

        self.detected = True

        logger.info("Network environment detected:")
        logger.info("  Gateways:    %s", self.gateways)
        logger.info("  DNS servers: %s", self.dns_servers[:5])
        logger.info("  Local IPs:   %s", self.local_ips[:5])
        logger.info("  DHCP:        %s", self.dhcp_servers)
        logger.info("  Subnet:      %s", self.local_subnet)
        logger.info("  Auto-whitelisted IPs: %d", len(self.auto_whitelist_ips))

        return self

    def should_skip_ids(self, src_ip, dst_ip, dst_port=0, protocol=""):
        """
        Check if a packet should be excluded from IDS heuristic rules
        (port scan, brute force, etc.) based on network environment.

        Note: This does NOT skip threat intel checks — if your gateway IP
        shows up in a botnet feed, you still want to know about that.
        """
        # Always skip multicast and broadcast
        if is_multicast(src_ip) or is_multicast(dst_ip):
            return True
        if src_ip in SPECIAL_ADDRESSES or dst_ip in SPECIAL_ADDRESSES:
            return True
        if is_link_local(src_ip) or is_link_local(dst_ip):
            return True

        # Skip traffic from/to gateway and DNS servers for heuristic rules
        if src_ip in self.auto_whitelist_ips or dst_ip in self.auto_whitelist_ips:
            # Exception: still check for truly suspicious stuff even from gateway
            # like known malware ports
            if dst_port in {4444, 5555, 6666, 1337, 31337, 12345}:
                return False
            return True

        # Skip noisy benign discovery protocols
        if dst_port in NOISY_BENIGN_PORTS:
            return True

        return False

    @staticmethod
    def _domain_in_suffix_set(domain, suffix_set):
        """Check if domain matches any entry in suffix_set in O(k) time.
        Walks up the label hierarchy: for 'sub.example.com' checks
        'sub.example.com', 'example.com', 'com' against the set.
        """
        if not domain:
            return False
        domain = domain.lower().strip('.')
        # Check exact match first
        if domain in suffix_set:
            return True
        # Walk up labels: 'a.b.c.com' → check 'b.c.com' → 'c.com' → 'com'
        idx = 0
        while True:
            idx = domain.find('.', idx)
            if idx == -1:
                break
            idx += 1  # skip the dot
            if domain[idx:] in suffix_set:
                return True
        return False

    def is_known_cloud_domain(self, domain):
        """Check if a domain belongs to a known first-party cloud/CDN service."""
        return self._domain_in_suffix_set(domain, self._cloud_domain_set)

    def is_cloud_hosting_domain(self, domain):
        """
        Check if a domain is on a cloud hosting platform (anyone can deploy here).
        These need extra scrutiny — legitimate AND malicious sites use them.
        """
        return self._domain_in_suffix_set(domain, self._hosting_domain_set)

    def load_known_devices(self, devices_list):
        """
        Load known device registry from config.
        Each device: {"name": "...", "ip": "...", "mac": "...", "type": "...",
                       "expected_ports": [...], "expected_protocols": [...]}

        Known devices get auto-whitelisted for heuristic rules (not threat intel).
        """
        for dev in devices_list:
            if dev.get('ip'):
                self.known_devices[dev['ip']] = dev
                self.known_device_ips.add(dev['ip'])
                # Add to auto-whitelist so heuristic rules skip them
                self.auto_whitelist_ips.add(dev['ip'])
            if dev.get('mac'):
                self.known_device_macs[dev['mac'].lower()] = dev

        if devices_list:
            logger.info("Loaded %d known devices into network environment: %s",
                        len(devices_list),
                        ', '.join(d.get('name', d.get('ip', '?')) for d in devices_list))

    def get_device_name(self, ip=None, mac=None):
        """Look up a known device by IP or MAC. Returns name or None."""
        if ip and ip in self.known_devices:
            return self.known_devices[ip].get('name')
        if mac and mac.lower() in self.known_device_macs:
            return self.known_device_macs[mac.lower()].get('name')
        return None

    def get_summary(self):
        """Return a summary dict for display in GUI."""
        return {
            'gateways': self.gateways,
            'dns_servers': self.dns_servers[:8],
            'local_ips': [ip for ip in self.local_ips
                          if not ip.startswith('127.') and ip != '::1'][:5],
            'dhcp_servers': self.dhcp_servers,
            'local_subnet': self.local_subnet,
            'auto_whitelisted_ips': len(self.auto_whitelist_ips),
            'auto_whitelisted_ports': sorted(self.auto_whitelist_ports),
            'known_devices': [
                {'name': d.get('name', '?'), 'ip': d.get('ip', '?'), 'type': d.get('type', '?')}
                for d in self.known_devices.values()
            ],
            'detected': self.detected,
        }
