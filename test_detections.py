"""
NetSentinel Test Suite
======================
Simulates various attack patterns to verify every detection rule works.
Run this WHILE NetSentinel is monitoring to see alerts fire in real time.

Usage:
    python test_detections.py              # Run all tests
    python test_detections.py --test 3     # Run specific test
    python test_detections.py --list       # List all tests

IMPORTANT: Run this from a SECOND terminal while NetSentinel is monitoring.
           Some tests require Administrator privileges.
"""

import sys
import time
import socket
import struct
import argparse
import threading
from datetime import datetime

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, DNS, DNSQR, ARP, Ether, Raw,
        send, sendp, sr1, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not available. Some tests will use socket fallbacks.")

TARGET_IP = "127.0.0.1"
PAUSE_BETWEEN_TESTS = 3


def banner(test_num, name, description):
    print(f"\n{'='*70}")
    print(f"  TEST {test_num}: {name}")
    print(f"  {description}")
    print(f"{'='*70}")


def wait_for_alert(seconds=2):
    print(f"  [*] Waiting {seconds}s for NetSentinel to process...")
    time.sleep(seconds)
    print(f"  [+] Check NetSentinel Alerts tab for results\n")


class Tests:

    @staticmethod
    def test_1_port_scan():
        """PORT-SCAN: >15 unique ports from one IP in 60 seconds"""
        banner(1, "PORT SCAN", "Connecting to 25 different ports rapidly")
        ports = list(range(20, 45))
        connected = 0
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect_ex((TARGET_IP, port))
                s.close()
                connected += 1
                sys.stdout.write(f"\r  [*] Scanned {connected}/{len(ports)} ports...")
                sys.stdout.flush()
            except Exception:
                pass
            time.sleep(0.05)
        print(f"\n  [*] Scanned {connected} ports")
        print(f"  [!] Expected: [HIGH] Port Scan Detected")
        print(f"      Evidence: list of all {len(ports)} ports, scan rate, targets")
        wait_for_alert()

    @staticmethod
    def test_2_brute_force():
        """BRUTE-FORCE: >10 failed connections to same port in 30 seconds"""
        banner(2, "BRUTE FORCE", "Rapid failed connections to SSH port (22)")
        failures = 0
        for i in range(15):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect_ex((TARGET_IP, 22))
                s.close()
                failures += 1
            except Exception:
                failures += 1
            time.sleep(0.1)
        print(f"  [*] Sent {failures} rapid connection attempts to port 22")
        print(f"  [!] Expected: [HIGH] Potential Brute Force (SSH)")
        print(f"      Evidence: attempt count, rate, target service name")
        wait_for_alert()

    @staticmethod
    def test_3_suspicious_port():
        """BAD-PORT: connection to known malware ports"""
        banner(3, "SUSPICIOUS PORT", "Connecting to known malware ports")
        bad_ports = {4444: 'Metasploit', 1337: 'Backdoor', 31337: 'Back Orifice'}
        for port, name in bad_ports.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect_ex((TARGET_IP, port))
                s.close()
                print(f"  [*] Attempted connection to port {port} ({name})")
            except Exception:
                print(f"  [*] Attempted port {port} ({name}) - connection failed (expected)")
        print(f"  [!] Expected: [HIGH] Known Malicious Port (for each port)")
        print(f"      Evidence: port number, known usage, process name")
        wait_for_alert()

    @staticmethod
    def test_4_dns_tunneling():
        """DNS-TUNNEL: DNS query with subdomain > 60 chars or high entropy"""
        banner(4, "DNS TUNNELING", "Sending DNS queries with long encoded subdomains")
        import random, string
        long_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=80))
        tunnel_domain = f"{long_sub}.evil-tunnel-test.example.com"
        try:
            socket.getaddrinfo(tunnel_domain, None)
        except socket.gaierror:
            pass
        print(f"  [*] Sent DNS query: {tunnel_domain[:60]}...")
        medium_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=65))
        medium_domain = f"{medium_sub}.test-exfil.example.com"
        try:
            socket.getaddrinfo(medium_domain, None)
        except socket.gaierror:
            pass
        print(f"  [*] Sent DNS query: {medium_domain[:60]}...")
        print(f"  [!] Expected: [HIGH] Possible DNS Tunneling")
        print(f"      Evidence: full query, subdomain length, entropy score")
        wait_for_alert()

    @staticmethod
    def test_5_suspicious_tld():
        """DNS-BAD-TLD: DNS query to known high-abuse TLDs"""
        banner(5, "SUSPICIOUS TLD", "Querying domains with high-abuse TLDs")
        domains = [
            "definitely-not-malware.xyz",
            "free-prizes-here.tk",
            "totally-legit-site.top",
            "get-rich-quick.buzz",
        ]
        for domain in domains:
            try:
                socket.getaddrinfo(domain, None)
            except socket.gaierror:
                pass
            print(f"  [*] DNS query: {domain}")
            time.sleep(0.2)
        print(f"  [!] Expected: [MEDIUM] Suspicious TLD Query (for each)")
        print(f"      Evidence: TLD name, recent queries to same TLD")
        wait_for_alert()

    @staticmethod
    def test_6_dns_flood():
        """DNS-FLOOD: >50 DNS queries in 10 seconds"""
        banner(6, "DNS FLOOD", "Sending 65 DNS queries in rapid succession")
        import random, string
        count = 0
        for i in range(65):
            rand_sub = ''.join(random.choices(string.ascii_lowercase, k=8))
            try:
                socket.getaddrinfo(f"{rand_sub}.flood-test-{i}.example.com", None)
            except socket.gaierror:
                pass
            count += 1
            if count % 20 == 0:
                sys.stdout.write(f"\r  [*] Sent {count}/65 queries...")
                sys.stdout.flush()
        print(f"\n  [*] Sent {count} DNS queries rapidly")
        print(f"  [!] Expected: [MEDIUM] Excessive DNS Queries")
        print(f"      Evidence: query count, unique domains, sample list, rate")
        wait_for_alert()

    @staticmethod
    def test_7_syn_flood():
        """SYN-FLOOD: >50 SYN packets in 10 seconds (requires admin + scapy)"""
        banner(7, "SYN FLOOD", "Sending rapid SYN packets (requires admin + scapy)")
        if not SCAPY_AVAILABLE:
            print("  [SKIP] Scapy not available. Install with: pip install scapy")
            return
        try:
            count = 0
            for i in range(60):
                pkt = IP(dst=TARGET_IP) / TCP(sport=40000+i, dport=80, flags='S')
                send(pkt, verbose=False)
                count += 1
            print(f"  [*] Sent {count} SYN packets to port 80")
            print(f"  [!] Expected: [CRITICAL] SYN Flood Attack")
            print(f"      Evidence: SYN count, rate, target IP")
        except PermissionError:
            print("  [SKIP] Requires Administrator privileges")
        except Exception as e:
            print(f"  [SKIP] Error: {e}")
        wait_for_alert()

    @staticmethod
    def test_8_icmp_flood():
        """ICMP-FLOOD: >30 ICMP packets in 10 seconds (requires admin + scapy)"""
        banner(8, "ICMP FLOOD", "Sending rapid ping packets (requires admin + scapy)")
        if not SCAPY_AVAILABLE:
            print("  [SKIP] Scapy not available.")
            return
        try:
            count = 0
            for i in range(40):
                pkt = IP(dst=TARGET_IP) / ICMP()
                send(pkt, verbose=False)
                count += 1
            print(f"  [*] Sent {count} ICMP packets")
            print(f"  [!] Expected: [HIGH] ICMP Flood Detected")
        except PermissionError:
            print("  [SKIP] Requires Administrator privileges")
        except Exception as e:
            print(f"  [SKIP] Error: {e}")
        wait_for_alert()

    @staticmethod
    def test_9_large_transfer():
        """DATA-EXFIL: >100 MB sent to single destination"""
        banner(9, "LARGE DATA TRANSFER", "Sending 105 MB to localhost (safe)")
        receiver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            receiver.bind(('127.0.0.1', 59999))
            receiver.listen(1)
            receiver.settimeout(30)

            def drain():
                try:
                    conn, _ = receiver.accept()
                    while True:
                        data = conn.recv(65536)
                        if not data:
                            break
                    conn.close()
                except Exception:
                    pass

            t = threading.Thread(target=drain, daemon=True)
            t.start()

            sender = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sender.connect(('127.0.0.1', 59999))
            chunk = b'X' * 65536
            total_mb = 0
            while total_mb < 105:
                sender.send(chunk)
                total_mb += len(chunk) / (1024 * 1024)
                if int(total_mb) % 20 == 0:
                    sys.stdout.write(f"\r  [*] Sent {total_mb:.0f}/105 MB...")
                    sys.stdout.flush()
            sender.close()
            print(f"\n  [*] Sent {total_mb:.0f} MB to localhost")
            print(f"  [!] Expected: [HIGH] Large Data Transfer")
            print(f"      Evidence: MB transferred, destination, threshold, process")
        except Exception as e:
            print(f"  [SKIP] Error: {e}")
        finally:
            receiver.close()
        wait_for_alert(5)

    @staticmethod
    def test_10_ml_anomaly():
        """ML-ANOMALY: traffic pattern deviates from learned baseline"""
        banner(10, "ML ANOMALY", "Generating unusual traffic burst")
        print("  [*] Generating diverse, rapid connections across many ports...")
        import random
        for i in range(100):
            try:
                port = random.randint(1024, 65535)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect_ex((TARGET_IP, port))
                s.close()
            except Exception:
                pass
            if i % 5 == 0:
                rand = ''.join(random.choices('abcdefghijklmnop', k=10))
                try:
                    socket.getaddrinfo(f"{rand}.anomaly-test-{i}.example.com", None)
                except Exception:
                    pass
        print(f"  [*] Generated 100 connections + 20 DNS queries")
        print(f"  [!] Expected: [MEDIUM] ML Anomaly Detected")
        print(f"      Evidence: which features deviated, z-scores vs baseline,")
        print(f"                human-readable comparison, recommendations")
        print(f"  [*] Note: Requires trained model (200+ samples = ~17 min of monitoring)")
        wait_for_alert(8)

    @staticmethod
    def test_11_threat_intel():
        """Verify threat intelligence feeds are loaded and operational"""
        banner(11, "THREAT INTEL VERIFICATION",
               "Checking that threat feeds downloaded and loaded")
        print("  [*] This test verifies threat intelligence feeds loaded correctly.")
        print("  [*] Check the startup log output for lines like:")
        print("")
        print("      Threat Intel initialized: XXXX IPs, XX domains, XXX URLs from 6 feeds")
        print("")
        print("  [*] Feeds checked:")
        print("      - Feodo Tracker (botnet C2 IPs)")
        print("      - SSL Blacklist (malicious SSL certificate IPs)")
        print("      - URLhaus (malware distribution URLs/domains)")
        print("      - Emerging Threats (compromised IPs)")
        print("      - DShield (top attacker IPs last 24h)")
        print("      - blocklist.de (brute force / scanner IPs)")
        print("")
        print("  [*] Threat intel alerts fire automatically when any packet's")
        print("      source or destination IP matches a feed, or when a DNS query")
        print("      resolves a domain in the malware database.")
        print("")
        print("  [*] You can trigger a test by adding a known-bad IP to your")
        print("      blacklist in Settings and pinging it.")
        wait_for_alert()

    @staticmethod
    def test_12_blacklist():
        """BL-IP-DST: traffic to user-configured blacklisted IP"""
        banner(12, "BLACKLIST", "Testing user-configured IP blacklist")
        print("  [*] To test:")
        print("      1. Open NetSentinel > Settings tab")
        print("      2. Add '192.0.2.1' to Blacklisted IPs")
        print("      3. Click Save Settings")
        print("      4. Then this test sends traffic to that IP")
        print("")
        print("  [*] Attempting connection to 192.0.2.1...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect_ex(('192.0.2.1', 80))
            s.close()
        except Exception:
            pass
        print(f"  [!] Expected: [HIGH] Blacklisted Destination IP")
        print(f"      Evidence: blacklisted IP, direction, protocol, process")
        wait_for_alert()

    @staticmethod
    def test_13_network_detection():
        """Verify network auto-detection and smart whitelisting"""
        banner(13, "NETWORK AUTO-DETECTION", "Verifying gateway/DNS whitelisting")
        print("  [*] Check NetSentinel startup logs for:")
        print("")
        print("      Network environment detected:")
        print("        Gateways:    ['10.20.0.1']")
        print("        DNS servers: ['10.20.0.1', '8.8.8.8', ...]")
        print("        Local IPs:   ['10.20.0.x', ...]")
        print("        Auto-whitelisted IPs: XX")
        print("")
        print("  [*] Verification: browse the web for 60 seconds.")
        print("      You should NOT see 'Port Scan Detected' from your gateway.")
        print("      Threat intel checks STILL run on gateway traffic.")
        print("")
        print("  [*] Also auto-whitelisted:")
        print("      - Broadcast/multicast (255.255.255.255, 224.x.x.x)")
        print("      - Link-local (169.254.x.x)")
        print("      - mDNS (5353), SSDP (1900), LLMNR (5355), NetBIOS (137-139)")
        print("      - DHCP (67/68), DHCPv6 (546/547)")
        print("      - Known cloud domains (Microsoft, Google, Apple, etc.)")
        wait_for_alert()


ALL_TESTS = [
    (1,  "Port Scan Detection",        Tests.test_1_port_scan),
    (2,  "Brute Force Detection",       Tests.test_2_brute_force),
    (3,  "Suspicious Port Detection",   Tests.test_3_suspicious_port),
    (4,  "DNS Tunneling Detection",     Tests.test_4_dns_tunneling),
    (5,  "Suspicious TLD Detection",    Tests.test_5_suspicious_tld),
    (6,  "DNS Flood / DGA Detection",   Tests.test_6_dns_flood),
    (7,  "SYN Flood Detection*",        Tests.test_7_syn_flood),
    (8,  "ICMP Flood Detection*",       Tests.test_8_icmp_flood),
    (9,  "Large Data Exfiltration",     Tests.test_9_large_transfer),
    (10, "ML Anomaly Detection",        Tests.test_10_ml_anomaly),
    (11, "Threat Intel Verification",   Tests.test_11_threat_intel),
    (12, "Blacklist Detection",         Tests.test_12_blacklist),
    (13, "Network Auto-Detection",      Tests.test_13_network_detection),
]


def list_tests():
    print("\nAvailable Tests:")
    print("-" * 60)
    for num, name, _ in ALL_TESTS:
        marker = " *" if num in (7, 8) else ""
        print(f"  {num:>2}. {name}{marker}")
    print("\n  * = Requires Administrator + Scapy for raw packet tests")
    print(f"\nRun all:       python {sys.argv[0]}")
    print(f"Run specific:  python {sys.argv[0]} --test 3")
    print(f"Run range:     python {sys.argv[0]} --test 1-6")


def main():
    parser = argparse.ArgumentParser(description="NetSentinel Detection Test Suite")
    parser.add_argument('--test', type=str, help='Test number or range (e.g., 3 or 1-6)')
    parser.add_argument('--list', action='store_true', help='List all tests')
    parser.add_argument('--target', type=str, default='127.0.0.1', help='Target IP')
    parser.add_argument('--pause', type=int, default=3, help='Seconds between tests')
    args = parser.parse_args()

    if args.list:
        list_tests()
        return

    global TARGET_IP, PAUSE_BETWEEN_TESTS
    TARGET_IP = args.target
    PAUSE_BETWEEN_TESTS = args.pause

    print("""
 ===================================================================
   NETSENTINEL - Detection Test Suite
 ===================================================================

   Make sure NetSentinel is RUNNING and MONITORING before starting.
   Watch the Alerts tab in real time as each test fires.

   Target: {}
   Tests marked * require Administrator + Scapy for raw packets.
 ===================================================================
    """.format(TARGET_IP))

    if args.test:
        if '-' in args.test:
            start, end = args.test.split('-')
            test_nums = list(range(int(start), int(end) + 1))
        else:
            test_nums = [int(args.test)]
    else:
        input("Press Enter to start all tests (Ctrl+C to cancel)...")
        test_nums = list(range(1, len(ALL_TESTS) + 1))

    passed = 0
    skipped = 0
    for num, name, func in ALL_TESTS:
        if num in test_nums:
            try:
                func()
                passed += 1
            except KeyboardInterrupt:
                print("\n\n  [!] Interrupted by user")
                break
            except Exception as e:
                print(f"  [ERROR] Test {num} failed: {e}")
                skipped += 1
            time.sleep(PAUSE_BETWEEN_TESTS)

    print(f"\n{'='*70}")
    print(f"  SUMMARY: {passed} tests run, {skipped} skipped")
    print(f"{'='*70}")
    print(f"  Check NetSentinel Alerts tab to verify each test generated")
    print(f"  the expected alert(s) with detailed evidence.")
    print(f"")
    print(f"  If ML Anomaly (test 10) didn't fire, let NetSentinel build")
    print(f"  a baseline first (~17 min), then re-run: python {sys.argv[0]} --test 10")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
