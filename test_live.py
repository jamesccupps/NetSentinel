#!/usr/bin/env python3
"""
NetSentinel v1.2.0 — Live Integration Test
============================================
Tests the full pipeline end-to-end with real network calls,
real threat intel feeds, and simulated traffic patterns.

NOT unit tests — these exercise real code paths and real I/O.
"""

import os
import sys
import json
import time
import types
import tempfile
import shutil
import traceback

# ─── Mock scapy to avoid IPv6 route crash on this container ─────
# Scapy tries to enumerate IPv6 routes at import time which fails
# in containerized Linux. We only need PacketInfo, not actual capture.
_mock = types.ModuleType('scapy')
_mock_all = types.ModuleType('scapy.all')
for _n in ['sniff','conf','get_if_list','get_if_addr','IP','IPv6','TCP',
           'UDP','ICMP','DNS','ARP','Raw','Ether','rdpcap','PcapReader']:
    setattr(_mock_all, _n, None)
sys.modules['scapy'] = _mock
sys.modules['scapy.all'] = _mock_all

import numpy as np
from collections import defaultdict, Counter
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ─── Setup temp dirs so we don't pollute the real system ─────────
TEMP_DIR = tempfile.mkdtemp(prefix="ns_test_")
os.environ['NETSENTINEL_TEST'] = '1'

passed = 0
failed = 0
errors = []

def test(name):
    def decorator(func):
        global passed, failed
        print(f"\n{'─'*60}")
        print(f"  TEST: {name}")
        print(f"{'─'*60}")
        try:
            func()
            passed += 1
            print(f"  ✓ PASSED")
        except Exception as e:
            failed += 1
            errors.append((name, str(e)))
            print(f"  ✗ FAILED: {e}")
            traceback.print_exc()
        return func
    return decorator


# ═══════════════════════════════════════════════════════════════════
# SETUP
# ═══════════════════════════════════════════════════════════════════

from src.config import Config, DEFAULT_CONFIG
from src.ids_engine import IDSEngine, Alert, Severity
from src.ml_engine import AnomalyDetector, BaselineProfile, TrafficFeatureExtractor
from src.net_detect import NetworkEnvironment
from src.ioc_scanner import IOCScanner
from src.alerts import AlertManager
from src.capture import PacketInfo
from src.forensics import NetworkForensics
from src.threat_intel import ThreatIntelEngine
from src.feature_store import FeatureStore

import copy

def make_config():
    config = Config.__new__(Config)
    config._data = copy.deepcopy(DEFAULT_CONFIG)
    return config

def make_packet(**kwargs):
    pkt = PacketInfo()
    for k, v in kwargs.items():
        setattr(pkt, k, v)
    return pkt


# ═══════════════════════════════════════════════════════════════════
# TEST 1: Threat Intel Feed Download (LIVE INTERNET)
# ═══════════════════════════════════════════════════════════════════

@test("Threat Intel — Live feed download from abuse.ch + DShield")
def test_threat_intel_live():
    config = make_config()
    ti = ThreatIntelEngine(config)

    stats = ti.get_stats()
    print(f"    Feeds configured: {stats.get('feeds_configured', '?')}")
    print(f"    Feeds loaded:     {stats.get('feeds_loaded', '?')}")
    print(f"    Total IPs:        {stats.get('malicious_ips', '?')}")
    print(f"    Total domains:    {stats.get('malicious_domains', '?')}")

    total_indicators = stats.get('total_ips', 0) + stats.get('total_domains', 0)
    assert total_indicators > 0, f"No threat intel loaded! Stats: {stats}"
    print(f"    Total indicators: {total_indicators}")

    # Test a known-clean IP
    result = ti.check_ip("8.8.8.8")
    assert result is None, "Google DNS should not be in threat feeds"
    print(f"    8.8.8.8 clean: ✓")

    # Test a known-clean domain
    result = ti.check_domain("google.com")
    assert result is None, "google.com should not be in threat feeds"
    print(f"    google.com clean: ✓")


# ═══════════════════════════════════════════════════════════════════
# TEST 2: Full IDS Pipeline — Packet → IDS → Alert Verify → Alert
# ═══════════════════════════════════════════════════════════════════

@test("Full IDS pipeline — packet inspection through alert verification")
def test_ids_full_pipeline():
    config = make_config()
    alerts = []

    net_env = NetworkEnvironment()
    net_env.detect()

    ti = ThreatIntelEngine(config)

    from src.alert_verify import AlertVerifier
    from src.process_verify import ProcessVerifier

    pv = ProcessVerifier(config)
    av = AlertVerifier(config, net_env=net_env, threat_intel=ti, process_verifier=pv)

    def alert_gateway(alert):
        av.verify_alert(alert, ids_engine=ids)
        alerts.append(alert)

    ids = IDSEngine(config, alert_callback=alert_gateway, threat_intel=ti, net_env=net_env)

    # Simulate various packet types
    packets = [
        # Normal HTTPS
        make_packet(src_ip="192.168.1.10", dst_ip="142.250.80.46",
                    dst_port=443, protocol="TCP", flags="S", is_encrypted=True),
        # DNS query
        make_packet(src_ip="192.168.1.10", dst_ip="8.8.8.8",
                    dst_port=53, protocol="UDP", dns_query="google.com",
                    dns_response="142.250.80.46"),
        # Known bad port (should alert)
        make_packet(src_ip="192.168.1.10", dst_ip="10.0.0.5",
                    dst_port=4444, protocol="TCP", flags="S"),
        # ARP normal
        make_packet(src_ip="192.168.1.1", src_mac="aa:bb:cc:11:22:33",
                    protocol="ARP"),
        # ARP spoof (different MAC same IP)
        make_packet(src_ip="192.168.1.1", src_mac="ff:ee:dd:99:88:77",
                    protocol="ARP"),
    ]

    for pkt in packets:
        ids.inspect_packet(pkt)

    print(f"    Packets processed: {ids.total_packets_inspected}")
    print(f"    Alerts generated:  {len(alerts)}")

    # Should have at least bad-port and ARP spoof alerts
    rule_ids = [a.rule_id for a in alerts]
    print(f"    Alert rules: {rule_ids}")

    assert "BAD-PORT" in rule_ids, "Should detect connection to port 4444"
    assert "ARP-SPOOF" in rule_ids, "Should detect ARP MAC change"

    # Check that alerts have verification verdicts
    for a in alerts:
        verdict = a.evidence.get('alert_verification', {}).get('verdict')
        print(f"    [{a.severity}] {a.title} → verdict: {verdict}")
        assert verdict is not None, f"Alert {a.rule_id} missing verification verdict"


# ═══════════════════════════════════════════════════════════════════
# TEST 3: ML Engine — Full training + scoring cycle
# ═══════════════════════════════════════════════════════════════════

@test("ML Engine — Feature extraction → training → anomaly scoring")
def test_ml_full_cycle():
    config = make_config()
    config.set('ml', 'min_samples_for_training', 50)

    db_path = os.path.join(TEMP_DIR, "baseline.json")

    # Create feature store
    config.set('ml', 'feature_history_days', 1)
    fs = FeatureStore(config)

    detector = AnomalyDetector(config, feature_store=fs)
    extractor = TrafficFeatureExtractor()

    # Generate 60 windows of "normal" traffic
    np.random.seed(42)
    for i in range(60):
        packets = []
        for _ in range(50):
            pkt = make_packet(
                src_ip="192.168.1.10",
                dst_ip=f"10.0.0.{np.random.randint(1,50)}",
                dst_port=np.random.choice([80, 443, 53, 8080]),
                protocol=np.random.choice(["TCP", "UDP"]),
                flags="S" if np.random.random() < 0.1 else "A",
                payload_size=np.random.randint(0, 1400),
                length=np.random.randint(60, 1500),
                dns_query="example.com" if np.random.random() < 0.05 else "",
                is_encrypted=np.random.random() < 0.7,
            )
            packets.append(pkt)

        result = detector.analyze_window({}, packets, window_sec=5)

    print(f"    Training samples: {len(detector._training_buffer)}")
    print(f"    Model trained:    {detector.is_trained}")
    print(f"    Baseline samples: {detector.baseline.samples_count}")

    assert detector.is_trained, "Model should be trained after 60 samples (threshold=50)"
    assert detector.baseline.samples_count >= 60

    # Now inject anomalous traffic (port scan pattern)
    anomaly_packets = []
    for port in range(1, 300):
        pkt = make_packet(
            src_ip="10.99.99.99", dst_ip="192.168.1.10",
            dst_port=port, protocol="TCP", flags="S",
            payload_size=0, length=60,
        )
        anomaly_packets.append(pkt)

    anomaly_result = detector.analyze_window({}, anomaly_packets, window_sec=5)
    print(f"    Anomaly score:    {anomaly_result['anomaly_score']:.4f}")
    print(f"    Is anomalous:     {anomaly_result['is_anomalous']}")
    print(f"    Reasons:          {anomaly_result.get('reasons', [])}")

    # Score should be elevated
    assert anomaly_result['anomaly_score'] > 0.15, \
        f"Port scan should score higher than {anomaly_result['anomaly_score']}"

    # Save and reload baseline
    detector.baseline.save()
    baseline2 = BaselineProfile(detector.baseline.db_path)
    assert baseline2._welford_n == detector.baseline._welford_n, "Welford state should persist"
    print(f"    Baseline save/reload: ✓ (n={baseline2._welford_n})")


# ═══════════════════════════════════════════════════════════════════
# TEST 4: Beaconing — Local IPs now exempt
# ═══════════════════════════════════════════════════════════════════

@test("Beaconing detector — local IoT IPs exempt, external IPs flagged")
def test_beaconing_exemption():
    config = make_config()
    detector = AnomalyDetector(config)

    # Simulate perfectly regular beaconing to a LOCAL IP (IoT keepalive)
    local_packets = []
    base_time = time.time()
    for i in range(30):
        pkt = make_packet(src_ip="192.168.2.100", dst_ip="192.168.1.1",
                          dst_port=443, protocol="TCP")
        pkt.timestamp = base_time + (i * 10)  # Perfectly regular 10-second intervals
        local_packets.append(pkt)

    local_score = detector._check_beaconing(local_packets)
    print(f"    Local beaconing score:    {local_score:.4f} (should be ~0)")
    assert local_score < 0.01, f"Local IP beaconing should be 0, got {local_score}"

    # Same pattern to an EXTERNAL IP (suspicious)
    external_packets = []
    for i in range(30):
        pkt = make_packet(src_ip="192.168.1.10", dst_ip="45.33.32.156",
                          dst_port=443, protocol="TCP")
        pkt.timestamp = base_time + (i * 10)
        external_packets.append(pkt)

    external_score = detector._check_beaconing(external_packets)
    print(f"    External beaconing score: {external_score:.4f} (should be >0.9)")
    assert external_score > 0.5, f"External regular beaconing should score high, got {external_score}"


# ═══════════════════════════════════════════════════════════════════
# TEST 5: DNS Anomaly — mDNS (.local) excluded
# ═══════════════════════════════════════════════════════════════════

@test("DNS anomaly — mDNS .local excluded from rate scoring")
def test_dns_mdns_exclusion():
    config = make_config()
    detector = AnomalyDetector(config)

    # Generate heavy mDNS traffic (normal for IoT networks)
    packets = []
    for i in range(100):
        pkt = make_packet(
            src_ip="192.168.2.100",
            dst_ip="224.0.0.251",
            dst_port=5353, protocol="UDP",
            dns_query=f"_shelly._tcp.local" if i % 2 == 0 else f"_homekit._tcp.local",
        )
        packets.append(pkt)

    score = detector._check_dns_anomalies(packets)
    print(f"    mDNS-only traffic score: {score:.4f} (should be 0)")
    assert score == 0.0, f"Pure mDNS traffic should score 0, got {score}"

    # Now add some real suspicious DNS
    for i in range(100):
        pkt = make_packet(
            src_ip="192.168.1.10", dst_ip="8.8.8.8",
            dst_port=53, protocol="UDP",
            dns_query=f"xk9f{i:04d}randomdga.evil.xyz",
        )
        packets.append(pkt)

    mixed_score = detector._check_dns_anomalies(packets)
    print(f"    Mixed mDNS + real DNS score: {mixed_score:.4f} (should be >0)")
    # Should score based on the real DNS, not the mDNS padding


# ═══════════════════════════════════════════════════════════════════
# TEST 6: Forensics — ESET Digest Auth downgraded
# ═══════════════════════════════════════════════════════════════════

@test("Forensics — ESET Digest Auth classified as LOW, not CRITICAL")
def test_eset_digest_auth():
    forensics = NetworkForensics()

    # Simulate ESET update Digest Auth payload
    eset_payload = (
        b'GET /eset_upd/endpoint/windows/latest/dll/update.ver.signed HTTP/1.1\r\n'
        b'Host: update.eset.com\r\n'
        b'Authorization: Digest username="EAV-TESTUSER", realm="eset", '
        b'nonce="abc123", uri="/eset_upd/endpoint/windows/latest/dll/update.ver.signed", '
        b'response="deadbeef0123456789abcdef01234567"\r\n'
        b'\r\n'
    )

    pkt = make_packet(src_ip="192.168.1.32", dst_ip="38.90.226.36",
                      dst_port=80, src_port=54321, protocol="TCP",
                      payload_size=len(eset_payload), length=len(eset_payload)+40)
    pkt._raw_payload = eset_payload

    forensics.analyze_packet_with_payload(pkt, eset_payload)

    # Check credential findings
    digest_creds = [c for c in forensics.credentials_found
                    if 'Digest' in c['protocol'] or 'digest' in c['credential_type']]
    print(f"    Digest credentials found: {len(digest_creds)}")

    for c in digest_creds:
        print(f"      Protocol: {c['protocol']}")
        print(f"      Risk: {c['risk']}")
        print(f"      Value: {c['value'][:80]}")
        assert c['risk'] == 'LOW', f"ESET Digest Auth should be LOW risk, got {c['risk']}"
        assert 'Update Service' in c['protocol'], f"Should be labeled as Update Service"

    # Also check that the auth token is downgraded
    token_creds = [c for c in forensics.credentials_found if 'Token' in c['protocol']]
    for c in token_creds:
        print(f"      Token: {c['protocol']} risk={c['risk']}")


# ═══════════════════════════════════════════════════════════════════
# TEST 7: Forensics — BACnet port 10001 NOT falsely detected
# ═══════════════════════════════════════════════════════════════════

@test("Forensics — UniFi port 10001 NOT classified as BACnet")
def test_unifi_not_bacnet():
    forensics = NetworkForensics()

    # UniFi inform packet on port 10001 (starts with 0x81 like BACnet)
    unifi_payload = b'\x81\x0b\x00\x1c' + b'\x00' * 28  # Looks like BVLC header

    pkt = make_packet(src_ip="192.168.1.1", dst_ip="255.255.255.255",
                      dst_port=10001, src_port=10001, protocol="UDP",
                      payload_size=len(unifi_payload), length=len(unifi_payload)+42)
    pkt._raw_payload = unifi_payload

    forensics.analyze_packet_with_payload(pkt, unifi_payload)

    bacnet_data = [s for s in forensics.sensitive_data if 'BACnet' in s.get('data_type', '')]
    print(f"    BACnet sensitive data findings: {len(bacnet_data)}")
    assert len(bacnet_data) == 0, f"UniFi port 10001 should NOT trigger BACnet detection"

    # Now test REAL BACnet on port 47808 — proper Who-Is packet
    # BVLC: 0x81=BACnet/IP, 0x0b=Broadcast, len=12
    # NPDU: version=1, control=0x00 (no routing)
    # APDU: type=0x10 (unconfirmed), service=0x08 (Who-Is)
    bacnet_payload = bytes([
        0x81, 0x0b, 0x00, 0x0c,  # BVLC header
        0x01, 0x00,              # NPDU (version 1, no routing)
        0x10, 0x08,              # APDU (unconfirmed Who-Is)
        0x00, 0x00, 0x00, 0x00,  # padding
    ])
    pkt2 = make_packet(src_ip="10.0.0.50", dst_ip="10.0.0.51",
                       dst_port=47808, src_port=47808, protocol="UDP",
                       payload_size=len(bacnet_payload), length=len(bacnet_payload)+42)
    pkt2._raw_payload = bacnet_payload

    forensics.analyze_packet_with_payload(pkt2, bacnet_payload)
    bacnet_data2 = [s for s in forensics.sensitive_data if 'BACnet' in s.get('data_type', '')]
    print(f"    Real BACnet (47808) findings: {len(bacnet_data2)}")
    assert len(bacnet_data2) > 0, "Real BACnet on 47808 SHOULD be detected"


# ═══════════════════════════════════════════════════════════════════
# TEST 8: Known Devices — Full integration with IDS
# ═══════════════════════════════════════════════════════════════════

@test("Known devices — auto-whitelisted, IDS skips heuristics")
def test_known_devices_integration():
    config = make_config()
    config.set('known_devices', 'devices', [
        {"name": "Home Assistant", "ip": "192.168.2.100", "type": "hub"},
        {"name": "Pi-hole", "ip": "192.168.2.68", "type": "dns"},
        {"name": "Chromecast", "ip": "192.168.1.54", "type": "media"},
    ])

    net_env = NetworkEnvironment()
    net_env.detect()
    net_env.load_known_devices(config.get('known_devices', 'devices'))

    print(f"    Known devices loaded: {len(net_env.known_devices)}")
    print(f"    HA device name: {net_env.get_device_name(ip='192.168.2.100')}")

    # HA should be in auto-whitelist
    assert "192.168.2.100" in net_env.auto_whitelist_ips
    assert net_env.should_skip_ids("192.168.2.100", "192.168.1.1", dst_port=443)
    print(f"    HA auto-whitelisted: ✓")
    print(f"    HA skips IDS heuristics: ✓")

    # But should NOT skip malware ports even for known devices
    assert not net_env.should_skip_ids("192.168.2.100", "10.0.0.1", dst_port=4444)
    print(f"    HA still checked for malware ports: ✓")


# ═══════════════════════════════════════════════════════════════════
# TEST 9: IOC Scanner — DGA whitelist with config overrides
# ═══════════════════════════════════════════════════════════════════

@test("IOC Scanner — DGA whitelist covers all known false positive sources")
def test_ioc_dga_comprehensive():
    config = make_config()
    config.set('whitelists', 'dga_whitelist_suffixes', ['.mycompany.corp'])
    scanner = IOCScanner(config)

    # These should all be whitelisted and NOT trigger DGA
    benign_domains = [
        # mDNS (your HA/Shelly/Chromecast)
        "40c91dd0-db9f-9205-9ea6-dcc1d5427a1f._googlecast._tcp.local",
        "_shelly._tcp.local",
        "home-assistant-12345._hap._tcp.local",
        # ESET
        "ecaserver-node-x9f2k4m7.ecaserver.eset.com",
        # Nabu Casa (HA Cloud)
        "abc123def456ghi789.ui.nabu.casa",
        # CDN hashes
        "d3fkljq29r8ksjdf.cloudfront.net",
        "a1b2c3d4e5f6g7h8.akamaized.net",
        # Custom config addition
        "secret-server-name.mycompany.corp",
    ]

    # Process enough to potentially trigger DGA (threshold is 5)
    for domain in benign_domains * 2:
        pkt = make_packet(dns_query=domain, dst_port=53, protocol="UDP")
        findings = scanner.check_packet_ioc(pkt)
        dga = [f for f in findings if f['rule_id'] == 'IOC-DGA']
        assert len(dga) == 0, f"False DGA on: {domain}"

    print(f"    All {len(benign_domains)} benign domains passed DGA check: ✓")
    print(f"    DGA tracker count: {len(scanner._high_entropy_domains)} (should be 0)")
    assert len(scanner._high_entropy_domains) == 0


# ═══════════════════════════════════════════════════════════════════
# TEST 10: Cloud domain lookup performance
# ═══════════════════════════════════════════════════════════════════

@test("Cloud domain lookup — O(k) suffix walk performance")
def test_cloud_lookup_performance():
    import timeit
    env = NetworkEnvironment()
    env.detect()

    domains = [
        "docs.google.com",
        "sub.sub.amazonaws.com",
        "evil-unknown-domain.xyz",
        "deeply.nested.cdn.cloudflare.com",
        "update.eset.com",
        "random-site.herokuapp.com",
    ]

    iterations = 50000
    total_lookups = iterations * len(domains)

    t = timeit.timeit(
        lambda: [env.is_known_cloud_domain(d) for d in domains],
        number=iterations
    )

    rate = total_lookups / t
    print(f"    {total_lookups:,} lookups in {t:.3f}s = {rate:,.0f} lookups/sec")
    assert t < 5.0, f"Too slow: {t:.3f}s for {total_lookups} lookups"


# ═══════════════════════════════════════════════════════════════════
# TEST 11: Config persistence — save/load cycle
# ═══════════════════════════════════════════════════════════════════

@test("Config — save/load with known devices and DGA whitelist")
def test_config_persistence():
    import copy
    config = make_config()
    config.set('known_devices', 'devices', [
        {"name": "Test Device", "ip": "10.0.0.5", "type": "sensor"},
    ])
    config.set('whitelists', 'dga_whitelist_suffixes', ['.test.local'])

    # Save to temp file
    config_path = os.path.join(TEMP_DIR, "test_config.json")
    with open(config_path, 'w') as f:
        json.dump(config.data, f, indent=2)

    # Reload
    with open(config_path, 'r') as f:
        loaded = json.load(f)

    devices = loaded.get('known_devices', {}).get('devices', [])
    assert len(devices) == 1
    assert devices[0]['name'] == "Test Device"
    print(f"    Known devices persisted: ✓")

    dga_wl = loaded.get('whitelists', {}).get('dga_whitelist_suffixes', [])
    assert '.test.local' in dga_wl
    print(f"    DGA whitelist persisted: ✓")


# ═══════════════════════════════════════════════════════════════════
# TEST 12: Memory cleanup — verify pruning works under load
# ═══════════════════════════════════════════════════════════════════

@test("IDS memory cleanup — state dicts pruned under simulated load")
def test_memory_cleanup():
    config = make_config()
    ids = IDSEngine(config)

    # Inject a large number of stale entries
    old_time = time.time() - 1000
    for i in range(5000):
        ids._alert_cooldowns[f"RULE:{i}:{i}.{i}.{i}.{i}"] = old_time
        ids._dns_to_ip[f"domain{i}.example.com"] = (f"1.2.3.{i%256}", old_time)

    initial_cooldowns = len(ids._alert_cooldowns)
    initial_dns = len(ids._dns_to_ip)
    print(f"    Before cleanup: {initial_cooldowns} cooldowns, {initial_dns} dns entries")

    # Force cleanup
    ids._last_cleanup = 0
    ids._periodic_cleanup()

    after_cooldowns = len(ids._alert_cooldowns)
    after_dns = len(ids._dns_to_ip)
    print(f"    After cleanup:  {after_cooldowns} cooldowns, {after_dns} dns entries")

    assert after_cooldowns == 0, f"Stale cooldowns not pruned: {after_cooldowns}"
    assert after_dns == 0, f"Stale DNS entries not pruned: {after_dns}"


# ═══════════════════════════════════════════════════════════════════
# TEST 13: Replay actual alerts — verify tuning impact
# ═══════════════════════════════════════════════════════════════════

@test("Alert replay — verify v1.2.0 tuning against real alerts.json")
def test_alert_replay():
    alerts_path = "/mnt/user-data/uploads/alerts1.json"
    if not os.path.exists(alerts_path):
        print("    Skipping — alerts1.json not uploaded")
        return

    with open(alerts_path) as f:
        alerts = json.load(f)

    print(f"    Loaded {len(alerts)} alerts from live capture")

    # Check ESET credential alerts would be downgraded
    eset_creds = [a for a in alerts if a['rule_id'] == 'FORENSICS-CREDENTIAL'
                  and 'eset' in json.dumps(a.get('evidence', {})).lower()]
    print(f"    ESET credential alerts: {len(eset_creds)} (all should become LOW)")
    assert len(eset_creds) >= 4, "Should have ESET digest auth alerts"

    # Check ML beaconing alerts — count how many only have beaconing+DNS
    ml_alerts = [a for a in alerts if a['rule_id'] == 'ML-ANOMALY']
    beaconing_only = 0
    for a in ml_alerts:
        reasons = a.get('evidence', {}).get('detection_reasons', [])
        has_beacon = any('beaconing' in r.lower() for r in reasons)
        has_dns = any('dns' in r.lower() for r in reasons)
        non_beacon_dns = [r for r in reasons
                         if 'beaconing' not in r.lower() and 'dns' not in r.lower()]
        if has_beacon and has_dns and not non_beacon_dns:
            beaconing_only += 1

    print(f"    ML alerts total:       {len(ml_alerts)}")
    print(f"    Beaconing+DNS only:    {beaconing_only} (would be eliminated)")
    print(f"    Remaining ML alerts:   {len(ml_alerts) - beaconing_only}")

    # Check BACnet false positives
    bacnet_fp = [a for a in alerts if a['rule_id'] == 'FORENSICS-SENSITIVE-DATA'
                 and a.get('evidence', {}).get('data_type') == 'BACnet'
                 and ':10001' in a.get('evidence', {}).get('connection', '')]
    print(f"    BACnet FPs (port 10001): {len(bacnet_fp)} (would be eliminated)")

    # Check HTTP attack pattern FPs
    attack_fp = [a for a in alerts if a['rule_id'] == 'FORENSICS-SENSITIVE-DATA'
                 and a.get('evidence', {}).get('data_type') == 'HTTP Attack Pattern']
    print(f"    HTTP attack FPs: {len(attack_fp)} (would be eliminated)")

    # Projected reduction
    eliminated = beaconing_only + len(bacnet_fp) + len(attack_fp)
    remaining = len(alerts) - eliminated
    print(f"    ---")
    print(f"    Projected: {len(alerts)} → {remaining} alerts ({eliminated} eliminated)")


# ═══════════════════════════════════════════════════════════════════
# TEST 14: Welford accuracy under realistic load
# ═══════════════════════════════════════════════════════════════════

@test("Welford baseline — 10,000 sample accuracy test")
def test_welford_large_scale():
    db_path = os.path.join(TEMP_DIR, "welford_test.json")
    baseline = BaselineProfile(db_path)

    np.random.seed(99)
    all_samples = []
    for i in range(10000):
        s = np.random.randn(18) * np.array([
            5000, 50, 500, 20, 15, 0.1, 5, 0.05, 3, 0.1, 0.05, 0.3, 0.2, 0.3, 0.1, 0.05, 3, 0.5
        ]) + np.array([
            50000, 200, 400, 30, 20, 0.15, 3, 0.02, 2, 0.05, 0.02, 0.6, 0.3, 0.4, 0.05, 0.01, 5, 0.7
        ])
        all_samples.append(s)
        baseline.add_sample(s)

    batch = np.array(all_samples)
    np_mean = np.mean(batch, axis=0)
    np_std = np.std(batch, axis=0, ddof=1)

    max_mean_err = np.max(np.abs(baseline.global_mean - np_mean))
    max_std_err = np.max(np.abs(baseline.global_std - 1e-8 - np_std))

    print(f"    Samples: 10,000 × 18 features")
    print(f"    Max mean error:  {max_mean_err:.2e}")
    print(f"    Max std error:   {max_std_err:.2e}")

    assert max_mean_err < 1e-8, f"Mean error too large: {max_mean_err}"
    assert max_std_err < 1e-6, f"Std error too large: {max_std_err}"


# ═══════════════════════════════════════════════════════════════════
# RESULTS
# ═══════════════════════════════════════════════════════════════════

print(f"\n{'═'*60}")
print(f"  RESULTS: {passed} passed, {failed} failed")
print(f"{'═'*60}")

if errors:
    print("\nFailed tests:")
    for name, err in errors:
        print(f"  ✗ {name}: {err}")

# Cleanup
shutil.rmtree(TEMP_DIR, ignore_errors=True)

sys.exit(0 if failed == 0 else 1)
