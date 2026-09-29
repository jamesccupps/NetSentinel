"""
Reading captures.
=================
Tests build real frames with Scapy, write a real pcap, and read it back through
the real reader. Nothing is mocked: the bugs this code is prone to — a layer
that dissects differently than expected, a payload that is not where it looks
like it should be — only appear when Scapy is actually in the loop.

Two themes.

The first is the payload prohibition. A segment marked `store_payload: false`
must not be parsed above the transport header at all, and the tests check that
nothing derived from its payload ever reaches an event.

The second is that a trunk mirror shows routed packets twice. Counting both
doubles every byte total and blames the router for half the traffic.
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import _test_support  # noqa: E402,F401

from netmon.profile import SiteProfile  # noqa: E402
from netmon.sources.pcap import PcapError, packet_to_events, read_pcap  # noqa: E402
from netmon_tests.test_bacnet import (bvlc, confirmed, context_uint,  # noqa: E402
                                      npdu, object_id, unconfirmed)

try:
    from scapy.all import (ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, Dot1Q, Ether,
                           IP, Raw, TCP, UDP, wrpcap)
    import scapy.all as scapy
    HAVE_SCAPY = hasattr(scapy, 'PcapReader')
except Exception:                                              # pragma: no cover
    HAVE_SCAPY = False

requires_scapy = unittest.skipUnless(HAVE_SCAPY, 'needs a real scapy')

ROUTER_MAC = '00:11:22:00:00:50'
SENDER_MAC = '00:11:22:00:00:40'
TARGET_MAC = '00:11:22:00:00:02'


def profile():
    return SiteProfile({
        'site': {'name': 'test'},
        'vlans': {
            20: {'name': 'ot', 'subnet': '10.10.20.0/24', 'zone': 'ot',
                 'gateway': '10.10.20.1'},
            40: {'name': 'restricted', 'subnet': '10.10.40.0/24',
                 'zone': 'restricted', 'store_payload': False},
            60: {'name': 'staff', 'subnet': '10.10.60.0/24', 'zone': 'corporate',
                 'gateway': '10.10.60.1'},
        },
        'router_macs': [ROUTER_MAC],
    })


def frame(vlan=None, src_mac=SENDER_MAC, dst_mac=TARGET_MAC):
    packet = Ether(src=src_mac, dst=dst_mac)
    if vlan is not None:
        packet /= Dot1Q(vlan=vlan)
    return packet


@requires_scapy
class _PcapCase(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-pcap-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.profile = profile()

    def through_file(self, packets, **kw):
        """Write a capture and read it back — the whole path, not a shortcut."""
        path = os.path.join(self.scratch, 'sample.pcap')
        wrpcap(path, packets)
        return list(read_pcap(path, self.profile, **kw))

    def one(self, packet):
        events = self.through_file([packet])
        self.assertEqual(len(events), 1, [e.kind for e in events])
        return events[0]


# ─── The basics ──────────────────────────────────────────────────────────────

class TestFlowExtraction(_PcapCase):

    def test_a_plain_tcp_packet_becomes_a_flow(self):
        event = self.one(frame() / IP(src='10.10.60.50', dst='10.10.20.21')
                         / TCP(sport=50000, dport=8080))
        self.assertEqual(event.kind, 'flow')
        self.assertEqual(event.src_ip, '10.10.60.50')
        self.assertEqual(event.dst_port, 8080)
        self.assertEqual(event.protocol, 'tcp')

    def test_macs_are_lowercased(self):
        event = self.one(frame(src_mac='AA:BB:CC:DD:EE:FF')
                         / IP(src='10.10.60.50', dst='10.10.20.21') / TCP())
        self.assertEqual(event.src_mac, 'aa:bb:cc:dd:ee:ff')

    def test_a_vlan_tag_is_read(self):
        event = self.one(frame(vlan=20) / IP(src='10.10.20.21', dst='10.10.20.10')
                         / UDP(sport=1000, dport=1001))
        self.assertEqual(event.vlan, 20)

    def test_an_untagged_frame_has_no_vlan(self):
        event = self.one(frame() / IP(src='10.10.60.50', dst='10.10.20.21') / TCP())
        self.assertIsNone(event.fields['observed_vlan']
                          if 'observed_vlan' in event.fields else None)

    def test_the_byte_count_is_the_frame_length(self):
        packet = frame() / IP(src='10.10.60.50', dst='10.10.20.21') / TCP() / Raw(b'x' * 100)
        self.assertEqual(self.one(packet).bytes_to_dst, len(packet))

    def test_arp_is_read_from_its_own_fields(self):
        """An ARP frame has no IP header to read addresses from."""
        event = self.one(frame(dst_mac='ff:ff:ff:ff:ff:ff')
                         / ARP(op=1, psrc='10.10.60.50', pdst='10.10.60.99'))
        self.assertEqual(event.kind, 'arp')
        self.assertEqual(event.src_ip, '10.10.60.50')
        self.assertEqual(event.dst_ip, '10.10.60.99')
        self.assertEqual(event.fields['arp_operation'], 'request')

    def test_an_arp_reply_is_marked_as_an_answer(self):
        event = self.one(frame() / ARP(op=2, psrc='10.10.60.50',
                                       pdst='10.10.60.99'))
        self.assertTrue(event.fields['is_answer'])

    def test_a_frame_with_no_network_layer_yields_nothing(self):
        self.assertEqual(self.through_file([frame() / Raw(b'\x00' * 40)]), [])


# ─── BACnet ──────────────────────────────────────────────────────────────────

class TestBacnetFromTheWire(_PcapCase):

    def bacnet(self, body, src='10.10.60.50', dst='10.10.20.21'):
        return (frame(vlan=20) / IP(src=src, dst=dst)
                / UDP(sport=47808, dport=47808) / Raw(body))

    def test_a_write_is_recognised(self):
        body = bvlc(0x0A, npdu() + confirmed(
            15, object_id(2, 7) + context_uint(1, 85)))
        event = self.one(self.bacnet(body))
        self.assertEqual(event.kind, 'bacnet')
        self.assertEqual(event.fields['service'], 'WriteProperty')
        self.assertEqual(event.fields['object'], 'analog-value-7')
        self.assertTrue(event.fields['bacnet_write'])

    def test_a_who_is_is_not_a_write(self):
        event = self.one(self.bacnet(bvlc(0x0B, npdu() + unconfirmed(8))))
        self.assertEqual(event.fields['service'], 'Who-Is')
        self.assertIs(event.fields['bacnet_write'], False)

    def test_a_broadcast_table_write_is_topology(self):
        event = self.one(self.bacnet(bvlc(0x01, bytes(10))))
        self.assertTrue(event.fields['bacnet_topology'])

    def test_a_forwarded_npdu_reports_its_origin(self):
        body = bvlc(0x04, bytes([192, 168, 0, 7]) + (47808).to_bytes(2, 'big')
                    + npdu() + unconfirmed(8))
        self.assertEqual(self.one(self.bacnet(body)).fields['peer'],
                         '192.168.0.7:47808')

    def test_a_non_bacnet_packet_on_the_bacnet_port_is_still_a_flow(self):
        event = self.one(self.bacnet(b'this is not bacnet at all'))
        self.assertEqual(event.kind, 'flow')

    def test_the_whole_registered_port_range_is_covered(self):
        """Sites with several BACnet networks use 47809 and up."""
        packet = (frame(vlan=20) / IP(src='10.10.60.50', dst='10.10.20.21')
                  / UDP(sport=47810, dport=47810)
                  / Raw(bvlc(0x0B, npdu() + unconfirmed(8))))
        self.assertEqual(self.one(packet).kind, 'bacnet')


# ─── Names ───────────────────────────────────────────────────────────────────

class TestNameResolution(_PcapCase):

    def query(self, name, port=53, answers=None, rcode=0):
        dns = DNS(qr=1 if answers is not None else 0, rcode=rcode,
                  qd=DNSQR(qname=name))
        if answers:
            dns.an = answers
        return (frame() / IP(src='10.10.60.50', dst='10.10.60.1')
                / UDP(sport=50000, dport=port) / dns)

    def test_a_dns_query(self):
        event = self.one(self.query('example.test'))
        self.assertEqual(event.kind, 'dns')
        self.assertEqual(event.fields['query'], 'example.test')
        self.assertFalse(event.fields['is_answer'])

    def test_llmnr_and_mdns_and_nbns_are_distinguished(self):
        """
        They matter more than DNS here: none of them authenticates anything, so
        a name nobody owns is a standing invitation.
        """
        for port, kind in ((5355, 'llmnr'), (5353, 'mdns'), (137, 'nbns')):
            with self.subTest(kind=kind):
                self.assertEqual(self.one(self.query('wpad', port=port)).kind, kind)

    def test_every_answer_becomes_an_event(self):
        """
        Scapy 2.7 returns a list subclass that also proxies `rdata` to its first
        element, so a naive check finds one answer and silently misses the rest
        — which is exactly what a fast-flux rule counts.
        """
        # A list, not a `/` stack: stacking sets ancount to 1, so only the
        # first answer survives the round trip and the fixture would be testing
        # nothing.
        answers = [DNSRR(rrname='example.test', rdata=f'203.0.113.{n}', ttl=60)
                   for n in (1, 2, 3)]
        events = self.through_file([self.query('example.test', answers=answers)])
        self.assertEqual(len(events), 3)
        self.assertEqual({e.fields['answer'] for e in events},
                         {'203.0.113.1', '203.0.113.2', '203.0.113.3'})

    def test_a_single_answer_still_works(self):
        events = self.through_file([self.query(
            'example.test', answers=[DNSRR(rrname='example.test',
                                           rdata='203.0.113.1', ttl=300)])])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].fields['ttl'], 300)

    def test_nxdomain_is_flagged(self):
        event = self.one(self.query('nope.test', answers=None, rcode=3))
        event_fields = event.fields
        self.assertEqual(event_fields['rcode'], 3)

    def test_the_query_name_is_lowercased_and_stripped(self):
        self.assertEqual(self.one(self.query('WPAD.Local.')).fields['query'],
                         'wpad.local')


# ─── DHCP ────────────────────────────────────────────────────────────────────

class TestDhcp(_PcapCase):

    def dhcp(self, message_type, src='0.0.0.0', dst='255.255.255.255',
             src_mac=SENDER_MAC):
        return (frame(src_mac=src_mac, dst_mac='ff:ff:ff:ff:ff:ff')
                / IP(src=src, dst=dst) / UDP(sport=68, dport=67)
                / BOOTP(chaddr=bytes.fromhex(src_mac.replace(':', '')))
                / DHCP(options=[('message-type', message_type), 'end']))

    def test_a_discover(self):
        event = self.one(self.dhcp(1))
        self.assertEqual(event.kind, 'dhcp')
        self.assertEqual(event.fields['message'], 'discover')

    def test_an_offer(self):
        self.assertEqual(self.one(self.dhcp(2)).fields['message'], 'offer')

    def test_the_client_mac_comes_from_the_bootp_header(self):
        """An offer to a broadcast address still names who it is for."""
        self.assertEqual(self.one(self.dhcp(1)).fields['client_mac'], SENDER_MAC)

    def test_a_malformed_dhcp_packet_does_not_stop_the_read(self):
        good = self.dhcp(1)
        bad = (frame() / IP(src='0.0.0.0', dst='255.255.255.255')
               / UDP(sport=68, dport=67) / Raw(b'\xff' * 8))
        events = self.through_file([bad, good])
        self.assertEqual(len(events), 2)


# ─── TLS ─────────────────────────────────────────────────────────────────────

class TestTls(_PcapCase):

    def client_hello(self, sni):
        from netmon_tests._tls_fixture import build_client_hello
        return (frame() / IP(src='10.10.60.50', dst='203.0.113.9')
                / TCP(sport=50000, dport=443) / Raw(build_client_hello(sni)))

    def test_the_server_name_is_extracted(self):
        event = self.one(self.client_hello('relay-9f2.net.anydesk.com'))
        self.assertEqual(event.kind, 'tls')
        self.assertEqual(event.fields['sni'], 'relay-9f2.net.anydesk.com')

    def test_a_fingerprint_is_produced(self):
        event = self.one(self.client_hello('example.test'))
        self.assertTrue(event.fields.get('ja3') or event.fields.get('ja4'))

    def test_non_tls_on_port_443_is_still_a_flow(self):
        packet = (frame() / IP(src='10.10.60.50', dst='203.0.113.9')
                  / TCP(sport=50000, dport=443) / Raw(b'not tls'))
        self.assertEqual(self.one(packet).kind, 'flow')


# ─── Cleartext credentials ───────────────────────────────────────────────────

class TestCleartextCredentials(_PcapCase):
    """
    The finding is that a credential crossed in the clear. The value is the one
    thing that must never be recorded — it would end up in logs, in alerts and
    in AI prompts.
    """

    def http(self, headers):
        return (frame() / IP(src='10.10.60.50', dst='10.10.20.10')
                / TCP(sport=50000, dport=80) / Raw(headers))

    def test_an_authorization_header_is_reported_by_type_only(self):
        event = self.one(self.http(
            b'GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic aHVudGVyMg==\r\n\r\n'))
        self.assertEqual(event.fields['credential_type'], 'http-authorization')
        blob = str(event.as_dict())
        self.assertNotIn('aHVudGVyMg', blob)
        self.assertNotIn('Basic', blob)

    def test_a_session_cookie_is_reported_by_type_only(self):
        event = self.one(self.http(
            b'GET / HTTP/1.1\r\nHost: x\r\nCookie: SESSIONID=abcdef123\r\n\r\n'))
        self.assertEqual(event.fields['credential_type'], 'http-session-cookie')
        self.assertNotIn('abcdef123', str(event.as_dict()))

    def test_plain_http_with_no_credentials_is_just_a_flow(self):
        self.assertEqual(self.one(self.http(b'GET / HTTP/1.1\r\nHost: x\r\n\r\n')).kind,
                         'flow')

    def test_telnet_and_ftp_are_reported_by_port(self):
        for port, kind in ((23, 'telnet'), (21, 'ftp')):
            with self.subTest(port=port):
                packet = (frame() / IP(src='10.10.60.50', dst='10.10.20.10')
                          / TCP(sport=50000, dport=port) / Raw(b'USER admin\r\n'))
                self.assertEqual(self.one(packet).fields['credential_type'], kind)

    def test_no_payload_bytes_reach_the_event(self):
        event = self.one(self.http(
            b'POST /login HTTP/1.1\r\nAuthorization: Basic c2VjcmV0\r\n\r\n'
            b'username=admin&password=hunter2'))
        blob = str(event.as_dict())
        for secret in ('hunter2', 'c2VjcmV0', 'password=', 'POST /login'):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, blob)


# ─── The payload prohibition ─────────────────────────────────────────────────

class TestMetadataOnlySegments(_PcapCase):
    """
    VLAN 40 is marked `store_payload: false`. Nothing above the transport
    header may be parsed there — not looking is a stronger guarantee than
    looking and discarding, and it is the one the site asked for.
    """

    def restricted(self, upper):
        return (frame(vlan=40) / IP(src='10.10.40.10', dst='10.10.40.11') / upper)

    def test_a_flow_event_is_still_produced(self):
        """Metadata is the point: who talked to whom, when, how much."""
        event = self.one(self.restricted(TCP(sport=50000, dport=80)))
        self.assertEqual(event.kind, 'flow')
        self.assertEqual(event.src_ip, '10.10.40.10')
        self.assertEqual(event.dst_port, 80)
        self.assertGreater(event.bytes_to_dst, 0)

    def test_it_is_marked_as_metadata_only(self):
        self.assertTrue(self.one(self.restricted(TCP(dport=80)))
                        .fields['metadata_only'])

    def test_credentials_on_a_restricted_segment_are_not_even_looked_for(self):
        event = self.one(self.restricted(
            TCP(sport=50000, dport=80)
            / Raw(b'GET / HTTP/1.1\r\nAuthorization: Basic c2VjcmV0\r\n\r\n')))
        self.assertEqual(event.kind, 'flow')
        self.assertNotIn('credential_type', event.fields)
        self.assertNotIn('c2VjcmV0', str(event.as_dict()))

    def test_a_server_name_on_a_restricted_segment_is_not_extracted(self):
        from netmon_tests._tls_fixture import build_client_hello
        event = self.one(self.restricted(
            TCP(sport=50000, dport=443) / Raw(build_client_hello('secret.test'))))
        self.assertEqual(event.kind, 'flow')
        self.assertNotIn('sni', event.fields)
        self.assertNotIn('secret.test', str(event.as_dict()))

    def test_a_dns_query_on_a_restricted_segment_is_not_extracted(self):
        event = self.one(self.restricted(
            UDP(sport=50000, dport=53) / DNS(qd=DNSQR(qname='private.test'))))
        self.assertEqual(event.kind, 'flow')
        self.assertNotIn('private.test', str(event.as_dict()))

    def test_bacnet_on_a_restricted_segment_is_not_parsed(self):
        event = self.one(self.restricted(
            UDP(sport=47808, dport=47808)
            / Raw(bvlc(0x0A, npdu() + confirmed(15, object_id(2, 7))))))
        self.assertEqual(event.kind, 'flow')
        self.assertNotIn('service', event.fields)

    def test_an_unrestricted_segment_is_unaffected(self):
        packet = (frame(vlan=20) / IP(src='10.10.20.21', dst='10.10.20.10')
                  / UDP(sport=50000, dport=53) / DNS(qd=DNSQR(qname='ok.test')))
        self.assertEqual(self.one(packet).fields['query'], 'ok.test')

    def test_with_no_profile_nothing_is_restricted(self):
        """A caller with no profile gets full parsing, not silent suppression."""
        path = os.path.join(self.scratch, 'noprofile.pcap')
        wrpcap(path, [self.restricted(UDP(sport=50000, dport=53)
                                      / DNS(qd=DNSQR(qname='ok.test')))])
        events = list(read_pcap(path, profile=None))
        self.assertEqual(events[0].kind, 'dns')


# ─── Router deduplication ────────────────────────────────────────────────────

class TestRouterDeduplication(_PcapCase):
    """
    A routed packet crosses a trunk mirror twice. In a measured seven-second
    sample, 3,178 packets appeared on both sides; counting both doubles every
    byte total and blames the router for half the traffic.
    """

    def routed_pair(self):
        """The same IP packet as the mirror sees it, twice."""
        arriving = (frame(vlan=60, src_mac=SENDER_MAC, dst_mac=ROUTER_MAC)
                    / IP(src='10.10.60.50', dst='10.10.20.21') / TCP(dport=443))
        leaving = (frame(vlan=20, src_mac=ROUTER_MAC, dst_mac=TARGET_MAC)
                   / IP(src='10.10.60.50', dst='10.10.20.21') / TCP(dport=443))
        return [arriving, leaving]

    def test_the_relayed_copy_is_dropped(self):
        events = self.through_file(self.routed_pair())
        self.assertEqual(len(events), 1)

    def test_the_surviving_copy_is_the_senders(self):
        """So the traffic is attributed to who actually sent it."""
        event = self.through_file(self.routed_pair())[0]
        self.assertEqual(event.src_mac, SENDER_MAC)
        self.assertEqual(event.vlan, 60)

    def test_traffic_the_router_itself_sends_is_kept(self):
        """It has the router's MAC and the router's address."""
        packet = (frame(vlan=60, src_mac=ROUTER_MAC)
                  / IP(src='10.10.60.1', dst='203.0.113.9') / UDP(dport=53))
        self.assertEqual(len(self.through_file([packet])), 1)

    def test_same_vlan_traffic_is_kept(self):
        """
        A simpler rule — count only frames addressed to the router — would
        discard all of this.
        """
        packet = (frame(vlan=20, src_mac=TARGET_MAC, dst_mac=SENDER_MAC)
                  / IP(src='10.10.20.21', dst='10.10.20.10') / TCP(dport=502))
        self.assertEqual(len(self.through_file([packet])), 1)

    def test_deduplication_can_be_turned_off(self):
        self.assertEqual(len(self.through_file(self.routed_pair(),
                                               dedup_router=False)), 2)

    def test_without_router_macs_nothing_is_dropped(self):
        path = os.path.join(self.scratch, 'nodedup.pcap')
        wrpcap(path, self.routed_pair())
        self.assertEqual(len(list(read_pcap(path, SiteProfile({})))), 2)

    def test_byte_totals_are_not_doubled(self):
        packets = self.routed_pair()
        events = self.through_file(packets)
        self.assertEqual(sum(e.bytes_to_dst for e in events), len(packets[0]))


# ─── Reading ─────────────────────────────────────────────────────────────────

class TestReading(_PcapCase):

    def test_a_missing_capture_says_so(self):
        with self.assertRaises(PcapError) as ctx:
            list(read_pcap('/nonexistent.pcap'))
        self.assertIn('not found', str(ctx.exception))

    def test_a_file_that_is_not_a_capture_says_so(self):
        path = os.path.join(self.scratch, 'not.pcap')
        with open(path, 'w') as f:
            f.write('hello')
        with self.assertRaises(PcapError):
            list(read_pcap(path))

    def test_limit(self):
        packets = [frame() / IP(src='10.10.60.50', dst='10.10.20.21')
                   / TCP(dport=p) for p in range(8000, 8020)]
        self.assertEqual(len(self.through_file(packets, limit=5)), 5)

    def test_it_is_a_generator(self):
        path = os.path.join(self.scratch, 'gen.pcap')
        wrpcap(path, [frame() / IP(src='10.10.60.50', dst='10.10.20.21') / TCP()])
        self.assertFalse(isinstance(read_pcap(path), list))

    def test_an_empty_capture_yields_nothing(self):
        packets = [frame() / IP(src='10.10.60.50', dst='10.10.20.21') / TCP()]
        path = os.path.join(self.scratch, 'one.pcap')
        wrpcap(path, packets)
        self.assertEqual(len(list(read_pcap(path, self.profile, limit=0))), 1)

    def test_events_come_out_in_capture_order(self):
        packets = [frame() / IP(src='10.10.60.50', dst='10.10.20.21')
                   / TCP(dport=p) for p in (8001, 8002, 8003)]
        self.assertEqual([e.dst_port for e in self.through_file(packets)],
                         [8001, 8002, 8003])

    def test_timestamps_survive_the_round_trip(self):
        packet = frame() / IP(src='10.10.60.50', dst='10.10.20.21') / TCP()
        packet.time = 1_790_255_100.5
        self.assertAlmostEqual(self.one(packet).ts, 1_790_255_100.5, places=1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
