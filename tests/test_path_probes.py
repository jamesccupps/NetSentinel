"""
Path probes are not floods.

PingerPlot on a work laptop maps the route to each target it watches once a
second: echo requests to 8.8.8.8 with the TTL stepped from 1 to 11, and TCP
SYNs to Outlook on 443 with the TTL stepped from 1 to 12, each router on the
way answering "time exceeded". In two hours that was 56 HIGH "ICMP Flood" and
two CRITICAL "SYN Flood" alerts. All but the last probe of each round die at a
router, so the target never sees them.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_lan_threats import pkt  # noqa: E402
from test_third_review import T0  # noqa: E402

PC = '192.168.10.32'
LAN_HOST = '192.168.10.40'
RESOLVER = '8.8.8.8'          # documentation ranges count as private in Python
MAIL = '45.60.10.114'


def engine():
    from src.ids_engine import IDSEngine
    alerts = []
    return IDSEngine(reset_config(), alert_callback=alerts.append), alerts


def rules(alerts):
    return [a.rule_id for a in alerts]


def traceroute_pings(ids, dst, hops, seconds, ts=T0):
    """One round a second: an echo request at every TTL from 1 to `hops`."""
    for s in range(seconds):
        for ttl in range(1, hops + 1):
            ids.inspect_packet(pkt(ts=ts + s + ttl * 0.0001, src_ip=PC, dst_ip=dst,
                                   protocol='ICMP', icmp_type=8, ttl=ttl, payload_size=32))


def tcp_traceroute(ids, dst, hops, seconds, ts=T0, per_hop=3):
    """One round a second: `per_hop` SYNs at every TTL, a new source port per hop."""
    port = 43000
    for s in range(seconds):
        for ttl in range(1, hops + 1):
            port += 1
            for k in range(per_hop):
                ids.inspect_packet(pkt(ts=ts + s + ttl * 0.001 + k * 0.0002, src_ip=PC,
                                       src_port=port, dst_ip=dst, dst_port=443,
                                       protocol='TCP', flags='S', ttl=ttl))


class TestPathProbes(unittest.TestCase):

    def test_a_traceroute_by_ping_is_not_an_icmp_flood(self):
        ids, alerts = engine()
        traceroute_pings(ids, RESOLVER, hops=11, seconds=60)
        self.assertNotIn('ICMP-FLOOD', rules(alerts))

    def test_a_tcp_traceroute_is_not_a_syn_flood(self):
        ids, alerts = engine()
        tcp_traceroute(ids, MAIL, hops=12, seconds=60)       # 36 SYNs a second
        tcp_traceroute(ids, MAIL, hops=17, seconds=60, ts=T0 + 100)   # 51 a second
        self.assertNotIn('SYN-FLOOD', rules(alerts))

    def test_the_probes_that_reach_the_target_still_count(self):
        """Probes above the hop count arrive; a flood sent at a TTL of 31 or more is counted."""
        ids, alerts = engine()
        for i in range(600):
            ids.inspect_packet(pkt(ts=T0 + i * 0.01, src_ip=PC, dst_ip=RESOLVER,
                                   protocol='ICMP', icmp_type=8, ttl=31, payload_size=32))
        self.assertIn('ICMP-FLOOD', rules(alerts))

    def test_a_syn_flood_at_a_normal_ttl_still_alerts(self):
        ids, alerts = engine()
        for i in range(800):
            ids.inspect_packet(pkt(ts=T0 + i * 0.01, src_ip=PC, src_port=20000 + i,
                                   dst_ip=MAIL, dst_port=443, protocol='TCP', flags='S',
                                   ttl=128))
        self.assertIn('SYN-FLOOD', rules(alerts))

    def test_a_low_ttl_means_nothing_on_the_lan(self):
        """No router between two hosts on one network: TTL 1 arrives."""
        ids, alerts = engine()
        for i in range(600):
            ids.inspect_packet(pkt(ts=T0 + i * 0.01, src_ip=PC, dst_ip=LAN_HOST,
                                   protocol='ICMP', icmp_type=8, ttl=1, payload_size=32))
        self.assertIn('ICMP-FLOOD', rules(alerts))

    def test_a_flood_from_the_internet_is_counted_whatever_its_ttl(self):
        """A packet from outside arrives with its TTL worn down by the hops it took."""
        ids, alerts = engine()
        for i in range(600):
            ids.inspect_packet(pkt(ts=T0 + i * 0.01, src_ip=RESOLVER, dst_ip=PC,
                                   protocol='ICMP', icmp_type=8, ttl=12, payload_size=32))
        self.assertIn('ICMP-FLOOD', rules(alerts))

    def test_an_unknown_ttl_is_counted(self):
        ids, alerts = engine()
        for i in range(600):
            ids.inspect_packet(pkt(ts=T0 + i * 0.01, src_ip=PC, dst_ip=RESOLVER,
                                   protocol='ICMP', icmp_type=8, payload_size=32))
        self.assertIn('ICMP-FLOOD', rules(alerts))


if __name__ == '__main__':
    unittest.main()
