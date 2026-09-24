"""
Cached IP address classification.
=================================
Parsing an address string with `ipaddress` is not free, and the packet path asks
the same questions about the same handful of addresses over and over. The profiler
recorded ~8 ip_address() constructions per packet before this existed.

`functools.lru_cache` is used rather than a hand-rolled dict so the bound is
enforced and lookups stay in C.
"""

import ipaddress
from functools import lru_cache

__all__ = ['classify', 'is_private', 'is_multicast_addr', 'is_link_local_addr',
           'is_global', 'cache_info']

# Enough for a busy LAN plus a working set of remote peers.
_CACHE_SIZE = 8192


@lru_cache(maxsize=_CACHE_SIZE)
def classify(ip):
    """
    Return (valid, private, multicast, link_local, loopback) for an address string.

    `private` follows Python's definition, which is broader than RFC1918: it also
    covers loopback, link-local, TEST-NET and benchmarking ranges. That is the
    behaviour callers here want — "not somewhere on the public internet".
    Carrier-grade NAT (100.64.0.0/10) is deliberately NOT private, so traffic to a
    CGNAT address still counts as leaving the network.
    """
    if not ip:
        return (False, False, False, False, False)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return (False, False, False, False, False)
    return (True, addr.is_private, addr.is_multicast,
            addr.is_link_local, addr.is_loopback)


def is_private(ip):
    """True for addresses that are not on the public internet."""
    valid, private, _, _, _ = classify(ip)
    return valid and private


def is_multicast_addr(ip):
    valid, _, multicast, _, _ = classify(ip)
    return valid and multicast


def is_link_local_addr(ip):
    valid, _, _, link_local, _ = classify(ip)
    return valid and link_local


def is_global(ip):
    """True for a valid address that is routable on the public internet."""
    valid, private, multicast, link_local, loopback = classify(ip)
    return valid and not (private or multicast or link_local or loopback)


def cache_info():
    return classify.cache_info()
