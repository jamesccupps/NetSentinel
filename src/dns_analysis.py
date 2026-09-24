"""
DNS response analysis.
======================
Until now only DNS *queries* were inspected. Responses carry the strongest
signals available from DNS, and all of them need the answer section:

- **NXDOMAIN bursts.** Domain-generation-algorithm malware tries many generated
  names and most do not exist. A host producing a run of failures over
  high-entropy names is the classic DGA signature, and it is visible only in the
  response code.
- **Fast-flux.** A name that resolves to many different addresses in a short
  window, with a short TTL, is hosting that moves faster than legitimate hosting
  needs to.
- **Sinkholes and parked infrastructure.** One address answering for many
  unrelated names.

False positives this deliberately guards against
-------------------------------------------------
NXDOMAIN is not rare in healthy traffic:

- Chrome issues three random 10-character lookups at startup specifically to
  detect NXDOMAIN hijacking by an ISP. That alone is a burst of high-entropy
  failures, so the threshold sits well above it.
- Windows appends DNS search suffixes, so one failed name produces several
  NXDOMAINs.
- Typos.

Short TTLs are likewise normal: Cloudflare, Akamai and most CDNs answer with
30-60 second TTLs by design. A short TTL on its own means nothing, so it is only
ever combined with address churn on the same name.
"""

import logging
import math
import time
from collections import Counter, defaultdict, deque

logger = logging.getLogger("NetSentinel.DNS")

__all__ = ['DnsResponseMonitor', 'domain_entropy', 'looks_algorithmic',
           'RCODE_NAMES', 'RCODE_NXDOMAIN']

RCODE_NOERROR = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3

RCODE_NAMES = {
    0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
    4: 'NOTIMP', 5: 'REFUSED',
}

# Chrome's startup probe is 3 lookups; Windows suffix search multiplies a single
# failure by the number of configured suffixes. 15 in a minute is well clear of
# both while still catching a DGA, which typically tries hundreds.
NXDOMAIN_BURST_COUNT = 15
NXDOMAIN_WINDOW_SEC = 60

# Mean Shannon entropy per character of the failing labels. English-like and
# typo'd names sit below this; algorithmically generated ones sit above.
DGA_ENTROPY_THRESHOLD = 3.2
DGA_MIN_LABEL_LEN = 7

# Fast-flux: distinct addresses for ONE name inside the window, plus a TTL at or
# under the ceiling. Both are required — CDNs have the short TTL but not the churn.
FLUX_MIN_ADDRESSES = 8
FLUX_TTL_CEILING = 300
FLUX_WINDOW_SEC = 900

# One address answering for this many unrelated registrable domains.
SHARED_IP_DOMAIN_COUNT = 25

_HEX_CHARS = set('0123456789abcdef')


def domain_entropy(label):
    """Shannon entropy per character of a single DNS label."""
    if not label:
        return 0.0
    counts = Counter(label)
    total = len(label)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def looks_algorithmic(name):
    """
    Whether the leftmost label looks machine-generated rather than chosen.

    Deliberately conservative. Plenty of legitimate infrastructure uses long
    random-looking hostnames — CDN cache keys, cloud instance names — so this is
    only ever one input to a decision, never the decision.
    """
    if not name:
        return False
    label = name.split('.')[0]
    if len(label) < DGA_MIN_LABEL_LEN:
        return False
    # Hyphens and underscores mean someone typed this. Generators emit a single
    # run of characters; 'my-company-intranet' otherwise trips the vowel test.
    if '-' in label or '_' in label:
        return False
    # Pure hex is usually a content hash, not a DGA.
    if set(label) <= _HEX_CHARS:
        return False
    if domain_entropy(label) < DGA_ENTROPY_THRESHOLD:
        return False
    # A DGA name is mostly letters and digits with few vowels.
    vowels = sum(1 for c in label if c in 'aeiou')
    return vowels / len(label) < 0.30


def _registrable(name):
    """Last two labels — good enough to group related names without a PSL."""
    parts = name.lower().rstrip('.').split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else name.lower()


class DnsResponseMonitor:
    """
    Tracks DNS responses and reports findings.

    Kept separate from IDSEngine so the thresholds above can be exercised
    directly, and because this is per-response state rather than per-packet.
    """

    def __init__(self, config=None):
        self.config = config
        # Read directly rather than through a helper: a lambda wrapper hides the
        # key from the check that every DEFAULT_CONFIG entry is actually consulted.
        if config is not None:
            self.nxdomain_threshold = config.get(
                'ids', 'dns_nxdomain_threshold', default=NXDOMAIN_BURST_COUNT)
            self.flux_threshold = config.get(
                'ids', 'dns_flux_address_threshold', default=FLUX_MIN_ADDRESSES)
        else:
            self.nxdomain_threshold = NXDOMAIN_BURST_COUNT
            self.flux_threshold = FLUX_MIN_ADDRESSES

        # {src_ip: deque[(timestamp, queried_name)]}
        self._failures = defaultdict(lambda: deque(maxlen=512))
        # {domain: {'addresses': {ip: last_seen}, 'min_ttl': int, 'first': ts}}
        self._resolutions = {}
        # {address: {registrable_domain}}
        self._addr_to_domains = defaultdict(set)

        self._reported_nxdomain = {}
        self._reported_flux = {}
        self._report_cooldown = 300

        self.responses_seen = 0
        self.nxdomain_seen = 0
        # Seeded from the first observation rather than the wall clock: callers
        # supply their own timestamps (live capture uses time.time(), but a PCAP
        # replay does not), and mixing the two clocks meant pruning never ran.
        self._last_prune = None

    # ─── Ingest ──────────────────────────────────────────────────────────

    def observe_response(self, src_ip, name, rcode, answers=(), ttl=-1,
                         timestamp=None):
        """
        Record one DNS response. Returns a list of finding dicts (usually empty).

        `src_ip` is the host that asked, not the resolver that answered — the
        finding is about which machine is behaving oddly.
        """
        if not name or rcode < 0:
            return []
        now = timestamp or time.time()
        self.responses_seen += 1
        name = name.lower().rstrip('.')
        findings = []

        if rcode == RCODE_NXDOMAIN:
            self.nxdomain_seen += 1
            self._failures[src_ip].append((now, name))
            finding = self._check_nxdomain_burst(src_ip, now)
            if finding:
                findings.append(finding)
        elif rcode == RCODE_NOERROR and answers:
            finding = self._record_resolution(name, answers, ttl, now)
            if finding:
                findings.append(finding)

        self._maybe_prune(now)
        return findings

    # ─── Checks ──────────────────────────────────────────────────────────

    def _check_nxdomain_burst(self, src_ip, now):
        cutoff = now - NXDOMAIN_WINDOW_SEC
        recent = [(t, n) for t, n in self._failures[src_ip] if t >= cutoff]
        if len(recent) < self.nxdomain_threshold:
            return None
        if now - self._reported_nxdomain.get(src_ip, 0) < self._report_cooldown:
            return None

        names = [n for _, n in recent]
        algorithmic = [n for n in names if looks_algorithmic(n)]
        distinct = {_registrable(n) for n in names}
        entropies = [domain_entropy(n.split('.')[0]) for n in names]
        mean_entropy = sum(entropies) / len(entropies) if entropies else 0.0

        # A burst of failures against ONE domain is a broken service, not a DGA.
        if len(distinct) < 5:
            return None

        self._reported_nxdomain[src_ip] = now
        algorithmic_ratio = len(algorithmic) / len(names)
        return {
            'type': 'nxdomain_burst',
            'severity': 'HIGH' if algorithmic_ratio > 0.5 else 'MEDIUM',
            'src_ip': src_ip,
            'failure_count': len(recent),
            'window_sec': NXDOMAIN_WINDOW_SEC,
            'distinct_domains': len(distinct),
            'algorithmic_ratio': round(algorithmic_ratio, 2),
            'mean_entropy': round(mean_entropy, 2),
            'sample_domains': names[-10:],
            'description': (
                f"{len(recent)} failed DNS lookups from {src_ip} in "
                f"{NXDOMAIN_WINDOW_SEC}s across {len(distinct)} different domains, "
                f"{algorithmic_ratio:.0%} of them machine-generated in appearance."),
            'recommendation': (
                'Malware using a domain-generation algorithm tries many names until '
                'one resolves, so most of its lookups fail. Identify the process '
                'making these queries. A browser checking for DNS hijacking, or a '
                'misconfigured search suffix, produces a much smaller burst.'),
        }

    def _record_resolution(self, name, answers, ttl, now):
        addresses = [a for a in answers if a and _looks_like_address(a)]
        if not addresses:
            return None

        entry = self._resolutions.get(name)
        if entry is None:
            entry = {'addresses': {}, 'min_ttl': ttl if ttl >= 0 else 1 << 30,
                     'first': now}
            self._resolutions[name] = entry
        for addr in addresses:
            entry['addresses'][addr] = now
            self._addr_to_domains[addr].add(_registrable(name))
        if 0 <= ttl < entry['min_ttl']:
            entry['min_ttl'] = ttl

        cutoff = now - FLUX_WINDOW_SEC
        live = {a: t for a, t in entry['addresses'].items() if t >= cutoff}
        entry['addresses'] = live

        if len(live) < self.flux_threshold:
            return None
        if entry['min_ttl'] > FLUX_TTL_CEILING:
            # Many addresses with a long TTL is ordinary load balancing.
            return None
        if now - self._reported_flux.get(name, 0) < self._report_cooldown:
            return None

        self._reported_flux[name] = now
        return {
            'type': 'fast_flux',
            'severity': 'HIGH',
            'domain': name,
            'address_count': len(live),
            'min_ttl': entry['min_ttl'],
            'window_sec': FLUX_WINDOW_SEC,
            'sample_addresses': sorted(live)[:10],
            'description': (
                f"{name} resolved to {len(live)} different addresses within "
                f"{FLUX_WINDOW_SEC // 60} minutes with a TTL of "
                f"{entry['min_ttl']}s."),
            'recommendation': (
                'Hosting that moves this fast is characteristic of fast-flux '
                'networks, which rotate through compromised hosts to stay '
                'reachable. Large CDNs also use short TTLs, but they do not churn '
                'this many addresses for one name. Check whether this is a service '
                'you recognise.'),
        }

    # ─── Queries ─────────────────────────────────────────────────────────

    def domains_for_address(self, address):
        return self._addr_to_domains.get(address, set())

    def shared_hosting_addresses(self):
        """Addresses answering for an unusual number of unrelated domains."""
        return {addr: names for addr, names in self._addr_to_domains.items()
                if len(names) >= SHARED_IP_DOMAIN_COUNT}

    def get_stats(self):
        return {
            'responses_seen': self.responses_seen,
            'nxdomain_seen': self.nxdomain_seen,
            'nxdomain_ratio': round(
                self.nxdomain_seen / self.responses_seen, 3) if self.responses_seen else 0.0,
            'domains_tracked': len(self._resolutions),
            'addresses_tracked': len(self._addr_to_domains),
            'hosts_with_failures': len(self._failures),
        }

    # ─── Housekeeping ────────────────────────────────────────────────────

    def _maybe_prune(self, now):
        if self._last_prune is None:
            self._last_prune = now
            return
        if now - self._last_prune < 120:
            return
        self._last_prune = now

        cutoff = now - FLUX_WINDOW_SEC
        stale = [name for name, e in self._resolutions.items()
                 if not e['addresses'] or max(e['addresses'].values()) < cutoff]
        for name in stale:
            del self._resolutions[name]

        fail_cutoff = now - NXDOMAIN_WINDOW_SEC * 4
        empty = [ip for ip, dq in self._failures.items()
                 if not dq or dq[-1][0] < fail_cutoff]
        for ip in empty:
            del self._failures[ip]

        for store in (self._reported_nxdomain, self._reported_flux):
            for key in [k for k, t in store.items()
                        if now - t > self._report_cooldown * 4]:
                del store[key]

        # Bounded regardless of traffic: a resolver under a flood would otherwise
        # grow this without limit.
        if len(self._addr_to_domains) > 50000:
            for addr in list(self._addr_to_domains)[:25000]:
                del self._addr_to_domains[addr]


def _looks_like_address(value):
    """True for an IPv4/IPv6 literal, false for a CNAME target."""
    if not isinstance(value, str):
        return False
    if ':' in value:
        return True
    parts = value.split('.')
    return len(parts) == 4 and all(p.isdigit() and len(p) <= 3 for p in parts)
