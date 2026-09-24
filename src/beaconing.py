"""
Beaconing / periodicity scoring.
=================================
Detects a host checking in with a destination on a schedule — the shape of C2
traffic, and also of perfectly innocent polling, which is why this returns a
score and its components rather than a verdict.

Why not just measure the coefficient of variation
--------------------------------------------------
The previous rule flagged a destination when `std(intervals) / mean(intervals)`
fell below 0.05. Measured against synthetic beacons, that catches a beacon with
no jitter and essentially nothing else:

    jitter    median CV    caught by CV < 0.05
      0%        0.000            100%
     10%        0.057              5%      <- Cobalt Strike's default is 0-10%
     20%        0.115              0%      <- Sliver, Mythic typical
     50%        0.285              0%

Every mainstream C2 framework ships with jitter enabled, so the rule only ever
caught naive scripts.

What this uses instead
----------------------
Three properties that survive jitter, scored 0-1 and combined:

- **Symmetry** (Bowley skewness of the intervals). Jitter is symmetric around
  the base interval, so a beacon stays near zero skew however much of it there
  is. Human and application traffic is strongly right-skewed: long idle gaps
  with short bursts inside them.
- **Dispersion** (median absolute deviation over the median). Robust to the
  occasional missed check-in in a way that standard deviation is not. Scaled so
  that random (exponentially distributed) arrivals score zero.
- **Volume consistency**. C2 check-ins carry near-identical payloads — an empty
  "any work for me?" and its reply. Bulk transfers and browsing do not. This is
  the component that separates a beacon from a polling app, so it is weighted
  accordingly.

What this deliberately does NOT do
-----------------------------------
Decide whether a beacon is malicious. NTP polling scores 0.90 here, and it should
— it is a beacon by every structural measure available from timing and volume.
Nothing in the arrival series distinguishes a C2 check-in from a legitimate
scheduled poll, and a scorer that claimed otherwise would be lying.

Separating the two needs context the caller has and this module does not: the
destination port (a well-known service), whether the destination was already
beaconing during baseline learning, and threat intel. `is_expected_periodic`
covers the first of those; the caller supplies the rest.

Thresholds are calibrated in test_beaconing.py against synthetic beacons at
several jitter levels, Poisson arrivals, bursty browsing and NTP-style polling.
"""

import logging
import math

logger = logging.getLogger("NetSentinel.Beaconing")

__all__ = ['score_beacon', 'bowley_skewness', 'mad_ratio', 'is_expected_periodic',
           'MIN_OBSERVATIONS', 'BENIGN_PERIODIC_PORTS']

# Below this there is not enough signal to distinguish a schedule from luck.
MIN_OBSERVATIONS = 12

# Intervals outside this range are not C2-relevant: sub-second is streaming or a
# websocket, and beyond an hour there is rarely enough history to judge.
MIN_INTERVAL_SEC = 1.0
MAX_INTERVAL_SEC = 3600.0

# MAD/median at or above this is treated as unstructured. Exponentially
# distributed (i.e. random) arrivals sit near 1.0; a beacon with 50% jitter sits
# near 0.25.
DISPERSION_CEILING = 0.60

# How the components combine. Volume consistency carries the most weight because
# it is what separates a C2 check-in from an application that legitimately polls.
WEIGHTS = {
    'symmetry': 0.25,
    'dispersion': 0.35,
    'volume': 0.30,
    'observations': 0.10,
}


# Services whose whole job is to poll on a schedule. Traffic to these is expected
# to look exactly like a beacon, so periodicity alone carries no information.
BENIGN_PERIODIC_PORTS = frozenset({
    123,        # NTP
    53,         # DNS (resolvers retry and refresh on timers)
    67, 68,     # DHCP lease renewal
    161, 162,   # SNMP polling
    514,        # syslog
    5353,       # mDNS announcements
    1900,       # SSDP
    323,        # PTP
    319, 320,   # PTP event/general
})


def is_expected_periodic(dst_port=0, src_port=0):
    """
    True when this destination is a service that is supposed to be periodic.

    Timing analysis cannot distinguish these from C2, so the caller should not
    raise on periodicity alone.
    """
    return dst_port in BENIGN_PERIODIC_PORTS or src_port in BENIGN_PERIODIC_PORTS


def _median(values):
    ordered = sorted(values)
    n = len(ordered)
    if not n:
        return 0.0
    mid = n // 2
    if n % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _quartiles(values):
    """Q1, Q2, Q3 by the midpoint method — no numpy needed on the packet path."""
    ordered = sorted(values)
    n = len(ordered)
    if n < 4:
        m = _median(ordered)
        return m, m, m
    mid = n // 2
    lower = ordered[:mid]
    upper = ordered[mid + 1:] if n % 2 else ordered[mid:]
    return _median(lower), _median(ordered), _median(upper)


def bowley_skewness(values):
    """
    Quartile-based skewness in [-1, 1]. Zero means symmetric.

    Preferred over the moment-based measure because it is not dragged around by
    a single very long gap, which any real capture will contain.
    """
    q1, q2, q3 = _quartiles(values)
    spread = q3 - q1
    if spread <= 0:
        return 0.0
    return (q3 + q1 - 2 * q2) / spread


def mad_ratio(values):
    """Median absolute deviation divided by the median. 0 = perfectly regular."""
    med = _median(values)
    if med <= 0:
        return 1.0
    return _median([abs(v - med) for v in values]) / med


def _clamp01(value):
    return max(0.0, min(1.0, value))


def score_beacon(timestamps, sizes=None):
    """
    Score how strongly a series of arrival times looks scheduled.

    Args:
        timestamps: arrival times in seconds. Need not be sorted.
        sizes: matching payload sizes, if known. Without them the volume
            component is neutral (0.5) rather than absent, so a destination is
            not penalised for information we simply did not collect.

    Returns a dict with `score` (0-1), the component scores, `interval` (the
    estimated period), and `reason` — a short phrase for the alert evidence.
    A score of 0 means "not enough evidence" as well as "not a beacon"; check
    `qualified`.
    """
    result = {
        'score': 0.0,
        'qualified': False,
        'interval': 0.0,
        'observations': len(timestamps) if timestamps else 0,
        'symmetry': 0.0,
        'dispersion': 0.0,
        'volume': 0.0,
        'deviation_pct': 0.0,
        'reason': 'insufficient observations',
    }

    if not timestamps or len(timestamps) < MIN_OBSERVATIONS:
        return result

    ordered = sorted(timestamps)
    intervals = [b - a for a, b in zip(ordered, ordered[1:]) if b > a]
    if len(intervals) < MIN_OBSERVATIONS - 1:
        result['reason'] = 'too few distinct arrivals'
        return result

    median_interval = _median(intervals)
    result['interval'] = median_interval

    if median_interval < MIN_INTERVAL_SEC:
        result['reason'] = f'interval {median_interval:.2f}s too short to be a beacon'
        return result
    if median_interval > MAX_INTERVAL_SEC:
        result['reason'] = f'interval {median_interval:.0f}s beyond the scored range'
        return result

    dispersion = mad_ratio(intervals)
    skew = bowley_skewness(intervals)

    result['qualified'] = True
    result['deviation_pct'] = dispersion * 100.0
    result['symmetry'] = _clamp01(1.0 - abs(skew))
    result['dispersion'] = _clamp01(1.0 - dispersion / DISPERSION_CEILING)
    result['volume'] = _score_volume(sizes)
    result['observations_score'] = _score_observations(len(intervals))

    result['score'] = round(
        WEIGHTS['symmetry'] * result['symmetry'] +
        WEIGHTS['dispersion'] * result['dispersion'] +
        WEIGHTS['volume'] * result['volume'] +
        WEIGHTS['observations'] * result['observations_score'], 4)
    result['reason'] = _describe(result)
    return result


def _score_volume(sizes):
    """
    How consistent the payload sizes are. 0.5 (neutral) when unknown.

    Identical sizes are the clearest beacon signature: a check-in carries the
    same nearly-empty request every time.
    """
    if not sizes:
        return 0.5
    usable = [s for s in sizes if s and s > 0]
    if len(usable) < MIN_OBSERVATIONS // 2:
        return 0.5
    return _clamp01(1.0 - mad_ratio(usable) / DISPERSION_CEILING)


def _score_observations(count):
    """More check-ins, more confidence. Saturates once a schedule is obvious."""
    if count <= 0:
        return 0.0
    return _clamp01(math.log(count + 1) / math.log(60))


def _describe(result):
    interval = result['interval']
    if interval >= 60:
        period = f"{interval / 60:.1f} min"
    else:
        period = f"{interval:.1f} s"
    # Median deviation, not the peak-to-peak jitter a C2 operator configures:
    # ±10% configured jitter shows up here as roughly ±5%.
    parts = [f"every ~{period}",
             f"{result['deviation_pct']:.0f}% median deviation",
             f"{result['observations']} check-ins"]
    if result['volume'] >= 0.8:
        parts.append("near-identical payload sizes")
    return ', '.join(parts)
