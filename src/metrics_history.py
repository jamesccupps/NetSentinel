"""
Traffic history for the dashboard's charts.
===========================================
The charts drew only what the page had seen since it opened, so a fresh page
showed one point, and nothing said what a line stood for. This keeps the last
day: every 5 seconds, the capture's packet and byte counters and the alert
total, turned into rates from the change since the last sample. That is the
real average over the interval, every packet captured, before the analysis cap.

A gap (monitoring stopped, a counter reset by a restart of capture) is left as
a gap, not drawn as zero. Kept in memory only: a restart starts a new history.
"""

import math
import threading
import time
from collections import deque

INTERVAL_SEC = 5
KEEP_SEC = 24 * 3600
MAX_POINTS = 720


class MetricsHistory:
    """
    `source()` returns the current counters, or None while nothing is being
    captured: {'packets': total, 'bytes': total, 'alerts': total,
    'dropped': total}.
    """

    def __init__(self, source, interval=INTERVAL_SEC, keep_sec=KEEP_SEC, clock=time.time):
        self._source = source
        self.interval = interval
        self._clock = clock
        self._samples = deque(maxlen=int(keep_sec // interval) + 1)
        self._last = None          # (time, counters) of the previous reading
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def sample(self, now=None):
        """Take one reading. Returns the stored sample, or None for a gap."""
        now = self._clock() if now is None else now
        try:
            counters = self._source()
        except Exception:
            counters = None
        last, self._last = self._last, (now, counters) if counters else None
        if not counters or last is None:
            return None
        then, before = last
        elapsed = now - then
        deltas = {k: counters.get(k, 0) - before.get(k, 0)
                  for k in ('packets', 'bytes', 'alerts', 'dropped')}
        # A reset counter (capture restarted) or a stalled clock is a gap.
        if elapsed <= 0 or elapsed > 3 * self.interval or deltas['packets'] < 0:
            return None
        point = (now, deltas['packets'] / elapsed, deltas['bytes'] / elapsed,
                 max(0, deltas['alerts']), max(0, deltas['dropped']))
        with self._lock:
            self._samples.append(point)
        return point

    def series(self, minutes=60, max_points=MAX_POINTS, now=None):
        """
        The last `minutes`, in buckets of whole intervals so there are at most
        `max_points`: per bucket the time, the average and peak packet and byte
        rates, and the alerts raised and packets dropped.
        """
        now = self._clock() if now is None else now
        span = max(1, minutes) * 60
        bucket = self.interval * max(1, math.ceil(span / max_points / self.interval))
        start = now - span
        with self._lock:
            samples = [s for s in self._samples if s[0] > start]
        points, current = [], None
        for t, pps, bps, alerts, dropped in samples:
            key = int(t // bucket)
            if current is None or current[0] != key:
                if current is not None:
                    points.append(_close(current))
                current = [key, t, [], [], 0, 0]
            current[2].append(pps)
            current[3].append(bps)
            current[4] += alerts
            current[5] += dropped
        if current is not None:
            points.append(_close(current))
        return {'interval': self.interval, 'bucket_sec': bucket, 'from': start, 'to': now,
                'fields': ['t', 'pps', 'pps_peak', 'bps', 'bps_peak', 'alerts', 'dropped'],
                'points': points}

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name='MetricsHistory')
            self._thread.start()

    def stop(self):
        self._stop.set()

    def _run(self):
        while not self._stop.wait(self.interval):
            self.sample()


def _close(bucket):
    _, t, pps, bps, alerts, dropped = bucket
    return [round(t, 1), round(sum(pps) / len(pps), 2), round(max(pps), 2),
            round(sum(bps) / len(bps), 1), round(max(bps), 1), alerts, dropped]
