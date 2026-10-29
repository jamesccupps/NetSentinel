"""
What NetSentinel itself costs the machine.
==========================================
CPU, memory and threads of this process for the dashboard, and an option to run
below normal priority, so a busy desktop wins over the monitor watching it.

Lower priority is a trade: under load the capture falls behind sooner, and the
engine then samples packets (the dashboard's "sampling" figure) rather than
queueing them, so detection is thinner while that lasts.
"""

import logging
import os

logger = logging.getLogger("NetSentinel.Resources")

try:
    import psutil
except ImportError:  # pragma: no cover - psutil is a core dependency
    psutil = None


class ResourceMonitor:
    """Samples this process. Each snapshot covers the time since the last one."""

    def __init__(self):
        self._process = psutil.Process() if psutil else None
        self._cpus = (psutil.cpu_count() or 1) if psutil else 1
        if self._process is not None:
            self._process.cpu_percent(None)   # the first reading is always 0

    def snapshot(self):
        if self._process is None:
            return {'available': False}
        try:
            with self._process.oneshot():
                cpu = self._process.cpu_percent(None)
                rss = self._process.memory_info().rss
                threads = self._process.num_threads()
                priority = self._process.nice()
        except (psutil.Error, OSError) as e:
            logger.debug("Could not read process resources: %s", e)
            return {'available': False}
        return {
            'available': True,
            # Of the whole machine. psutil counts each core as 100%, which reads as
            # alarming on a many-core desktop when it is not.
            'cpu_percent': round(cpu / self._cpus, 1),
            'rss_bytes': rss,
            'threads': threads,
            'low_priority': _is_low(priority),
        }


def _is_low(priority):
    if os.name == 'nt':
        return priority in (psutil.BELOW_NORMAL_PRIORITY_CLASS, psutil.IDLE_PRIORITY_CLASS)
    return priority > 0


def set_low_priority():
    """
    Lower this process's CPU and I/O priority. Returns whether it worked.

    One way only: on Linux, raising priority back needs privileges the process
    should not have, so normal priority means not calling this.
    """
    if psutil is None:
        return False
    process = psutil.Process()
    try:
        if os.name == 'nt':
            process.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        else:
            process.nice(10)
    except (psutil.Error, OSError) as e:
        logger.warning("Could not lower NetSentinel's priority: %s", e)
        return False
    try:
        if os.name == 'nt':
            process.ionice(psutil.IOPRIO_LOW)
        elif hasattr(psutil, 'IOPRIO_CLASS_BE'):
            process.ionice(psutil.IOPRIO_CLASS_BE, 7)
    except (psutil.Error, OSError, AttributeError) as e:
        # CPU priority is the part that matters; disk priority is a bonus.
        logger.debug("Could not lower I/O priority: %s", e)
    logger.info("Running at lower priority.")
    return True
