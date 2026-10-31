"""
PCAP Writer
=============
Exports captured packets to standard PCAP format for analysis
in Wireshark or other tools.

Features:
- Ring buffer: keeps the last N minutes of packets in memory
- On-demand export: save current buffer to .pcap file
- Continuous recording: write all packets to a rolling pcap file
- Auto-rotation: rotate files by size or time
"""

import os
import re
import struct
import time
import logging
import threading
from collections import deque
from datetime import datetime

logger = logging.getLogger("NetSentinel.PcapWriter")

# PCAP file format constants
PCAP_MAGIC = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_LINKTYPE_ETHERNET = 1
PCAP_LINKTYPE_RAW = 101       # Raw IP, no link layer
PCAP_LINKTYPE_NULL = 0        # BSD loopback
PCAP_SNAPLEN = 65535


# 802.1Q, 802.1ad (QinQ) and the old QinQ tag: 4 bytes each before the real type.
_VLAN_TAGS = (0x8100, 0x88a8, 0x9100)


def _frame_involves(frame, endpoints):
    """
    Cheap check for whether an Ethernet frame involves one of these IPv4/IPv6 hosts.

    Deliberately byte-level rather than a Scapy parse: this runs over the whole ring
    buffer when an alert fires, and re-parsing 150k frames would stall the caller.

    VLAN tags are skipped. A network that delivers tagged frames to this machine
    had every tagged packet fail the check, so alerts about them got a capture of
    all traffic instead of theirs. ARP is read too: without it an ARP alert's
    capture held everything but the ARP that raised it.
    """
    try:
        offset = 12
        ethertype = (frame[offset] << 8) | frame[offset + 1]
        while ethertype in _VLAN_TAGS:
            offset += 4
            ethertype = (frame[offset] << 8) | frame[offset + 1]
        ip = offset + 2
        if ethertype == 0x0806 and len(frame) >= ip + 28:           # ARP, IPv4 over Ethernet
            src = '.'.join(str(b) for b in frame[ip + 14:ip + 18])  # sender address
            dst = '.'.join(str(b) for b in frame[ip + 24:ip + 28])  # target address
        elif ethertype == 0x0800 and len(frame) >= ip + 20:          # IPv4
            src = '.'.join(str(b) for b in frame[ip + 12:ip + 16])
            dst = '.'.join(str(b) for b in frame[ip + 16:ip + 20])
        elif ethertype == 0x86dd and len(frame) >= ip + 40:        # IPv6
            import ipaddress
            src = str(ipaddress.IPv6Address(bytes(frame[ip + 8:ip + 24])))
            dst = str(ipaddress.IPv6Address(bytes(frame[ip + 24:ip + 40])))
        else:
            return False
        return src in endpoints or dst in endpoints
    except (IndexError, ValueError):
        return False


class PcapWriter:
    """
    Captures and exports packets to PCAP format.
    Maintains a ring buffer of recent raw packets for on-demand export.
    """

    def __init__(self, config, output_dir=None):
        self.config = config

        if output_dir is None:
            from src.config import APP_DIR
            output_dir = os.path.join(APP_DIR, "captures")
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        # Ring buffer: stores (timestamp, raw_bytes) tuples
        # Configurable via capture.pcap_buffer_packets (default 150000)
        # At 500 pps with 1500B avg, 150K packets ≈ 225 MB memory
        buffer_size = config.get('capture', 'pcap_buffer_packets', default=150000)
        self._buffer = deque(maxlen=buffer_size)
        self._lock = threading.Lock()
        # Separate from _lock so recording I/O never blocks buffer readers.
        self._record_lock = threading.RLock()

        # Continuous recording state
        self._recording = False
        self._record_file = None
        self._record_path = None
        self._record_packets = 0
        self._record_start = 0
        self._record_dir = self.output_dir
        self._record_budget = None      # bytes; None means prune by file count
        self._record_max_age = None     # seconds
        self._max_file_mb = config.get('capture', 'pcap_max_file_mb', default=100)
        self.link_type = config.get('capture', 'pcap_link_type',
                                    default=PCAP_LINKTYPE_ETHERNET)

        logger.info("PCAP writer initialized. Buffer: %d pkts, Max file: %d MB, Dir: %s",
                    buffer_size, self._max_file_mb, self.output_dir)

    def buffer_packet(self, raw_packet):
        """
        Add a raw packet to the ring buffer.
        Called from the capture thread — must be fast.

        Args:
            raw_packet: raw bytes of the captured packet (Ethernet frame)
        """
        if not raw_packet:
            return

        ts = time.time()
        with self._lock:
            self._buffer.append((ts, raw_packet))
            recording = self._recording and self._record_file is not None

        # File writes deliberately happen outside the buffer lock: this runs on the
        # capture thread, and holding the lock across disk I/O stalls every reader
        # (and the export path, which copies 150k entries) behind the filesystem.
        if recording:
            with self._record_lock:
                if not (self._recording and self._record_file):
                    return
                try:
                    self._write_packet_record(self._record_file, ts, raw_packet)
                    self._record_packets += 1
                    if self._record_file.tell() > self._max_file_mb * 1024 * 1024:
                        self._rotate_recording()
                except Exception as e:
                    logger.debug("PCAP write error: %s", e)

    def export_buffer(self, filename=None, last_minutes=5):
        """
        Export the ring buffer to a PCAP file.

        Args:
            filename: output filename (auto-generated if None)
            last_minutes: only export packets from the last N minutes

        Returns:
            str: path to the exported file, or None on failure
        """
        if filename is None:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"netsentinel_capture_{ts}.pcap"

        filepath = os.path.join(self.output_dir, filename)
        cutoff = time.time() - (last_minutes * 60)

        with self._lock:
            packets = [(ts, data) for ts, data in self._buffer if ts >= cutoff]

        if not packets:
            logger.warning("No packets in buffer to export")
            return None

        try:
            with open(filepath, 'wb') as f:
                self._write_pcap_header(f)
                for ts, raw in packets:
                    self._write_packet_record(f, ts, raw)

            size_mb = os.path.getsize(filepath) / (1024 * 1024)
            logger.info("Exported %d packets to %s (%.2f MB)",
                       len(packets), filepath, size_mb)
            return filepath

        except Exception as e:
            logger.error("Failed to export PCAP: %s", e)
            return None

    def export_for_alert(self, alert, seconds=60, directory=None):
        """
        Save the packets around an alert so it can be opened in Wireshark.

        The ring buffer already holds recent traffic, so the evidence for an alert
        is usually still in memory at the moment it fires — this just writes it out
        before it ages away. Returns the path, or None if there was nothing to save.

        With a directory (review mode), the file goes there and its caller prunes
        it; otherwise the newest pcap_max_alert_files are kept.
        """
        cutoff = time.time() - seconds
        endpoints = {ip for ip in (getattr(alert, 'src_ip', ''),
                                   getattr(alert, 'dst_ip', '')) if ip}

        with self._lock:
            candidates = [(ts, data) for ts, data in self._buffer if ts >= cutoff]

        if not candidates:
            return None

        # Narrow to the hosts involved when we can identify them; a scan or flood
        # alert is far easier to read without the rest of the network mixed in.
        packets = candidates
        if endpoints:
            focused = [(ts, data) for ts, data in candidates
                       if _frame_involves(data, endpoints)]
            if focused:
                packets = focused
            elif hasattr(alert, 'evidence'):
                # Say so: read as the alert's traffic, the rest of the network is
                # misleading.
                alert.evidence['packet_capture_scope'] = (
                    "everything in the window: no packet named the alert's hosts")

        safe_rule = re.sub(r'[^A-Za-z0-9_.-]', '_', str(getattr(alert, 'rule_id', 'alert')))
        filename = (f"alert_{safe_rule}_{getattr(alert, 'id', 0)}_"
                    f"{datetime.now():%Y%m%d_%H%M%S}.pcap")
        filepath = os.path.join(directory or self.output_dir, filename)

        try:
            with open(filepath, 'wb') as f:
                self._write_pcap_header(f)
                for ts, raw in packets:
                    self._write_packet_record(f, ts, raw)
            logger.info("Saved %d packets for %s to %s",
                        len(packets), safe_rule, filepath)
            if directory is None:
                self._prune_alert_captures()
            return filepath
        except OSError as e:
            logger.error("Could not save alert capture: %s", e)
            return None

    def _prune_alert_captures(self):
        """Cap how many per-alert captures accumulate on disk."""
        keep = self.config.get('capture', 'pcap_max_alert_files', default=50)
        try:
            files = [os.path.join(self.output_dir, f)
                     for f in os.listdir(self.output_dir)
                     if f.startswith('alert_') and f.endswith('.pcap')]
            files.sort(key=os.path.getmtime, reverse=True)
            for path in files[keep:]:
                os.remove(path)
        except OSError as e:
            logger.debug("Alert capture pruning error: %s", e)

    def start_recording(self, filename=None, directory=None, budget_bytes=None,
                        max_age_sec=None):
        """
        Start continuous PCAP recording.

        With a byte budget or a maximum age (review mode's rolling capture), old
        files in the directory are pruned by age, then by size, instead of by
        pcap_max_files.
        """
        if self._recording:
            return self._record_path

        if filename is None:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"netsentinel_recording_{ts}.pcap"

        self._record_dir = directory or self.output_dir
        self._record_budget = budget_bytes
        self._record_max_age = max_age_sec
        os.makedirs(self._record_dir, exist_ok=True)
        filepath = os.path.join(self._record_dir, filename)

        try:
            self._record_file = open(filepath, 'wb')
            self._write_pcap_header(self._record_file)
            self._record_path = filepath
            self._record_packets = 0
            self._record_start = time.time()
            self._recording = True
            logger.info("Started PCAP recording: %s", filepath)
            self._prune_old_captures()   # what the last run left over the budget
            return filepath
        except Exception as e:
            logger.error("Failed to start recording: %s", e)
            return None

    def stop_recording(self):
        """Stop continuous recording and return stats."""
        if not self._recording:
            return None

        with self._record_lock:
            self._recording = False
            if self._record_file:
                try:
                    self._record_file.flush()
                    os.fsync(self._record_file.fileno())
                    self._record_file.close()
                except Exception:
                    pass
                self._record_file = None

        duration = time.time() - self._record_start
        stats = {
            'filepath': self._record_path,
            'packets': self._record_packets,
            'duration_sec': int(duration),
            'size_mb': round(os.path.getsize(self._record_path) / (1024 * 1024), 2)
                       if self._record_path and os.path.exists(self._record_path) else 0,
        }
        logger.info("Stopped PCAP recording: %d packets in %ds", stats['packets'], stats['duration_sec'])
        return stats

    def _rotate_recording(self):
        """
        Rotate the recording file when it gets too large.

        Errors are contained here. Previously a failed open() left _record_file
        pointing at a closed handle while _recording stayed True, so every subsequent
        packet raised into a debug-level except and recording died silently forever.
        """
        old = self._record_file
        ts = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        new_path = os.path.join(self._record_dir, f"netsentinel_recording_{ts}.pcap")
        try:
            new_file = open(new_path, 'wb')
            self._write_pcap_header(new_file)
        except OSError as e:
            logger.error("PCAP rotation failed (%s); continuing in the current file.", e)
            return
        self._record_file = new_file
        self._record_path = new_path
        if old:
            try:
                old.close()
            except OSError:
                pass
        logger.info("Rotated PCAP recording to %s", new_path)
        self._prune_old_captures()

    def _prune_old_captures(self):
        """
        Keep the captures directory bounded.

        Continuous recording rotates every pcap_max_file_mb with no ceiling, so an
        unattended run will otherwise fill the disk.
        """
        keep = self.config.get('capture', 'pcap_max_files', default=20)
        try:
            files = [
                os.path.join(self._record_dir, f)
                for f in os.listdir(self._record_dir)
                if f.startswith('netsentinel_recording_') and f.endswith('.pcap')
            ]
            files.sort(key=os.path.getmtime, reverse=True)
            if self._record_budget is None and self._record_max_age is None:
                doomed = files[keep:]
            else:
                doomed = self._over_budget(files)
            for path in doomed:
                if path == self._record_path:
                    continue
                os.remove(path)
                logger.info("Pruned old capture %s", os.path.basename(path))
        except OSError as e:
            logger.debug("Capture pruning error: %s", e)

    def _over_budget(self, newest_first):
        """Files past the age limit, then the oldest until the rest fit the budget."""
        doomed, kept, total = [], [], 0
        now = time.time()
        for path in newest_first:
            size, mtime = os.path.getsize(path), os.path.getmtime(path)
            too_old = self._record_max_age and now - mtime > self._record_max_age
            too_big = self._record_budget and total + size > self._record_budget and kept
            if path != self._record_path and (too_old or too_big):
                doomed.append(path)
            else:
                kept.append(path)
                total += size
        return doomed

    def _write_pcap_header(self, f):
        """
        Write the PCAP global header.

        The link type must describe what was actually captured. Hardcoding Ethernet
        makes exports from loopback or raw-IP interfaces unreadable in Wireshark.
        """
        header = struct.pack(
            '<IHHiIII',
            PCAP_MAGIC,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,                  # thiszone (GMT)
            0,                  # sigfigs
            PCAP_SNAPLEN,
            self.link_type,
        )
        f.write(header)

    def set_link_type(self, link_type):
        """Record the DLT of the interface being captured (called by the app)."""
        self.link_type = int(link_type)

    @staticmethod
    def _write_packet_record(f, timestamp, raw_data):
        """Write a single packet record to the PCAP file."""
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)
        caplen = len(raw_data)
        origlen = caplen

        record_header = struct.pack('<IIII', ts_sec, ts_usec, caplen, origlen)
        f.write(record_header)
        f.write(raw_data)

    @property
    def is_recording(self):
        return self._recording

    def get_buffer_stats(self):
        """Return buffer statistics."""
        with self._lock:
            count = len(self._buffer)
            oldest = self._buffer[0][0] if self._buffer else 0
            newest = self._buffer[-1][0] if self._buffer else 0
        return {
            'buffer_packets': count,
            'buffer_span_sec': int(newest - oldest) if count > 0 else 0,
            'is_recording': self._recording,
            'recording_packets': self._record_packets if self._recording else 0,
            'recording_path': self._record_path if self._recording else None,
        }

    def get_capture_files(self):
        """List all PCAP files in the output directory."""
        files = []
        try:
            entries = sorted(os.listdir(self.output_dir), reverse=True)
        except OSError as e:
            logger.debug("Could not list captures: %s", e)
            return files
        for f in entries:
            if not f.endswith('.pcap'):
                continue
            path = os.path.join(self.output_dir, f)
            try:
                # Rotation/pruning can delete a file between listdir and stat.
                files.append({
                    'filename': f,
                    'path': path,
                    'size_mb': round(os.path.getsize(path) / (1024 * 1024), 2),
                    'modified': datetime.fromtimestamp(
                        os.path.getmtime(path)
                    ).strftime('%Y-%m-%d %H:%M:%S'),
                })
            except OSError:
                continue
        return files

    def cleanup(self):
        """Close any open files."""
        if self._recording:
            self.stop_recording()
