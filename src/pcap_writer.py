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
PCAP_SNAPLEN = 65535


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

        # Continuous recording state
        self._recording = False
        self._record_file = None
        self._record_path = None
        self._record_packets = 0
        self._record_start = 0
        self._max_file_mb = config.get('capture', 'pcap_max_file_mb', default=100)

        logger.info("PCAP writer initialized. Buffer: %d pkts, Max file: %d MB, Dir: %s",
                    buffer_size, self._max_file_mb, self.output_dir)

    def buffer_packet(self, raw_packet):
        """
        Add a raw packet to the ring buffer.
        Called from the capture thread — must be fast.

        Args:
            raw_packet: raw bytes of the captured packet (Ethernet frame)
        """
        if raw_packet:
            with self._lock:
                self._buffer.append((time.time(), raw_packet))

                # If continuous recording is active, write immediately
                if self._recording and self._record_file:
                    try:
                        self._write_packet_record(self._record_file, time.time(), raw_packet)
                        self._record_packets += 1

                        # Check file size for rotation
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

    def start_recording(self, filename=None):
        """Start continuous PCAP recording."""
        if self._recording:
            return self._record_path

        if filename is None:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"netsentinel_recording_{ts}.pcap"

        filepath = os.path.join(self.output_dir, filename)

        try:
            self._record_file = open(filepath, 'wb')
            self._write_pcap_header(self._record_file)
            self._record_path = filepath
            self._record_packets = 0
            self._record_start = time.time()
            self._recording = True
            logger.info("Started PCAP recording: %s", filepath)
            return filepath
        except Exception as e:
            logger.error("Failed to start recording: %s", e)
            return None

    def stop_recording(self):
        """Stop continuous recording and return stats."""
        if not self._recording:
            return None

        self._recording = False
        if self._record_file:
            try:
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
        """Rotate the recording file when it gets too large."""
        if self._record_file:
            self._record_file.close()

        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        new_path = os.path.join(self.output_dir, f"netsentinel_recording_{ts}.pcap")

        self._record_file = open(new_path, 'wb')
        self._write_pcap_header(self._record_file)
        self._record_path = new_path
        logger.info("Rotated PCAP recording to %s", new_path)

    @staticmethod
    def _write_pcap_header(f):
        """Write the PCAP global header."""
        header = struct.pack(
            '<IHHiIII',
            PCAP_MAGIC,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,                  # thiszone (GMT)
            0,                  # sigfigs
            PCAP_SNAPLEN,
            PCAP_LINKTYPE_ETHERNET,
        )
        f.write(header)

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
        for f in sorted(os.listdir(self.output_dir), reverse=True):
            if f.endswith('.pcap'):
                path = os.path.join(self.output_dir, f)
                files.append({
                    'filename': f,
                    'path': path,
                    'size_mb': round(os.path.getsize(path) / (1024 * 1024), 2),
                    'modified': datetime.fromtimestamp(
                        os.path.getmtime(path)
                    ).strftime('%Y-%m-%d %H:%M:%S'),
                })
        return files

    def cleanup(self):
        """Close any open files."""
        if self._recording:
            self.stop_recording()
