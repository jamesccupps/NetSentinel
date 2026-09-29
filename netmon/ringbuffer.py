"""
The rolling capture.
====================
A day or two of packets on disk, so that when a rule fires there is something to
look at. An alert that says "a controller was commanded at 03:14" is worth much
more with the thirty seconds around it attached.

    python -m netmon.ringbuffer --profile my-site.yaml --dir /var/lib/netmon/capture --command
    python -m netmon.ringbuffer --profile my-site.yaml --dir ... --extract 1790000051 --seconds 30

Why this supervises tcpdump rather than capturing itself
--------------------------------------------------------
At 5,000 packets a second — measured on this kind of mirror with one video
stream open — a Python capture loop is the wrong tool, and writing one would
mean reimplementing rotation, snap lengths and privilege dropping that libpcap
already does well. So netmon owns the policy (what to capture, what to keep, how
to get it back out) and tcpdump owns the plumbing. `capture_command()` prints
the exact invocation, filter included, to put in a unit file.

Restricted segments are excluded by the filter, not omitted from it
-------------------------------------------------------------------
A capture that happens not to select VLAN 40 is one edit away from selecting it.
The command this builds names the metadata-only segments in a `not` term, so
their payload cannot reach the disk whatever else the capture section says — and
extraction re-applies the same exclusion, because a file written last week
predates this week's profile.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import time

from netmon import bpf

logger = logging.getLogger("netmon.ringbuffer")

__all__ = ['RingBuffer', 'RingBufferError']


class RingBufferError(RuntimeError):
    """The capture directory or a file in it could not be used."""


#: tcpdump writes these with `-w <dir>/netmon-%Y%m%d-%H%M%S.pcap -G <seconds>`.
_FILENAME = re.compile(r'^netmon-(\d{8})-(\d{6})\.pcapn?g?$')
_PREFIX = 'netmon'


class RingBuffer:
    """
    A directory of rotating captures, with a retention policy and extraction.

    Nothing here captures packets. It decides what the capture should do, keeps
    the directory within its bounds, and pulls a window back out when a rule
    fires.
    """

    def __init__(self, directory, profile=None, hours=36, max_gb=200,
                 rotate_seconds=900, snaplen=2048, interface=''):
        self.directory = directory
        self.profile = profile
        self.hours = float(hours)
        self.max_bytes = int(float(max_gb) * 1024 ** 3)
        self.rotate_seconds = int(rotate_seconds)
        self.snaplen = int(snaplen)
        self.interface = interface or self._configured('interface', '')

    def _configured(self, key, default):
        capture = (getattr(self.profile, 'raw', {}) or {}).get('capture') or {}
        return capture.get(key, default)

    # ─── What to capture ─────────────────────────────────────────────────

    def filter_expression(self):
        """
        The capture filter, with the metadata-only segments excluded by name.

        Built from the profile so the exclusion cannot drift from the policy it
        implements.
        """
        if self.profile is None:
            return ''
        return bpf.from_profile(self.profile)

    def restricted_vlans(self):
        return sorted(getattr(self.profile, 'metadata_only_vlans', set()) or set())

    def capture_command(self, user='netmon'):
        """
        The exact tcpdump invocation, as a list of arguments.

        Printed rather than run: capture needs privileges this process should
        not have, and a unit file is where the decision belongs. Everything that
        matters is in the arguments — the filter, the snap length, the rotation,
        and dropping privileges after the socket is open.
        """
        if not self.interface:
            raise RingBufferError(
                'no capture interface. Set capture.interface in the profile, '
                'or pass --interface')

        pattern = os.path.join(self.directory, f'{_PREFIX}-%Y%m%d-%H%M%S.pcap')
        command = [
            'tcpdump', '-i', self.interface,
            '-w', pattern,
            '-G', str(self.rotate_seconds),
            '-s', str(self.snaplen),
            '-n',                          # no name lookups from the sensor
            '-Z', user,                    # drop privileges once the socket is open
            '--immediate-mode',
        ]
        expression = self.filter_expression()
        if expression:
            command.append(expression)
        return command

    def describe(self):
        """What the capture will and will not contain, in words."""
        restricted = self.restricted_vlans()
        lines = [
            f'interface       {self.interface or "(not set)"}',
            f'directory       {self.directory}',
            f'rotate every    {self.rotate_seconds}s',
            f'snap length     {self.snaplen} bytes',
            f'keep            {self.hours:g} hours, up to '
            f'{self.max_bytes / 1024 ** 3:.0f} GB',
        ]
        if restricted:
            lines.append('excluded        VLAN '
                         + ', '.join(str(v) for v in restricted)
                         + '  (metadata only — payload must not reach disk)')
        else:
            lines.append('excluded        nothing — no VLAN is marked '
                         'metadata-only in the profile')
        capture = (getattr(self.profile, 'raw', {}) or {}).get('capture') or {}
        if capture.get('drop_hosts') or capture.get('drop_ports'):
            lines.append(f"also dropped    hosts {capture.get('drop_hosts') or '-'}, "
                         f"ports {capture.get('drop_ports') or '-'}")
        return '\n'.join(lines)

    # ─── The directory ───────────────────────────────────────────────────

    def ensure_directory(self):
        """
        Create it owner-only. It holds packet payload.
        """
        os.makedirs(self.directory, exist_ok=True)
        try:
            os.chmod(self.directory, 0o700)
        except OSError as e:
            logger.warning('could not restrict %s: %s', self.directory, e)
        return self.directory

    def files(self):
        """Every capture in the directory, oldest first, with its start time."""
        if not os.path.isdir(self.directory):
            return []
        out = []
        for name in os.listdir(self.directory):
            path = os.path.join(self.directory, name)
            if not os.path.isfile(path):
                continue
            started = self._started_at(name, path)
            if started is None:
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            out.append({'path': path, 'name': name, 'started': started,
                        'size': size})
        return sorted(out, key=lambda f: f['started'])

    @staticmethod
    def _started_at(name, path):
        """
        When a capture began, from its name, falling back to its mtime.

        The name is authoritative because mtime moves as the file is written;
        a file still being written has an mtime of now and a name from an hour
        ago, and pruning by mtime would keep the wrong ones.
        """
        found = _FILENAME.match(name)
        if found:
            try:
                return time.mktime(time.strptime(found.group(1) + found.group(2),
                                                 '%Y%m%d%H%M%S'))
            except ValueError:
                pass
        if not name.endswith(('.pcap', '.pcapng')):
            return None
        try:
            return os.path.getmtime(path)
        except OSError:
            return None

    def status(self):
        files = self.files()
        total = sum(f['size'] for f in files)
        now = time.time()
        return {
            'directory': self.directory,
            'files': len(files),
            'bytes': total,
            'gigabytes': round(total / 1024 ** 3, 2),
            'oldest': files[0]['started'] if files else None,
            'newest': files[-1]['started'] if files else None,
            'hours_held': round((now - files[0]['started']) / 3600, 1)
            if files else 0.0,
            'within_retention': (not files
                                 or now - files[0]['started'] <= self.hours * 3600),
            'within_size': total <= self.max_bytes,
        }

    def prune(self, now=None, dry_run=False):
        """
        Delete what is past the retention window or over the size budget.

        Age first, then size, oldest first. The newest file is never deleted
        even when it alone exceeds the budget — it is the one being written, and
        removing it would leave the capture writing to a deleted inode with no
        error anywhere.
        """
        now = now if now is not None else time.time()
        files = self.files()
        removed, freed = [], 0

        cutoff = now - self.hours * 3600
        for entry in list(files):
            if entry['started'] < cutoff and len(files) > 1:
                if not dry_run:
                    self._remove(entry['path'])
                removed.append(entry['name'])
                freed += entry['size']
                files.remove(entry)

        total = sum(f['size'] for f in files)
        while total > self.max_bytes and len(files) > 1:
            entry = files.pop(0)
            if not dry_run:
                self._remove(entry['path'])
            removed.append(entry['name'])
            freed += entry['size']
            total -= entry['size']

        return {'removed': removed, 'freed_bytes': freed,
                'remaining': len(files)}

    @staticmethod
    def _remove(path):
        try:
            os.remove(path)
        except OSError as e:
            logger.warning('could not remove %s: %s', path, e)

    # ─── Getting a window back out ───────────────────────────────────────

    def files_covering(self, start, end):
        """
        The captures whose time range overlaps [start, end].

        A file covers from its own start until the next one begins, so the
        window is found by looking at neighbours rather than by reading any
        packets.
        """
        files = self.files()
        out = []
        for index, entry in enumerate(files):
            finishes = (files[index + 1]['started'] if index + 1 < len(files)
                        else float('inf'))
            if entry['started'] <= end and finishes >= start:
                out.append(entry)
        return out

    def extract(self, around, seconds=30, out_path=None, endpoints=()):
        """
        Write the packets near a timestamp to a new capture.

        This is what an alert links to. `endpoints` narrows it to the addresses
        involved, which usually turns a hundred thousand packets into a few
        dozen — the ones someone will actually read.

        The restricted-VLAN exclusion is applied again here. A file on disk was
        written under whatever profile was current at the time, and a segment
        marked metadata-only since then must not come back out.
        """
        try:
            from scapy.all import Dot1Q, PcapReader, PcapWriter
        except ImportError as e:
            raise RingBufferError(
                'scapy is needed to extract from the ring buffer') from e

        start, end = around - seconds / 2, around + seconds / 2
        sources = self.files_covering(start, end)
        if not sources:
            raise RingBufferError(
                f'nothing on disk covers {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(around))}'
                + (f'; the buffer holds {self.status()["hours_held"]:g} hours'
                   if self.files() else '; the buffer is empty'))

        if out_path is None:
            stamp = time.strftime('%Y%m%d-%H%M%S', time.localtime(around))
            out_path = os.path.join(self.directory, f'extract-{stamp}.pcap')

        wanted = {str(e) for e in endpoints if e}
        restricted = set(self.restricted_vlans())
        written = skipped_restricted = 0
        writer = None

        try:
            for entry in sources:
                try:
                    reader = PcapReader(entry['path'])
                except Exception as e:
                    logger.warning('skipping %s: %s', entry['name'], e)
                    continue
                with reader:
                    for packet in reader:
                        stamp = float(getattr(packet, 'time', 0) or 0)
                        if not start <= stamp <= end:
                            continue
                        if restricted:
                            tag = packet.getlayer(Dot1Q)
                            if tag is not None and int(tag.vlan) in restricted:
                                skipped_restricted += 1
                                continue
                        if wanted and not _involves(packet, wanted):
                            continue
                        if writer is None:
                            writer = PcapWriter(out_path, append=False, sync=False)
                        writer.write(packet)
                        written += 1
        finally:
            if writer is not None:
                writer.close()

        if written == 0:
            raise RingBufferError(
                'nothing matched in that window'
                + (f' for {", ".join(sorted(wanted))}' if wanted else ''))

        try:
            os.chmod(out_path, 0o600)
        except OSError:
            pass

        if skipped_restricted:
            logger.info('left out %d frames from metadata-only VLANs',
                        skipped_restricted)
        return {'path': out_path, 'packets': written,
                'from_files': [e['name'] for e in sources],
                'excluded_restricted': skipped_restricted,
                'window': [start, end]}

    def extract_for_finding(self, finding, seconds=30, out_path=None):
        """
        The window around one finding, narrowed to the addresses involved.

        The thing an alert links to. A finding with no event behind it — a
        digest entry, say — has no window to extract.
        """
        event = getattr(finding, 'event', None)
        if event is None:
            raise RingBufferError(f'{finding.rule_id} carries no packet to '
                                  f'extract around')
        endpoints = {event.src_ip, event.dst_ip} - {'', None}
        return self.extract(finding.ts, seconds, out_path, endpoints)


def _involves(packet, endpoints):
    """Whether a packet has one of these addresses at either end."""
    try:
        from scapy.all import ARP, IP, IPv6
    except ImportError:                                        # pragma: no cover
        return True
    for layer in (IP, IPv6):
        found = packet.getlayer(layer)
        if found is not None:
            return str(found.src) in endpoints or str(found.dst) in endpoints
    arp = packet.getlayer(ARP)
    if arp is not None:
        return str(arp.psrc) in endpoints or str(arp.pdst) in endpoints
    return False


def _main(argv=None):
    import argparse
    import json
    import sys

    from netmon.profile import ProfileError, load_profile

    parser = argparse.ArgumentParser(
        prog='python -m netmon.ringbuffer',
        description='Manage the rolling capture: what to run, what to keep, '
                    'and how to get a window back out.')
    parser.add_argument('--profile', required=True)
    parser.add_argument('--dir', required=True, help='the capture directory')
    parser.add_argument('--interface', default='', help='the capture interface')
    parser.add_argument('--hours', type=float, default=36)
    parser.add_argument('--max-gb', type=float, default=200)
    parser.add_argument('--rotate', type=int, default=900,
                        help='seconds per file (default 900)')
    parser.add_argument('--snaplen', type=int, default=2048)

    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--command', action='store_true',
                        help='print the tcpdump invocation to run')
    action.add_argument('--status', action='store_true')
    action.add_argument('--prune', action='store_true')
    action.add_argument('--extract', type=float, metavar='TIMESTAMP',
                        help='pull the window around this unix time')

    parser.add_argument('--seconds', type=float, default=30,
                        help='width of the extracted window')
    parser.add_argument('--host', action='append', default=[],
                        help='narrow the extract to this address; repeatable')
    parser.add_argument('--out', help='where to write the extract')
    parser.add_argument('--dry-run', action='store_true',
                        help='with --prune, say what would go')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    try:
        profile = load_profile(args.profile)
    except ProfileError as e:
        print(f'profile: {e}', file=sys.stderr)
        return 1

    ring = RingBuffer(args.dir, profile, hours=args.hours, max_gb=args.max_gb,
                      rotate_seconds=args.rotate, snaplen=args.snaplen,
                      interface=args.interface)

    if args.command:
        try:
            command = ring.capture_command()
        except RingBufferError as e:
            print(str(e), file=sys.stderr)
            return 1
        print(ring.describe())
        print()
        print('Run this as root, or from a unit file:')
        print()
        print('  ' + ' '.join(_quote(part) for part in command))
        print()
        if not ring.restricted_vlans():
            print('Note: no VLAN is marked metadata-only in the profile, so')
            print('nothing is excluded. If a segment carries credentials or')
            print('cardholder data, set store_payload: false on it first.')
        return 0

    if args.status:
        status = ring.status()
        print(json.dumps(status, indent=2) if args.json else
              '\n'.join(f'{k:18} {v}' for k, v in status.items()))
        return 0

    if args.prune:
        result = ring.prune(dry_run=args.dry_run)
        verb = 'would remove' if args.dry_run else 'removed'
        print(f"{verb} {len(result['removed'])} files, "
              f"{result['freed_bytes'] / 1024 ** 2:.0f} MB; "
              f"{result['remaining']} remain")
        for name in result['removed'][:20]:
            print(f'  - {name}')
        return 0

    try:
        result = ring.extract(args.extract, args.seconds, args.out, args.host)
    except RingBufferError as e:
        print(str(e), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2) if args.json else
          f"{result['packets']} packets -> {result['path']}"
          + (f" ({result['excluded_restricted']} frames from metadata-only "
             f"VLANs left out)" if result['excluded_restricted'] else ''))
    return 0


def _quote(part):
    return f"'{part}'" if ' ' in part or '(' in part else part


if __name__ == '__main__':
    import sys
    from netmon.ringbuffer import _main as main
    sys.exit(main())
