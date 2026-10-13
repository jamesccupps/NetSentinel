"""
The sensor, running.
====================
One process that does the recurring work: analyse each capture file as it
rotates, check the controller configuration on a schedule, follow the canary
log, push what needs attention and serve the UI.

    python -m netmon serve --profile my-site.yaml --ring /var/lib/netmon/capture

It does not capture packets — tcpdump does that, under its own unit, with the
filter `netmon capture --command` prints. Keeping them separate means a crash
here loses analysis and not the capture, which is the one thing that cannot be
reconstructed afterwards.

What it does, and how often
---------------------------
    capture files   each one, once, as soon as it stops being written
    drift           every few hours
    canary          follows the log, so hits arrive as they happen
    pruning         hourly, so the disk policy is enforced by the thing that
                    knows the policy
    digest          once a day

Each job is independent. One failing — the controller unreachable, the canary
log rotated out from under it — is logged and does not stop the others, because
the alternative is a sensor that goes quiet for a reason nobody notices.

Restarts
--------
What has been processed is kept on disk, so a restart does not re-analyse
yesterday or re-alert on what was already sent. The alternative is a service
nobody dares restart.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import threading
import time

logger = logging.getLogger("netmon.service")

__all__ = ['Service', 'ServiceConfig']


class ServiceConfig:
    """What to run and how often. Seconds throughout."""

    def __init__(self, profile_path, rules_path='', ring_dir='',
                 state_dir='', unifi_host='', unifi_fingerprint='',
                 unifi_ca='', unifi_insecure=False, unifi_site='default',
                 canary_log='', secrets='', web_host='127.0.0.1', web_port=0,
                 drift_interval=4 * 3600, prune_interval=3600,
                 digest_hour=7, poll_interval=30, notify=True, dry_run=False):
        self.profile_path = profile_path
        self.rules_path = rules_path
        self.ring_dir = ring_dir
        self.state_dir = state_dir or os.path.expanduser('~/.local/state/netmon')
        self.unifi_host = unifi_host
        self.unifi_fingerprint = unifi_fingerprint
        self.unifi_ca = unifi_ca
        self.unifi_insecure = unifi_insecure
        self.unifi_site = unifi_site
        self.canary_log = canary_log
        self.secrets = secrets
        self.web_host = web_host
        self.web_port = web_port
        self.drift_interval = int(drift_interval)
        self.prune_interval = int(prune_interval)
        self.digest_hour = int(digest_hour)
        self.poll_interval = int(poll_interval)
        self.notify = bool(notify)
        self.dry_run = bool(dry_run)

    @property
    def processed_path(self):
        return os.path.join(self.state_dir, 'processed.json')

    @property
    def drift_state_path(self):
        return os.path.join(self.state_dir, 'unifi-config.json')

    @property
    def canary_state_path(self):
        return os.path.join(self.state_dir, 'canary-position.json')


class _Processed:
    """
    What has already been handled, so a restart does not redo it.

    Keyed by name and size: a file still being written has a different size
    from the finished one, so this also stops a half-written capture being
    analysed and then never looked at again.
    """

    def __init__(self, path, keep=500):
        self.path = path
        self.keep = keep
        self._seen = self._load()

    def _load(self):
        try:
            with open(self.path, encoding='utf-8') as handle:
                return list(json.load(handle))
        except (OSError, json.JSONDecodeError, TypeError):
            return []

    def key(self, path):
        try:
            return f'{os.path.basename(path)}:{os.path.getsize(path)}'
        except OSError:
            return os.path.basename(path)

    def __contains__(self, path):
        return self.key(path) in self._seen

    def add(self, path):
        self._seen.append(self.key(path))
        del self._seen[:-self.keep]
        self.save()

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
            temporary = self.path + '.tmp'
            with open(temporary, 'w', encoding='utf-8') as handle:
                json.dump(self._seen, handle)
            os.replace(temporary, self.path)
        except OSError as e:
            logger.warning('could not record progress: %s', e)


class _Tail:
    """
    Follows a growing file, surviving rotation.

    When the canary rotates its log, the path is the same name and a different
    file, and reading from the old offset would skip the start of the new one.

    Rotation is detected by the inode *and* a fingerprint of the file's first
    bytes, because the inode alone is not enough: deleting a file and
    immediately recreating it very often reuses the same inode number, which is
    measurably what happens on the filesystems this runs on. Either changing
    means a new file.
    """

    #: How much of the start to fingerprint. Enough to differ between two logs,
    #: small enough to read on every pass without thinking about it.
    _FINGERPRINT_BYTES = 256

    def __init__(self, path, state_path=''):
        self.path = path
        self.state_path = state_path
        self._offset = 0
        self._inode = None
        self._fingerprint = None
        self.resumed = self._load()

    def _load(self):
        """
        Resume where the last run stopped.

        Without this, `--once` from a cron entry would skip to the end on every
        invocation and never report a hit — the first run's "do not re-alert on
        the whole log" would apply to every run.
        """
        if not self.state_path or not os.path.exists(self.state_path):
            return False
        try:
            with open(self.state_path, encoding='utf-8') as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return False
        if data.get('path') != self.path:
            return False
        self._offset = int(data.get('offset', 0))
        self._inode = data.get('inode')
        fingerprint = data.get('fingerprint')
        self._fingerprint = bytes.fromhex(fingerprint) if fingerprint else None
        return True

    def _save(self):
        if not self.state_path:
            return
        try:
            os.makedirs(os.path.dirname(self.state_path) or '.', exist_ok=True)
            temporary = self.state_path + '.tmp'
            with open(temporary, 'w', encoding='utf-8') as handle:
                json.dump({'path': self.path, 'offset': self._offset,
                           'inode': self._inode,
                           'fingerprint': self._fingerprint.hex()
                           if self._fingerprint else None}, handle)
            os.replace(temporary, self.state_path)
        except OSError as e:
            logger.warning('could not record the canary read position: %s', e)

    def _head(self):
        try:
            with open(self.path, 'rb') as handle:
                return handle.read(self._FINGERPRINT_BYTES)
        except OSError:
            return b''

    def lines(self):
        try:
            stat = os.stat(self.path)
        except OSError:
            return

        head = self._head()
        rotated = (self._inode is not None
                   and (stat.st_ino != self._inode
                        or (self._fingerprint is not None
                            and head != self._fingerprint
                            and not head.startswith(self._fingerprint)
                            and not self._fingerprint.startswith(head))))
        if rotated:
            logger.info('%s was rotated; following the new file',
                        os.path.basename(self.path))
            self._offset = 0

        self._inode = stat.st_ino
        if stat.st_size >= self._FINGERPRINT_BYTES or self._fingerprint is None:
            self._fingerprint = head

        if stat.st_size < self._offset:
            self._offset = 0                   # truncated in place
        if stat.st_size == self._offset:
            return

        try:
            with open(self.path, encoding='utf-8', errors='replace') as handle:
                handle.seek(self._offset)
                for line in handle:
                    if not line.endswith('\n'):
                        break                  # a half-written last line
                    self._offset += len(line.encode('utf-8', 'replace'))
                    yield line.strip()
        except OSError as e:
            logger.warning('could not read %s: %s', self.path, e)
        finally:
            self._save()

    def skip_to_end(self):
        """Start from now, so a restart does not re-alert on the whole log."""
        try:
            stat = os.stat(self.path)
        except OSError:
            return
        self._offset, self._inode = stat.st_size, stat.st_ino
        self._fingerprint = self._head()
        self._save()


class Service:
    """The recurring work, with each job independent of the others."""

    def __init__(self, config, clock=time.time):
        from netmon.profile import load_profile
        from netmon.rules_engine import load_rules

        self.config = config
        self._clock = clock
        self.profile = load_profile(config.profile_path)
        self.rules = load_rules(config.rules_path or None) if config.rules_path \
            else load_rules(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         'rules'))

        self.processed = _Processed(config.processed_path)
        self.canary = None
        if config.canary_log:
            self.canary = _Tail(config.canary_log, config.canary_state_path)
            if not self.canary.resumed:
                # Only on a first ever run. Skipping to the end every time
                # would mean `--once` from a cron entry never reports anything.
                self.canary.skip_to_end()

        self.ring = None
        if config.ring_dir:
            from netmon.ringbuffer import RingBuffer
            self.ring = RingBuffer(config.ring_dir, self.profile)

        self.notifier = self._build_notifier() if config.notify else None
        self.web = None

        self._stop = threading.Event()
        self._next = {'drift': 0.0, 'prune': 0.0, 'digest': 0.0}
        self.counts = {'captures': 0, 'findings': 0, 'pushed': 0,
                       'canary': 0, 'drift': 0, 'errors': 0}
        self.recent = []

    def _build_notifier(self):
        from netmon.alerting import AlertingError, Notifier, load_config
        try:
            alert_config = load_config(self.config.secrets)
            if self.config.dry_run:
                alert_config.dry_run = True
            alert_config.validate()
        except AlertingError as e:
            logger.warning('alerting is off: %s', e)
            return None
        return Notifier(alert_config, self.profile, ring=self.ring)

    # ─── Jobs ────────────────────────────────────────────────────────────

    def analyse_new_captures(self):
        """
        Each rotated capture, once.

        The newest file is skipped: tcpdump is still writing it, and analysing
        half a file would mean the other half is never looked at.
        """
        if self.ring is None:
            return []
        files = self.ring.files()
        findings = []
        for entry in files[:-1]:
            if entry['path'] in self.processed:
                continue
            findings.extend(self._analyse(entry['path']))
            self.processed.add(entry['path'])
            self.counts['captures'] += 1
        return findings

    def _analyse(self, path):
        from netmon.analyze import Analyzer
        from netmon.sources.pcap import PcapError, read_pcap

        analyzer = Analyzer(self.profile, self.rules)
        try:
            analyzer.feed(read_pcap(path, self.profile))
        except PcapError as e:
            logger.warning('could not read %s: %s', os.path.basename(path), e)
            self.counts['errors'] += 1
            return []
        logger.info('%s: %d events, %d findings', os.path.basename(path),
                    analyzer.events_seen, len(analyzer.findings))
        return analyzer.findings

    def check_drift(self):
        if not self.config.unifi_host:
            return []
        from netmon.drift import check
        from netmon.sources.unifi_api import UnifiApiError, UnifiClient

        try:
            client = UnifiClient(
                self.config.unifi_host, site=self.config.unifi_site,
                api_key=os.environ.get('UNIFI_API_KEY', ''),
                username=os.environ.get('UNIFI_USERNAME', ''),
                password=os.environ.get('UNIFI_PASSWORD', ''),
                fingerprint=self.config.unifi_fingerprint,
                ca_bundle=self.config.unifi_ca,
                insecure=self.config.unifi_insecure)
            client.login()
            findings, report = check(client, self.profile,
                                     self.config.drift_state_path)
        except UnifiApiError as e:
            # The controller being unreachable is a reason to look, not a reason
            # to stop analysing packets.
            logger.warning('configuration check failed: %s', e)
            self.counts['errors'] += 1
            return []
        self.counts['drift'] += report['changed']
        logger.info('configuration: %d standing, %d changed',
                    report['standing'], report['changed'])
        return findings

    def read_canary(self):
        if self.canary is None:
            return []
        from netmon.canary import finding_for, parse_event

        findings = []
        for line in self.canary.lines():
            record = parse_event(line)
            if record is not None:
                findings.append(finding_for(record, self.profile))
        if findings:
            self.counts['canary'] += len(findings)
            logger.warning('%d canary hits', len(findings))
        return findings

    def prune(self):
        if self.ring is None:
            return
        result = self.ring.prune()
        if result['removed']:
            logger.info('pruned %d capture files, %d MB',
                        len(result['removed']),
                        result['freed_bytes'] // (1024 * 1024))

    def send_digest(self):
        if self.notifier is None:
            return
        from netmon.alerting import build_digest

        class _Window:
            """The day's findings, in the shape the digest builder expects."""

            def __init__(self, findings, counts):
                self.findings = findings
                self.events_seen = counts['captures']

            def by_severity(self):
                from netmon.events import Severity
                return sorted(self.findings,
                              key=lambda f: -Severity.rank(f.severity))

            def report(self):
                from netmon.events import Severity
                by_severity = {}
                for finding in self.findings:
                    by_severity[finding.severity] = \
                        by_severity.get(finding.severity, 0) + 1
                return {'events': self.events_seen,
                        'findings': len(self.findings),
                        'by_severity': by_severity, 'suppressed_repeats': 0}

        window = _Window(list(self.recent), self.counts)
        try:
            self.notifier.send_digest(window)
            logger.info('digest sent: %d findings', len(window.findings))
        except Exception as e:
            logger.warning('could not send the digest: %s', e)
            self.counts['errors'] += 1
        self.recent.clear()

    # ─── Delivery ────────────────────────────────────────────────────────

    def deliver(self, findings):
        """Push what needs attention now; keep the rest for the digest."""
        if not findings:
            return
        self.counts['findings'] += len(findings)
        self.recent.extend(findings)
        del self.recent[:-2000]

        if self.notifier is None:
            for finding in findings:
                logger.info('[%s] %s', finding.severity, finding.description)
            return
        try:
            sent, _ = self.notifier.send(findings)
            self.counts['pushed'] += len(sent)
        except Exception as e:
            logger.warning('could not deliver: %s', e)
            self.counts['errors'] += 1

    # ─── The loop ────────────────────────────────────────────────────────

    def tick(self, now=None):
        """
        One pass. Separate from the loop so it can be driven by a test, and so
        a failure in one job cannot take out the others.
        """
        now = now if now is not None else self._clock()
        findings = []

        def run(name, job, schedule=None):
            """
            One job. A failure is logged and the rest continue — the
            alternative is a sensor that goes quiet for a reason nobody
            notices.
            """
            if schedule is not None and now < self._next[schedule]:
                return
            try:
                result = job()
            except Exception:
                logger.exception('%s failed; the other jobs continue', name)
                self.counts['errors'] += 1
                result = None
            finally:
                if schedule is not None:
                    # Rescheduled even on failure, so an unreachable controller
                    # does not mean retrying it every poll.
                    self._next[schedule] = now + getattr(
                        self.config, f'{schedule}_interval')
            if result:
                findings.extend(result)

        run('captures', self.analyse_new_captures)
        run('canary', self.read_canary)
        run('configuration', self.check_drift, schedule='drift')
        run('pruning', self.prune, schedule='prune')

        self.deliver(findings)

        if self._due_for_digest(now):
            self.send_digest()
            self._next['digest'] = now + 23 * 3600
        return findings

    def _due_for_digest(self, now):
        if self.notifier is None or now < self._next['digest']:
            return False
        if self._next['digest'] == 0.0:
            # Not on the first tick: a restart at 07:05 should not send a second
            # digest for a day that already had one.
            self._next['digest'] = _next_occurrence(now, self.config.digest_hour)
            return False
        return True

    def start_web(self):
        if self.config.web_port is None:
            return None
        from netmon.web import WebServer
        self.web = WebServer(self.config.profile_path, self.config.rules_path,
                             analyzer=_LiveView(self),
                             host=self.config.web_host,
                             port=self.config.web_port)
        port = self.web.start()
        logger.info('UI on http://%s:%d/', self.config.web_host, port)
        return port

    def run(self):
        """Loop until stopped. Returns the counts."""
        self.start_web()
        logger.info('netmon watching %s', self.profile.name)

        for name in ('SIGTERM', 'SIGINT'):
            if hasattr(signal, name):
                try:
                    signal.signal(getattr(signal, name),
                                  lambda *_: self._stop.set())
                except ValueError:
                    pass                       # not the main thread

        try:
            while not self._stop.is_set():
                self.tick()
                self._stop.wait(self.config.poll_interval)
        finally:
            if self.web is not None:
                self.web.stop()
            self.processed.save()
        logger.info('stopped: %s', self.counts)
        return self.counts

    def stop(self):
        self._stop.set()


class _LiveView:
    """The service's recent findings, in the shape the UI expects."""

    def __init__(self, service):
        self._service = service

    @property
    def findings(self):
        return self._service.recent

    @property
    def events_seen(self):
        return self._service.counts['captures']

    def by_severity(self):
        from netmon.events import Severity
        return sorted(self._service.recent,
                      key=lambda f: (-Severity.rank(f.severity), f.ts))

    def report(self):
        return dict(self._service.counts, findings=len(self._service.recent),
                    events=self._service.counts['captures'])


def _next_occurrence(now, hour):
    """The next time it is `hour` o'clock, local."""
    parts = time.localtime(now)
    today = time.mktime((parts.tm_year, parts.tm_mon, parts.tm_mday, hour, 0, 0,
                         0, 0, parts.tm_isdst))
    return today if today > now else today + 86400


def _main(argv=None):
    import argparse
    import sys

    from netmon.profile import ProfileError
    from netmon.rules_engine import RuleError

    parser = argparse.ArgumentParser(
        prog='python -m netmon serve',
        description='Run the recurring work: analyse rotated captures, check '
                    'the controller configuration, follow the canary log, push '
                    'alerts and serve the UI. It does not capture packets — '
                    'tcpdump does, under its own unit.')
    parser.add_argument('--profile', required=True)
    parser.add_argument('--rules', default='')
    parser.add_argument('--ring', default='', metavar='DIR',
                        help='the rolling capture directory')
    parser.add_argument('--state', default='', metavar='DIR',
                        help='where to keep progress between restarts')
    parser.add_argument('--canary-log', default='', metavar='FILE')
    parser.add_argument('--secrets', default='', metavar='FILE')

    unifi = parser.add_argument_group('controller')
    unifi.add_argument('--unifi-host', default='')
    unifi.add_argument('--unifi-site', default='default')
    unifi.add_argument('--fingerprint', default='')
    unifi.add_argument('--ca', default='')
    unifi.add_argument('--insecure', action='store_true')

    web = parser.add_argument_group('ui')
    web.add_argument('--web-host', default='127.0.0.1')
    web.add_argument('--web-port', type=int, default=8788)
    web.add_argument('--no-web', action='store_true')

    timing = parser.add_argument_group('schedule')
    timing.add_argument('--drift-interval', type=int, default=4 * 3600,
                        metavar='SEC')
    timing.add_argument('--digest-hour', type=int, default=7)
    timing.add_argument('--poll', type=int, default=30, metavar='SEC')

    parser.add_argument('--no-notify', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--once', action='store_true',
                        help='one pass and exit, for a cron entry or a check')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s %(levelname)-7s %(name)s: %(message)s')

    config = ServiceConfig(
        profile_path=args.profile, rules_path=args.rules, ring_dir=args.ring,
        state_dir=args.state, unifi_host=args.unifi_host,
        unifi_fingerprint=args.fingerprint, unifi_ca=args.ca,
        unifi_insecure=args.insecure, unifi_site=args.unifi_site,
        canary_log=args.canary_log, secrets=args.secrets,
        web_host=args.web_host,
        web_port=None if args.no_web or args.once else args.web_port,
        drift_interval=args.drift_interval, digest_hour=args.digest_hour,
        poll_interval=args.poll, notify=not args.no_notify,
        dry_run=args.dry_run)

    try:
        service = Service(config)
    except (ProfileError, RuleError) as e:
        print(str(e), file=sys.stderr)
        return 1

    if args.once:
        findings = service.tick()
        print(f'{len(findings)} findings; {service.counts}')
        return 2 if findings else 0

    try:
        service.run()
    except KeyboardInterrupt:
        service.stop()
    return 0


if __name__ == '__main__':
    import sys
    from netmon.service import _main as main
    sys.exit(main())
