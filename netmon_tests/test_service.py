"""
The sensor, running.
====================
The jobs are driven a tick at a time rather than by letting the loop run, so
their scheduling and their failure behaviour are testable without waiting.

Two properties this file is mostly about. One job failing must not stop the
others — the alternative is a sensor that goes quiet for a reason nobody
notices. And a restart must not re-analyse yesterday or re-alert on what was
already sent, because a service nobody dares restart is a service nobody
updates.
"""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import _test_support  # noqa: E402,F401

from netmon.service import (Service, ServiceConfig, _next_occurrence,  # noqa: E402
                            _Processed, _Tail)

try:
    from scapy.all import Dot1Q, Ether, IP, TCP, wrpcap
    import scapy.all as scapy
    HAVE_SCAPY = hasattr(scapy, 'PcapReader')
except Exception:                                              # pragma: no cover
    HAVE_SCAPY = False

requires_scapy = unittest.skipUnless(HAVE_SCAPY, 'needs a real scapy')

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')


class _ServiceCase(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-service-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.ring_dir = os.path.join(self.scratch, 'capture')
        self.state_dir = os.path.join(self.scratch, 'state')
        os.makedirs(self.ring_dir)

    def service(self, **overrides):
        settings = dict(profile_path=EXAMPLE, ring_dir=self.ring_dir,
                        state_dir=self.state_dir, notify=False)
        settings.update(overrides)
        config = ServiceConfig(**settings)
        config.web_port = None
        return Service(config, clock=lambda: 1000.0)

    def write_capture(self, name, packets=None, when=None):
        path = os.path.join(self.ring_dir, name)
        wrpcap(path, packets or [
            Ether(src='00:11:22:00:00:40', dst='00:aa:bb:cc:dd:ee')
            / Dot1Q(vlan=60) / IP(src='10.10.60.50', dst='10.10.20.21')
            / TCP(dport=22)])
        if when is not None:
            os.utime(path, (when, when))
        return path

    def capture_name(self, when):
        return time.strftime('netmon-%Y%m%d-%H%M%S.pcap', time.localtime(when))


# ─── Captures ────────────────────────────────────────────────────────────────

@requires_scapy
class TestAnalysingCaptures(_ServiceCase):

    def test_a_rotated_capture_is_analysed(self):
        now = time.time()
        self.write_capture(self.capture_name(now - 3600))
        self.write_capture(self.capture_name(now))        # still being written
        service = self.service()
        findings = service.analyse_new_captures()
        self.assertEqual(service.counts['captures'], 1)
        self.assertTrue(findings)

    def test_the_newest_file_is_left_alone(self):
        """
        tcpdump is still writing it. Analysing half a file would mean the other
        half is never looked at.
        """
        now = time.time()
        newest = self.write_capture(self.capture_name(now))
        service = self.service()
        service.analyse_new_captures()
        self.assertNotIn(newest, service.processed)

    def test_a_capture_is_analysed_once(self):
        now = time.time()
        self.write_capture(self.capture_name(now - 3600))
        self.write_capture(self.capture_name(now))
        service = self.service()
        self.assertTrue(service.analyse_new_captures())
        self.assertEqual(service.analyse_new_captures(), [])

    def test_a_restart_does_not_re_analyse(self):
        """A service nobody dares restart is a service nobody updates."""
        now = time.time()
        self.write_capture(self.capture_name(now - 3600))
        self.write_capture(self.capture_name(now))
        first = self.service()
        first.analyse_new_captures()
        second = self.service()
        self.assertEqual(second.analyse_new_captures(), [])

    def test_a_damaged_capture_does_not_stop_the_rest(self):
        now = time.time()
        with open(os.path.join(self.ring_dir,
                               self.capture_name(now - 7200)), 'wb') as handle:
            handle.write(b'not a capture')
        self.write_capture(self.capture_name(now - 3600))
        self.write_capture(self.capture_name(now))
        service = self.service()
        self.assertTrue(service.analyse_new_captures())
        self.assertEqual(service.counts['errors'], 1)

    def test_no_ring_directory_is_not_an_error(self):
        service = self.service(ring_dir='')
        self.assertEqual(service.analyse_new_captures(), [])


class TestProcessedState(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-processed-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.path = os.path.join(self.scratch, 'processed.json')
        self.sample = os.path.join(self.scratch, 'sample.pcap')
        with open(self.sample, 'w') as handle:
            handle.write('x' * 100)

    def test_it_remembers(self):
        processed = _Processed(self.path)
        processed.add(self.sample)
        self.assertIn(self.sample, _Processed(self.path))

    def test_a_file_that_grew_is_not_the_same_file(self):
        """
        Keyed by name and size, so a half-written capture that is later
        finished is analysed when it is finished rather than never.
        """
        processed = _Processed(self.path)
        processed.add(self.sample)
        with open(self.sample, 'a') as handle:
            handle.write('more')
        self.assertNotIn(self.sample, processed)

    def test_the_list_is_bounded(self):
        processed = _Processed(self.path, keep=10)
        for n in range(50):
            path = os.path.join(self.scratch, f'f{n}.pcap')
            with open(path, 'w') as handle:
                handle.write('x')
            processed.add(path)
        self.assertLessEqual(len(_Processed(self.path, keep=10)._seen), 10)

    def test_a_corrupt_state_file_is_a_fresh_start(self):
        with open(self.path, 'w') as handle:
            handle.write('not json')
        self.assertEqual(_Processed(self.path)._seen, [])

    def test_an_unwritable_state_directory_does_not_raise(self):
        """Failing to record progress is not a reason to stop working."""
        processed = _Processed('/proc/cannot/write/here.json')
        processed.add(self.sample)          # logs, does not raise


# ─── The canary log ──────────────────────────────────────────────────────────

class TestTailing(unittest.TestCase):

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-tail-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.path = os.path.join(self.scratch, 'canary.log')

    def append(self, *lines):
        with open(self.path, 'a') as handle:
            for line in lines:
                handle.write(line + '\n')

    def test_new_lines_are_read(self):
        self.append('one', 'two')
        tail = _Tail(self.path)
        self.assertEqual(list(tail.lines()), ['one', 'two'])

    def test_only_new_lines_on_the_next_pass(self):
        self.append('one')
        tail = _Tail(self.path)
        list(tail.lines())
        self.append('two')
        self.assertEqual(list(tail.lines()), ['two'])

    def test_a_half_written_line_is_left_for_next_time(self):
        self.append('complete')
        with open(self.path, 'a') as handle:
            handle.write('half')
        tail = _Tail(self.path)
        self.assertEqual(list(tail.lines()), ['complete'])
        with open(self.path, 'a') as handle:
            handle.write(' written\n')
        self.assertEqual(list(tail.lines()), ['half written'])

    def test_rotation_is_survived(self):
        """
        The path is the same name and a different file. Reading from the old
        offset would skip the start of the new one.
        """
        self.append('before rotation')
        tail = _Tail(self.path)
        list(tail.lines())
        os.remove(self.path)
        self.append('after rotation')
        with self.assertLogs('netmon.service', level='INFO'):
            self.assertEqual(list(tail.lines()), ['after rotation'])

    def test_rotation_is_caught_even_when_the_inode_is_reused(self):
        """
        Deleting a file and immediately recreating it very often reuses the
        same inode number — measurably so on the filesystems this runs on — so
        the inode alone is not enough.
        """
        self.append('x' * 300)
        tail = _Tail(self.path)
        list(tail.lines())
        before = os.stat(self.path).st_ino
        os.remove(self.path)
        self.append('y' * 300)
        self.assertEqual(os.stat(self.path).st_ino, before,
                         'this test only means something if the inode is reused')
        with self.assertLogs('netmon.service', level='INFO'):
            self.assertEqual(list(tail.lines()), ['y' * 300])

    def test_an_appending_file_is_not_mistaken_for_a_rotated_one(self):
        """The fingerprint must not fire on ordinary growth."""
        self.append('first line')
        tail = _Tail(self.path)
        list(tail.lines())
        for n in range(10):
            self.append(f'line {n}')
            self.assertEqual(list(tail.lines()), [f'line {n}'])

    def test_truncation_in_place_is_survived(self):
        self.append('a' * 100)
        tail = _Tail(self.path)
        list(tail.lines())
        with open(self.path, 'w') as handle:
            handle.write('short\n')
        self.assertEqual(list(tail.lines()), ['short'])

    def test_skip_to_end_means_a_restart_does_not_re_alert(self):
        self.append('old hit', 'another old hit')
        tail = _Tail(self.path)
        tail.skip_to_end()
        self.assertEqual(list(tail.lines()), [])
        self.append('new hit')
        self.assertEqual(list(tail.lines()), ['new hit'])

    def test_a_missing_file_yields_nothing(self):
        self.assertEqual(list(_Tail('/nonexistent.log').lines()), [])


class TestTailPositionSurvivesRestarts(unittest.TestCase):
    """
    Without this, `--once` from a cron entry would skip to the end on every
    invocation and never report a hit: the first run's "do not re-alert on the
    whole log" would apply to every run.
    """

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix='netmon-tailstate-')
        self.addCleanup(shutil.rmtree, self.scratch, True)
        self.path = os.path.join(self.scratch, 'canary.log')
        self.state = os.path.join(self.scratch, 'state', 'position.json')

    def append(self, *lines):
        with open(self.path, 'a') as handle:
            for line in lines:
                handle.write(line + '\n')

    def tail(self):
        return _Tail(self.path, self.state)

    def test_a_fresh_tail_has_nothing_to_resume(self):
        self.append('old')
        self.assertFalse(self.tail().resumed)

    def test_the_position_is_remembered(self):
        self.append('one')
        first = self.tail()
        first.skip_to_end()
        self.append('two')
        self.assertEqual(list(first.lines()), ['two'])

        second = self.tail()
        self.assertTrue(second.resumed)
        self.assertEqual(list(second.lines()), [])

    def test_a_hit_arriving_between_runs_is_reported_once(self):
        self.append('old')
        first = self.tail()
        first.skip_to_end()
        self.append('new hit')
        self.assertEqual(list(self.tail().lines()), ['new hit'])
        self.assertEqual(list(self.tail().lines()), [])

    def test_a_state_file_for_another_path_is_ignored(self):
        self.append('one')
        self.tail().skip_to_end()
        other = _Tail(os.path.join(self.scratch, 'elsewhere.log'), self.state)
        self.assertFalse(other.resumed)

    def test_a_corrupt_state_file_is_a_fresh_start(self):
        os.makedirs(os.path.dirname(self.state), exist_ok=True)
        with open(self.state, 'w') as handle:
            handle.write('not json')
        self.assertFalse(self.tail().resumed)

    def test_rotation_between_runs_is_caught(self):
        self.append('x' * 300)
        self.tail().skip_to_end()
        os.remove(self.path)
        self.append('y' * 300)
        self.assertEqual(list(self.tail().lines()), ['y' * 300])

    def test_an_unwritable_state_path_does_not_raise(self):
        tail = _Tail(self.path, '/proc/cannot/write/here.json')
        self.append('one')
        with self.assertLogs('netmon.service', level='WARNING'):
            self.assertEqual(list(tail.lines()), ['one'])


@requires_scapy
class TestCanaryJob(_ServiceCase):

    def test_hits_become_findings(self):
        log = os.path.join(self.scratch, 'canary.log')
        open(log, 'w').close()
        service = self.service(canary_log=log)
        with open(log, 'a') as handle:
            handle.write(json.dumps({
                'logtype': 4002, 'src_host': '10.10.60.99',
                'dst_host': '10.10.20.250', 'dst_port': 22,
                'logdata': {'USERNAME': 'root'}}) + '\n')
        findings = service.read_canary()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, 'canary_hit')

    def test_a_first_run_does_not_re_alert_on_the_whole_log(self):
        log = os.path.join(self.scratch, 'canary.log')
        with open(log, 'w') as handle:
            for _ in range(5):
                handle.write(json.dumps({'logtype': 4002,
                                         'src_host': '10.0.0.1'}) + '\n')
        self.assertEqual(self.service(canary_log=log).read_canary(), [])

    def test_but_a_later_run_reports_what_arrived_in_between(self):
        """
        Which is what makes `--once` usable from a cron entry: the backlog is
        skipped once, not on every invocation.
        """
        log = os.path.join(self.scratch, 'canary.log')
        with open(log, 'w') as handle:
            handle.write(json.dumps({'logtype': 4002,
                                     'src_host': '10.0.0.1'}) + '\n')
        self.service(canary_log=log).read_canary()          # skips the backlog
        with open(log, 'a') as handle:
            handle.write(json.dumps({'logtype': 9001,
                                     'src_host': '10.0.0.2'}) + '\n')
        findings = self.service(canary_log=log).read_canary()
        self.assertEqual(len(findings), 1)
        self.assertEqual(self.service(canary_log=log).read_canary(), [])

    def test_no_canary_log_is_not_an_error(self):
        self.assertEqual(self.service().read_canary(), [])


# ─── Scheduling and failure ──────────────────────────────────────────────────

@requires_scapy
class TestScheduling(_ServiceCase):

    def test_drift_runs_on_its_interval_not_every_tick(self):
        service = self.service(unifi_host='https://unreachable.invalid',
                               drift_interval=3600)
        calls = []
        service.check_drift = lambda: calls.append(1) or []
        service.tick(now=1000.0)
        service.tick(now=1100.0)
        self.assertEqual(len(calls), 1)
        service.tick(now=1000.0 + 3700)
        self.assertEqual(len(calls), 2)

    def test_a_failing_job_is_rescheduled_not_retried_every_poll(self):
        """An unreachable controller should not mean a request every 30s."""
        service = self.service(drift_interval=3600)
        calls = []

        def explode():
            calls.append(1)
            raise RuntimeError('unreachable')

        service.check_drift = explode
        service.tick(now=1000.0)
        service.tick(now=1100.0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(service.counts['errors'], 1)

    def test_one_job_failing_does_not_stop_the_others(self):
        """The alternative is a sensor that goes quiet for a reason nobody sees."""
        now = time.time()
        self.write_capture(self.capture_name(now - 3600))
        self.write_capture(self.capture_name(now))
        service = self.service()

        def explode():
            raise RuntimeError('boom')

        service.check_drift = explode
        service.read_canary = explode
        findings = service.tick()
        self.assertTrue(findings)
        self.assertEqual(service.counts['captures'], 1)
        self.assertEqual(service.counts['errors'], 2)

    def test_pruning_runs_on_its_own_interval(self):
        service = self.service(prune_interval=3600)
        calls = []
        service.prune = lambda: calls.append(1)
        service.tick(now=1000.0)
        service.tick(now=1100.0)
        self.assertEqual(len(calls), 1)

    def test_findings_are_collected_across_jobs(self):
        from netmon.events import Finding
        made = {name: Finding(name, 't', description=name)
                for name in ('a', 'b', 'c')}
        service = self.service()
        service.analyse_new_captures = lambda: [made['a']]
        service.read_canary = lambda: [made['b']]
        service.check_drift = lambda: [made['c']]
        self.assertEqual([f.rule_id for f in service.tick(now=1000.0)],
                         ['a', 'b', 'c'])


class TestDigestTiming(unittest.TestCase):

    def test_the_next_occurrence_is_today_if_it_has_not_happened(self):
        now = time.mktime(time.strptime('2026-10-13 03:00:00',
                                        '%Y-%m-%d %H:%M:%S'))
        nxt = _next_occurrence(now, 7)
        self.assertEqual(time.strftime('%Y-%m-%d %H', time.localtime(nxt)),
                         '2026-10-13 07')

    def test_and_tomorrow_if_it_has(self):
        now = time.mktime(time.strptime('2026-10-13 09:00:00',
                                        '%Y-%m-%d %H:%M:%S'))
        nxt = _next_occurrence(now, 7)
        self.assertEqual(time.strftime('%Y-%m-%d %H', time.localtime(nxt)),
                         '2026-10-14 07')


@requires_scapy
class TestDeliveryAndTheLiveView(_ServiceCase):

    def test_findings_are_kept_for_the_ui(self):
        from netmon.events import Finding
        service = self.service()
        service.analyse_new_captures = lambda: [
            Finding('r1', 't', description='a'), Finding('r2', 't', description='b')]
        service.tick(now=1000.0)
        self.assertEqual(len(service.recent), 2)

    def test_the_kept_list_is_bounded(self):
        from netmon.events import Finding
        service = self.service()
        service.deliver([Finding(f'r{n}', 't', description=str(n))
                         for n in range(5000)])
        self.assertLessEqual(len(service.recent), 2000)

    def test_without_a_notifier_findings_are_logged_not_lost(self):
        from netmon.events import Finding
        service = self.service(notify=False)
        self.assertIsNone(service.notifier)
        with self.assertLogs('netmon.service', level='INFO'):
            service.deliver([Finding('r', 'A title', description='something')])
        self.assertEqual(service.counts['findings'], 1)

    def test_the_live_view_presents_what_the_ui_expects(self):
        from netmon.events import Finding
        from netmon.service import _LiveView
        service = self.service()
        service.deliver([Finding('r', 't', severity='high', description='x'),
                         Finding('r2', 't', severity='low', description='y')])
        view = _LiveView(service)
        self.assertEqual([f.rule_id for f in view.by_severity()], ['r', 'r2'])
        self.assertEqual(view.report()['findings'], 2)


@requires_scapy
class TestOnePass(_ServiceCase):
    """`--once`, which is what a cron entry would use."""

    def test_a_single_tick_does_the_work_and_stops(self):
        now = time.time()
        self.write_capture(self.capture_name(now - 3600))
        self.write_capture(self.capture_name(now))
        service = self.service()
        findings = service.tick()
        self.assertTrue(findings)
        self.assertEqual(service.counts['captures'], 1)

    def test_a_second_pass_finds_nothing_new(self):
        now = time.time()
        self.write_capture(self.capture_name(now - 3600))
        self.write_capture(self.capture_name(now))
        service = self.service()
        service.tick()
        self.assertEqual(service.tick(), [])


class TestTheDispatcher(unittest.TestCase):

    def test_every_command_names_a_module_with_an_entry_point(self):
        import importlib
        from netmon.__main__ import COMMANDS
        for name, (module_name, description) in COMMANDS.items():
            with self.subTest(command=name):
                module = importlib.import_module(module_name)
                self.assertTrue(hasattr(module, '_main'),
                                f'{module_name} has no _main')
                self.assertTrue(description)

    def test_every_alias_points_at_a_real_command(self):
        from netmon.__main__ import ALIASES, COMMANDS
        for alias, target in ALIASES.items():
            with self.subTest(alias=alias):
                self.assertIn(target, COMMANDS)

    def test_no_arguments_prints_what_there_is(self):
        import io
        from contextlib import redirect_stdout
        from netmon.__main__ import main
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(main([]), 0)
        self.assertIn('Commands:', out.getvalue())
        self.assertIn('Start here', out.getvalue())

    def test_an_unknown_command_suggests_something(self):
        import io
        from contextlib import redirect_stderr
        from netmon.__main__ import main
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(main(['prof']), 2)
        self.assertIn('did you mean', err.getvalue())

    def test_a_command_is_dispatched(self):
        import io
        from contextlib import redirect_stdout
        from netmon.__main__ import main
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(['profile', EXAMPLE])
        self.assertEqual(code, 0)
        self.assertIn('valid', out.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
