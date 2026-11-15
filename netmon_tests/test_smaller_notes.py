"""
The outside review's smaller notes on netmon (2026-11-14).
==========================================================
Each is small; each has a case here.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLE = os.path.join(ROOT, 'netmon', 'profiles', 'example-site.yaml')
RULES = os.path.join(ROOT, 'netmon', 'rules')


class TestWebErrors(unittest.TestCase):

    def test_a_failure_tells_the_log_not_the_caller(self):
        from netmon.web import WebServer
        server = WebServer(EXAMPLE, RULES, None, host='127.0.0.1', port=0)
        base = f'http://127.0.0.1:{server.start()}'
        self.addCleanup(server.stop)

        def broken(params):
            raise RuntimeError('/etc/netmon/secrets.yaml has no key')
        server.routes['/api/findings'] = broken
        with self.assertLogs('netmon', level='ERROR'), \
                self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(base + '/api/findings', timeout=5)
        body = json.loads(ctx.exception.read())
        self.assertEqual(body, {'error': 'internal error'})


class TestNtfy(unittest.TestCase):

    def test_the_public_server_needs_a_token_however_it_is_written(self):
        from netmon.alerting import AlertingError, NotifierConfig
        for server in ('https://ntfy.sh', 'https://ntfy.sh:443', 'https://www.ntfy.sh',
                       'https://ntfy.sh.', 'https://user@ntfy.sh/'):
            with self.subTest(server=server), self.assertRaises(AlertingError):
                NotifierConfig(enabled=True, server=server, topic='t').validate()

    def test_a_server_of_ones_own_does_not(self):
        from netmon.alerting import NotifierConfig
        self.assertTrue(NotifierConfig(enabled=True, server='https://ntfy.example.org',
                                       topic='t').validate())


class TestUnifi(unittest.TestCase):

    def test_plain_http_is_refused_unless_insecure(self):
        from netmon.sources.unifi_api import UnifiApiError, UnifiClient
        with self.assertRaises(UnifiApiError):
            UnifiClient('http://192.168.10.1', api_key='k', opener=object())
        UnifiClient('http://192.168.10.1', api_key='k', insecure=True, opener=object())
        UnifiClient('192.168.10.1', api_key='k', opener=object())        # https by default

    @unittest.skipIf(os.name == 'nt', 'POSIX file modes')
    def test_state_files_are_owner_only_from_the_start(self):
        from netmon.sources.unifi_api import _private_open
        folder = tempfile.mkdtemp(prefix='netmon_private_')
        self.addCleanup(shutil.rmtree, folder, True)
        path = os.path.join(folder, 'x.tmp')
        with _private_open(path) as f:
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            f.write('{}')


class TestRules(unittest.TestCase):

    def test_a_bad_pattern_fails_at_load(self):
        from netmon.rules_engine import Rule, RuleError
        with self.assertRaises(RuleError) as ctx:
            Rule({'id': 'r', 'title': 't', 'severity': 'low', 'tier': 'digest',
                  'when': {'sni': {'matches': 'anydesk('}}})
        self.assertIn('bad pattern', str(ctx.exception))


class TestBpf(unittest.TestCase):

    def test_two_groups_joined_keep_their_grouping(self):
        from netmon.bpf import combine
        self.assertEqual(combine('(vlan 5) or (vlan 6)', 'tcp port 443'),
                         '((vlan 5) or (vlan 6)) and (tcp port 443)')
        self.assertEqual(combine('(vlan 5 or vlan 6)', 'udp'), '(vlan 5 or vlan 6) and udp')


class TestRingBuffer(unittest.TestCase):

    def test_two_extracts_in_one_second_do_not_overwrite(self):
        from netmon_tests._support import HAVE_SCAPY
        if not HAVE_SCAPY:
            self.skipTest('scapy is needed to extract')
        import time
        from scapy.all import IP, TCP, Ether, wrpcap
        from netmon.profile import SiteProfile
        from netmon.ringbuffer import RingBuffer
        folder = tempfile.mkdtemp(prefix='netmon_extract_')
        self.addCleanup(shutil.rmtree, folder, True)
        now = time.time()
        frame = Ether(src='00:00:5e:00:53:01', dst='00:00:5e:00:53:02') / \
            IP(src='10.10.20.10', dst='10.10.20.21') / TCP(sport=1, dport=2)
        frame.time = now
        stamp = time.strftime('%Y%m%d-%H%M%S', time.localtime(now - 60))
        wrpcap(os.path.join(folder, f'netmon-{stamp}.pcap'), [frame])
        ring = RingBuffer(folder, SiteProfile({}), interface='mirror0')
        first = ring.extract(now, seconds=30)
        second = ring.extract(now, seconds=30)
        self.assertNotEqual(first['path'] if isinstance(first, dict) else first,
                            second['path'] if isinstance(second, dict) else second)


class TestOsBuild(unittest.TestCase):

    def test_one_insider_pc_does_not_put_the_site_behind(self):
        from netmon.events import Event
        from netmon.handlers import os_build

        class Rule:
            id, title, severity, tier, next_check = 'os_support', 't', 'low', 'weekly', ''
            params = {'unsupported_builds': [], 'minimum_build': 0}
        state = {}
        found = []
        for i, build in enumerate([26100, 26100, 26100, 27900, 26100]):   # one Insider PC
            result = os_build(Event(kind='flow', src_ip=f'10.10.60.{i + 1}',
                                    fields={'os_build': build}), Rule(), state)
            if result:
                found.append(result.evidence['os_build'])
        self.assertEqual(found, [])
        lagging = os_build(Event(kind='flow', src_ip='10.10.60.40', fields={'os_build': 22631}),
                           Rule(), state)
        self.assertIsNotNone(lagging)
        self.assertIn('most run 26100', lagging.description)


if __name__ == '__main__':
    unittest.main()
