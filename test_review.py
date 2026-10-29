"""
Review mode and its bundles.
=============================
The bundle leaves the machine, so most of these check what is never written:
query strings, cookies, credentials, tokens, user names in paths and, when asked,
LAN addresses. The rest check that what a reviewer needs is there, and that a
verdict coming back stops the alert it was about, and nothing else.

All traffic here is synthetic.
"""

import json
import os
import queue
import shutil
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import SCAPY_REAL  # noqa: E402

from src.app import NetSentinelApp  # noqa: E402
from src.baseline_whitelist import (BaselineWhitelist, ConfirmedFalsePositives,  # noqa: E402
                                    alert_subjects)
from src.config import Config  # noqa: E402
from src.ids_engine import Alert  # noqa: E402
from src.pcap_writer import PcapWriter  # noqa: E402
from src.public_suffix import registrable_domain  # noqa: E402
from src.review import (Pseudonymiser, ReviewRecorder, _Redactor, build_bundle,  # noqa: E402
                        import_verdicts, read_alerts, review_id)

SECRETS = ('Hunter2Secret', 'SECRETCOOKIE123', 'Zm9vOmJhcg', 'sessionid', 'pass=',
           'eyJhbGciOiJIUzI1NiJ9')


def record(rule, src, dst, severity='HIGH', ts=None, snippet=None, **evidence):
    alert = Alert(rule, severity, f'{rule} title', f'{rule} description',
                  src_ip=src, dst_ip=dst, dst_port=443, protocol='TCP',
                  category='Test', evidence=evidence)
    if ts is not None:
        alert.timestamp = ts
    r = alert.to_dict()
    r['review_id'] = review_id(alert)
    if snippet:
        r['snippet'] = snippet
    return r


def write_jsonl(directory, records):
    with open(os.path.join(directory, 'alerts.jsonl'), 'w', encoding='utf-8') as f:
        for r in records:
            f.write(json.dumps(r) + '\n')


def write_snippet(path):
    """A capture with a DNS lookup, a TLS hello, an HTTP request with secrets, and ARP."""
    from scapy.all import ARP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap
    from test_tls import build_client_hello
    lan, gw, web, shop = '192.168.1.20', '192.168.1.1', '203.0.113.7', '203.0.113.8'
    mac = 'aa:bb:cc:dd:ee:01'
    http = (b'GET /login?user=bob&pass=Hunter2Secret HTTP/1.1\r\n'
            b'Host: shop.example.com\r\nCookie: sessionid=SECRETCOOKIE123\r\n'
            b'Authorization: Basic Zm9vOmJhcg==\r\n\r\n')
    packets = [
        Ether(src=mac) / IP(src=lan, dst=gw) / UDP(sport=50000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname='bad.example.org')),
        Ether(dst=mac) / IP(src=gw, dst=lan) / UDP(sport=53, dport=50000)
        / DNS(qr=1, qd=DNSQR(qname='bad.example.org'),
              an=DNSRR(rrname='bad.example.org', rdata=web)),
        Ether(src=mac) / IP(src=lan, dst=web) / TCP(sport=50001, dport=443, flags='PA')
        / Raw(load=build_client_hello(sni=b'bad.example.org')),
        Ether(src=mac) / IP(src=lan, dst=shop) / TCP(sport=50002, dport=80, flags='PA')
        / Raw(load=http),
        Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, psrc=lan, hwsrc=mac, pdst=gw),
    ]
    for n, p in enumerate(packets):
        p.time = 1_790_000_000 + n
    wrpcap(path, packets)


def bundle_text(folder):
    out = []
    for root, _, files in os.walk(folder):
        for f in files:
            if f.endswith('.pcap'):
                continue
            with open(os.path.join(root, f), encoding='utf-8') as fh:
                out.append(fh.read())
    return '\n'.join(out)


class TestRedaction(unittest.TestCase):

    def test_query_strings_cookies_and_tokens_never_reach_the_text(self):
        text = _Redactor().text(
            'GET https://a.example/x?token=abc&u=1 then Cookie: sid=1 and '
            'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghijkl, password=Hunter2Secret')
        self.assertIn('https://a.example/x?[query removed]', text)
        for leak in ('token=abc', 'sid=1', 'eyJhbGci', 'Hunter2Secret'):
            self.assertNotIn(leak, text)

    def test_evidence_keys_that_hold_secrets_are_dropped(self):
        out = _Redactor().evidence({
            'value': 'Hu**********', 'cookie': 'x', 'session_id': 'x', 'api_key': 'x',
            'tls_sni': 'ok.example', 'extra': {'url': 'http://h.example/p?x=1', 'host': 'h'},
        })
        self.assertEqual(set(out), {'tls_sni', 'extra'})
        self.assertEqual(out['extra'], {'url': 'http://h.example/p?[query removed]', 'host': 'h'})

    def test_user_names_in_paths_are_hidden(self):
        self.assertEqual(_Redactor().text(r'C:\Users\james\AppData\evil.exe'),
                         r'C:\Users\<user>\AppData\evil.exe')
        self.assertEqual(_Redactor().text('/home/james/x'), '/home/<user>/x')

    def test_card_numbers_are_masked_when_they_check_out(self):
        self.assertNotIn('4111', _Redactor().text('card 4111 1111 1111 1111'))
        self.assertIn('4111 1111 1111 1112', _Redactor().text('not a card 4111 1111 1111 1112'))

    def test_lan_addresses_get_the_same_label_everywhere(self):
        p = Pseudonymiser()
        self.assertEqual(p.ip('192.168.1.20'), 'lan-1')
        self.assertEqual(p.ip('192.168.1.21'), 'lan-2')
        self.assertEqual(p.ip('192.168.1.20'), 'lan-1')
        self.assertEqual(p.ip('100.101.1.2'), 'lan-3')        # CGNAT, as Tailscale uses
        self.assertEqual(p.ip('8.8.8.8'), '8.8.8.8')
        self.assertEqual(p.text('from 192.168.1.21 at aa:bb:cc:dd:ee:01 via fe80::1'),
                         'from lan-2 at mac-1 via lan-4')


class _BundleCase(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='ns_review_')
        self.addCleanup(shutil.rmtree, self.dir, True)
        os.makedirs(os.path.join(self.dir, 'snippets'))
        snippet = None
        if SCAPY_REAL:
            snippet = 'alert_DNS-TUNNEL_1.pcap'
            write_snippet(os.path.join(self.dir, 'snippets', snippet))
        base = 1_790_000_000
        self.records = [record('DNS-TUNNEL', '192.168.1.20', '192.168.1.1', 'MEDIUM',
                               ts=base + n, snippet=snippet if n == 0 else None,
                               dns_query=f'x{n}.tunnel.evil.example')
                        for n in range(6)]
        self.records.append(record(
            'FORENSICS-CREDENTIAL', '192.168.1.20', '203.0.113.8', 'CRITICAL', ts=base + 10,
            value='Hu************', extra={'url': 'http://shop.example.com/login?pass=Hunter2Secret'}))
        self.records[-1]['description'] = 'password=Hunter2Secret seen, and token: "abc\\"def"'
        self.records.append(record('PORT-SCAN', '10.0.0.5', '192.168.1.20', ts=base + 20))
        write_jsonl(self.dir, self.records)


class TestBundle(_BundleCase):

    def test_a_bundle_has_its_parts_and_fits(self):
        r = build_bundle(self.dir, version='test')
        names = set()
        for root, _, files in os.walk(r['folder']):
            names |= {os.path.relpath(os.path.join(root, f), r['folder']).replace('\\', '/')
                      for f in files}
        self.assertTrue({'README.md', 'summary.md', 'alerts.json'} <= names)
        self.assertLessEqual(len(names), 30)
        self.assertLess(r['bytes'], 20 * 1024 * 1024)
        with zipfile.ZipFile(r['zip']) as z:
            self.assertEqual({n.replace('\\', '/') for n in z.namelist()}, names)
        with open(os.path.join(r['folder'], 'alerts.json'), encoding='utf-8') as f:
            alerts = json.load(f)                 # valid despite the quotes above
        self.assertEqual(len(alerts), len(self.records))
        self.assertIn('"verdict": "false_positive"', open(
            os.path.join(r['folder'], 'README.md'), encoding='utf-8').read())

    def test_nothing_secret_is_written(self):
        r = build_bundle(self.dir)
        text = bundle_text(r['folder'])
        for leak in SECRETS:
            self.assertNotIn(leak, text)
        self.assertGreater(r['masked'], 0)

    def test_the_summary_points_at_the_rule_firing_over_and_over(self):
        r = build_bundle(self.dir)
        with open(os.path.join(r['folder'], 'summary.md'), encoding='utf-8') as f:
            summary = f.read()
        section = summary.split('## Firing over and over on one host')[1].split('##')[0]
        self.assertIn('DNS-TUNNEL for 192.168.1.20: 6 times', section)
        self.assertNotIn('PORT-SCAN', section)

    def test_pseudonymised_bundles_carry_no_lan_addresses(self):
        r = build_bundle(self.dir, pseudonymise=True)
        text = bundle_text(r['folder'])
        self.assertNotIn('192.168.', text)
        self.assertNotIn('10.0.0.5', text)
        self.assertIn('203.0.113.8', text)          # public addresses stay

    def test_raw_captures_only_when_asked(self):
        r = build_bundle(self.dir)
        self.assertFalse(any(f.endswith('.pcap') for _, _, fs in os.walk(r['folder']) for f in fs))
        if SCAPY_REAL:
            r = build_bundle(self.dir, include_pcaps=True)
            self.assertTrue(os.path.isdir(os.path.join(r['folder'], 'pcaps')))

    def test_an_empty_review_folder_says_so(self):
        empty = tempfile.mkdtemp(prefix='ns_review_empty_')
        self.addCleanup(shutil.rmtree, empty, True)
        with self.assertRaises(FileNotFoundError):
            build_bundle(empty)


@unittest.skipUnless(SCAPY_REAL, 'real scapy needed to write and read captures')
class TestTrafficDigest(_BundleCase):

    def test_the_digest_shows_names_not_payloads(self):
        r = build_bundle(self.dir)
        traffic = os.path.join(r['folder'], 'traffic')
        [name] = os.listdir(traffic)
        with open(os.path.join(traffic, name), encoding='utf-8') as f:
            digest = f.read()
        self.assertIn('DNS query bad.example.org', digest)
        self.assertIn('DNS answer bad.example.org → 203.0.113.7', digest)
        self.assertIn('SNI=bad.example.org', digest)
        self.assertIn('HTTP GET shop.example.com/login?[query removed]', digest)
        self.assertIn('ARP   who-has 192.168.1.1', digest)
        for leak in SECRETS + ('Cookie', 'Authorization'):
            self.assertNotIn(leak, digest)


@unittest.skipUnless(SCAPY_REAL, 'real scapy needed to build frames')
class TestSnippetNarrowing(unittest.TestCase):
    """Found on a real network that delivers VLAN-tagged frames to the desktop."""

    def test_vlan_tagged_frames_are_matched(self):
        from scapy.all import IP, UDP, Dot1AD, Dot1Q, Ether, IPv6
        from src.pcap_writer import _frame_involves
        tagged = bytes(Ether() / Dot1Q(vlan=12) / IPv6(src='fe80::1', dst='ff02::fb') / UDP())
        qinq = bytes(Ether() / Dot1AD(vlan=5) / Dot1Q(vlan=12) / IP(src='10.0.0.9', dst='10.0.0.1'))
        plain = bytes(Ether() / IP(src='10.0.0.9', dst='10.0.0.1'))
        self.assertTrue(_frame_involves(tagged, {'fe80::1'}))
        self.assertTrue(_frame_involves(qinq, {'10.0.0.1'}))
        self.assertTrue(_frame_involves(plain, {'10.0.0.9'}))
        self.assertFalse(_frame_involves(tagged, {'fe80::2'}))
        self.assertFalse(_frame_involves(b'\x00' * 10, {'10.0.0.9'}))

    def test_a_capture_of_everything_says_so(self):
        """It fell back to all traffic silently, and read as the alert's own."""
        from scapy.all import IP, Ether
        out = tempfile.mkdtemp(prefix='ns_scope_')
        self.addCleanup(shutil.rmtree, out, True)
        writer = PcapWriter(Config().load(), output_dir=out)
        writer.buffer_packet(bytes(Ether() / IP(src='10.9.9.9', dst='10.9.9.8')))
        alert = an_alert()
        self.assertTrue(writer.export_for_alert(alert, directory=out))
        self.assertIn('no packet named', alert.evidence['packet_capture_scope'])

    def test_an_mdns_announcement_is_named(self):
        from scapy.all import DNS, DNSRR
        from src.review import _dns_names
        line = _dns_names(DNS(qr=1, qd=[], an=DNSRR(rrname='_googlecast._tcp.local', type='PTR',
                                                   rdata='tv._googlecast._tcp.local')))
        self.assertTrue(line.startswith('DNS answer _googlecast._tcp.local → '), line)


class _FakeWriter:
    def __init__(self, size=1000):
        self.size, self.n = size, 0
        self.is_recording, self.recording = False, None

    def export_for_alert(self, alert, seconds=60, directory=None):
        self.n += 1
        path = os.path.join(directory, f'alert_{self.n}.pcap')
        with open(path, 'wb') as f:
            f.write(b'x' * self.size)
        stamp = time.time() + self.n
        os.utime(path, (stamp, stamp))
        return path

    def start_recording(self, **options):
        self.is_recording, self.recording = True, options
        return 'recording.pcap'

    def stop_recording(self):
        self.is_recording = False


def an_alert(rule='DNS-TUNNEL', severity='LOW', src='192.168.1.20', **evidence):
    return Alert(rule, severity, 't', 'd', src_ip=src, dst_ip='203.0.113.7',
                 category='Test', evidence=evidence)


class TestRecorder(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='ns_review_rec_')
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.writer = _FakeWriter()
        self.recorder = ReviewRecorder(self.dir, self.writer)

    def test_an_alert_is_recorded_with_its_snippet(self):
        alert = an_alert()
        alert.evidence['packet_capture'] = self.recorder.snippet(alert)
        self.recorder.record(alert)
        [line] = read_alerts(self.dir)
        self.assertEqual(line['snippet'], 'alert_1.pcap')
        self.assertEqual(line['review_id'], review_id(alert))

    def test_over_budget_the_snippets_alerts_still_point_at_are_kept(self):
        self.recorder.snippet_budget = 2500
        s1, s2, s3 = (self.recorder.snippet(an_alert()) for _ in range(3))
        s4 = self.recorder.snippet(an_alert(), referenced=lambda: {s1})
        self.assertTrue(os.path.exists(s1))
        self.assertFalse(os.path.exists(s2))
        self.assertTrue(os.path.exists(s3) and os.path.exists(s4))

        blocked = an_alert()
        self.assertIsNone(self.recorder.snippet(blocked, referenced=lambda: {s1, s3, s4}))
        self.assertIn('budget', blocked.evidence['packet_capture_note'])

    def test_a_half_written_last_line_is_skipped(self):
        self.recorder.record(an_alert())
        with open(self.recorder.jsonl_path, 'a', encoding='utf-8') as f:
            f.write('{"rule_id": "PORT-SC')
        self.assertEqual(len(read_alerts(self.dir)), 1)

    def test_the_rolling_capture_starts_and_stops_with_monitoring(self):
        self.recorder.start()
        self.assertEqual(self.writer.recording['directory'], self.recorder.capture_dir)
        self.assertEqual(self.writer.recording['budget_bytes'], 2048 * 1024 * 1024)
        self.recorder.stop()
        self.assertFalse(self.writer.is_recording)

    def test_a_recording_the_user_started_is_left_alone(self):
        self.writer.is_recording = True
        self.recorder.start()
        self.recorder.stop()
        self.assertTrue(self.writer.is_recording)


class TestRollingCapture(unittest.TestCase):

    def test_it_stays_within_its_budget_and_age(self):
        out = tempfile.mkdtemp(prefix='ns_roll_')
        self.addCleanup(shutil.rmtree, out, True)
        writer = PcapWriter(Config().load(), output_dir=out)
        capture = os.path.join(out, 'capture')
        os.makedirs(capture)
        now = time.time()
        for n, age in enumerate((10, 20, 30, 40, 99999)):
            path = os.path.join(capture, f'netsentinel_recording_old{n}.pcap')
            with open(path, 'wb') as f:
                f.write(b'x' * 1000)
            os.utime(path, (now - age, now - age))
        current = writer.start_recording(directory=capture, budget_bytes=3100,
                                         max_age_sec=3600)
        self.addCleanup(writer.stop_recording)
        left = sorted(os.listdir(capture))
        self.assertIn(os.path.basename(current), left)
        self.assertEqual(left, sorted([os.path.basename(current),
                                       'netsentinel_recording_old0.pcap',
                                       'netsentinel_recording_old1.pcap',
                                       'netsentinel_recording_old2.pcap']))


class TestVerdicts(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='ns_review_v_')
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.store = ConfirmedFalsePositives(os.path.join(self.dir, 'confirmed.json'))
        self.fp = record('DNS-TUNNEL', '192.168.1.20', '192.168.1.1',
                         dns_query='x1.tunnel.evil.example')
        self.real = record('PORT-SCAN', '10.0.0.5', '192.168.1.20')
        write_jsonl(self.dir, [self.fp, self.real])

    def test_an_answer_pasted_with_its_explanation_is_imported(self):
        answer = ("Here is my assessment:\n```json\n[\n"
                  f'{{"review_id": "{self.fp["review_id"]}", "verdict": "false_positive",'
                  ' "reason": "CDN"},\n'
                  f'{{"review_id": "{self.real["review_id"]}", "verdict": "real"}},\n'
                  '{"review_id": "nope", "verdict": "real"}]\n```\nHope that helps.')
        result = import_verdicts(self.dir, answer, self.store)
        self.assertEqual((result['false_positive'], result['real']), (1, 1))
        self.assertEqual(result['unknown_ids'], ['nope'])

        same = an_alert('DNS-TUNNEL', dns_query='x9.tunnel.evil.example')
        self.assertIsNotNone(self.store.matches(same), 'the same rule for the same domain')
        self.assertIsNone(self.store.matches(an_alert('DNS-BAD-TLD', dns_query='x9.tunnel.evil.example')))
        self.assertIsNone(self.store.matches(an_alert('PORT-SCAN', src='10.0.0.5')),
                          '"real" must suppress nothing')

    def test_a_verdict_from_another_process_is_seen_without_a_restart(self):
        running = ConfirmedFalsePositives(self.store.path)   # the app's copy
        self.store.add(self.fp)                              # the command line's
        self.assertIsNotNone(running.matches(an_alert('DNS-TUNNEL', dns_query='a.tunnel.evil.example')))

    def test_a_false_positive_needs_something_to_match_on(self):
        ml = record('ML-ANOMALY', '', '')
        self.assertIsNone(self.store.add(ml))
        self.assertEqual(alert_subjects(ml), [])

    def test_a_multicast_destination_is_not_a_subject(self):
        """Found live: an mDNS verdict was tied to 224.0.0.251, i.e. every device."""
        mdns = an_alert('FORENSICS-SENSITIVE-DATA', src='192.168.8.40')
        mdns.dst_ip = '224.0.0.251'
        self.assertEqual(alert_subjects(mdns), [('src_ip', '192.168.8.40')])
        mdns.dst_ip = 'ff02::fb'
        self.assertEqual(alert_subjects(mdns), [('src_ip', '192.168.8.40')])

    def test_domains_come_from_the_traffic_not_from_a_guess(self):
        guessed = an_alert('DATA-EXFIL', destination_domains=['innocent.example'])
        self.assertNotIn(('domain', 'innocent.example'), alert_subjects(guessed))
        self.assertEqual(alert_subjects(an_alert(tls_sni='a.b.example.co.za'))[0],
                         ('domain', 'example.co.za'))


def bare_app(review=None):
    app = NetSentinelApp.__new__(NetSentinelApp)
    app.review = review
    app.suppressed_alerts = 0
    app.ids_engine = None
    app.baseline_whitelist = None
    app._verify_queue = queue.Queue()
    app._pcap_on_alert = False
    app._pcap_on_alert_severity = 'CRITICAL'
    app._pcap_on_alert_seconds = 60
    app._pcap_alert_cooldown = 60
    app._pcap_alert_cooldowns = {}
    app._pcap_alert_last = {}
    app.alert_manager = SimpleNamespace(get_alerts=lambda limit: [], max_stored=10)
    return app


class TestTheGateway(unittest.TestCase):

    def test_a_confirmed_false_positive_is_not_raised_again(self):
        app = bare_app()
        app.baseline_whitelist = SimpleNamespace(suppresses=lambda alert: {'rule_id': 'x'})
        emitted = []
        app._emit_alert = emitted.append
        app._verified_alert_gateway(an_alert())
        self.assertEqual(emitted, [])
        self.assertEqual(app.suppressed_alerts, 1)

    def test_the_severity_before_verification_is_kept(self):
        app = bare_app()
        app.alert_verifier = SimpleNamespace(
            verify_alert=lambda alert, ids_engine=None: setattr(alert, 'severity', 'LOW'))
        emitted = []
        app._emit_alert = emitted.append
        app._verified_alert_gateway(an_alert(severity='HIGH'))
        self.assertEqual(emitted[0].evidence['severity_before_verification'], 'HIGH')


class TestReviewModeInTheApp(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='ns_review_app_')
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.recorder = ReviewRecorder(self.dir, _FakeWriter())
        self.app = bare_app(self.recorder)

    def test_review_mode_can_be_turned_on_before_monitoring_exists(self):
        """--review crashed at startup: __init__ enabled it before _running was set."""
        app = NetSentinelApp.__new__(NetSentinelApp)
        app.review = None
        app.pcap_writer = _FakeWriter()
        app.config = Config().load()
        recorder = app.enable_review(self.dir)
        self.assertEqual(recorder.directory, os.path.abspath(self.dir))
        self.assertFalse(app.pcap_writer.is_recording)

    def test_every_severity_gets_a_snippet_and_repeats_share_it(self):
        """pcap_on_alert defaults to CRITICAL; review mode needs the LOW ones too."""
        first, second = an_alert(severity='LOW'), an_alert(severity='LOW')
        self.app._capture_alert_evidence(first)
        self.app._capture_alert_evidence(second)
        self.assertTrue(os.path.exists(first.evidence['packet_capture']))
        self.assertEqual(second.evidence['packet_capture'], first.evidence['packet_capture'])

    def test_a_deferred_alert_is_recorded_once_its_verdict_is_in(self):
        verified = threading.Event()

        def verify(alert, ids_engine=None):
            alert.evidence['alert_verification'] = {'verdict': 'VERIFIED'}
            verified.set()
        self.app.alert_verifier = SimpleNamespace(verify_alert=verify)
        alert = an_alert('IOC-PROC-NAME')
        alert.stored = True
        self.app._verify_queue.put(alert)
        stop = threading.Event()
        worker = threading.Thread(target=self.app._verification_loop, args=(stop,))
        worker.start()
        self.assertTrue(verified.wait(5))
        deadline = time.time() + 5
        while not read_alerts(self.dir) and time.time() < deadline:
            time.sleep(0.02)
        stop.set()
        worker.join(5)
        [line] = read_alerts(self.dir)
        self.assertEqual(line['evidence']['alert_verification']['verdict'], 'VERIFIED')


class TestLearningByRegistrableDomain(unittest.TestCase):

    def test_suffixes_nobody_owns_are_not_domains(self):
        self.assertIsNone(registrable_domain('github.io'))
        self.assertIsNone(registrable_domain('co.za'))
        self.assertEqual(registrable_domain('x.y.evil.github.io'), 'evil.github.io')
        self.assertEqual(registrable_domain('a.b.example.co.za'), 'example.co.za')
        self.assertEqual(registrable_domain('www.example.com'), 'example.com')

    def test_learning_one_tenant_does_not_vouch_for_another(self):
        """By last two labels, one github.io site or one .co.za site whitelisted them all."""
        wl = BaselineWhitelist(Config().load())
        for _ in range(3):
            wl.observe_dns('192.168.1.20', 'alice-review-test.github.io')
            wl.observe_dns('192.168.1.20', 'www.shop-review-test.co.za')
        self.assertTrue(wl.is_learned_domain('alice-review-test.github.io'))
        self.assertFalse(wl.is_learned_domain('mallory-review-test.github.io'))
        self.assertTrue(wl.is_learned_domain('mail.shop-review-test.co.za'))
        self.assertFalse(wl.is_learned_domain('other-review-test.co.za'))

    def test_user_suffixes_match_on_a_label_boundary(self):
        wl = BaselineWhitelist(Config().load())
        wl._user_dga_suffixes = {'ample-review-test.com'}
        self.assertFalse(wl.is_learned_domain('example-review-test.com'))
        self.assertTrue(wl.is_learned_domain('cdn.ample-review-test.com'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
