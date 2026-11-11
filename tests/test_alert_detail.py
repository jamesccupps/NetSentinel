"""
Alerts that say what they matched.
==================================
A week of 1.14 on the owner's network had five HIGH "Suspicious User Agent"
alerts that said only "Suspicious User Agent found in unencrypted traffic". Not
the user agent, not what in it matched, not the site. They were Edge running
headless for its own background job and fetching from edge.microsoft.com over
plain HTTP, which matched "headless"; nobody could have told from the alert.
Addresses here are documentation addresses or made up.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401

from test_third_review import T0, PC, _Alerts, forensics, http_get, tcp  # noqa: E402

EDGE_HEADLESS = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                 '(KHTML, like Gecko) HeadlessChrome/158.0.0.0 Safari/537.36 Edg/158.0.0.0')
CHROME_HEADLESS = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                   '(KHTML, like Gecko) HeadlessChrome/158.0.0.0 Safari/537.36')
MS_FRONT_ENDS = ['198.51.100.11', '198.51.100.12', '198.51.100.13']
SITE = '203.0.113.80'


def request(f, host, agent, dst=SITE, path='/', ts=T0, src=PC):
    f.analyze_packet(tcp(src, 50000, dst, 80, http_get(host, path, agent), server=80, ts=ts))


def found(f, data_type='Suspicious User Agent'):
    return [d for d in f.sensitive_data if d['data_type'] == data_type]


class TestABrowsersOwnJob(unittest.TestCase):

    def test_headless_edge_asking_microsoft_is_not_suspicious(self):
        f = forensics()
        for i, dst in enumerate(MS_FRONT_ENDS):
            request(f, 'edge.microsoft.com', EDGE_HEADLESS, dst=dst, ts=T0 + i)
        self.assertEqual(found(f), [])

    def test_headless_chrome_asking_google_is_not_either(self):
        f = forensics()
        request(f, 'update.googleapis.com', CHROME_HEADLESS)
        self.assertEqual(found(f), [])

    def test_headless_edge_anywhere_else_still_is(self):
        f = forensics()
        request(f, 'shop.example.com', EDGE_HEADLESS)
        [item] = found(f)
        self.assertEqual(item['risk'], 'HIGH')
        self.assertEqual(item['evidence']['matched'], 'headless')
        self.assertEqual(item['evidence']['host'], 'shop.example.com')

    def test_a_maker_look_alike_is_not_the_maker(self):
        f = forensics()
        request(f, 'edge.microsoft.com.example.net', EDGE_HEADLESS)
        self.assertEqual(len(found(f)), 1)

    def test_the_browsers_own_job_does_not_use_up_the_note(self):
        """Once per source: had Edge's request been noted, automation after it would not."""
        f = forensics()
        request(f, 'edge.microsoft.com', EDGE_HEADLESS)
        request(f, 'login.example.com', CHROME_HEADLESS, ts=T0 + 5)
        [item] = found(f)
        self.assertEqual(item['evidence']['host'], 'login.example.com')


class TestTheAlertSaysWhatMatched(unittest.TestCase):

    def alert(self, item):
        from src.forensics import sensitive_alert
        return sensitive_alert(item)

    def test_a_user_agent_alert_names_the_agent_the_match_and_the_site(self):
        f = forensics()
        request(f, 'shop.example.com', 'Scrapy/2.11 (+https://scrapy.org)')
        alert = self.alert(found(f)[0])
        self.assertEqual(alert.evidence['user_agent'], 'Scrapy/2.11 (+https://scrapy.org)')
        self.assertEqual(alert.evidence['matched'], 'scrapy')
        self.assertEqual(alert.evidence['host'], 'shop.example.com')
        self.assertIn('Scrapy/2.11', alert.description)
        self.assertIn('matched "scrapy"', alert.description)
        self.assertNotIn('encrypted connections', alert.evidence['recommendation'])

    def test_a_scripted_client_and_a_missing_agent_say_so_too(self):
        f = forensics()
        request(f, 'api.example.com', 'python-requests/2.32')
        request(f, 'files.example.com', None, ts=T0 + 1, src='192.168.1.51')
        scripted = self.alert(found(f, 'Scripted HTTP Client')[0])
        self.assertEqual(scripted.evidence['matched'], 'python-requests')
        missing = self.alert(found(f, 'Missing User Agent')[0])
        self.assertEqual(missing.evidence['host'], 'files.example.com')
        self.assertIn('no User-Agent', missing.description)

    def test_a_card_or_cookie_value_never_reaches_the_alert(self):
        """The finding's value is the data itself; only its evidence is shown."""
        for data_type, value in (('Credit Card', '****4242 (high)'),
                                 ('Session Cookie', 'sid=s3cr3tc00ki3v4lu3'),
                                 ('SSN', '***-**-6789')):
            alert = self.alert({'data_type': data_type, 'value': value, 'risk': 'HIGH',
                                'source_ip': PC, 'destination_ip': SITE, 'port': 80})
            text = repr(alert.evidence) + alert.description + alert.title
            self.assertNotIn(value, text)
            self.assertNotIn(value[-4:], text)

    def test_an_attack_patterns_request_hides_a_token(self):
        f = forensics()
        token = 'ghp_' + 'Ab3Xk9QzR7mT2vLw8NcYp4Hs6JdF1uGe5KiO'
        request(f, 'app.example.com', 'Mozilla/5.0',
                path=f'/../../etc/passwd?access_token={token}')
        [item] = found(f, 'HTTP Attack Pattern')
        alert = self.alert(item)
        self.assertEqual(alert.evidence['matched'], 'Path traversal attempt')
        self.assertIn('app.example.com', alert.evidence['request'])
        self.assertNotIn(token, repr(alert.evidence) + alert.description)

    def test_a_capture_is_alerted_as_live_monitoring_alerts(self):
        """PCAP analysis builds the same alert, evidence included."""
        import inspect
        from src import pcap_analyzer
        self.assertIn('sensitive_alert(', inspect.getsource(pcap_analyzer))


class TestOneSiteIsOneAlert(unittest.TestCase):

    def test_one_site_behind_several_addresses_is_one_alert(self):
        f = forensics()
        alerts = _Alerts(f)
        for dst in MS_FRONT_ENDS:
            f.sensitive_data.append({
                'data_type': 'Suspicious User Agent', 'value': 'x', 'risk': 'HIGH',
                'source_ip': PC, 'destination_ip': dst, 'port': 80,
                'evidence': {'matched': 'httpclient', 'host': 'Downloads.Example.com'}})
        f.sensitive_data.append({
            'data_type': 'Suspicious User Agent', 'value': 'x', 'risk': 'HIGH',
            'source_ip': PC, 'destination_ip': SITE, 'port': 80,
            'evidence': {'matched': 'httpclient', 'host': 'other.example.com'}})
        alerts.app._check_forensics_alerts()
        hosts = [a.evidence['host'] for a in alerts.raised]
        self.assertEqual(hosts, ['Downloads.Example.com', 'other.example.com'])


if __name__ == '__main__':
    unittest.main()
