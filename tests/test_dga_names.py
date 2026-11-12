"""
The DGA check scores the label someone registered, not every label.

A work laptop raised HIGH "Domain Generation Algorithm Detected" twice: once
for a OneDrive sync (numbered storage accounts, a SharePoint host and an Azure
SignalR relay) and once for an evening of web pages (Claude's artifact frames
and Google's ad frames, a UUID or a hash under each). A DGA has to register the
names it generates, so its randomness is in the registered label.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(1, os.path.dirname(os.path.abspath(__file__)))  # tests/, for _test_support

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

from test_lan_threats import pkt  # noqa: E402
from test_third_review import T0  # noqa: E402

PC = '192.168.10.32'

ONEDRIVE_SYNC = [
    'signalrp2-relayhub-prod-eu01-3.service.signalr.net',
    '481207-ipv4fdsmte.gr.global.aa-rt.sharepoint.com',
    'onedriveclucprodbn20031.blob.core.windows.net',
    'onedriveclubproddm20012.blob.core.windows.net',
    'onedriveclucprodbn20058.blob.core.windows.net',
    'onedriveclubproddm20077.blob.core.windows.net',
]
WEB_PAGES = [
    '4f0b2a91-7c3e-4d58-9a16-2be0c4d7f3a8.frame.claudeusercontent.com',
    '9e41c7d2a08b5f36e17c4a29d0b8f5e3.safeframe.googlesyndication.com',
    'onedriveclubproddm20019.blob.core.windows.net',
    'onedriveclubproddm20044.blob.core.windows.net',
    '7d2c9b06e5a14f83b0c6d1e9a2f47b58.safeframe.googlesyndication.com',
]
GENERATED = ['xkqzvbnmtrwplh.com', 'qwrtzpsdfghjkl.co.uk', 'zxcvbnmlkjhgfd.org',
             'xj4k9wqzp2mvb7.duckdns.org', 'plkmnjuhbvgytf.biz']


def dga_findings(names, src=PC):
    from src.ioc_scanner import IOCScanner
    scanner = IOCScanner(reset_config())
    found = []
    for i, name in enumerate(names):
        found += [f for f in scanner.check_packet_ioc(pkt(src_ip=src, dns_query=name,
                                                          timestamp=T0 + i * 20))
                  if f['rule_id'] == 'IOC-DGA']
    return found


class TestDgaNames(unittest.TestCase):

    def test_a_onedrive_sync_is_not_a_dga(self):
        self.assertEqual(dga_findings(ONEDRIVE_SYNC), [])

    def test_random_labels_under_known_services_are_not_a_dga(self):
        self.assertEqual(dga_findings(WEB_PAGES), [])

    def test_generated_registered_names_still_are(self):
        """Including under co.uk and a dynamic-DNS suffix, where the account is the name."""
        found = dga_findings(GENERATED)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['evidence']['total_dga_domains'], 5)

    def test_generated_storage_account_names_still_count(self):
        """blob.core.windows.net is a public suffix: the account name is the registered label."""
        names = [n.split('.')[0] + '.blob.core.windows.net' for n in GENERATED]
        self.assertEqual(len(dga_findings(names)), 1)

    def test_the_registered_label(self):
        from src.ioc_scanner import _registered_label
        self.assertEqual(_registered_label('a.b.example.co.uk'), 'example')
        self.assertEqual(_registered_label('acct1.blob.core.windows.net'), 'acct1')
        self.assertEqual(_registered_label('co.uk'), '')


if __name__ == '__main__':
    unittest.main()
