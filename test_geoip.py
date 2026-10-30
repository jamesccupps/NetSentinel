"""
GeoIP from DB-IP Lite: off by default, atomic monthly updates, local lookups.
==============================================================================
The databases here are tiny MaxMind DB files built by hand (one search-tree node:
addresses whose first bit is 1 have a record, the rest do not), so the real
`maxminddb` reader is exercised without shipping or downloading anything.
"""

import gzip
import os
import shutil
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _test_support  # noqa: E402,F401
from _test_support import reset_config  # noqa: E402

try:
    import maxminddb  # noqa: F401
    MAXMINDDB = True
except ImportError:  # pragma: no cover
    MAXMINDDB = False


# ─── A minimal MaxMind DB writer ──────────────────────────────────────────────

class U16(int):
    pass


class U64(int):
    pass


def _enc(value):
    # libmaxminddb (the C reader) checks metadata types exactly, so these match
    # the spec: uint16 and uint64 where it says so, uint32 otherwise.
    if isinstance(value, U16):
        raw = value.to_bytes(2, 'big').lstrip(b'\x00')
        return bytes([0xa0 | len(raw)]) + raw
    if isinstance(value, U64):
        raw = value.to_bytes(8, 'big').lstrip(b'\x00')
        return bytes([len(raw), 9 - 7]) + raw
    if isinstance(value, str):
        raw = value.encode()
        if len(raw) < 29:
            return bytes([0x40 | len(raw)]) + raw
        assert len(raw) < 285
        return bytes([0x40 | 29, len(raw) - 29]) + raw
    if isinstance(value, dict):
        out = bytes([0xe0 | len(value)])
        for k, v in value.items():
            out += _enc(k) + _enc(v)
        return out
    if isinstance(value, list):
        out = bytes([len(value), 11 - 7])            # extended type: array
        for v in value:
            out += _enc(v)
        return out
    if isinstance(value, int):
        raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big') if value else b''
        return bytes([0xc0 | len(raw)]) + raw         # uint32
    raise TypeError(value)


def build_mmdb(record):
    """IPv4 database: 128.0.0.0/1 -> record, 0.0.0.0/1 -> nothing."""
    node_count = 1
    no_data, data_ptr = node_count, node_count + 16 + 0
    tree = no_data.to_bytes(3, 'big') + data_ptr.to_bytes(3, 'big')
    data = _enc(record)
    meta = {'node_count': node_count, 'record_size': U16(24), 'ip_version': U16(4),
            'database_type': 'NetSentinel-Test', 'languages': ['en'],
            'binary_format_major_version': U16(2), 'binary_format_minor_version': U16(0),
            'build_epoch': U64(1_700_000_000), 'description': {'en': 'test'}}
    return tree + b'\x00' * 16 + data + b'\xab\xcd\xefMaxMind.com' + _enc(meta)


COUNTRY = {'country': {'iso_code': 'DE', 'names': {'en': 'Germany'}}}
ASN = {'autonomous_system_number': 64500, 'autonomous_system_organization': 'Example Net'}


class TestGeoIP(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='ns_geo_')
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def geo(self, enabled=True, fetch=None):
        from src.geoip import GeoIP
        cfg = reset_config(**{'geoip.enabled': enabled})
        self.addCleanup(reset_config, **{'geoip.enabled': False})
        return GeoIP(cfg, data_dir=self.tmp, fetch=fetch)

    def test_off_by_default_and_silent(self):
        from src.geoip import GeoIP
        geo = GeoIP(reset_config(), data_dir=self.tmp)
        self.assertFalse(geo.enabled)
        self.assertEqual(geo.lookup('128.1.1.1'), {})
        self.assertFalse(geo.update())

    def test_the_engine_does_not_load_it_when_off(self):
        from src.ids_engine import IDSEngine
        self.assertIsNone(IDSEngine(reset_config()).geoip)

    def test_attribution_credits_db_ip(self):
        from src.geoip import ATTRIBUTION, ATTRIBUTION_URL
        self.assertIn('DB-IP', ATTRIBUTION)
        self.assertIn('CC BY 4.0', ATTRIBUTION)
        self.assertEqual(ATTRIBUTION_URL, 'https://db-ip.com')

    @unittest.skipUnless(MAXMINDDB, 'maxminddb not installed')
    def test_monthly_update_then_lookup(self):
        urls = []

        def fetch(url):
            urls.append(url)
            return gzip.compress(build_mmdb(ASN if '-asn-' in url else COUNTRY))

        geo = self.geo(fetch=fetch)
        now = 1_793_000_000                          # 2026-10
        self.assertTrue(geo.update(now=now))
        self.assertEqual(sorted(u.rsplit('/', 1)[1] for u in urls),
                         ['dbip-asn-lite-2026-10.mmdb.gz', 'dbip-country-lite-2026-10.mmdb.gz'])
        self.assertEqual(geo.lookup('128.1.2.3'),
                         {'country': 'DE', 'country_name': 'Germany', 'asn': 64500,
                          'as_org': 'Example Net'})
        self.assertEqual(geo.lookup('10.0.0.1'), {}, 'private addresses are not looked up')
        self.assertEqual(geo.annotate('128.1.2.3', 'dst'),
                         {'dst_country': 'DE', 'dst_asn': 64500, 'dst_as_org': 'Example Net'})
        self.assertFalse(geo.update(now=now), 'this month is already here')
        self.assertEqual(len(urls), 2)

    @unittest.skipUnless(MAXMINDDB, 'maxminddb not installed')
    def test_a_bad_download_never_replaces_a_good_database(self):
        good = gzip.compress(build_mmdb(COUNTRY))
        geo = self.geo(fetch=lambda url: good)
        geo.update(now=1_793_000_000)
        before = open(os.path.join(self.tmp, 'dbip-country-lite.mmdb'), 'rb').read()

        geo._fetch = lambda url: gzip.compress(b'not a database')
        self.assertFalse(geo.update(force=True, now=1_795_600_000))
        after = open(os.path.join(self.tmp, 'dbip-country-lite.mmdb'), 'rb').read()
        self.assertEqual(before, after)
        self.assertFalse([f for f in os.listdir(self.tmp) if f.endswith('.download')])
        self.assertEqual(geo.lookup('128.9.9.9').get('country'), 'DE')
        self.assertIn('not updated', geo.last_error)

    def test_talkers_are_annotated(self):
        geo = self.geo()
        geo._readers = {'country': type('R', (), {'get': staticmethod(
            lambda ip: COUNTRY if ip.startswith('128.') else None)})()}
        rows = geo.annotate_talkers({'128.1.1.1': 500, '10.0.0.5': 100})
        self.assertEqual(rows[0]['country'], 'DE')
        self.assertNotIn('country', rows[1])


if __name__ == '__main__':
    unittest.main()
