"""
Shared test setup.
==================
Leading underscore so `unittest discover -p "test_*.py"` does not collect it.

Two jobs, both of which used to be copy-pasted into every test module with subtly
different behaviour:

1. **Isolate the data directory.** `src.config` resolves APP_DIR from `$HOME` once,
   at import. Whichever test module imports it first therefore fixes the location
   for the whole process, so the temp directory has to be set up before any import
   of `src` and shared by everyone.

2. **Provide Scapy.** Older Scapy enumerated IPv6 routes at import and blew up in
   containers, so each module installed a stub. That stub left `src.capture` holding
   `IP = TCP = UDP = Raw = None` while `SCAPY_AVAILABLE` still read True, and which
   module imported first decided whether the rest of the suite got real layers —
   so tests passed alone and failed under discovery.

   Now the real library is tried first and the stub is only a fallback. Use
   `SCAPY_REAL` to skip tests that need genuine packet construction.
"""

import os
import sys
import tempfile
import types

__all__ = ['SCAPY_REAL', 'TEST_HOME', 'reset_config']

# ─── 1. Isolated HOME, established before anything imports src.config ─────────
TEST_HOME = os.environ.get('NETSENTINEL_TEST_HOME')
if not TEST_HOME:
    TEST_HOME = tempfile.mkdtemp(prefix='ns_tests_')
    os.environ['NETSENTINEL_TEST_HOME'] = TEST_HOME
os.environ['HOME'] = TEST_HOME
os.environ['USERPROFILE'] = TEST_HOME
os.environ.setdefault('NETSENTINEL_TEST', '1')


# ─── 2. Real Scapy if it works, a stub only if it genuinely does not ──────────
def _install_stub():
    stub = types.ModuleType('scapy')
    stub_all = types.ModuleType('scapy.all')
    for name in ['sniff', 'conf', 'get_if_list', 'get_if_addr', 'IP', 'IPv6',
                 'TCP', 'UDP', 'ICMP', 'DNS', 'ARP', 'Raw', 'Ether', 'rdpcap',
                 'PcapReader', 'wrpcap']:
        setattr(stub_all, name, None)
    sys.modules['scapy'] = stub
    sys.modules['scapy.all'] = stub_all


if 'scapy.all' in sys.modules and not getattr(sys.modules['scapy.all'], '__file__', None):
    # A previously installed stub would win over the real library; drop it first.
    for _m in [m for m in sys.modules if m == 'scapy' or m.startswith('scapy.')]:
        del sys.modules[_m]

try:
    import scapy.all  # noqa: F401
    SCAPY_REAL = True
except Exception:  # pragma: no cover - only on hosts where scapy cannot import
    _install_stub()
    SCAPY_REAL = False


def reset_config(**overrides):
    """
    Return the shared Config singleton with test-friendly defaults applied.

    Config is a process-wide singleton that persists to disk, so a value set by one
    test is still there for the next one. Tests that care about a setting should set
    it explicitly rather than assume a default.
    """
    from src.config import Config
    cfg = Config().load()
    cfg.set('threat_intel', 'auto_update', False)
    for section_key, value in overrides.items():
        section, key = section_key.split('.', 1)
        cfg.set(section, key, value)
    return cfg
