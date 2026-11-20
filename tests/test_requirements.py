"""
The minimum versions NetSentinel asks for.
==========================================
The exe is built from requirements-build.lock, but requirements.txt and
pyproject.toml say what an install from source accepts, and Dependabot's alerts
judge those minimums. In November 2026 three of them still allowed versions with
published advisories, all fixed in the versions the lock already pinned:
cryptography 41 (fixed by 50.0.0), py7zr 1.0 (1.1.3: archive extraction) and
scikit-learn 1.3 (1.5.0). Pillow's fixes need 13.0, which needs Python 3.11, so
its minimum waits on dropping 3.10.

Read as text: tomllib is not in Python 3.10.
"""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The lowest version past every advisory OSV lists for the package (checked
# 2026-11-20). Raise these, never lower them.
PAST_ADVISORIES = {
    'cryptography': (50, 0, 0),
    'py7zr': (1, 1, 3),
    'scikit-learn': (1, 5, 0),
}


def version(text):
    return tuple(int(part) for part in re.findall(r'\d+', text))


def read(name):
    with open(os.path.join(ROOT, name), encoding='utf-8') as f:
        return f.read()


def requirements():
    """{package: minimum} from requirements.txt."""
    found = {}
    for line in read('requirements.txt').splitlines():
        m = re.match(r'^\s*([A-Za-z0-9_.-]+)\s*>=\s*([0-9][0-9.]*)\s*(?:#.*)?$', line)
        if m:
            found[m.group(1).lower()] = m.group(2)
    return found


def pyproject():
    """{package: minimum} from pyproject.toml's dependencies and extras."""
    return {m.group(1).lower(): m.group(2) for m in
            re.finditer(r'"([A-Za-z0-9_.-]+)>=([0-9][0-9.]*)"', read('pyproject.toml'))}


def locked():
    """{package: version} from requirements-build.lock."""
    return {m.group(1).lower(): m.group(2) for m in
            re.finditer(r'^([A-Za-z0-9_.-]+)==([0-9][0-9.]*)', read('requirements-build.lock'), re.M)}


class TestMinimums(unittest.TestCase):

    def test_requirements_are_read(self):
        self.assertIn('scapy', requirements())
        self.assertIn('scapy', pyproject())
        self.assertIn('scapy', locked())

    def test_minimums_are_past_known_advisories(self):
        for listing, found in (('requirements.txt', requirements()),
                               ('pyproject.toml', pyproject())):
            for package, floor in PAST_ADVISORIES.items():
                with self.subTest(listing=listing, package=package):
                    self.assertIn(package, found)
                    self.assertGreaterEqual(version(found[package]), floor)

    def test_requirements_and_pyproject_agree(self):
        """Two lists of the same minimums drift apart unless something checks."""
        listed = pyproject()
        for package, minimum in requirements().items():
            with self.subTest(package=package):
                self.assertIn(package, listed)
                self.assertEqual(version(listed[package]), version(minimum))

    def test_the_build_lock_meets_every_minimum(self):
        """
        Raising a minimum without regenerating the lock (the command is at the top
        of release.yml) builds the exe without the change.
        """
        lock = locked()
        for package, minimum in requirements().items():
            with self.subTest(package=package):
                self.assertIn(package, lock)
                self.assertGreaterEqual(version(lock[package]), version(minimum))


if __name__ == '__main__':
    unittest.main()
