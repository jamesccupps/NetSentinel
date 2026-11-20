"""
The minimum versions NetSentinel asks for, of its packages and of Python.
========================================================================
The exe is built from requirements-build.lock, but requirements.txt and
pyproject.toml say what an install from source accepts, and Dependabot's alerts
judge those minimums. In November 2026 four of them still allowed versions with
published advisories, all fixed in the versions the lock already pinned:
cryptography 41 (fixed by 50.0.0), py7zr 1.0 (1.1.3: archive extraction),
scikit-learn 1.3 (1.5.0) and Pillow 10 (13.0.0). Pillow 13 needs Python 3.11,
and 3.10 had reached its end of life, so 3.11 became the lowest Python.
"""

import os
import re
import tomllib
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The lowest version past every advisory OSV lists for the package (checked
# 2026-11-20). Raise these, never lower them.
PAST_ADVISORIES = {
    'cryptography': '50.0.0',
    'pillow': '13.0.0',
    'py7zr': '1.1.3',
    'scikit-learn': '1.5.0',
}

# Where a person installing from source is told which Python to bring.
PYTHON_FLOOR_STATED_IN = ('README.md', 'site/index.html', 'setup.bat',
                          'netmon/README.md', 'netmon/deploy/README.md')


def version(text):
    """Comparable: 13.0 and 13.0.0 are the same version, so trailing zeros go."""
    parts = [int(part) for part in re.findall(r'\d+', text)]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def read(name):
    with open(os.path.join(ROOT, name), encoding='utf-8') as f:
        return f.read()


def project():
    with open(os.path.join(ROOT, 'pyproject.toml'), 'rb') as f:
        return tomllib.load(f)


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
    meta = project()['project']
    specs = list(meta['dependencies'])
    for extra in meta.get('optional-dependencies', {}).values():
        specs.extend(extra)
    found = {}
    for spec in specs:
        m = re.match(r'^([A-Za-z0-9_.-]+)>=([0-9][0-9.]*)$', spec.replace(' ', ''))
        if m:
            found[m.group(1).lower()] = m.group(2)
    return found


def locked():
    """{package: version} from requirements-build.lock."""
    return {m.group(1).lower(): m.group(2) for m in
            re.finditer(r'^([A-Za-z0-9_.-]+)==([0-9][0-9.]*)', read('requirements-build.lock'), re.M)}


def python_floor():
    """(3, N) from pyproject's requires-python, which must be a plain >=3.N."""
    m = re.fullmatch(r'>=\s*3\.(\d+)', project()['project']['requires-python'])
    if not m:
        raise AssertionError('requires-python is not of the form >=3.N')
    return (3, int(m.group(1)))


class TestMinimums(unittest.TestCase):

    def test_requirements_are_read(self):
        self.assertIn('scapy', requirements())
        self.assertIn('scapy', pyproject())
        self.assertIn('plyer', pyproject())     # an extra, not a dependency
        self.assertIn('scapy', locked())

    def test_minimums_are_past_known_advisories(self):
        for listing, found in (('requirements.txt', requirements()),
                               ('pyproject.toml', pyproject())):
            for package, floor in PAST_ADVISORIES.items():
                with self.subTest(listing=listing, package=package):
                    self.assertIn(package, found)
                    self.assertGreaterEqual(version(found[package]), version(floor))

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


class TestPythonFloor(unittest.TestCase):
    """
    Python 3.10's end of life (October 2026) and Pillow 13 moved the floor to
    3.11. Every place that names it, and the oldest Python CI tests, move with
    requires-python, or an install from source is told one thing and tested on
    another.
    """

    def test_python_3_10_is_no_longer_accepted(self):
        self.assertEqual(python_floor(), (3, 11))

    def test_ci_tests_the_oldest_python_accepted(self):
        workflow = read('.github/workflows/test.yml')
        m = re.search(r'python-version:\s*\[([^\]]*)\]', workflow)
        self.assertIsNotNone(m, 'no python-version matrix in test.yml')
        tested = [version(v) for v in re.findall(r'[\'"]([0-9.]+)[\'"]', m.group(1))]
        self.assertEqual(min(tested), python_floor())

    def test_classifiers_and_ruff_target_match(self):
        meta = project()
        classified = [version(c.rsplit('::', 1)[1]) for c in meta['project']['classifiers']
                      if re.fullmatch(r'Programming Language :: Python :: 3\.\d+', c)]
        self.assertEqual(min(classified), python_floor())
        major, minor = python_floor()
        self.assertEqual(meta['tool']['ruff']['target-version'], f'py{major}{minor}')

    def test_the_docs_state_the_same_floor(self):
        major, minor = python_floor()
        floor = f'{major}.{minor}'
        for name in PYTHON_FLOOR_STATED_IN:
            with self.subTest(file=name):
                stated = re.findall(r'\b(3\.\d+)(?:\+| or newer)', read(name))
                self.assertTrue(stated, f'{name} no longer says which Python it needs')
                self.assertEqual(set(stated), {floor})

    def test_setup_bat_checks_the_version(self):
        """It used to check only that some python ran; pip then failed on Pillow."""
        major, minor = python_floor()
        self.assertIn(f'sys.version_info < ({major}, {minor})', read('setup.bat'))


if __name__ == '__main__':
    unittest.main()
