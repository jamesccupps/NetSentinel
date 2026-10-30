"""
Turn unittest failures into GitHub annotations.

GitHub shows a workflow's log only to someone signed in, but annotations are
public, on the run's page and through the API. Printed as workflow commands,
each failing test, with the last line of its traceback, is readable without
digging through, or being allowed to see, the log.

    python -m unittest ... 2>&1 | tee test-output.txt
    python tools/ci_failures.py test-output.txt
"""

import re
import sys

_SEPARATOR = re.compile(r'^={50,}$', re.M)
_HEAD = re.compile(r'^(ERROR|FAIL): (\S+) \(([^)]+)\)')


def failures(text):
    """(kind, test id, last line of its traceback) for each failure in the output."""
    out = []
    for block in _SEPARATOR.split(text)[1:]:
        lines = block.strip('\n').splitlines()
        if not lines:
            continue
        head = _HEAD.match(lines[0])
        if head is None:
            continue
        body = block.split('-' * 70, 1)[-1]
        body = body.split('\n' + '-' * 70, 1)[0]          # the summary after the last one
        reason = next((line.strip() for line in reversed(body.splitlines())
                       if line.strip()), '')
        out.append((head.group(1), head.group(3), reason))
    return out


def _escape(value, title=False):
    value = value.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    if title:
        value = value.replace(':', '%3A').replace(',', '%2C')
    return value


def annotations(text, limit=40):
    found = failures(text)
    lines = [f"::error title={_escape(f'{kind} {test}', True)}::{_escape(reason[:500])}"
             for kind, test, reason in found[:limit]]
    if len(found) > limit:
        lines.append(f"::error::{len(found) - limit} more failures are in the log.")
    return lines


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    with open(argv[0], encoding='utf-8', errors='replace') as f:
        text = f.read()
    for line in annotations(text):
        print(line)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
