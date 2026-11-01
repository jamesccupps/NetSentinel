"""Print the release notes for a tag: its CHANGELOG.md section, then install notes."""

import os
import re
import sys

INSTALL = """
---

**Installing.** Install [Npcap](https://npcap.com) first (tick "WinPcap API-compatible
mode"), then run `NetSentinel.exe`. It asks for administrator rights because packet
capture needs them. `NetSentinel.exe.sha256` holds the checksum to verify the download,
and `NetSentinel.exe.sig` the signature the built-in updater checks before installing.
"""


def notes(tag, changelog):
    match = re.search(rf'^## {re.escape(tag)}\b[^\n]*\n(.*?)(?=^## |\Z)',
                      changelog, re.M | re.S)
    body = match.group(1).strip() if match else f'NetSentinel {tag}'
    return body + '\n' + INSTALL


if __name__ == '__main__':
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, 'CHANGELOG.md'), encoding='utf-8') as f:
        print(notes(sys.argv[1], f.read()))
