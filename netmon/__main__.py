"""
One entry point.
================
    python -m netmon <command> [options]

Each command is also importable and runnable on its own — `python -m
netmon.drift` and so on — which is what a cron entry or a unit file should use.
This exists so that `python -m netmon` with no arguments tells you what there
is, rather than requiring you to already know.
"""

from __future__ import annotations

import sys

#: command -> (module, one-line description). Imported lazily: scapy costs a
#: second or two and a UniFi-export user should never pay for it.
COMMANDS = {
    'analyze': ('netmon.analyze',
                'run the rules over a capture or a flow export'),
    'profile': ('netmon.profile', 'validate a site profile and describe it'),
    'rules': ('netmon.rules_engine', 'validate the detection rules'),
    'bpf': ('netmon.bpf', 'build and verify a VLAN-aware capture filter'),
    'capture': ('netmon.ringbuffer',
                'the rolling capture: what to run, keep and extract'),
    'drift': ('netmon.drift',
              'check the controller configuration and what changed'),
    'canary': ('netmon.canary', 'turn canary hits into findings'),
    'sync': ('netmon.sources.unifi_api',
             'build a site profile from the UniFi controller'),
    'web': ('netmon.web', 'the local web UI'),
    'serve': ('netmon.service', 'run everything on a schedule, as a service'),
}

#: Longer spellings people reach for.
ALIASES = {'analyse': 'analyze', 'summarise': 'analyze', 'ui': 'web',
           'ring': 'capture', 'ringbuffer': 'capture', 'unifi': 'sync',
           'daemon': 'serve', 'run': 'serve'}


def _usage():
    width = max(len(name) for name in COMMANDS)
    lines = [
        'netmon — a passive monitor for one building\'s network.',
        '',
        'Usage: python -m netmon <command> [options]',
        '       python -m netmon <command> --help',
        '',
        'Commands:',
    ]
    for name, (_, description) in COMMANDS.items():
        lines.append(f'  {name:<{width}}  {description}')
    lines += [
        '',
        'Start here if you have nothing yet:',
        '  python -m netmon sync    --host https://unifi.example --out my-site.yaml',
        '  python -m netmon profile my-site.yaml',
        '  python -m netmon analyze --profile my-site.yaml --pcap capture.pcapng',
        '',
        'Each command is also a module: python -m netmon.drift ... — which is',
        'what a unit file or a cron entry should use.',
    ]
    return '\n'.join(lines)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv or argv[0] in ('-h', '--help', 'help'):
        print(_usage())
        return 0
    if argv[0] in ('-V', '--version', 'version'):
        from netmon import __version__
        print(f'netmon {__version__}')
        return 0

    name = ALIASES.get(argv[0], argv[0])
    if name not in COMMANDS:
        print(f'netmon: no command "{argv[0]}"', file=sys.stderr)
        close = [c for c in COMMANDS if c.startswith(argv[0][:3])]
        if close:
            print(f'  did you mean: {", ".join(close)}?', file=sys.stderr)
        print(file=sys.stderr)
        print(_usage(), file=sys.stderr)
        return 2

    module_name, _ = COMMANDS[name]
    import importlib
    module = importlib.import_module(module_name)
    entry = getattr(module, '_main', None)
    if entry is None:
        print(f'netmon: {module_name} has no entry point', file=sys.stderr)
        return 1
    return entry(argv[1:])


if __name__ == '__main__':
    sys.exit(main())
