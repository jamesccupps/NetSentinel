"""
Restart NetSentinel: start a new copy with the same arguments, then exit.

Several settings apply only at start (lower priority, review mode, GeoIP), so
"restart" is how they take effect without hunting for the process. Monitoring
resumes in the new copy if it was running in this one.
"""

import os
import subprocess
import sys

# Environment a PyInstaller onefile program passes to its children. Inherited,
# the new copy would reuse this one's unpack folder, which is deleted as this
# copy exits; PYINSTALLER_RESET_ENVIRONMENT (PyInstaller 6.9+) tells it to start
# afresh, and dropping the older variables covers earlier bootloaders.
_PYINSTALLER_VARS = ('_MEIPASS2', '_PYI_APPLICATION_HOME_DIR', '_PYI_ARCHIVE_FILE',
                     '_PYI_PARENT_PROCESS_LEVEL', '_PYI_SPLASH_IPC')


def relaunch_command(argv=None, executable=None, frozen=None, monitor=False):
    """The command that starts this program again, with --monitor if it should resume."""
    argv = list(sys.argv if argv is None else argv)
    executable = executable or sys.executable
    frozen = getattr(sys, 'frozen', False) if frozen is None else frozen
    args = [a for a in argv[1:] if a != '--monitor']
    if monitor:
        args.append('--monitor')
    if frozen:
        return [executable] + args
    return [executable, os.path.abspath(argv[0])] + args


def relaunch_environment(environ=None):
    env = dict(os.environ if environ is None else environ)
    for name in _PYINSTALLER_VARS:
        env.pop(name, None)
    env['PYINSTALLER_RESET_ENVIRONMENT'] = '1'
    return env


def relaunch(monitor=False):
    """Start the new copy, detached from this one. The caller then exits."""
    flags = 0
    if os.name == 'nt':
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen(relaunch_command(monitor=monitor), cwd=os.getcwd(),
                            env=relaunch_environment(), creationflags=flags,
                            close_fds=True)
