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


def relaunch(monitor=False, popen=None):
    """
    Start the new copy, detached from this one. The caller then exits.

    The exe is started through this process's hold on it (launch_guard), so it
    is the same file this copy started from: a program running as the owner
    could otherwise rename it and put its own in its place, to be started as
    Administrator with no prompt.
    """
    from src.launch_guard import own_exe_hold, start_held
    command = relaunch_command(monitor=monitor)
    flags = 0
    if os.name == 'nt':
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    kwargs = dict(cwd=os.getcwd(), env=relaunch_environment(), creationflags=flags,
                  close_fds=True)
    hold = own_exe_hold(command[0]) if getattr(sys, 'frozen', False) else None
    if hold is not None:
        return start_held(command, held_file=hold, popen=popen, **kwargs)
    return (popen or subprocess.Popen)(command, **kwargs)
