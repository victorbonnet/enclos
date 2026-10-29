"""Runs a command with a new terminal as its controlling terminal and copies
what it prints to stdout, so the TIOCSTI probe has a terminal to push into
on a CI runner, which has none. Exits with the command's status.

    python3 -I pty-run.py -- command...
"""

import os
import pty
import sys

cmd = sys.argv[1:]
if cmd[:1] == ["--"]:
    cmd = cmd[1:]
pid, fd = pty.fork()
if pid == 0:
    os.execvp(cmd[0], cmd)
while True:
    try:
        data = os.read(fd, 65536)
    except OSError:  # EIO once the terminal's last user is gone
        break
    if not data:
        break
    sys.stdout.buffer.write(data.replace(b"\r\n", b"\n"))
    sys.stdout.flush()
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
