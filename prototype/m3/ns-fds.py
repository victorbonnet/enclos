"""Gets a sandbox's namespaces from its holder (ns-holder.py) and runs a
command with them open as file descriptors 10 (user), 11 (PID) and 12
(network), for nsenter or bubblewrap to join (M3-03).

    python3 -I ns-fds.py HOLDER_SOCKET -- command...
"""

import fcntl
import os
import socket
import sys


def main():
    path, rest = sys.argv[1], sys.argv[2:]
    cmd = rest[1:] if rest[:1] == ["--"] else rest
    if not cmd:
        sys.exit("usage: ns-fds.py HOLDER_SOCKET -- command...")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(path)
    _, fds, _, _ = socket.recv_fds(s, 16, 3)
    s.close()
    if len(fds) != 3:
        sys.exit(f"ns-fds.py: the holder sent {len(fds)} descriptors, not 3")
    # Move them out of the way first, so no dup2 lands on one not yet moved.
    high = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 100) for fd in fds]
    for fd in fds:
        os.close(fd)
    for want, fd in zip((10, 11, 12), high):
        os.dup2(fd, want, inheritable=True)
        os.close(fd)
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()
