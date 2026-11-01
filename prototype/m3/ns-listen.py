"""Makes the Unix socket the service's port is relayed through (M3-03, option
2) and runs a command with it listening as file descriptor 13. The host makes
it, in the sandbox's run/ folder, which the sandbox reads but cannot write,
so the service's session needs no write access there.

    python3 -I ns-listen.py SOCKET -- command...
"""

import os
import socket
import sys

FD = 13


def main():
    path, rest = sys.argv[1], sys.argv[2:]
    cmd = rest[1:] if rest[:1] == ["--"] else rest
    if not cmd:
        sys.exit("usage: ns-listen.py SOCKET -- command...")
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    os.chmod(path, 0o600)
    s.listen(64)
    os.dup2(s.fileno(), FD, inheritable=True)
    s.close()
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()
