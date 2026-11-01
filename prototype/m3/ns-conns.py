"""Who is connected to a port in a process's network namespace (M3-03), read
from the host: the established client ends to 127.0.0.1:PORT in
/proc/<pid>/net/tcp, each with the processes holding it. This shows whether the
dashboard's terminal holds its backend connection, rather than inferring it.

    python3 -I ns-conns.py PID PORT

One line per connection: the client's port, then each holder as pid:comm.
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import peerowner  # noqa: E402


def clients(text, port):
    """(client port, inode) of each established connection to 127.0.0.1:port."""
    found = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        try:
            local, remote = peerowner.address(fields[1]), peerowner.address(fields[2])
            state, inode = fields[3], fields[9]
        except (IndexError, ValueError, OSError):
            continue
        if remote == ("127.0.0.1", port) and state == peerowner.ESTABLISHED:
            found.append((local[1], inode))
    return found


def main():
    pid, port = sys.argv[1], int(sys.argv[2])
    spec = importlib.util.spec_from_file_location("ns_listeners", f"{HERE}/ns-listeners.py")
    listeners = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(listeners)
    try:
        with open(f"/proc/{pid}/net/tcp") as f:
            found = clients(f.read(), port)
    except OSError as e:
        sys.exit(f"/proc/{pid}/net/tcp: {e.strerror}")
    held, _ = listeners.holders({inode for _, inode in found})
    for client, inode in sorted(found):
        print(f"{client}\t{' '.join(sorted(held.get(inode, []))) or 'holders unreadable'}")


if __name__ == "__main__":
    main()
