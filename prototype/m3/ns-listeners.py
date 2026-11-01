"""The TCP ports listening on 127.0.0.1 in the network namespace of a host
process, and which processes hold each (M3-03), read from the host as ADR
0028 has enclos read its service's port: from /proc/<pid>/net/tcp, matched to
the holders' socket descriptors in /proc/*/fd.

    python3 -I ns-listeners.py PID [--ephemeral] [--held-by PID,...] [--port-only]

One line per port: the port, then each holder as pid:comm, or
`holders unreadable` when no descriptor of the user's processes could be
read. --ephemeral keeps the ports in the system's ephemeral range, where a
bind on port 0 lands; --held-by keeps the ports those processes hold, since in
a shared network namespace another session can listen there too; --port-only
prints the port alone when exactly one port is left, and nothing otherwise.
"""

import os
import sys


def listeners(pid):
    found = {}
    with open(f"/proc/{pid}/net/tcp") as f:
        for line in f.read().splitlines()[1:]:
            fields = line.split()
            addr, port = fields[1].split(":")
            if fields[3] == "0A" and addr == "0100007F":
                found[int(port, 16)] = fields[9]
    return found


def holders(inodes):
    held, unreadable = {}, 0
    for p in os.listdir("/proc"):
        if not p.isdigit():
            continue
        try:
            fds = os.listdir(f"/proc/{p}/fd")
        except OSError:
            unreadable += 1
            continue
        for fd in fds:
            try:
                target = os.readlink(f"/proc/{p}/fd/{fd}")
            except OSError:
                continue
            if target.startswith("socket:[") and target[8:-1] in inodes:
                try:
                    comm = open(f"/proc/{p}/comm").read().strip()
                except OSError:
                    comm = "?"
                held.setdefault(target[8:-1], set()).add(f"{p}:{comm}")
    return held, unreadable


def held_only(ports, held, pids):
    """The ports in `ports` (port: inode) one of `pids` holds, given `held`
    (inode: the set of "pid:comm" holders)."""
    want = {str(p) for p in pids}
    return {port: inode for port, inode in ports.items()
            if any(h.split(":")[0] in want for h in held.get(inode, ()))}


def main():
    pid = sys.argv[1]
    ephemeral = "--ephemeral" in sys.argv
    port_only = "--port-only" in sys.argv
    try:
        ports = listeners(pid)
    except OSError as e:
        sys.exit(f"/proc/{pid}/net/tcp: {e.strerror}")
    if ephemeral:
        lo, hi = map(int, open("/proc/sys/net/ipv4/ip_local_port_range").read().split())
        ports = {p: i for p, i in ports.items() if lo <= p <= hi}
    if "--held-by" in sys.argv:
        pids = [p for p in sys.argv[sys.argv.index("--held-by") + 1].split(",") if p]
        ports = held_only(ports, holders(set(ports.values()))[0], pids)
    if port_only:
        if len(ports) == 1:
            print(next(iter(ports)))
        return
    held, _ = holders(set(ports.values()))
    for port, inode in sorted(ports.items()):
        names = " ".join(sorted(held.get(inode, []))) or "holders unreadable"
        print(f"{port}\t{names}")


if __name__ == "__main__":
    main()
