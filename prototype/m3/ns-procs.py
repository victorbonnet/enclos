"""Host-side process lookups for the M3-03 checks, read from /proc only.

    python3 -I ns-procs.py descendants PID   # PID's descendants, deepest first
    python3 -I ns-procs.py match WORD...     # pid, comm and command line of every
                                             # process whose command line holds
                                             # every word, launchers left out

The first run counted Hermes's gateways by "gateway run" in `ps`, which
matched the relay inside.py forks (it keeps inside.py's command line) and not
Hermes's own gateway; `match` leaves out the launchers and prints `comm`, so
the output says which process it found.
"""

import os
import sys

LAUNCHERS = ("bwrap", "nsenter", "inside.py", "ns-fds.py", "ns-listen.py", "sbx-ns.sh",
             "timeout", "env", "bash")


def processes():
    for p in os.listdir("/proc"):
        if not p.isdigit():
            continue
        try:
            with open(f"/proc/{p}/stat") as f:
                ppid = int(f.read().rsplit(")", 1)[1].split()[1])
            with open(f"/proc/{p}/cmdline", "rb") as f:
                argv = [a.decode(errors="replace") for a in f.read().split(b"\0") if a]
            with open(f"/proc/{p}/comm") as f:
                comm = f.read().strip()
        except (OSError, IndexError, ValueError):
            continue
        yield int(p), ppid, comm, argv


def descendants(root):
    children = {}
    for pid, ppid, _, _ in processes():
        children.setdefault(ppid, []).append(pid)
    out, depth, todo = [], {}, [(root, 0)]
    while todo:
        pid, d = todo.pop()
        for c in children.get(pid, []):
            depth[c] = d + 1
            out.append(c)
            todo.append((c, d + 1))
    return sorted(out, key=lambda p: -depth[p])


def match(words):
    words = [w.lower() for w in words]
    for pid, _, comm, argv in processes():
        if pid == os.getpid() or not argv:
            continue
        line = " ".join(argv).lower()
        if not all(w in line for w in words):
            continue
        if any(os.path.basename(a) in LAUNCHERS for a in argv[:3]):
            continue
        yield pid, comm, " ".join(argv)


def main():
    if sys.argv[1] == "descendants":
        print(" ".join(map(str, descendants(int(sys.argv[2])))))
    elif sys.argv[1] == "match":
        for pid, comm, line in match(sys.argv[2:]):
            print(f"{pid}\t{comm}\t{line[:140]}")
    else:
        sys.exit(f"unknown command {sys.argv[1]}")


if __name__ == "__main__":
    main()
