"""What refuses joining a holder's namespaces (M3-03): run with the holder's
descriptors at 10 (user), 11 (PID) and 12 (network), from ns-fds.py, it
enters them one at a time as nsenter does, user first, and prints after each
step its AppArmor label, its capabilities and the error, if any.

    python3 -I ns-fds.py HOLDER_SOCKET -- python3 -I ns-diag.py [net-first]

With `net-first` it tries the network namespace before the user namespace,
the order in which a process outside the user namespace would need a
capability it does not have, as a control.
"""

import errno
import os
import sys


def state():
    try:
        label = open("/proc/self/attr/current").read().strip()
    except OSError as e:
        label = f"unreadable ({errno.errorcode.get(e.errno, e.errno)})"
    caps = []
    for line in open("/proc/self/status"):
        if line.startswith(("CapEff", "CapPrm")):
            caps.append(line.split()[0] + line.split()[1])
    ns = " ".join(os.readlink(f"/proc/self/ns/{n}") for n in ("user", "net", "pid"))
    return f"label={label} {' '.join(caps)} {ns}"


def step(name, fd, flag):
    try:
        os.setns(fd, flag)
        print(f"setns({name})\tok\t{state()}", flush=True)
    except OSError as e:
        print(f"setns({name})\t{errno.errorcode.get(e.errno, e.errno)}\t{state()}", flush=True)


def main():
    print(f"start\t-\t{state()}", flush=True)
    order = [("user", 10, os.CLONE_NEWUSER), ("net", 12, os.CLONE_NEWNET), ("pid", 11, os.CLONE_NEWPID)]
    if sys.argv[1:] == ["net-first"]:
        order = [order[1], order[0], order[2]]
    for name, fd, flag in order:
        step(name, fd, flag)


if __name__ == "__main__":
    main()
