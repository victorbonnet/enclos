"""How a session joins its sandbox's namespaces (M3-03, design §15's row on
network and PID namespaces). Pure: it rewrites the compiled bubblewrap
arguments for one way of joining and prints the command, NUL-separated, for
sbx-ns.sh; test_nsjoin.py tests it anywhere.

    python3 -I nsjoin.py --compiled compiled.json --join <way> -- inside...

The namespaces are held by ns-holder.py, which ns-fds.py asks for them over a
Unix socket: they arrive as file descriptors 10 (user), 11 (PID) and 12
(network) before this command runs. bubblewrap can join a user namespace
(`--userns`) and a PID namespace (`--pidns`) but has no option to join a
network namespace, and entering one needs a capability in the user namespace
that owns it. So the ways tried are:

    own           today's prototype: every session its own namespaces
    nsenter       nsenter enters the holder's user and network namespaces,
                  then bubblewrap makes a user namespace nested in it and its
                  own PID namespace
    nsenter-pid   the same, and nsenter also enters the holder's PID
                  namespace, which bubblewrap then keeps
    nsenter-userns nsenter enters the user and network namespaces, then
                  bubblewrap is given the same user namespace with --userns
    userns        bubblewrap joins the holder's user and PID namespaces
                  (--userns, --pidns) and keeps CAP_SYS_ADMIN there, so
                  inside.py can enter the network namespace (setns) before it
                  drops every capability, then Landlock and seccomp
    userns-subpid the same, with a PID namespace of the session's own made
                  under the holder's (--unshare-pid with --pidns)
"""

import argparse
import json
import sys

FD_USER, FD_PID, FD_NET = 10, 11, 12
WAYS = ["own", "nsenter", "nsenter-pid", "nsenter-userns", "userns", "userns-subpid"]


def fd_path(fd):
    return f"/proc/self/fd/{fd}"


def without(args, *flags):
    return [a for a in args if a not in flags]


def join(bwrap_args, way):
    """Returns (prefix, bwrap_args, inside_args): the command run before
    bubblewrap, bubblewrap's arguments, and the extra arguments for inside.py.
    Every way but `own` closes the namespace descriptors in inside.py, so
    the command never holds them."""
    if way not in WAYS:
        raise ValueError(f"unknown way {way!r}")
    if way == "own":
        return [], list(bwrap_args), []
    close = ["--close-fd", str(FD_USER), "--close-fd", str(FD_PID), "--close-fd", str(FD_NET)]
    nsenter = ["nsenter", f"--user={fd_path(FD_USER)}", f"--net={fd_path(FD_NET)}"]
    if way == "nsenter":
        return nsenter + ["--preserve-credentials", "--"], without(bwrap_args, "--unshare-net"), close
    if way == "nsenter-pid":
        return (nsenter + [f"--pid={fd_path(FD_PID)}", "--preserve-credentials", "--"],
                without(bwrap_args, "--unshare-net", "--unshare-pid"), close)
    if way == "nsenter-userns":
        args = without(bwrap_args, "--unshare-user", "--disable-userns", "--unshare-net")
        return nsenter + ["--preserve-credentials", "--"], ["--userns", str(FD_USER)] + args, close
    drop = ["--unshare-user", "--disable-userns", "--unshare-net"]
    if way == "userns":
        drop.append("--unshare-pid")
    args = without(bwrap_args, *drop)
    joined = ["--userns", str(FD_USER), "--pidns", str(FD_PID), "--cap-add", "CAP_SYS_ADMIN"]
    return [], joined + args, ["--setns-net-fd", str(FD_NET)] + close


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--compiled", required=True)
    p.add_argument("--join", choices=WAYS, required=True)
    p.add_argument("--bwrap", default="bwrap")
    p.add_argument("inside", nargs=argparse.REMAINDER)
    o = p.parse_args(argv)
    inside = o.inside[1:] if o.inside[:1] == ["--"] else o.inside
    with open(o.compiled) as f:
        compiled = json.load(f)
    prefix, args, extra = join(compiled["bwrap"], o.join)
    # inside is `python3 -I inside.py <its options> -- command...`: the extra
    # options go before its `--`.
    cut = inside.index("--") if "--" in inside else len(inside)
    cmd = prefix + [o.bwrap] + args + ["--"] + inside[:cut] + extra + inside[cut:]
    sys.stdout.write("".join(a + "\0" for a in cmd))


if __name__ == "__main__":
    main()
