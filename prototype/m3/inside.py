"""The small program bubblewrap runs first inside the prototype sandbox,
a draft of what enclos itself will run there. It applies the Landlock
rules where the kernel has Landlock (ADR 0037), then the seccomp filter,
then starts the relay, confined like the rest, and runs the command.

    python3 -I inside.py --compiled compiled.json [--landlock auto|off]
        [--seccomp on|off] [--proc-truncate] [--relay] [--setns-net-fd N] [--close-fd N]...
        [--service-forward FD PORT_FILE] [--service-relay PORT SOCKET]
        -- command...

--setns-net-fd enters the sandbox's network namespace from a
descriptor its holder gave (nsjoin.py's `userns` ways, where bubblewrap kept
CAP_SYS_ADMIN in the holder's user namespace), then drops every capability,
before Landlock and seccomp, which refuses setns. --close-fd closes the
holder's descriptors so the command never holds them.

For nsjoin.py's `relay` way, where every session has its
own network namespace: in the service's session, --service-forward accepts
on a Unix socket the host made and passed in as FD (in the sandbox's run/
folder, which the sandbox cannot write) and forwards each connection to
127.0.0.1 at the port the host wrote in PORT_FILE, also in run/, after it
read the port from the service's own listeners. In every other session,
--service-relay listens on 127.0.0.1:PORT and forwards each connection to
that socket, as the proxy's relay does.

Landlock goes through its three system calls with ctypes (stdlib only);
seccomp through libseccomp's Python binding (`python3-seccomp`). Each line it
prints on stderr starts with `inside:`, so a check can tell what applied.
"""

import argparse
import ctypes
import errno
import json
import os
import platform
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import relay  # noqa: E402

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

# Landlock's system calls have the same numbers on every architecture.
SYS_CREATE_RULESET, SYS_ADD_RULE, SYS_RESTRICT_SELF = 444, 445, 446
CREATE_RULESET_VERSION = 1
RULE_PATH_BENEATH = 1
PR_SET_NO_NEW_PRIVS = 38
PR_CAPBSET_DROP = 24
PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 47, 4
LINUX_CAPABILITY_VERSION_3 = 0x20080522

# Filesystem rights (include/uapi/linux/landlock.h).
EXECUTE = 1 << 0
WRITE_FILE = 1 << 1
READ_FILE = 1 << 2
READ_DIR = 1 << 3
REMOVE_DIR = 1 << 4
REMOVE_FILE = 1 << 5
MAKE_CHAR = 1 << 6
MAKE_DIR = 1 << 7
MAKE_REG = 1 << 8
MAKE_SOCK = 1 << 9
MAKE_FIFO = 1 << 10
MAKE_BLOCK = 1 << 11
MAKE_SYM = 1 << 12
REFER = 1 << 13      # ABI 2
TRUNCATE = 1 << 14   # ABI 3
IOCTL_DEV = 1 << 15  # ABI 5
SCOPES = {"abstract_unix_socket": 1 << 0, "signal": 1 << 1}  # ABI 6

# What landlock_create_ruleset answers where Landlock is missing: not built, or
# built and not active. Any other error stops the session (ADR 0037 covers a
# missing Landlock, not an outer filter's EPERM or an ENOMEM).
LANDLOCK_MISSING = {errno.errorcode[errno.ENOSYS], errno.errorcode[errno.EOPNOTSUPP]}
# seccomp: the calls of the deny list an architecture does not have. Any other
# rule that cannot be added stops the session.
SECCOMP_ABSENT = {"aarch64": {"ioperm", "iopl", "uselib"}}

READ = READ_FILE | READ_DIR
WRITE = (WRITE_FILE | REMOVE_DIR | REMOVE_FILE | MAKE_DIR | MAKE_REG
         | MAKE_SOCK | MAKE_FIFO | MAKE_SYM | REFER | TRUNCATE)


def say(msg):
    print(f"inside: {msg}", file=sys.stderr, flush=True)


def handled_for(abi):
    rights = (1 << 13) - 1  # ABI 1: EXECUTE … MAKE_SYM
    if abi >= 2:
        rights |= REFER
    if abi >= 3:
        rights |= TRUNCATE
    if abi >= 5:
        rights |= IOCTL_DEV
    return rights


def landlock_abi():
    r = libc.syscall(SYS_CREATE_RULESET, None, ctypes.c_size_t(0),
                     ctypes.c_uint32(CREATE_RULESET_VERSION))
    if r < 0:
        return None, errno.errorcode.get(ctypes.get_errno(), "?")
    return r, None


def landlock_grants(rules, proc_truncate=False):
    """(path, rights) for each rule. `proc_truncate` adds TRUNCATE to the /proc
    rule, for oom-check.sh and test_oom.py to compare; the draft rules leave
    it out, while TRUNCATE stays handled."""
    grants = []
    for path in rules["read"]:
        grants.append((path, READ))
    for path in rules["execute"]:
        grants.append((path, READ | EXECUTE))
    for path in rules["write"]:
        grants.append((path, READ | WRITE))
    for path in rules["devices"]:
        grants.append((path, READ | WRITE_FILE | TRUNCATE | IOCTL_DEV))
    for path in rules["proc_write"]:
        grants.append((path, READ | WRITE_FILE | (TRUNCATE if proc_truncate else 0)))
    return grants


def apply_landlock(rules, proc_truncate=False):
    abi, err = landlock_abi()
    if abi is None:
        if err not in LANDLOCK_MISSING:
            sys.exit(f"inside: landlock_create_ruleset: {err}")
        say(f"landlock=missing ({err}): writes held by bubblewrap's mounts alone")
        return
    handled = handled_for(abi)
    scoped = 0
    if abi >= 6:
        for s in rules["scoped"]:
            scoped |= SCOPES[s]
    # struct landlock_ruleset_attr: handled_access_fs, handled_access_net,
    # scoped. Fields the kernel does not know must be zero, which they are.
    attr = struct.pack("=QQQ", handled, 0, scoped)
    fd = libc.syscall(SYS_CREATE_RULESET, attr, ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
    if fd < 0:
        sys.exit(f"inside: landlock_create_ruleset: {os.strerror(ctypes.get_errno())}")

    added = []
    for path, access in landlock_grants(rules, proc_truncate):
        try:
            pfd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        except FileNotFoundError:
            continue
        # A file (not a folder) may hold only the rights that apply to files.
        if not os.path.isdir(path):
            access &= EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV
        # struct landlock_path_beneath_attr is packed: u64 then s32.
        beneath = struct.pack("=Qi", access & handled, pfd)
        r = libc.syscall(SYS_ADD_RULE, ctypes.c_int(fd), ctypes.c_int(RULE_PATH_BENEATH),
                         beneath, ctypes.c_uint32(0))
        e = ctypes.get_errno()
        os.close(pfd)
        if r < 0:
            sys.exit(f"inside: landlock_add_rule {path}: {os.strerror(e)}")
        added.append(path)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, ctypes.c_ulong(1), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)) != 0:
        sys.exit(f"inside: no_new_privs: {os.strerror(ctypes.get_errno())}")
    if libc.syscall(SYS_RESTRICT_SELF, ctypes.c_int(fd), ctypes.c_uint32(0)) < 0:
        sys.exit(f"inside: landlock_restrict_self: {os.strerror(ctypes.get_errno())}")
    os.close(fd)
    say(f"landlock=applied abi={abi} handled=0x{handled:x} scoped=0x{scoped:x} rules={len(added)}")


def capabilities():
    with open("/proc/self/status") as f:
        return " ".join(line.split()[0] + line.split()[1] for line in f
                        if line.startswith(("CapEff", "CapPrm", "CapBnd", "CapAmb")))


def enter_netns(fd):
    """Enter the network namespace, then drop every capability: the
    ambient set, the bounding set where allowed, then capset to nothing."""
    before = os.readlink("/proc/self/ns/net")
    try:
        os.setns(fd, os.CLONE_NEWNET)
    except OSError as e:
        sys.exit(f"inside: setns(net): {errno.errorcode.get(e.errno, e.errno)}")
    after = os.readlink("/proc/self/ns/net")
    libc.prctl(PR_CAP_AMBIENT, ctypes.c_ulong(PR_CAP_AMBIENT_CLEAR_ALL), ctypes.c_ulong(0),
               ctypes.c_ulong(0), ctypes.c_ulong(0))
    for cap in range(64):
        libc.prctl(PR_CAPBSET_DROP, ctypes.c_ulong(cap), ctypes.c_ulong(0), ctypes.c_ulong(0),
                   ctypes.c_ulong(0))
    header = struct.pack("=Ii", LINUX_CAPABILITY_VERSION_3, 0)
    data = bytes(24)  # two __user_cap_data_struct, all zero
    if libc.capset(header, data) != 0:
        sys.exit(f"inside: capset: {os.strerror(ctypes.get_errno())}")
    say(f"netns=joined {before} -> {after}; capabilities after: {capabilities()}")


def apply_seccomp(spec):
    import seccomp  # python3-seccomp

    refuse = seccomp.ERRNO(getattr(errno, spec["errno"]))
    f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
    absent = SECCOMP_ABSENT.get(platform.machine(), set())
    skipped = []
    for name in spec["deny"]:
        if name in absent:
            skipped.append(name)
            continue
        # libseccomp knows every name on every architecture, and silently
        # drops a rule for a call this one lacks (a negative number here).
        try:
            if seccomp.resolve_syscall(seccomp.Arch.NATIVE, name) < 0:
                sys.exit(f"inside: seccomp: {name} is not a system call here")
            f.add_rule(refuse, name)
        except (RuntimeError, ValueError, OSError) as e:
            sys.exit(f"inside: seccomp rule for {name}: {e}")
    for value in spec["ioctl"].values():
        f.add_rule(refuse, "ioctl", seccomp.Arg(1, seccomp.MASKED_EQ, 0xFFFFFFFF, value))
    for flag in spec["clone_flags"].values():
        for call in ("unshare", "clone"):
            f.add_rule(refuse, call, seccomp.Arg(0, seccomp.MASKED_EQ, flag, flag))
    for name in spec["enosys"]:
        f.add_rule(seccomp.ERRNO(errno.ENOSYS), name)
    f.load()  # sets no_new_privs first
    note = f" (not on this architecture: {' '.join(skipped)})" if skipped else ""
    say(f"seccomp=applied deny={len(spec['deny']) - len(skipped)}{note}")


def start_service_forward(fd, port_file):
    """In the service's session: each connection on the host's Unix socket
    to 127.0.0.1 at the port the host recorded."""
    srv = socket.socket(fileno=fd)

    def one(conn):
        port = relay.read_port(port_file)
        if port is None:
            conn.close()
            return
        try:
            up = socket.create_connection(("127.0.0.1", port), timeout=10)
            up.settimeout(None)
        except OSError:
            conn.close()
            return
        relay.pump(conn, up)

    if os.fork() == 0:
        import threading
        try:
            while True:
                conn, _ = srv.accept()
                threading.Thread(target=one, args=(conn,), daemon=True).start()
        finally:
            os._exit(0)
    srv.close()
    say(f"service-forward=fd {fd} -> 127.0.0.1:<port in {port_file}>")


def start_service_relay(port, path):
    """In every other session: 127.0.0.1:port to the service's socket."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(64)
    if os.fork() == 0:
        relay.serve(srv, path)
        os._exit(0)
    srv.close()
    say(f"service-relay=127.0.0.1:{port} -> {path}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--compiled", required=True)
    p.add_argument("--landlock", choices=["auto", "off"], default="auto")
    p.add_argument("--seccomp", choices=["on", "off"], default="on")
    p.add_argument("--proc-truncate", action="store_true")
    p.add_argument("--relay", action="store_true")
    p.add_argument("--setns-net-fd", type=int)
    p.add_argument("--close-fd", type=int, action="append", default=[])
    p.add_argument("--service-forward", nargs=2, metavar=("FD", "PORT_FILE"))
    p.add_argument("--service-relay", nargs=2, metavar=("PORT", "SOCKET"))
    p.add_argument("command", nargs=argparse.REMAINDER)
    o = p.parse_args()
    cmd = o.command[1:] if o.command[:1] == ["--"] else o.command
    if not cmd:
        p.error("no command")
    with open(o.compiled) as f:
        compiled = json.load(f)

    if o.setns_net_fd is not None:
        enter_netns(o.setns_net_fd)
    for fd in o.close_fd:
        try:
            os.close(fd)
        except OSError:
            pass
    if o.landlock == "auto":
        apply_landlock(compiled["landlock"], o.proc_truncate)
    else:
        say("landlock=off (asked)")
    if o.seccomp == "on":
        apply_seccomp(compiled["seccomp"])
    else:
        say("seccomp=off (asked)")
    if o.relay:
        # Listen before forking, so the command never races the relay.
        r = compiled["relay"]
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", r["port"]))
        srv.listen(64)
        if os.fork() == 0:
            relay.serve(srv, r["socket"])
            os._exit(0)
        srv.close()
        say(f"relay=127.0.0.1:{r['port']} -> {r['socket']}")
    if o.service_forward:
        start_service_forward(int(o.service_forward[0]), o.service_forward[1])
    if o.service_relay:
        start_service_relay(int(o.service_relay[0]), o.service_relay[1])
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()
