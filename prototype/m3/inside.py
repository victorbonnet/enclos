"""The small program bubblewrap runs first inside the prototype sandbox
(M3-02; what M3-14's hidden enclos command will do). It applies the Landlock
rules where the kernel has Landlock (ADR 0037), then the seccomp filter,
then starts the relay, confined like the rest, and runs the command.

    python3 -I inside.py --compiled compiled.json [--landlock auto|off]
        [--seccomp on|off] [--relay] -- command...

Landlock goes through its three system calls with ctypes (stdlib only);
seccomp through libseccomp's Python binding (`python3-seccomp`). Each line it
prints on stderr starts with `inside:`, so a check can tell what applied.
"""

import argparse
import ctypes
import errno
import json
import os
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


def apply_landlock(rules):
    abi, err = landlock_abi()
    if abi is None:
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
        grants.append((path, READ | WRITE_FILE))
    added = []
    for path, access in grants:
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


def apply_seccomp(spec):
    import seccomp  # python3-seccomp

    refuse = seccomp.ERRNO(getattr(errno, spec["errno"]))
    f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
    skipped = []
    for name in spec["deny"]:
        try:
            f.add_rule(refuse, name)
        except (RuntimeError, ValueError, OSError):
            skipped.append(name)  # not a system call on this architecture
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


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--compiled", required=True)
    p.add_argument("--landlock", choices=["auto", "off"], default="auto")
    p.add_argument("--seccomp", choices=["on", "off"], default="on")
    p.add_argument("--relay", action="store_true")
    p.add_argument("command", nargs=argparse.REMAINDER)
    o = p.parse_args()
    cmd = o.command[1:] if o.command[:1] == ["--"] else o.command
    if not cmd:
        p.error("no command")
    with open(o.compiled) as f:
        compiled = json.load(f)

    if o.landlock == "auto":
        apply_landlock(compiled["landlock"])
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
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()
