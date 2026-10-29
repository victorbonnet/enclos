"""The prototype's compile step (M3-02, a draft of what M3-13 builds).

Turns the prototype's policy into what the bubblewrap backend applies:
bubblewrap's arguments, the Landlock rules and the seccomp filter, written as
one JSON file that sbx.sh hands to bubblewrap and inside.py reads inside the
sandbox. Pure apart from listing the folders that hold a denied path, so it
is safe on any host; test_compile.py runs it on a temporary folder.

    python3 -I compile.py --host-home H --sandbox-dir D --workspace W \\
        --deny H/.ssh ... [--new-session] --out compiled.json

The deny list is not mounted: every folder that holds a denied path gets an
empty tmpfs, then each of its other entries is bound back read-only, so a
denied path does not exist in the sandbox (ENOENT), not merely empty. Entries
made on the host after the session starts do not appear in such a folder.
"""

import argparse
import json
import os
import sys

# Programs may run from these where Landlock applies (and from the sandbox's
# home, where the runtime installs itself); the workspaces may not.
EXEC_SYSTEM = ["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/opt", "/snap"]

# The sandbox's own, empty places, each a tmpfs: they hide the host's
# sockets there (/run/user/<uid>, the system bus, resolved, Docker,
# /tmp/.X11-unix) and give the sandbox somewhere to write temporary files.
OWN_TMPFS = ["/tmp", "/var/tmp", "/run", "/dev/shm"]

# seccomp: system calls refused outright (design §14's list, then the kernel
# module, reboot and swap calls, which need privileges the sandbox lacks, and
# io_uring, whose operations seccomp does not see).
SECCOMP_DENY = [
    "keyctl", "add_key", "request_key",
    "bpf", "perf_event_open", "userfaultfd",
    "mount", "umount2", "pivot_root", "move_mount", "open_tree", "fsopen",
    "fsconfig", "fsmount", "fspick", "mount_setattr",
    "setns",
    "kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module",
    "reboot", "swapon", "swapoff", "acct", "quotactl", "quotactl_fd",
    "ioperm", "iopl", "open_by_handle_at", "uselib",
    "io_uring_setup", "io_uring_enter", "io_uring_register",
]
# ioctl requests refused (arg 1, compared on its low 32 bits as the kernel does).
SECCOMP_IOCTL = {"TIOCSTI": 0x5412, "TIOCLINUX": 0x541C}
# Namespace flags refused in unshare(2) and clone(2) (arg 0 for both, on
# x86_64 and arm64). clone3 passes its flags in memory seccomp cannot read,
# so it gets ENOSYS and the C library falls back to clone.
CLONE_NEW = {
    "CLONE_NEWTIME": 0x00000080,
    "CLONE_NEWNS": 0x00020000,
    "CLONE_NEWCGROUP": 0x02000000,
    "CLONE_NEWUTS": 0x04000000,
    "CLONE_NEWIPC": 0x08000000,
    "CLONE_NEWUSER": 0x10000000,
    "CLONE_NEWPID": 0x20000000,
    "CLONE_NEWNET": 0x40000000,
}


def under(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def hide(folder, denied, args, remount):
    """Mount an empty tmpfs on `folder`, then bind back every entry that is
    neither denied nor on the way to a denied path."""
    args += ["--tmpfs", folder]
    remount.append(folder)
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if path in denied:
            continue
        if os.path.islink(path):
            args += ["--symlink", os.readlink(path), path]
        elif os.path.isdir(path) and any(under(d, path) for d in denied):
            hide(path, denied, args, remount)
        else:
            args += ["--ro-bind", path, path]


def compile_policy(o):
    home = os.path.join(o.sandbox_dir, "home")
    run = os.path.join(o.sandbox_dir, "run")
    compiled = os.path.join(o.sandbox_dir, "compiled")
    denied = {os.path.normpath(d) for d in o.deny}
    for d in denied:
        if not under(d, o.host_home) or d == o.host_home:
            sys.exit(f"compile.py: deny entry {d} is not under {o.host_home}")

    args = ["--ro-bind", "/", "/"]  # broad reads (ADR 0015)
    remount = []
    if denied:
        hide(o.host_home, denied, args, remount)
    args += ["--dev", "/dev", "--proc", "/proc"]
    for t in OWN_TMPFS:
        args += ["--tmpfs", t]
    args += ["--bind", home, home]
    for w in o.workspace:
        args += ["--bind", w, w]
    # The proxy's socket and the compiled policy, read-only: connecting to a
    # socket needs no write access to its mount (ADR 0004).
    args += ["--ro-bind", run, run, "--ro-bind", compiled, compiled]
    # The tmpfs that hide denied paths were writable while bubblewrap made
    # mount points in them; nothing may write there afterwards.
    for r in remount:
        args += ["--remount-ro", r]
    args += [
        "--unshare-user", "--disable-userns",
        "--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts",
        "--unshare-cgroup-try",
        "--die-with-parent",
    ]
    if o.new_session:
        args += ["--new-session"]
    proxy = f"http://127.0.0.1:{o.relay_port}"
    env = {
        "HOME": home,
        "PATH": f"{home}/.local/bin:/usr/local/bin:/usr/bin:/bin",
        "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
        "TERM": "xterm-256color",
        "HTTPS_PROXY": proxy, "HTTP_PROXY": proxy,
        "https_proxy": proxy, "http_proxy": proxy,
        "NO_PROXY": "", "NODE_USE_ENV_PROXY": "1",
        "ENCLOS_PROXY_SOCKET": os.path.join(run, "proxy.sock"),
    }
    args += ["--clearenv"]
    for k, v in env.items():
        args += ["--setenv", k, v]
    args += ["--chdir", home]

    return {
        "bwrap": args,
        "landlock": {
            "read": ["/"],
            "execute": EXEC_SYSTEM + [home],
            "write": [home] + list(o.workspace) + ["/tmp", "/var/tmp", "/dev/shm"],
            "devices": ["/dev"],
            "proc_write": ["/proc"],
            "scoped": ["abstract_unix_socket", "signal"],
        },
        "seccomp": {
            "errno": "EPERM",
            "deny": SECCOMP_DENY,
            "ioctl": SECCOMP_IOCTL,
            "clone_flags": CLONE_NEW,
            "enosys": ["clone3"],
        },
        "relay": {"port": o.relay_port, "socket": env["ENCLOS_PROXY_SOCKET"]},
    }


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--host-home", required=True)
    p.add_argument("--sandbox-dir", required=True)
    p.add_argument("--workspace", action="append", default=[])
    p.add_argument("--deny", action="append", default=[])
    p.add_argument("--relay-port", type=int, default=18080)
    p.add_argument("--new-session", action="store_true")
    p.add_argument("--out", required=True)
    o = p.parse_args(argv)
    with open(o.out, "w") as f:
        json.dump(compile_policy(o), f, indent=1)


if __name__ == "__main__":
    main()
