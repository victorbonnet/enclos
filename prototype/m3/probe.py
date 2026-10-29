"""Probes for the M3-02 bubblewrap prototype. Each argument is one probe, its
words separated by spaces; each prints one tab-separated line: the probe,
then `ok` or the error's name (ENOENT, EROFS, EACCES, EPERM, …), then a
detail. The same probes run on the host as their control and in the sandbox
in each mode, so a refusal is read against what the host does.

    python3 -I probe.py 'read /home/u/.ssh/id' 'write /usr/x' 'tiocsti' ...

Probes that would change something undo it: a file written is removed, a
folder renamed is renamed back, a ptrace attach is detached at once. The only
signal sent is signal 0, which checks a process exists and delivers nothing.
"""

import ctypes
import errno
import os
import platform
import select
import socket
import subprocess
import sys

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

# System call numbers for the calls glibc has no wrapper for.
NR = {
    "x86_64": {"keyctl": 250, "bpf": 321, "perf_event_open": 298, "userfaultfd": 323,
               "io_uring_setup": 425},
    "aarch64": {"keyctl": 219, "bpf": 280, "perf_event_open": 241, "userfaultfd": 282,
                "io_uring_setup": 425},
}[platform.machine()]


def err(e):
    return errno.errorcode.get(e, str(e))


def sys_result(r):
    if r < 0:
        return err(ctypes.get_errno()), ""
    return "ok", f"returned {r}"


def p_read(path):
    try:
        if os.path.isdir(path):
            return "ok", f"{len(os.listdir(path))} entries"
        with open(path, "rb") as f:
            f.read(1)
        return "ok", "read"
    except OSError as e:
        return err(e.errno), ""


def p_exists(path):
    return ("ok", "exists") if os.path.lexists(path) else ("ENOENT", "")


def p_write(path):
    """Create the file, then remove it."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as e:
        return err(e.errno), ""
    os.close(fd)
    os.unlink(path)
    return "ok", "created and removed"


def p_leave(path):
    """Create the file and leave it, for the host to look for afterwards."""
    try:
        with open(path, "x") as f:
            f.write("left by probe.py\n")
        return "ok", "left"
    except OSError as e:
        return err(e.errno), ""


def p_exec(path):
    try:
        out = subprocess.run([path], capture_output=True, timeout=20, text=True)
        return ("ok" if out.returncode == 0 else f"exit {out.returncode}"), out.stdout.strip()
    except OSError as e:
        return err(e.errno), ""


def p_rename(path):
    """Rename a folder beside itself, then back."""
    try:
        os.rename(path, path + ".moved")
    except OSError as e:
        return err(e.errno), ""
    os.rename(path + ".moved", path)
    return "ok", "renamed (and back)"


def p_tiocsti():
    """Push two characters into the terminal's input, then read them back."""
    import fcntl
    import termios
    if not os.isatty(0):
        return "inconclusive", "stdin is not a terminal"
    try:
        for c in b"Z\n":
            fcntl.ioctl(0, termios.TIOCSTI, bytes([c]))
    except OSError as e:
        return err(e.errno), ""
    if select.select([0], [], [], 2)[0]:
        return "ok", f"pushed, read back {os.read(0, 16)!r}"
    return "ok", "pushed, nothing read back"


def p_unshare(which):
    flag = {"user": os.CLONE_NEWUSER, "mount": os.CLONE_NEWNS, "net": os.CLONE_NEWNET}[which]
    try:
        os.unshare(flag)
        return "ok", f"made a {which} namespace"
    except OSError as e:
        return err(e.errno), ""


def p_mount():
    r = libc.mount(b"none", b"/tmp", b"tmpfs", ctypes.c_ulong(0), None)
    if r == 0:
        libc.umount2(b"/tmp", 0)
        return "ok", "mounted (and unmounted)"
    return err(ctypes.get_errno()), ""


def p_keyctl():
    # KEYCTL_GET_KEYRING_ID (0) of the session keyring (-3), without creating it.
    return sys_result(libc.syscall(NR["keyctl"], 0, -3, 0))


def p_bpf():
    # BPF_MAP_CREATE with an all-zero attribute: EINVAL if the call is let through.
    attr = ctypes.create_string_buffer(128)
    return sys_result(libc.syscall(NR["bpf"], 0, attr, 128))


def p_perf():
    # A zeroed perf_event_attr: EINVAL (or EACCES by perf_event_paranoid) if let through.
    attr = ctypes.create_string_buffer(128)
    return sys_result(libc.syscall(NR["perf_event_open"], attr, 0, -1, -1, 0))


def p_userfaultfd():
    # UFFD_USER_MODE_ONLY (1), which an unprivileged process may ask for.
    r = libc.syscall(NR["userfaultfd"], 1 | os.O_CLOEXEC)
    if r >= 0:
        os.close(r)
    return sys_result(r)


def p_io_uring():
    params = ctypes.create_string_buffer(120)
    r = libc.syscall(NR["io_uring_setup"], 1, params)
    if r >= 0:
        os.close(r)
    return sys_result(r)


def p_kill(pid):
    try:
        os.kill(int(pid), 0)
        return "ok", "process exists and could be signalled"
    except OSError as e:
        return err(e.errno), ""


def p_ptrace(pid):
    PTRACE_ATTACH, PTRACE_DETACH = 16, 17
    r = libc.ptrace(PTRACE_ATTACH, int(pid), None, None)
    if r == 0:
        # Wait for the attach's stop (__WALL), then detach, letting it run on.
        try:
            os.waitpid(int(pid), 0x40000000)
        except OSError:
            pass
        libc.ptrace(PTRACE_DETACH, int(pid), None, None)
        return "ok", "attached (and detached)"
    return err(ctypes.get_errno()), ""


def p_environ(marker):
    """Whether any process's start-up environment this side can read holds
    the marker the host's process was started with."""
    seen = 0
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                if marker.encode() in f.read():
                    return "ok", f"marker read in /proc/{pid}/environ"
            seen += 1
        except OSError:
            continue
    return "absent", f"marker in none of the {seen} environments readable"


def p_connect_unix(path, kind="stream"):
    t = {"stream": socket.SOCK_STREAM, "dgram": socket.SOCK_DGRAM,
         "seqpacket": socket.SOCK_SEQPACKET}[kind]
    s = socket.socket(socket.AF_UNIX, t)
    s.settimeout(3)
    addr = "\0" + path[1:] if path.startswith("@") else path
    try:
        s.connect(addr)
        return "ok", "connected"
    except OSError as e:
        return err(e.errno) if e.errno else "timeout", ""
    finally:
        s.close()


def p_connect_tcp(host, port):
    try:
        with socket.create_connection((host, int(port)), timeout=5):
            return "ok", "connected"
    except OSError as e:
        return err(e.errno) if e.errno else "timeout", ""


def p_dns(name):
    try:
        addrs = {a[4][0] for a in socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)}
        return "ok", " ".join(sorted(addrs))
    except socket.gaierror as e:
        return "EAI", str(e)


PROBES = {
    "read": p_read, "exists": p_exists, "write": p_write, "leave": p_leave,
    "exec": p_exec, "rename": p_rename, "tiocsti": p_tiocsti, "unshare": p_unshare,
    "mount": p_mount, "keyctl": p_keyctl, "bpf": p_bpf, "perf_event_open": p_perf,
    "userfaultfd": p_userfaultfd, "io_uring": p_io_uring, "kill": p_kill,
    "ptrace": p_ptrace, "environ": p_environ, "connect-unix": p_connect_unix,
    "connect-tcp": p_connect_tcp, "dns": p_dns,
}


def main():
    for spec in sys.argv[1:]:
        name, *args = spec.split()
        try:
            result, detail = PROBES[name](*args)
        except Exception as e:  # noqa: BLE001 - a probe that breaks is reported, not fatal
            result, detail = "error", repr(e)
        print(f"{spec}\t{result}\t{detail}", flush=True)


if __name__ == "__main__":
    main()
