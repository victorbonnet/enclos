"""Probes for the bubblewrap prototype. Each argument is one probe, its
words separated by spaces; each prints one tab-separated line: the probe,
then `ok` or the error's name (ENOENT, EROFS, EACCES, EPERM, …), then a
detail. The same probes run on the host as their control and in the sandbox
in each mode, so a refusal is read against what the host does.

    python3 -I probe.py 'read /home/u/.ssh/id' 'write /usr/x' 'tiocsti' ...

Probes that would change something undo it: a file written is removed, a
folder renamed is renamed back, a ptrace attach is detached at once. unshare
cannot be undone, so it runs in a process of its own, and the probes after it
stay as they started. The only signal sent is signal 0, which checks a process
exists and delivers nothing.
"""

import ctypes
import errno
import fcntl
import os
import platform
import select
import socket
import struct
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

# The dynamic loader, which runs the program it is given in its own process.
LOADER = {"x86_64": "/lib64/ld-linux-x86-64.so.2",
          "aarch64": "/lib/ld-linux-aarch64.so.1"}[platform.machine()]


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
            n = len(f.read(64))
        return "ok", f"read, {n} bytes"
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


def p_open_write(path):
    """Open an existing file to write, changing nothing."""
    try:
        os.close(os.open(path, os.O_WRONLY))
    except OSError as e:
        return err(e.errno), ""
    return "ok", "opened to write"


def p_leave(path):
    """Create the file and leave it, for the host to look for afterwards."""
    try:
        with open(path, "x") as f:
            f.write("left by probe.py\n")
        return "ok", "left"
    except OSError as e:
        return err(e.errno), ""


def run_program(argv, pass_fds=()):
    try:
        out = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=20,
                             text=True, pass_fds=pass_fds)
        return ("ok" if out.returncode == 0 else f"exit {out.returncode}"), out.stdout.strip()
    except OSError as e:
        return err(e.errno), ""


def p_exec(path):
    return run_program([path])


def p_exec_loader(path):
    """Have the loader run it: the exec is of the loader, not of the path."""
    return run_program([LOADER, path])


def p_exec_memfd(path):
    """Copy it to a memfd and exec that, which is on no path a rule names."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return err(e.errno), ""
    fd = os.memfd_create("probe", 0)  # not close-on-exec: the exec goes through it
    try:
        os.write(fd, data)
        return run_program([f"/proc/self/fd/{fd}"], pass_fds=(fd,))
    finally:
        os.close(fd)


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
    """In a forked process, which reports the errno as its exit status."""
    flag = {"user": os.CLONE_NEWUSER, "mount": os.CLONE_NEWNS, "net": os.CLONE_NEWNET}[which]
    pid = os.fork()
    if pid == 0:
        try:
            os.unshare(flag)
            os._exit(0)
        except OSError as e:
            os._exit(e.errno)
    code = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
    if code == 0:
        return "ok", f"made a {which} namespace"
    return (err(code), "") if code > 0 else (f"signal {-code}", "")


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


def p_connect_vsock(cid, port):
    """To a CID (2 the hypervisor, 1 this kernel), which is no network
    interface, so a network namespace may not hold it."""
    try:
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    except OSError as e:
        return err(e.errno), ""
    s.settimeout(3)
    try:
        s.connect((int(cid), int(port)))
        return "ok", "connected"
    except OSError as e:
        return err(e.errno) if e.errno else "timeout", ""
    finally:
        s.close()


def p_dns(name):
    try:
        addrs = {a[4][0] for a in socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)}
        return "ok", " ".join(sorted(addrs))
    except socket.gaierror as e:
        return "EAI", str(e)


# What a session sees of its sandbox's other sessions.

def p_netns():
    return "ok", " ".join(os.readlink(f"/proc/self/ns/{n}") for n in ("user", "pid", "net"))


# The marker is passed to these probes reversed, so that neither their own
# command line nor bubblewrap's, which holds the probes', matches it.
LAUNCHERS = ("bwrap", "nsenter", "inside.py", "ns-fds.py", "sbx-ns.sh", "probe.py", "timeout")


def find_marker(reversed_marker):
    """The pids, as this side numbers them, of the processes whose command
    line holds the marker, launchers left out."""
    marker = reversed_marker[::-1].encode()
    found = []
    for p in os.listdir("/proc"):
        if not p.isdigit() or int(p) == os.getpid():
            continue
        try:
            with open(f"/proc/{p}/cmdline", "rb") as f:
                argv = f.read().split(b"\0")
        except OSError:
            continue
        if not any(marker in a for a in argv):
            continue
        if any(os.path.basename(a.decode(errors="replace")) in LAUNCHERS for a in argv[:3]):
            continue
        found.append(int(p))
    return found


def p_find(marker):
    found = find_marker(marker)
    total = sum(1 for p in os.listdir("/proc") if p.isdigit())
    if found:
        return "ok", f"pids {' '.join(map(str, found))} of {total} listed"
    return "absent", f"{total} processes listed, marker in none"


def peer(marker, act):
    found = find_marker(marker)
    if not found:
        return "absent", "no process with the marker in sight"
    result, detail = act(found[-1])
    return result, f"pid {found[-1]}" + (f"; {detail}" if detail else "")


def p_peer_kill(marker):
    return peer(marker, p_kill)


def p_peer_ptrace(marker):
    return peer(marker, p_ptrace)


def p_peer_environ(marker):
    def read(pid):
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                held = marker[::-1].encode() in f.read()
            return ("ok", "marker read") if held else ("ok", "read, no marker")
        except OSError as e:
            return err(e.errno), ""
    return peer(marker, read)


def p_listen_tcp(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, int(port)))
        s.listen(1)
        return "ok", f"bound {host}:{s.getsockname()[1]}"
    except OSError as e:
        return err(e.errno), ""
    finally:
        s.close()


def p_http(url):
    """A request through the proxy variables, as clients make them."""
    import urllib.request
    try:
        return "ok", f"status {urllib.request.urlopen(url, timeout=20).status}"
    except urllib.error.HTTPError as e:
        return "ok", f"status {e.code}"
    except OSError as e:
        return err(e.errno) if getattr(e, "errno", None) else "error", str(e)[:80]


def p_fds():
    """Namespace descriptors this process holds open."""
    held = []
    for fd in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            continue
        if target.split(":")[0] in ("user", "pid", "net", "mnt"):
            held.append(f"{fd}={target}")
    return ("held", " ".join(held)) if held else ("none", "")


def p_setns_net():
    """Joining the network namespace this process is already in: the call
    still needs CAP_SYS_ADMIN in the user namespace that owns it."""
    fd = os.open("/proc/self/ns/net", os.O_RDONLY)
    try:
        os.setns(fd, os.CLONE_NEWNET)
        return "ok", "joined"
    except OSError as e:
        return err(e.errno), ""
    finally:
        os.close(fd)


def p_net_admin():
    """Setting loopback's flags to what they are: needs CAP_NET_ADMIN in the
    user namespace that owns the network namespace, and changes nothing."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        req = fcntl.ioctl(s, 0x8913, struct.pack("16sh14x", b"lo", 0))  # SIOCGIFFLAGS
        fcntl.ioctl(s, 0x8914, req)  # SIOCSIFFLAGS
        return "ok", "set"
    except OSError as e:
        return err(e.errno), ""
    finally:
        s.close()


def p_status():
    """What the kernel holds of this process's confinement."""
    want = ("NoNewPrivs", "Seccomp", "CapEff", "CapBnd")
    with open("/proc/self/status") as f:
        found = dict(line.split(":\t", 1) for line in f if ":\t" in line)
    return "ok", " ".join(f"{k}={found[k].strip()}" for k in want if k in found)


def p_max_userns():
    with open("/proc/sys/user/max_user_namespaces") as f:
        return "ok", f.read().strip()


def p_nsopen(path):
    try:
        fd = os.open(path, os.O_RDONLY)
        os.close(fd)
        return "ok", os.readlink(path)
    except OSError as e:
        return err(e.errno), ""


PROBES = {
    "read": p_read, "exists": p_exists, "write": p_write, "open-write": p_open_write, "leave": p_leave,
    "exec": p_exec, "exec-loader": p_exec_loader, "exec-memfd": p_exec_memfd, "rename": p_rename, "tiocsti": p_tiocsti, "unshare": p_unshare,
    "mount": p_mount, "keyctl": p_keyctl, "bpf": p_bpf, "perf_event_open": p_perf,
    "userfaultfd": p_userfaultfd, "io_uring": p_io_uring, "kill": p_kill,
    "ptrace": p_ptrace, "connect-unix": p_connect_unix,
    "connect-tcp": p_connect_tcp, "connect-vsock": p_connect_vsock, "dns": p_dns,
    "netns": p_netns, "find": p_find, "peer-kill": p_peer_kill, "peer-ptrace": p_peer_ptrace,
    "peer-environ": p_peer_environ, "listen-tcp": p_listen_tcp, "http": p_http, "fds": p_fds,
    "nsopen": p_nsopen, "setns-net": p_setns_net, "net-admin": p_net_admin, "status": p_status,
    "max-userns": p_max_userns,
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
