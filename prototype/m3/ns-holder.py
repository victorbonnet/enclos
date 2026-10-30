"""The holder of a sandbox's namespaces (M3-03): what enclos would run for a
sandbox, in its proxy service for instance, so that every session joins one
network and PID namespace. bubblewrap starts it in a new user, PID and network
namespace; it opens its own namespaces and hands them, as file descriptors,
to whoever connects to its Unix socket (ns-fds.py), so the host needs no
access to /proc/<pid>/ns. With --relay, it also serves the sandbox's one
relay on 127.0.0.1 in that network namespace, so sessions need none of
their own. With --host-relay, it serves the other direction (decision 2): each
connection to a Unix socket in the host-only folder is passed to 127.0.0.1 in
that namespace, at the port in PORT_FILE. The host writes that file after
reading the port from the service's side; it is read per connection, so a
restarted service needs nothing from the holder, and no session can reach it.

    python3 -I ns-holder.py --socket S --info info.json [--relay PORT PROXY_SOCKET]
        [--host-relay SOCKET PORT_FILE]

The socket lives in a folder of the sandbox's that no session mounts.
"""

import argparse
import json
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import relay  # noqa: E402

NAMESPACES = ["user", "pid", "net"]  # the order ns-fds.py puts them at 10, 11, 12


def ns_ids():
    return {n: os.readlink(f"/proc/self/ns/{n}") for n in ["user", "pid", "net", "mnt", "ipc"]}


def serve_host_relay(srv, port_file):
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=to_service, args=(conn, port_file), daemon=True).start()


def to_service(conn, port_file):
    port = relay.read_port(port_file)
    if port is None:
        conn.close()
        return
    try:
        up = socket.create_connection(("127.0.0.1", port))
    except OSError:
        conn.close()
        return
    relay.pump(conn, up)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--socket", required=True)
    p.add_argument("--info", required=True)
    p.add_argument("--relay", nargs=2, metavar=("PORT", "PROXY_SOCKET"))
    p.add_argument("--host-relay", nargs=2, metavar=("SOCKET", "PORT_FILE"))
    o = p.parse_args()

    fds = [os.open(f"/proc/self/ns/{n}", os.O_RDONLY | os.O_CLOEXEC) for n in NAMESPACES]
    info = {"pid_inside": os.getpid(), "namespaces": ns_ids(), "relay": None}
    if o.relay:
        port, proxy = int(o.relay[0]), o.relay[1]
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(64)
        threading.Thread(target=relay.serve, args=(srv, proxy), daemon=True).start()
        info["relay"] = f"127.0.0.1:{port} -> {proxy}"

    if o.host_relay:
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(o.host_relay[0])
        os.chmod(o.host_relay[0], 0o600)
        srv.listen(64)
        threading.Thread(target=serve_host_relay, args=(srv, o.host_relay[1]), daemon=True).start()

    try:
        os.unlink(o.socket)
    except FileNotFoundError:
        pass
    ls = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    ls.bind(o.socket)
    os.chmod(o.socket, 0o600)
    ls.listen(16)
    tmp = o.info + ".tmp"
    with open(tmp, "w") as f:
        json.dump(info, f)
    os.rename(tmp, o.info)  # the check waits for this file
    while True:
        conn, _ = ls.accept()
        try:
            socket.send_fds(conn, [b"ns"], fds)
        except OSError:
            pass
        conn.close()


if __name__ == "__main__":
    main()
