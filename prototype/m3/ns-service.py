"""A stand-in for a runtime's service in a session (M3-03): it listens as
Hermes's gateway does, on 127.0.0.1 at a port the kernel picks, and also on
every address and on an abstract Unix socket, then writes where it listens to
a file in the sandbox's home and waits. Its marker is in its command line and
its start-up environment, so the other sessions' probes can look for it.

    env ENCLOS_NS_MARKER=M python3 -I ns-service.py --name A --marker M --out F [--seconds N]
"""

import argparse
import json
import os
import socket
import threading
import time


def serve(srv):
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        try:
            conn.sendall(b"service\n")
        except OSError:
            pass
        conn.close()


def listen(family, addr):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.bind(addr)
    s.listen(16)
    threading.Thread(target=serve, args=(s,), daemon=True).start()
    return s


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--name", required=True)
    p.add_argument("--marker", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--seconds", type=int, default=600)
    o = p.parse_args()

    loopback = listen(socket.AF_INET, ("127.0.0.1", 0))
    anyaddr = listen(socket.AF_INET, ("0.0.0.0", 0))
    abstract = f"enclos-ns-{o.name}"
    listen(socket.AF_UNIX, "\0" + abstract)
    info = {
        "loopback": loopback.getsockname()[1],
        "any": anyaddr.getsockname()[1],
        "abstract": "@" + abstract,
        "pid_inside": os.getpid(),
        "marker": o.marker,
        "namespaces": {n: os.readlink(f"/proc/self/ns/{n}") for n in ["user", "pid", "net"]},
    }
    tmp = o.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(info, f)
    os.rename(tmp, o.out)
    time.sleep(o.seconds)


if __name__ == "__main__":
    main()
