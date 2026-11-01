"""The host's side of the path to a sandbox's service (M3-03): it listens on
the host's 127.0.0.1 at the sandbox's reserved port and passes each connection
to a Unix socket in the host-only folder, which the holder relays into the
sandbox's network namespace (ns-holder.py --host-relay). Only the user running
it is served: each client's socket must belong to that user (peerowner.py), and
any other connection is closed before a byte reaches the service, because
Hermes publishes its session token to whoever reaches its page.

    python3 -I host-listen.py --port RESERVED --socket S [--no-reuseaddr]

Loopback and the check on the owner are hard-coded: there is deliberately no
option for either. --no-reuseaddr is the check's control for a restart.
dashboard-cmd.py uses bind and serve directly.
"""

import argparse
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import peerowner  # noqa: E402
import relay  # noqa: E402

ADDRESS = "127.0.0.1"


def say_out(text):
    print(text, flush=True)


def admit(conn, path, uid, read=peerowner.read_tables, say=say_out):
    try:
        client, server = conn.getpeername(), conn.getsockname()
    except OSError:
        conn.close()
        return
    found = peerowner.owner(read(), client[:2], server[:2])
    if not peerowner.allowed(found, uid):
        say(f"refused {client[0]}:{client[1]}: owner {'unknown' if found is None else found}")
        conn.close()
        return
    say(f"served {client[0]}:{client[1]}: owner {found}")
    relay.one(conn, path)


def bind(port, reuse=True):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if reuse:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((ADDRESS, port))
    srv.listen(64)
    return srv


def serve(srv, path, uid, say=say_out):
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=admit, args=(conn, path, uid), kwargs={"say": say},
                         daemon=True).start()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--socket", required=True)
    p.add_argument("--no-reuseaddr", action="store_true")
    o = p.parse_args()
    srv = bind(o.port, not o.no_reuseaddr)
    print(f"listening on {ADDRESS}:{o.port} -> {o.socket}", flush=True)
    serve(srv, o.socket, os.getuid())


if __name__ == "__main__":
    main()
