"""The host's side of the path to a sandbox's service (M3-03, decision 2):
what the sandbox's proxy service would run while the service runs. It listens
on the host's 127.0.0.1 at the sandbox's reserved port and passes each
connection to a Unix socket in the host-only folder, which the holder relays
into the sandbox's network namespace (ns-holder.py --host-relay).

    python3 -I host-listen.py --port RESERVED --socket S [--no-reuseaddr]

Loopback is hard-coded: there is deliberately no option for the address.
--no-reuseaddr is the check's control for a restart.
"""

import argparse
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import relay  # noqa: E402

ADDRESS = "127.0.0.1"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--socket", required=True)
    p.add_argument("--no-reuseaddr", action="store_true")
    o = p.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if not o.no_reuseaddr:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((ADDRESS, o.port))
    srv.listen(64)
    print(f"listening on {ADDRESS}:{o.port} -> {o.socket}", flush=True)
    relay.serve(srv, o.socket)


if __name__ == "__main__":
    main()
