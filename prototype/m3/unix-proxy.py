"""The milestone 1 prototype's proxy (prototype/m1/proxy.py) served on a Unix
socket instead of a TCP port, as the bubblewrap sandbox reaches it (design
§5, Linux networking; M3-08 builds the real listener). Same allowlist,
--learn mode and JSON log.

    python3 -I unix-proxy.py --socket PATH (--allow FILE | --learn) --log FILE
"""

import argparse
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "m1"))
import proxy as m1  # noqa: E402


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--socket", required=True)
    p.add_argument("--allow")
    p.add_argument("--learn", action="store_true")
    p.add_argument("--log")
    o = p.parse_args()
    m1.ARGS = argparse.Namespace(port="unix", allow=o.allow, learn=o.learn, log=o.log)
    if os.path.exists(o.socket):
        os.unlink(o.socket)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(o.socket)
    srv.listen(128)
    print(f"proxy listening on {o.socket} ({'learn' if o.learn else 'allowlist'})", flush=True)
    while True:
        conn, _ = srv.accept()
        # m1's handler logs the peer's port; a Unix socket has none.
        threading.Thread(target=m1.handle, args=(conn, ("unix", 0)), daemon=True).start()


if __name__ == "__main__":
    main()
