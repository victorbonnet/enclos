"""A stand-in for a runtime's dashboard in a session (M3-03): a page, an asset
and a WebSocket that echoes, on 127.0.0.1 at a port the kernel picks. It says
which Host header it saw, and writes its port to a file in the sandbox's home
that the check only compares with what it read from the host.

    python3 -I ns-webservice.py --out F
"""

import argparse
import http.server
import json
import os
import socket
import socketserver
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wsmini  # noqa: E402

PAGE = b'<!doctype html><title>stand-in</title><script src="/asset.js"></script>'
ASSET = b"console.log('stand-in');"


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def send_body(self, code, body):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Seen-Host", self.headers.get("Host", ""))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/ws":
            return self.echo()
        self.send_body(*{"/": (200, PAGE), "/asset.js": (200, ASSET)}.get(path, (404, b"")))

    def echo(self):
        self.send_response_only(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", wsmini.accept_key(self.headers["Sec-WebSocket-Key"]))
        self.end_headers()
        self.wfile.flush()
        buf = b""
        self.close_connection = True
        while True:
            try:
                data = self.connection.recv(65536)
            except OSError:
                return
            if not data:
                return
            buf += data
            while (frame := wsmini.decode(buf)) is not None:
                opcode, body, used = frame
                buf = buf[used:]
                if opcode == wsmini.CLOSE:
                    return
                self.connection.sendall(wsmini.encode(body, opcode))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    o = p.parse_args()
    srv = Server(("127.0.0.1", 0), Handler)
    tmp = o.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"port": srv.socket.getsockname()[1],
                   "net": os.readlink("/proc/self/ns/net")}, f)
    os.rename(tmp, o.out)
    srv.serve_forever()


if __name__ == "__main__":
    main()
