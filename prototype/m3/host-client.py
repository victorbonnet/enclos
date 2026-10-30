"""What a browser on the host does at a sandbox's service (M3-03, decision 2):
the page, its assets and its WebSocket, with the Host and Origin a browser
would send for BASE's own port. Prints probe.py's lines (spec, result, detail)
for table.py, with the URL's port written <url port>, so a column read through
the host's path and one read inside the sandbox line up. The session token a
page holds is used and never printed.

    python3 -I host-client.py check BASE [--ws PATH]...
    python3 -I host-client.py get BASE
    python3 -I host-client.py hold BASE PATH OUT [--seconds N]

`hold` opens a WebSocket and writes to OUT what became of it.
"""

import argparse
import http.client
import json
import os
import re
import socket
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wsmini  # noqa: E402

TOKEN = re.compile(r'__HERMES_SESSION_TOKEN__\s*=\s*"([^"]+)"')
ASSET = re.compile(r'(?:src|href)="((?:/|\./|assets/)[^"#]+)"')


def line(spec, result, detail=""):
    print(f"{spec}\t{result}\t{detail}", flush=True)


def get(base, path, host=None, headers=None):
    u = urllib.parse.urlsplit(base)
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=30)
    try:
        c.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        c.putheader("Host", host or u.netloc)
        for k, v in (headers or {}).items():
            c.putheader(k, v)
        c.endheaders()
        r = c.getresponse()
        return r.status, r.getheader("X-Seen-Host"), r.read()
    finally:
        c.close()


def named(e):
    return type(e).__name__ + (f": {e}" if str(e) else "")


def assets_of(body):
    seen = []
    for m in ASSET.findall(body.decode("utf-8", "replace")):
        path = "/" + m.lstrip("./")
        if path not in seen:
            seen.append(path)
    return seen


def ws_open(base, path, host=None, origin=None):
    """Sends the upgrade. Returns (status line, socket, bytes already read)."""
    u = urllib.parse.urlsplit(base)
    s = socket.create_connection((u.hostname, u.port), timeout=30)
    req = [f"GET {path} HTTP/1.1", f"Host: {host or u.netloc}", "Upgrade: websocket",
           "Connection: Upgrade", f"Sec-WebSocket-Key: {wsmini.new_key()}",
           "Sec-WebSocket-Version: 13", f"Origin: {origin or base}"]
    s.sendall(("\r\n".join(req) + "\r\n\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        data = s.recv(65536)
        if not data:
            break
        buf += data
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head.split(b"\r\n")[0].decode("latin-1"), s, rest


def first_frame(s, rest, wait=5):
    """The first frame's opcode and size, after a message, or why none came."""
    s.settimeout(wait)
    s.sendall(wsmini.encode(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode(),
                            mask=os.urandom(4)))
    buf = rest
    try:
        while (frame := wsmini.decode(buf)) is None:
            data = s.recv(65536)
            if not data:
                return "closed by the far side"
            buf += data
    except TimeoutError:
        return f"no frame in {wait} s"
    return f"frame opcode {frame[0]}, {len(frame[1])} bytes"


def with_token(path, token):
    if not token:
        return path
    return path + ("&" if "?" in path else "?") + urllib.parse.urlencode({"token": token})


def ws_row(spec, base, path, **kw):
    try:
        status, s, rest = ws_open(base, path, **kw)
    except OSError as e:
        return line(spec, "error", named(e))
    try:
        code = status.split()[1] if len(status.split()) > 1 else "none"
        if code == "101":
            try:
                line(spec, "ok", f"101, {first_frame(s, rest)}")
            except OSError as e:
                line(spec, "ok", f"101, then {named(e)}")
        else:
            line(spec, "refused", status[:60])
    finally:
        s.close()


def check(base, ws_paths):
    u = urllib.parse.urlsplit(base)
    try:
        status, seen, body = get(base, "/")
    except (OSError, http.client.HTTPException) as e:
        return line("GET / (Host: 127.0.0.1:<url port>)", "error", named(e))
    token = (m := TOKEN.search(body.decode("utf-8", "replace"))) and m.group(1)
    same = "seen as sent" if seen == u.netloc else ""
    line("GET / (Host: 127.0.0.1:<url port>)", "ok" if status == 200 else "refused",
         f"{status}, {len(body)} bytes, session token in page: {'yes' if token else 'no'} {same}".strip())
    for label, host in (("localhost:<url port>", f"localhost:{u.port}"),
                        ("127.0.0.1:1", "127.0.0.1:1"),
                        ("evil.example:<url port>", f"evil.example:{u.port}")):
        status, _, _ = get(base, "/", host=host)
        line(f"GET / (Host: {label})", "ok" if status == 200 else "refused", str(status))
    paths = assets_of(body)
    failed = []
    size = 0
    for path in paths:
        status, _, data = get(base, path)
        size += len(data)
        if status != 200:
            failed.append(f"{status} {path}")
    line("assets named by the page", "ok" if paths and not failed else "refused" if failed else "none",
         f"{len(paths) - len(failed)} of {len(paths)}, {size} bytes" + (f"; {failed[0]}" if failed else ""))
    headers = {"X-Hermes-Session-Token": token} if token else {}
    for path in ("/api/status", "/api/auth/me"):
        status, _, data = get(base, path, headers=headers)
        line(f"GET {path}", "ok" if status == 200 else "refused", f"{status}, {len(data)} bytes")
    for path in ws_paths:
        ws_row(f"WS {path}", base, with_token(path, token))
        ws_row(f"WS {path} (no token)", base, path)
        ws_row(f"WS {path} (Origin: evil.example)", base, with_token(path, token),
               origin="http://evil.example")
        ws_row(f"WS {path} (Host: evil.example)", base, with_token(path, token),
               host=f"evil.example:{u.port}")
        ws_row(f"WS {path} (Origin: localhost:<url port>)", base, with_token(path, token),
               origin=f"http://localhost:{u.port}")


def hold(base, path, out, seconds):
    def say(text):
        with open(out, "a") as f:
            f.write(text + "\n")
    start = time.monotonic()
    try:
        _, _, body = get(base, "/")
        token = (m := TOKEN.search(body.decode("utf-8", "replace"))) and m.group(1)
        status, s, _ = ws_open(base, with_token(path, token))
    except (OSError, http.client.HTTPException) as e:
        return say(f"not opened: {named(e)}")
    say(f"opened: {status[:40]}")
    s.settimeout(seconds)
    try:
        while s.recv(65536):
            pass
        say(f"closed by the far side after {time.monotonic() - start:.1f} s")
    except TimeoutError:
        say(f"still open after {seconds} s")
    except OSError as e:
        say(f"ended after {time.monotonic() - start:.1f} s: {named(e)}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["check", "get", "hold"])
    p.add_argument("base")
    p.add_argument("rest", nargs="*")
    p.add_argument("--ws", action="append", default=[])
    p.add_argument("--seconds", type=int, default=120)
    o = p.parse_args()
    if o.command == "check":
        check(o.base, o.ws)
    elif o.command == "hold":
        hold(o.base, o.rest[0], o.rest[1], o.seconds)
    else:
        try:
            status, _, body = get(o.base, "/")
            line("GET /", "ok" if status == 200 else "refused", f"{status}, {len(body)} bytes")
        except (OSError, http.client.HTTPException) as e:
            line("GET /", "error", named(e))


if __name__ == "__main__":
    main()
