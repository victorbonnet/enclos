"""What a browser on the host does at a sandbox's service (M3-03, decision 2):
the page, its assets and its WebSocket, with the Host and Origin a browser
would send for BASE's own port. Prints probe.py's lines (spec, result, detail)
for table.py, with the URL's port written <url port>, so a column read through
the host's path and one read inside the sandbox line up. The session token a
page holds is used and never printed.

    python3 -I host-client.py check BASE [--ws PATH]...
    python3 -I host-client.py get BASE
    python3 -I host-client.py hold BASE PATH OUT [--seconds N]
    python3 -I host-client.py chat BASE
    python3 -I host-client.py pty BASE
    python3 -I host-client.py pty-chat BASE OUT [--prompt TEXT]
    python3 -I host-client.py raw BASE OUT [--path PATH]
    python3 -I host-client.py token BASE OUT

`hold` opens a WebSocket and writes to OUT what became of it. `chat` opens
Hermes's chat over /api/ws (session.create, then prompt.submit) and says how
far it got. `pty` drives the terminal on /api/pty as the page does: a size, then
typed text, which must come back. `pty-chat` types a real prompt there and keeps
all the terminal showed, raw in OUT and as text in OUT.txt, split at the prompt;
the session token is taken out of both. `raw` sends one request and keeps every byte
of the answer in OUT, for a check that a refused client got nothing. `token`
writes the page's session token to OUT, the one place it is written.
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


ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\\\)|[@-Z\\\\^_])")
MARK = "enclosmark"


def plain(text):
    """Terminal output as text: control sequences out, whitespace closed up."""
    return " ".join(ANSI.sub("", text).split())


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


def frames(s, buf, seconds):
    """Yields (opcode, body) until `seconds` pass or the socket closes."""
    end = time.monotonic() + seconds
    while True:
        while (frame := wsmini.decode(buf)) is not None:
            buf = buf[frame[2]:]
            if frame[0] == wsmini.PING:  # a server closes a client that stays silent
                s.sendall(wsmini.encode(frame[1], wsmini.PONG, mask=os.urandom(4)))
                continue
            yield frame[0], frame[1]
        left = end - time.monotonic()
        if left <= 0:
            return
        s.settimeout(left)
        try:
            data = s.recv(65536)
        except TimeoutError:
            return
        if not data:
            return
        buf += data


def send(s, text):
    s.sendall(wsmini.encode(text.encode(), mask=os.urandom(4)))


def page_token(base):
    body = get(base, "/")[2].decode("utf-8", "replace")
    return (m := TOKEN.search(body)) and m.group(1)


def turn_end(kind, payload, last):
    """What stopped the turn: an `error` event's text, else the text of the
    `message.complete` that ended it, else what was known. A session.info
    frame is not an answer, whatever words it holds."""
    if not isinstance(payload, dict):
        return last
    if kind == "error":
        return str(payload.get("message") or payload.get("error") or payload)[:200]
    if kind == "message.complete" and not last:
        return str(payload.get("text") or payload.get("rendered") or "")[:200]
    return last


def pty_chat(base, out, prompt):
    """The page's order, then a real prompt and Enter, as the Chat tab sends."""
    token = page_token(base)
    status, s, rest = ws_open(base, with_token("/api/pty", token))
    if " 101 " not in status + " ":
        return line("terminal: /api/pty", "refused", status[:60])
    line("terminal: /api/pty", "ok", "101")
    send(s, "\x1b[RESIZE:120;40]")
    before = b"".join(body for _, body in frames(s, rest, 30))
    send(s, prompt + "\r")
    after = b"".join(body for _, body in frames(s, b"", 45))
    s.close()

    def clean(data):
        text = data.decode("utf-8", "replace")
        return text.replace(token, "<token>") if token else text
    with open(out, "w") as f:
        f.write(clean(before) + "\n=== after the prompt ===\n" + clean(after))
    with open(out + ".txt", "w") as f:
        f.write(plain(clean(before)) + "\n=== after the prompt ===\n" + plain(clean(after)) + "\n")
    line("terminal: before the prompt", "ok" if before else "none", f"{len(before)} bytes")
    line("terminal: after the prompt", "ok" if after else "none", f"{len(after)} bytes")


def chat(base):
    """Hermes's newline-free JSON-RPC over /api/ws, as far as an install with no
    account goes: the reply to each call, then the events of the turn."""
    status, s, rest = ws_open(base, with_token("/api/ws", page_token(base)))
    if " 101 " not in status + " ":
        return line("chat: /api/ws", "refused", status[:60])
    line("chat: /api/ws", "ok", "101")
    send(s, json.dumps({"jsonrpc": "2.0", "id": 1, "method": "session.create", "params": {}}))
    sid, submitted, events, last = None, False, [], ""
    for opcode, body in frames(s, rest, 45):
        if opcode != wsmini.TEXT:
            continue
        try:
            msg = json.loads(body)
        except ValueError:
            continue
        if msg.get("method") == "event":
            kind = msg.get("params", {}).get("type", "?")
            if kind not in events:
                events.append(kind)
            last = turn_end(kind, msg.get("params", {}).get("payload"), last)
        elif msg.get("id") == 1:
            sid = msg.get("result", {}).get("session_id")
            line("chat: session.create", "ok" if sid else "refused",
                 "a session" if sid else str(msg.get("error"))[:80])
            if not sid:
                break
            send(s, json.dumps({"jsonrpc": "2.0", "id": 2, "method": "prompt.submit",
                                "params": {"session_id": sid, "text": "Reply with exactly one word: ok"}}))
        elif msg.get("id") == 2:
            submitted = True
            error = msg.get("error")
            line("chat: prompt.submit", "refused" if error else "ok", str(error)[:80] if error else "accepted")
    s.close()
    line("chat: events of the turn", "ok" if events else "none", " ".join(events)[:100])
    line("chat: what stopped it", "seen" if last else "none", last.replace("\t", " ").replace("\n", " "))
    if not submitted and sid:
        line("chat: prompt.submit", "none", "no reply")


def pty(base):
    """The page's order: a size, then keys; the text typed must come back."""
    status, s, rest = ws_open(base, with_token("/api/pty", page_token(base)))
    if " 101 " not in status + " ":
        return line("terminal: /api/pty", "refused", status[:60])
    line("terminal: /api/pty", "ok", "101")
    send(s, "\x1b[RESIZE:120;40]")
    seen = b""
    for _, body in frames(s, rest, 25):
        seen += body
    line("terminal: output", "ok" if seen else "none", f"{len(seen)} bytes: {plain(seen.decode('utf-8', 'replace'))[:60]}")
    send(s, MARK)
    typed = b""
    for _, body in frames(s, b"", 8):
        typed += body
    s.close()
    line("terminal: typed text comes back", "ok" if MARK in plain(typed.decode("utf-8", "replace")) else "none",
         f"{len(typed)} bytes after typing")


def raw(base, out, path):
    u = urllib.parse.urlsplit(base)
    got = b""
    try:
        s = socket.create_connection((u.hostname, u.port), timeout=15)
        try:
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {u.netloc}\r\nConnection: close\r\n\r\n".encode())
            while data := s.recv(65536):
                got += data
        finally:
            s.close()
    except OSError as e:
        with open(out, "wb") as f:
            f.write(got)
        return line(f"raw GET {path}", "served" if got else "refused", f"{len(got)} bytes, then {type(e).__name__}")
    with open(out, "wb") as f:
        f.write(got)
    line(f"raw GET {path}", "served" if got else "refused", f"{len(got)} bytes")


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
    p.add_argument("command", choices=["check", "get", "hold", "chat", "pty", "pty-chat", "raw", "token"])
    p.add_argument("base")
    p.add_argument("rest", nargs="*")
    p.add_argument("--ws", action="append", default=[])
    p.add_argument("--seconds", type=int, default=120)
    p.add_argument("--path", default="/")
    p.add_argument("--prompt", default="Reply with exactly one word: ok")
    o = p.parse_args()
    if o.command == "check":
        check(o.base, o.ws)
    elif o.command == "hold":
        hold(o.base, o.rest[0], o.rest[1], o.seconds)
    elif o.command == "chat":
        chat(o.base)
    elif o.command == "pty":
        pty(o.base)
    elif o.command == "pty-chat":
        pty_chat(o.base, o.rest[0], o.prompt)
    elif o.command == "raw":
        raw(o.base, o.rest[0], o.path)
    elif o.command == "token":
        with open(o.rest[0], "w") as f:
            f.write(page_token(o.base) or "")
    else:
        try:
            status, _, body = get(o.base, "/")
            line("GET /", "ok" if status == 200 else "refused", f"{status}, {len(body)} bytes")
        except (OSError, http.client.HTTPException) as e:
            line("GET /", "error", named(e))


if __name__ == "__main__":
    main()
