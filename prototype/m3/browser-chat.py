"""Hermes's Chat tab in a real Chromium on the host, through the host's listener
(M3-03): the page's own JavaScript opens /api/pty, this types a prompt into its
terminal as a user would, and keeps every frame the page received, read over
the DevTools protocol, with a screenshot.

    python3 -I browser-chat.py URL OUT PROMPT -- chrome --remote-debugging-pipe ...

Writes OUT.txt (the terminal's text, split at the prompt) and OUT.png, and
prints probe.py's lines. The socket's URL, which holds the token, is not kept.
The driving is as cdp-load.py's: fd 3 and fd 4.
"""

import base64
import fcntl
import importlib.util
import json
import os
import select
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
url, out, prompt = sys.argv[1:4]
cmd = sys.argv[4:]
if cmd[:1] == ["--"]:
    cmd = cmd[1:]
spec = importlib.util.spec_from_file_location("host_client", f"{HERE}/host-client.py")
client = importlib.util.module_from_spec(spec)
sys.path.insert(0, HERE)
spec.loader.exec_module(client)

WAIT_READY, WAIT_ANSWER = 30, 45
PTY = "/api/pty"
FOCUS = "document.querySelector('.xterm-helper-textarea')?.focus(); !!document.activeElement"


def line(spec_, result, detail=""):
    print(f"{spec_}\t{result}\t{detail}", flush=True)


def high(fd):
    new = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10)
    os.close(fd)
    return new


to_r, to_w = map(high, os.pipe())
from_r, from_w = map(high, os.pipe())


def fds():
    os.dup2(to_r, 3)
    os.dup2(from_w, 4)


p = subprocess.Popen(cmd, preexec_fn=fds, pass_fds=(3, 4), stdin=subprocess.DEVNULL)
os.close(to_r)
os.close(from_w)
buf, next_id, sockets, frames = b"", 0, set(), []


def send(method, params=None, session=None):
    global next_id
    next_id += 1
    msg = {"id": next_id, "method": method, "params": params or {}}
    if session:
        msg["sessionId"] = session
    os.write(to_w, json.dumps(msg).encode() + b"\0")
    return next_id


def note(msg):
    """Keeps what the page's terminal socket carried."""
    method, params = msg.get("method"), msg.get("params", {})
    if method == "Network.webSocketCreated" and PTY in params.get("url", ""):
        sockets.add(params["requestId"])
    elif method == "Network.webSocketFrameReceived" and params.get("requestId") in sockets:
        frame = params["response"]
        data = frame["payloadData"]
        frames.append(base64.b64decode(data) if frame.get("opcode") == 2 else data.encode())


def pump(until, want=None):
    """Reads to `until`; returns the message `want` accepts, if one comes."""
    global buf
    while True:
        while b"\0" in buf:
            raw, buf = buf.split(b"\0", 1)
            msg = json.loads(raw)
            note(msg)
            if want and want(msg):
                return msg
        left = until - time.time()
        if left <= 0 or not select.select([from_r], [], [], left)[0]:
            return None
        data = os.read(from_r, 1 << 20)
        if not data:
            return None
        buf += data


def call(method, params=None, session=None):
    i = send(method, params, session)
    return pump(time.time() + 30, lambda m: m.get("id") == i) or {}


def text_of(data):
    return client.plain(data.decode("utf-8", "replace"))


status = 0
try:
    target = call("Target.createTarget", {"url": "about:blank"})["result"]["targetId"]
    sid = call("Target.attachToTarget", {"targetId": target, "flatten": True})["result"]["sessionId"]
    for domain in ("Page.enable", "Network.enable", "Runtime.enable"):
        call(domain, session=sid)
    call("Page.navigate", {"url": url.rstrip("/") + "/chat"}, sid)
    pump(time.time() + WAIT_READY)
    line("browser: the page's terminal socket", "ok" if sockets else "none", f"{len(sockets)} opened")
    before = b"".join(frames)
    frames.clear()
    call("Runtime.evaluate", {"expression": FOCUS, "returnByValue": True}, sid)
    call("Input.insertText", {"text": prompt}, sid)
    enter = {"key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13, "text": "\r"}
    call("Input.dispatchKeyEvent", {"type": "keyDown", **enter}, sid)
    call("Input.dispatchKeyEvent", {"type": "keyUp", "key": "Enter", "code": "Enter"}, sid)
    pump(time.time() + WAIT_ANSWER)
    after = b"".join(frames)
    with open(out + ".txt", "w") as f:
        f.write(text_of(before) + "\n=== after the prompt ===\n" + text_of(after) + "\n")
    line("browser: terminal output before the prompt", "ok" if before else "none", f"{len(before)} bytes")
    line("browser: terminal output after the prompt", "ok" if after else "none", f"{len(after)} bytes")
    shot = call("Page.captureScreenshot", {"format": "png"}, sid).get("result", {}).get("data")
    if shot:
        with open(out + ".png", "wb") as f:
            f.write(base64.b64decode(shot))
    line("browser: screenshot", "ok" if shot else "none")
except (KeyError, OSError) as e:
    status = 1
    line("browser: driving Chromium", "error", repr(e)[:100])
try:
    send("Browser.close")
except OSError:
    pass
try:
    p.wait(10)
except subprocess.TimeoutExpired:
    p.kill()
sys.exit(status)
