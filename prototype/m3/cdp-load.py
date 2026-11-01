"""Loads one page in Chromium through the DevTools protocol over a pipe, as
browser tools such as Playwright drive it, rather than with `--dump-dom`,
which on the runners never returned, on the host as in the sandbox (the
second bwrap-prototype run, PR #113). Prints the stage it reached and the
page's title; exits 0 once the page's load event fired and its title was
read, 1 otherwise.

    python3 -I cdp-load.py URL SECONDS -- command...

The command is Chromium with its flags, `--remote-debugging-pipe` included,
possibly behind sbx.sh; it reads the protocol on fd 3 and answers on fd 4.
"""

import fcntl
import json
import os
import select
import subprocess
import sys
import time

url, secs = sys.argv[1], float(sys.argv[2])
cmd = sys.argv[3:]
if cmd[:1] == ["--"]:
    cmd = cmd[1:]

def high(fd):
    """The same pipe end moved to 10 or above, so dup2 onto 3 and 4 never
    clobbers the other end."""
    new = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10)
    os.close(fd)
    return new


to_chrome_r, to_chrome_w = map(high, os.pipe())
from_chrome_r, from_chrome_w = map(high, os.pipe())


def fds():
    os.dup2(to_chrome_r, 3)
    os.dup2(from_chrome_w, 4)


p = subprocess.Popen(cmd, preexec_fn=fds, pass_fds=(3, 4), stdin=subprocess.DEVNULL)
os.close(to_chrome_r)
os.close(from_chrome_w)
deadline = time.time() + secs
buf = b""
next_id = 0
stage = "started"
loaded = False  # Page.loadEventFired may arrive while another reply is awaited


def send(method, params=None, session=None):
    global next_id
    next_id += 1
    msg = {"id": next_id, "method": method, "params": params or {}}
    if session:
        msg["sessionId"] = session
    os.write(to_chrome_w, json.dumps(msg).encode() + b"\0")
    return next_id


def wait(pred):
    """The first message pred accepts, or None at the deadline."""
    global buf, loaded
    while True:
        while b"\0" in buf:
            raw, buf = buf.split(b"\0", 1)
            msg = json.loads(raw)
            if msg.get("method") == "Page.loadEventFired":
                loaded = True
            if pred(msg):
                return msg
        left = deadline - time.time()
        if left <= 0 or not select.select([from_chrome_r], [], [], left)[0]:
            return None
        data = os.read(from_chrome_r, 65536)
        if not data:
            return None
        buf += data


def call(method, params=None, session=None):
    i = send(method, params, session)
    return wait(lambda m: m.get("id") == i)


def finish(ok, detail):
    print(f"stage: {stage}; {detail}", flush=True)
    try:
        send("Browser.close")
    except OSError:
        pass
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    sys.exit(0 if ok else 1)


try:
    r = call("Target.createTarget", {"url": "about:blank"})
    if not r or "result" not in r:
        finish(False, f"no target: {r}")
    stage = "target"
    r = call("Target.attachToTarget", {"targetId": r["result"]["targetId"], "flatten": True})
    if not r or "result" not in r:
        finish(False, f"not attached: {r}")
    sid = r["result"]["sessionId"]
    stage = "attached"
    call("Page.enable", session=sid)
    loaded = False
    r = call("Page.navigate", {"url": url}, sid)
    if not r or r.get("result", {}).get("errorText"):
        finish(False, f"navigate: {r}")
    stage = "navigated"
    if not loaded and not wait(lambda m: m.get("method") == "Page.loadEventFired"):
        finish(False, "no load event")
    stage = "loaded"
    r = call("Runtime.evaluate", {"expression": "document.title", "returnByValue": True}, sid)
    title = (r or {}).get("result", {}).get("result", {}).get("value")
    finish(bool(title), f"title: {title!r}")
except OSError as e:  # the pipe closed: Chromium exited
    finish(False, f"pipe: {e}; exit {p.poll()}")
