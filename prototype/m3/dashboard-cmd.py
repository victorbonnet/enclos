"""A stand-in for `enclos dashboard <sandbox>` (M3-03): the way to Hermes's
dashboard from the host's browser. It starts `hermes dashboard --no-open` as a
recorded session under the sandbox's policy, reads the port that session holds
from the host (never from a file the sandbox writes), opens the listener on the
host's 127.0.0.1 at the sandbox's reserved port (host-listen.py), and prints the
URL. Ctrl-C ends both and records the end. A second run on the same sandbox
refuses, naming the first. Loopback and serving only this user are hard-coded,
with no setting. On a remote host, run this over ssh with -L.

    python3 -I dashboard-cmd.py run --sandbox S --run DIR --port RESERVED --audit F --log F
    python3 -I dashboard-cmd.py status --sandbox S

--run is the host-only run/<sandbox>/, which here is the holder's folder: the
holder's socket, its pid, host-relay.sock and service.port. `status` is what
`enclos status` says on Linux: the command, and no URL.
"""

import argparse
import fcntl
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
COMMAND = 'export PATH="$HOME/.local/bin:$PATH"; exec hermes dashboard --no-open'
REFUSED = 3
START_SECONDS = 600


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), f"{HERE}/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def url(port):
    return f"http://127.0.0.1:{port}/"


def status_text(sandbox):
    return (f"dashboard: run `enclos dashboard {sandbox}`, which prints its address while it runs; "
            f"on a remote host, run it over ssh with -L")


def take_lock(path):
    """The open lock file, held until this process ends, or None when another
    run holds it. The kernel drops it however a run ends, so none goes stale."""
    f = open(path, "a+")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        f.close()
        return None
    return f


def refusal(sandbox, record):
    """The message for a second run, naming the first from its record."""
    if not record:
        return f"enclos dashboard: {sandbox} already has a dashboard starting"
    return (f"enclos dashboard: {sandbox} already has a dashboard: pid {record['pid']}, "
            f"session {record['session']}, started {record['started']}, at {record['url']}")


def read_record(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def audit(path, event, **fields):
    with open(path, "a") as f:
        f.write(json.dumps({"at": time.time(), "event": event, **fields}) + "\n")


def held_port(holder_pid, session_pid):
    """The one port on 127.0.0.1 in the sandbox's network namespace that the
    session's processes hold, read from the host, or None."""
    listeners, procs = load("ns-listeners"), load("ns-procs")
    try:
        ports = listeners.listeners(holder_pid)
    except OSError:
        return None
    held, _ = listeners.holders(set(ports.values()))
    mine = listeners.held_only(ports, held, procs.descendants(session_pid) + [session_pid])
    return next(iter(mine)) if len(mine) == 1 else None


def stop_session(session):
    if session.poll() is not None:
        return
    session.terminate()
    try:
        session.wait(10)
    except subprocess.TimeoutExpired:
        os.killpg(session.pid, signal.SIGKILL)
        session.wait()


def run(o):
    lock_path = os.path.join(o.run, "dashboard.lock")
    record_path = os.path.join(o.run, "dashboard.json")
    port_path = os.path.join(o.run, "service.port")
    lock = take_lock(lock_path)
    if lock is None:
        print(refusal(o.sandbox, read_record(record_path)), file=sys.stderr, flush=True)
        return REFUSED
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: stop.set())

    session_id = uuid.uuid4().hex[:12]
    record = {"pid": os.getpid(), "session": session_id, "started": time.strftime("%FT%TZ", time.gmtime()),
              "url": url(o.port)}
    with open(record_path, "w") as f:
        json.dump(record, f)
    audit(o.audit, "dashboard-start", sandbox=o.sandbox, **record)
    with open(os.path.join(o.run, "pid")) as f:
        holder_pid = f.read().strip()
    env = {**os.environ, "SBX_JOIN": "nsenter", "SBX_HOLDER": os.path.join(o.run, "holder.sock")}
    log = open(o.log, "ab")
    session = subprocess.Popen([f"{HERE}/sbx-ns.sh", "--", "/bin/bash", "-c", COMMAND], env=env,
                               stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True)
    srv, reason, code = None, "stopped", 0
    port = None
    end = time.monotonic() + START_SECONDS
    while port is None and not stop.is_set() and session.poll() is None and time.monotonic() < end:
        port = held_port(holder_pid, session.pid)
        if port is None:
            stop.wait(1)
    if port is None and not stop.is_set():
        reason, code = "the dashboard did not start", 1
    if port is not None:
        with open(port_path, "w") as f:
            f.write(str(port))
        try:
            srv = load("host-listen").bind(o.port)
        except OSError as e:
            reason, code = f"cannot listen on the reserved port: {e.strerror}", 1
    if srv is not None:
        def say(text):
            log.write((text + "\n").encode())
            log.flush()
        threading.Thread(target=load("host-listen").serve,
                         args=(srv, os.path.join(o.run, "host-relay.sock"), os.getuid(), say),
                         daemon=True).start()
        audit(o.audit, "dashboard-open", sandbox=o.sandbox, session=session_id, service_port=port)
        print(url(o.port), flush=True)
        print(f"Serves only this user. Remote host: ssh -L {o.port}:127.0.0.1:{o.port} <host>. Ctrl-C to end.",
              flush=True)
        while not stop.wait(0.5):
            if session.poll() is not None:
                reason, code = "the dashboard ended", 1
                break

    if srv is not None:
        try:
            srv.shutdown(socket.SHUT_RD)  # wakes accept()
        except OSError:
            pass
        srv.close()
    stop_session(session)
    for path in (port_path, record_path):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    audit(o.audit, "dashboard-end", sandbox=o.sandbox, session=session_id, reason=reason)
    if code:
        print(f"enclos dashboard: {reason}", file=sys.stderr, flush=True)
    return code


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run")
    r.add_argument("--sandbox", required=True)
    r.add_argument("--run", required=True)
    r.add_argument("--port", type=int, required=True)
    r.add_argument("--audit", required=True)
    r.add_argument("--log", required=True)
    s = sub.add_parser("status")
    s.add_argument("--sandbox", required=True)
    o = p.parse_args()
    if o.command == "status":
        print(status_text(o.sandbox))
        return 0
    return run(o)


if __name__ == "__main__":
    sys.exit(main())
