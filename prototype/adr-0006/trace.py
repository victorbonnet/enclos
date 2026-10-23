"""Runs an enclos command for a sandbox under one Seatbelt baseline, and
collects the denials, and the reports of `(with report)` rules, tagged
`enclos:<sandbox>` (ADR 0006's evidence).

The denials come from a live `log stream --style ndjson` this script
starts itself: it needs an admin user, is read through a pipe, keeps at
most MAX_LINES events of each kind, and is stopped (its own child) once the
command ends, also when this script fails or is signalled. On macOS 26 a
tagged denial's message is two lines, the denial and then the tag alone.

A capture that could read as clean without being so fails instead: a
stream that is not running, says anything on stderr or reports lost
events; a canary denial (a write to `/`, made through `enclos exec` before
and after the command) that never shows parsed; events past the cap; tagged
events the script cannot read; or a command run on another baseline than
the one asked for, as enclos's notice on stderr says, and the compiled
files written meanwhile when there are some. Only events between the two
canaries count. SANDBOX must be named in ENCLOS-ARGS.

usage: ENCLOS=<enclos binary> ENCLOS_HOME=<folder> [TIMEOUT=<seconds>] \\
       python3 -I trace.py SANDBOX allow|deny OUT -- ENCLOS-ARGS...

TIMEOUT (3600 by default) bounds the command. Past it, or on a signal or a
failure of this script, `enclos sandbox stop SANDBOX` ends what the command
started, and the command's process group is asked to stop (SIGTERM), then
killed.

Writes OUT: one line per distinct verdict, operation and argument with its
count and the programs that met it, then each event it could not read
(UNREAD), each untagged one (UNTAGGED), notes (NOTE) and failures (FAILED),
at most MAX_LINES of each. Writes OUT.stdout and OUT.stderr, the command's
output, and exits 1 when the capture or the command failed.
"""
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time

MAX_LINES = 300_000
CANARY_WAIT = 20
NOTICE = "compiled from (allow default)"
# What `log stream` prints before its first event.
HEADER = "Filtering the log data"
# The program may hold spaces (`Google Chrome He`).
DENIAL = re.compile(r"Sandbox: (.+?)\((\d+)\) (allow|deny)(?:\(\d+\))? (\S+)(?: (.*))?$")

if len(sys.argv) < 5 or sys.argv[4] != "--" or sys.argv[2] not in ("allow", "deny"):
    sys.exit(__doc__)
sandbox, baseline, out = sys.argv[1], sys.argv[2], sys.argv[3]
args = sys.argv[5:]
if sandbox not in args and not any(a.endswith("=" + sandbox) for a in args):
    sys.exit(f"{sandbox} is not named in the command: its denials could not be the command's")
enclos = os.environ["ENCLOS"]
tag = f"enclos:{sandbox}"

env = dict(os.environ)
env.pop("ENCLOS_SEATBELT_BASELINE", None)
if baseline == "allow":
    env["ENCLOS_SEATBELT_BASELINE"] = "allow-default"


class Capped(list):
    """At most MAX_LINES items, and how many more there were."""
    dropped = 0

    def add(self, item):
        if len(self) < MAX_LINES:
            self.append(item)
        else:
            self.dropped += 1


# Each tagged event, as (program, verdict, operation, argument) or None
# when the script cannot read it, with its raw message.
events, untagged, other, errors = Capped(), Capped(), Capped(), Capped()
first_line = [True]


def read():
    for line in stream.stdout:
        line = line.rstrip("\n")
        if first_line[0]:
            first_line[0] = False
            if line.startswith(HEADER):
                continue
        try:
            event = json.loads(line)
        except ValueError:
            other.add(line)
            continue
        if event.get("eventType") != "logEvent":
            other.add(line)
            continue
        message = event.get("eventMessage", "")
        parts = message.split("\n")
        if tag not in (p.strip() for p in parts):
            untagged.add(message)
            continue
        m = DENIAL.search(parts[0])
        parsed = None
        if m:
            parsed = (m.group(1), m.group(3), m.group(4), (m.group(5) or "").strip())
        events.add((parsed, message))


def read_errors():
    for line in stream.stderr:
        errors.add(line)


def canary(name):
    """A write to `/` from the sandbox, which every baseline denies, whose
    denial must reach the stream and be read: returns its event's index, or
    the reason it is missing."""
    mark = f"/enclos-trace-canary-{name}-{os.getpid()}"
    ran = subprocess.run([enclos, "--text", "exec", sandbox, "--", "/bin/sh", "-c", f": > {mark}"],
                         env=env, capture_output=True, text=True, timeout=120)
    if ran.returncode == 0 or "Operation not permitted" not in ran.stderr:
        return None, f"the {name} canary did not run as a refused write: exit {ran.returncode}: {ran.stderr.strip()}"
    deadline = time.time() + CANARY_WAIT
    while time.time() < deadline:
        for i, (parsed, _) in enumerate(list(events)):
            if parsed and parsed[3].startswith(mark):
                return i, None
        time.sleep(0.2)
    return None, f"the {name} canary's denial never reached the stream readable: nothing collected can be trusted"


def compiled_files():
    folder = os.path.join(os.environ["ENCLOS_HOME"], "sandboxes", sandbox, "compiled")
    found = {}
    try:
        names = os.listdir(folder)
    except FileNotFoundError:
        return found
    for f in names:
        # enclos writes a file under a dot name, then renames it.
        if f.startswith("."):
            continue
        try:
            found[os.path.join(folder, f)] = os.stat(os.path.join(folder, f)).st_mtime
        except FileNotFoundError:
            pass
    return found


def third_line(path):
    """A compiled policy's baseline line, as `Baseline::of_compiled` reads it."""
    try:
        with open(path) as f:
            lines = [f.readline().rstrip("\n") for _ in range(3)]
    except FileNotFoundError:
        return None
    return lines[2]


def stop_command():
    """Ends what the command started: its sandbox, then its process group."""
    stopped = subprocess.run([enclos, "--text", "sandbox", "stop", sandbox], env=env,
                             capture_output=True, text=True, timeout=120)
    if stopped.returncode != 0:
        failed.append(f"`enclos sandbox stop {sandbox}` failed: {stopped.stderr.strip()}")
    if command.poll() is None:
        os.killpg(command.pid, signal.SIGTERM)
        try:
            command.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(command.pid, signal.SIGKILL)
            command.wait()


# A signal ends the script through `finally`, which stops what it started.
for sig in (signal.SIGTERM, signal.SIGHUP):
    signal.signal(sig, lambda n, _: sys.exit(128 + n))

failed, notes = [], []
command = None
stdout = stderr = ""
took = 0.0
start_at = end_at = None
stream = subprocess.Popen(["/usr/bin/log", "stream", "--style", "ndjson", "--predicate",
                           f'eventMessage CONTAINS "{tag}"'],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
readers = [threading.Thread(target=read, daemon=True), threading.Thread(target=read_errors, daemon=True)]
try:
    for r in readers:
        r.start()
    time.sleep(1)
    if stream.poll() is not None:
        sys.exit("log stream is not running: " + "".join(errors).strip())
    start_at, why = canary("start")
    if why:
        sys.exit(why)
    before = compiled_files()
    started = time.time()
    command = subprocess.Popen([enclos, "--text", *args], env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = command.communicate(timeout=int(os.environ.get("TIMEOUT", "3600")))
    except subprocess.TimeoutExpired:
        failed.append("the command ran past TIMEOUT")
        stop_command()
        try:
            stdout, stderr = command.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            failed.append("its output is incomplete: a process it left holds it")
    took = time.time() - started
    written = [p for p, m in compiled_files().items() if before.get(p) != m]
    if not written:
        notes.append("no compiled file was written: the baseline is shown by enclos's notice alone")
    for path in written:
        line = third_line(path)
        on_allow = line == "(allow default)"
        if line is not None and on_allow != (baseline == "allow"):
            failed.append(f"{path} was compiled on another baseline than {baseline}")
    end_at, why = canary("end")
    if why:
        failed.append(why)
except BaseException:
    if command is not None and command.poll() is None:
        stop_command()
    raise
finally:
    stream.terminate()
    try:
        stream.wait(timeout=5)
    except subprocess.TimeoutExpired:
        stream.kill()
        stream.wait()
    for r in readers:
        r.join(timeout=5)

seen, unread = {}, []
for parsed, message in events[start_at + 1:end_at]:
    if parsed is None:
        unread.append(message)
        continue
    program, verdict, op, arg = parsed
    entry = seen.setdefault((verdict, op, arg), {"n": 0, "programs": set()})
    entry["n"] += 1
    entry["programs"].add(program)

for kind, kept in (("tagged events", events), ("untagged events", untagged), ("other lines", other)):
    if kept.dropped:
        failed.append(f"TRUNCATED: {kept.dropped} {kind} past the cap of {MAX_LINES} were dropped")
if unread:
    failed.append(f"{len(unread)} tagged events this script cannot read")
if untagged:
    failed.append(f"{len(untagged)} events matched the stream's filter without the tag alone on a line")
if other:
    failed.append(f"{len(other)} lines of the stream are no log event (lost events, or output it cannot read)")
if errors:
    failed.append("log stream said on stderr: " + "".join(errors).strip())
if (NOTICE in stderr) != (baseline == "allow"):
    failed.append(f"the command did not run on the {baseline} baseline asked for, as its stderr says")
if command is not None and command.returncode != 0:
    failed.append(f"the command exited {command.returncode}")

with open(out, "w") as f:
    for (verdict, op, arg), v in sorted(seen.items()):
        f.write(f"{v['n']:6d} {verdict} {op} {arg}  [{','.join(sorted(v['programs']))}]\n")
    for message in unread:
        f.write(f"UNREAD {json.dumps(message)}\n")
    for message in untagged:
        f.write(f"UNTAGGED {json.dumps(message)}\n")
    for line in other:
        f.write(f"OTHER {line}\n")
    for note in notes:
        f.write(f"NOTE {note}\n")
    for why in failed:
        f.write(f"FAILED {why}\n")
open(out + ".stdout", "w").write(stdout or "")
open(out + ".stderr", "w").write(stderr or "")
print(f"exit {command.returncode if command else '-'} in {took:.0f}s, "
      f"{len(events)} tagged events, {len(seen)} distinct -> {out}")
for note in notes:
    print(f"NOTE: {note}", file=sys.stderr)
for why in failed:
    print(f"FAILED: {why}", file=sys.stderr)
sys.exit(1 if failed else 0)
