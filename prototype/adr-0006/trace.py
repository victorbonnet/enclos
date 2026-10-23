"""Runs an enclos command for a sandbox under one Seatbelt baseline, and
collects the denials, and the reports of `(with report)` rules, tagged
`enclos:<sandbox>` (ADR 0006's evidence).

The denials come from a live `log stream` this script starts itself: it
needs an admin user, is bounded in lines, is read through a pipe, and is
stopped (its own child) once the command ends, also when this script fails
or is signalled. It is never written to disk whole: OUT holds the counted
lines and any line the script could not read.

A capture that could read as clean without being so fails instead: a
stream that is not running or says anything on stderr, a canary denial (a
write to `/`, made through `enclos exec` before and after the command)
that never shows parsed, lines past the cap, tagged lines the script cannot
read, untagged lines, or a baseline other than the one asked for, as
enclos's notice on stderr and the compiled files written meanwhile say.

usage: ENCLOS=<enclos binary> ENCLOS_HOME=<folder> [TIMEOUT=<seconds>] \\
       python3 -I trace.py SANDBOX allow|deny OUT -- ENCLOS-ARGS...

TIMEOUT (3600 by default) bounds the command: past it, enclos is asked to
stop (SIGTERM), then killed, and `enclos sandbox stop SANDBOX` ends what it
left.

Writes OUT, one line per distinct verdict, operation and argument with its
count and the programs that met it, OUT.stdout and OUT.stderr, the
command's output, and exits 1 when the capture or the command failed.
"""
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
# What `log stream` prints before any line of the log.
HEADER = "Filtering the log data"

if len(sys.argv) < 5 or sys.argv[4] != "--" or sys.argv[2] not in ("allow", "deny"):
    sys.exit(__doc__)
sandbox, baseline, out = sys.argv[1], sys.argv[2], sys.argv[3]
args = sys.argv[5:]
enclos = os.environ["ENCLOS"]
tag = f"enclos:{sandbox}"
# The tag whole: `enclos:home` is not `enclos:home2`'s.
tagged = re.compile(re.escape(tag) + r"(?![A-Za-z0-9_-])")
denial = re.compile(r"Sandbox: (\S+?)\(\d+\) (allow|deny)(?:\(\d+\))? (\S+)(?: (.*))?$")

env = dict(os.environ)
env.pop("ENCLOS_SEATBELT_BASELINE", None)
if baseline == "allow":
    env["ENCLOS_SEATBELT_BASELINE"] = "allow-default"

# A signal ends the script through `finally`, which stops the stream.
for sig in (signal.SIGTERM, signal.SIGHUP):
    signal.signal(sig, lambda n, _: sys.exit(128 + n))

stream = subprocess.Popen(
    ["/usr/bin/log", "stream", "--style", "compact", "--predicate", f'eventMessage CONTAINS "{tag}"'],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
lines, untagged, dropped, errors = [], [], [0], []


def read():
    for line in stream.stdout:
        if not tagged.search(line):
            if HEADER not in line:
                untagged.append(line)
            continue
        if len(lines) < MAX_LINES:
            lines.append(line)
        else:
            dropped[0] += 1


def read_errors():
    for line in stream.stderr:
        errors.append(line)


def parse(line):
    """The program, verdict, operation and argument of a tagged line, or
    None when the script cannot read it."""
    if "Sandbox:" not in line:
        return None
    m = denial.search(line[line.find("Sandbox:"):])
    if not m:
        return None
    # The argument whole, its tag left out: a path may hold ` (`.
    arg = tagged.sub("", m.group(4) or "").strip()
    return m.group(1), m.group(2), m.group(3), arg


def canary(name):
    """A write to `/` from the sandbox, which every baseline denies, whose
    denial must reach the stream and be read."""
    mark = f"/enclos-trace-canary-{name}-{os.getpid()}"
    ran = subprocess.run([enclos, "--text", "exec", sandbox, "--", "/bin/sh", "-c", f": > {mark}"],
                         env=env, capture_output=True, text=True, timeout=120)
    if ran.returncode == 0 or "Operation not permitted" not in ran.stderr:
        return f"the {name} canary did not run as a refused write: exit {ran.returncode}: {ran.stderr.strip()}"
    deadline = time.time() + CANARY_WAIT
    while time.time() < deadline:
        if any(p and p[3].startswith(mark) for p in map(parse, list(lines))):
            return None
        time.sleep(0.2)
    return f"the {name} canary's denial never reached the stream readable: nothing collected can be trusted"


def compiled_files():
    folder = os.path.join(os.environ["ENCLOS_HOME"], "sandboxes", sandbox, "compiled")
    try:
        return {os.path.join(folder, f): os.stat(os.path.join(folder, f)).st_mtime for f in os.listdir(folder)}
    except FileNotFoundError:
        return {}


failed = []
run = None
took = 0.0
readers = [threading.Thread(target=read, daemon=True), threading.Thread(target=read_errors, daemon=True)]
try:
    for r in readers:
        r.start()
    time.sleep(1)
    if stream.poll() is not None:
        sys.exit("log stream is not running: " + "".join(errors).strip())
    why = canary("start")
    if why:
        sys.exit(why)
    before = compiled_files()
    started = time.time()
    command = subprocess.Popen([enclos, "--text", *args], env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = command.communicate(timeout=int(os.environ.get("TIMEOUT", "3600")))
    except subprocess.TimeoutExpired:
        command.terminate()
        try:
            stdout, stderr = command.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            command.kill()
            stdout, stderr = command.communicate()
        subprocess.run([enclos, "--text", "sandbox", "stop", sandbox], env=env, capture_output=True, timeout=120)
        failed.append("the command ran past TIMEOUT: it was stopped, and its sandbox too")
    run = subprocess.CompletedProcess(command.args, command.returncode, stdout, stderr)
    took = time.time() - started
    for path, mtime in compiled_files().items():
        if before.get(path) == mtime:
            continue
        with open(path) as f:
            head = f.read(4096)
        on_allow = "\n(allow default)\n" in head
        if on_allow != (baseline == "allow"):
            failed.append(f"{path} was compiled on another baseline than {baseline}")
    why = canary("end")
    if why:
        failed.append(why)
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
for line in lines:
    parsed = parse(line)
    if parsed is None:
        unread.append(line)
        continue
    program, verdict, op, arg = parsed
    if arg.startswith("/enclos-trace-canary-"):
        continue
    entry = seen.setdefault((verdict, op, arg), {"n": 0, "programs": set()})
    entry["n"] += 1
    entry["programs"].add(program)

if dropped[0]:
    failed.append(f"TRUNCATED: {dropped[0]} lines past the cap of {MAX_LINES} were dropped")
if unread:
    failed.append(f"{len(unread)} tagged lines this script cannot read")
if untagged:
    failed.append(f"{len(untagged)} lines of the stream without the tag, which may stand for lines it dropped")
if errors:
    failed.append("log stream said on stderr: " + "".join(errors).strip())
if (NOTICE in run.stderr) != (baseline == "allow"):
    failed.append(f"the command did not run on the {baseline} baseline asked for, as its stderr says")
if run.returncode != 0:
    failed.append(f"the command exited {run.returncode}")

with open(out, "w") as f:
    for (verdict, op, arg), v in sorted(seen.items()):
        f.write(f"{v['n']:6d} {verdict} {op} {arg}  [{','.join(sorted(v['programs']))}]\n")
    for line in unread:
        f.write(f"UNREAD {line}")
    for line in untagged:
        f.write(f"UNTAGGED {line}")
    for why in failed:
        f.write(f"FAILED {why}\n")
open(out + ".stdout", "w").write(run.stdout)
open(out + ".stderr", "w").write(run.stderr)
print(f"exit {run.returncode} in {took:.0f}s, {len(lines)} log lines, {len(seen)} distinct lines -> {out}")
for why in failed:
    print(f"FAILED: {why}", file=sys.stderr)
sys.exit(1 if failed else 0)
