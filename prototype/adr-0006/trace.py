"""Runs an enclos command for a sandbox under one Seatbelt baseline, and
collects the denials, and the reports of `(with report)` rules, tagged
`enclos:<sandbox>` (ADR 0006's evidence).

The denials come from a live `log stream` this script starts itself: it
needs an admin user, is bounded in lines, is read through a pipe, is never
written to disk, and is stopped (its own child) once the command ends, also
when this script fails.

A capture that could read as clean without being so fails instead: a
stream that is not running, a canary denial (a write to `/`, made through
`enclos exec` before and after the command) that never shows, lines past
the cap, `Sandbox:` lines the script cannot read, or a baseline other than
the one asked for, as enclos's notice on stderr says.

usage: ENCLOS=<enclos binary> ENCLOS_HOME=<folder> \\
       python3 -I trace.py SANDBOX allow|deny OUT -- ENCLOS-ARGS...

Writes OUT, one line per distinct denial with its count and the programs
that met it, OUT.stdout and OUT.stderr, the command's output, and exits 1
when the capture or the command failed.
"""
import os
import re
import subprocess
import sys
import threading
import time

MAX_LINES = 300_000
CANARY_WAIT = 20
NOTICE = "compiled from (allow default)"

if len(sys.argv) < 5 or sys.argv[4] != "--" or sys.argv[2] not in ("allow", "deny"):
    sys.exit(__doc__)
sandbox, baseline, out = sys.argv[1], sys.argv[2], sys.argv[3]
args = sys.argv[5:]
tag = f"enclos:{sandbox}"
# The tag whole: `enclos:home` is not `enclos:home2`'s.
tagged = re.compile(re.escape(tag) + r"(?![A-Za-z0-9_-])")

env = dict(os.environ)
env.pop("ENCLOS_SEATBELT_BASELINE", None)
if baseline == "allow":
    env["ENCLOS_SEATBELT_BASELINE"] = "allow-default"

stream = subprocess.Popen(
    ["/usr/bin/log", "stream", "--style", "compact", "--predicate", f'eventMessage CONTAINS "{tag}"'],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
lines, dropped, errors = [], [0], []


def read():
    for line in stream.stdout:
        if not tagged.search(line):
            continue
        if len(lines) < MAX_LINES:
            lines.append(line)
        else:
            dropped[0] += 1


def read_errors():
    for line in stream.stderr:
        errors.append(line)


def canary(name):
    """A write to `/` from the sandbox, which every baseline denies, and
    whose denial must reach the stream."""
    mark = f"/enclos-trace-canary-{name}-{os.getpid()}"
    subprocess.run([os.environ["ENCLOS"], "--text", "exec", sandbox, "--", "/bin/sh", "-c", f": > {mark}"],
                   env=env, capture_output=True, timeout=120)
    deadline = time.time() + CANARY_WAIT
    while time.time() < deadline:
        if any(mark in line for line in lines):
            return True
        time.sleep(0.2)
    return False


failed = []
run = None
try:
    threading.Thread(target=read, daemon=True).start()
    threading.Thread(target=read_errors, daemon=True).start()
    time.sleep(1)
    if stream.poll() is not None:
        sys.exit("log stream is not running: " + "".join(errors).strip())
    if not canary("start"):
        sys.exit("the canary denial never reached the stream: nothing it collects can be trusted")
    started = time.time()
    run = subprocess.run([os.environ["ENCLOS"], "--text", *args], env=env, capture_output=True,
                         text=True, timeout=int(os.environ.get("TIMEOUT", "3600")))
    took = time.time() - started
    if not canary("end"):
        failed.append("the closing canary never reached the stream: late denials may be missing")
finally:
    stream.terminate()
    try:
        stream.wait(timeout=5)
    except subprocess.TimeoutExpired:
        stream.kill()
        stream.wait()

seen, unread = {}, []
for line in lines:
    if "Sandbox:" not in line:
        continue
    body = line[line.find("Sandbox:"):]
    m = re.search(r"Sandbox: (\S+?)\(\d+\) (allow|deny)(?:\(\d+\))? (\S+)(?: (.*?))?(?: \(|$)", body)
    if not m:
        unread.append(line)
        continue
    program, op, arg = m.group(1), m.group(3), (m.group(4) or "").strip()
    if "enclos-trace-canary-" in arg:
        continue
    entry = seen.setdefault((op, arg), {"n": 0, "programs": set()})
    entry["n"] += 1
    entry["programs"].add(program)

if dropped[0]:
    failed.append(f"TRUNCATED: {dropped[0]} lines past the cap of {MAX_LINES} were dropped")
if unread:
    failed.append(f"{len(unread)} Sandbox: lines this script cannot read")
if (NOTICE in run.stderr) != (baseline == "allow"):
    failed.append(f"the command did not run on the {baseline} baseline asked for, as its stderr says")
if run.returncode != 0:
    failed.append(f"the command exited {run.returncode}")

with open(out, "w") as f:
    for (op, arg), v in sorted(seen.items()):
        f.write(f"{v['n']:6d} {op} {arg}  [{','.join(sorted(v['programs']))}]\n")
    for line in unread:
        f.write(f"UNREAD {line}")
    for why in failed:
        f.write(f"FAILED {why}\n")
open(out + ".stdout", "w").write(run.stdout)
open(out + ".stderr", "w").write(run.stderr)
print(f"exit {run.returncode} in {took:.0f}s, {len(lines)} log lines, {len(seen)} distinct denials -> {out}")
for why in failed:
    print(f"FAILED: {why}", file=sys.stderr)
sys.exit(1 if failed else 0)
