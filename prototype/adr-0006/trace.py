"""Runs an enclos command for a sandbox under one Seatbelt baseline, and
collects the denials tagged `enclos:<sandbox>` (ADR 0006's evidence).

The denials come from a live `log stream` this script starts itself: it
needs an admin user, is bounded in lines, is read through a pipe, is never
written to disk, and is stopped (its own child) once the command ends.

usage: ENCLOS=<enclos binary> ENCLOS_HOME=<folder> \\
       python3 -I trace.py SANDBOX allow|deny OUT -- ENCLOS-ARGS...

Writes OUT, one line per distinct denial with its count and the programs
that met it, and OUT.stdout, the command's output.
"""
import os
import re
import subprocess
import sys
import threading
import time

MAX_LINES = 300_000

sandbox, baseline, out = sys.argv[1], sys.argv[2], sys.argv[3]
assert sys.argv[4] == "--"
args = sys.argv[5:]
tag = f"enclos:{sandbox}"
stream = subprocess.Popen(
    ["/usr/bin/log", "stream", "--style", "compact", "--predicate", f'eventMessage CONTAINS "{tag}"'],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
lines = []


def read():
    for line in stream.stdout:
        if len(lines) < MAX_LINES:
            lines.append(line)


reader = threading.Thread(target=read, daemon=True)
reader.start()
time.sleep(1.5)
env = dict(os.environ)
if baseline == "allow":
    env["ENCLOS_SEATBELT_BASELINE"] = "allow-default"
started = time.time()
run = subprocess.run([os.environ["ENCLOS"], "--text", *args], env=env, capture_output=True,
                     text=True, timeout=int(os.environ.get("TIMEOUT", "3600")))
took = time.time() - started
time.sleep(2)
stream.terminate()
stream.wait()
reader.join(timeout=5)

seen = {}
for line in lines:
    if "Sandbox:" not in line:
        continue
    body = line[line.find("Sandbox:"):]
    m = re.search(r"Sandbox: (\S+?)\(\d+\) (allow|deny)(?:\(\d+\))? (\S+)(?: (.*?))?(?: \(|$)", body)
    if not m:
        continue
    program, op, arg = m.group(1), m.group(3), (m.group(4) or "").strip()
    entry = seen.setdefault((op, arg), {"n": 0, "programs": set()})
    entry["n"] += 1
    entry["programs"].add(program)
with open(out, "w") as f:
    for (op, arg), v in sorted(seen.items()):
        f.write(f"{v['n']:6d} {op} {arg}  [{','.join(sorted(v['programs']))}]\n")
open(out + ".stdout", "w").write(run.stdout)
print(f"exit {run.returncode} in {took:.0f}s, {len(lines)} log lines, {len(seen)} distinct denials -> {out}")
