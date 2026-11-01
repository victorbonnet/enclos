"""A session left open (M3-03): what a user's terminal is while the service,
the proxy or the holder restarts. Run as a session's command, it waits for
commands the check drops in a folder of the sandbox's home, runs each inside
this one session and leaves its output there (lib.sh's `ask`), so the check
can tell what an open session sees, not what a new one would.

    python3 -I ns-open-session.py DIR

DIR/<n>.cmd holds a JSON list, the command; it answers in DIR/<n>.out and
DIR/<n>.exit. DIR/stop ends it.
"""

import json
import os
import subprocess
import sys
import time


def run(argv, out):
    try:
        with open(out, "wb") as f:
            return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=f,
                                  stderr=subprocess.STDOUT).returncode
    except OSError as e:
        with open(out, "a") as f:
            f.write(f"{e}\n")
        return 127


def main():
    d = sys.argv[1]
    open(os.path.join(d, "ready"), "w").close()
    n = 0
    while not os.path.exists(os.path.join(d, "stop")):
        cmd = os.path.join(d, f"{n}.cmd")
        if not os.path.exists(cmd):
            time.sleep(0.2)
            continue
        with open(cmd) as f:
            code = run(json.load(f), os.path.join(d, f"{n}.out"))
        tmp = os.path.join(d, f"{n}.tmp")
        with open(tmp, "w") as f:
            f.write(str(code))
        os.rename(tmp, os.path.join(d, f"{n}.exit"))
        n += 1


if __name__ == "__main__":
    main()
