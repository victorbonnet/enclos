#!/bin/bash
# Can the sandbox bind and connect to a Unix socket inside its own home? Hermes's
# gateway needs this (control socket, loop-tick socket). The socket is bound by
# a relative path from $HOME/tmp, so the long prototype path does not hit the
# 104-byte sun_path limit. Run with the current policy, then with an allow rule.
set -u
M1="$(cd "$(dirname "$0")/.." && pwd -P)"
source "$M1/env.sh"
PY="$(ls "$SBX_HOME"/.hermes/tools/python-*/bin/python3 | head -1)"
CODE='import os, socket
os.chdir(os.environ["HOME"] + "/tmp")
p = "probe-%d.sock" % os.getpid()
s = socket.socket(socket.AF_UNIX)
try:
    s.bind(p); s.listen(1)
    c = socket.socket(socket.AF_UNIX); c.connect(p); c.close()
    print("bind+connect ok")
except OSError as e:
    print("refused:", e); raise SystemExit(1)
finally:
    s.close()
    if os.path.exists(p): os.unlink(p)'
echo "== current compiled policy"
"$M1/sbx.sh" -- "$PY" -I -c "$CODE"
echo "== plus an allow rule for Unix sockets under the sandbox home"
SBX_EXTRA_RULES='(allow network-bind network-inbound (local unix-socket (subpath (param "SANDBOX_HOME"))))
(allow network-outbound (remote unix-socket (subpath (param "SANDBOX_HOME"))))' \
    "$M1/sbx.sh" -- "$PY" -I -c "$CODE"
