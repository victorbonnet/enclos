#!/bin/bash
# Runs a command in the prototype sandbox as one session of it, joined to the
# sandbox's namespaces in one of nsjoin.py's ways (M3-03):
#
#   SBX_JOIN=<one of nsjoin.py's ways> [SBX_HOLDER=<holder socket>] \
#   [SBX_LANDLOCK=auto|off] [SBX_SECCOMP=on|off] [SBX_RELAY=1] \
#   [SBX_SERVICE_FORWARD=1 | SBX_SERVICE_PORT=<port>] sbx-ns.sh -- command...
#
# `own` and `relay` are sbx.sh: namespaces of the session's own. Every other
# way gets the namespaces from the holder (ns-holder.py) at SBX_HOLDER
# through ns-fds.py, then runs nsenter and bubblewrap as nsjoin.py says, then
# inside.py.
#
# For the `relay` way (option 2): SBX_SERVICE_FORWARD=1 marks the service's
# session: ns-listen.py makes run/service.sock on the host and inside.py
# forwards it to 127.0.0.1 at the port the host writes in run/service.port.
# SBX_SERVICE_PORT=<port> marks any other session: inside.py listens on
# 127.0.0.1:<port> and forwards to run/service.sock.
set -u
source "$(dirname "$0")/lib.sh"
[ "${1:-}" = -- ] && shift
[ $# -gt 0 ] || { echo "usage: sbx-ns.sh -- command..." >&2; exit 2; }
join="${SBX_JOIN:-own}"

compile_policy || exit 1
inside=(/usr/bin/python3 -I "$M3/inside.py" --compiled "$SBX_COMPILED/compiled.json"
    --landlock "${SBX_LANDLOCK:-auto}" --seccomp "${SBX_SECCOMP:-on}")
[ "${SBX_RELAY:-0}" = 1 ] && inside+=(--relay)
SERVICE_SOCK="$SBX_RUN/service.sock"
[ "${SBX_SERVICE_FORWARD:-0}" = 1 ] && inside+=(--service-forward 13 "$SBX_RUN/service.port")
[ -n "${SBX_SERVICE_PORT:-}" ] && inside+=(--service-relay "$SBX_SERVICE_PORT" "$SERVICE_SOCK")
mapfile -d '' cmd < <(python3 -I "$M3/nsjoin.py" --compiled "$SBX_COMPILED/compiled.json" \
    --join "$join" -- "${inside[@]}" -- "$@")
[ "${#cmd[@]}" -gt 0 ] || { echo "sbx-ns.sh: nsjoin.py gave no command" >&2; exit 1; }

if [ "${SBX_SERVICE_FORWARD:-0}" = 1 ]; then
    cmd=(python3 -I "$M3/ns-listen.py" "$SERVICE_SOCK" -- "${cmd[@]}")
fi
if [ "$join" = own ] || [ "$join" = relay ]; then
    exec "${cmd[@]}"
fi
[ -n "${SBX_HOLDER:-}" ] || { echo "sbx-ns.sh: SBX_JOIN=$join needs SBX_HOLDER" >&2; exit 2; }
exec python3 -I "$M3/ns-fds.py" "$SBX_HOLDER" -- "${cmd[@]}"
