#!/bin/bash
# Runs a command in the prototype's bubblewrap sandbox (M3-02):
#
#   [SBX_LANDLOCK=auto|off] [SBX_SECCOMP=on|off] [SBX_RELAY=1] [SBX_NEW_SESSION=1] \
#       sbx.sh -- command...
#
# It compiles the policy (compile.py), lists the host and finishes bubblewrap's
# arguments (wrap.py, which a cached policy would go through at each session's
# start), runs bubblewrap, and inside it inside.py, which applies Landlock where the kernel
# has it and SBX_LANDLOCK is not off (ADR 0037), then seccomp, then starts
# the relay when SBX_RELAY=1, then runs the command.
set -u
source "$(dirname "$0")/lib.sh"
[ "${1:-}" = -- ] && shift
[ $# -gt 0 ] || { echo "usage: sbx.sh -- command..." >&2; exit 2; }

extra=()
[ "${SBX_NEW_SESSION:-0}" = 1 ] && extra+=(--new-session)
compile_policy "${extra[@]}" || exit 1
mapfile -d '' args < <(python3 -I "$M3/wrap.py" "$SBX_COMPILED/compiled.json")

inside=(--compiled "$SBX_COMPILED/compiled.json"
    --landlock "${SBX_LANDLOCK:-auto}" --seccomp "${SBX_SECCOMP:-on}")
[ "${SBX_RELAY:-0}" = 1 ] && inside+=(--relay)
exec bwrap "${args[@]}" -- /usr/bin/python3 -I "$M3/inside.py" "${inside[@]}" -- "$@"
