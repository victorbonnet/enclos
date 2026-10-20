# Sourced by every prototype script. Everything the prototype creates lives in
# .work/ next to this file (gitignored): the sandbox home, the compiled policy,
# the probe helper, logs. Nothing is written to the real home.
M1="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
WORK="$M1/.work"
SBX_HOME="${SBX_HOME:-$WORK/home}"          # the sandbox home
SBX_TAG="${SBX_TAG:-enclos-sbx-proto}"      # appears in every Seatbelt log line of this sandbox
PROXY_PORT="${PROXY_PORT:-18080}"
REAL_HOME="$(cd ~ && pwd -P)"                # only used to deny reads of it
mkdir -p "$WORK/bin" "$WORK/logs" "$SBX_HOME"
SBX_HOME="$(cd "$SBX_HOME" && pwd -P)"
PROBE="$WORK/bin/probe"
[ -x "$PROBE" ] && [ "$PROBE" -nt "$M1/probes/probe.c" ] || cc -O2 -Wall -o "$PROBE" "$M1/probes/probe.c"
