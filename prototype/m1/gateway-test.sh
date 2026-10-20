#!/bin/bash
# What does `hermes gateway run` do with no messaging platform, and does a
# profile's chat (a real model call) work alongside it? Everything runs through
# run-capped.sh: only the process groups it creates are ever signalled.
#   ./gateway-test.sh [profile] [seconds]
#
# Hermes 0.22.2 runs ONE gateway per Hermes home (the default profile's),
# serving every profile under profiles/; `hermes -p <name> gateway run` with no
# gateway running refuses (exit 78), and with one running it is meant to attach.
#
# Never run `hermes gateway status` here: Hermes's launchd helper takes the home
# from the password database, so it read the host's own LaunchAgents and listed
# the host's own gateway processes (now denied by 20-read-deny.sb).
set -u
M1="$(cd "$(dirname "$0")" && pwd -P)"
source "$M1/env.sh"
profile="${1:-main}"
secs="${2:-90}"
log="$WORK/logs/gateway-default.out"

"$M1/run-capped.sh" "$secs" -- hermes gateway run -v --external-supervisor >"$log" 2>&1 &
leader=$!     # the run-capped leader; its pid is the gateway's process group
sleep 25

echo "== processes in the gateway's process group $leader (listed, not signalled)"
ps -A -o pid=,ppid=,pgid=,command= | awk -v g="$leader" '$3 == g' | cut -c1-120 \
    | sed -E "s#$SBX_HOME#\$SBX_HOME#g"
echo "== a one-shot model call for $profile while the gateway runs"
HERMES_MODEL="${HERMES_MODEL:-gpt-5.6-luna}" CAP_SECS=60 "$M1/model-call.sh" "beside-gateway" "$profile" \
    | grep -vE 'auth.json|size='
echo "== waiting for the gateway's cap (${secs}s)"
wait "$leader"
echo "gateway exit status: $?"
echo "== gateway: last lines"
grep -E 'Cron scheduler|Press Ctrl|SIGTERM|Exiting|Gateway stopped' "$log" | cut -c1-160 | sed -E "s#$SBX_HOME#\$SBX_HOME#g"
