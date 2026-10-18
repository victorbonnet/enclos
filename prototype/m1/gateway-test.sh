#!/bin/bash
# What does `hermes gateway run` do with no messaging platform, and can a chat
# for a profile run alongside it? Everything runs through run-capped.sh: only
# the process groups it creates are ever signalled.
#   ./gateway-test.sh [profile] [seconds]
#
# Hermes 0.22.2 runs ONE gateway per Hermes root (the default profile's),
# serving every profile under profiles/; `hermes -p <name> gateway run` with no
# host gateway running refuses (exit 78), and with one running it attaches.
set -u
M1="$(cd "$(dirname "$0")" && pwd -P)"
source "$M1/env.sh"
profile="${1:-main}"
secs="${2:-60}"
log="$WORK/logs/gateway-default.out"

"$M1/run-capped.sh" "$secs" -- hermes gateway run -v --external-supervisor >"$log" 2>&1 &
leader=$!     # the run-capped leader; its pid is the gateway's process group
sleep 25

echo "== processes in the gateway's process group $leader (listed, not signalled)"
ps -A -o pid=,ppid=,pgid=,command= | awk -v g="$leader" '$3 == g' | cut -c1-140 \
    | sed -E "s#$SBX_HOME#\$SBX_HOME#g"
echo "== gateway status"
"$M1/run-capped.sh" 40 -- hermes gateway status 2>&1 | tail -15
echo "== hermes -p $profile gateway run while the host gateway runs (expect: attach and exit)"
"$M1/run-capped.sh" 60 -- hermes -p "$profile" gateway run 2>&1 | tail -10
echo "exit status: ${PIPESTATUS[0]}"
echo "== a one-shot chat for $profile while the gateway runs"
"$M1/run-capped.sh" 60 -- hermes -p "$profile" chat -q "Reply with the word ok." 2>&1 | tail -8
echo "== waiting for the gateway's cap (${secs}s)"
wait "$leader"
echo "gateway exit status: $?"
echo "== gateway output (last 60 lines)"
tail -n 60 "$log" | cut -c1-200 | sed -E "s#$SBX_HOME#\$SBX_HOME#g"
