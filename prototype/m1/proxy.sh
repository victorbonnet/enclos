#!/bin/bash
# Start the prototype proxy in the background and record its pid.
#   ./proxy.sh            allowlist mode, allowlist in allow.txt
#   ./proxy.sh --learn    allow any public destination and log it
#   ./proxy.sh stop
#
# Only the pid this script recorded is ever signalled, and only after checking
# that it is still our proxy.py (a stale pid may have been reused by another
# process). The recorded pid is `uv run`, which forwards SIGTERM to python;
# stop then checks that the port was released.
set -u
source "$(dirname "$0")/env.sh"
pidfile="$WORK/proxy.pid"
if [ -f "$pidfile" ]; then
    pid="$(cat "$pidfile")"
    if ps -o command= -p "$pid" 2>/dev/null | grep -qF "$M1/proxy.py"; then
        kill "$pid"
        sleep 1
    fi
    rm -f "$pidfile"
fi
if [ "${1:-}" = stop ]; then
    if /usr/sbin/lsof -nP -iTCP:"$PROXY_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
        echo "port $PROXY_PORT still in use after stop" >&2
        exit 1
    fi
    exit 0
fi
if /usr/sbin/lsof -nP -iTCP:"$PROXY_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $PROXY_PORT is in use; set PROXY_PORT to a free high port" >&2
    exit 1
fi
mode=(--allow "$M1/allow.txt")
[ "${1:-}" = --learn ] && mode=(--learn)
nohup uv run --no-project python -I "$M1/proxy.py" --port "$PROXY_PORT" "${mode[@]}" \
    --log "$WORK/logs/net.jsonl" >"$WORK/logs/proxy.out" 2>&1 &
echo $! >"$pidfile"
sleep 1
cat "$WORK/logs/proxy.out"
