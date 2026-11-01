#!/bin/bash
# The host's path to a sandbox's service (M3-03, decision 2), so that Hermes's
# dashboard opens in the host's browser: a listener on the host's 127.0.0.1 at
# the sandbox's reserved port (host-listen.py) -> a Unix socket in the host-only
# folder -> the holder's relay (ns-holder.py --host-relay) -> 127.0.0.1:<service
# port> in the sandbox's network namespace. The service's port is read from the
# host, from the sockets the service's own processes hold, and written to a
# file only the host and the holder see (ADR 0028's rule, never a file the
# sandbox writes).
#
# First a stand-in (ns-webservice.py), with another session listening on an
# ephemeral port too, then Hermes's real listeners: the gateway's port, which
# serves the dashboard with its session token withheld, and
# `hermes dashboard --no-open`, which publishes it. For each, host-client.py
# through the path and, as the control, inside a joined session on the service's
# port. Then what a restart of the listener does, and for the stand-in a stale
# port and a holder restart.
#
# Needs Hermes where hermes-ns-check.sh installed it. Acts on the host (runs
# bubblewrap, makes namespaces): CI only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/70-dashboard.md"
tmp="$RESULTS_DIR/dashboard"
mkdir -p "$tmp"
RESERVED=18931
base="http://127.0.0.1:$RESERVED"

python3 -I "$M3/unix-proxy.py" --socket "$PROXY_SOCK" --learn --log "$tmp/proxy.jsonl" \
    >"$tmp/proxy.out" 2>&1 &
started=($!)
trap 'kill "${started[@]}" 2>/dev/null' EXIT
sleep 1

client() { python3 -I "$M3/host-client.py" "$@"; }
# held_port HOLDER_PID SESSION_PID [--ephemeral]: the one port on 127.0.0.1 in
# the holder's network namespace held by the session's processes, from the host.
held_port() {
    local pids
    pids=$(python3 -I "$M3/ns-procs.py" descendants "$2" | tr ' ' ',')
    python3 -I "$M3/ns-listeners.py" "$1" --held-by "${pids:-none}" --port-only ${3:+"$3"} 2>/dev/null
}
# listener [--no-reuseaddr]: starts the listener; says whether it bound.
listener() {
    python3 -I "$M3/host-listen.py" --port "$RESERVED" --socket "$dir/host-relay.sock" "$@" \
        >>"$tmp/listener.log" 2>&1 &
    lpid=$!
    started+=($lpid)
    sleep 0.7
    if [ -d "/proc/$lpid" ]; then echo "listener bound ($*)"; else echo "listener failed ($*): $(tail -1 "$tmp/listener.log")"; fi
}
# holder NAME: a holder and a control session in its namespace.
holder() {
    start_holder "$1"
    dir=$HOLDER
    hpid=$(cat "$dir/pid" 2>/dev/null)
    started+=("$(cat "$dir/bwrap.pid")")
    C="$SBX_HOME/open-dash-$1"
    open_session "$C" SBX_JOIN=nsenter SBX_HOLDER="$dir/holder.sock" || echo "control session of $1 did not start"
    started+=($OPEN_PID)
}
# compare LABEL PORT [--ws PATH]...: through the path, then inside the namespace.
compare() {
    local label="$1" port="$2"
    shift 2
    client check "$base" "$@" >"$tmp/$label-path.tsv" 2>&1
    ask "$C" 90 /usr/bin/python3 -I "$M3/host-client.py" check "http://127.0.0.1:$port" "$@" \
        2>&1 | grep -v '^inside:' >"$tmp/$label-direct.tsv"
}
# restart_listener LABEL WS_PATH: an open WebSocket, then the listener ended and
# started again, first without SO_REUSEADDR.
restart_listener() {
    local f="$tmp/$1-restart.txt" held="$tmp/$1-held.txt"
    {
        echo "## the listener restarted, with a WebSocket open through it"
        rm -f "$held"
        client hold "$base" "$2" "$held" --seconds 20 &
        local h=$!
        sleep 2
        echo "stopping the listener"
        kill "$lpid" 2>/dev/null
        wait "$lpid" 2>/dev/null
        wait "$h" 2>/dev/null
        cat "$held"
        echo "while it is down: $(client get "$base")"
        listener --no-reuseaddr
        if [ -d "/proc/$lpid" ]; then kill "$lpid" 2>/dev/null; wait "$lpid" 2>/dev/null; fi
        listener
        echo "after: $(client get "$base")"
        rm -f "$held"
        client hold "$base" "$2" "$held" --seconds 3
        cat "$held"
    } >"$f" 2>&1
}

# --- the stand-in
holder S
web="$SBX_HOME/web.json"
rm -f "$web"
join_cmd "$dir"
"${JOINED[@]}" /usr/bin/python3 -I "$M3/ns-webservice.py" --out "$web" >"$tmp/stand-in.out" 2>&1 &
svc=$!
started+=($svc)
for _ in $(seq 100); do [ -e "$web" ] && break; sleep 0.2; done
# Another session of the sandbox listening on an ephemeral port too.
"${JOINED[@]}" /usr/bin/python3 -I "$M3/ns-service.py" --name other --marker other \
    --out "$SBX_HOME/other.json" --seconds 900 >"$tmp/other.out" 2>&1 &
started+=($!)
sleep 2
port=$(held_port "$hpid" "$svc" --ephemeral)
{
    echo "every port on 127.0.0.1 in the ephemeral range:"
    python3 -I "$M3/ns-listeners.py" "$hpid" --ephemeral
    echo "the one port, not asking who holds it (empty when not one): [$(python3 -I "$M3/ns-listeners.py" "$hpid" --ephemeral --port-only)]"
    echo "held by the service's processes: [$port]"
    echo "what the service reports, for comparison only: $(cat "$web" 2>/dev/null)"
} >"$tmp/stand-in-port.txt" 2>&1
echo "$port" >"$dir/service.port"
listener >"$tmp/stand-in-listener.txt"
compare stand-in "$port" --ws /ws
{
    ask "$C" 30 /usr/bin/python3 -I "$M3/probe.py" "connect-unix $dir/host-relay.sock" \
        "connect-unix $dir/holder.sock" "read $dir/service.port" "connect-tcp 127.0.0.1 $RESERVED" \
        | grep -v '^inside:'
} >"$tmp/stand-in-session.tsv" 2>&1
restart_listener stand-in /ws
{
    echo
    echo "## the service restarted, so its port changes"
    kill "$svc" 2>/dev/null
    wait "$svc" 2>/dev/null
    echo "service down, old port still written: $(client get "$base")"
    rm -f "$web"
    "${JOINED[@]}" /usr/bin/python3 -I "$M3/ns-webservice.py" --out "$web" >>"$tmp/stand-in.out" 2>&1 &
    svc=$!
    started+=($svc)
    for _ in $(seq 100); do [ -e "$web" ] && break; sleep 0.2; done
    sleep 1
    echo "service up on a new port, old port still written: $(client get "$base")"
    new=$(held_port "$hpid" "$svc" --ephemeral)
    echo "$new" >"$dir/service.port"
    echo "port rewritten (changed: $([ "$new" != "$port" ] && echo yes || echo no)): $(client get "$base")"
    rm -f "$dir/service.port"
    echo "no port written: $(client get "$base")"
    echo "$new" >"$dir/service.port"
    echo
    echo "## the holder stopped, the listener left running"
    kill "$(cat "$dir/bwrap.pid")" 2>/dev/null
    sleep 2
    echo "$(client get "$base")"
    echo "listener alive: $([ -d "/proc/$lpid" ] && echo yes || echo no); service alive: $([ -d "/proc/$svc" ] && echo yes || echo no)"
} >>"$tmp/stand-in-restart.txt" 2>&1
touch "$C/stop"
kill "$svc" "$lpid" 2>/dev/null
wait "$lpid" 2>/dev/null
sleep 1

# --- Hermes
hermes_note="not run: Hermes is not installed in the sandbox's home"
if [ -x "$SBX_HOME/.local/bin/hermes" ]; then
    hermes_note=""
    src=$(find "$SBX_HOME" -path '*/hermes_cli/web_server_boundary.py' -not -path '*/node_modules/*' 2>/dev/null | head -1)
    src=${src%/hermes_cli/web_server_boundary.py}
    own() { SBX_JOIN=own SBX_RELAY=1 "$M3/sbx-ns.sh" -- /bin/bash -c "$1"; }
    {
        own 'export PATH="$HOME/.local/bin:$PATH"; hermes --version; hermes dashboard --help' | grep -v '^inside:'
        echo
        echo "== the Host check, the auth rule and the token, in the installed source ($src)"
        grep -nE 'def _is_accepted_host|def should_require_auth|def ws_host_origin_reason|return host_only in _LOOPBACK' \
            "$src/hermes_cli/web_server_boundary.py"
        grep -n 'withhold_session_token' "$src/gateway/run_api.py" "$src/hermes_cli/web_server_dashboard.py"
        grep -n 'type=int, default=9119' "$src/hermes_cli/subcommands/dashboard.py"
        ls "$src/hermes_cli/web_dist/index.html" 2>&1
    } 2>&1 | sed "s#$SBX_HOME#~#g" | cut -c1-200 >"$tmp/source.txt"

    holder H
    rm -f "$dir/service.port" "$SBX_HOME/.hermes/gateway.sock"
    join_cmd "$dir"
    "${JOINED[@]}" /bin/bash -c 'export PATH="$HOME/.local/bin:$PATH"; exec hermes -p default gateway run --external-supervisor -v' \
        </dev/null >"$tmp/gateway.log" 2>&1 &
    gw=$!
    started+=($gw)
    gport=""
    for _ in $(seq 90); do
        gport=$(held_port "$hpid" "$gw" --ephemeral)
        [ -n "$gport" ] && break
        sleep 1
    done
    echo "$gport" >"$dir/service.port"
    listener >"$tmp/hermes-listener.txt"
    compare gateway "${gport:-0}" --ws /api/ws

    # The real command, as `hermes dashboard --help` gives it: no browser to
    # open here. It builds the web UI itself if the installer's build is stale,
    # so it is given time, and it stays on its default port, 9119.
    "${JOINED[@]}" /bin/bash -c 'export PATH="$HOME/.local/bin:$PATH"; exec hermes dashboard --no-open' \
        </dev/null >"$tmp/dashboard.log" 2>&1 &
    dash=$!
    started+=($dash)
    dport=""
    for _ in $(seq 300); do
        dport=$(held_port "$hpid" "$dash")
        [ -n "$dport" ] && break
        [ -d "/proc/$dash" ] || break
        sleep 2
    done
    {
        echo "dashboard's port from the host: ${dport:-none}; alive: $([ -d "/proc/$dash" ] && echo yes || echo no)"
        python3 -I "$M3/ns-listeners.py" "$hpid"
    } >"$tmp/dashboard-port.txt" 2>&1
    if [ -n "$dport" ]; then
        sleep 5
        echo "$dport" >"$dir/service.port"
        compare dashboard "$dport" --ws /api/ws --ws /api/pty
        restart_listener dashboard /api/ws
    fi
    touch "$C/stop"
    kill "$gw" "$dash" "$lpid" "$(cat "$dir/bwrap.pid")" 2>/dev/null
    sleep 2
fi

side() { # side FILE...: each file with its last lines cut to a readable width.
    for f in "$@"; do [ -e "$f" ] && sed "s#$SBX_HOME#~#g" "$f" | cut -c1-220 | fence; done
}
{
    echo "# The host's path to a sandbox's service ($(uname -m))"
    echo
    echo "A listener on the host's 127.0.0.1:$RESERVED -> a Unix socket in a host-only folder -> the holder's relay -> 127.0.0.1:<service port> in the sandbox's network namespace. \"through the path\" is host-client.py on the host; \"in the namespace\" is the same in a joined session, on the service's own port, so a difference is the path's."
    section "A stand-in: the port read from the host"
    side "$tmp/stand-in-port.txt"
    section "A stand-in: page, asset, WebSocket"
    python3 -I "$M3/table.py" "through the path=$tmp/stand-in-path.tsv" "in the namespace=$tmp/stand-in-direct.tsv"
    section "A stand-in: what a session sees of the path"
    python3 -I "$M3/table.py" "a joined session=$tmp/stand-in-session.tsv"
    section "A stand-in: restarts"
    side "$tmp/stand-in-restart.txt"
    section "Hermes"
    [ -z "$hermes_note" ] || echo "$hermes_note"
    side "$tmp/source.txt"
    section "Hermes's gateway port"
    python3 -I "$M3/table.py" "through the path=$tmp/gateway-path.tsv" "in the namespace=$tmp/gateway-direct.tsv"
    section "\`hermes dashboard --no-open\`"
    side "$tmp/dashboard-port.txt"
    python3 -I "$M3/table.py" "through the path=$tmp/dashboard-path.tsv" "in the namespace=$tmp/dashboard-direct.tsv"
    echo
    echo "Its output, last lines:"
    [ -e "$tmp/dashboard.log" ] && grep -v '^inside:' "$tmp/dashboard.log" | tail -25 | sed "s#$SBX_HOME#~#g" | cut -c1-200 | fence
    section "\`hermes dashboard\`: the listener restarted"
    side "$tmp/dashboard-restart.txt"
} >"$out"
cat "$out"
