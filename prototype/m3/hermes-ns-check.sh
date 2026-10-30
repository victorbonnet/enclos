#!/bin/bash
# Whether Hermes's clients find a gateway that runs in another session of the
# sandbox (M3-03, design §15 and §14): in a network namespace of the
# sandbox's, held by ns-holder.py, and in the same PID namespace or another.
#
# It installs Hermes in the sandbox's home (as hermes-check.sh, through the
# relay and a proxy in --learn mode), reads in Hermes's own source how a
# client finds its gateway, then for each way below starts
# `hermes -p default gateway run --external-supervisor` as the service
# session and, in a second session, a one-shot chat (`hermes -z`, which needs
# the gateway before it needs a model) and hermes-discover.py. No account is
# logged in, so the chat is expected to stop at the model; what matters is
# whether it got past the gateway, and whether it started a gateway of its
# own (ADR 0028, Consequences), counted from the host before and after and
# read in Hermes's gateway-starts.log.
#
#   own          each session its own network and PID namespaces (control)
#   userns-net   one network namespace, the holder's, joined with bubblewrap's
#                --userns and inside.py's setns; each session its own PIDs
#                (option 1a)
#   relay        each session its own namespaces; the gateway's port, read
#                from the host, relayed through run/service.sock (option 2)
#
# The first run's nsenter and --pidns ways failed at start (README.md), so
# they are not run again here; ns-diagnose.sh looks at why.
#
# Acts on the host (runs bubblewrap, makes namespaces, installs Hermes in the
# home): CI only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/60-hermes-namespaces.md"
tmp="$RESULTS_DIR/hermes-namespaces"
mkdir -p "$tmp"
installer_url="https://hermes-agent.nousresearch.com/install.sh"  # src/runtime/hermes.rs
WAYS=(own userns-net relay)

python3 -I "$M3/unix-proxy.py" --socket "$PROXY_SOCK" --learn --log "$tmp/proxy.jsonl" \
    >"$tmp/proxy.out" 2>&1 &
started=($!)
trap 'kill "${started[@]}" 2>/dev/null' EXIT
sleep 1

# --- install Hermes in the sandbox's home, in a session of its own
own() { SBX_JOIN=own SBX_RELAY=1 "$M3/sbx-ns.sh" -- /bin/bash -c "$1"; }
if [ ! -x "$SBX_HOME/.local/bin/hermes" ]; then
    own "mkdir -p ~/dl && curl -fsSL -o ~/dl/install.sh '$installer_url'" >"$tmp/download.log" 2>&1
    SBX_JOIN=own SBX_RELAY=1 timeout 2400 "$M3/sbx-ns.sh" -- /bin/bash "$SBX_HOME/dl/install.sh" \
        --non-interactive --skip-computer-use </dev/null >"$tmp/install.log" 2>&1
    echo "install: exit $?" >>"$tmp/install.log"
fi
own 'export PATH="$HOME/.local/bin:$PATH"; hermes --version' >"$tmp/version.log" 2>&1

# --- Hermes's source: how a client finds the gateway
client=$(find "$SBX_HOME" -path '*/hermes_cli/gateway_client.py' -not -path '*/node_modules/*' 2>/dev/null | head -1)
src=${client%/hermes_cli/gateway_client.py}
py=$(head -1 "$SBX_HOME/.local/bin/hermes" 2>/dev/null | sed -n 's/^#!\([^ ]*python[^ ]*\).*/\1/p')
[ -x "$py" ] || py=$(find "$SBX_HOME" -path '*/bin/python3' -path '*venv*' 2>/dev/null | head -1)
{
    echo "client: ${client:-not found}"
    echo "interpreter: ${py:-not found}"
    if [ -n "$client" ]; then
        echo
        echo "== hermes_cli/gateway_client.py: lines naming a pid, a signal, a lock, a socket or a port"
        grep -nE 'pid|kill|psutil|signal|lock|\.sock|port|127\.0\.0\.1|localhost' "$client" | cut -c1-200 | head -120
        echo
        echo "== the gateway's side (gateway/): pid files, liveness checks"
        grep -rnE 'os\.kill\(|pid_exists|psutil\.Process|getpid\(\)|\.pid\b|gateway\.pid|gateway\.lock' \
            "$src/gateway" "$src/hermes_cli" --include='*.py' 2>/dev/null | sed "s#$src/##" | cut -c1-200 | head -120
    fi
} >"$tmp/source.txt"

# Hermes's gateway, found two ways from the host: the processes holding a
# port on 127.0.0.1 in the ephemeral range in its network namespace (as ADR
# 0028 has enclos find it), and the processes whose command line names
# Hermes and its gateway (ns-procs.py leaves the launchers out, which the
# first run's count did not). gateway-starts.log, in the home, is Hermes's
# own record of each gateway start.
starts() { wc -l <"$SBX_HOME/.hermes/gateway-starts.log" 2>/dev/null || echo 0; }
by_name() { python3 -I "$M3/ns-procs.py" match hermes gateway | sed "s#$SBX_HOME#~#g" | cut -c1-200; }
summary=()
for way in "${WAYS[@]}"; do
    start_holder A
    A=$HOLDER
    hA=$(cat "$A/pid" 2>/dev/null)
    started+=("$(cat "$A/bwrap.pid")")
    relay=()
    case $way in own|relay) relay=(SBX_RELAY=1) ;; esac
    gwrole=()
    [ "$way" = relay ] && gwrole=(SBX_SERVICE_FORWARD=1)
    rm -f "$SBX_HOME/.hermes/gateway.sock" "$SBX_RUN/service.sock" "$SBX_RUN/service.port"
    sess=(env SBX_JOIN="$way" SBX_HOLDER="$A/holder.sock" "${relay[@]}" timeout 600 "$M3/sbx-ns.sh" --)
    starts_before=$(starts)

    env "${gwrole[@]}" "${sess[@]:1}" /bin/bash -c 'export PATH="$HOME/.local/bin:$PATH"; exec hermes -p default gateway run --external-supervisor -v' \
        </dev/null >"$tmp/$way-gateway.log" 2>&1 &
    gw=$!
    started+=($gw)
    for _ in $(seq 90); do [ -S "$SBX_HOME/.hermes/gateway.sock" ] && break; sleep 1; done
    sleep 10

    # A process in the gateway's network namespace: holder A's when shared,
    # else the deepest of the gateway session's processes with a listener
    # in the ephemeral range.
    nspid=""
    if [ "$way" = userns-net ]; then
        nspid=$hA
    else
        for p in $(python3 -I "$M3/ns-procs.py" descendants "$gw"); do
            if [ -n "$(python3 -I "$M3/ns-listeners.py" "$p" --ephemeral 2>/dev/null)" ]; then nspid=$p; break; fi
        done
    fi
    listeners=$(python3 -I "$M3/ns-listeners.py" "${nspid:-none}" --ephemeral 2>&1 | tr '\t\n' ' ;')
    port=$(python3 -I "$M3/ns-listeners.py" "${nspid:-none}" --ephemeral --port-only 2>/dev/null)
    named_before=$(by_name)
    chatrole=()
    if [ "$way" = relay ] && [ -n "$port" ]; then
        echo "$port" >"$SBX_RUN/service.port"
        chatrole=(SBX_SERVICE_PORT="$port")
    fi

    env "${chatrole[@]}" "${sess[@]:1}" /bin/bash -c 'export PATH="$HOME/.local/bin:$PATH"; timeout 120 hermes -z "Reply with exactly one word: ok"' \
        </dev/null >"$tmp/$way-chat.log" 2>&1
    chat=$?
    env "${chatrole[@]}" "${sess[@]:1}" "$py" -I "$M3/hermes-discover.py" "$src" </dev/null >"$tmp/$way-discover.log" 2>&1
    sleep 5
    named_after=$(by_name)
    starts_after=$(starts)
    listeners_after=$(python3 -I "$M3/ns-listeners.py" "${nspid:-none}" --ephemeral 2>&1 | tr '\t\n' ' ;')
    {
        echo "### \`$way\`"
        echo
        echo "gateway.sock: $([ -S "$SBX_HOME/.hermes/gateway.sock" ] && echo present || echo absent)"
        echo
        echo "The gateway session's launch: $(grep -h '^inside:\|^bwrap:\|^nsenter:' "$tmp/$way-gateway.log" | tr '\n' ' ')"
        echo
        echo "Ports on 127.0.0.1 in the ephemeral range in the gateway's network namespace (host pid ${nspid:-none}), with their holders: before the chat ${listeners:-none}; after ${listeners_after:-none}"
        echo
        echo "The port given to the chat's session: ${port:-none} ($([ "$way" = relay ] && echo "relayed through run/service.sock" || echo "not relayed"))"
        echo
        echo "Processes naming Hermes and its gateway, before the chat:"
        echo "${named_before:-none}" | fence
        echo "after the chat and the discovery:"
        echo "${named_after:-none}" | fence
        echo "gateway-starts.log: $starts_before lines before the gateway, $starts_after after the chat; its last lines:"
        tail -5 "$SBX_HOME/.hermes/gateway-starts.log" 2>&1 | fence
        echo "The chat (exit $chat), its last 40 lines:"
        grep -v '^inside:' "$tmp/$way-chat.log" | tail -40 | sed "s#$SBX_HOME#~#g" | cut -c1-200 | fence
        echo "What inside.py applied to the chat's session: $(grep -h '^inside:' "$tmp/$way-chat.log" | tr '\n' ' ')"
        echo
        echo "hermes-discover.py:"
        grep -v '^inside:' "$tmp/$way-discover.log" | sed "s#$SBX_HOME#~#g" | cut -c1-200 | head -80 | fence
        echo "The gateway's output, lines naming a client, a ticket, a socket or a port:"
        grep -inE 'client|ticket|socket|listen|port|websocket|lock|already|attach' "$tmp/$way-gateway.log" \
            | sed "s#$SBX_HOME#~#g" | cut -c1-200 | head -40 | fence
        echo "Hermes's gateway files in its home:"
        ls -la "$SBX_HOME/.hermes" 2>&1 | grep -i gateway | fence
    } >"$tmp/$way.md"
    summary+=("| \`$way\` | ${port:-none} | $(echo "$named_before" | grep -c .) | $(echo "$named_after" | grep -c .) | $((starts_after - starts_before)) | exit $chat: $(grep -v '^inside:' "$tmp/$way-chat.log" | tail -1 | tr '|' ' ' | cut -c1-100) |")

    # End the gateway session and holder this check started; in a shared
    # PID namespace, whatever the chat started there ends with the holder.
    kill "$gw" "$(cat "$A/bwrap.pid")" 2>/dev/null
    wait "$gw" 2>/dev/null
    sleep 3
done

{
    echo "# Hermes's clients and a gateway in another session ($(uname -m))"
    section "Hermes"
    { tail -3 "$tmp/version.log"; [ -e "$tmp/install.log" ] && tail -1 "$tmp/install.log"; } \
        | sed "s#$SBX_HOME#~#g" | fence
    section "How a client finds its gateway, in Hermes's source"
    sed "s#$SBX_HOME#~#g" "$tmp/source.txt" | fence
    section "Each way"
    echo "\"port\": the gateway's one port on 127.0.0.1 in the ephemeral range, read from the host. \"named\": processes whose command line names Hermes and its gateway, launchers left out, before and after the chat. \"starts\": lines added to Hermes's gateway-starts.log by the gateway and the chat."
    echo
    echo "| way | port | named before | named after | starts | chat |"
    echo "| --- | --- | --- | --- | --- | --- |"
    printf '%s\n' "${summary[@]}"
    echo
    for way in "${WAYS[@]}"; do [ -e "$tmp/$way.md" ] && cat "$tmp/$way.md"; done
    section "Endpoints the proxy saw (host:port verdict)"
    python3 -I -c '
import json, sys, collections
seen = collections.Counter()
for line in open(sys.argv[1]):
    e = json.loads(line)
    seen[(e.get("host"), e.get("port"), e.get("verdict"), e.get("reason", ""))] += 1
for (h, p, v, r), n in sorted(seen.items(), key=str):
    print(f"- {h}:{p} {v} {r} ({n})")
' "$tmp/proxy.jsonl"
} >"$out"
cat "$out"
