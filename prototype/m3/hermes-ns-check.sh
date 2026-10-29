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
# own (ADR 0028, Consequences), counted from the host before and after.
#
#   own          each session its own network and PID namespaces (control)
#   nsenter      one network namespace, each session its own PIDs
#   nsenter-pid  one network and one PID namespace
#   userns       one network and one PID namespace, bubblewrap joining them
#
# Acts on the host (runs bubblewrap, makes namespaces, installs Hermes in the
# home): CI only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/60-hermes-namespaces.md"
tmp="$RESULTS_DIR/hermes-namespaces"
mkdir -p "$tmp"
installer_url="https://hermes-agent.nousresearch.com/install.sh"  # src/runtime/hermes.rs
WAYS=(own nsenter nsenter-pid userns)

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

gateways() { ps -eo pid=,args= | grep -E '[g]ateway run' | grep -v -E 'bwrap|nsenter|timeout|sbx-ns' ; }
summary=()
for way in "${WAYS[@]}"; do
    start_holder A
    A=$HOLDER
    hA=$(cat "$A/pid" 2>/dev/null)
    started+=("$(cat "$A/bwrap.pid")")
    relay=()
    [ "$way" = own ] && relay=(SBX_RELAY=1)
    sess=(env SBX_JOIN="$way" SBX_HOLDER="$A/holder.sock" "${relay[@]}" timeout 600 "$M3/sbx-ns.sh" --)
    rm -f "$SBX_HOME/.hermes/gateway.sock"

    "${sess[@]}" /bin/bash -c 'export PATH="$HOME/.local/bin:$PATH"; exec hermes -p default gateway run --external-supervisor -v' \
        </dev/null >"$tmp/$way-gateway.log" 2>&1 &
    gw=$!
    started+=($gw)
    for _ in $(seq 90); do [ -S "$SBX_HOME/.hermes/gateway.sock" ] && break; sleep 1; done
    sleep 10
    before=$(gateways)
    # The gateway's loopback listeners, read from the host: in holder A's
    # network namespace, or (own) in the gateway's own.
    gwpid=$(echo "$before" | awk 'NR==1 {print $1}')
    nspid=$hA
    [ "$way" = own ] && nspid=$gwpid
    listeners=$(python3 -I -c '
import socket, struct, sys
try:
    lines = open(f"/proc/{sys.argv[1]}/net/tcp").read().splitlines()[1:]
except OSError as e:
    sys.exit(f"unreadable ({e.strerror})")
for line in lines:
    local, state = line.split()[1], line.split()[3]
    if state == "0A":
        addr, port = local.split(":")
        ip = socket.inet_ntoa(struct.pack("<I", int(addr, 16)))
        print(f"{ip}:{int(port, 16)}", end=" ")
' "${nspid:-none}" 2>&1)

    "${sess[@]}" /bin/bash -c 'export PATH="$HOME/.local/bin:$PATH"; timeout 120 hermes -z "Reply with exactly one word: ok"' \
        </dev/null >"$tmp/$way-chat.log" 2>&1
    chat=$?
    "${sess[@]}" "$py" -I "$M3/hermes-discover.py" "$src" </dev/null >"$tmp/$way-discover.log" 2>&1
    sleep 5
    after=$(gateways)
    {
        echo "### \`$way\`"
        echo
        echo "gateway.sock: $([ -S "$SBX_HOME/.hermes/gateway.sock" ] && echo present || echo absent)"
        echo
        echo "Listening on 127.0.0.1 in the gateway's network namespace (host pid ${nspid:-none}): ${listeners:-none}"
        echo
        echo "Gateway processes on the host, before the chat:"
        echo "${before:-none}" | sed "s#$SBX_HOME#~#g" | cut -c1-160 | fence
        echo "after the chat and the discovery:"
        echo "${after:-none}" | sed "s#$SBX_HOME#~#g" | cut -c1-160 | fence
        echo "The chat (exit $chat), its last 40 lines:"
        grep -v '^inside:' "$tmp/$way-chat.log" | tail -40 | sed "s#$SBX_HOME#~#g" | cut -c1-200 | fence
        echo "What inside.py applied to the chat's session: $(grep -h '^inside:' "$tmp/$way-chat.log" | tr '\n' ' ')"
        echo
        echo "hermes-discover.py:"
        grep -v '^inside:' "$tmp/$way-discover.log" | sed "s#$SBX_HOME#~#g" | cut -c1-200 | head -80 | fence
        echo "The gateway's output, lines naming a client, a ticket, a socket or a port:"
        grep -inE 'client|ticket|socket|listen|port|websocket|lock|already' "$tmp/$way-gateway.log" \
            | sed "s#$SBX_HOME#~#g" | cut -c1-200 | head -40 | fence
        echo "Hermes's gateway files in its home:"
        ls -la "$SBX_HOME/.hermes" 2>&1 | grep -i gateway | fence
    } >"$tmp/$way.md"
    summary+=("| \`$way\` | $(echo "$before" | grep -c .) | $(echo "$after" | grep -c .) | exit $chat |")

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
    echo "| way | gateways before the chat | after | chat |"
    echo "| --- | --- | --- | --- |"
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
