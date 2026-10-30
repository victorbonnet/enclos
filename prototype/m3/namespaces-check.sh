#!/bin/bash
# Namespaces per session or per sandbox (M3-03, design §15 and §14): can
# bubblewrap start inside a network namespace enclos entered first, so every
# session of a sandbox shares one and reaches its service's port (ADR 0028)?
# And what does sharing, or not, change for PIDs, signals, start-up
# environments, abstract sockets, the relay and the host?
#
# For each of nsjoin.py's ways, in full mode and without Landlock (ADR
# 0037), it starts two holders (ns-holder.py in bubblewrap: sandboxes A and
# B, each with its own user, PID and network namespace and its relay), a
# service session in sandbox A (ns-service.py, listening as Hermes's gateway
# does), then the same probes from a second session of A, from a session of
# B, and from the host. Then it ends A's holder and looks whether the service
# outlived it. Sandboxes A and B share one compiled policy, home and run/
# folder: only their namespaces differ. In the `relay` way (option 2), the
# service's session forwards run/service.sock to its port, which the host
# reads from the service's namespace and writes to run/service.port, and the
# other session of A relays that port; B is given no relay, as a sandbox
# without the service, but reaches the socket only because it shares run/.
#
# Then, for the `nsenter` way, the one decided on: what still holds in a joined
# session with each layer off in turn (--disable-userns, the seccomp filter,
# capabilities), and what a service, proxy or holder restart does to a session
# left open (ns-open-session.py), and to a new one.
#
# Acts on the host (runs bubblewrap, makes namespaces): CI only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/50-namespaces.md"
tmp="$RESULTS_DIR/namespaces"
mkdir -p "$tmp"
# The rejected ways stay in nsjoin.py; the third run measured them (README.md).
WAYS=(own nsenter relay)
HOST_PORT=18999

# --- the proxy every sandbox's relay reaches, and a listener on the host
allow="$tmp/allow.txt"
echo example.com >"$allow"
start_proxy() {
    python3 -I "$M3/unix-proxy.py" --socket "$PROXY_SOCK" --allow "$allow" --log "$tmp/proxy.jsonl" \
        >>"$tmp/proxy.out" 2>&1 &
    proxy=$!
}
start_proxy
started=($proxy)
python3 -I -m http.server --bind 127.0.0.1 "$HOST_PORT" >/dev/null 2>&1 &
started+=($!)
# Only what this script started is ever signalled.
trap 'kill "${started[@]}" 2>/dev/null' EXIT
sleep 1

# listening_in PID PORT: whether PORT listens on 127.0.0.1 or any address
# in the network namespace of host process PID, read from the host.
listening_in() {
    python3 -I - "$1" "$2" <<'EOF'
import sys
pid, port = sys.argv[1], int(sys.argv[2])
try:
    lines = open(f"/proc/{pid}/net/tcp").read().splitlines()[1:]
except OSError as e:
    print(f"unreadable ({e.strerror})"); sys.exit()
for line in lines:
    local, state = line.split()[1], line.split()[3]
    if state == "0A" and int(local.split(":")[1], 16) == port:
        print("yes"); sys.exit()
print("no")
EOF
}

# ns_of DIR: the holder's namespaces, as it read them itself.
ns_of() { python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["namespaces"]["net"])' "$1/info.json" 2>/dev/null || echo none; }

# --- controls on the host: what making the namespaces needs under AppArmor
{
    echo "unshare --user --map-current-user -- true: $(unshare --user --map-current-user -- true 2>&1 && echo ok)"
    echo "unshare --user --map-current-user --net -- true: $(unshare --user --map-current-user --net -- true 2>&1 && echo ok)"
    echo "unshare --user --map-current-user --net --pid --fork -- true: $(unshare --user --map-current-user --net --pid --fork -- true 2>&1 && echo ok)"
    echo "nsenter: $(nsenter --version 2>&1)"
    echo "bubblewrap: $(bwrap --version 2>&1)"
} >"$tmp/controls.txt"

summary=()
for way in "${WAYS[@]}"; do
    for mode in full nolandlock; do
        key="$way-$mode"
        ll=auto
        [ "$mode" = nolandlock ] && ll=off
        start_holder A; A=$HOLDER
        start_holder B; B=$HOLDER
        started+=("$(cat "$A/bwrap.pid")" "$(cat "$B/bwrap.pid")")
        hA=$(cat "$A/pid" 2>/dev/null)
        relay=()
        case $way in own|relay) relay=(SBX_RELAY=1) ;; esac
        # Option 2: the service's session forwards run/service.sock; the
        # other session of A relays the service's port to it (below).
        svcrole=()
        [ "$way" = relay ] && svcrole=(SBX_SERVICE_FORWARD=1)
        rm -f "$SBX_RUN/service.sock" "$SBX_RUN/service.port"
        # session HOLDER_DIR: the environment and launcher of one session of
        # that holder's sandbox, to put before the command.
        session() {
            sess=(env SBX_JOIN="$way" SBX_HOLDER="$1/holder.sock" SBX_LANDLOCK="$ll" "${relay[@]}"
                timeout 300 "$M3/sbx-ns.sh" --)
        }

        marker="svcmark-$key-$RANDOM$RANDOM"
        rev=$(printf '%s' "$marker" | rev)
        svcjson="$SBX_HOME/ns-service-A.json"
        rm -f "$svcjson"
        # A simple command in the background, so $! is timeout's, which
        # passes a TERM on to the session.
        session "$A"
        sess=(env "${svcrole[@]}" "${sess[@]:1}")
        "${sess[@]}" /usr/bin/env ENCLOS_NS_MARKER="$marker" /usr/bin/python3 -I "$M3/ns-service.py" \
            --name A --marker "$marker" --out "$svcjson" --seconds 240 >"$tmp/$key-svc.out" 2>&1 &
        svc=$!
        started+=($svc)
        for _ in $(seq 100); do [ -e "$svcjson" ] && break; sleep 0.2; done
        if [ ! -e "$svcjson" ]; then
            summary+=("| \`$way\` | $mode | the service session did not start: $(grep -v '^inside:' "$tmp/$key-svc.out" | tail -2 | tr '\n|' '  ' | cut -c1-200) | | | | |")
            kill "$svc" "$(cat "$A/bwrap.pid")" "$(cat "$B/bwrap.pid")" 2>/dev/null
            wait "$svc" 2>/dev/null
            continue
        fi
        cp "$svcjson" "$tmp/$key-svc.json"
        read -r lp ap abs svcnet < <(python3 -I -c '
import json, sys
s = json.load(open(sys.argv[1]))
print(s["loopback"], s["any"], s["abstract"], s["namespaces"]["net"])' "$svcjson")

        # The service's port as enclos would take it: read from the host, the
        # one port on 127.0.0.1 in the ephemeral range in the service's
        # network namespace (ADR 0028), never from the file the sandbox wrote.
        svchost=$(python3 -I "$M3/probe.py" "find $rev" | cut -f3 | sed -n 's/^pids \([0-9]*\).*/\1/p')
        hostport=$(python3 -I "$M3/ns-listeners.py" "${svchost:-none}" --ephemeral --port-only 2>/dev/null)
        python3 -I "$M3/ns-listeners.py" "${svchost:-none}" >"$tmp/$key-listeners.txt" 2>&1
        clientrole=()
        if [ "$way" = relay ] && [ -n "$hostport" ]; then
            echo "$hostport" >"$SBX_RUN/service.port"
            clientrole=(SBX_SERVICE_PORT="$hostport")
        fi

        probes=(
            "netns"
            "connect-tcp 127.0.0.1 $lp"
            "connect-tcp 127.0.0.1 $ap"
            "connect-unix $abs"
            "find $rev"
            "peer-kill $rev"
            "peer-environ $rev"
            "peer-ptrace $rev"
            "listen-tcp 127.0.0.1 $RELAY_PORT"
            "http https://example.com/"
            "connect-tcp 127.0.0.1 $HOST_PORT"
            "unshare user"
            "fds"
            "connect-unix $SBX_RUN/service.sock"
        )
        session "$A"
        sess=(env "${clientrole[@]}" "${sess[@]:1}")
        "${sess[@]}" /usr/bin/python3 -I "$M3/probe.py" "${probes[@]}" >"$tmp/$key-A.tsv" 2>"$tmp/$key-A.err"
        echo "exit $?" >>"$tmp/$key-A.err"
        session "$B"
        "${sess[@]}" /usr/bin/python3 -I "$M3/probe.py" "${probes[@]}" >"$tmp/$key-B.tsv" 2>"$tmp/$key-B.err"
        echo "exit $?" >>"$tmp/$key-B.err"
        python3 -I "$M3/probe.py" "${probes[@]}" "nsopen /proc/$hA/ns/net" "nsopen /proc/$hA/ns/user" \
            >"$tmp/$key-host.tsv" 2>&1
        # The rows read the same whatever the port and marker.
        for f in "$tmp/$key-A.tsv" "$tmp/$key-B.tsv" "$tmp/$key-host.tsv"; do
            sed -i -e "s/ $lp\t/ <service, 127.0.0.1>\t/; s/ $ap\t/ <service, any address>\t/" \
                -e "s/$rev/<marker>/g; s/ $RELAY_PORT\t/ <relay port>\t/; s/ $HOST_PORT\t/ <host listener>\t/" \
                -e "s#/proc/$hA/#/proc/<holder A>/#g" "$f"
        done

        # Where the service listens, read from the host, and whether it
        # outlives its holder (signal only the holder this script started).
        in_holder=$(listening_in "$hA" "$lp")
        kill "$(cat "$A/bwrap.pid")" 2>/dev/null
        sleep 2
        survives=unknown
        if [ -n "$svchost" ]; then
            if [ -d "/proc/$svchost" ]; then survives=yes; else survives=no; fi
        fi
        kill "$svc" "$(cat "$B/bwrap.pid")" 2>/dev/null
        wait "$svc" 2>/dev/null

        same=no
        [ "$svcnet" = "$(ns_of "$A")" ] && same=yes
        fromhost="${hostport:-none}"
        [ "$hostport" = "$lp" ] && fromhost="$hostport (the service's)"
        summary+=("| \`$way\` | $mode | started | $same | $in_holder | $survives | $fromhost |")
        {
            echo "### \`$way\`, $mode"
            echo
            echo "- holder A: $(cat "$A/info.json" 2>/dev/null) (host pid $hA)"
            echo "- holder B: $(cat "$B/info.json" 2>/dev/null)"
            echo "- service: $(cat "$tmp/$key-svc.json")"
            echo "- service session's launch: $(grep -h '^inside:\|^bwrap:\|^nsenter:' "$tmp/$key-svc.out" | tr '\n' ' ')"
            echo "- session of A: $(grep -h '^inside:\|^exit\|^bwrap:\|^nsenter:' "$tmp/$key-A.err" | tr '\n' ' ')"
            echo "- session of B: $(grep -h '^inside:\|^exit\|^bwrap:\|^nsenter:' "$tmp/$key-B.err" | tr '\n' ' ')"
            echo "- the service's network namespace, read from the host (port, holders): $(tr '\t\n' ' ;' <"$tmp/$key-listeners.txt")"
            echo
            python3 -I "$M3/table.py" "host=$tmp/$key-host.tsv" "another session of A=$tmp/$key-A.tsv" \
                "a session of B=$tmp/$key-B.tsv"
            echo
        } >"$tmp/$key.md"
    done
done

# --- what still holds in a joined session, each layer off in turn
holds=("status" "max-userns" "unshare user" "unshare mount" "unshare net" "mount" "keyctl" "bpf"
    "perf_event_open" "userfaultfd" "io_uring" "setns-net" "net-admin" "fds")
start_holder A; A=$HOLDER
started+=("$(cat "$A/bwrap.pid")")
python3 -I "$M3/probe.py" "${holds[@]}" >"$tmp/holds-host.tsv" 2>&1
holds_cols=("host=$tmp/holds-host.tsv")
# holds_in LABEL WAY LANDLOCK SECCOMP
holds_in() {
    env SBX_JOIN="$2" SBX_HOLDER="$A/holder.sock" SBX_LANDLOCK="$3" SBX_SECCOMP="$4" \
        timeout 120 "$M3/sbx-ns.sh" -- /usr/bin/python3 -I "$M3/probe.py" "${holds[@]}" \
        >"$tmp/holds-$1.tsv" 2>"$tmp/holds-$1.err"
    echo "exit $?" >>"$tmp/holds-$1.err"
    holds_cols+=("$1=$tmp/holds-$1.tsv")
}
holds_in own-full own auto on
holds_in own-no-seccomp own auto off
holds_in nsenter-full nsenter auto on
holds_in nsenter-no-landlock nsenter off on
holds_in nsenter-no-seccomp nsenter auto off
holds_in nsenter-neither nsenter off off
kill "$(cat "$A/bwrap.pid")" 2>/dev/null
sleep 1

# --- restarts, with one session of the sandbox left open
log="$tmp/restarts.txt"
joined() {
    env SBX_JOIN=nsenter SBX_HOLDER="$1/holder.sock" timeout 900 "$M3/sbx-ns.sh" -- "${@:2}"
}
# stand_in N: a service in a session of $A; sets svc and port.
stand_in() {
    local out="$SBX_HOME/ns-service-restart.json"
    rm -f "$out"
    joined "$A" /usr/bin/python3 -I "$M3/ns-service.py" --name "R$1" --marker "restart-$1" \
        --out "$out" --seconds 800 >"$tmp/restart-svc-$1.out" 2>&1 &
    svc=$!
    started+=($svc)
    for _ in $(seq 100); do [ -e "$out" ] && break; sleep 0.2; done
    port=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["loopback"])' "$out")
}
# step TITLE: a heading in the log. seen PROBE...: those probes in the open
# session. new HOLDER PROBE...: the same in a new session of that holder.
step() { printf '\n## %s\n' "$1" >>"$log"; }
seen() {
    {
        echo "open session (pid $open alive: $([ -d "/proc/$open" ] && echo yes || echo no)):"
        ask "$O" 45 /usr/bin/python3 -I "$M3/probe.py" "$@"
    } 2>&1 | grep -v '^inside:' >>"$log"
}
new() {
    local h="$1"
    shift
    {
        echo "new session:"
        joined "$h" /usr/bin/python3 -I "$M3/probe.py" "$@"
    } 2>&1 | grep -v '^inside:' >>"$log"
}
: >"$log"
start_holder A; A=$HOLDER
started+=("$(cat "$A/bwrap.pid")")
stand_in 1
old=$port
O="$SBX_HOME/open-restarts"
open_session "$O" SBX_JOIN=nsenter SBX_HOLDER="$A/holder.sock" || echo "the open session did not start" >>"$log"
open=$OPEN_PID
started+=($open)

step "before any restart"
seen netns "connect-tcp 127.0.0.1 $port" "http https://example.com/"

step "service restarted, so its port changes"
kill "$svc" 2>/dev/null
wait "$svc" 2>/dev/null
stand_in 2
echo "old port $old, new port $port" >>"$log"
seen "connect-tcp 127.0.0.1 $old" "connect-tcp 127.0.0.1 $port"

step "proxy stopped"
kill "$proxy" 2>/dev/null
wait "$proxy" 2>/dev/null
seen "http https://example.com/" "connect-tcp 127.0.0.1 $RELAY_PORT"
step "proxy started again, same socket"
start_proxy
started+=($proxy)
sleep 1
seen "http https://example.com/"
new "$A" "http https://example.com/"

step "holder stopped"
kill "$(cat "$A/bwrap.pid")" 2>/dev/null
sleep 2
echo "service alive: $([ -d "/proc/$svc" ] && echo yes || echo no)" >>"$log"
seen netns "connect-tcp 127.0.0.1 $port" "http https://example.com/" "listen-tcp 127.0.0.1 $RELAY_PORT"
step "a new holder: a new network namespace"
start_holder A2; A2=$HOLDER
started+=("$(cat "$A2/bwrap.pid")")
new "$A2" netns "connect-tcp 127.0.0.1 $port" "http https://example.com/"
seen netns "http https://example.com/" "connect-unix $A2/holder.sock"
echo "service alive: $([ -d "/proc/$svc" ] && echo yes || echo no)" >>"$log"
touch "$O/stop"
kill "$svc" "$(cat "$A2/bwrap.pid")" 2>/dev/null
sed -i -e "s/ $old\t/ <old port>\t/; s/ $port\t/ <service>\t/" "$log"

{
    echo "# Namespaces per session or per sandbox ($(uname -m))"
    section "Controls on the host"
    fence <"$tmp/controls.txt"
    section "Each way"
    echo "\"same\": the service's network namespace is holder A's. \"listens in A\": its 127.0.0.1 port is in holder A's network namespace, read from the host in \`/proc/<holder>/net/tcp\`. \"outlives\": the service is still running 2 s after holder A's bubblewrap is ended."
    echo
    echo "\"port from the host\": the one 127.0.0.1 port in the ephemeral range in the service's network namespace, read from the host (\`ns-listeners.py\`), and whether it is the one the service reported."
    echo
    echo "| way | mode | service | same | listens in A | outlives | port from the host |"
    echo "| --- | --- | --- | --- | --- | --- | --- |"
    printf '%s\n' "${summary[@]}"
    section "What still holds in a joined session"
    echo "\`status\` is the probe's own \`/proc/self/status\`. With seccomp off, \`unshare user\` shows \`--disable-userns\` alone (ENOSPC from it, as in M3-02); \`setns-net\` and \`net-admin\` show the session has no capability over the sandbox's network namespace."
    echo
    python3 -I "$M3/table.py" "${holds_cols[@]}"
    echo
    echo "Launches: $(grep -h '^exit\|^bwrap:\|^nsenter:' "$tmp"/holds-*.err | sort | uniq -c | tr '\n' ';')"
    section "Restarts with a session open"
    echo "The \`nsenter\` way, full mode. Each probe line: probe, result, detail."
    echo
    fence <"$log"
    section "Probes, by way and mode"
    echo "\`ok\` means the operation succeeded; an error name means it was refused with that error. \`find\` and the \`peer-\` rows look for the service by its marker; \`listen-tcp <relay port>\` shows whether a session could start a relay of its own; \`http\` goes through the proxy variables, to the relay."
    echo
    for way in "${WAYS[@]}"; do
        for mode in full nolandlock; do
            [ -e "$tmp/$way-$mode.md" ] && cat "$tmp/$way-$mode.md"
        done
    done
} >"$out"
cat "$out"
