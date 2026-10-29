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
# outlived it. Sandboxes A and B share one compiled policy and home: only
# their namespaces differ.
#
# Acts on the host (runs bubblewrap, makes namespaces): CI only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/50-namespaces.md"
tmp="$RESULTS_DIR/namespaces"
mkdir -p "$tmp"
WAYS=(own nsenter nsenter-pid nsenter-userns userns userns-subpid)
HOST_PORT=18999

# --- the proxy every sandbox's relay reaches, and a listener on the host
allow="$tmp/allow.txt"
echo example.com >"$allow"
python3 -I "$M3/unix-proxy.py" --socket "$PROXY_SOCK" --allow "$allow" --log "$tmp/proxy.jsonl" \
    >"$tmp/proxy.out" 2>&1 &
started=($!)
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
        [ "$way" = own ] && relay=(SBX_RELAY=1)
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
        "${sess[@]}" /usr/bin/env ENCLOS_NS_MARKER="$marker" /usr/bin/python3 -I "$M3/ns-service.py" \
            --name A --marker "$marker" --out "$svcjson" --seconds 240 >"$tmp/$key-svc.out" 2>&1 &
        svc=$!
        started+=($svc)
        for _ in $(seq 100); do [ -e "$svcjson" ] && break; sleep 0.2; done
        if [ ! -e "$svcjson" ]; then
            summary+=("| \`$way\` | $mode | the service session did not start: $(grep -v '^inside:' "$tmp/$key-svc.out" | tail -2 | tr '\n|' '  ' | cut -c1-200) | | | |")
            kill "$svc" "$(cat "$A/bwrap.pid")" "$(cat "$B/bwrap.pid")" 2>/dev/null
            wait "$svc" 2>/dev/null
            continue
        fi
        cp "$svcjson" "$tmp/$key-svc.json"
        read -r lp ap abs svcnet < <(python3 -I -c '
import json, sys
s = json.load(open(sys.argv[1]))
print(s["loopback"], s["any"], s["abstract"], s["namespaces"]["net"])' "$svcjson")

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
        )
        session "$A"
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
        svchost=$(python3 -I "$M3/probe.py" "find $rev" | cut -f3 | sed -n 's/^pids \([0-9]*\).*/\1/p')
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
        summary+=("| \`$way\` | $mode | started | $same | $in_holder | $survives |")
        {
            echo "### \`$way\`, $mode"
            echo
            echo "- holder A: $(cat "$A/info.json" 2>/dev/null) (host pid $hA)"
            echo "- holder B: $(cat "$B/info.json" 2>/dev/null)"
            echo "- service: $(cat "$tmp/$key-svc.json")"
            echo "- service session's launch: $(grep -h '^inside:\|^bwrap:\|^nsenter:' "$tmp/$key-svc.out" | tr '\n' ' ')"
            echo "- session of A: $(grep -h '^inside:\|^exit\|^bwrap:\|^nsenter:' "$tmp/$key-A.err" | tr '\n' ' ')"
            echo "- session of B: $(grep -h '^inside:\|^exit\|^bwrap:\|^nsenter:' "$tmp/$key-B.err" | tr '\n' ' ')"
            echo
            python3 -I "$M3/table.py" "host=$tmp/$key-host.tsv" "another session of A=$tmp/$key-A.tsv" \
                "a session of B=$tmp/$key-B.tsv"
            echo
        } >"$tmp/$key.md"
    done
done

{
    echo "# Namespaces per session or per sandbox ($(uname -m))"
    section "Controls on the host"
    fence <"$tmp/controls.txt"
    section "Each way"
    echo "\"same\": the service's network namespace is holder A's. \"listens in A\": its 127.0.0.1 port is in holder A's network namespace, read from the host in \`/proc/<holder>/net/tcp\`. \"outlives\": the service is still running 2 s after holder A's bubblewrap is ended."
    echo
    echo "| way | mode | service | same | listens in A | outlives |"
    echo "| --- | --- | --- | --- | --- | --- |"
    printf '%s\n' "${summary[@]}"
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
