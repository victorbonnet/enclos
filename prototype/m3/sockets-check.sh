#!/bin/bash
# The host's Unix sockets (design §5, Linux host services; §14): which ones
# the user can connect to on the host, listed from the host, and whether any
# is reachable from the sandbox, abstract sockets included. First the runner
# as it is, a server install; then with what a desktop session adds that a
# runner can run: an X server (Xvfb), a session bus, GNOME Keyring and an
# ssh agent, plus a socket in the home outside the deny list and an abstract
# socket of the check's own. A real desktop session (Wayland, PipeWire, the
# user's systemd manager under a graphical login) is for a VM.
#
# Connecting sends nothing: each probe connects and closes. CI only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/20-sockets.md"
tmp="$RESULTS_DIR/sockets"
mkdir -p "$tmp"

# Every socket with a name in the host's network namespace that one could
# connect to: listening stream and seqpacket sockets, and bound datagram ones.
list_sockets() {
    awk 'NR > 1 && $8 != "" {
        type = $5; listening = ($4 == "00010000")
        if (type == "0001" && listening) print $8 "\tstream"
        else if (type == "0005" && listening) print $8 "\tseqpacket"
        else if (type == "0002") print $8 "\tdgram"
    }' /proc/net/unix | sort -u
}

run_round() {  # name
    local name=$1 probes=() path kind
    list_sockets >"$tmp/$name.list"
    while IFS=$'\t' read -r path kind; do
        case "$path" in *" "*) continue ;; esac
        probes+=("connect-unix $path $kind")
    done <"$tmp/$name.list"
    python3 -I "$M3/probe.py" "${probes[@]}" >"$tmp/$name-host.tsv"
    SBX_LANDLOCK=off "$M3/sbx.sh" -- /usr/bin/python3 -I "$M3/probe.py" "${probes[@]}" \
        >"$tmp/$name-seccomp.tsv" 2>"$tmp/$name-seccomp.err"
    "$M3/sbx.sh" -- /usr/bin/python3 -I "$M3/probe.py" "${probes[@]}" \
        >"$tmp/$name-full.tsv" 2>"$tmp/$name-full.err"
}

reachable() {  # name: the sockets the sandbox connected to, in either mode
    awk -F'\t' '$2 == "ok" {print "- `" $1 "`"}' "$tmp/$1-seccomp.tsv" "$tmp/$1-full.tsv" | sort -u
}

run_round server

# --- what a desktop session adds, as far as a runner can run it
pids=()
Xvfb :99 -nolisten tcp >/dev/null 2>&1 &
pids+=($!)
eval "$(dbus-launch --sh-syntax)"
pids+=("$DBUS_SESSION_BUS_PID")
eval "$(ssh-agent -s)" >/dev/null
pids+=("$SSH_AGENT_PID")
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
keyring=$(gnome-keyring-daemon --start --components=secrets 2>&1)
python3 -I -c '
import socket, sys, time
a = socket.socket(socket.AF_UNIX); a.bind(sys.argv[1]); a.listen()
b = socket.socket(socket.AF_UNIX); b.bind("\0enclos-proto-abstract"); b.listen()
time.sleep(900)
' "$H/enclos-proto-sock" &
pids+=($!)
trap 'kill "${pids[@]}" 2>/dev/null; rm -f "$H/enclos-proto-sock"' EXIT
sleep 3
run_round desktop

{
    echo "# The host's Unix sockets ($(uname -m))"
    section "The runner"
    {
        echo "XDG_RUNTIME_DIR: ${XDG_RUNTIME_DIR}"
        echo "/run/user: $(ls /run/user 2>&1 | tr '\n' ' ')"
        echo "systemd --user: $(systemctl --user is-system-running 2>&1)"
        echo "session bus: ${DBUS_SESSION_BUS_ADDRESS:-}"
        echo "ssh agent: ${SSH_AUTH_SOCK:-}"
        echo "gnome-keyring: $keyring"
        echo "inside.py (full): $(grep -h '^inside:' "$tmp/desktop-full.err" | tr '\n' ' ')"
    } | fence
    for round in server desktop; do
        section "Reached from the sandbox ($round)"
        r=$(reachable "$round")
        echo "${r:-none}"
        section "Every socket listed from the host ($round)"
        python3 -I "$M3/table.py" "host=$tmp/$round-host.tsv" \
            "sandbox, no Landlock=$tmp/$round-seccomp.tsv" "sandbox, full=$tmp/$round-full.tsv"
    done
} >"$out"
cat "$out"
