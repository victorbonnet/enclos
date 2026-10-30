#!/bin/bash
# The stand-in for `enclos dashboard <sandbox>` (dashboard-cmd.py), end to end
# (M3-03): Hermes's real dashboard from the host, through the listener, for the
# user running it and for no other. In order:
#
#   a. page, assets, WebSockets, the terminal (/api/pty) and the chat as far as
#      an install with no account goes, with Host and Origin refused when wrong;
#   b. a second unix user refused, with the session token not in what it got,
#      and a control that this user's network works;
#   c. the same user served, the token in what it got, as the control of (b);
#   d. ssh -L on the runner: this user served, the second user refused;
#   e. a second run refused, then SIGINT to the command this check started,
#      leaving no listener, session or dashboard process, then a clean rerun.
#
# verdicts.tsv says what each was expected to do and what it did. Keys and the
# token stay in a folder outside the results, which are uploaded. Needs Hermes
# where hermes-ns-check.sh installed it. Acts on the host (a user, sshd,
# bubblewrap, namespaces): CI only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/75-dashboard-cmd.md"
tmp="$RESULTS_DIR/dashboard-cmd"
mkdir -p "$tmp"
OTHER=enclosother
RESERVED=18951
CONTROL=18952
TUNNEL=18953
OTHER_TUNNEL=18954
OTHER_CONTROL=18955
base="http://127.0.0.1:$RESERVED"
me=$(id -un)
secret=$(mktemp -d /tmp/enclos-secret.XXXXXX)
share=$(mktemp -d /tmp/enclos-other.XXXXXX)
chmod 755 "$share"
mkdir "$share/out"
chmod 1777 "$share/out"
cp "$M3/host-client.py" "$M3/wsmini.py" "$share/"
chmod 644 "$share"/*.py

python3 -I "$M3/unix-proxy.py" --socket "$PROXY_SOCK" --learn --log "$tmp/proxy.jsonl" \
    >"$tmp/proxy.out" 2>&1 &
started=($!)
python3 -I -m http.server --bind 127.0.0.1 "$CONTROL" --directory "$share/out" >/dev/null 2>&1 &
started+=($!)
finish() {
    kill "${started[@]}" 2>/dev/null
    rm -rf "$secret" "$share"
    sudo userdel -r "$OTHER" 2>/dev/null
}
trap finish EXIT
sleep 1

client() { python3 -I "$M3/host-client.py" "$@"; }
other() { sudo -u "$OTHER" python3 -I "$share/host-client.py" "$@"; }
: >"$tmp/verdicts.tsv"
# want LABEL EXPECTED MEASURED: a row of the verdicts.
want() {
    local v=FAIL
    [ "$2" = "$3" ] && v=pass
    printf '%s\t%s\texpected: %s; measured: %s\n' "$1" "$v" "$2" "$3" >>"$tmp/verdicts.tsv"
}
# cell FILE SPEC: the result and detail of that row.
cell() { awk -F'\t' -v s="$2" '$1 == s { print $2, $3; exit }' "$1"; }
# first WORD of a row.
result() { awk -F'\t' -v s="$2" '$1 == s { print $2; exit }' "$1"; }
# raw_as WHO LABEL BASE [PATH]: one request as that user; verdict inputs left
# in $share/out/LABEL, and the row in $tmp/LABEL.tsv.
raw_as() {
    local who=$1 label=$2 url=$3 path=${4:-/}
    if [ "$who" = other ]; then
        other raw "$url" "$share/out/$label" --path "$path" >"$tmp/$label.tsv" 2>&1
    else
        client raw "$url" "$share/out/$label" --path "$path" >"$tmp/$label.tsv" 2>&1
    fi
}
# has_token LABEL: how many times the token is in that answer.
has_token() { grep -cF "$(cat "$secret/token")" "$share/out/$1" 2>/dev/null || true; }
snapshot() { # snapshot NAME: the host's listeners and the sandbox's, by name.
    {
        echo "== the host's listening sockets on the reserved port"
        ss -ltnH "sport = :$RESERVED"
        echo "== ports on 127.0.0.1 in the sandbox's network namespace"
        python3 -I "$M3/ns-listeners.py" "$hpid"
    } >"$tmp/snapshot-$1.txt" 2>&1
}

if [ ! -x "$SBX_HOME/.local/bin/hermes" ]; then
    echo "not run: Hermes is not installed in the sandbox's home" | tee "$out"
    exit 0
fi

# --- the second user and sshd, on this runner only
{
    sudo useradd -m -s /bin/bash "$OTHER"
    sudo usermod -p '*' "$OTHER"
    systemctl list-unit-files ssh.service >/dev/null 2>&1 || sudo apt-get install -y -qq openssh-server
    sudo systemctl start ssh
    ssh-keygen -q -t ed25519 -N '' -f "$secret/mine"
    ssh-keygen -q -t ed25519 -N '' -f "$secret/theirs"
    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    cat "$secret/mine.pub" >>~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    sudo install -d -m 700 -o "$OTHER" -g "$OTHER" "/home/$OTHER/.ssh"
    sudo install -m 600 -o "$OTHER" -g "$OTHER" "$secret/theirs.pub" "/home/$OTHER/.ssh/authorized_keys"
    id "$OTHER"
} >"$tmp/setup.log" 2>&1
tunnel() { # tunnel KEY USER -L...: an ssh with those forwards; sets tpid.
    local key=$1 user=$2
    shift 2
    ssh -i "$secret/$key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o IdentitiesOnly=yes -o ExitOnForwardFailure=yes -o LogLevel=ERROR -N "$@" "$user@127.0.0.1" \
        >>"$tmp/ssh.log" 2>&1 &
    tpid=$!
    started+=($tpid)
    sleep 3
}

# --- the command
start_holder H
dir=$HOLDER
hpid=$(cat "$dir/pid" 2>/dev/null)
started+=("$(cat "$dir/bwrap.pid")")
audit="$tmp/audit.jsonl"
start_cmd() {
    python3 -I "$M3/dashboard-cmd.py" run --sandbox proto --run "$dir" --port "$RESERVED" \
        --audit "$audit" --log "$tmp/session.log" >"$tmp/$1.out" 2>&1 &
    cmd=$!
    started+=($cmd)
    for _ in $(seq 600); do
        grep -q '^http://127' "$tmp/$1.out" && return 0
        [ -d "/proc/$cmd" ] || return 1
        sleep 1
    done
    return 1
}
snapshot before
python3 -I "$M3/dashboard-cmd.py" status --sandbox proto >"$tmp/status.txt" 2>&1
want "status names the command, gives no URL" "1 0" "$(grep -c 'enclos dashboard proto' "$tmp/status.txt") $(grep -c 'http' "$tmp/status.txt")"
if start_cmd first; then
    sleep 3
    snapshot during
    during=$(python3 -I "$M3/ns-procs.py" descendants "$cmd")
    {
        echo "$cmd (the command)"
        for p in $during; do echo "$p $(cat "/proc/$p/comm" 2>/dev/null)"; done
    } >"$tmp/processes-during.txt"
    want "URL printed is the reserved port" "$base/" "$(grep '^http://' "$tmp/first.out")"
    client token "$base" "$secret/token"
    want "a session token was read, as this user" 1 "$([ -s "$secret/token" ] && echo 1 || echo 0)"

    # (a) and (c)
    client check "$base" --ws /api/ws --ws /api/pty >"$tmp/path.tsv" 2>&1
    client pty "$base" >"$tmp/terminal.tsv" 2>&1
    client chat "$base" >"$tmp/chat.tsv" 2>&1
    want "page" ok "$(result "$tmp/path.tsv" 'GET / (Host: 127.0.0.1:<url port>)')"
    want "assets" ok "$(result "$tmp/path.tsv" 'assets named by the page')"
    want "/api/status, /api/auth/me" "ok ok" "$(result "$tmp/path.tsv" 'GET /api/status') $(result "$tmp/path.tsv" 'GET /api/auth/me')"
    want "WebSocket /api/ws" ok "$(result "$tmp/path.tsv" 'WS /api/ws')"
    want "terminal /api/pty opens" ok "$(result "$tmp/terminal.tsv" 'terminal: /api/pty')"
    want "terminal gives output" ok "$(result "$tmp/terminal.tsv" 'terminal: output')"
    want "typed text comes back on the terminal" ok "$(result "$tmp/terminal.tsv" 'terminal: typed text comes back')"
    want "chat: session.create" ok "$(result "$tmp/chat.tsv" 'chat: session.create')"
    want "chat: prompt.submit" ok "$(result "$tmp/chat.tsv" 'chat: prompt.submit')"
    want "wrong Host is 400" "refused 400" "$(cell "$tmp/path.tsv" 'GET / (Host: evil.example:<url port>)')"
    want "wrong Host on a WebSocket is 403" "403" "$(cell "$tmp/path.tsv" 'WS /api/ws (Host: evil.example)' | awk '{print $3}')"
    want "wrong Origin is 403" "403" "$(cell "$tmp/path.tsv" 'WS /api/ws (Origin: evil.example)' | awk '{print $3}')"
    want "no token is 403" "403" "$(cell "$tmp/path.tsv" 'WS /api/ws (no token)' | awk '{print $3}')"

    raw_as me same-user "$base"
    want "this user served" served "$(result "$tmp/same-user.tsv" 'raw GET /')"
    want "this user's answer holds the token (the control of the next rows)" 1 "$(has_token same-user)"

    # (b)
    raw_as other other-page "$base"
    raw_as other other-pty "$base" /api/pty
    other get "$base" >"$tmp/other-get.tsv" 2>&1
    raw_as other other-control "http://127.0.0.1:$CONTROL"
    want "second user refused on the page" refused "$(result "$tmp/other-page.tsv" 'raw GET /')"
    want "second user gets no bytes" 0 "$(wc -c <"$share/out/other-page")"
    want "second user's answer holds no token" 0 "$(has_token other-page)"
    want "second user refused on /api/pty" refused "$(result "$tmp/other-pty.tsv" 'raw GET /api/pty')"
    want "second user's own network works (control)" served "$(result "$tmp/other-control.tsv" 'raw GET /')"
    want "the second user's connection was refused by owner" 1 "$(grep -c "owner $(id -u "$OTHER")\$" "$tmp/session.log" | awk '{print ($1 > 0)}')"

    # (d)
    tunnel mine "$me" -L "127.0.0.1:$TUNNEL:127.0.0.1:$RESERVED"
    t1=$tpid
    tunnel theirs "$OTHER" -L "127.0.0.1:$OTHER_TUNNEL:127.0.0.1:$RESERVED" -L "127.0.0.1:$OTHER_CONTROL:127.0.0.1:$CONTROL"
    t2=$tpid
    client check "http://127.0.0.1:$TUNNEL" --ws /api/ws --ws /api/pty >"$tmp/tunnel.tsv" 2>&1
    client pty "http://127.0.0.1:$TUNNEL" >"$tmp/tunnel-terminal.tsv" 2>&1
    want "ssh -L as this user: page" ok "$(result "$tmp/tunnel.tsv" 'GET / (Host: 127.0.0.1:<url port>)')"
    want "ssh -L as this user: WebSocket" ok "$(result "$tmp/tunnel.tsv" 'WS /api/ws')"
    want "ssh -L as this user: typed text comes back" ok "$(result "$tmp/tunnel-terminal.tsv" 'terminal: typed text comes back')"
    raw_as me tunnel-other "http://127.0.0.1:$OTHER_TUNNEL"
    raw_as me tunnel-other-control "http://127.0.0.1:$OTHER_CONTROL"
    want "ssh -L as the second user: refused" refused "$(result "$tmp/tunnel-other.tsv" 'raw GET /')"
    want "ssh -L as the second user: no token" 0 "$(has_token tunnel-other)"
    want "ssh -L as the second user: its tunnel works (control)" served "$(result "$tmp/tunnel-other-control.tsv" 'raw GET /')"
    kill "$t1" "$t2" 2>/dev/null

    # (e)
    python3 -I "$M3/dashboard-cmd.py" run --sandbox proto --run "$dir" --port "$RESERVED" \
        --audit "$audit" --log "$tmp/session.log" >"$tmp/second.out" 2>&1
    want "a second run is refused" 3 "$?"
    want "the refusal names the first" 1 "$(grep -c "pid $cmd" "$tmp/second.out")"
    want "the first still serves" ok "$(client get "$base" | cut -f2)"
    kill -INT "$cmd"
    wait "$cmd"
    want "SIGINT ends the command" 0 "$?"
    sleep 2
    snapshot after
    left=""
    for p in $during; do [ -d "/proc/$p" ] && left="$left $p"; done
    want "no process of the session left" "" "$left"
    want "no listener on the reserved port" 0 "$(ss -ltnH "sport = :$RESERVED" | wc -l)"
    want "the dashboard's port is gone from the sandbox" 0 "$(grep -c '^9119' "$tmp/snapshot-after.txt")"
    want "client refused after the end" error "$(client get "$base" | cut -f2)"
    want "no service.port or record left" "0" "$(ls "$dir/service.port" "$dir/dashboard.json" 2>/dev/null | wc -l)"
    want "the end is audited" 1 "$(grep -c '"dashboard-end"' "$audit")"
    if start_cmd third; then
        want "a run after the end starts" ok "$(client get "$base" | cut -f2)"
        kill -INT "$cmd"
        wait "$cmd"
    else
        want "a run after the end starts" ok "failed: $(tail -1 "$tmp/third.out")"
    fi
else
    want "the command starts" yes "no: $(tail -3 "$tmp/first.out" | tr '\n' ' ')"
fi

{
    echo "# \`enclos dashboard\`, the stand-in ($(uname -m))"
    echo
    echo "dashboard-cmd.py, with Hermes's real dashboard, through the listener at $base. Each row below says what was expected and what was measured."
    section "Verdicts"
    echo "Failed: $(grep -c "$(printf '\tFAIL\t')" "$tmp/verdicts.tsv"); passed: $(grep -c "$(printf '\tpass\t')" "$tmp/verdicts.tsv")"
    echo
    python3 -I "$M3/table.py" "verdict=$tmp/verdicts.tsv"
    section "Page, assets, WebSockets, Host and Origin"
    python3 -I "$M3/table.py" "through the listener=$tmp/path.tsv" "through ssh -L=$tmp/tunnel.tsv"
    section "The terminal"
    python3 -I "$M3/table.py" "through the listener=$tmp/terminal.tsv" "through ssh -L=$tmp/tunnel-terminal.tsv"
    section "The chat, with no account"
    python3 -I "$M3/table.py" "through the listener=$tmp/chat.tsv"
    section "The second user"
    python3 -I "$M3/table.py" "page=$tmp/other-page.tsv"
    python3 -I "$M3/table.py" "/api/pty=$tmp/other-pty.tsv"
    python3 -I "$M3/table.py" "control, a plain server=$tmp/other-control.tsv"
    python3 -I "$M3/table.py" "ssh -L=$tmp/tunnel-other.tsv"
    section "What the listener said"
    grep -E '^(served|refused) ' "$tmp/session.log" | awk '{print $1, $3, $4}' | sort | uniq -c | fence
    section "Before, during and after"
    for s in before during after; do
        echo "### $s"
        echo
        fence <"$tmp/snapshot-$s.txt"
    done
    echo "The session's processes while it ran:"
    fence <"$tmp/processes-during.txt"
    section "The audit"
    fence <"$audit"
    section "The second run's refusal"
    fence <"$tmp/second.out"
    section "status"
    fence <"$tmp/status.txt"
    section "The setup, and ssh"
    { tail -3 "$tmp/setup.log"; cat "$tmp/ssh.log" 2>/dev/null; } | fence
} >"$out"
cat "$out"
