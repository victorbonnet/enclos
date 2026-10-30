#!/bin/bash
# Whether the dashboard's Chat tab reaches its backend (M3-03), as a control
# pair in one run. The fifth run's proxy refused `GET http://127.0.0.1:<port>`
# while the terminal was open: the terminal's program, in a session with
# NODE_USE_ENV_PROXY=1 and NO_PROXY empty, seems to send its own backend
# connection to the proxy. So the same round runs twice through the stand-in:
#
#   as-is   the dashboard's session as it is
#   fixed   that session alone with NO_PROXY=127.0.0.1,localhost,::1 and no_proxy
#
# Each round uses the terminal two ways, one at a time: host-client.py types a
# prompt on /api/pty, then a real Chromium on the host (the one Hermes installed)
# opens the Chat tab and types one. The server starts the same terminal program
# for both. Measured from the host: the program's environment, its connection
# to the dashboard's port, the proxy's loopback denials, and every word shown.
#
# Run last by dashboard-cmd-check.sh. Acts on the host: CI only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/76-dashboard-chat.md"
tmp="$RESULTS_DIR/dashboard-chat"
mkdir -p "$tmp"
RESERVED=18961
PROMPT="Reply with exactly one word: ok"
base="http://127.0.0.1:$RESERVED"
log="$tmp/proxy.jsonl"
gui="$SBX_HOME/.hermes/logs/gui.log"
ANSWER='provider|hermes model|/login|not processed|not connected'

python3 -I "$M3/unix-proxy.py" --socket "$PROXY_SOCK" --learn --log "$log" >"$tmp/proxy.out" 2>&1 &
started=($!)
scratch=$(mktemp -d /tmp/enclos-chrome.XXXXXX)  # outside the results: a browser profile
trap 'kill "${started[@]}" 2>/dev/null' EXIT
sleep 1

if [ ! -x "$SBX_HOME/.local/bin/hermes" ]; then
    echo "not run: Hermes is not installed in the sandbox's home" | tee "$out"
    exit 0
fi
chrome=$(find "$SBX_HOME" -type f \( -name chrome -o -name headless_shell -o -name chrome-headless-shell \) \
    -perm -u+x 2>/dev/null | head -1)

: >"$tmp/verdicts.tsv"
: >"$log"
want() {
    local v=FAIL
    [ "$2" = "$3" ] && v=pass
    printf '%s\t%s\texpected: %s; measured: %s\n' "$1" "$v" "$2" "$3" >>"$tmp/verdicts.tsv"
}
lines() { wc -l <"$log"; }
# between FROM TO: the proxy's loopback denials between those log lines.
between() { tail -n +"$(($1 + 1))" "$log" | head -n "$(($2 - $1))" | grep -c blocked-address; }
accepted() { grep -c 'ws accepted' "$gui" 2>/dev/null || true; }
result() { awk -F'\t' -v s="$2" '$1 == s { print $2; exit }' "$1"; }
# after FILE: what a terminal showed after the prompt, without the prompt itself.
after() { sed -n '/^=== after the prompt ===$/,$p' "$1" 2>/dev/null | tail -n +2 | sed "s/$PROMPT//g"; }

# watch_terminal LABEL: while the terminal is used, every 3 s, who holds a
# connection to the dashboard's port, and the terminal program's environment.
watch_terminal() {
    local label=$1 p
    while :; do
        {
            date +%T
            python3 -I "$M3/ns-conns.py" "$hpid" 9119
        } >>"$tmp/$label-connections.txt" 2>&1
        for p in $(python3 -I "$M3/ns-procs.py" descendants "$cmd"); do
            if [ "$(cat "/proc/$p/comm" 2>/dev/null)" != bwrap ]; then
                echo "== $(cat "/proc/$p/comm" 2>/dev/null)"
                tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null \
                    | grep -E '^(NO_PROXY|no_proxy|NODE_USE_ENV_PROXY|HTTP_PROXY|HERMES_TUI_GATEWAY_URL)=' \
                    | sed 's/?.*//'
            fi
        done >>"$tmp/$label-environment-samples.txt" 2>&1
        sleep 3
    done
}

# round LABEL [--no-proxy-loopback]
round() {
    local label=$1 flag=${2:-} w n0 n1 n2 a0 a1 ok="" pids conn answered banswered nobackend
    start_holder C
    dir=$HOLDER
    hpid=$(cat "$dir/pid" 2>/dev/null)
    started+=("$(cat "$dir/bwrap.pid")")
    python3 -I "$M3/dashboard-cmd.py" run --sandbox proto --run "$dir" --port "$RESERVED" \
        --audit "$tmp/audit.jsonl" --log "$tmp/$label-session.log" $flag >"$tmp/$label-cmd.out" 2>&1 &
    cmd=$!
    started+=($cmd)
    for _ in $(seq 300); do
        grep -q '^http://127' "$tmp/$label-cmd.out" && { ok=1; break; }
        [ -d "/proc/$cmd" ] || break
        sleep 1
    done
    if [ -z "$ok" ]; then
        want "$label: the command starts" yes "no: $(tail -2 "$tmp/$label-cmd.out" | tr '\n' ' ')"
        kill "$(cat "$dir/bwrap.pid")" 2>/dev/null
        return
    fi
    sleep 3

    watch_terminal "$label" &
    w=$!
    started+=($w)
    n0=$(lines)
    a0=$(accepted)
    python3 -I "$M3/host-client.py" pty-chat "$base" "$tmp/$label-terminal" --prompt "$PROMPT" \
        >"$tmp/$label-terminal.tsv" 2>&1
    n1=$(lines)
    a1=$(accepted)
    kill "$w" 2>/dev/null
    wait "$w" 2>/dev/null
    sort -u "$tmp/$label-environment-samples.txt" >"$tmp/$label-environment.txt" 2>/dev/null

    if [ -n "$chrome" ]; then
        python3 -I "$M3/browser-chat.py" "$base" "$tmp/$label-browser" "$PROMPT" -- "$chrome" \
            --headless --disable-gpu --no-first-run --no-sandbox --remote-debugging-pipe \
            --user-data-dir="$scratch/$label" about:blank >"$tmp/$label-browser.tsv" 2>"$tmp/$label-browser.err"
    else
        printf 'browser: driving Chromium\tnone\tno Chromium in the sandbox home\n' >"$tmp/$label-browser.tsv"
    fi
    n2=$(lines)
    python3 -I "$M3/host-client.py" chat "$base" >"$tmp/$label-chat.tsv" 2>&1

    # Client ends of the dashboard's port not held by the holder's own relay.
    pids=$(python3 -I "$M3/ns-procs.py" descendants "$(cat "$dir/bwrap.pid")" | tr ' ' '|')
    conn=$(grep -P '^\d+\t' "$tmp/$label-connections.txt" | grep -vE "[[:space:]](${pids:-none}):" | grep -c .)
    answered=$(after "$tmp/$label-terminal.txt" | grep -ciE "$ANSWER")
    banswered=$(after "$tmp/$label-browser.txt" | grep -ciE "$ANSWER")
    nobackend=$(grep -ciE 'reconnect|gateway failed|start timeout|not attached' "$tmp/$label-terminal.txt")
    {
        printf 'loopback denials, the terminal by host-client.py\tmeasured\t%s\n' "$(between "$n0" "$n1")"
        printf 'loopback denials, the Chat tab in Chromium\tmeasured\t%s\n' "$(between "$n1" "$n2")"
        printf 'samples of a sandbox process connected to the port\tmeasured\t%s\n' "$conn"
        printf 'WebSockets the dashboard accepted (gui.log)\tmeasured\t%s\n' "$((a1 - a0))"
        printf 'terminal lines answering after the prompt\tmeasured\t%s\n' "$answered"
        printf 'Chat tab lines answering after the prompt\tmeasured\t%s\n' "$banswered"
        printf 'terminal lines saying it has no backend\tmeasured\t%s\n' "$nobackend"
    } >"$tmp/$label-measures.tsv"

    if [ "$label" = as-is ]; then
        want "as-is: NO_PROXY stays empty in the terminal's program" 0 "$(grep -cE '^NO_PROXY=.' "$tmp/$label-environment.txt")"
    else
        want "fixed: NO_PROXY reaches the terminal's program" yes "$(grep -qE '^NO_PROXY=127' "$tmp/$label-environment.txt" && echo yes || echo no)"
    fi
    want "$label: no loopback denial in the proxy log while the terminal is used" 0 "$(between "$n0" "$n2")"
    want "$label: the Chat tab's backend connection is established" yes "$([ "$conn" -gt 0 ] && echo yes || echo no)"
    want "$label: a prompt typed on /api/pty gets an answer in the terminal" yes "$([ "$answered" -gt 0 ] && echo yes || echo no)"
    want "$label: the page's own terminal socket opens in Chromium" ok "$(result "$tmp/$label-browser.tsv" "browser: the page's terminal socket")"
    want "$label: a prompt typed in the Chat tab gets an answer" yes "$([ "$banswered" -gt 0 ] && echo yes || echo no)"
    want "$label: the chat over /api/ws is accepted" ok "$(result "$tmp/$label-chat.tsv" 'chat: prompt.submit')"

    tail -40 "$gui" 2>/dev/null | sed -E "s#$SBX_HOME#~#g; s/token=[^ &]*/token=<token>/g" | cut -c1-220 \
        >"$tmp/$label-gui-log.txt"
    kill -INT "$cmd"
    wait "$cmd"
    kill "$(cat "$dir/bwrap.pid")" 2>/dev/null
    sleep 2
}

round as-is
round fixed --no-proxy-loopback

as=$(grep -c "^as-is: .*	FAIL	" "$tmp/verdicts.tsv")
fx=$(grep -c "^fixed: .*	FAIL	" "$tmp/verdicts.tsv")
if [ "$as" -gt 0 ] && [ "$fx" = 0 ]; then
    reading="The run shows the failure and the fix: the session's proxy environment is the cause."
elif [ "$as" = 0 ] && [ "$fx" = 0 ]; then
    reading="Both rounds pass: this run does not reproduce the failure, so the fix is not shown to matter."
else
    reading="The fix does not make every row pass: read the rows; NO_PROXY is not the whole cause."
fi

{
    echo "# The dashboard's Chat tab, as it is and with NO_PROXY for loopback ($(uname -m))"
    echo
    echo "**$reading** Failed rows as it is: $as; with the fix: $fx."
    section "Verdicts"
    echo "Each is written as what a working dashboard must do, so the as-is rows are expected to fail if the proxy is the cause."
    echo
    python3 -I "$M3/table.py" "verdict=$tmp/verdicts.tsv"
    section "Measures"
    python3 -I "$M3/table.py" "NO_PROXY empty=$tmp/as-is-measures.tsv" "NO_PROXY for loopback=$tmp/fixed-measures.tsv"
    for label in as-is fixed; do
        section "Round: $label"
        echo "The terminal's program:"
        fence <"$tmp/$label-environment.txt"
        echo "Connections to the dashboard's port, by sample (the last 12 lines):"
        tail -12 "$tmp/$label-connections.txt" | fence
        echo "What stopped the turn, from a chat over /api/ws:"
        echo
        python3 -I "$M3/table.py" "$label=$tmp/$label-chat.tsv"
        echo
        echo "The terminal, by host-client.py:"
        echo
        python3 -I "$M3/table.py" "$label=$tmp/$label-terminal.tsv"
        cut -c1-1500 "$tmp/$label-terminal.txt" 2>/dev/null | fence
        echo "The Chat tab, in Chromium:"
        echo
        python3 -I "$M3/table.py" "$label=$tmp/$label-browser.tsv"
        cut -c1-1500 "$tmp/$label-browser.txt" 2>/dev/null | fence
    done
} >"$out"
cat "$out"
