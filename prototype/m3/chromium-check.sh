#!/bin/bash
# Chromium in the prototype sandbox (design §14, "Hermes on Linux"): does a
# headless Chromium load a page through the relay, with its own sandbox on
# and with it off (`--no-sandbox`)? The sandbox makes no user namespace and
# refuses the namespace calls, so Chromium's own sandbox is expected not to
# start. It uses the Chromium Hermes's installer left in the sandbox's home
# (hermes-check.sh runs first); if there is none, Playwright's, installed in
# the sandbox's home through the relay. On the host as the control, then in
# each sandbox mode, driven over the DevTools protocol (cdp-load.py). A proxy in --learn mode on the host. CI only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/50-chromium.md"
tmp="$RESULTS_DIR/chromium"
mkdir -p "$tmp"

python3 -I "$M3/unix-proxy.py" --socket "$PROXY_SOCK" --learn --log "$tmp/proxy.jsonl" \
    >"$tmp/proxy.out" 2>&1 &
proxy=$!
trap 'kill "$proxy" 2>/dev/null' EXIT
sleep 1

find_chrome() {
    find "$SBX_HOME" -type f \( -name chrome -o -name headless_shell -o -name chrome-headless-shell \) \
        -perm -u+x 2>/dev/null | head -1
}
chrome=$(find_chrome)
source_of="Hermes's installer"
if [ -z "$chrome" ]; then
    source_of="Playwright (npx playwright install chromium), Hermes's installer left none"
    SBX_RELAY=1 timeout 900 "$M3/sbx.sh" -- /bin/sh -c \
        'PLAYWRIGHT_BROWSERS_PATH=$HOME/.cache/ms-playwright npx -y playwright install chromium' \
        >"$tmp/playwright.log" 2>&1
    chrome=$(find_chrome)
fi

# Two ways to load the page. `--dump-dom` is what the first two runs used;
# in the second (PR #113) it never returned within 120 s on the host either,
# so it says nothing about the sandbox, and it is kept only on the host and
# in full mode, for comparison. cdp-load.py drives Chromium over the
# DevTools protocol on a pipe, as Hermes's browser tool and Playwright do,
# and waits for the page's load event: that runs in every mode. Each run:
# key, label, the sandbox mode's prefix, Chromium's own sandbox on or off.
# The host goes straight out; the sandbox modes through the relay.
prefix() {
    case $1 in
        host) pre=() ;;
        bwrap) pre=(env SBX_LANDLOCK=off SBX_SECCOMP=off SBX_RELAY=1 "$M3/sbx.sh" --) ;;
        seccomp) pre=(env SBX_LANDLOCK=off SBX_RELAY=1 "$M3/sbx.sh" --) ;;
        landlock) pre=(env SBX_SECCOMP=off SBX_RELAY=1 "$M3/sbx.sh" --) ;;
        *) pre=(env SBX_RELAY=1 "$M3/sbx.sh" --) ;;
    esac
}
row() {  # label, status, took, err file, detail
    local renderers why
    renderers=$(grep -c 'adjust OOM score of renderer' "$4")
    why=$(grep -iE 'fatal|crash|signal|seccomp|sandbox|renderer process' "$4" \
        | grep -v '^inside:' | head -2 | tr '\t\n' '  ' | cut -c1-160)
    printf '%s\t%s\t%s\n' "$1" "$([ "$2" = 0 ] && echo ok || echo "exit $2")" \
        "$5, ${3}s, ${renderers} renderer OOM-score refusals; $why" >>"$tmp/runs.tsv"
}
: >"$tmp/runs.tsv"
if [ -n "$chrome" ]; then
    base=(--headless --disable-gpu --no-first-run --enable-logging=stderr)
    for r in "host|host" "bwrap|bubblewrap only" "seccomp|+ seccomp, no Landlock" \
        "landlock|+ Landlock, no seccomp" "full|full"; do
        IFS='|' read -r key label <<<"$r"
        prefix "$key"
        flags=("${base[@]}" --no-sandbox --remote-debugging-pipe --user-data-dir="$SBX_HOME/tmp-chrome-cdp-$key")
        [ "$key" = host ] || flags+=(--proxy-server="http://127.0.0.1:$RELAY_PORT")
        rm -rf "$SBX_HOME/tmp-chrome-cdp-$key"
        start=$(date +%s)
        o=$(timeout 150 python3 -I "$M3/cdp-load.py" https://example.com/ 90 -- \
            "${pre[@]}" "$chrome" "${flags[@]}" about:blank 2>"$tmp/cdp-$key.err")
        st=$?
        row "DevTools protocol, $label" "$st" "$(( $(date +%s) - start ))" "$tmp/cdp-$key.err" "$o"
        rm -rf "$SBX_HOME/tmp-chrome-cdp-$key"
    done
    for r in "host|host|off" "full|full|off" "full-own|full, its own sandbox on|on"; do
        IFS='|' read -r key label own <<<"$r"
        prefix "$key"
        flags=("${base[@]}" --user-data-dir="$SBX_HOME/tmp-chrome-$key")
        [ "$own" = off ] && flags+=(--no-sandbox)
        [ "$key" = host ] || flags+=(--proxy-server="http://127.0.0.1:$RELAY_PORT")
        rm -rf "$SBX_HOME/tmp-chrome-$key"
        start=$(date +%s)
        o=$(timeout 120 "${pre[@]}" "$chrome" "${flags[@]}" --dump-dom https://example.com/ 2>"$tmp/$key.err")
        st=$?
        title=$(printf '%s' "$o" | grep -o '<title>[^<]*</title>' | head -1)
        row "--dump-dom, $label" "$st" "$(( $(date +%s) - start ))" "$tmp/$key.err" "${title:-no page}"
        rm -rf "$SBX_HOME/tmp-chrome-$key"
    done
fi

{
    echo "# Chromium in the sandbox ($(uname -m))"
    section "Which Chromium"
    {
        echo "binary: ${chrome:-none found}" | sed "s|$SBX_HOME|~|"
        echo "from: $source_of"
        [ -n "$chrome" ] && "$M3/sbx.sh" -- "$chrome" --version 2>&1 | grep -v '^inside:'
    } | fence
    section "Loading https://example.com/ (the sandbox modes through the relay, the host straight out)"
    python3 -I "$M3/table.py" "result=$tmp/runs.tsv"
    [ -f "$tmp/playwright.log" ] && { section "Playwright's install"; tail -20 "$tmp/playwright.log" | fence; }
} >"$out"
cat "$out"
