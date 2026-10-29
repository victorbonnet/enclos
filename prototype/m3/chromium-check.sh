#!/bin/bash
# Chromium in the prototype sandbox (design §14, "Hermes on Linux"): does a
# headless Chromium load a page through the relay, with its own sandbox on
# and with it off (`--no-sandbox`)? The sandbox makes no user namespace and
# refuses the namespace calls, so Chromium's own sandbox is expected not to
# start. It uses the Chromium Hermes's installer left in the sandbox's home
# (hermes-check.sh runs first); if there is none, Playwright's, installed in
# the sandbox's home through the relay. On the host as the control, then in
# each sandbox mode. A proxy in --learn mode on the host. CI only.
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

# Each run: one label, the sandbox mode (host = no sandbox, the control,
# going straight out rather than through the relay), Chromium's own sandbox
# on or off. The first CI run had only the last two modes: with its own
# sandbox Chromium aborted, and with it off it loaded the page through the
# relay but never printed it, so these runs tell seccomp, Landlock and
# bubblewrap apart, and show whether the host does the same.
runs=(
    "host|host|off"
    "bwrap|bubblewrap only|off"
    "seccomp|+ seccomp, no Landlock|off"
    "landlock|+ Landlock, no seccomp|off"
    "full|full|off"
    "full-own|full, its own sandbox on|on"
)
: >"$tmp/runs.tsv"
if [ -n "$chrome" ]; then
    for r in "${runs[@]}"; do
        IFS='|' read -r key label own <<<"$r"
        flags=(--headless --disable-gpu --no-first-run --enable-logging=stderr)
        [ "$own" = off ] && flags+=(--no-sandbox)
        prof="$SBX_HOME/tmp-chrome-$key"
        rm -rf "$prof"
        case $key in
            host) pre=() ;;
            bwrap) pre=(env SBX_LANDLOCK=off SBX_SECCOMP=off SBX_RELAY=1 "$M3/sbx.sh" --) ;;
            seccomp) pre=(env SBX_LANDLOCK=off SBX_RELAY=1 "$M3/sbx.sh" --) ;;
            landlock) pre=(env SBX_SECCOMP=off SBX_RELAY=1 "$M3/sbx.sh" --) ;;
            *) pre=(env SBX_RELAY=1 "$M3/sbx.sh" --) ;;
        esac
        [ "$key" = host ] || flags+=(--proxy-server="http://127.0.0.1:$RELAY_PORT")
        start=$(date +%s)
        o=$(timeout 120 "${pre[@]}" "$chrome" "${flags[@]}" --user-data-dir="$prof" \
            --dump-dom https://example.com/ 2>"$tmp/$key.err")
        st=$?
        took=$(( $(date +%s) - start ))
        title=$(printf '%s' "$o" | grep -o '<title>[^<]*</title>' | head -1)
        renderers=$(grep -c 'adjust OOM score of renderer' "$tmp/$key.err")
        why=$(grep -iE 'fatal|crash|signal|seccomp|sandbox|renderer process' "$tmp/$key.err" \
            | grep -v '^inside:' | head -2 | tr '\t\n' '  ' | cut -c1-160)
        printf '%s\t%s\t%s\n' "chromium $label" "$([ $st = 0 ] && echo ok || echo "exit $st")" \
            "${title:-no page}, ${took}s, ${renderers} renderer OOM-score refusals; $why" >>"$tmp/runs.tsv"
        rm -rf "$prof"
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
