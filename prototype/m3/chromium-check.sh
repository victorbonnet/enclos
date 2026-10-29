#!/bin/bash
# Chromium in the prototype sandbox (design §14, "Hermes on Linux"): does a
# headless Chromium load a page through the relay, with its own sandbox on
# and with it off (`--no-sandbox`)? The sandbox makes no user namespace and
# refuses the namespace calls, so Chromium's own sandbox is expected not to
# start. It uses the Chromium Hermes's installer left in the sandbox's home
# (hermes-check.sh runs first); if there is none, Playwright's, installed in
# the sandbox's home through the relay. Full mode, then without Landlock.
# A proxy in --learn mode on the host. CI only.
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

: >"$tmp/full.tsv"
: >"$tmp/nolandlock.tsv"
if [ -n "$chrome" ]; then
    for mode in full nolandlock; do
        ll=auto
        [ "$mode" = nolandlock ] && ll=off
        for variant in own-sandbox no-sandbox; do
            flags=""
            [ "$variant" = no-sandbox ] && flags="--no-sandbox"
            prof="$SBX_HOME/tmp-chrome-$mode-$variant"
            o=$(SBX_LANDLOCK=$ll SBX_RELAY=1 timeout 120 "$M3/sbx.sh" -- "$chrome" --headless --disable-gpu \
                --no-first-run --user-data-dir="$prof" --proxy-server="http://127.0.0.1:$RELAY_PORT" \
                $flags --dump-dom https://example.com/ 2>"$tmp/$mode-$variant.err")
            st=$?
            title=$(printf '%s' "$o" | grep -o '<title>[^<]*</title>' | head -1)
            why=$(grep -iE 'sandbox|namespace|denied|not permitted|fatal' "$tmp/$mode-$variant.err" \
                | grep -v '^inside:' | head -2 | tr '\t\n' '  ' | cut -c1-160)
            printf '%s\t%s\t%s\n' "chromium $variant" "$([ $st = 0 ] && echo ok || echo "exit $st")" \
                "${title:-no page} $why" >>"$tmp/$mode.tsv"
            rm -rf "$prof"
        done
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
    section "Loading https://example.com/ through the relay"
    python3 -I "$M3/table.py" "full=$tmp/full.tsv" "no Landlock=$tmp/nolandlock.tsv"
    [ -f "$tmp/playwright.log" ] && { section "Playwright's install"; tail -20 "$tmp/playwright.log" | fence; }
} >"$out"
cat "$out"
