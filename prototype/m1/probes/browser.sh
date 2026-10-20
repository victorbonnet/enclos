#!/bin/bash
# Does the headless browser Hermes installed run inside Seatbelt, through the
# proxy, and does it need its own sandbox disabled? Chrome for Testing with
# --dump-dom loads one page and exits; no debugging port is opened. Each run
# gets a fresh profile directory under the sandbox home and is capped.
set -u
M1="$(cd "$(dirname "$0")/.." && pwd -P)"
source "$M1/env.sh"
CHROME="$(ls -d "$SBX_HOME"/.hermes/tools/chromium-*/chrome-mac-*/"Google Chrome for Testing.app"/Contents/MacOS/"Google Chrome for Testing" | head -1)"
URL="${1:-https://example.com/}"
run() {  # label, extra flags...
    local label="$1"; shift
    local prof="$SBX_HOME/tmp/chrome-probe-$label"
    rm -rf "$prof"
    out=$("$M1/run-capped.sh" 60 -- "$CHROME" --headless=new --disable-gpu --no-first-run \
        --user-data-dir="$prof" --proxy-server="http://127.0.0.1:$PROXY_PORT" "$@" \
        --dump-dom "$URL" 2>"$WORK/logs/chrome-$label.err"); st=$?
    title=$(echo "$out" | grep -o '<title>[^<]*</title>' | head -1)
    printf '%-14s status %-4s %s\n' "$label" "$st" "${title:-no page}"
    grep -iE 'sandbox|denied|not permitted|FATAL' "$WORK/logs/chrome-$label.err" | head -4 | cut -c1-200
    rm -rf "$prof"
}
run chrome-sandbox
run no-sandbox --no-sandbox
