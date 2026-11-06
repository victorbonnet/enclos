#!/bin/bash
# Hermes's installer in the prototype sandbox on Linux (design §14, "Hermes
# on Linux"), in full mode, through the relay and a proxy in --learn mode,
# which allows any public destination and logs it: which endpoints the
# installer reaches, whether it asks for sudo or system packages, and
# whether `hermes` then runs. The installer is downloaded inside the sandbox
# and its SHA-256 recorded, as it is whatever the endpoint serves that day.
#
# The device-code login and a model call need an account, so they are not
# here: README.md gives them as manual steps for a VM. CI only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/40-hermes.md"
tmp="$RESULTS_DIR/hermes"
mkdir -p "$tmp"
installer_url="https://hermes-agent.nousresearch.com/install.sh"  # src/runtime/hermes.rs

python3 -I "$M3/unix-proxy.py" --socket "$PROXY_SOCK" --learn --log "$tmp/proxy.jsonl" \
    >"$tmp/proxy.out" 2>&1 &
proxy=$!
trap 'kill "$proxy" 2>/dev/null' EXIT
sleep 1

in_sbx() { SBX_RELAY=1 "$M3/sbx.sh" -- /bin/bash -c "$1"; }

in_sbx "mkdir -p ~/dl && curl -fsSL -o ~/dl/install.sh '$installer_url'" >"$tmp/download.log" 2>&1
dl=$?
sha=$(sha256sum "$SBX_HOME/dl/install.sh" 2>/dev/null | cut -d' ' -f1)
start=$(date +%s)
SBX_RELAY=1 timeout 2400 "$M3/sbx.sh" -- /bin/bash "$SBX_HOME/dl/install.sh" \
    --non-interactive --skip-computer-use </dev/null >"$tmp/install.log" 2>&1
st=$?
took=$(( $(date +%s) - start ))
in_sbx 'export PATH="$HOME/.local/bin:$PATH"; command -v hermes; hermes --version' >"$tmp/version.log" 2>&1
vst=$?

{
    echo "# Hermes's installer in the sandbox ($(uname -m))"
    section "Run"
    {
        echo "download: exit $dl"
        echo "installer sha256: ${sha:-none}"
        echo "install: exit $st after ${took}s (cap 2400s)"
        echo "hermes --version: exit $vst"
        grep -h '^inside:' "$tmp/install.log" | sort -u
    } | fence
    section "hermes --version"
    grep -v '^inside:' "$tmp/version.log" | tail -20 | fence
    section "Endpoints the proxy saw (host:port verdict)"
    python3 -I "$M3/proxy-summary.py" "$tmp/proxy.jsonl"
    section "Lines of the install log naming sudo, apt or a refusal"
    grep -inE 'sudo|apt(-get)?|permission denied|read-only|operation not permitted|not found' "$tmp/install.log" \
        | head -60 | cut -c1-200 | fence
    section "The install log's last 60 lines"
    tail -60 "$tmp/install.log" | cut -c1-200 | fence
    section "What the install left in the sandbox's home (top two levels, sizes)"
    du -h --max-depth=2 "$SBX_HOME" 2>/dev/null | sort -h | tail -30 | sed "s|$SBX_HOME|~|" | fence
} >"$out"
cat "$out"
