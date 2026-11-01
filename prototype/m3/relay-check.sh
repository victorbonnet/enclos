#!/bin/bash
# The relay (design §5, Linux networking; §14): in the sandbox's own network
# namespace, with no DNS, do the usual clients reach the proxy through the
# relay on 127.0.0.1, and is a destination the policy does not list refused?
# The proxy runs on the host on the sandbox's Unix socket, with an
# allowlist; the clients run in the sandbox in full mode, then in the mode
# without Landlock (ADR 0037). Python's httpx, requests and uv are installed
# by pip into a virtual environment in the sandbox's home, through the relay.
# CI only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/30-relay.md"
tmp="$RESULTS_DIR/relay"
mkdir -p "$tmp"

allow="$tmp/allow.txt"
cat >"$allow" <<'EOF'
pypi.org
files.pythonhosted.org
github.com
registry.npmjs.org
example.com
EOF
python3 -I "$M3/unix-proxy.py" --socket "$PROXY_SOCK" --allow "$allow" --log "$tmp/proxy.jsonl" \
    >"$tmp/proxy.out" 2>&1 &
proxy=$!
trap 'kill "$proxy" 2>/dev/null' EXIT
sleep 1

venv="$SBX_HOME/venv"
# Each client: one label, then a shell command run in the sandbox.
clients=(
    "dns: getaddrinfo (no DNS expected)|python3 -I -c 'import socket; socket.getaddrinfo(\"pypi.org\", 443)'"
    "curl|curl -sS -o /dev/null -w '%{http_code}' https://pypi.org/simple/"
    "curl, a destination not allowed|curl -sS -o /dev/null -w '%{http_code}' https://example.org/"
    "python urllib|python3 -I -c 'import urllib.request as u; print(u.urlopen(\"https://pypi.org/simple/\", timeout=30).status)'"
    "pip install into a venv|python3 -m venv $venv && $venv/bin/pip install -q httpx requests uv && echo installed"
    "python httpx|$venv/bin/python -I -c 'import httpx; print(httpx.get(\"https://pypi.org/simple/\", timeout=30).status_code)'"
    "python requests|$venv/bin/python -I -c 'import requests; print(requests.get(\"https://pypi.org/simple/\", timeout=30).status_code)'"
    "uv pip compile|echo idna | $venv/bin/uv pip compile --no-config --no-header -q -"
    "git ls-remote|git ls-remote https://github.com/NousResearch/hermes-agent.git HEAD"
    "node fetch (NODE_USE_ENV_PROXY)|node -e 'fetch(\"https://registry.npmjs.org/\").then(r => console.log(r.status), e => { console.log(String(e.cause || e)); process.exit(1) })'"
    "npm view|npm view left-pad version --loglevel=error"
)

for mode in full nolandlock; do
    ll=auto
    [ "$mode" = nolandlock ] && ll=off
    : >"$tmp/$mode.tsv"
    for c in "${clients[@]}"; do
        label=${c%%|*}
        cmd=${c#*|}
        o=$(SBX_LANDLOCK=$ll SBX_RELAY=1 timeout 300 "$M3/sbx.sh" -- /bin/sh -c "$cmd" 2>"$tmp/$mode.err")
        st=$?
        printf '%s\t%s\t%s\n' "$label" "$([ $st = 0 ] && echo ok || echo "exit $st")" \
            "$(printf '%s %s' "$o" "$(grep -v '^inside:' "$tmp/$mode.err" | tail -1)" | tr '\t\n' '  ' | cut -c1-120)" \
            >>"$tmp/$mode.tsv"
    done
done

{
    echo "# The relay ($(uname -m))"
    section "Clients through the relay"
    python3 -I "$M3/table.py" "full=$tmp/full.tsv" "no Landlock=$tmp/nolandlock.tsv"
    section "What the proxy logged (host, verdict, reason)"
    python3 -I "$M3/proxy-summary.py" "$tmp/proxy.jsonl"
} >"$out"
cat "$out"
