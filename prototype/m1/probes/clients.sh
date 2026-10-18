#!/bin/bash
# Do the usual clients work through the proxy with DNS denied? Each client makes
# one HTTPS request from inside the sandbox under the full compiled policy
# (mDNSResponder socket, DNS-SD Mach service and port 53 all denied), so the
# only way out is HTTPS_PROXY. Run after the Hermes install, which provides
# uv, Python, Node and npm in the sandbox home. Read-only requests only.
set -u
M1="$(cd "$(dirname "$0")/.." && pwd -P)"
source "$M1/env.sh"
H="$SBX_HOME/.hermes"
# Tools Hermes installed (located inside the sandbox home only).
UV="$(ls -d "$H"/tools/uv-*/uv 2>/dev/null | head -1)"
NODE="$(find "$H" -path '*/bin/node' -type f -perm -u+x 2>/dev/null | head -1)"
NPM="$(dirname "${NODE:-/x}")/npm"
VPY="$(ls "$H"/installs/*/environments/*/venv/bin/python 2>/dev/null | head -1)"

check() {  # label, command...
    local label="$1"; shift
    out=$("$M1/run-capped.sh" 60 -- "$@" 2>&1); st=$?
    printf '%-26s %-6s %s\n' "$label" "$([ $st = 0 ] && echo ok || echo FAIL)" "$(echo "$out" | tail -1 | cut -c1-90)"
}

echo "uv=${UV#$SBX_HOME/} node=${NODE#$SBX_HOME/} venv-python=${VPY#$SBX_HOME/}"
check "dns: getaddrinfo (denied)" "${VPY:-python3}" -I -c 'import socket; socket.getaddrinfo("pypi.org", 443)'
check "curl" curl -sS -o /dev/null -w '%{http_code}' https://pypi.org/simple/
check "python urllib" "${VPY:-python3}" -I -c 'import urllib.request as u; print(u.urlopen("https://pypi.org/simple/", timeout=30).status)'
[ -n "$VPY" ] && check "python httpx (hermes venv)" "$VPY" -I -c 'import httpx; print(httpx.get("https://pypi.org/simple/", timeout=30).status_code)'
[ -n "$VPY" ] && check "python requests (venv)" "$VPY" -I -c 'import requests; print(requests.get("https://pypi.org/simple/", timeout=30).status_code)'
[ -n "$UV" ] && check "uv pip compile" /bin/sh -c "echo idna | '$UV' pip compile --no-config --no-header -q - "
check "git ls-remote" /usr/bin/git ls-remote https://github.com/NousResearch/hermes-agent.git HEAD
if [ -n "$NODE" ]; then
    check "node fetch (env proxy)" "$NODE" -e 'fetch("https://registry.npmjs.org/").then(r => console.log(r.status), e => { console.log(String(e.cause || e)); process.exit(1) })'
    check "node https.get" "$NODE" -e 'require("https").get("https://registry.npmjs.org/", r => console.log(r.statusCode)).on("error", e => { console.log(String(e)); process.exit(1) })'
    check "npm view" /usr/bin/env PATH="$(dirname "$NODE"):/usr/bin:/bin" "$NPM" view left-pad version --loglevel=error
fi
