#!/usr/bin/env bash
# What the organization's boundaries hold, tried from inside each sandbox.
# Exits 1 if any check fails. Each `enclos connect` here is a session: it shows
# in `enclos sandbox show` and the audit log, like any other.

# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

passed=0
failed=0

# expect ok|fail <label> <command...>: run the command, compare with what we expect.
expect() {
    local want=$1 label=$2 got=ok
    shift 2
    "$@" > /dev/null 2>&1 || got=fail
    if [ "$got" = "$want" ]; then
        printf 'PASS  %s\n' "$label"
        passed=$((passed + 1))
    else
        printf 'FAIL  %s (expected to %s, did %s)\n' "$label" "$want" "$got"
        failed=$((failed + 1))
    fi
}

# Open a tunnel to a site from inside a sandbox. Any HTTP answer means the proxy
# allowed it; a refused destination makes curl fail (CONNECT answered 403).
fetch() { in_sandbox "$1" curl -sS -m 20 -o /dev/null "$2"; }
read_file() { in_sandbox "$1" cat "$2"; }

for sandbox in "${SANDBOXES[@]}"; do
    sandbox_exists "$sandbox" || die "sandbox $sandbox does not exist: run setup.sh first"
done

say "Escape probes, from inside each sandbox (every probe must fail)"
for sandbox in "${SANDBOXES[@]}"; do
    if run "$ENCLOS" policy test "$sandbox"; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
    fi
done

say "Sandboxes cannot read each other's files"
for a in "${SANDBOXES[@]}"; do
    for b in "${SANDBOXES[@]}"; do
        [ "$a" = "$b" ] && continue
        expect fail "$a cannot read $b's Hermes configuration" \
            read_file "$a" "$(sandbox_home "$b")/.hermes/config.yaml"
    done
done
expect fail "$COMMUNITY cannot read enclos's state database" read_file "$COMMUNITY" "$ENCLOS_DATA/state.db"
expect fail "$COMMUNITY cannot read enclos's audit log" read_file "$COMMUNITY" "$ENCLOS_DATA/audit.jsonl"

say "Each role reaches only its own services"
expect ok "$MANAGER reaches api.telegram.org" fetch "$MANAGER" https://api.telegram.org/
expect fail "$MANAGER cannot reach api.supabase.com" fetch "$MANAGER" https://api.supabase.com/
expect ok "$DEV reaches api.supabase.com" fetch "$DEV" https://api.supabase.com/
expect fail "$DEV cannot reach api.telegram.org" fetch "$DEV" https://api.telegram.org/
expect ok "$COMMUNITY reaches api.telegram.org" fetch "$COMMUNITY" https://api.telegram.org/
expect fail "$COMMUNITY cannot reach api.supabase.com" fetch "$COMMUNITY" https://api.supabase.com/
if [ -n "${COMMUNITY_MCP_URL:-}" ]; then
    mcp_host="$(url_host "$COMMUNITY_MCP_URL")"
    expect ok "$COMMUNITY reaches the MCP server's host ($mcp_host)" fetch "$COMMUNITY" "https://$mcp_host/"
    expect fail "$MANAGER cannot reach the MCP server's host" fetch "$MANAGER" "https://$mcp_host/"
fi
for sandbox in "${SANDBOXES[@]}"; do
    expect fail "$sandbox cannot reach an unlisted site (example.com)" fetch "$sandbox" https://example.com/
done

say "Known gap: the Hermes adapter allows its install sources in every sandbox (README)"
expect ok "$COMMUNITY reaches api.github.com, granted by the adapter, not by this setup" \
    fetch "$COMMUNITY" https://api.github.com/

say "The audit log"
if run "$ENCLOS" audit verify; then
    passed=$((passed + 1))
else
    failed=$((failed + 1))
fi

say "What each sandbox was refused"
for sandbox in "${SANDBOXES[@]}"; do
    "$ENCLOS" net denied "$sandbox" || true
done

say "Result"
printf '   %d passed, %d failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
