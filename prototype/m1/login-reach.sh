#!/bin/bash
# How far does Hermes's ChatGPT (openai-codex) device-code login get inside the
# sandbox through the proxy? Starts the login, lets it print the URL and code,
# and stops it at the cap. Nobody approves the code, so it expires unused; the
# code is redacted from the saved output. Endpoints come from the proxy log.
#   ./login-reach.sh [seconds]
# The real login is run by the user: see README.md, "Logging in".
set -u
M1="$(cd "$(dirname "$0")" && pwd -P)"
source "$M1/env.sh"
secs="${1:-30}"
since="$(date '+%Y-%m-%dT%H:%M:%S')"
"$M1/run-capped.sh" "$secs" -- hermes auth add openai-codex --no-browser </dev/null 2>&1 \
    | perl -pe 's/\e\[[0-9;]*m//g; s/(?<![A-Za-z0-9])[A-Z0-9]{4}-[A-Z0-9]{4,6}(?![A-Za-z0-9])/XXXX-XXXXX/g' \
    >"$WORK/logs/login-reach.out"
echo "== login output (code redacted)"
cut -c1-160 "$WORK/logs/login-reach.out" | grep -v '^\s*$' | head -30
echo "== endpoints contacted since $since"
"$M1/report.sh" net "$since"
