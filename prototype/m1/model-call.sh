#!/bin/bash
# One model call through Hermes inside the sandbox, after the user's login.
#   ./model-call.sh <label> [profile] [prompt...]
# Runs `hermes [-p profile] -z <prompt>` with the ChatGPT (openai-codex)
# provider, capped. Prints the answer (token-like strings redacted), the
# endpoints the proxy saw since the start, and the size and mtime of each
# auth.json (never its contents). Each run is a separate sbx.sh invocation.
set -u
M1="$(cd "$(dirname "$0")" && pwd -P)"
source "$M1/env.sh"
label="$1"; profile="${2:-}"; shift $(( $# >= 2 ? 2 : 1 ))
prompt="${*:-Reply with exactly one word: ok}"
# Hermes's built-in defaults (gpt-5.4-mini, gpt-5.5) were refused with HTTP 400
# for the prototype's ChatGPT account; gpt-5.6-luna worked. For another
# account, list its models with probes/codex-models.py and set HERMES_MODEL.
model="${HERMES_MODEL:-gpt-5.6-luna}"
secs="${CAP_SECS:-180}"
pflag=(); [ -n "$profile" ] && [ "$profile" != default ] && pflag=(-p "$profile")
redact() { perl -pe 's/\e\[[0-9;]*m//g; s/eyJ[A-Za-z0-9_-]{10,}(\.[A-Za-z0-9_-]+)*/<redacted-jwt>/g; s/\b(sk|rt|sess)-[A-Za-z0-9_-]{16,}/<redacted-token>/g'; }
authmeta() {
    for f in "$SBX_HOME/.hermes/auth.json" "$SBX_HOME"/.hermes/profiles/*/auth.json; do
        [ -f "$f" ] && stat -f '  %N size=%z mtime=%Sm' -t '%H:%M:%S' "$f" | sed "s#$SBX_HOME#\$SBX_HOME#"
    done
}
echo "== $label: auth.json before"; authmeta
since="$(date '+%Y-%m-%dT%H:%M:%S')"
out="$WORK/logs/model-$label.out"
extra=(); [ -n "${HERMES_TOOLSETS:-}" ] && extra=(-t "$HERMES_TOOLSETS")
"$M1/run-capped.sh" "$secs" -- hermes ${pflag[@]+"${pflag[@]}"} ${extra[@]+"${extra[@]}"} -z "$prompt" \
    --provider openai-codex -m "$model" </dev/null 2>&1 | redact >"$out"
echo "== $label: exit ${PIPESTATUS[0]}, answer (last 25 lines)"
tail -n 25 "$out" | cut -c1-200
echo "== $label: auth.json after"; authmeta
echo "== $label: endpoints since $since"
"$M1/report.sh" net "$since"
