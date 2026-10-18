#!/bin/bash
# Summaries for a prototype step: endpoints the proxy saw and Seatbelt denials.
#   ./report.sh net [since-iso]      distinct host:port and verdict from .work/logs/net.jsonl
#   ./report.sh denials <start>      distinct Seatbelt denials tagged for this sandbox since
#                                    <start> ("YYYY-MM-DD HH:MM:SS"), capped
set -u
source "$(dirname "$0")/env.sh"
case "${1:-}" in
  net)
    since="${2:-}"
    uv run --no-project python -I - "$WORK/logs/net.jsonl" "$since" <<'EOF'
import collections, json, sys
path, since = sys.argv[1], sys.argv[2]
seen = collections.Counter()
for line in open(path):
    e = json.loads(line)
    if since and e.get("at", "") < since:
        continue
    seen[(e.get("host"), e.get("port"), e.get("verdict"), e.get("reason", ""))] += 1
for (host, port, verdict, reason), n in sorted(seen.items(), key=lambda kv: (str(kv[0][0]), kv[0][1] or 0)):
    print(f"{n:5d}  {verdict:6s} {host}:{port} {reason}")
EOF
    ;;
  denials)
    start="$2"
    [ -f "$start" ] && start="$(cat "$start")"   # or a file holding the start time
    /usr/bin/log show --style compact --start "$start" \
        --predicate "(sender == \"Sandbox\" OR subsystem == \"com.apple.sandbox.reporting\") AND eventMessage CONTAINS \"$SBX_TAG\"" 2>/dev/null \
        | grep 'Sandbox: ' | head -n 5000 \
        | sed -E 's/^.*Sandbox: ([^(]+)\([0-9]+\) deny\([0-9]+\) ([a-z*-]+) ([^ "]*).*$/\1 \2 \3/' \
        | sed -E "s#$REAL_HOME#\$HOME#g; s#/var/folders/[^/]+/[^/]+/#/var/folders/../#" \
        | sort | uniq -c | sort -rn | head -n 80
    ;;
  *) echo "usage: report.sh net [since] | denials <start>" >&2; exit 2 ;;
esac
