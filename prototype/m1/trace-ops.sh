#!/bin/bash
# Run a command under (allow default) with every use of one Seatbelt operation
# reported, then print the distinct lines the kernel logged. Used to learn which
# Mach services (or other operations) a tool relies on.
#
#   ./trace-ops.sh mach-lookup -- /usr/bin/security list-keychains
#
# Reads the persisted log afterwards with a capped `log show`; it never streams
# the log to a file (a looping process can log millions of lines and fill the disk).
set -u
op="$1"; shift
[ "${1:-}" = "--" ] && shift
tag="enclos-trace-$$"
start="$(date '+%Y-%m-%d %H:%M:%S')"
sandbox-exec -p "(version 1)(allow default)(allow $op (with report) (with message \"$tag\"))" "$@"
echo "exit status: $?"
sleep 2
/usr/bin/log show --style compact --start "$start" \
    --predicate "(sender == \"Sandbox\" OR subsystem == \"com.apple.sandbox.reporting\") AND eventMessage CONTAINS \"$tag\"" 2>/dev/null \
    | grep 'Sandbox: ' | head -n 2000 | grep -oE "(allow|deny)(\([0-9]+\))? $op [^ \"]+" \
    | sed -E 's/^(allow|deny)(\([0-9]+\))? /\1 /' | sort | uniq -c
