#!/bin/sh
# Checks survey.sh, which is read-only, so this is safe on any host. busctl is
# stubbed on the PATH.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -f "$tmp/busctl"; rmdir "$tmp"' EXIT
failed=0

# $1: the stub's body; $2: the line survey.sh must print.
expect() {
    printf '#!/bin/sh\n%s\n' "$1" >"$tmp/busctl"
    chmod +x "$tmp/busctl"
    if ! PATH="$tmp:$PATH" sh "$here/survey.sh" | grep -qx -- "$2"; then
        echo "expected the line: $2" >&2
        failed=1
    fi
}

expect 'exit 0' 'seccomp\.actions_avail: .*'
expect 'exit 0' 'seccomp\.self_mode: .*'
expect 'exit 0' 'seccomp\.self_filters: .*'
expect 'exit 0' 'kconfig\.SECCOMP: .*'
expect 'exit 0' 'kconfig\.SECCOMP_FILTER: .*'

# bwrap-check.sh must refuse here, before it runs anything
if env -u GITHUB_ACTIONS -u RUNNER_ENVIRONMENT sh "$here/bwrap-check.sh" 2>/dev/null; then
    echo "bwrap-check.sh ran outside a GitHub-hosted runner" >&2
    failed=1
fi

exit "$failed"
