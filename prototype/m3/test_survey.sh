#!/bin/sh
# Checks survey.sh, which is read-only, so this is safe on any host. busctl is
# stubbed on the PATH. SIGPIPE is ignored, as on the runners, so a reader that
# leaves early shows as errors from survey.sh.
set -eu
trap '' PIPE

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -f "$tmp/busctl" "$tmp/stderr"; rmdir "$tmp"' EXIT
failed=0

# $1: the stub's body; $2: the line survey.sh must print.
expect() {
    printf '#!/bin/sh\n%s\n' "$1" >"$tmp/busctl"
    chmod +x "$tmp/busctl"
    if ! PATH="$tmp:$PATH" sh "$here/survey.sh" 2>"$tmp/stderr" | grep -x -- "$2" >/dev/null; then
        echo "expected the line: $2" >&2
        failed=1
    fi
    if grep -q 'I/O error' "$tmp/stderr"; then
        echo "survey.sh's output was cut off while looking for: $2" >&2
        failed=1
    fi
}

expect 'exit 0' 'seccomp\.actions_avail: .*'
expect 'exit 0' 'seccomp\.self_mode: .*'
expect 'exit 0' 'seccomp\.self_filters: .*'
expect 'exit 0' 'kconfig\.SECCOMP: .*'
expect 'exit 0' 'kconfig\.SECCOMP_FILTER: .*'

# lp(): logind's answer, and `unknown` when it cannot be asked
expect 'echo "b false"' 'logind\.KillUserProcesses: false'
expect 'echo "t 10000000"' 'logind\.UserStopDelayUSec: 10000000'
expect 'exit 1' 'logind\.KillUserProcesses: unknown'
expect 'exit 1' 'logind\.UserStopDelayUSec: unknown'

# Both scripts that act on the host must refuse here, before they run anything.
# The guard's status and its message together: dash also exits 2 on a syntax error.
refuses() {
    status=0
    out=$(env -u GITHUB_ACTIONS -u RUNNER_ENVIRONMENT sh "$here/$1" 2>&1) || status=$?
    if [ "$status" -ne 2 ] || [ "$out" != "$1 runs only on a GitHub-hosted runner (it changes host settings)" ]; then
        echo "$1 did not refuse outside a GitHub-hosted runner: exit $status: $out" >&2
        failed=1
    fi
}

refuses bwrap-check.sh
refuses logout-check.sh

exit "$failed"
