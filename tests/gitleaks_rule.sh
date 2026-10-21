#!/bin/sh
# Checks the `home-folder-path` rule of .gitleaks.toml with a real gitleaks:
# each sample below must be reported, or must not be. The samples are
# written to a temporary folder, never to the repository, and the ones that
# must be reported are built from "$U" and "$H" so this file itself passes
# the scan. Usage: tests/gitleaks_rule.sh [path to gitleaks]
set -eu

gitleaks=${1:-gitleaks}
config=$(cd "$(dirname "$0")/.." && pwd)/.gitleaks.toml
tmp=$(mktemp -d)
trap 'rm -f "$tmp/sample.txt"; rmdir "$tmp"' EXIT
U=Users
H=home
failed=0

# $1: "found" or "clean"; $2: the sample line.
check() {
    printf '%s\n' "$2" > "$tmp/sample.txt"
    if (cd "$tmp" && "$gitleaks" dir --no-banner --log-level error \
        --config "$config" --enable-rule home-folder-path sample.txt); then
        got=clean
    else
        got=found
    fi
    if [ "$got" != "$1" ]; then
        echo "expected $1, got $got: $2" >&2
        failed=1
    fi
}

check found "/$U/bob/x"
check found "see /$U/bob/x"
check found "HOME=/$H/bob"
check found "\"/$U/bob.smith\""
check found "(/$H/bob)"
check found "file:///$U/bob/x"
check found "a file:///$H/bob/x"
check found "/System/Volumes/Data/$U/bob/x"

check clean '/Users/alice/x'
check clean 'HOME=/home/alicex'
check clean '/Users/x/y'
check clean 'file:///Users/alice/x'
check clean '/home/runner/work'
check clean '/Users/Shared/x'
check clean 'sandboxes/home/bob'
check clean '~/home/bob'
check clean 'https://example.com/home/bob'
check clean '/Users/$USER'
check clean '/home/<name>'

if [ "$failed" -ne 0 ]; then
    exit 1
fi
echo "home-folder-path: every sample as expected"
