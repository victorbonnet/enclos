#!/bin/bash
# Why Chromium's writes to its renderers' oom_score_adj are refused with
# Landlock (design §14). The likely cause is that the /proc rule lacks
# TRUNCATE; this records whether that is so for a shell's write. A redirection
# with `>` opens the file with O_TRUNC, `1<>` does not, and each runs on the
# host as the control, then in the sandbox without Landlock, then with Landlock
# without and with TRUNCATE on the /proc rule. Whether Chromium itself opens
# the file with O_TRUNC is not checked here. Only the shell's own value is
# written. Acts on the host (runs bubblewrap): CI or a guarded disposable VM only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/55-oom.md"
tmp="$RESULTS_DIR/oom"
mkdir -p "$tmp"

writes=(
    "the value now|cat /proc/self/oom_score_adj"
    "echo 0 > (O_TRUNC)|echo 0 > /proc/self/oom_score_adj"
    "echo 0 1<> (no O_TRUNC)|echo 0 1<> /proc/self/oom_score_adj"
)
run() {  # key, then the mode's variables, none on the host
    local key=$1 c o st
    shift
    : >"$tmp/$key.tsv"
    for c in "${writes[@]}"; do
        if [ "$key" = host ]; then
            o=$(/bin/sh -c "${c#*|}" 2>"$tmp/$key.err")
        else
            o=$(env "$@" "$M3/sbx.sh" -- /bin/sh -c "${c#*|}" 2>"$tmp/$key.err")
        fi
        st=$?
        printf '%s\t%s\t%s\n' "${c%%|*}" "$([ $st = 0 ] && echo ok || echo "exit $st")" \
            "$(printf '%s %s' "$o" "$(grep -v '^inside:' "$tmp/$key.err" | tail -1)" | tr '\t\n' '  ' | cut -c1-120)" \
            >>"$tmp/$key.tsv"
    done
}
run host
run nolandlock SBX_LANDLOCK=off
run without SBX_PROC_TRUNCATE=0
run with SBX_PROC_TRUNCATE=1

{
    echo "# OOM-score writes under Landlock ($(uname -m))"
    section "What inside.py applied"
    for key in nolandlock without with; do
        echo "- $key: $(grep -h '^inside:' "$tmp/$key.err" | tr '\n' ' ')"
    done
    section "Writes to /proc/self/oom_score_adj"
    echo "Going below the value a process starts with takes a privilege the job lacks, so if the first row is not 0, read a refusal against the host and no-Landlock columns."
    echo
    python3 -I "$M3/table.py" "host=$tmp/host.tsv" "no Landlock=$tmp/nolandlock.tsv" \
        "Landlock, /proc without TRUNCATE=$tmp/without.tsv" "Landlock, /proc with TRUNCATE=$tmp/with.tsv"
} >"$out"
cat "$out"
