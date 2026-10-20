#!/bin/bash
# Member tracking on macOS (design §8, ADR 0019). Starts two sandboxes (two
# tags, so two different member markers). In sandbox A the session starts a
# normal child, a nohup child, and an "escaper" that double-forks and calls
# setsid (new session and process group, parent becomes launchd). Then, from
# outside, it finds A's members three ways and compares:
#   pgid    processes in the session's process group (set up by the launcher)
#   parent  descendants of the launcher by parent chain
#   marker  every process of this user for which sandbox_check says the
#           marker path of A is denied (sb/90-member-marker.sb)
# DISABLED. Its one run showed the process group misses the setsid escaper and
# that the marker check is useless (sandbox_check on another pid returned 1 for
# every process). That run also sent SIGTERM to the marker list, which was most
# of the user's processes. Member-tracking experiments now run only in a
# disposable macOS VM, and never signal a list of processes found by searching.
set -u
echo "members.sh is disabled: its marker check is refuted (see the WARNING below)." >&2
exit 1
source "$(dirname "$0")/env.sh"

members_by_marker() {  # tag -> pids
    local marker="/private/var/empty/enclos-member-$1" pid
    for pid in $(ps -U "$(id -u)" -o pid=); do
        "$PROBE" check "$pid" file-read-data "$marker" >/dev/null 2>&1 || echo "$pid"
    done
}
descendants() {  # pid -> pid and all descendants by parent chain
    local all; all=$(ps -A -o pid=,ppid=)
    local queue=("$1") out=() p
    while [ ${#queue[@]} -gt 0 ]; do
        p=${queue[0]}; queue=("${queue[@]:1}"); out+=("$p")
        for c in $(awk -v p="$p" '$2 == p {print $1}' <<<"$all"); do queue+=("$c"); done
    done
    printf '%s\n' "${out[@]}"
}
show() { for p in "$@"; do ps -o pid=,ppid=,pgid=,sess=,command= -p "$p" 2>/dev/null | cut -c1-90; done; }

SESSION='sleep 300 & nohup sleep 301 >/dev/null 2>&1 &
perl -MPOSIX -e "fork and exit; POSIX::setsid(); exec q(sleep), 302" &
wait'

# Launcher: its own process group (what `enclos launch` would do), then the sandbox.
perl -e 'setpgrp(0, 0); exec @ARGV' ./sbx.sh -- /bin/sh -c "$SESSION" &
launcher=$!
SBX_TAG=enclos-sbx-other SBX_HOME="$WORK/home-other" ./sbx.sh -- /bin/sleep 303 &
other=$!
sleep 1.5

pg=$(ps -o pgid= -p "$launcher" | tr -d ' ')
by_pgid=$(ps -A -o pid=,pgid= | awk -v g="$pg" '$2 == g {print $1}' | sort -n)
by_parent=$(descendants "$launcher" | sort -n)
by_marker=$(members_by_marker "$SBX_TAG" | sort -n)
other_marker=$(members_by_marker enclos-sbx-other | sort -n)

echo "== sandbox A members by process group $pg"; show $by_pgid
echo "== by parent chain from launcher $launcher"; show $by_parent
echo "== by marker (sandbox_check)"; show $by_marker
echo "== sandbox B members by its own marker"; show $other_marker
echo "== found by marker but not by process group:"; show $(comm -13 <(echo "$by_pgid") <(echo "$by_marker"))

# WARNING: the marker check is NOT validated. On macOS 26.5 sandbox_check on
# another pid returned 1 for every process tried, sandboxed or not (including
# launchd), so "by marker" lists unrelated host processes. Never signal the
# marker list. An earlier version of this script did, and sent SIGTERM to most
# of the user's processes. Only the launcher's process group is signalled here.
echo "== stop A: SIGTERM to the launcher's process group only"
kill -TERM -"$pg" 2>/dev/null
kill -TERM "$other" 2>/dev/null
sleep 0.5
echo "sandbox A processes left in process group $pg:"
ps -A -o pid=,pgid= | awk -v g="$pg" '$2 == g {print $1}'
echo "the setsid escaper is not in the group; find it by command line and stop it by pid"
wait 2>/dev/null
