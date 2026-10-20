#!/bin/bash
# Run a command inside the sandbox with a time cap, and clean up after it
# without signalling anything found by searching.
#
#   ./run-capped.sh 30 -- hermes gateway run
#
# A small perl leader makes a new process group (pgid = its own pid), ignores
# SIGTERM itself, forks the sandboxed command, and polls it. When the cap is
# reached, the leader sends SIGTERM to its own process group: the command and
# every descendant that stayed in the group. Whatever is still there after a
# grace period (GRACE_SECS, default 3) gets SIGKILL: the leader first moves
# itself back to the group it came from, so it survives, then kills the group
# by its id. The id stays valid throughout because the leader, whose pid it
# is, is alive, so no other process can be hit. The same TERM, grace, KILL
# ends what stays in the group after the command exits on its own.
# Descendants that left the group (setsid) are listed by the caller afterwards
# and left alone; they are reported, never signalled.
#
# Exit status: the command's, or 124 when the cap was reached.
set -u
M1="$(cd "$(dirname "$0")" && pwd -P)"
secs="$1"; shift
[ "${1:-}" = "--" ] && shift
exec perl -e '
    use POSIX ();
    use Time::HiRes qw(time sleep);
    my $outer = getpgrp();
    setpgrp(0, 0);
    $SIG{TERM} = "IGNORE";
    my ($secs, $grace) = (shift @ARGV, shift @ARGV);
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) { $SIG{TERM} = "DEFAULT"; exec @ARGV or POSIX::_exit(127); }

    # SIGKILL to the group cannot be ignored, so the leader first moves back
    # to the group it came from. Its pid, the group id, stays its own.
    my $left = 0;
    my $kill_group = sub {
        POSIX::setpgid(0, $outer) unless $left++;
        kill "KILL", -$$;
    };

    my ($capped, $killed, $st, $term_at) = (0, 0);
    my $start = time;
    while (1) {
        if (waitpid($pid, POSIX::WNOHANG()) == $pid) { $st = $?; last; }
        my $now = time;
        if (!$capped && $now - $start >= $secs) {
            $capped = 1; $term_at = $now; kill "TERM", -$$;
        } elsif ($capped && !$killed && $now - $term_at >= $grace) {
            $killed = 1; $kill_group->();
        }
        sleep 0.1;
    }
    # Leftovers that stayed in the group: TERM, a second, then KILL.
    kill "TERM", -$$ unless $left;
    sleep 1;
    $kill_group->();
    if ($capped) {
        my $how = $killed ? ", killed after a ${grace}s grace period" : "";
        print STDERR "run-capped: stopped after ${secs}s$how\n";
        exit 124;
    }
    exit($st & 127 ? 128 + ($st & 127) : $st >> 8);
' "$secs" "${GRACE_SECS:-3}" "$M1/sbx.sh" -- "$@"
