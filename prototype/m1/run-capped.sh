#!/bin/bash
# Run a command inside the sandbox with a time cap, and clean up after it
# without signalling anything found by searching.
#
#   ./run-capped.sh 30 -- hermes gateway run
#
# A small perl leader makes a new process group (pgid = its own pid), ignores
# SIGTERM itself, forks the sandboxed command, and waits. When the command ends
# or the cap is reached, the leader sends SIGTERM to its own process group: the
# command and every descendant that stayed in the group. The group id is valid
# at that moment because the leader is alive, so no other process can be hit.
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
    setpgrp(0, 0);
    $SIG{TERM} = "IGNORE";
    my $secs = shift @ARGV;
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if ($pid == 0) { $SIG{TERM} = "DEFAULT"; exec @ARGV or POSIX::_exit(127); }
    my $capped = 0;
    $SIG{ALRM} = sub { $capped = 1; kill "TERM", -$$; };
    alarm $secs;
    waitpid($pid, 0);
    my $st = $?;
    alarm 0;
    kill "TERM", -$$;   # leftovers that stayed in the group
    sleep 1;
    if ($capped) { print STDERR "run-capped: stopped after ${secs}s\n"; exit 124; }
    exit($st & 127 ? 128 + ($st & 127) : $st >> 8);
' "$secs" "$M1/sbx.sh" -- "$@"
