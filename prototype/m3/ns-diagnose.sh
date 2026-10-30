#!/bin/bash
# What refused the first run's joins (M3-03): `nsenter` entering the holder's
# network namespace and bubblewrap's `--pidns`, both EPERM on the runners.
# With AppArmor's restriction on unprivileged user namespaces on (as the
# runners are, with setup-runner.sh's profile for /usr/bin/bwrap), then off,
# then on again, it records:
#
#   - the AppArmor state: the restriction's sysctl, the profiles naming
#     bwrap, nsenter or user namespaces, and the job's label;
#   - ns-diag.py: each setns in turn, with the label and capabilities after
#     each step, user namespace first, then network first as a control;
#   - nsenter's and bubblewrap's joins, as nsjoin.py's ways run them, under
#     strace (setns, unshare, clone, clone3 and their errors);
#   - the kernel's AppArmor messages (dmesg, the journal) since the start.
#
# It turns the restriction off only for its own steps and restores it, also
# on exit. Acts on the host (sysctl, bubblewrap, namespaces): CI only.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/55-ns-diagnosis.md"
tmp="$RESULTS_DIR/ns-diagnosis"
mkdir -p "$tmp"
sudo apt-get install -y -qq strace >/dev/null 2>&1
sysctl_name=kernel.apparmor_restrict_unprivileged_userns
initial=$(sysctl -n "$sysctl_name" 2>/dev/null || echo absent)
started=()
restore() {
    kill "${started[@]}" 2>/dev/null
    [ "$initial" = absent ] || sudo sysctl -qw "$sysctl_name=$initial"
}
trap restore EXIT
since=$(date '+%Y-%m-%d %H:%M:%S')

compile_policy

# join WAY: the command nsjoin.py gives for WAY, running `true` inside, with
# no Landlock or seccomp, so only the join is tried.
join() {
    python3 -I "$M3/nsjoin.py" --compiled "$SBX_COMPILED/compiled.json" --join "$1" -- \
        /usr/bin/python3 -I "$M3/inside.py" --compiled "$SBX_COMPILED/compiled.json" \
        --landlock off --seccomp off -- /bin/true
}

# attempts LABEL: one round of every attempt, with the AppArmor setting as it is.
attempts() {
    local label="$1" dir way
    start_holder D
    dir=$HOLDER
    started+=("$(cat "$dir/bwrap.pid")")
    {
        echo "### $label"
        echo
        echo "$sysctl_name: $(sysctl -n "$sysctl_name" 2>/dev/null || echo absent)"
        echo
        echo "ns-diag.py, user namespace first:"
        python3 -I "$M3/ns-fds.py" "$dir/holder.sock" -- python3 -I "$M3/ns-diag.py" 2>&1 | fence
        echo "ns-diag.py, network namespace first (control):"
        python3 -I "$M3/ns-fds.py" "$dir/holder.sock" -- python3 -I "$M3/ns-diag.py" net-first 2>&1 | fence
        for way in nsenter nsenter-pid userns userns-net; do
            mapfile -d '' cmd < <(join "$way")
            echo "\`$way\` under strace (the namespace calls and the last lines):"
            timeout 60 strace -f -qq -e trace=setns,unshare,clone,clone3 -o "$tmp/$label-$way.strace" \
                python3 -I "$M3/ns-fds.py" "$dir/holder.sock" -- "${cmd[@]}" >"$tmp/$label-$way.out" 2>&1
            echo "exit $?" >>"$tmp/$label-$way.out"
            {
                grep -E 'setns|unshare|clone' "$tmp/$label-$way.strace" | sed -E 's/^[0-9]+ +//' \
                    | grep -E 'NEW|= -1' | head -30
                echo "--"
                grep -v '^inside:' "$tmp/$label-$way.out" | tail -5
            } | cut -c1-200 | fence
        done
    } >"$tmp/$label.md"
    kill "$(cat "$dir/bwrap.pid")" 2>/dev/null
    sleep 1
}

{
    echo "job's label: $(cat /proc/self/attr/current 2>&1)"
    echo "$sysctl_name at start: $initial"
    echo "nsenter: $(command -v nsenter) ($(nsenter --version 2>&1)); bwrap: $(command -v bwrap) ($(bwrap --version 2>&1))"
    echo
    echo "AppArmor profiles naming bwrap, nsenter, unshare or user namespaces (aa-status):"
    sudo aa-status 2>&1 | grep -iE 'bwrap|nsenter|unshare|userns|profiles are' | head -20
    echo
    echo "/etc/apparmor.d entries naming bwrap, nsenter or unshare:"
    grep -lE 'bwrap|nsenter|unshare' /etc/apparmor.d/* 2>/dev/null | head -20
} >"$tmp/state.txt"

attempts "restriction-on"
if [ "$initial" != absent ]; then
    sudo sysctl -qw "$sysctl_name=0"
    attempts "restriction-off"
    sudo sysctl -qw "$sysctl_name=$initial"
    attempts "restriction-on-again"
fi

{
    sudo dmesg 2>&1 | grep -iE 'apparmor|userns' | tail -40
    echo "-- journal (kernel) since $since"
    sudo journalctl -k --since "$since" --no-pager 2>&1 | grep -iE 'apparmor|userns' | tail -40
} | cut -c1-220 >"$tmp/kernel.txt"

{
    echo "# What refuses joining a holder's namespaces ($(uname -m))"
    section "AppArmor and the tools"
    fence <"$tmp/state.txt"
    section "Attempts"
    echo "ns-diag.py prints each setns with its result, then the process's AppArmor label, its effective and permitted capabilities and its user, network and PID namespaces after that step. The strace excerpts keep the namespace calls that make or join one, and every one that failed."
    echo
    for f in restriction-on restriction-off restriction-on-again; do
        [ -e "$tmp/$f.md" ] && cat "$tmp/$f.md"
    done
    section "The kernel's AppArmor messages"
    fence <"$tmp/kernel.txt"
} >"$out"
cat "$out"
