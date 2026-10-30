#!/bin/bash
# Prepares a GitHub-hosted Ubuntu runner for the M3-02 checks: installs
# bubblewrap and what the checks use, then finds the least setting that lets
# bubblewrap make its user namespace under AppArmor (design §14): none, a
# profile that lets /usr/bin/bwrap alone make user namespaces, or the
# restriction turned off. It keeps that setting for the rest of the job.
set -u
source "$(dirname "$0")/lib.sh"
out="$RESULTS_DIR/00-setup.md"

sudo apt-get update -qq
sudo apt-get install -y -qq bubblewrap python3-seccomp python3-venv xvfb gnome-keyring dbus-x11 >/dev/null

try() { bwrap --ro-bind / / --dev /dev --proc /proc --unshare-all --die-with-parent true 2>&1; }

{
    section "Runner"
    {
        echo "os: $(. /etc/os-release && echo "$PRETTY_NAME")"
        echo "arch: $(uname -m)"
        echo "kernel: $(uname -r)"
        echo "bubblewrap: $(bwrap --version)"
        echo "python3: $(python3 --version 2>&1)"
        echo "python3-seccomp: $(dpkg-query -W -f '${Version}' python3-seccomp)"
        echo "lsm.active: $(cat /sys/kernel/security/lsm 2>/dev/null)"
        echo "dev.tty.legacy_tiocsti: $(cat /proc/sys/dev/tty/legacy_tiocsti 2>/dev/null || echo absent)"
        # The second run's environ probe got EACCES on the host for a process
        # the check itself started: these say whether a label or /proc's
        # mount options explain it.
        echo "job's AppArmor label: $(cat /proc/self/attr/current 2>&1)"
        echo "/proc mount: $(awk '$2 == "/proc" {print $4}' /proc/mounts)"
        echo "kernel.yama.ptrace_scope: $(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo absent)"
        echo "kernel.unprivileged_bpf_disabled: $(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo absent)"
        echo "vm.unprivileged_userfaultfd: $(cat /proc/sys/vm/unprivileged_userfaultfd 2>/dev/null || echo absent)"
        echo "kernel.perf_event_paranoid: $(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo absent)"
        echo "kernel.io_uring_disabled: $(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo absent)"
        echo "apparmor_restrict_unprivileged_userns: $(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo absent)"
        echo "node: $(node --version 2>&1)"
        echo "git: $(git --version 2>&1)"
        echo "curl: $(curl --version 2>&1 | head -1)"
    } | fence

    section "The setting bubblewrap needed"
    {
        if o=$(try); then
            echo "setting: none (bubblewrap runs as installed)"
        else
            echo "as installed: fails: $o"
            profile=/etc/apparmor.d/enclos-proto-bwrap
            sudo tee "$profile" >/dev/null <<'EOF'
abi <abi/4.0>,
include <tunables/global>
profile enclos-proto-bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
}
EOF
            sudo apparmor_parser -r "$profile"
            if o=$(try); then
                echo "setting: an AppArmor profile for /usr/bin/bwrap with \`userns,\`"
            else
                echo "with the profile: fails: $o"
                sudo sysctl -qw kernel.apparmor_restrict_unprivileged_userns=0
                if o=$(try); then
                    echo "setting: kernel.apparmor_restrict_unprivileged_userns=0"
                else
                    echo "with the restriction off: fails: $o"
                    echo "setting: none found"
                fi
            fi
        fi
    } | fence
} | tee "$out"
grep -q '^setting: none found' "$out" && exit 1
exit 0
