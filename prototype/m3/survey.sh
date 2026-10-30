#!/bin/sh
# Host survey for milestone 3 (design §14, issue #102, M3-01). Read-only:
# it reads /sys, /proc, the kernel's build configuration, package versions
# and systemd's settings, and prints one `key: value` line per fact. It runs
# no bubblewrap, creates no namespace, changes no setting and signals
# nothing, so it is safe on any host.
#
# The Landlock ABI comes from landlock_create_ruleset(NULL, 0,
# LANDLOCK_CREATE_RULESET_VERSION), which only returns a number: it creates
# no ruleset and restricts nothing.
set -u

say() { printf '%s: %s\n' "$1" "$2"; }
first() { cat "$1" 2>/dev/null | tr '\0\n' '  ' | sed 's/ *$//' || true; }
or_absent() { [ -n "$1" ] && printf '%s' "$1" || printf 'absent'; }

# --- the host
. /etc/os-release 2>/dev/null || true
say os "${PRETTY_NAME:-unknown}"
# Raspberry Pi OS calls itself Debian in os-release; its image says otherwise
[ -r /etc/rpi-issue ] && say rpi_issue "$(head -1 /etc/rpi-issue)"
say arch "$(uname -m)"
say kernel "$(uname -r)"
say glibc "$(getconf GNU_LIBC_VERSION 2>/dev/null || echo unknown)"

# --- Landlock
config=""
for f in /proc/config.gz "/boot/config-$(uname -r)"; do
    [ -r "$f" ] && config=$f && break
done
kconf() {
    case "$config" in
        "") echo "unknown (no kernel config)" ;;
        *.gz) zcat "$config" | grep -E "^(# )?$1[= ]" | head -1 ;;
        *) grep -E "^(# )?$1[= ]" "$config" | head -1 ;;
    esac
}
say lsm.active "$(or_absent "$(first /sys/kernel/security/lsm)")"
say kconfig.SECURITY_LANDLOCK "$(kconf CONFIG_SECURITY_LANDLOCK)"
say kconfig.LSM "$(kconf CONFIG_LSM)"
say cmdline.lsm "$(tr ' ' '\n' </proc/cmdline | grep -E '^(lsm|security|apparmor)=' | tr '\n' ' ' | sed 's/ *$//')"
abi=$(python3 -I -c '
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
# landlock_create_ruleset is 444 on every architecture (unified numbering)
r = libc.syscall(444, None, ctypes.c_size_t(0), ctypes.c_uint32(1))
print(r if r >= 0 else "none (" + os.strerror(ctypes.get_errno()) + ")")
' 2>/dev/null || echo "unknown (no python3)")
say landlock.abi "$abi"

# --- user namespaces and AppArmor
say userns.max_user_namespaces "$(or_absent "$(first /proc/sys/user/max_user_namespaces)")"
say userns.unprivileged_userns_clone "$(or_absent "$(first /proc/sys/kernel/unprivileged_userns_clone)")"
say userns.apparmor_restrict_unprivileged_userns "$(or_absent "$(first /proc/sys/kernel/apparmor_restrict_unprivileged_userns)")"
say apparmor.enabled "$(or_absent "$(first /sys/module/apparmor/parameters/enabled)")"
bwrap_profile=""
for p in /etc/apparmor.d/bwrap /etc/apparmor.d/bwrap-userns-restrict /etc/apparmor.d/usr.bin.bwrap; do
    [ -e "$p" ] && bwrap_profile="$bwrap_profile $p"
done
say apparmor.bwrap_profile "$(or_absent "${bwrap_profile# }")"
say kconfig.USER_NS "$(kconf CONFIG_USER_NS)"

# --- bubblewrap (the package only: bwrap itself is not run)
pkg() { dpkg-query -W -f '${Version}' "$1" 2>/dev/null || true; }
say bubblewrap.installed "$(or_absent "$(pkg bubblewrap)")"
cand=$(apt-cache policy bubblewrap 2>/dev/null | sed -n 's/^ *Candidate: //p')
say bubblewrap.candidate "$(or_absent "$cand")"
if [ -e /usr/bin/bwrap ]; then
    say bubblewrap.mode "$(stat -c '%A %U' /usr/bin/bwrap)"
fi

# --- cgroups
say cgroup.mount "$(awk '$3 ~ /^cgroup/ {print $3 " " $2}' /proc/mounts | tr '\n' ' ' | sed 's/ *$//')"
say cgroup.root_controllers "$(first /sys/fs/cgroup/cgroup.controllers)"
say kconfig.MEMCG "$(kconf CONFIG_MEMCG)"
say cmdline.cgroup "$(tr ' ' '\n' </proc/cmdline | grep -E '^cgroup_(disable|enable|memory)=' | tr '\n' ' ' | sed 's/ *$//')"
uid=$(id -u)
user_cg=/sys/fs/cgroup/user.slice/user-$uid.slice/user@$uid.service
say cgroup.user_manager_controllers "$(or_absent "$(first "$user_cg/cgroup.controllers")")"
say systemd.user_unit_delegate "$(systemctl cat user@.service 2>/dev/null | sed -n 's/^Delegate=//p' | tr '\n' ' ' | sed 's/ *$//')"

# --- systemd --user at logout
say systemd.version "$(systemctl --version 2>/dev/null | head -1)"
say logind.linger "$(loginctl show-user "$(id -un)" -p Linger --value 2>/dev/null || echo 'unknown (no session)')"
lp() {
    value=$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager "$1" 2>/dev/null) || { echo unknown; return; }
    printf '%s\n' "$value" | cut -d' ' -f2-
}
say logind.KillUserProcesses "$(lp KillUserProcesses)"
say logind.UserStopDelayUSec "$(lp UserStopDelayUSec)"
