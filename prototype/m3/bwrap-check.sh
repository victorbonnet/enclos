#!/bin/sh
# Whether bubblewrap runs as an unprivileged user, and which setting it needs
# (design §14, M3-01). It creates user namespaces and, with sudo, loads an
# AppArmor profile and changes a sysctl, so it runs only on a throwaway
# GitHub-hosted runner, never on the user's machine.
set -u

if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
    echo "bwrap-check.sh runs only on a GitHub-hosted runner (it changes host settings)" >&2
    exit 2
fi

say() { printf '%s: %s\n' "$1" "$2"; }

# One try: a read-only root, every namespace bubblewrap makes, `true` inside.
try() {
    out=$(bwrap --ro-bind / / --dev /dev --proc /proc --unshare-all --die-with-parent true 2>&1)
    status=$?
    if [ "$status" -eq 0 ]; then say "$1" "runs"; else say "$1" "fails ($status): $out"; fi
}

say bubblewrap.version "$(bwrap --version 2>&1)"
sysctl=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
restrict=$(cat "$sysctl" 2>/dev/null || echo absent)
say userns.apparmor_restrict_unprivileged_userns "$restrict"
try bwrap.as_installed

if [ "$restrict" = 1 ]; then
    # A profile that lets /usr/bin/bwrap alone make user namespaces, written
    # as Ubuntu's own profiles for chrome and others are (apparmor.d/chrome).
    profile=/etc/apparmor.d/enclos-survey-bwrap
    sudo tee "$profile" >/dev/null <<'EOF'
abi <abi/4.0>,
include <tunables/global>
profile enclos-survey-bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
}
EOF
    sudo apparmor_parser -r "$profile"
    try bwrap.with_userns_profile
    sudo apparmor_parser -R "$profile"
    sudo rm -f "$profile"

    sudo sysctl -qw kernel.apparmor_restrict_unprivileged_userns=0
    try bwrap.with_restriction_off
    sudo sysctl -qw kernel.apparmor_restrict_unprivileged_userns="$restrict"
fi
