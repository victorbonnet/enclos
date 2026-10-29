#!/bin/sh
# What happens to a `systemd --user` unit when its user's last session ends,
# with and without lingering (design §14 and §15, M3-01). It logs in over
# ssh to localhost, starts a unit, logs out, and looks again. It installs
# sshd, changes lingering and ends sessions, so it runs only on a throwaway
# GitHub-hosted runner, never on the user's machine.
set -u

if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
    echo "logout-check.sh runs only on a GitHub-hosted runner (it changes host settings)" >&2
    exit 2
fi

say() { printf '%s: %s\n' "$1" "$2"; }
user=$(id -un)
uid=$(id -u)
unit=enclos-survey-logout

if ! systemctl list-unit-files ssh.service >/dev/null 2>&1; then
    sudo apt-get install -y -qq openssh-server >/dev/null
fi
sudo systemctl start ssh
mkdir -p ~/.ssh
[ -f ~/.ssh/enclos-survey ] || ssh-keygen -q -t ed25519 -N '' -f ~/.ssh/enclos-survey
cat ~/.ssh/enclos-survey.pub >>~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
ssh_in() {
    ssh -i ~/.ssh/enclos-survey -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR "$user@localhost" "$@"
}

delay_us=$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 \
    org.freedesktop.login1.Manager UserStopDelayUSec | cut -d' ' -f2)
say logind.KillUserProcesses "$(busctl get-property org.freedesktop.login1 /org/freedesktop/login1 \
    org.freedesktop.login1.Manager KillUserProcesses | cut -d' ' -f2)"
say logind.UserStopDelayUSec "$delay_us"
say sessions.before "$(loginctl list-sessions --no-legend | grep -c " $user " || true)"

one_run() {
    label=$1
    ssh_in "systemd-run --user --unit=$unit sleep 600 >/dev/null 2>&1; \
        systemctl --user is-active $unit" | sed "s/^/$label.in_session: /"
    # Past the stop delay, with a margin for the manager to stop
    sleep $((delay_us / 1000000 + 10))
    say "$label.user_manager_after" "$(systemctl is-active "user@$uid.service" 2>&1)"
    if systemctl is-active --quiet "user@$uid.service"; then
        say "$label.unit_after" "$(XDG_RUNTIME_DIR=/run/user/$uid systemctl --user is-active $unit 2>&1)"
        XDG_RUNTIME_DIR=/run/user/$uid systemctl --user stop $unit 2>/dev/null || true
    else
        say "$label.unit_after" "gone with the user manager"
    fi
}

say linger.before "$(loginctl show-user "$user" -p Linger --value 2>/dev/null || echo 'no user record')"
sudo loginctl disable-linger "$user"
one_run without_linger
sudo loginctl enable-linger "$user"
one_run with_linger
sudo loginctl disable-linger "$user"
