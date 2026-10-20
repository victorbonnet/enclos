#!/usr/bin/env bash
# Stop and remove the three sandboxes, with their Hermes installs and logins.
# enclos asks before removing each one; pass --yes to skip the questions.

# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

for sandbox in "${SANDBOXES[@]}"; do
    if sandbox_exists "$sandbox"; then
        say "$sandbox"
        run "$ENCLOS" sandbox stop "$sandbox" || true
        run "$ENCLOS" sandbox rm "$sandbox" "$@"
    else
        note "$sandbox: no such sandbox"
    fi
done
