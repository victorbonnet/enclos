# Shared by setup.sh, check.sh and teardown.sh. Source it; do not run it.
# shellcheck shell=bash

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Settings and secrets come from examples/organization/.env (ignored by git),
# or the file ORG_ENV names. See .env.example.
ENV_FILE="${ORG_ENV:-$HERE/.env}"
if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    set +a
fi

ENCLOS="${ENCLOS:-$(command -v enclos || echo "$HOME/.cargo/bin/enclos")}"
ENCLOS_DATA="${ENCLOS_HOME:-$HOME/.enclos}"

# One sandbox per role: the sandbox is the permission boundary (ADR 0003), so
# roles with different permissions cannot share one.
MANAGER="${MANAGER:-manager}"
DEV="${DEV:-dev}"
COMMUNITY="${COMMUNITY:-community}"
SANDBOXES=("$MANAGER" "$DEV" "$COMMUNITY")

say() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
run() { printf '+ %s\n' "$*"; "$@"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

sandbox_exists() { "$ENCLOS" sandbox list | awk 'NR > 1 { print $1 }' | grep -qx -- "$1"; }
sandbox_home() { printf '%s/sandboxes/%s/home' "$ENCLOS_DATA" "$1"; }
runtime_installed() { [ -x "$(sandbox_home "$1")/.local/bin/hermes" ]; }
# What `enclos status` uses too: Hermes keeps its login here, and enclos never reads it.
logged_in() { [ -f "$(sandbox_home "$1")/.hermes/auth.json" ]; }

# Run a command inside a sandbox through enclos. Standard input passes through.
in_sandbox() {
    local sandbox=$1
    shift
    "$ENCLOS" connect "$sandbox" -- "$@"
}

# `hermes config set <key> <value>` inside a sandbox. An UPPER_SNAKE key lands in
# the sandbox's ~/.hermes/.env; a dotted key in its config.yaml.
hermes_set() { in_sandbox "$1" hermes config set "$2" "$3"; }

# The same, with the value read from this script's standard input, so a secret
# never appears on the host side of the command line.
hermes_set_stdin() { in_sandbox "$1" sh -c 'hermes config set "$1" "$(cat)"' set "$2"; }

# Write a file in the sandbox home from standard input, with Hermes's view of `~`.
write_home_file() { in_sandbox "$1" sh -c 'mkdir -p "$(dirname ~/"$1")" && cat > ~/"$1"' write "$2"; }

# Let a sandbox reach destinations. Allowing one that is already allowed changes nothing.
allow() {
    local sandbox=$1
    shift
    local destination
    for destination in "$@"; do
        run "$ENCLOS" --yes policy allow "$sandbox" "$destination"
    done
}

# The host of a URL, for `enclos policy allow`.
url_host() { printf '%s' "$1" | sed -E 's#^[a-z]+://##; s#[/:?].*$##'; }
