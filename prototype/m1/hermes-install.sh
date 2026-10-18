#!/bin/bash
# Install Hermes Agent inside the prototype sandbox, through the proxy.
#
#   ./proxy.sh --learn            (first, to learn the endpoints)
#   ./hermes-install.sh preflight  git, environment and disk checks only
#   ./hermes-install.sh            run the installer
#
# The installer (downloaded to .work/home/dl/installer/ and read before use)
# runs with HOME = the sandbox home, so HERMES_HOME = $HOME/.hermes and the
# checkout, uv, Python, node and browsers all land under .work/home. The
# compiled policy refuses writes anywhere else. Flags:
#   --non-interactive   skips the `setup` and `gateway` stages: no `hermes
#                       setup`, no `hermes gateway install` (no launchd job)
#   --skip-computer-use no cua-driver; the browser tools (agent-browser and
#                       Chromium) stay in
set -u
source "$(dirname "$0")/env.sh"
INSTALLER="$SBX_HOME/dl/installer/install.sh"
EXPECTED_SHA256="${HERMES_INSTALLER_SHA256:-20f44240ebada354a468104a6a6724d037afcb8883d4d09ddeb4815622c52d8b}"

free_gb() { df -g / | awk 'NR == 2 {print $4}'; }
if [ "$(free_gb)" -lt 15 ]; then
    echo "only $(free_gb) GB free on /; need 15 GB. Stopping." >&2
    exit 1
fi

if [ "${1:-}" = preflight ]; then
    "$M1/sbx.sh" -- /bin/sh -c 'echo "HOME=$HOME"; echo "TMPDIR=$TMPDIR"; echo "HERMES vars: $(env | grep -c ^HERMES)"; git --version'
    exit $?
fi

[ -f "$INSTALLER" ] || { echo "download the installer to $INSTALLER first" >&2; exit 1; }
got="$(shasum -a 256 "$INSTALLER" | cut -d' ' -f1)"
if [ "$got" != "$EXPECTED_SHA256" ]; then
    echo "installer changed (sha256 $got); read it again before running it" >&2
    exit 1
fi
"$M1/sbx.sh" -- /bin/bash "$INSTALLER" --non-interactive --skip-computer-use --verbose
