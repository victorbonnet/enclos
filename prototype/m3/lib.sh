# Sourced by the M3-02 bubblewrap prototype's scripts (design §14, issue #102).
# Everything they run acts on the host (user namespaces, bubblewrap, sudo,
# packages, planted files in the home), so they refuse to run anywhere but a
# throwaway GitHub-hosted runner. Each check writes its result, as Markdown,
# to $RESULTS_DIR, which the bwrap-prototype workflow uploads as an artifact.

if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
    echo "$(basename "$0") runs only on a GitHub-hosted runner (it acts on the host)" >&2
    exit 2
fi

M3="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RESULTS_DIR="${RESULTS_DIR:-$PWD/m3-results}"
mkdir -p "$RESULTS_DIR"

# The prototype's sandbox, laid out as enclos lays one out (design §11).
H="$(cd ~ && pwd -P)"                      # the user's own home, read broadly
SBX="$H/.enclos/sandboxes/proto"           # the sandbox's folder (protected)
SBX_HOME="$SBX/home"
SBX_RUN="$SBX/run"
SBX_COMPILED="$SBX/compiled"
WORK="$H/proto-workspace"                  # one workspace, bound writable
PROXY_SOCK="$SBX_RUN/proxy.sock"
RELAY_PORT=18080
mkdir -p "$SBX_HOME" "$SBX_RUN" "$SBX_COMPILED" "$WORK"

# The deny list the checks plant files under: a few of the default list's
# Linux entries (M3-07) and enclos's own folder, which is protected.
DENY=(
    "$H/.ssh"
    "$H/.aws"
    "$H/.gnupg"
    "$H/.config/google-chrome"
    "$H/.local/share/keyrings"
    "$H/.password-store"
    "$H/.enclos"
)

# Compile the prototype's policy into $SBX_COMPILED/compiled.json. Extra
# arguments go to compile.py (--new-session).
compile_policy() {
    local args=(--host-home "$H" --sandbox-dir "$SBX" --workspace "$WORK"
        --relay-port "$RELAY_PORT" --out "$SBX_COMPILED/compiled.json")
    local d
    for d in "${DENY[@]}"; do args+=(--deny "$d"); done
    python3 -I "$M3/compile.py" "${args[@]}" "$@"
}

# One section of a result file: a heading, then lines of text.
section() { printf '\n## %s\n\n' "$1"; }
fence() { printf '```\n'; cat; printf '```\n'; }
