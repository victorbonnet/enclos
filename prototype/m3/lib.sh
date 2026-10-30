# Sourced by the M3-02 bubblewrap prototype's scripts (design §14, issue #102).
# Everything they run acts on the host (user namespaces, bubblewrap, sudo,
# packages, planted files in the home), so they refuse to run anywhere but a
# throwaway GitHub-hosted runner, or a disposable VM for the manual steps in
# README.md: there ENCLOS_PROTO_DISPOSABLE_VM=1 must be set and
# systemd-detect-virt must report a VM, so bare metal is refused either way.
# Each check writes its result, as Markdown, to $RESULTS_DIR, which the
# bwrap-prototype workflow uploads as an artifact.

if [ "${GITHUB_ACTIONS:-}" = true ] && [ "${RUNNER_ENVIRONMENT:-}" = github-hosted ]; then
    :
elif [ "${ENCLOS_PROTO_DISPOSABLE_VM:-}" = 1 ] && virt=$(systemd-detect-virt --vm 2>/dev/null) \
    && [ "$virt" != none ]; then
    :
else
    echo "$(basename "$0") runs only on a GitHub-hosted runner or a disposable VM (it acts on the host)" >&2
    exit 2
fi

M3="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
RESULTS_DIR="${RESULTS_DIR:-$PWD/m3-results}"
mkdir -p "$RESULTS_DIR"

# The prototype's sandbox, laid out as enclos lays one out (design §11).
H="$(cd ~ && pwd -P)"                      # the user's own home, read broadly
SBX="$H/.enclos/sandboxes/proto"           # the sandbox's folder (protected)
SBX_HOME="$SBX/home"
SBX_RUN="$SBX/run/visible"
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
# The text in a fence, ending in a newline even when the input does not.
fence() { printf '```\n'; sed -e '$a\'; printf '```\n'; }

# M3-03's holder of a sandbox's namespaces (ns-holder.py), with the
# sandbox's relay to $PROXY_SOCK.
#
# start_holder NAME: a holder for sandbox NAME in its own folder, which no
# session mounts (it is under ~/.enclos, on the deny list). Sets HOLDER to
# the folder; the holder's host pid is in <folder>/pid once it is ready. Not
# run in a subshell, which would end at once and, as bubblewrap's parent,
# take the holder with it (--die-with-parent).
start_holder() {
    local dir="$SBX/ns-$1"
    rm -rf "$dir"
    mkdir -p "$dir"
    bwrap --unshare-user --unshare-pid --unshare-net --die-with-parent \
        --ro-bind / / --proc /proc --tmpfs /tmp --bind "$dir" "$dir" \
        --info-fd 3 \
        -- /usr/bin/python3 -I "$M3/ns-holder.py" --socket "$dir/holder.sock" --info "$dir/info.json" \
        --relay "$RELAY_PORT" "$PROXY_SOCK" \
        3>"$dir/bwrap-info.json" >"$dir/holder.out" 2>&1 &
    echo $! >"$dir/bwrap.pid"
    for _ in $(seq 50); do [ -e "$dir/info.json" ] && break; sleep 0.2; done
    python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["child-pid"])' \
        "$dir/bwrap-info.json" >"$dir/pid" 2>/dev/null
    HOLDER="$dir"
}

# A session left open across restarts (ns-open-session.py).
#
# open_session DIR ENV=VALUE...: a session with that environment (SBX_JOIN and
# so on), waiting for commands in DIR, in the sandbox's home so both sides
# see it. Sets OPEN_PID, for the caller's list of what it started. Not run in
# a subshell, which would take the session with it.
open_session() {
    local dir="$1"
    shift
    rm -rf "$dir"
    mkdir -p "$dir"
    env "$@" timeout 1800 "$M3/sbx-ns.sh" -- /usr/bin/python3 -I "$M3/ns-open-session.py" "$dir" \
        </dev/null >"$dir.log" 2>&1 &
    OPEN_PID=$!
    for _ in $(seq 100); do [ -e "$dir/ready" ] && return 0; sleep 0.2; done
    return 1
}

# ask DIR SECONDS command...: runs the command in that open session, prints
# its output and returns its exit code, or says it had no answer.
ask() {
    local dir="$1" wait="$2" n
    shift 2
    n=$(find "$dir" -name '*.exit' | wc -l)
    python3 -I -c 'import json, sys; json.dump(sys.argv[1:], sys.stdout)' "$@" >"$dir/$n.new"
    mv "$dir/$n.new" "$dir/$n.cmd"
    for _ in $(seq $((wait * 5))); do [ -e "$dir/$n.exit" ] && break; sleep 0.2; done
    if [ ! -e "$dir/$n.exit" ]; then
        echo "no answer from the open session in $wait s"
        return 124
    fi
    cat "$dir/$n.out"
    return "$(cat "$dir/$n.exit")"
}
