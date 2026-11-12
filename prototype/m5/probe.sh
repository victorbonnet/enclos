#!/bin/sh
# Disposable macOS OpenClaw experiment. Every OpenClaw command crosses enclos.
set -eu

if [ "$(uname -s)" != Darwin ]; then
    echo 'This experiment is macOS only; Linux acceptance is deferred.' >&2
    exit 2
fi

phase=${1:-install}
enclos_bin=${ENCLOS_BIN:-enclos}
case "$enclos_bin" in
    /*) ;;
    *) enclos_bin=$(command -v "$enclos_bin") ;;
esac

if [ -z "${M5_WORK_DIR:-}" ]; then
    if [ "$phase" != install ]; then
        echo 'Set M5_WORK_DIR to the disposable experiment directory.' >&2
        exit 2
    fi
    M5_WORK_DIR=$(mktemp -d /private/tmp/e5.XXXXXX)
fi
export M5_WORK_DIR
printf 'M5_WORK_DIR=%s\n' "$M5_WORK_DIR" >&2
export ENCLOS_HOME="$M5_WORK_DIR/state"
sb=m5openclaw
sb_home="$ENCLOS_HOME/sandboxes/$sb/home"
prefix="$sb_home/.local/share/openclaw"
native="$prefix/bin/openclaw"

run() {
    "$enclos_bin" --yes "$@"
}

inside() {
    run exec "$sb" -- /usr/bin/env \
        OPENCLAW_HOME="$sb_home" \
        OPENCLAW_STATE_DIR="$sb_home/.openclaw" \
        OPENCLAW_CONFIG_PATH="$sb_home/.openclaw/openclaw.json" \
        OPENCLAW_SUPERVISOR_MODE=external \
        OPENCLAW_SERVICE_REPAIR_POLICY=external \
        OPENCLAW_NO_RESPAWN=1 \
        OPENCLAW_DISABLE_BONJOUR=1 \
        OPENCLAW_LOAD_SHELL_ENV=0 \
        NODE_USE_ENV_PROXY=1 \
        "$@"
}

case "$phase" in
    install)
        if [ -e "$ENCLOS_HOME/state.db" ]; then
            echo 'Refusing to install into existing enclos state; use a fresh M5_WORK_DIR.' >&2
            exit 2
        fi
        mkdir -p "$M5_WORK_DIR/evidence"
        printf '%s\n' "$M5_WORK_DIR" > "$M5_WORK_DIR/evidence/work-dir.txt"
        sw_vers > "$M5_WORK_DIR/evidence/macos.txt"
        uname -m >> "$M5_WORK_DIR/evidence/macos.txt"
        run init
        run sandbox create "$sb" --template assistant
        mkdir -p "$sb_home/.prototype"
        # Download as data; execute only through an enclos sandbox session.
        curl -fsSL --proto '=https' https://openclaw.ai/install-cli.sh \
            -o "$sb_home/.prototype/install-cli.sh"
        shasum -a 256 "$sb_home/.prototype/install-cli.sh" \
            > "$M5_WORK_DIR/evidence/installer.sha256"
        inside /bin/bash "$sb_home/.prototype/install-cli.sh" \
            --prefix "$prefix" --npm --runtime-only --no-onboard --json \
            > "$M5_WORK_DIR/evidence/install.jsonl" \
            2> "$M5_WORK_DIR/evidence/install.stderr"
        inside "$native" --version > "$M5_WORK_DIR/evidence/version.txt"
        run net log "$sb" > "$M5_WORK_DIR/evidence/network.json"
        run audit verify > "$M5_WORK_DIR/evidence/audit.json"
        printf 'M5_WORK_DIR=%s\n' "$M5_WORK_DIR"
        ;;
    inspect)
        inside "$native" --version
        inside "$native" agents list --json --bindings
        run audit verify
        ;;
    exec)
        shift
        inside "$native" "$@"
        ;;
    stop)
        run sandbox stop "$sb"
        ;;
    remove)
        run sandbox stop "$sb"
        run sandbox rm "$sb"
        echo "Evidence retained in $M5_WORK_DIR/evidence"
        ;;
    *)
        echo 'Usage: probe.sh install|inspect|exec <native args...>|stop|remove' >&2
        exit 2
        ;;
esac
