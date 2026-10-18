#!/bin/bash
# Run a command inside the prototype sandbox: the compiled policy built from
# sb/*.sb, the environment pointed at the sandbox home, and every common proxy
# variable set to the prototype proxy.
#
#   ./sbx.sh -- hermes --version
#   SBX_WITHOUT="41 44" ./sbx.sh -- cmd   # leave out sb/41-*.sb and sb/44-*.sb
#   SBX_POLICY=none ./sbx.sh -- cmd       # same environment, plain (allow default)
set -u
source "$(dirname "$0")/env.sh"
[ "${1:-}" = "--" ] && shift

compiled="$WORK/compiled.sb"
if [ "${SBX_POLICY:-}" = none ]; then
    printf '(version 1)\n(allow default)\n' >"$compiled"
else
    : >"$compiled"
    for f in "$M1"/sb/*.sb; do
        n=$(basename "$f" | cut -c1-2)
        case " ${SBX_WITHOUT:-} " in *" $n "*) continue ;; esac
        printf ';; ---- %s\n' "$(basename "$f")" >>"$compiled"
        cat "$f" >>"$compiled"
    done
fi
# Extra SBPL appended last, for experiments: SBX_EXTRA_RULES='(deny appleevent-send)'
printf '%s\n' "${SBX_EXTRA_RULES:-}" >>"$compiled"

mkdir -p "$SBX_HOME"/{tmp,.cache,.config,.local/share,.local/bin,bin}
proxy="http://127.0.0.1:$PROXY_PORT"
exec /usr/bin/env -i \
    HOME="$SBX_HOME" USER="$(id -un)" LOGNAME="$(id -un)" SHELL=/bin/zsh \
    TERM="${TERM:-xterm-256color}" LANG="${LANG:-en_US.UTF-8}" \
    PATH="$SBX_HOME/.local/bin:$SBX_HOME/bin:$M1/shims:/usr/bin:/bin:/usr/sbin:/sbin" \
    TMPDIR="$SBX_HOME/tmp/" \
    XDG_CONFIG_HOME="$SBX_HOME/.config" XDG_CACHE_HOME="$SBX_HOME/.cache" \
    XDG_DATA_HOME="$SBX_HOME/.local/share" XDG_STATE_HOME="$SBX_HOME/.local/state" \
    UV_CACHE_DIR="$SBX_HOME/.cache/uv" npm_config_cache="$SBX_HOME/.npm" \
    HTTPS_PROXY="$proxy" HTTP_PROXY="$proxy" https_proxy="$proxy" http_proxy="$proxy" \
    ALL_PROXY="$proxy" all_proxy="$proxy" NO_PROXY="" no_proxy="" NODE_USE_ENV_PROXY=1 \
    ${SBX_EXTRA_ENV:-} \
    /usr/bin/sandbox-exec -f "$compiled" \
    -D SANDBOX_HOME="$SBX_HOME" -D REAL_HOME="$REAL_HOME" \
    -D PROXY_PORT="$PROXY_PORT" -D SANDBOX_TAG="$SBX_TAG" \
    "$@"
