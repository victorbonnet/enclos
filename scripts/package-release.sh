#!/usr/bin/env bash
# Packs a release binary the way install.sh reads it: one executable named
# `enclos` at the archive's root, in `enclos-<TARGET>.tar.gz`, and the
# archive's SHA-256 in `shasum -a 256` format. The release workflow and
# tests/test_install.py both use it.
#
# Usage: scripts/package-release.sh BINARY TARGET OUT_DIR
#
# TARGET is a Rust target triple install.sh knows.
set -euo pipefail

[ "$#" -eq 3 ] || { echo "usage: $0 BINARY TARGET OUT_DIR" >&2; exit 2; }
binary="$1"
target="$2"
out="$3"
case "$target" in
  aarch64-apple-darwin | x86_64-unknown-linux-musl | aarch64-unknown-linux-musl) ;;
  *) echo "$0: install.sh installs no archive for $target" >&2; exit 2 ;;
esac
[ -f "$binary" ] || { echo "$0: no file at $binary" >&2; exit 1; }
asset="enclos-$target.tar.gz"

# The same line from either tool: macOS has shasum, a Linux host sha256sum.
sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$@"; else sha256sum "$@"; fi
}

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p -- "$out"
install -m 755 "$binary" "$work/enclos"
# No AppleDouble `._enclos` entry beside it.
COPYFILE_DISABLE=1 tar -czf "$out/$asset" -C "$work" enclos
(
  cd "$out"
  sha256 "$asset" > "$asset.sha256"
  sha256 -c "$asset.sha256" >/dev/null
)
[ "$(tar -tzf "$out/$asset")" = enclos ] || { echo "$0: the archive holds more than enclos" >&2; exit 1; }
printf '%s\n' "$out/$asset" "$out/$asset.sha256"
