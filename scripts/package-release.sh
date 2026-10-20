#!/usr/bin/env bash
# Packs a release binary the way install.sh reads it: one executable named
# `enclos` at the archive's root, and the archive's SHA-256 in `shasum -a 256`
# format. The release workflow and tests/test_install.py both use it.
#
# Usage: scripts/package-release.sh BINARY OUT_DIR
set -euo pipefail

readonly asset="enclos-aarch64-apple-darwin.tar.gz"

[ "$#" -eq 2 ] || { echo "usage: $0 BINARY OUT_DIR" >&2; exit 2; }
binary="$1"
out="$2"
[ -f "$binary" ] || { echo "$0: no file at $binary" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p -- "$out"
install -m 755 "$binary" "$work/enclos"
# No AppleDouble `._enclos` entry beside it.
COPYFILE_DISABLE=1 tar -czf "$out/$asset" -C "$work" enclos
(
  cd "$out"
  shasum -a 256 "$asset" > "$asset.sha256"
  shasum -a 256 -c "$asset.sha256" >/dev/null
)
[ "$(tar -tzf "$out/$asset")" = enclos ] || { echo "$0: the archive holds more than enclos" >&2; exit 1; }
printf '%s\n' "$out/$asset" "$out/$asset.sha256"
