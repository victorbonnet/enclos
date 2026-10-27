#!/usr/bin/env bash
# Install the latest enclos release on an Apple silicon Mac:
#
#   curl -fsSL https://enclos.dev/install.sh | bash
#
# The entry point is the last line, so a download cut short installs nothing.
set -euo pipefail

readonly repository="https://github.com/victorbonnet/enclos"
readonly asset="enclos-aarch64-apple-darwin.tar.gz"

temp_dir=""
staging_dir=""

usage() {
  cat <<'HELP'
Install the latest enclos release on an Apple silicon Mac running macOS 15 or later.

Usage: install.sh [--prefix PATH]

  --prefix PATH  Install into PATH/bin (default: $HOME/.local).
  --help         Show this help.

Through a pipe: curl -fsSL https://enclos.dev/install.sh | bash -s -- --prefix PATH

The installer needs curl, tar and shasum. It never uses sudo, edits shell
startup files or creates sandboxes. To build from source instead, see
https://github.com/victorbonnet/enclos/blob/main/docs/getting-started.md
HELP
}

fail() {
  printf 'enclos installer: %s\n' "$*" >&2
  exit 1
}

# Removes what the installer created; one failure does not stop the other.
cleanup() {
  if [ -n "$staging_dir" ]; then rm -rf -- "$staging_dir" || true; fi
  if [ -n "$temp_dir" ]; then rm -rf -- "$temp_dir" || true; fi
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required."
}

# HTTPS only, including redirects, with bounded connection and transfer times.
fetch() {
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --fail --silent --show-error --location \
    --connect-timeout 15 --max-time 180 "$@"
}

# GitHub redirects /releases/latest to the newest published release that is
# neither a draft nor a prerelease, or to /releases when there is none.
latest_tag() {
  local url tag
  url=$(fetch --output /dev/null --write-out '%{url_effective}' "$repository/releases/latest") \
    || fail "Could not get the latest release from $repository/releases (see the error above)."
  case "$url" in
    "$repository/releases/tag/"*) tag=${url#"$repository/releases/tag/"} ;;
    "$repository/releases" | "$repository/releases/") \
      fail "enclos has no published release yet. Watch $repository/releases, or build from source: $repository/blob/main/docs/getting-started.md" ;;
    *) fail "GitHub did not name a release ($url)." ;;
  esac
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "Unexpected release tag: $tag"
  printf '%s\n' "$tag"
}

install_latest() {
  local prefix="$1"
  local tag digest named extra actual listing binary version

  need curl
  need tar
  need shasum
  temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/enclos-install.XXXXXX")

  printf 'Finding the latest enclos release…\n'
  tag=$(latest_tag)
  printf 'Downloading enclos %s for Apple silicon…\n' "$tag"
  fetch --output "$temp_dir/$asset" "$repository/releases/download/$tag/$asset" \
    || fail "Could not download $asset for $tag; nothing was installed."
  fetch --output "$temp_dir/$asset.sha256" "$repository/releases/download/$tag/$asset.sha256" \
    || fail "Could not download the checksum for $tag; nothing was installed."

  # `read` fails at a missing final newline even when it read the line.
  read -r digest named extra < "$temp_dir/$asset.sha256" || [ -n "${digest:-}" ] \
    || fail "The release checksum file is invalid; nothing was installed."
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] && [ -z "$extra" ] \
    || fail "The release checksum file is invalid; nothing was installed."
  case "$named" in
    "$asset" | "*$asset") ;;
    *) fail "The release checksum names another file; nothing was installed." ;;
  esac
  actual=$(shasum -a 256 "$temp_dir/$asset")
  [ "${actual%% *}" = "$digest" ] \
    || fail "The release checksum does not match; nothing was installed."

  # Take only the expected executable, into a file created here: the archive's
  # paths, links, owners and modes never reach the host.
  listing=$(tar -tzf "$temp_dir/$asset") \
    || fail "The release archive cannot be read; nothing was installed."
  [ "$listing" = enclos ] \
    || fail "The release archive must hold only enclos; nothing was installed."
  binary="$temp_dir/enclos"
  tar -xOzf "$temp_dir/$asset" enclos > "$binary" \
    || fail "Could not unpack the release; nothing was installed."
  [ -s "$binary" ] || fail "The release executable is empty; nothing was installed."
  chmod 755 "$binary"
  version=$("$binary" --version) \
    || fail "The release executable did not run; nothing was installed."
  [ "$version" = "enclos ${tag#v}" ] \
    || fail "The release executable says '$version', not $tag; nothing was installed."

  [ ! -d "$prefix/bin/enclos" ] || fail "$prefix/bin/enclos is a folder."
  mkdir -p -- "$prefix/bin" 2>/dev/null \
    || fail "Cannot create $prefix/bin. Choose a folder you own with --prefix; nothing was installed."
  # Staged next to the destination, so the replacement is one atomic rename.
  staging_dir=$(mktemp -d "$prefix/bin/.enclos-install.XXXXXX")
  cp -- "$binary" "$staging_dir/enclos"
  mv -f -- "$staging_dir/enclos" "$prefix/bin/enclos"
  printf '%s\n' "$version"
}

main() {
  local prefix="${HOME:?HOME must be set}/.local" macos found

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --prefix)
        [ "$#" -ge 2 ] && [ -n "$2" ] || fail "--prefix needs a value. Run with --help."
        prefix="$2"
        shift 2
        ;;
      --help | -h) usage; return 0 ;;
      *) fail "Unknown option: $1. Run with --help." ;;
    esac
  done
  case "$prefix" in
    /*) while [[ "$prefix" == */ ]]; do prefix="${prefix%/}"; done ;;
    *) fail "--prefix must be an absolute path." ;;
  esac
  [ -n "$prefix" ] || fail "Do not install into the filesystem root."

  [ "$(uname -s)" = Darwin ] || fail "enclos supports only macOS for now."
  # `uname -m` says x86_64 when this shell runs under Rosetta; the Mac decides.
  [ "$(uname -m)" = arm64 ] || [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ] \
    || fail "enclos needs an Apple silicon Mac."
  macos=$(sw_vers -productVersion)
  case "${macos%%.*}" in '' | *[!0-9]*) fail "Cannot tell the macOS version." ;; esac
  [ "${macos%%.*}" -ge 15 ] || fail "macOS 15 or later is required (found $macos)."
  [ "$(id -u)" != 0 ] || fail "Run the installer as yourself, without sudo."

  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  install_latest "$prefix"

  printf '\nInstalled enclos in %s/bin.\n' "$prefix"
  case ":$PATH:" in
    *":$prefix/bin:"*) ;;
    *) printf 'Add it to your PATH:\n  export PATH=%q:"$PATH"\n' "$prefix/bin" ;;
  esac
  found=$(command -v enclos 2>/dev/null || true)
  if [ -n "$found" ] && [ "$found" != "$prefix/bin/enclos" ]; then
    printf '\nAnother enclos comes first on your PATH: %s\n' "$found"
    printf 'Remove it (for one built with cargo: cargo uninstall enclos), or put %s first.\n' "$prefix/bin"
  fi
  printf '\nNext:\n  enclos init\n  enclos sandbox create lab\n  enclos runtime install hermes --sandbox lab\n'
}

main "$@"
