#!/usr/bin/env bash
# Keep the entry point last so an incomplete download cannot start an install.
set -euo pipefail

install_temp_dir=""
install_staging_dir=""

usage() {
  cat <<'HELP'
Install enclos on an Apple silicon Mac running macOS 14 or later.

Usage: bash install.sh [--version VERSION | --source PATH | --ref REF] [--prefix PATH]

  (default)         Install the latest published release binary, even in a checkout.
  --version VERSION Install a specific release (for example v0.1.0).
  --source PATH     Build an existing checkout instead of installing a release.
  --ref REF         Download and build a GitHub branch, tag or commit.
  --prefix PATH     Install into PATH/bin (default: $HOME/.local).
  --help            Show this help.

Release installation needs curl, tar and shasum; Rust is not required.
Source builds additionally need Xcode Command Line Tools and the pinned Rust
version, through rustup or matching local Cargo and rustc binaries.
The installer never uses sudo, installs prerequisites, edits shell startup
files, or creates sandboxes. If no release exists, choose --source explicitly.
HELP
}

fail() {
  printf 'enclos installer: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [ -n "$install_staging_dir" ]; then
    rm -rf -- "$install_staging_dir"
  fi
  if [ -n "$install_temp_dir" ]; then
    rm -rf -- "$install_temp_dir"
  fi
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "$2"
}

make_temp() {
  if [ -z "$install_temp_dir" ]; then
    install_temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/enclos-install.XXXXXX")
  fi
}

# HTTPS only, including redirects, with bounded connection and transfer times.
fetch() {
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --fail --silent --show-error --location \
    --connect-timeout 15 --max-time 180 "$@"
}

valid_release_tag() {
  [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]]
}

install_release() {
  local version="$1" prefix="$2"
  local repository="https://github.com/victorbonnet/enclos"
  local latest_url tag asset checksum_digest checksum_asset checksum_extra actual_digest
  local release_binary binary_version
  asset="enclos-aarch64-apple-darwin.tar.gz"

  need curl "curl is required to download releases."
  need tar "tar is required to unpack releases."
  need shasum "shasum is required to verify releases."
  make_temp

  if [ "$version" = latest ]; then
    printf 'Finding the latest published enclos release…\n'
    latest_url=$(fetch --output /dev/null --write-out '%{url_effective}' "$repository/releases/latest") \
      || fail "Could not find the latest published release. Check $repository/releases and your connection. For a development build, use --source /path/to/checkout."
    case "$latest_url" in
      "$repository/releases/tag/"*) tag=${latest_url#"$repository/releases/tag/"} ;;
      *) fail "GitHub did not resolve a published release tag. See $repository/releases. Use --source /path/to/checkout for a development build." ;;
    esac
  else
    case "$version" in
      v*) tag="$version" ;;
      *) tag="v$version" ;;
    esac
  fi
  valid_release_tag "$tag" || fail "Invalid release version: $tag"

  printf 'Downloading enclos %s for Apple silicon…\n' "$tag"
  fetch --output "$install_temp_dir/$asset" "$repository/releases/download/$tag/$asset" \
    || fail "Could not download the $tag binary; nothing was installed."
  fetch --output "$install_temp_dir/$asset.sha256" "$repository/releases/download/$tag/$asset.sha256" \
    || fail "Could not download the $tag checksum; nothing was installed."

  read -r checksum_digest checksum_asset checksum_extra < "$install_temp_dir/$asset.sha256" \
    || fail "The release checksum file is invalid; nothing was installed."
  [[ "$checksum_digest" =~ ^[0-9a-f]{64}$ ]] && [ -z "$checksum_extra" ] \
    || fail "The release checksum file is invalid; nothing was installed."
  case "$checksum_asset" in
    "$asset" | "*$asset") ;;
    *) fail "The release checksum names an unexpected file; nothing was installed." ;;
  esac
  actual_digest=$(shasum -a 256 "$install_temp_dir/$asset")
  actual_digest=${actual_digest%% *}
  [ "$actual_digest" = "$checksum_digest" ] \
    || fail "The release checksum does not match; nothing was installed."

  # Extract only the expected executable to a file we create ourselves. Archive
  # paths, links, ownership and permissions are never installed on the host.
  [ "$(tar -tzf "$install_temp_dir/$asset")" = enclos ] \
    || fail "The release archive must contain only enclos; nothing was installed."
  release_binary="$install_temp_dir/enclos"
  tar -xOzf "$install_temp_dir/$asset" enclos > "$release_binary" \
    || fail "Could not unpack the release; nothing was installed."
  [ -s "$release_binary" ] || fail "The release executable is empty; nothing was installed."
  chmod 755 "$release_binary"
  binary_version=$("$release_binary" --version) \
    || fail "The release executable could not run; nothing was installed."
  [ "$binary_version" = "enclos ${tag#v}" ] \
    || fail "The release executable version does not match $tag; nothing was installed."

  [ ! -d "$prefix/bin/enclos" ] || fail "The destination is a directory: $prefix/bin/enclos"
  mkdir -p -- "$prefix/bin"
  install_staging_dir=$(mktemp -d "$prefix/bin/.enclos-install.XXXXXX")
  cp -- "$release_binary" "$install_staging_dir/enclos"
  # Stage on the destination filesystem so replacement is an atomic rename.
  mv -f -- "$install_staging_dir/enclos" "$prefix/bin/enclos"
  printf '%s\n' "$binary_version"
}

install_source() {
  local source_dir="$1" source_ref="$2" prefix="$3"
  local toolchain cargo_version rustc_version
  local cargo_command=()

  need xcode-select "Install Xcode Command Line Tools first: xcode-select --install"
  xcode-select -p >/dev/null 2>&1 || fail "Install Xcode Command Line Tools first: xcode-select --install"
  if ! command -v rustup >/dev/null 2>&1 && ! command -v cargo >/dev/null 2>&1; then
    fail "Install Rust through https://rustup.rs, then run this source build again."
  fi

  if [ -z "$source_dir" ]; then
    need curl "curl is required to download the source."
    need tar "tar is required to unpack the source."
    make_temp
    printf 'Downloading enclos source (%s)…\n' "$source_ref"
    fetch --output "$install_temp_dir/source.tar.gz" \
      "https://codeload.github.com/victorbonnet/enclos/tar.gz/$source_ref" \
      || fail "Source download failed. Check the ref and your connection; nothing was installed."
    source_dir="$install_temp_dir/source"
    mkdir -p -- "$source_dir"
    tar -xzf "$install_temp_dir/source.tar.gz" -C "$source_dir" --strip-components=1 \
      || fail "Could not unpack the source; nothing was installed."
  fi

  [ -d "$source_dir" ] || fail "Source directory does not exist: $source_dir"
  source_dir=$(CDPATH= cd -- "$source_dir" && pwd -P)
  [ -f "$source_dir/Cargo.toml" ] && [ -f "$source_dir/Cargo.lock" ] \
    && [ -f "$source_dir/rust-toolchain.toml" ] \
    || fail "Source must contain Cargo.toml, Cargo.lock and rust-toolchain.toml."
  toolchain=$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$source_dir/rust-toolchain.toml")
  [[ "$toolchain" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || fail "Expected a pinned numeric Rust version in rust-toolchain.toml."
  if command -v rustup >/dev/null 2>&1; then
    rustup run "$toolchain" cargo --version >/dev/null 2>&1 \
      || fail "Install the pinned Rust toolchain first: rustup toolchain install $toolchain --profile minimal"
    cargo_command=(rustup run "$toolchain" cargo)
  else
    need rustc "Rust $toolchain is required. Install it through https://rustup.rs."
    cargo_version=$(cargo --version | sed -n 's/^cargo \([0-9][0-9.]*\) .*/\1/p')
    rustc_version=$(rustc --version | sed -n 's/^rustc \([0-9][0-9.]*\) .*/\1/p')
    [ "$cargo_version" = "$toolchain" ] && [ "$rustc_version" = "$toolchain" ] \
      || fail "Cargo and rustc must match pinned Rust $toolchain. Install that toolchain through https://rustup.rs."
    cargo_command=(cargo)
  fi

  printf 'Building enclos with Rust %s. This may take a few minutes.\n' "$toolchain"
  "${cargo_command[@]}" install --locked --path "$source_dir" --root "$prefix" \
    || fail "Build or installation failed. See the Cargo error above; enclos state was not changed."
  [ -x "$prefix/bin/enclos" ] || fail "Cargo finished but did not create $prefix/bin/enclos."
  "$prefix/bin/enclos" --version || fail "The installed binary could not run."
}

main() {
  local source_dir="" source_ref="" release_version="latest" mode="release" mode_given=false
  local prefix="${HOME:?HOME must be set}/.local" macos_version macos_major

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --source | --ref | --version | --prefix)
        [ "$#" -ge 2 ] && [ -n "$2" ] || fail "$1 needs a value. Run with --help."
        if [ "$1" != --prefix ]; then
          [ "$mode_given" = false ] || fail "Use only one of --version, --source or --ref."
          mode_given=true
        fi
        case "$1" in
          --source) source_dir="$2"; mode=source ;;
          --ref) source_ref="$2"; mode=source ;;
          --version) release_version="$2" ;;
          --prefix) prefix="$2" ;;
        esac
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
  if [ -n "$source_ref" ]; then
    case "$source_ref" in
      -* | *[!a-zA-Z0-9._/-]*) fail "Invalid source ref: $source_ref" ;;
    esac
  fi
  if [ "$mode" = release ] && [ "$release_version" != latest ]; then
    case "$release_version" in v*) ;; *) release_version="v$release_version" ;; esac
    valid_release_tag "$release_version" || fail "Invalid release version: $release_version"
  fi

  [ "$(uname -s)" = Darwin ] || fail "This installer supports macOS only; Linux and Windows support is not available yet."
  [ "$(uname -m)" = arm64 ] || fail "An Apple silicon Mac and a native arm64 terminal are required. Intel Macs are not supported."
  macos_version=$(sw_vers -productVersion)
  macos_major=${macos_version%%.*}
  case "$macos_major" in '' | *[!0-9]*) fail "Cannot determine the macOS version." ;; esac
  [ "$macos_major" -ge 14 ] || fail "macOS 14 or later is required (found $macos_version)."
  [ "$(id -u)" != 0 ] || fail "Run this installer as your own user, without sudo."

  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  if [ "$mode" = release ]; then
    install_release "$release_version" "$prefix"
  else
    install_source "$source_dir" "$source_ref" "$prefix"
  fi

  printf '\nInstalled enclos in %s/bin.\n' "$prefix"
  case ":${PATH}:" in
    *":$prefix/bin:"*) ;;
    *) printf 'Add it to this terminal’s PATH:\n  export PATH=%q:"$PATH"\n\n' "$prefix/bin" ;;
  esac
  printf 'Next, run:\n  enclos init\n  enclos sandbox create lab\n\n'
  printf 'Hermes is installed separately with: enclos runtime install hermes --sandbox lab\n'
}

main "$@"
