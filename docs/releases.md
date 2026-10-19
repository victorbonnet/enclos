# Publishing releases

The installer downloads the latest published stable GitHub Release by default. It requires a prebuilt binary; it does not build from the repository or fall back to a source build when release assets are missing.

The release workflow currently packages Apple silicon Macs running macOS 14 or later. Each release must contain both assets:

- `enclos-aarch64-apple-darwin.tar.gz`, containing one executable named `enclos` at the archive root.
- `enclos-aarch64-apple-darwin.tar.gz.sha256`, containing the archive's SHA-256 checksum in `shasum -a 256` format, including the archive filename.

To publish, merge the installer and release workflow, set the package version in `Cargo.toml` and `Cargo.lock`, and wait for CI to pass on the release commit. A maintainer can then push a tag named `v` followed by that exact package version. For example, package version `0.1.0` requires tag `v0.1.0`.

The tag push runs `.github/workflows/release.yml`. It uses the Rust toolchain pinned in `rust-toolchain.toml`, builds with the lockfile on macOS 14 with deployment target 14.0, checks the binary's architecture and version, and verifies the archive and checksum. It uploads assets to a draft release, downloads and compares them, then publishes. Stable releases are marked Latest, so publish stable versions in increasing order. Versions with a prerelease suffix are published as prereleases and do not become Latest.

If upload or verification fails, the release stays a draft. Rerunning the failed workflow replaces only that draft's assets and retries verification. The workflow refuses to replace assets on an already published release.

The public installation command needs `install.sh` on `main` and at least one published release with these assets. Adding the workflow alone does not make that command available. Until the first release is published, use the source build instructions in [Getting started](getting-started.md).

The archive and its checksum are hosted in the same GitHub Release; the checksum detects corruption, rather than providing an independent publisher signature. This workflow does not configure Apple Developer ID signing or notarization.
