# Releases

A release is a GitHub Release with two assets, built for Apple silicon Macs running macOS 14 or later:

- `enclos-aarch64-apple-darwin.tar.gz`: one executable, `enclos`, at the archive's root.
- `enclos-aarch64-apple-darwin.tar.gz.sha256`: the archive's SHA-256, in `shasum -a 256` format with the archive's name.

[`install.sh`](../install.sh) always installs the latest release: the newest one published that is not a prerelease. It refuses to install when there is none, and never falls back to building from source.

## Publishing one

1. Set the version in `Cargo.toml` (and `Cargo.lock`, with `cargo check`), merge it, and wait for CI to pass on `main`.
2. Push a tag named `v` and that version, such as `v0.1.0` for `0.1.0`, on that commit.

The tag runs [`release.yml`](../.github/workflows/release.yml). With the toolchain pinned in `rust-toolchain.toml`, on macOS 14 with deployment target 14.0, it:

- refuses a tag that does not match the version in `Cargo.toml`;
- builds with the lockfile and checks that the binary is arm64 and prints `enclos <version>`;
- packs the archive, writes its checksum, and checks both by unpacking and running the result;
- records a signed [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations) for the archive;
- uploads both assets to a draft release, downloads and compares them, then publishes it.

A version with a suffix, such as `0.2.0-rc.1`, is published as a prerelease and never becomes the latest. A stable version becomes the latest, so publish stable versions in increasing order. If a step fails, the release stays a draft and rerunning the workflow replaces that draft's assets; it refuses to touch a published release.

## Checking one

The checksum sits in the same release as the archive, so it detects a corrupted download, not a replaced release. The attestation says which workflow run, commit and repository built the archive:

```bash
gh attestation verify enclos-aarch64-apple-darwin.tar.gz --repo victorbonnet/enclos
```

The binary is not signed with an Apple Developer ID or notarized. `curl` does not mark what it downloads for Gatekeeper, so the installed binary runs without a prompt; a browser download would be blocked.

## The website

[`pages.yml`](../.github/workflows/pages.yml) publishes [`site/`](../site/) and `install.sh` to <https://victorbonnet.github.io/enclos/> on every change to them on `main`, so the install command always serves the installer on `main`. It needs the repository's Pages source set to GitHub Actions, once.
