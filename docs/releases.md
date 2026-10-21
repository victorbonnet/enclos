# Releases

A release is a GitHub Release with two assets, built for Apple silicon Macs running macOS 15 or later:

- `enclos-aarch64-apple-darwin.tar.gz`: one executable, `enclos`, at the archive's root.
- `enclos-aarch64-apple-darwin.tar.gz.sha256`: the archive's SHA-256, in `shasum -a 256` format with the archive's name.

[`install.sh`](../install.sh) always installs the latest release: the newest one published that is not a prerelease. It refuses to install when there is none, and never falls back to building from source.

## Publishing one

1. Set the version in `Cargo.toml` (and `Cargo.lock`, with `cargo check`), merge it, and wait for CI to pass on `main`.
2. Push a tag named `v` and that version, such as `v0.1.0` for `0.1.0`, on that commit.

The tag runs [`release.yml`](../.github/workflows/release.yml) in two jobs. **build**, with read access only, so dependency build scripts never see a token that can publish:

- refuses a tag that does not match the version in `Cargo.toml`;
- builds with the lockfile and the toolchain pinned in `rust-toolchain.toml`, on a macOS 26 runner with deployment target 15.0 (so the binary runs on macOS 15 and later), and checks that the binary is arm64 and prints `enclos <version>`;
- packs it with [`scripts/package-release.sh`](../scripts/package-release.sh), the same script the installer tests use, then unpacks and runs the result.

**publish**, which builds nothing:

- checks the assets it received against their checksum;
- records a signed [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations) for the archive;
- uploads both assets to a draft release, downloads and compares them, then publishes it. It creates the release only when GitHub says there is none, and stops on any other error.

A version with a suffix, such as `0.2.0-rc.1`, is published as a prerelease and never becomes the latest. A stable version becomes the latest, so publish stable versions in increasing order. If a step fails, the release stays a draft and rerunning the workflow replaces that draft's assets; it refuses to touch a published release.

## Checking one

The checksum sits in the same release as the archive, so it detects a corrupted download, not a replaced release. The attestation says which workflow run, commit and repository built the archive:

```bash
gh attestation verify enclos-aarch64-apple-darwin.tar.gz --repo victorbonnet/enclos
```

The binary is not signed with an Apple Developer ID or notarized. `curl` does not mark what it downloads for Gatekeeper, so the installed binary runs without a prompt; a browser download would be blocked.

## The website

[`pages.yml`](../.github/workflows/pages.yml) publishes [`site/`](../site/) and `install.sh` to <https://victorbonnet.github.io/enclos/> on every change to them on `main`, so the install command always serves the installer on `main`. It needs the repository's Pages source set to GitHub Actions, once.
