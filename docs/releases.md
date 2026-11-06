# Releases

A release is a GitHub Release with three archives, each with its checksum beside it:

- `enclos-aarch64-apple-darwin.tar.gz`: for Apple silicon Macs running macOS 15 or later.
- `enclos-x86_64-unknown-linux-musl.tar.gz`: for Linux on x86_64.
- `enclos-aarch64-unknown-linux-musl.tar.gz`: for Linux on arm64 (aarch64), such as a Raspberry Pi with a 64-bit kernel.

Each archive holds one executable, `enclos`, at its root. Each `<archive>.sha256` holds the archive's SHA-256, in `shasum -a 256` format with the archive's name.

The Linux binaries are static, linked against musl rather than the host's glibc, so they load no library of the host's and run whatever glibc a distribution ships: Ubuntu 24.04 and 26.04, Debian 13 and 64-bit Raspberry Pi OS are the hosts enclos supports, and a 64-bit kernel with a 32-bit userland runs them too. What they do need of the host is outside the binary: systemd 254 or later, bubblewrap and user namespaces ([getting started](getting-started.md#linux-requirements)). musl reads no `/etc/nsswitch.conf`: the proxy resolves names through `/etc/hosts` and the servers in `/etc/resolv.conf` (on Ubuntu, systemd-resolved's local stub), not through NSS modules such as mDNS's for `.local` names, and a user missing from `/etc/passwd`, such as one from LDAP or systemd-homed, is recorded in the audit log as `unknown`.

[`install.sh`](../install.sh) always installs the latest release: the newest one published that is not a prerelease. It picks the archive for the host (on Linux, for the kernel's architecture), refuses to install when there is none, and never falls back to building from source. On Linux it warns, and still installs, when systemd is older than 254 or its version cannot be read, since enclos then refuses to start a session.

## Publishing one

1. Set the version in `Cargo.toml` (and `Cargo.lock`, with `cargo check`), write its notes in `docs/release-notes/<version>.md`, merge them, and wait for CI to pass on `main`.
2. Run the [manual end-to-end test](manual-e2e.md) with a build of that commit, on a Mac and on Linux.
3. Push a tag named `v` and that version, such as `v0.1.0` for `0.1.0`, on that commit.
4. Once it is published, put its notes on the release: `gh release edit v0.1.0 --notes-file docs/release-notes/0.1.0.md`. The workflow only generates a list of changes.

The tag runs [`release.yml`](../.github/workflows/release.yml) in three jobs. **build**, once for each archive, with read access only, so dependency build scripts never see a token that can publish:

- refuses a tag that does not match the version in `Cargo.toml`;
- builds with the lockfile and the toolchain pinned in `rust-toolchain.toml`, natively on each architecture: on a macOS 26 runner with deployment target 15.0 (so the binary runs on macOS 15 and later), and checks that the binary is arm64; on GitHub's `ubuntu-24.04` and `ubuntu-24.04-arm` runners for the musl targets, with `musl-gcc` for the bundled SQLite, and checks that the binary is static (no program interpreter, no shared library) and for its architecture; and checks that each prints `enclos <version>`;
- packs it with [`scripts/package-release.sh`](../scripts/package-release.sh), the same script the installer tests use, then unpacks and runs the result; on Linux, the packed binary's `enclos doctor` must find bubblewrap running on the runner.

**try**, for the Linux archives, on hosts that did not build them: Ubuntu 26.04, and Debian 13 in a container on each architecture. Each runs `enclos --version` and `enclos doctor`, which must find bubblewrap running. A container shares the runner's kernel, so it shows Debian 13's userland only.

**publish**, which builds nothing, once build and try have passed:

- checks that it received every archive and checksum, and each archive against its checksum;
- records a signed [build provenance attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations) for each archive;
- uploads every asset to a draft release, downloads and compares them, then publishes it. It creates the release only when GitHub says there is none, and stops on any other error.

A version with a suffix, such as `0.2.0-rc.1`, is published as a prerelease and never becomes the latest. A stable version becomes the latest, so publish stable versions in increasing order. If a step fails, the release stays a draft and rerunning the workflow replaces that draft's assets; it refuses to touch a published release.

A pull request that changes `release.yml`, the packaging script, the toolchain or the dependencies runs build and try as a dry run, and so can a manual run of the workflow: nothing is published. CI's `musl` job runs the test suite against the musl build on both architectures on every change.

## Checking one

The checksum sits in the same release as the archive, so it detects a corrupted download, not a replaced release. The attestation says which workflow run, commit and repository built the archive:

```bash
gh attestation verify enclos-aarch64-apple-darwin.tar.gz --repo victorbonnet/enclos
```

The same works for each Linux archive.

The macOS binary is not signed with an Apple Developer ID or notarized. `curl` does not mark what it downloads for Gatekeeper, so the installed binary runs without a prompt; a browser download would be blocked.

## The website

[`pages.yml`](../.github/workflows/pages.yml) publishes [`site/`](../site/) and `install.sh` to <https://enclos.dev/> on every change to them on `main`, so the install command always serves the installer on `main`. It needs the repository's Pages source set to GitHub Actions and its custom domain (`enclos.dev`) set under Settings → Pages, once each. The `victorbonnet.github.io/enclos` address redirects there.
