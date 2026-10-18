# enclos

## Versions and dependencies

Your training data is older than today. Never write a version number from memory.

- Crates: add them with `cargo add <name>` (it picks the latest) or check `cargo search <name> --limit 1`. Don't hand-edit versions in Cargo.toml.
- GitHub Actions: check `git ls-remote --tags https://github.com/<owner>/<repo>`, use the latest major, and pin it to the commit SHA with the tag in a comment (`uses: actions/checkout@<sha> # v7`).
- Rust: check the latest stable with `git ls-remote --tags https://github.com/rust-lang/rust` and update `rust-toolchain.toml`, the only place the version is set. CI installs from it with `rustup toolchain install`.
- After any version change, run `just ci`. It includes `cargo deny check`, which rejects crates with known advisories, licenses not listed in `deny.toml`, or sources other than crates.io. Ask before adding a license or an advisory exception to `deny.toml`.
- `unsafe_code` is denied crate-wide. Ask before adding `#[allow(unsafe_code)]`.
- In the PR description, list each version you chose and how you checked it.

Dependabot also opens weekly update PRs for crates, actions and the Rust toolchain (see `.github/dependabot.yml`).
