fmt:
    cargo fmt --all -- --check

clippy:
    cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

test:
    cargo test --locked --workspace --all-features

deny:
    cargo deny check

# Needs gitleaks on the PATH; CI runs it in the `secrets` job.
gitleaks-rule:
    sh tests/gitleaks_rule.sh

ci: fmt clippy test deny
