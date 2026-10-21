fmt:
    cargo fmt --all -- --check

clippy:
    cargo clippy --locked --all-targets --all-features -- -D warnings

test:
    cargo test --locked --all-features

deny:
    cargo deny check

# Needs gitleaks on the PATH; CI runs it in the `secrets` job.
gitleaks-rule:
    sh tests/gitleaks_rule.sh

ci: fmt clippy test deny
