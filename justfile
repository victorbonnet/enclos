fmt:
    cargo fmt --all -- --check

clippy:
    cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

test:
    cargo test --locked --workspace --all-features

deny:
    cargo deny check

# The Hermes channel plugin (standard library only)
hermes-plugin:
    python3 -I -m unittest discover -s channels/hermes/tests

# Complete Hermes data transfer (standard library only)
hermes-transfer:
    python3 -I -m unittest discover -s src/runtime/hermes/tests

# Needs gitleaks on the PATH; CI runs it in the `secrets` job.
gitleaks-rule:
    sh tests/gitleaks_rule.sh

ci: fmt clippy test deny hermes-plugin hermes-transfer
