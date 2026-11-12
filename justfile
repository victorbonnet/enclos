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

# Needs gitleaks on the PATH; CI runs it in the `secrets` job.
gitleaks-rule:
    sh tests/gitleaks_rule.sh

openclaw-launchers:
    node --test src/runtime/openclaw/*.test.mjs

ci: fmt clippy test deny hermes-plugin openclaw-launchers
