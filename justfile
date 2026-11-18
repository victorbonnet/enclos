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

# Node 24; set ENCLOS_OPENCLAW_PACKAGE to include installed SDK probes.
openclaw-channel:
    node channels/openclaw/scripts/build.mjs --check
    node --test channels/openclaw/tests/*.test.js

# Needs gitleaks on the PATH; CI runs it in the `secrets` job.
gitleaks-rule:
    sh tests/gitleaks_rule.sh

openclaw-launchers:
    node --test src/runtime/openclaw/*.test.mjs

ci: fmt clippy test deny hermes-plugin hermes-transfer openclaw-launchers openclaw-channel
