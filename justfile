fmt:
    cargo fmt --all -- --check

clippy:
    cargo clippy --locked --all-targets --all-features -- -D warnings

test:
    cargo test --locked --all-features

deny:
    cargo deny check

ci: fmt clippy test deny
