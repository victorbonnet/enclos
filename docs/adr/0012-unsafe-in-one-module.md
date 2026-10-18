---
status: accepted
---

# `unsafe` lives in one module

`unsafe_code` is denied crate-wide. The only exception is a dedicated `sys` module that wraps the operating system calls the backends need, and every `unsafe` block there must have a `// SAFETY:` comment (enforced by clippy's `undocumented_unsafe_blocks`). Safe wrapper crates are preferred over writing `unsafe` ourselves, so the module should stay small. This keeps the code that reviewers must read most carefully in one place.
