---
status: proposed
---

# Compiled Seatbelt policies start from deny by default

Compiled Seatbelt policies start from `(deny default)` and allow only what the agent needs, instead of `(allow default)` with deny rules for writes, sensitive reads and the network. A deny-by-default policy cannot leak through an operation nobody thought to deny, and the agent sandbox escapes reported in 2026 targeted allow-by-default Seatbelt configurations.

## Before this is accepted

The milestone 2 prototype must show that Hermes (Python with `httpx` and `requests`), Telegram polling and model calls work under it, and list the `mach-lookup`, `sysctl`, `iokit` and `file-read` allowances that takes. If the list is too large to review, enclos keeps allow-by-default with deny rules and this ADR is rejected.
