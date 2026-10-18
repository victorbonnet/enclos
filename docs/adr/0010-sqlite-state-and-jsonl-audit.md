---
status: accepted
---

# State in SQLite, audit in hash-chained JSON Lines

Sandbox records, policy versions, the network log and denials live in a SQLite database. The audit log is a separate append-only JSON Lines file with one entry per state-changing command, where each entry holds the SHA-256 of the previous one, and `enclos audit verify` checks the chain. Both live under `~/.enclos/` (`$XDG_DATA_HOME/enclos` on Linux).

Whatever the policy says, the policy compiler always denies the sandbox write access anywhere in `~/.enclos` except its own `home/`, and read access to `state.db`, `audit.jsonl`, `config.toml`, the file secret store and other sandboxes' folders. These rules are added last, so no policy rule overrides them, and `enclos policy validate` rejects a policy that tries to grant them, including through a broad path such as `~` or a workspace that contains `~/.enclos`. Without this, a sandbox could rewrite its own audit trail or read other sandboxes' policies, network logs and secrets.

## Considered options

- **Audit log in SQLite:** one store, but a plain append-only file is easier to read, ship elsewhere and verify with standard tools.

## Consequences

- Every state-changing command takes a lock, records its intent, does the work, then records the result. A crash leaves an unfinished entry for `enclos state check` to find.
- The chain detects edits and deletions in the middle of the log, but not removal of the latest entries, and someone who can write the file outside a sandbox can rewrite the whole chain. Anchoring or signing the chain head can be added later without changing the format.
