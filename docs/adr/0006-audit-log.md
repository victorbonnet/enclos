# Audit log: hash-chained JSON Lines outside the project

Each session appends records to a JSON Lines audit log in the user's state directory (`$XDG_STATE_HOME/enclos` on Linux, `~/Library/Application Support/enclos` on macOS). Every record holds the SHA-256 of the previous record, and `enclos audit verify` checks the chain. The sandbox is always denied write access to this directory, whatever the policy says.

## Consequences

- The chain detects edits and deletions in the middle of the log. It cannot detect the most recent records being removed, and someone who can write the file outside a sandbox can rewrite the whole chain. Protection against the agent comes from the sandbox; the chain catches corruption and naive tampering.
- Stronger guarantees (signing records, or anchoring the chain head somewhere the user cannot write) can be added later without changing the format.
