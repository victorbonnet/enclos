---
status: proposed
---

# A connection the network log cannot record is refused

The network log is where the user sees where a sandbox's data went, and in `public` mode it is the only record of it ([0025](0025-public-web-by-default-for-assistants.md)). Today the proxy writes each connection's record to `state.db` when it decides on it, and if that write fails (a full disk, a database it cannot write) it says so in its service log and serves the connection anyway. So the log is complete only while the database can be written, and a sandbox that fills the disk can then connect without a trace.

Proposed: the proxy refuses a connection whose record it could not write, with `503` and a message that names the cause, and still reports the failure in its service log. A connection the proxy allowed shows in the log, or did not happen.

## Considered options

- **Fail open (today).** A full disk or a database that cannot be written leaves the agent online, and the gap shows only in the service log. The log can no longer be trusted to show everything, in the moment it matters most.
- **Fail closed (recommended).** The log is complete: every connection served has a record. In exchange, a full disk or a database that cannot be written stops the sandbox's network until it is fixed; the agent sees the refusals, and `enclos logs <sandbox>` says why. The proxy already fails closed when it cannot read the policy (`policy-unreadable`), so both failures of `state.db` would behave alike.

The update of a record when its connection closes (bytes and duration) stays best effort either way: the connection is already served.

## Consequences to decide

- **Retention.** Nothing removes records from `net_events` while the sandbox exists, so a busy or looping agent grows `state.db` without limit, and under fail closed a full disk stops its network. Options: a cap on records per sandbox, an age limit (for example 30 days), or both, removing the oldest first, with `enclos status` showing the log's size.
- **Coalescing.** A loop retrying a refused destination writes one record per try. Repeated denials of the same destination and reason within a short window could update one record's count and last time instead, as `enclos net denied` already groups them.
- Until a test with a log store that refuses writes shows the refusal, the design keeps describing fail open.
