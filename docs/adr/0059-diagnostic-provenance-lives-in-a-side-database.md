---
status: proposed
---

# Diagnostic provenance lives in a side database

`policy test` sends real connections through a sandbox's proxy, and their refusals land in the network log like any other. The mobile inbox ([0046](0046-the-hosts-person-approves-sandbox-policy-scopes-from-the-phone.md)) must not turn them into policy requests, while `enclos net denied` must keep them: the log needs to say which rows a host diagnostic run made.

Decision (proposed): that provenance is kept in `probe-sources.db`, a second SQLite file beside the state database (mode 0600, in enclos's protected data folder), which the state store attaches when it records a tagged connection or lists refusals for the inbox. It holds the runs the host registered (a random tag, its sandbox, an expiry within the hour) and the network log rows a run made, keyed by the row's id, sandbox and time. The state database's schema, its migrations and `net_events` are unchanged. A missing, unwritable or unreadable side file only means no row counts as diagnostic: `policy test` then runs its probes untagged, every refusal stays a request candidate, and nothing about enforcement or the log changes. Each new run drops the provenance of log rows that are gone, such as a removed sandbox's. The tag travels on the probes' command lines inside the sandbox, so another process of that sandbox could read it while a run lasts and mark its own refusals diagnostic until the run ends: that only keeps them out of the inbox, as they are still refused and logged.

Considered options: an appended migration adding a column or a table to the state database. It is the usual way (never edit a released migration, append one), but it raises the schema version, and an enclos that predates it refuses a newer schema, so going back to a released enclos after trying this one would lose the use of the whole state database for a piece of inbox bookkeeping.

Reason: the provenance is advisory and disposable, unlike the state database, so it should not decide which enclos can open that database. The cost is a second file to back up, protect and remove with the data folder, and a join across attached databases. If provenance ever has to be durable or shared with other state, it moves into the state database with a migration and this ADR is superseded.
