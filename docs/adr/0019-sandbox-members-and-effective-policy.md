---
status: accepted
---

# enclos tracks every process in a sandbox and the policy it started under

Every process running inside a sandbox is one of its members: interactive sessions, agent processes, browsers and helpers the agent starts, installers, and all their children. enclos records each session with the policy snapshot and compiled policy it was started with, and keeps track of its members. Stopping a sandbox stops every member, with a grace period, and checks that none remain; restarting stops every member and starts the sandbox's services again under the active policy. If members survive a stop, enclos reports them and marks the sandbox as failed instead of claiming it stopped.

A process keeps the restrictions it was started with. Network rules are enforced by the proxy and follow the active snapshot live; file, program and resource rules are fixed at launch. `enclos sandbox show` displays both versions for each session and flags sessions running under an older snapshot, so an older process is never presented as running under a newer restriction.

## Consequences

- On Linux, members are the processes in the sandbox's cgroup. On macOS there is no equivalent without privileged APIs; the mechanism (process groups set up by `enclos launch`, a per-sandbox marker checked through the sandbox API, a scan by parent chain, or a combination) is decided by the milestone 2 prototype.
- A process that escapes tracking but stays inside Seatbelt keeps its sandbox restrictions, so a tracking gap is a lifecycle bug (it may keep an older snapshot's rules), not a way out of the sandbox. `enclos state check` looks for such processes.
- An interactive session cannot be restarted for the user. A restart ends it and tells the user to reconnect.
