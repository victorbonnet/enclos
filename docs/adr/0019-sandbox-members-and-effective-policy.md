---
status: accepted
---

# enclos tracks every process in a sandbox and the policy it started under

Every process running inside a sandbox is one of its members: interactive sessions, agent processes, browsers and helpers the agent starts, installers, and all their children. enclos records each session with the policy snapshot and compiled policy it was started with, and keeps track of its members. Stopping a sandbox stops every member, with a grace period, and checks that none remain; restarting stops every member and starts the sandbox's services again under the active policy. If members survive a stop, enclos reports them and marks the sandbox as failed instead of claiming it stopped.

A process keeps the restrictions it was started with. Network rules are enforced by the proxy and follow the active snapshot live; file, program and resource rules are fixed at launch. `enclos sandbox show` displays both versions for each session and flags a session whose file, program or resource rules differ from the active snapshot's, so an older process is never presented as running under a newer restriction.

## Consequences

- On Linux, members are the processes in the sandbox's cgroup. On macOS there is no equivalent without privileged APIs. The milestone 1 prototype showed that a process group misses a child that calls `setsid`, and that a per-sandbox marker checked with `sandbox_check` on another process cannot recognize members. Milestone 1 uses process groups, the parent chain and members recorded while a session runs (design §8); a mechanism that also covers a double fork is decided by experiments in a disposable macOS VM.
- Stopping signals only processes enclos has shown to be members. A search that has not been shown to find only members (a refuted marker, a name match) never chooses what to signal.
- A process that escapes tracking but stays inside Seatbelt keeps its sandbox restrictions, so a tracking gap is a lifecycle bug (it may keep an older snapshot's rules), not a way out of the sandbox. `enclos state check` looks for such processes.
- An interactive session cannot be restarted for the user. A restart ends it and tells the user to reconnect.
