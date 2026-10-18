---
status: accepted
---

# No daemon: sandboxes run as launchd or systemd user services

There is no enclos daemon. The CLI is a thin layer over a core library, and a running sandbox is a set of ordinary user services that the core installs: one for the sandbox's proxy (`enclos.<sandbox>.proxy`) and one per running profile (`enclos.<sandbox>.<profile>`), managed by launchd on macOS and systemd user units on Linux. The operating system already restarts, logs and starts these at login, so enclos does not need a long-running process of its own. Interactive sessions (`enclos connect`, `enclos exec`) run in the user's terminal and use the same proxy service.

## Consequences

- On macOS, services are launchd agents in the user's login session, so sandboxes run while the user is logged in. Running while logged out is not a goal for now.
- The first milestone runs the proxy and every profile as launchd agents while the user is logged in, alongside interactive sessions. Messaging comes later.
- The web UI, MCP server and scripts are clients of the same core library, not of a server.
- State can drift from reality (a unit removed by hand, a crash mid-command). `enclos state check` compares records with the service units, processes and files, and `enclos state repair` fixes them.
