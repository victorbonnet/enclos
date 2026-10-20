# enclos

enclos creates sandboxes, installs agent runtimes in them and runs agents there, and keeps a state and an audit log of every command that changes them. It manages only the sandboxes it creates.

## Language

**Host**:
A machine where the enclos CLI runs and keeps its state. Each host is managed locally, by running enclos on it.
_Avoid_: machine, node, server

**Sandbox**:
A named, persistent isolated environment created by enclos, with its own backend, policy, home folder and lifecycle state. The sandbox is the permission boundary.
_Avoid_: container, jail, environment, enclosure

**Backend**:
The isolation technology a sandbox is built on, such as Seatbelt or bubblewrap.
_Avoid_: driver, provider, engine

**Policy**:
What a sandbox may do with files, programs, network, resources and secrets. Built on a template, and stored as policy snapshots.
_Avoid_: rules, permissions, config. A backend's file generated from a policy (such as a Seatbelt `.sb` file) is a compiled policy, never a "profile".

**Compiled policy**:
A backend's own file generated from a policy snapshot, such as a Seatbelt `.sb` file, which the backend applies to a session.
_Avoid_: profile, sandbox profile, rules file

**Policy snapshot**:
One immutable, fully resolved version of a sandbox's policy, identified by its content hash and recording the inputs it was resolved from.
_Avoid_: revision, policy file

**Network mode**:
Which destinations a sandbox may reach: `public`, any public address on the web ports as well as what its policy lists, or `allowlist`, only what its policy lists.
_Avoid_: open mode, internet access

**Active policy**:
The policy snapshot every new session in a sandbox starts under.
_Avoid_: current policy, live policy

**Pending policy**:
A policy snapshot saved for a sandbox because the user declined the restart it needs. It applies to nothing until the user applies it.
_Avoid_: draft, staged policy

**Template**:
A reusable policy that a sandbox's policy extends, such as `minimal`, `mcp-only`, `assistant` or `coding`.
_Avoid_: preset, base policy

**Runtime**:
The software installed in a sandbox to run its agents, such as Hermes, Claude Code or Codex. A sandbox holds at most one runtime.
_Avoid_: agent (for the software), platform, program

**Agent**:
A named identity of the sandbox's runtime, with its own configuration, memory, skills, sessions and channels. It shares the sandbox's runtime, policy, proxy and secrets. It is not a process and not a permission boundary: the runtime adapter decides how many processes run it, and the sandbox is the boundary. A runtime may have a built-in agent; a runtime without several agents has only its built-in one.
_Avoid_: profile (Hermes's word for it), instance, persona, bot

**Built-in agent**:
The agent a runtime always has once it is installed in a sandbox, such as Hermes's `default`. It exists as long as the runtime, and is not one enclos creates or removes.
_Avoid_: main agent, root profile, default profile

**Untracked agent**:
An agent the runtime has in a sandbox that enclos has no record of, usually made inside the sandbox with the runtime's own commands. It becomes a tracked agent when added.
_Avoid_: orphan, rogue agent, unknown agent

**Session**:
A single use of a sandbox from start to end: an interactive `connect`, an `exec`, or a service, with every process it starts. A session records the policy snapshot it started under.
_Avoid_: run, job, instance

**Secret**:
A value such as an API key or a bot token that enclos keeps on the host, outside every sandbox, and grants to a whole sandbox through its policy. The runtime's own login is not a secret: it stays in the sandbox home.
_Avoid_: credential (for a secret), key

**Service**:
A background process of a sandbox that the host's service manager runs while the user is logged in: the sandbox's proxy, or one its runtime declares under a stable name. Services belong to the sandbox, not to its agents.
_Avoid_: daemon, job, unit (the service manager's words), agent service

**Member**:
Any process running inside a sandbox, whichever session started it, including helpers, browsers and installers.
_Avoid_: child, worker

**Workspace**:
A host folder outside the sandbox home that a policy lets the sandbox write, such as a coding agent's project folder.
_Avoid_: mount, share, volume

**Protected path**:
A path enclos always denies to sandboxes whatever the policy says, such as the audit log, the state database and other sandboxes.
_Avoid_: system path, reserved path

**Escape probe**:
A check run by `enclos policy test` from inside a sandbox that tries one way out and must fail. It counts as closed only when its control, a harmless check run outside the sandbox, shows the same route works there (or, for the proxy, when the proxy refuses it); otherwise it is inconclusive.
_Avoid_: test case, attack

**Audit entry**:
The record of one state-changing command: time, user, host, command, state before and after, and result. Audit entries form an append-only, hash-chained audit log.
_Avoid_: event, log line
