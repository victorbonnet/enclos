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
_Avoid_: rules, permissions, config

**Compiled policy**:
A backend's own file generated from a policy snapshot, such as a Seatbelt `.sb` file, which the backend applies to a session.
_Avoid_: profile, sandbox profile, rules file

**Baseline**:
What a compiled policy does with every operation no rule of it names: refuse it (deny by default) or allow it (allow by default). On Seatbelt, `(deny default)` or `(allow default)`.
_Avoid_: default policy, fallback

**Comparison baseline**:
The `(allow default)` baseline, compiled only to compare against deny by default.

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
A named identity of the sandbox's runtime, with its own configuration, memory, skills, sessions and channels. It shares the sandbox's runtime, policy, proxy and secrets, and may be granted secrets of its own, such as its bot's token. It is not a process and not a permission boundary: the runtime adapter decides how many processes run it, and the sandbox is the boundary. A runtime may have a built-in agent; a runtime without several agents has only its built-in one.
_Avoid_: profile (Hermes's word for it), instance, persona, bot (for an agent)

**Built-in agent**:
The agent a runtime always has once it is installed in a sandbox, such as Hermes's `default`. It exists as long as the runtime, and is not one enclos creates or removes.
_Avoid_: main agent, root profile, default profile

**Untracked agent**:
An agent the runtime has in a sandbox that enclos has no record of, usually made inside the sandbox with the runtime's own commands. It becomes a tracked agent when added.
_Avoid_: orphan, rogue agent, unknown agent

**Export**:
An archive of an agent made by its runtime's own command, such as `hermes profile export`. An agent comes into a sandbox from the host only by importing an export with the runtime's own import; enclos has no archive format of its own.
_Avoid_: backup, bundle, snapshot (a policy's word)

**Session**:
A single use of a sandbox from start to end: an interactive `connect`, an `exec`, or a service, with every process it starts. A session records the policy snapshot it started under.
_Avoid_: run, job, instance

**Gone session**:
A session whose end is not recorded though none of its members runs any more, because nothing was left to record it, as after a crash or a restart of the Mac.
_Avoid_: stale session, zombie session

**Secret**:
A value such as an API key or a bot token that enclos keeps on the host, outside every sandbox, and grants to a whole sandbox, or to one agent of it, through its policy. The runtime's own login is not a secret: it stays in the sandbox home.
_Avoid_: credential (for a secret), key

**Secret store**:
Where enclos keeps secrets' values on the host, outside every sandbox: the macOS Keychain, the Secret Service through libsecret, or the file store, a `0600` file for a host where no Secret Service answers.
_Avoid_: vault, keystore

**Channel**:
A messaging service, such as Telegram, through which a sandbox answers people.
_Avoid_: platform, integration

**Bot**:
The account on a channel through which the sandbox's runtime answers people, such as a Telegram bot.
_Avoid_: agent (an agent is the runtime's identity, not the account)

**Service**:
A background process of a sandbox that the host's service manager runs while the user is logged in: the sandbox's proxy, or one its runtime declares under a stable name. Services belong to the sandbox, not to its agents.
_Avoid_: daemon, job, unit (the service manager's words), agent service

**Relay**:
On Linux, the part of enclos inside a session that listens on the session's own 127.0.0.1 and passes each connection to a Unix socket outside it: the sandbox's proxy, or its runtime's listening service.
_Avoid_: forwarder, port forward, tunnel (the proxy's word for a connection it carries)

**Holder**:
On Linux, the process that keeps a sandbox's network namespace in being while its proxy service runs, so that every session of the sandbox can join it.

**Member**:
Any process running inside a sandbox, whichever session started it, including helpers, browsers and installers.
_Avoid_: child, worker

**Scope**:
On Linux, the unit of the user's systemd manager that holds one session's processes in a cgroup of their own.

**Slice**:
On Linux, the unit of the user's systemd manager that groups the scopes of one sandbox's sessions.

**Workspace**:
A host folder outside the sandbox home that a policy lets the sandbox write, such as a coding agent's project folder.
_Avoid_: mount, share, volume

**Protected path**:
A path enclos always denies to sandboxes whatever the policy says, such as the audit log, the state database and other sandboxes.
_Avoid_: system path, reserved path

**Escape probe**:
A check run by `enclos policy test` from inside a sandbox that tries one way out and must fail. It counts as closed only when its control, a harmless check run outside the sandbox, shows the same route works there (or, for a call the filesystem itself always refuses, that the call gets as far as the filesystem there; for the proxy, when the proxy refuses it); otherwise it is inconclusive.
_Avoid_: test case, attack

**Audit entry**:
The record of one state-changing command: time, user, host, command, state before and after, and result. Audit entries form an append-only, hash-chained audit log.
_Avoid_: event, log line
