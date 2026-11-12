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

**Degraded control**:
A control of a backend that depends on the host, such as Landlock or the memory controller, which the backend runs without where the host lacks it, saying what is not enforced, the risk and the fix.
_Avoid_: missing feature, fallback mode

**Policy**:
What a sandbox may do with files, programs, network, resources and secrets. Built on a template, and stored as policy snapshots.
_Avoid_: rules, permissions, config

**Policy request**:
A proposed scope of access for a sandbox, which the host's person may approve or deny. Approving it changes the sandbox's policy for all of its agents.
_Avoid_: tool approval (a runtime's own decision), command approval

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
A reusable policy that a sandbox's policy extends, such as `minimal`, `assistant` or `coding`.
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

**Agent display name**:
The human-readable name shown for an agent, shared by the people who can reach it and independent of the identifier used to address it.
_Avoid_: nickname, alias, profile name

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

**Bridge**:
The service of an install that the mobile app reaches through its transport, and that talks to each agent's channel plugin inside its sandbox.
_Avoid_: daemon, server, gateway (the runtime's word), relay (the proxy's)

**Transport**:
What puts the bridge, which listens on the host's loopback only, on a network the person's devices are on, and tells the bridge who each caller is. Tailscale is the only one for now.
_Avoid_: tunnel (the proxy's word), front, VPN (one kind of transport)

**Paired device**:
A phone or other device that a bridge accepts, because the host's user paired it there and it holds the key it was paired with.
_Avoid_: client, session (a sandbox's word)

**Person**:
Someone the bridge knows by the login their transport gives (a tailnet login with Tailscale), who talks to agents from their paired devices. The host's user is one.
_Avoid_: user (for anyone but the host's user), member (a process's word), tenant, guest

**Share**:
What lets a person other than the host's user see and talk to a sandbox or one agent of it through the bridge, with the abilities it names. It isolates nothing.
_Avoid_: grant (a secret's or policy's word), permission

**Conversation**:
One exchange with an agent through the mobile app, started by one person, who owns it. The runtime keeps it apart from the agent's other conversations.
_Avoid_: session (a sandbox's word), chat, thread

**Archived conversation**:
A conversation other than Home that its owner has set aside from the active list, with its identity and history kept until restored.
_Avoid_: deleted conversation, closed conversation

**Home conversation**:
An agent's permanent conversation for messages that have no other destination, including scheduled output and the runtime's notices.

**Group**:
A conversation between one person and several agents of one sandbox, which the bridge keeps and whose turns it runs. Each agent answers in turn, when addressed by its handle (`@main`), by `@all`, or by another member.
_Avoid_: room (Hermes's word), channel (a messaging account), team

**Artefact**:
A page an agent makes for a person to open in the app from its conversation.
_Avoid_: artifact, app (for a generated page)

**Agent photo**:
The picture that stands for an agent in the app, the same for every person shown the agent. The host's person chooses it; without one, the agent shows its initial.
_Avoid_: profile picture, icon, avatar (the protocol's word, in `agent.avatar` and its fields, and nowhere else)

**Agent command**:
A command a person types to an agent's runtime in a conversation, `/` and its name, such as `/new` or `/model`. It is the runtime's: the bridge lists an agent's commands for the app, and passes them on as messages, without running them.
_Avoid_: command alone (enclos's own), shortcut, action

**Routine**:
A task an agent's runtime keeps and runs on a schedule, with instructions and an optional place to deliver its result.
_Avoid_: automation, scheduled session, cron job (except when naming a runtime's own feature)

**Question**:
An agent's request for a choice or missing information in a conversation, which that conversation's owner may answer or skip.
_Avoid_: approval (a policy request has different authority)

**Service**:
A background process of a sandbox that the host's service manager runs while the user is logged in: the sandbox's proxy, on Linux its namespace holder, or one its runtime declares under a stable name. Services belong to the sandbox, not to its agents.
_Avoid_: daemon, job, unit (the service manager's words), agent service

**Relay**:
On Linux, the part of enclos that passes connections between 127.0.0.1 in a sandbox's network namespace and a Unix socket outside it: to the sandbox's proxy, or from the host to its runtime's listening service.
_Avoid_: forwarder, port forward, tunnel (the proxy's word for a connection it carries)

**Namespace holder**:
On Linux, the process that keeps a sandbox's network namespace in being, so that every session of the sandbox can join it.

**Member**:
Any process running inside a sandbox, whichever session started it, including helpers, browsers and installers.
_Avoid_: child, worker

**Marker**:
A file enclos gives a program as a session starts, which the program and everything it starts hold open, so that holding it proves a process is that session's member.

**Scope**:
On Linux, the unit of the user's systemd manager that holds one session's processes in a cgroup of their own.

**Slice**:
On Linux, the unit of the user's systemd manager that groups the scopes of one sandbox's sessions.

**Limit**:
A bound a policy sets on what a sandbox's processes use: open files on each process, or memory and a share of the CPU on the sandbox as a whole, its sessions and services together.
_Avoid_: quota, resource cap

**Acceptance**:
The user's explicit, audited consent that a sandbox runs with a policy field this host does not enforce, such as a memory limit where the host has no memory controller. It is kept with the sandbox until the field's value changes.
_Avoid_: override, waiver

**Workspace**:
A host folder outside the sandbox home that a policy lets the sandbox write, such as a coding agent's project folder.
_Avoid_: mount, share, volume

**Mask**:
An empty, read-only stand-in over a denied path that cannot be left out, such as one a grant holds, so the path exists but shows nothing and what is around it stays as it was.
_Avoid_: stub, overlay

**Own place**:
A place each session of a sandbox has its own of instead of the host's, such as bubblewrap's `/run`, `/tmp` and `/proc`. No workspace may put the host's back over one, by its path or through a link.
_Avoid_: reserved path, private mount

**Protected path**:
A path enclos always denies to sandboxes whatever the policy says, such as the audit log, the state database and other sandboxes.
_Avoid_: system path, reserved path

**Escape probe**:
A check run by `enclos policy test` from inside a sandbox that tries one way out and must fail. It counts as closed only when its control, a harmless check run outside the sandbox, shows the same route works there (or, for a call refused outside too, that it gets as far there as the sandbox refuses it, such as to the filesystem; for what the host cannot reach either, that it is there; for the proxy, when the proxy refuses it); otherwise it is inconclusive.
_Avoid_: test case, attack

**Audit entry**:
The record of one state-changing command: time, user, host, command, state before and after, and result. Audit entries form an append-only, hash-chained audit log.
_Avoid_: event, log line
