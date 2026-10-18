# enclos

enclos creates sandboxes, installs AI agents in them, and keeps a state and an audit log of every command that changes them. It manages only the sandboxes it creates.

## Language

**Host**:
A machine where the enclos CLI runs and keeps its state. Another host is managed by running the CLI there over SSH.
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

**Policy snapshot**:
One immutable, fully resolved version of a sandbox's policy, identified by its content hash and recording the inputs it was resolved from.
_Avoid_: revision, policy file

**Active policy**:
The policy snapshot every new session in a sandbox starts under.
_Avoid_: current policy, live policy

**Pending policy**:
A policy snapshot saved for a sandbox because the user declined the restart it needs. It applies to nothing until the user applies it.
_Avoid_: draft, staged policy

**Template**:
A reusable policy that a sandbox's policy extends, such as `minimal`, `mcp-only`, `assistant` or `coding`.
_Avoid_: preset, base policy

**Agent**:
The agent runtime installed in a sandbox, such as Hermes, Claude Code or Codex. A sandbox holds at most one agent.
_Avoid_: bot, assistant, program

**Profile**:
A named configuration of the agent with its own memory, skills, model and channels, run as its own service or session. Profiles in a sandbox share its policy. Agents without profiles have one profile named `default`.
_Avoid_: instance, persona

**Session**:
One run inside a sandbox: an interactive `connect`, an `exec`, or a profile's service, with every process it starts. A session records the policy snapshot it started under.
_Avoid_: run, job, instance

**Member**:
Any process running inside a sandbox, whichever session started it, including helpers, browsers and installers.
_Avoid_: child, worker

**Audit entry**:
The record of one state-changing command: time, user, host, command, state before and after, and result. Audit entries form an append-only, hash-chained audit log.
_Avoid_: event, log line
