# Architecture

How enclos is put together in milestone 1, on a Mac with the Seatbelt backend. The [design](design.md) says what enclos is meant to be and why; the [ADRs](adr/) record each decision. Words such as sandbox, runtime, agent and policy are defined in the [glossary](../GLOSSARY.md).

## The big picture

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/architecture-dark.svg">
  <img alt="Clients (the enclos CLI; a web UI and an MCP server later) go through one core library: state and audit, policy, runtime adapters and the backend API. Backends: Seatbelt on macOS now; bubblewrap, OpenShell and a microVM later. Seatbelt runs the runtime inside the sandbox, whose only way out is its egress proxy to allowed domains, all run as launchd services." src="diagrams/architecture-light.svg">
</picture>

The drawing is made by [`diagrams/architecture.py`](diagrams/architecture.py): edit its boxes and run `uv run --no-project python docs/diagrams/architecture.py` to redraw both themes.

## What runs on your Mac

```mermaid
flowchart LR
  you(["You, in a terminal"])
  net(("Allowed destinations<br/>model provider, install sources,<br/>what you allowed"))

  subgraph mac["Your Mac"]
    cli["enclos CLI"]
    launchd["launchd"]
    proxy["Egress proxy<br/>one per sandbox,<br/>on one port"]

    subgraph data["~/.enclos (protected: sandboxes cannot write it)"]
      state[("state.db<br/>sandboxes, policy snapshots,<br/>sessions, network log")]
      audit[("audit.jsonl<br/>hash-chained")]
    end

    subgraph sb["Sandbox lab (Seatbelt, its compiled policy)"]
      gateway["Hermes gateway<br/>runtime service"]
      main["agent main<br/>hermes -p main"]
      scout["agent scout"]
      home[["home: Hermes install, agents,<br/>skills, login, caches"]]
    end
  end

  you --> cli
  cli -->|"connect lab -- main"| main
  cli -->|"sandbox start"| launchd
  launchd -->|"enclos launch lab"| gateway
  launchd -->|"enclos proxy run"| proxy
  cli --> state
  cli --> audit
  gateway -->|"HTTPS_PROXY: the only way out"| proxy
  main --> proxy
  scout --> proxy
  proxy -->|"allowlist, then validated addresses"| net
  proxy -->|"reads the active policy,<br/>logs every connection"| state
```

- **The sandbox** is the permission boundary ([ADR 0003](adr/0003-sandbox-is-the-permission-boundary.md)). Every process in it runs under `sandbox-exec` with the sandbox's compiled policy: it writes only to its home and to devices, cannot read the sensitive deny list (`~/.ssh`, keychains, browser data, other agents' configuration, other sandboxes, enclos's files), connects only to its proxy's ports, and cannot reach host services such as LaunchServices, Apple Events, launchd, preferences or the pasteboard, or signal processes outside it.
- **The runtime** (Hermes) is installed inside the sandbox's home by its own installer, run in the sandbox ([ADR 0020](adr/0020-runtimes-installed-per-sandbox.md)). Its **agents** share it, the policy, the proxy, the login and the secrets; each has its own configuration, memory, skills and sessions.
- **The egress proxy** runs on the host, outside the sandbox. It allows only destinations on the policy's allowlist, resolves names itself, connects only to addresses it has validated ([ADR 0017](adr/0017-proxy-connects-only-to-validated-addresses.md)), and logs every connection. It reads the active policy for each new connection, so `enclos policy allow` applies without a restart. Each sandbox has one proxy port, so the network log is per sandbox ([ADR 0024](adr/0024-agents-reached-through-the-runtime.md)).
- **Services**: `enclos sandbox start` installs two launchd jobs per sandbox, its proxy and its runtime's gateway, which serves every agent ([ADR 0021](adr/0021-one-runtime-service-per-sandbox.md)). There is no enclos daemon ([ADR 0002](adr/0002-no-daemon.md)). Interactive sessions run in your terminal and use the same proxy.
- **State and audit**: `state.db` (SQLite) holds the sandboxes, every policy snapshot, sessions and the network log; `audit.jsonl` holds one hash-chained entry per state-changing command ([ADR 0010](adr/0010-sqlite-state-and-jsonl-audit.md)).

## The code

```mermaid
flowchart TB
  main["main.rs, cli/<br/>commands, arguments, output"] --> engine["engine/<br/>the one place components meet:<br/>lock, audit, then the work"]

  engine --> policy["policy/<br/>layers, snapshots, validation"]
  engine --> backend["backend/seatbelt/<br/>compile a policy, wrap a command"]
  engine --> runtime["runtime/<br/>adapters: Hermes"]
  engine --> service["service/<br/>launchd jobs"]
  engine --> lifecycle["lifecycle/<br/>process groups, safe stop"]
  engine --> probes["probes/<br/>escape probes for policy test"]
  engine --> proxy["proxy/<br/>the egress proxy"]
  engine --> state["state/<br/>state.db"]
  engine --> audit["audit/<br/>audit.jsonl"]

  policy --> netmod["net/<br/>allowlist entries, address classes"]
  proxy --> netmod
  proxy --> state
```

Every client calls the `Engine` in `src/engine.rs`. A command that changes anything takes the state lock, opens an audit entry, does the work, saves the state and closes the entry, also on failure. Each component sits behind one interface (`Backend`, `RuntimeAdapter`, `ServiceManager`, `StateStore`, `AuditLog`), so a new backend or runtime is one new implementation. Typed records shared between components live in `model/`.

A sandbox's policy is resolved from four layers: built-in defaults, a template (`assistant`), the runtime adapter's endpoints, and the sandbox's own `policy.toml`. The result is an immutable snapshot identified by its hash ([ADR 0018](adr/0018-immutable-policy-snapshots.md)), and the backend compiles it into a `.sb` file under `sandboxes/<name>/compiled/`.

## A session, step by step

`enclos connect lab -- main`, which runs Hermes's own command for the agent `main`:

```mermaid
sequenceDiagram
  actor You
  participant CLI as enclos
  participant Data as state.db and audit.jsonl
  participant Proxy as Egress proxy
  participant SB as Sandbox lab

  You->>CLI: enclos connect lab -- main
  CLI->>Data: take the lock, open an audit entry, read the active snapshot
  CLI->>CLI: compile the policy (reused if unchanged)
  CLI->>Proxy: start it if it is not running (its own recorded session)
  CLI->>SB: sandbox-exec main, with an empty environment plus the proxy variables
  CLI->>Data: record the session, close the audit entry
  SB->>Proxy: CONNECT chatgpt.com:443
  Proxy->>Data: read the active policy, log the connection
  Proxy-->>SB: a tunnel, or 403 if not allowed
  SB-->>CLI: Hermes exits
  CLI->>Data: record the session's end, audited
```

`enclos sandbox stop lab` ends every recorded session's process group, services included. It signals a group only while its recorded leader is still the same process (same pid and start time), so it never signals a process that merely reused a pid.
