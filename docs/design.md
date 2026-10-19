# enclos — design

*enclos* (French for an enclosure, said "ahn-KLOH") is an open-source CLI that creates sandboxes, installs agent runtimes in them (Hermes first, then Claude Code, Codex, OpenClaw) and runs agents there, and keeps a proper state and an audit log of every command. It manages only the sandboxes it creates.

Status: design, before the first line of code. Target platforms: macOS on Apple Silicon first, then Linux (including Raspberry Pi). Windows through WSL2 later.

This document describes what enclos is and how it works. Decisions that are hard to reverse, and why they were made, are recorded in [`docs/adr/`](adr/). When this document and an ADR disagree, fix one of them in the same change. Three kinds of statement appear below: **decided** (an accepted ADR or plain design text), **proposed** (an ADR with `status: proposed`), and **to verify** (behavior the design depends on that no prototype has shown yet, listed in §14). Nothing in this document has been implemented or tested.

---

## 1. Threat model and principles

**Threat model** ([ADR 0014](adr/0014-threat-model-accidental-damage.md)). enclos primarily prevents accidental damage by agents the user mostly trusts: deleting the wrong files, reading credentials, reaching unexpected hosts, or leaving something running outside the sandbox. It is not designed to contain deliberately malicious code exploiting the kernel; that belongs in a VM backend.

1. **Control, not coordinate.** enclos isolates and governs agents. It never routes tasks between agents, delegates work, or models organizations.
2. **The CLI is the product.** Every operation is a command with readable and `--json` output. The web UI, an MCP server and scripts are clients of the same core and write the same audit log.
3. **Manage only what you create.** No background collector, and no scanning the host for agents enclos did not start. Inside a sandbox it created, enclos reads the runtime's own list of agents, to report the ones made there ([ADR 0023](adr/0023-agents-made-inside-a-sandbox.md)).
4. **Interfaces everywhere.** Each component has one job behind one interface. A new sandbox technology, secret store or runtime is one new implementation, with no change in the core.
5. **Typed models at every boundary.** Nothing untyped crosses a component boundary. Files on disk carry a `schema_version`.
6. **Never claim isolation that is not enforced or tested.** If a backend cannot enforce a policy field, enclos says so and refuses unless told otherwise. `enclos policy test` checks enforcement with probes that must fail, and reports only what it probed.
7. **Network is enforced by enclos, not by the backend.** Each sandbox reaches the outside only through its own egress proxy, which applies a domain allowlist, connects only to validated addresses and logs every connection.
8. **Readable code first.** Small files, explicit registration, no clever abstractions until a third implementation needs them.

## 2. Scope

**v1 goals**

- Create, start, stop, connect to and remove sandboxes from the CLI.
- Per-sandbox policy for files, network, programs, secrets and resources: edit, diff, roll back, test, with an active and a pending version.
- Install a runtime in a sandbox and run several of its agents there, starting with several Hermes sandboxes on a Mac, each with several agents running as background services.
- See each sandbox's network log, denied connections and other denials.
- Keep a state of every sandbox, its sessions and their processes, and an audit entry for every state-changing command.
- Seatbelt backend on macOS first, running while the user is logged in; then bubblewrap on Linux.

**Non-goals**

- Agent-to-agent delegation, task routing, organizations, pull request workflows.
- A collector, or discovery on the host of agents enclos did not create. Agents made inside an enclos sandbox are reported (§9).
- Remote control over chat channels.
- Writing our own isolation primitives: backends wrap OS features and existing VMs.
- Containing deliberately malicious code on the shared-kernel backends.
- Running sandboxes while the user is logged out (for now).
- Managing another host from this one (for now): run enclos on each host, over your own SSH session if needed.
- Hosting agents for other people (multi-tenant).

## 3. Concepts

| Concept | What it is | Example |
| --- | --- | --- |
| Host | A machine where the CLI runs and keeps its state. Each host is managed locally, by running enclos on it. | `mac`, `pi` |
| Sandbox | A named, persistent isolated environment created by enclos: backend, policy, home folder, mounts, lifecycle state. | `home` (Seatbelt), `pi-bot` (bubblewrap) |
| Policy | What a sandbox may do. Layered on a template, stored as immutable snapshots, compiled per backend. A sandbox has one active policy and at most one pending policy. | `extends = "assistant"` plus overrides |
| Runtime | The software installed in a sandbox to run its agents. One runtime per sandbox. | Hermes, Claude Code, Codex |
| Agent | A named identity of the sandbox's runtime, with its own configuration, memory, skills, sessions and channels. It shares the sandbox's runtime, policy, proxy and secrets. It is not a process and not a permission boundary: the runtime adapter decides how many processes run it, and the sandbox is the boundary. Runtimes without several agents (Claude Code, Codex) have one agent named `default`. | agent `main` in sandbox `home` |
| Session | One run inside a sandbox (an interactive `connect`, an `exec`, or an agent's service) with every process it starts. Each session records the policy snapshot it started under. | `enclos connect home -- main` |
| Audit entry | One record per state-changing command: time, user, host, command, state before and after, result. Append-only, hash-chained. | `enclos policy allow home api.telegram.org` |

Templates are reusable policies: `minimal`, `mcp-only`, `assistant`, `coding`.

**The sandbox is the permission boundary, the agent is not** ([ADR 0003](adr/0003-sandbox-is-the-permission-boundary.md)). Agents in one sandbox can read each other's files, because they share one policy. Agents that need different permissions go in different sandboxes.

## 4. Architecture

There is no daemon ([ADR 0002](adr/0002-no-daemon.md)). The CLI is a thin layer over a core library. A sandbox's proxy, and later its agent services, are ordinary launchd agents (macOS, in the user's login session) or systemd user units (Linux) that the core creates. Interactive sessions run in the user's terminal.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/architecture-dark.svg">
  <img alt="Clients (the enclos CLI; a web UI and an MCP server later) go through one core library: state and audit, policy, runtime adapters and the backend API. Backends: Seatbelt on macOS now; bubblewrap, OpenShell and a microVM later. Seatbelt runs the runtime inside the sandbox, whose only way out is its egress proxy to allowed domains, all run as launchd services." src="diagrams/architecture-light.svg">
</picture>

Every session runs inside the sandbox's policy, under the snapshot it started with.

Each sandbox has at most two units while the user is logged in ([ADR 0021](adr/0021-one-runtime-service-per-sandbox.md)): its proxy, `enclos.<install>.<sandbox>.proxy`, and its runtime's gateway, `enclos.<install>.<sandbox>.gateway`, one per sandbox because the gateway serves every agent. `enclos sandbox start` installs both, so they come back at each login, and `enclos sandbox stop` removes them. `<install>` is the first 8 hex digits of the SHA-256 of the enclos data folder: launchd labels are shared by every enclos install of the user (`ENCLOS_HOME`), and a sandbox name is unique only within one. The gateway starts the runtime only once the sandbox's own proxy holds its port: `proxy run --record` records itself after binding it, so a proxy session whose process still runs is the proof. The gateway unit runs `enclos launch <sandbox>`, which runs outside the sandbox, records the session, and runs the runtime's background command under the compiled policy in a process group of its own; interactive sessions (`enclos connect <sandbox>`, a shell or the command after `--`) run the same way in the user's terminal. Secrets never sit in a plist or unit file. The proxy has one listener port, reserved for the sandbox when it is created, so adding an agent never changes the compiled policy, and the network log is per sandbox ([ADR 0024](adr/0024-agents-reached-through-the-runtime.md)).

## 5. Isolation backends

| Policy field | Seatbelt (macOS) | bubblewrap (Linux) | OpenShell | MicroVM (libkrun, Firecracker) |
| --- | --- | --- | --- | --- |
| Isolation level | process, shared kernel | process, shared kernel | container, shared kernel | VM, own kernel |
| File writes | yes | yes (mount namespace + Landlock) | yes | yes |
| File read deny list | yes | yes (paths not mounted) | yes | yes |
| Programs allowed | yes (`process-exec` rules) | partial (mounted binaries + Landlock execute) | yes | yes |
| Network (via proxy) | yes (the sandbox's localhost proxy port only) | yes (own network namespace, Unix socket to proxy) | yes | yes (vsock or host IP) |
| Host-service delegation blocked | to verify (§5, §14) | planned: host sockets masked (§5), to verify in milestone 3 | yes | yes |
| CPU and memory limits | partial (`ulimit`, `taskpolicy`) | yes (cgroups via `systemd-run --user`) | yes | yes |
| Tracking every process | to verify (§8) | yes (cgroup) | yes | yes |
| Change without restart | network only | network only | network only | network only |
| Subscriptions work as-is | to verify (§12) | to verify (§12) | needs token delivery | needs token delivery |

**Security level, honestly stated.** Seatbelt and bubblewrap share the host kernel and user: they are designed to stop a misled agent from reading `~/.ssh` or deleting repos, not deliberately malicious code exploiting a kernel bug. That fits the threat model. Agents that read untrusted outside content with a shell, or run untrusted code, belong in a container or microVM backend. Most real risk is an agent misusing permissions it was given (exfiltration through an allowed destination, deleting its workspace), which only a narrow policy and logging address, on every backend.

**Filesystem defaults** ([ADR 0015](adr/0015-broad-reads-narrow-writes.md)). Reads are broad, except a sensitive-path deny list. Writes go only to the sandbox home and to workspaces the user grants. The initial deny list on macOS covers `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`, `~/.docker`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.config/gh`, shell history files, `~/Library/Keychains`, browser data folders, `~/Library/Mail`, `~/Library/Messages`, `~/Library/Cookies`, password-manager folders, the host's own agent configuration (`~/.claude`, `~/.codex`, `~/.hermes`), other sandboxes and enclos's protected paths. Policies can add entries; removing a default entry is an explicit, audited change. Milestone 1 has no such change, so a policy that leaves out a default entry is refused. The agent installs skills, dependencies and tools into its home: `HOME`, `TMPDIR`, caches, Python and Node environments and a `bin/` on `PATH` all point inside it, and programs installed there may run. The shared runtime under `runtimes/` stays read-only. Writes to device files the runtime needs (`/dev/null`, `/dev/tty` and similar) are part of every backend's baseline.

**Protected paths.** Whatever the policy says, every backend denies the sandbox write access anywhere in the enclos data and config folders (`~/.enclos` on macOS; `$XDG_DATA_HOME/enclos` and `$XDG_CONFIG_HOME/enclos` on Linux) except its own `home/`, and read access to `state.db`, `audit.jsonl` and its `audit.jsonl.torn-*` files, `config.toml`, the file secret store, the proxies' control sockets and other sandboxes' folders. The compiler adds these rules itself, and `validate` rejects a policy that tries to grant them, including through a broad path such as `~` or a workspace that contains them. `validate` compares paths after resolving symlinks and `..`, so a workspace symlinked into these folders is rejected too. This is also why the agent cannot widen its own policy. See [ADR 0010](adr/0010-sqlite-state-and-jsonl-audit.md).

**Host-service delegation** ([ADR 0016](adr/0016-seatbelt-blocks-host-service-delegation.md)). On macOS a sandboxed process can ask a host service to act for it, outside the sandbox. Whatever the Seatbelt baseline, the compiled policy must deny these routes with the Seatbelt operation that actually governs each one (`mach-lookup` for named services, `appleevent-send` for Apple Events, and whatever the prototype shows blocks launchd job submission, which goes through the bootstrap port rather than a named service), with executable denials only as an extra layer. The routes are:

- LaunchServices: `open`, opening apps, documents and URLs;
- Apple Events: `osascript`, scripting Terminal or any other app;
- synthetic keyboard and mouse events posted through WindowServer, and the pasteboard;
- launchd: submitting or bootstrapping jobs, `launchctl`; login items through ServiceManagement; writing LaunchAgents is already denied by the write rules;
- cfprefsd, which writes `~/Library/Preferences` on the caller's behalf, so the file-write rules never see those writes;
- `at` and `crontab`;
- Unix sockets to host services, such as the SSH agent and the Docker socket (denied by the network rules, which allow only the proxy port);
- the Keychain (the security daemon);
- name lookups through mDNSResponder (`com.apple.dnssd.service`), so the sandbox cannot resolve or leak data through DNS and every lookup happens in the proxy.

macOS privacy permissions (TCC) are not part of the sandbox: a process started from Terminal is attributed to Terminal, so it inherits whatever Full Disk Access, Accessibility or Automation grants Terminal has. The read deny list and the rules above must hold without relying on TCC.

The exact rule list is **to verify**: the milestone 1 prototype produces it with an escape probe per route, and `enclos policy test` runs those probes. On the user's Mac, `enclos policy test` runs only probes that cannot act on the host even if a rule does not hold (files, enclos's files, network, DNS, host sockets, signals, Keychain, pasteboard, crontab); the ones that could (LaunchServices, Apple Events, launchd, preferences) run only with `--host-services`, which CI's macOS runners use, and whatever they create is checked from the host and removed. Logins therefore use a device-code flow: the runtime prints a URL and a code, and the user opens the URL on the host.

**Linux networking.** A bubblewrap sandbox has its own, empty network namespace, and the proxy is reached through a Unix socket bound into it. Most HTTP clients (Python `httpx` and `requests`, Node, Go) need a TCP address in `HTTPS_PROXY`, so `wrap` starts a small relay inside the sandbox (enclos itself) that listens on `127.0.0.1:<port>` and forwards to the socket. Each sandbox gets one socket and one relay. The relay is the enclos binary, so bubblewrap always mounts it read-only and the program allowlist always permits it, even with `shell = false`. The agent can kill or replace its relay, which is harmless: the relay can only reach the proxy socket.

**Linux host services.** Linux has its own routes out: the D-Bus session bus, the `systemd --user` manager (which can start units outside the sandbox), and host sockets such as the SSH agent and Docker. A network namespace does not block Unix sockets that live on the filesystem, and a read-only mount does not stop a process from connecting to one, so broad reads must not expose them: bubblewrap masks `/run/user/<uid>` (which also holds the Wayland socket), `/tmp/.X11-unix` (X11 allows keystroke injection), the Docker socket and any socket named in `SSH_AUTH_SOCK`, and the escape probes cover them.

### Seatbelt specifics (first backend)

- `compile` renders a compiled policy (`.sb` file). The current plan is `(allow default)`, then: `(deny file-write*)` with writes allowed only to the sandbox home, granted workspaces and the device files the runtime needs; `(deny file-read*)` on the sensitive deny list, with the sandbox's own home re-allowed (later rules win); `(deny network*)` with outbound allowed only to the sandbox's reserved proxy ports on localhost, which also denies Unix sockets; the host-service denials above; an optional `process-exec` allowlist when `shell = false`; and last, so no policy rule can override them, the protected paths. [ADR 0006](adr/0006-seatbelt-deny-by-default.md) proposes starting from `(deny default)` instead; milestone 2 decides on evidence, not on Hermes merely running. Milestone 1 uses `(allow default)` with these rules.
- `wrap` returns `/usr/bin/sandbox-exec -f <compiled.sb> -D HOME=<home> -- <cmd>`, with the environment set for the sandbox: `HOME`, `TMPDIR`, `PATH` and the tool caches inside the home, and the proxy set for every common client: `HTTPS_PROXY`, `HTTP_PROXY` and their lowercase forms (curl reads only lowercase `http_proxy`), plus `NODE_USE_ENV_PROXY=1` for Node's built-in `fetch`. Clients that ignore all of these cannot connect.
- A compiled Seatbelt policy is fixed for the life of the process and its children. Network allowlist changes are live because the proxy enforces them; file, program and resource changes need a restart, which enclos asks for, and which stays pending if the user declines (§7).
- **Denials.** Two sources:
  1. The proxy log: every connection with its destination and verdict. This is the main network view.
  2. The macOS unified log: the kernel logs Seatbelt denials, for example `Sandbox: python3(4182) deny(1) file-read-data /Users/x/.ssh/id_ed25519`, readable with `log stream --predicate 'sender == "Sandbox"'`. Lines are attributed to a sandbox by process ID or a tag (to verify). macOS collapses repeated identical denials.
- `sandbox-exec` is marked deprecated by Apple but still ships and is used by major tools. Track it as a risk.

## 6. Network

**Destinations** ([ADR 0007](adr/0007-network-through-a-proxy-per-sandbox.md), [ADR 0017](adr/0017-proxy-connects-only-to-validated-addresses.md)). The proxy accepts a CONNECT (or a plain-HTTP request) for a host and port, normalizes the host (lowercase, trailing dot removed, IDNA to ASCII), and checks it against the allowlist; entries default to port 443 unless they name a port. It then resolves the host itself, since the sandbox is meant to have no DNS of its own (§5, to verify), and validates every IPv4 and IPv6 address it gets:

- always blocked: every entry in the IANA IPv4 and IPv6 special-purpose address registries that is not globally reachable, including loopback, unspecified and `0.0.0.0/8`, link-local (and with it cloud metadata addresses), multicast, broadcast, benchmarking (`198.18.0.0/15`), documentation ranges and the deprecated IPv4-compatible `::/96`;
- IPv6 forms that carry an IPv4 address (IPv4-mapped, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/32`) are checked as the IPv4 address they carry;
- private ranges (RFC 1918, carrier-grade NAT `100.64.0.0/10`, unique-local IPv6 `fc00::/7`) are blocked unless the host is both on the allowlist and named in the policy's `private` opt-in. The opt-in unlocks only these private ranges, never loopback, link-local or multicast, and applies the same way to IP literals and to hostnames that resolve to private addresses.

The proxy connects only to addresses that passed, by address. Falling back from one address to the next uses the same validated list, and a retry that resolves again validates again. If no address passes, the connection is denied with the reason `blocked-address`.

**Server name check.** For a TLS tunnel, the proxy reads the server name in the client's first, unencrypted message (the ClientHello), without decrypting anything. If it differs from the host the tunnel was opened for, the tunnel is closed with the reason `name-mismatch`. If no name is visible, because it is absent or encrypted (Encrypted Client Hello), the tunnel is allowed, since its host and address were already checked, and the log records that no name was seen. This stops simple attempts to reach another site through an allowed one, not fronting through an encrypted name.

**Unknown destinations.** A destination not on the allowlist is denied at once and logged; nothing is held waiting for an answer. `enclos net denied <sandbox>` lists denied destinations with counts and times, and the user allows what is needed from the host with `enclos policy allow`, which takes effect without a restart: the proxy reads the sandbox's active policy from `state.db` for each new connection (milestone 1; reloads over its control socket come later). The agent cannot widen its own policy: the proxy listener serves only proxy traffic, its control socket is a protected path, and enclos's state is not writable from the sandbox.

**What the network log shows.** For HTTPS, one record per tunnel: the host and port asked for, the address connected to, the server name seen in the ClientHello (or that none was visible), the verdict and reason, bytes each way, and duration. The proxy does not see the HTTP requests inside an encrypted tunnel, so the log never shows paths, methods or the number of requests made through one tunnel. For plain HTTP, the proxy also records each request's method and host.

**What the proxy can and cannot promise.** enclos constrains the connections the sandbox makes, not what the services it reaches do. A remote browser, a search service, an MCP server, or the model provider's own tools (a hosted web search, for example) can fetch other sites on the agent's behalf. Allowing such a service grants that capability: the policy and `enclos policy show` describe it as "remote fetching through <service>", not as network isolation. The same applies to any allowed destination that relays data.

**Host services.** Services on the host's loopback interface or local network are unreachable: there is no loopback exception. Reaching one (a local MCP server, for example) needs a host-service forward: a narrowly scoped mechanism that exposes one named host address and port to one sandbox through its own listener, logged and audited. Decided: no host-service forward before milestone 3.1, and then only one named host port to one sandbox per grant; the exact mechanism is still open (§15).

## 7. Policy

A policy is TOML that extends a template and overrides only what differs ([ADR 0008](adr/0008-layered-policy-with-declared-enforcement.md)). Layers resolve in order: built-in defaults, template, the endpoints the runtime adapter needs, the sandbox's `policy.toml`. Lists replace (`allow = [...]`) or extend (`allow_add = [...]`).

```toml
# ~/.enclos/sandboxes/home/policy.toml
extends = "assistant"

[filesystem]
write_add = ["~/Documents/notes"]        # a granted workspace
read_deny_add = ["~/dev/work"]

[network]
allow_add = ["api.telegram.org", "printer.lan"]
private = ["printer.lan"]                # must also be allowed; unlocks private ranges only for these hosts
log = "metadata"                         # per tunnel: host, port, address, bytes, duration; never contents

[resources]
memory = "2G"
cpu = 2.0

[secrets]                                # every session in the sandbox receives these
env = { TELEGRAM_BOT_TOKEN = "secret:home/telegram" }
```

| Template | Writes | Programs | Network | Use for |
| --- | --- | --- | --- | --- |
| `minimal` | own home | the runtime only | model provider only | a starting point |
| `mcp-only` | own home | runtime and its MCP servers | model provider + listed remote MCP endpoints | assistants working on outside data |
| `assistant` | own home | any, including what the agent installs in its home | model provider, the runtime's install sources, listed APIs | personal agents such as Hermes |
| `coding` | own home + the selected project folder, written in place | any | model provider, Git hosts, package registries | Claude Code, Codex, a dev agent |

Every template reads the host broadly, minus the sensitive deny list (§5). Validation: no loopback or link-local entries; a wildcard may only cover the subdomains of a named domain (`*.example.com`), never everything (`*`) or a public suffix (`*.com`, `*.co.uk`); private addresses only through `private`, for hosts that are also on the allowlist; no filesystem grant may cover the protected paths. Each runtime adapter contributes the endpoints its runtime needs to work at all (for Hermes: the model provider, its login endpoints and its install sources, listed after the prototype). No template or adapter contributes a weather service or any task-specific API.

**Snapshots** ([ADR 0018](adr/0018-immutable-policy-snapshots.md)). A snapshot is the fully resolved policy together with its inputs (enclos version and built-in defaults, template name and content hash, adapter version and contributed endpoints, and the overrides), identified by the SHA-256 of both. Snapshots are insert-only, and identical content reuses the existing snapshot. A sandbox's history is an append-only list of numbered policy versions, each pointing to a snapshot and recording who made it, when, and which version it restores if it is a rollback. Audit entries and session records reference both the version number and the snapshot hash.

- **Active and pending.** New sessions use the active snapshot. A file, program or resource change applies at once if no session is running; if sessions are running, it needs a restart and asks first; if the user declines, it becomes the pending snapshot, the active one stays, and `enclos policy show` and `enclos sandbox show` display both. `enclos policy apply` restarts and makes the pending snapshot active; `enclos policy discard` drops it. A change mixing restart-requiring and network parts is pending as a whole. A network-only change takes effect at once as a new active snapshot, and if a change is pending, it is re-resolved into a new pending snapshot that includes the network change.
- **Updates.** A new enclos version or template never silently changes grants: launch uses the active snapshot as stored. `enclos policy refresh` resolves again against the current template and adapter and turns any difference into a change for the user to accept. Until refresh and pending changes arrive (milestone 2), `enclos policy allow` resolves the whole `policy.toml` against the current template and adapter; when the result changes more than the entry asked for (edits not applied yet, or a newer template or built-in defaults), it lists each extra change and asks first.
- **Rollback.** `enclos policy rollback --to <version>` makes that snapshot's effective policy the target again, as a new version recording what it restores, and restores its overrides so later edits start from it. It follows the restart rules above. A rollback or refresh made while a change is pending replaces that pending change, after showing it and asking.

## 8. Lifecycle

**Members** ([ADR 0019](adr/0019-sandbox-members-and-effective-policy.md)). Every process inside a sandbox is a member: interactive sessions, the agent, browsers and helpers it starts, installers, and all their children. Each session is recorded with its target, kind (interactive, exec, service), the snapshot and compiled policy it started under, its start time, and its members.

- **Linux:** members are the processes in the sandbox's cgroup.
- **macOS (milestone 1):** a session's members are the processes in its process group: the terminal job of `enclos connect`, or the group `enclos` creates for a proxy or service. `stop` signals a group only while its recorded leader is the same process (same pid and start time), so a reused pid is never signalled; it sends TERM, waits, sends KILL, and reports what remains. When the program a session started exits but leaves members in the group, the session stays open until they end, so `show` lists them and `rm` refuses; `stop` cannot signal a group whose leader is gone, so it reports them. `connect` uses the terminal's job as the session's group when it leads that job, and a group of its own when it runs without a terminal (a script, CI); run from a terminal without a job of its own, the group is the caller's and nothing is counted. A process that leaves the group (`setsid`) is not seen: a known gap, and it keeps its Seatbelt restrictions. The prototype refuted a per-sandbox marker checked with `sandbox_check` (it answers the same for every process).

**Stop and restart.** `stop` ends every member: a signal, a grace period, then a forced kill, then a check that no member remains. Survivors are reported, and the sandbox is marked `Failed` instead of `Stopped`. `restart` stops every member and starts the sandbox's services again under the active snapshot; an interactive session ends and the CLI tells the user to reconnect.

**Effective policy.** Network rules follow the active snapshot live; file, program and resource rules are fixed when a session starts. `enclos sandbox show` lists each session with both, for example `network: v7 (live)  files, programs, resources: v5 (at launch)`, and flags a session as needing a restart only when its file, program or resource rules differ from the active snapshot's, not merely because the version number moved. A pending snapshot never applies to anything running.

**Starting a session: `enclos connect home -- main`, step by step**

1. Take the state lock; open an audit entry.
2. Load the record and the active snapshot; compile it if no compiled policy exists for this snapshot and this enclos version (an upgrade recompiles, which is how stricter enclos-owned rules reach new sessions without asking; `enclos doctor` lists what changed); `prepare`.
3. Start the proxy unit if it is not running, with the active network policy and the sandbox's listener.
4. Record the session with its snapshot and compiled-policy hashes; close the audit entry; release the lock.
5. `enclos launch` reads the sandbox's secrets, wraps the command (`main`, Hermes's own command for that agent; a login shell when none is given) and runs it in the terminal, tracking its members.
6. When the session ends, take the lock, record the end and any surviving members, and append an audit entry.
7. On failure at any step: stop what started, save `Failed { reason }`, and close the audit entry as failed.

`enclos sandbox start <name>` does the same for the proxy and every autostart agent's service.

## 9. Component APIs

Sketches in Rust. The `Engine` is the only code that combines components.

**Models**

```rust
pub struct SandboxName(String);              // [a-z][a-z0-9-]{1,40}
pub enum BackendKind { Seatbelt, Bubblewrap, OpenShell, Libkrun }
pub enum RuntimeKind { Hermes, ClaudeCode, Codex, OpenClaw }

pub struct AgentName(String);                // same rules; "default" for runtimes without several agents

pub struct SandboxSpec { pub name: SandboxName, pub backend: BackendKind, pub template: TemplateName,
                         pub workspaces: Vec<PathBuf>, pub runtime: Option<RuntimeKind> }
pub struct SandboxRecord { pub spec: SandboxSpec, pub state: SandboxState,
                           pub active_policy: SnapshotId, pub pending_policy: Option<SnapshotId>,
                           pub agents: Vec<AgentRecord>, pub created_at: Timestamp }
pub struct AgentRecord { pub name: AgentName, pub autostart: bool, pub state: SandboxState }
pub enum SandboxState { Created, Running, Stopped, Failed { reason: String } }

pub struct AgentRef { pub sandbox: SandboxName, pub agent: AgentName }    // "home/main", in the agent commands

pub struct SnapshotId([u8; 32]);             // SHA-256 of the resolved policy and its inputs
pub struct PolicySnapshot { pub id: SnapshotId, pub inputs: PolicyInputs, pub policy: Policy }   // insert-only
pub struct PolicyVersion { pub version: u32, pub snapshot: SnapshotId, pub by: Actor, pub at: Timestamp,
                           pub restores: Option<u32> }    // append-only history; set by a rollback
pub struct PolicyInputs { pub enclos_version: Version, pub defaults: ContentHash,
                          pub template: (TemplateName, ContentHash),
                          pub adapter: Option<(RuntimeKind, Version, ContentHash)>, pub overrides: ContentHash }

pub struct SessionRecord { pub id: SessionId, pub target: Target, pub kind: SessionKind,  // Interactive | Exec | Service
                           pub version: u32, pub snapshot: SnapshotId, pub compiled: ContentHash,
                           pub started_at: Timestamp, pub ended_at: Option<Timestamp> }
pub struct Member { pub pid: u32, pub session: Option<SessionId>, pub command: String, pub started_at: Timestamp }

pub struct Policy { pub fs: FsPolicy, pub exec: ExecPolicy, pub net: NetPolicy,
                    pub resources: Resources, pub secrets: Vec<SecretGrant> }
pub enum Enforcement { Enforced, Partial { note: String }, Unsupported }
pub struct Capabilities { pub isolation: Isolation, pub fs: Enforcement, pub exec: Enforcement,
                          pub resources: Enforcement, pub members: Enforcement, pub live: Vec<PolicyArea> }
```

**Policy** (pure functions)

```rust
pub fn resolve(inputs: &ResolvedInputs) -> Result<PolicySnapshot, PolicyError>;   // defaults, template, adapter, overrides
pub fn validate(policy: &Policy, caps: &Capabilities) -> Vec<Finding>;
pub fn diff(before: &Policy, after: &Policy) -> PolicyDiff;
pub fn needs_restart(diff: &PolicyDiff, caps: &Capabilities) -> bool;
```

**Backend** (prepares, wraps and finds members; never supervises)

```rust
pub trait Backend {
    fn kind(&self) -> BackendKind;
    fn probe(&self) -> Probe;
    fn capabilities(&self) -> Capabilities;
    fn compile(&self, policy: &Policy, ctx: &SandboxContext) -> Result<Compiled>;   // pure; adds protected paths and host-service blocks
    fn prepare(&self, sb: &SandboxRecord, compiled: &Compiled) -> Result<()>;
    fn wrap(&self, sb: &SandboxRecord, session: &SessionRecord, cmd: &Command) -> Result<Command>;
    fn members(&self, sb: &SandboxRecord) -> Result<Vec<Member>>;
    fn signal_members(&self, sb: &SandboxRecord, signal: StopSignal) -> Result<()>;   // Term | Kill
    fn escape_probes(&self) -> Vec<Probe>;                                            // run by `policy test`
    fn denials(&self, sb: &SandboxRecord, since: Timestamp) -> Result<Vec<Denial>>;
    fn teardown(&self, sb: &SandboxRecord, keep_data: bool) -> Result<()>;
    fn up(&self, _sb: &SandboxRecord) -> Result<()> { Ok(()) }     // a VM boots here
    fn down(&self, _sb: &SandboxRecord) -> Result<()> { Ok(()) }
}
```

**Egress proxy**

```rust
pub fn decide(net: &NetPolicy, host: &Host, port: u16) -> Decision;                // Allow | Deny { reason }
pub fn validate_addrs(net: &NetPolicy, host: &Host, addrs: &[IpAddr]) -> Vec<IpAddr>; // only addresses that passed
pub struct ProxyConfig { pub sandbox: SandboxName, pub listen: SocketAddr,
                         pub control: PathBuf, pub net: NetPolicy, pub events: PathBuf }
pub struct NetEvent { pub at: Timestamp, pub sandbox: SandboxName, pub host: String, pub port: u16,
                      pub addr: Option<IpAddr>, pub server_name: Option<String>,   // from the ClientHello, if visible
                      pub verdict: Verdict, pub reason: Option<DenyReason>,
                      pub bytes_up: u64, pub bytes_down: u64, pub duration: Duration }
pub enum ProxyRequest { Reload { net: NetPolicy }, Stats }
```

**Service manager**

```rust
pub trait ServiceManager {
    fn install(&self, unit: &ServiceUnit) -> Result<()>;
    fn uninstall(&self, name: &ServiceName) -> Result<()>;
    fn start(&self, name: &ServiceName) -> Result<()>;
    fn stop(&self, name: &ServiceName, grace: Duration) -> Result<()>;
    fn status(&self, name: &ServiceName) -> Result<ServiceStatus>;
}
```

**Secret store**

```rust
pub trait SecretStore {
    fn put(&self, r: &SecretRef, value: SecretValue) -> Result<()>;
    fn get(&self, r: &SecretRef) -> Result<SecretValue>;   // zeroized on drop, prints "***"
    fn delete(&self, r: &SecretRef) -> Result<()>;
    fn list(&self) -> Result<Vec<SecretRef>>;
}
```

**State store and audit log.** A write requires a `StateLock`, so writing outside the lock does not compile; an `AuditTicket` is consumed by `finish`. Snapshots are insert-only and versions append-only.

```rust
pub trait StateStore {
    fn lock(&self) -> Result<StateLock>;
    fn get(&self, name: &SandboxName) -> Result<Option<SandboxRecord>>;
    fn list(&self) -> Result<Vec<SandboxRecord>>;
    fn put(&self, lock: &StateLock, rec: &SandboxRecord) -> Result<()>;
    fn remove(&self, lock: &StateLock, name: &SandboxName) -> Result<()>;
    fn add_version(&self, lock: &StateLock, name: &SandboxName, snap: &PolicySnapshot,
                   by: &Actor, restores: Option<u32>) -> Result<PolicyVersion>;   // stores the snapshot if new
    fn snapshot(&self, id: &SnapshotId) -> Result<PolicySnapshot>;
    fn policy_history(&self, name: &SandboxName) -> Result<Vec<PolicyVersion>>;
    fn put_session(&self, lock: &StateLock, session: &SessionRecord) -> Result<()>;
    fn sessions(&self, name: &SandboxName, running_only: bool) -> Result<Vec<SessionRecord>>;
}

pub trait AuditLog {
    fn begin(&self, lock: &StateLock, intent: Intent) -> Result<AuditTicket>;
    fn finish(&self, ticket: AuditTicket, outcome: Outcome) -> Result<()>;
    fn entries(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>>;
    fn verify(&self) -> Result<VerifyReport>;
}
```

**Runtime adapter**

```rust
pub trait RuntimeAdapter {
    fn kind(&self) -> RuntimeKind;
    fn supports_multiple_agents(&self) -> bool;                                 // Hermes: yes; Claude Code, Codex: no
    fn requirements(&self) -> PolicyFragment;                                   // versioned; recorded in snapshot inputs
    fn install(&self, runtimes: &Path, version: &Version) -> Result<Runtime>;   // shared, read-only
    fn init_home(&self, sb: &SandboxRecord, runtime: &Runtime) -> Result<()>;   // writable environments, bin, caches, skills
    fn login(&self) -> Command;                                                 // the runtime's own login and setup, shown as `connect <sandbox> -- <this>`

    fn add_agent(&self, sb: &SandboxRecord, agent: &AgentSpec) -> Result<()>;          // model, skills, channels
    fn remove_agent(&self, sb: &SandboxRecord, agent: &AgentName, keep_data: bool) -> Result<()>;
    fn configure(&self, sb: &SandboxRecord, agent: &AgentName, cfg: &AgentConfig) -> Result<ConfigDiff>;
    fn service(&self, sb: &SandboxRecord) -> Option<Command>;                   // the background process serving every agent
    fn agents_in(&self, home: &Path) -> Option<Vec<String>>;                     // read on the host; None: cannot tell
}
```

For Hermes, each agent is a Hermes profile of the same name (Hermes's word for it): all live under the sandbox's Hermes home and run the same shared Hermes install, and `command` selects the profile. Hermes's own installs of skills, packages and tools are configured to land in the sandbox home, never in the shared runtime.

**Agents made inside a sandbox** ([ADR 0023](adr/0023-agents-made-inside-a-sandbox.md)). Anything run in the sandbox can create or delete agents with the runtime's own commands, such as `hermes profile create` in an `enclos connect` shell. They work, under the same policy, but enclos has no record of them, so they get no proxy port of their own and `connect <sandbox>/<agent>` refuses them. `agents_in` lists the agents the runtime has, the way the runtime itself does (for Hermes: a folder under `~/.hermes/profiles/` with a valid id, one of its identity files, and no marker under `.deleted/`), read on the host. What it reads is written by the sandbox: it never follows a link, reads a bounded number of entries, and answers `None` (cannot tell) rather than guess. enclos compares the list with its records in `agent list`, `sandbox show`, after each `connect` session and when a name is not found, and reports agents it does not track, names that are not valid agent names, and tracked agents the runtime no longer has, each with the command that fixes it. `enclos agent add` adopts an agent the runtime already has: it records it and gives it a port without creating it again. enclos never adopts or removes an agent on its own.

**Engine** — the API every client calls. Reads are not audited. Every write takes the lock, opens an audit entry, does the work, saves state and closes the entry, also on failure. `Confirm::DryRun` returns the plan without changing anything.

```rust
impl Engine {
    pub fn list(&self) -> Result<Vec<SandboxView>>;
    pub fn show(&self, name: &SandboxName) -> Result<SandboxView>;     // sessions, members, active and pending policy
    pub fn policy(&self, name: &SandboxName, compiled: bool) -> Result<PolicyView>;
    pub fn net_log(&self, name: &SandboxName, since: Timestamp) -> Result<Vec<NetEvent>>;
    pub fn net_denied(&self, name: &SandboxName, since: Timestamp) -> Result<Vec<DeniedDestination>>;
    pub fn denials(&self, name: &SandboxName, since: Timestamp) -> Result<Vec<Denial>>;

    pub fn create(&self, by: &Actor, spec: SandboxSpec, confirm: Confirm) -> Result<Planned<SandboxRecord>>;
    pub fn add_agent(&self, by: &Actor, sandbox: &SandboxName, agent: AgentSpec) -> Result<AddedAgent>;   // or adopts one made inside
    pub fn check_agents(&self, name: &SandboxName) -> Result<AgentCheck>;   // the runtime's agents vs the records
    pub fn remove_agent(&self, by: &Actor, agent: &AgentRef, keep_data: bool, confirm: Confirm) -> Result<Planned<()>>;
    pub fn start(&self, by: &Actor, name: &SandboxName) -> Result<SandboxRecord>;   // proxy + agent services
    pub fn stop(&self, by: &Actor, name: &SandboxName) -> Result<StopReport>;       // every member; survivors reported
    pub fn remove(&self, by: &Actor, name: &SandboxName, keep_data: bool, confirm: Confirm) -> Result<Planned<()>>;
    pub fn change_policy(&self, by: &Actor, name: &SandboxName, change: PolicyChange, confirm: Confirm) -> Result<Planned<PolicyApplied>>;
    pub fn apply_pending(&self, by: &Actor, name: &SandboxName, confirm: Confirm) -> Result<Planned<PolicyApplied>>;
    pub fn discard_pending(&self, by: &Actor, name: &SandboxName) -> Result<()>;
    pub fn refresh_policy(&self, by: &Actor, name: &SandboxName, confirm: Confirm) -> Result<Planned<PolicyApplied>>;
    pub fn rollback_policy(&self, by: &Actor, name: &SandboxName, to: u32, confirm: Confirm) -> Result<Planned<PolicyApplied>>;
    pub fn test_policy(&self, by: &Actor, name: &SandboxName) -> Result<TestReport>;
    pub fn connect(&self, by: &Actor, name: &SandboxName, command: Vec<OsString>) -> Result<Command>;   // a shell, or the command
    pub fn exec(&self, by: &Actor, name: &SandboxName, cmd: Command) -> Result<Command>;
    pub fn launch(&self, target: &Target, kind: SessionKind) -> Result<Infallible>;   // every session goes through here
}
```

**Readability rules**

1. One interface per file; each implementation in its own folder with its tests and fixtures.
2. No inheritance beyond the interface; implementations registered in one explicit list.
3. A command is three steps: parse arguments into a model, call one engine function, print the result.
4. Side effects only behind interfaces, so tests use fakes.
5. Typed errors that say what to do next.
6. Files of about 300 lines at most.

**Code layout**

```text
src/
  main.rs          CLI: parse args into models, call Engine, print the result
  cli/             one file per command group (policy.rs, ...): its arguments and output
  lib.rs           the core library every client uses
  engine.rs        the API above; the only place components meet; engine/ holds its parts (policy.rs, ...)
  error.rs         the engine's typed errors and their exit codes
  layout.rs        where enclos keeps its files (§11);  config.rs  config.toml
  model/           sandbox.rs  policy.rs  session.rs  net.rs  audit.rs
  policy/          mod.rs (resolve, snapshots)  file.rs (one TOML layer)  paths.rs  validate.rs  templates/*.toml
  net/             addr.rs (which addresses are reachable, ADR 0017)  host.rs (allowlist entries); shared by policy and proxy
  lifecycle/       sessions.rs  stop.rs
  backend/         mod.rs (trait)  fake/  seatbelt/{compile.rs, wrap.rs, host-services.sb, members.rs, probes.rs, denials.rs}
  proxy/           decide.rs (pure checks)  request.rs  server.rs  control.rs (later)
  service/         mod.rs (trait)  launchd.rs  systemd.rs
  secrets/         mod.rs (trait)  keychain.rs  file.rs
  state/           mod.rs (trait)  sqlite/
  audit/           mod.rs (trait)  jsonl/
  runtime/         mod.rs (trait)  hermes.rs  claude_code.rs  codex.rs
```

## 10. CLI

Every operation is `enclos <noun> <verb>`. Readable output in a terminal, JSON when piped or with `--json`. Exit codes: 0 ok, 1 error, 2 refused by policy, 3 needs confirmation. Changes print a diff and ask; `--yes` skips, `--dry-run` only shows. Commands act on the local host only.

```text
enclos init | doctor
enclos backend list | probe <name>

enclos sandbox create <name> --backend seatbelt --template assistant [--workspace ~/dev/x]
enclos sandbox list | show <name> | start | stop | restart    show: sessions, members, active and pending policy
enclos sandbox rm <name> [--keep-data]
enclos connect <name> [-- <command...>]       a shell, or a command such as the runtime's own, in the sandbox
enclos exec <name> -- <cmd...>
enclos logs <name> [-f]

enclos agent add <name>/<agent> [--model ...] [--no-autostart]   also adopts an agent made inside the sandbox
enclos agent list <name>                      with the agents made inside that enclos does not track
enclos agent start | stop | restart <name>/<agent>
enclos agent rm <name>/<agent> [--keep-data]

enclos policy show <name> [--compiled] [--pending]
enclos policy edit <name>
enclos policy allow <name> <domain> | deny-read <name> <path>
enclos policy apply | discard <name>          the pending change
enclos policy refresh <name>                  re-resolve against current templates and adapters
enclos policy diff | history | rollback <name> [--to <version>]
enclos policy test <name>                     enforcement and escape probes
enclos template list | show <template>

enclos runtime install <type> --sandbox <name> [--version x]
enclos runtime configure <name>[/<agent>] [--model ...] [--mcp-add name=https://...] [--channel ...]

enclos secret set | list | rm <ref>
enclos net log <name> [-f] | net denied <name>
enclos denials <name>

enclos state show | check | repair <name>
enclos audit [<name>] [--since 7d] | audit verify

enclos apply -f stack.toml
enclos ui
enclos mcp
```

**The first working flow** (milestone 1): two sandboxes, each with two Hermes agents running as background services.

```bash
enclos init
enclos sandbox create home --backend seatbelt --template assistant
enclos runtime install hermes --sandbox home
enclos agent add home/main
enclos agent add home/research
enclos connect home -- hermes setup             # Hermes's own setup: provider, login (a URL to open on the host), model

enclos sandbox create lab --backend seatbelt --template assistant
enclos runtime install hermes --sandbox lab
enclos agent add lab/scout
enclos agent add lab/writer
enclos connect lab -- hermes setup

enclos policy test home                         # probes: ~/.ssh and the other sandbox unreadable, writes outside home refused,
enclos policy test lab                          # `open` and osascript refused, unlisted destinations and private addresses refused
enclos sandbox start home lab                   # proxies + all four agents, under launchd
enclos sandbox show home                        # agents, sessions, members, policy each started under

enclos connect home -- main                     # Hermes's own command for the agent main
#   > What's the weather right now in Paris, Cali and Tokyo?
enclos net log home                             # every tunnel the sandbox opened
enclos net denied home                          # what was refused; allow what you trust with `enclos policy allow`
enclos sandbox stop home lab                    # every member, services and sessions alike
```

**Later** (milestones 2 and 3): agents that answer on Telegram with the sandbox's secrets, a dev sandbox writing to a project folder, and a community sandbox whose agents reach their data through a remote MCP server.

```bash
enclos secret set home/telegram-main
enclos runtime configure home/main --channel telegram --secret home/telegram-main

enclos sandbox create dev --backend seatbelt --template coding --workspace ~/dev/app
enclos runtime install claude-code --sandbox dev

enclos sandbox create community --backend seatbelt --template mcp-only
enclos runtime install hermes --sandbox community
enclos agent add community/support
enclos runtime configure community --mcp-add data=https://mcp.example.org/data  # every agent; a remote endpoint
enclos policy allow community mcp.example.org
```

## 11. State, audit and files

```text
~/.enclos/
  config.toml                  default backend, secret store, UI port, allowed UI actions
  state.db                     SQLite: sandbox records, policy snapshots, sessions and members, network log, denials
  state.lock                   held while a command changes state
  audit.jsonl                  append-only and hash-chained: one line when a state-changing command starts, one when it ends
  runtimes/<runtime>/<version>/  shared, read-only to every sandbox (later: milestone 1 installs per sandbox, ADR 0020)
  templates/                   user templates
  run/<sandbox>/               proxy control sockets
  sandboxes/<name>/
    sandbox.toml               backend, runtime, agents (autostart), created_at
    policy.toml                overrides: the input to the next policy change (snapshots in state.db)
    compiled/<snapshot>-<enclos version>/   what the backend received (.sb, bwrap argv)
    installers/                the runtime's installer and files for the home, checked on the host; the sandbox reads, never writes them
    home/                      the runtime's home: agents, skills, environments, bin/, caches, tmp/
    logs/                      its services' output
```

On Linux: `config.toml` and `templates/` in `$XDG_CONFIG_HOME/enclos`, everything else in `$XDG_DATA_HOME/enclos`. `ENCLOS_HOME` puts everything in one folder instead, on either system. Every state-changing command takes a lock, records its intent, does the work, then records result and new state. A crash leaves an unfinished entry, which `enclos audit verify` lists as a warning. A crash in the middle of writing a line leaves that line incomplete: `audit verify` warns about it, and the next state-changing command moves it to `audit.jsonl.torn-<line>` and records the move, with the removed bytes' hash, as a `recovered` line in the chain. Any other damage still stops every write until it is repaired. `enclos state check` compares records with reality (service units, sessions and their members, files, compiled policy).

## 12. Secrets and subscriptions

- Secrets live in the macOS Keychain, libsecret, or a `0600` file on a headless machine, referenced as `secret:<sandbox>/<name>`, and reach a sandbox only as environment variables, through `enclos launch` ([ADR 0022](adr/0022-secrets-granted-per-sandbox.md)). They are granted per sandbox: every session, whichever agent it runs, and the runtime's gateway receive the same variables, and agents that must not share a secret go in different sandboxes. The sandbox itself is meant to have no Keychain access (planned, to verify with the host-service probes).
- **Subscriptions, v1 (host backends):** the runtime's own login runs inside the sandbox and stays in its home. The first is Hermes with an existing ChatGPT subscription, through Hermes's supported login flow; its login endpoints come from the Hermes adapter. Because the sandbox cannot open a browser on the host, enclos supports only device-code logins: Hermes prints a URL and a short code, and the user opens the URL on the host. enclos makes no network exception for logins (no localhost callback port), and does not copy tokens in from a login made on the host. Hermes documents this login (its OpenAI Codex provider, "ChatGPT OAuth") as a device-code flow, and stores the credential in its own home (`~/.hermes/auth.json` inside the sandbox). Hermes can also import a host Codex CLI login from `~/.codex/auth.json`; inside the sandbox that path is on the read deny list, so the import is unavailable by design. That the login completes inside the sandbox is to verify (§14). Once logged in, every agent in the sandbox can read the runtime's refresh token; enclos flags it.
- **Subscriptions, v2:** one refresh owner on the host keeps the renewable credential; sandboxes get only short-lived access tokens.

## 13. Milestones

Each milestone holds only what its goal needs; everything else waits for a later one.

1. **Hermes sandboxes on a Mac** — goal: several Hermes sandboxes on the user's Mac, each with several agents running as background services, safe enough to start testing. In scope:
   - a prototype first, which settles the milestone 1 items in §14 before the code depends on them;
   - CLI, `init`, the `~/.enclos` layout, the state store with its lock, and the hash-chained audit log with `audit verify`;
   - the `assistant` template, policy resolution into immutable snapshots (§7), `policy show` and `policy allow`;
   - the Seatbelt backend: write rules, the sensitive deny list, protected paths, host-service blocks and proxy-only network, on the `(allow default)` baseline;
   - the per-sandbox proxy, the allowlist, immediate deny, address validation, `net log` and `net denied`;
   - the Hermes adapter: the shared runtime, writable install space in the home, agents, and the device-code subscription login;
   - `sandbox create`, `list`, `show`, `rm`; `agent add`, `list`, `rm`; `connect`;
   - launchd agents for each sandbox's proxy and each agent while the user is logged in, autostart, `sandbox` and `agent` `start`, `stop`, `restart`, and `logs`;
   - sessions and member tracking, with stop over every member;
   - `policy test` with the escape probes listed in the acceptance scenario.

   Deliberately not yet, with the behavior milestone 1 has instead: a change that needs a restart asks first, and if the user declines nothing changes (the pending policy comes in milestone 2); network changes apply live; there are no secrets, since the only credential is the runtime's own login in the sandbox home.

   Done when the acceptance scenario below passes.
2. **Policy lifecycle, messaging and hardening** — the pending policy with `policy apply` and `discard`; `policy refresh`, `diff`, `history` and `rollback`; the TLS server-name check; secrets granted per sandbox, stored in the Keychain and passed through `enclos launch`; Hermes messaging (Telegram first); `state check` and `repair`; `doctor`; `--json` output; `exec`; resource limits; the `minimal` and `mcp-only` templates; the evidence ADR 0006 asks for, and its decision.
3. **Breadth**, in this order unless needs change:
   1. The host-service forward (one named host port to one sandbox).
   2. Coding agents: Claude Code and Codex adapters (interactive), the `coding` template writing in place to the selected project folder.
   3. Linux: the bubblewrap backend with Landlock, seccomp and cgroups; the same policy file runs on Mac and Pi.
   4. UI: `enclos ui` with sandboxes, policy editor, active and pending policy, live network log, denials, state and audit.
   5. More backends: OpenShell, then a microVM (libkrun first, macOS and Linux). Host-owned subscription refresh.

**Acceptance scenario (milestone 1).** On a Mac, with the user logged in and an existing ChatGPT subscription:

1. The steps in §10's first working flow run without manual edits to files: two sandboxes, each with two Hermes agents, every agent logged in through Hermes's device-code flow.
2. `enclos sandbox start` on both sandboxes leaves each proxy and each agent running under launchd, and they keep running after the terminal that started them closes. `enclos sandbox show` lists every agent, session and member, and the snapshot each session started under.
3. Through `enclos connect <sandbox> -- <hermes command>`, each agent is asked for the current weather in several locations and answers with conditions for each. Hermes picks its own tools, browser or skills; the scenario neither names a weather provider nor uses MCP, and no template or adapter allows a weather service in advance.
4. Anything Hermes installs on the way (skills, packages, tools, a browser) lands in that sandbox's home, and the shared runtime, enclos's files and the other sandbox are unchanged.
5. Every connection appears in `enclos net log` for the sandbox that made it. If Hermes is refused a destination, it shows in `enclos net denied`; the user may allow it from the host with `enclos policy allow` and ask again, without a restart. Hermes cannot allow anything itself. If Hermes gets the weather through a remote service, such as the model provider's own web search, the log shows only that service, and that is reported as a granted capability, not as isolation.
6. `enclos policy test` on each sandbox runs at least these probes, all of which must fail to do what they try: every host-service route in §5 (including DNS), reads of each default sensitive path and protected path, reads and writes of the other sandbox's folder, a write outside the home, a connection to an unlisted destination, and connections to loopback, link-local and private addresses through an allowed name. The report lists every probe run.
7. `enclos sandbox stop` ends every member, including services, interactive sessions and any browser or installer Hermes started, and `enclos sandbox show` reports none left.
8. `enclos audit verify` passes, and the audit log holds an entry for every state-changing command in the scenario.

## 14. Awaiting prototype verification

The design depends on these, and none has been shown to work yet. The milestone 1 prototype resolves each one, except the ADR 0006 evidence, which milestone 2 gathers; the result is recorded in the design or an ADR.

- How Hermes creates and selects the profiles it keeps agents in (`HERMES_HOME`, `~/.hermes/profiles/<name>/`), and whether each agent needs its own login or shares one per sandbox.
- What Hermes runs as a background service when no messaging platform is configured, and that a `connect` session to an agent can run alongside that agent's service.
- The Seatbelt rules that block host-service delegation, with one escape probe per route in §5 ([ADR 0016](adr/0016-seatbelt-blocks-host-service-delegation.md)).
- The evidence ADR 0006 needs to decide between `(allow default)` and `(deny default)`.
- How macOS members are tracked, including processes that leave their process group (§8).
- That Hermes's documented device-code login for a ChatGPT subscription completes inside the sandbox through the proxy, which endpoints it needs (they go into the Hermes adapter), and that the refreshed credential keeps working across sessions.
- That Hermes's setup wizard, `hermes setup`, completes inside the sandbox through the proxy: the prototype logged in with `hermes model`, which covers only provider, login and model. A wizard section that acts on the host (installing a launchd job, for example) would be refused.
- That Hermes, its model calls, its installers (Python and Node package managers, skill downloads) and any headless browser it starts work through `HTTPS_PROXY` with writes limited to the home, and which install sources the Hermes adapter must allow.
- Whether a browser started inside Seatbelt needs its own sandbox disabled to run, which would leave only enclos's.
- Whether runtimes need writes to system temp or cache folders beyond `TMPDIR`.
- That denying mDNSResponder removes DNS from the sandbox without breaking clients that use the proxy.
- That the proxy environment variables reach every client Hermes and its installers use, including curl and Node's `fetch`.
- Whether Hermes's single gateway can take each agent's channel credentials (such as one Telegram bot token per agent) from environment variables, since secrets reach a sandbox only that way ([ADR 0022](adr/0022-secrets-granted-per-sandbox.md)). Milestone 2.
- The unified-log predicate for Seatbelt denials, how lines are attributed to a sandbox, and whether streaming needs admin rights.

## 15. Open decisions

Decided since the first draft: Rust as the language; a domain-level CONNECT proxy without TLS interception ([ADR 0007](adr/0007-network-through-a-proxy-per-sandbox.md)); one runtime per sandbox ([ADR 0003](adr/0003-sandbox-is-the-permission-boundary.md)); launchd and systemd user units ([ADR 0002](adr/0002-no-daemon.md)); the threat model ([ADR 0014](adr/0014-threat-model-accidental-damage.md)); unknown destinations denied without asking; stricter enclos-owned rules apply on upgrade without asking ([ADR 0018](adr/0018-immutable-policy-snapshots.md)); device-code logins only (§12); a server name check on TLS tunnels (§6); secrets granted per sandbox ([ADR 0022](adr/0022-secrets-granted-per-sandbox.md)); each host managed locally, with no `--host` option for now.

| Decision | Recommendation |
| --- | --- |
| Host-service forward mechanism | Decided: milestone 3.1, one named host port to one sandbox per grant, never a loopback range. Open: how it is exposed. Recommendation: its own listener (a Unix socket on Linux, a dedicated localhost port on macOS), logged per connection and audited when granted. |
