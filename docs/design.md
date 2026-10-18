# enclos — design

*enclos* (French for an enclosure, said "ahn-KLOH") is an open-source CLI that creates sandboxes, installs AI agents in them (Hermes, Claude Code, Codex, OpenClaw), and keeps a proper state and an audit log of every command. It manages only the sandboxes it creates.

Status: design, before the first line of code. Target platforms: macOS on Apple Silicon and Linux (including Raspberry Pi). Windows through WSL2 later.

This document describes what enclos is and how it works. Decisions that are hard to reverse, and why they were made, are recorded in [`docs/adr/`](adr/). When this document and an ADR disagree, fix one of them in the same change.

---

## 1. Principles

1. **Control, not coordinate.** enclos isolates and governs agents. It never routes tasks between agents, delegates work, or models organizations.
2. **The CLI is the product.** Every operation is a command with readable and `--json` output. The web UI, an MCP server and scripts are clients of the same core and write the same audit log.
3. **Manage only what you create.** No background collector, no scanning for agents enclos did not start.
4. **Interfaces everywhere.** Each component has one job behind one interface. A new sandbox technology, secret store or agent runtime is one new implementation, with no change in the core.
5. **Typed models at every boundary.** Nothing untyped crosses a component boundary. Files on disk carry a `schema_version`.
6. **Never claim isolation that is not enforced or tested.** If a backend cannot enforce a policy field, enclos says so and refuses unless told otherwise. `enclos policy test` proves enforcement with probes that must fail.
7. **Network is enforced by enclos, not by the backend.** Each sandbox reaches the outside only through its own egress proxy, which applies a domain allowlist and logs every request.
8. **Readable code first.** Small files, explicit registration, no clever abstractions until a third implementation needs them.

## 2. Scope

**v1 goals**

- Create, start, stop, connect to and remove sandboxes from the CLI.
- Per-sandbox policy for files, network, programs, secrets and resources: edit, diff, roll back, test.
- Install an agent runtime in a sandbox and run one or more of its profiles there, for example several Hermes profiles in one sandbox.
- See each sandbox's network log, blocked requests and denials.
- Keep a state of every sandbox and an audit entry for every state-changing command.
- Seatbelt backend on macOS first, then bubblewrap on Linux.

**Non-goals**

- Agent-to-agent delegation, task routing, organizations, pull request workflows.
- A collector or discovery of agents enclos did not create.
- Remote control over chat channels.
- Writing our own isolation primitives: backends wrap OS features and existing VMs.
- Hosting agents for other people (multi-tenant).

## 3. Concepts

| Concept | What it is | Example |
| --- | --- | --- |
| Host | A machine where the CLI runs and keeps its state. Another host is managed by running the CLI there over SSH. | `mac`, `pi` |
| Sandbox | A named, persistent isolated environment created by enclos: backend, policy, home folder, mounts, lifecycle state. | `dev` (Seatbelt), `community` (bubblewrap) |
| Policy | What a sandbox may do. Versioned, layered on a template, compiled per backend. | `extends = "mcp-only"` plus overrides |
| Agent | The agent runtime installed in a sandbox. One agent per sandbox. | Hermes, Claude Code, Codex |
| Profile | A named configuration of the agent with its own memory, skills, model and channels, run as its own service or session. A sandbox can hold several profiles; they share the sandbox's policy, proxy and secrets. Agents without profiles (Claude Code, Codex) have one `default` profile. | Hermes profiles `support` and `writer` in sandbox `community` |
| Audit entry | One record per state-changing command: time, user, host, command, state before and after, result. Append-only, hash-chained. | `enclos policy allow community github.com` |

Templates are reusable policies: `minimal`, `mcp-only`, `assistant`, `coding`.

**The sandbox is the permission boundary, the profile is not.** Profiles in one sandbox can read each other's files, because they share one policy. Profiles that need different permissions (a dev profile with a shell, a community profile limited to MCP) go in different sandboxes.

## 4. Architecture

There is no daemon. The CLI is a thin layer over a core library; running sandboxes are ordinary launchd (macOS) or systemd user (Linux) services that the core creates.

```text
  enclos (CLI)      enclos ui      enclos mcp / scripts
        \               |               /
         +------- Core library --------+
         | State + audit | Policy compiler | Agent adapters | Backend API |
                                   |
          +------------+-----------+-----------+
       Seatbelt    bubblewrap   OpenShell   MicroVM        (first: Seatbelt, bubblewrap)
          |
   Service units (launchd / systemd), per sandbox:
     [profile A] --+
     [profile B] --+--> [egress proxy, one per sandbox] --> allowed domains only
     (all profiles run inside the same sandbox policy)
```

Each sandbox has one proxy unit, `enclos.<sandbox>.proxy`, and one unit per running profile, `enclos.<sandbox>.<profile>`. A profile unit always runs `enclos launch <sandbox>/<profile>`, which executes outside the sandbox, reads the secrets, and then runs the wrapped agent command for that profile. Secrets never sit in a plist or unit file. Each profile gets its own listener port on the proxy, so the network log is per profile; this attribution is informative, not a security boundary, since profiles share a policy.

## 5. Isolation backends

| Policy field | Seatbelt (macOS) | bubblewrap (Linux) | OpenShell | MicroVM (libkrun, Firecracker) |
| --- | --- | --- | --- | --- |
| Isolation level | process, shared kernel | process, shared kernel | container, shared kernel | VM, own kernel |
| File writes | yes | yes (mount namespace + Landlock) | yes | yes |
| File read deny list | yes | yes (paths not mounted) | yes | yes |
| Programs allowed | yes (`process-exec` rules) | partial (mounted binaries + Landlock execute) | yes | yes |
| Network (via proxy) | yes (localhost port only) | yes (no network namespace + proxy socket) | yes | yes (vsock or host IP) |
| CPU and memory limits | partial (`ulimit`, `taskpolicy`) | yes (cgroups via `systemd-run --user`) | yes | yes |
| Change without restart | network only | network only | network only | network only |
| Subscriptions work as-is | yes | yes | needs token delivery | needs token delivery |

**Security level, honestly stated.** Seatbelt and bubblewrap share the host kernel and user: they stop a misled agent from reading `~/.ssh` or deleting repos, not deliberately malicious code exploiting a kernel bug. That fits personal agents and coding agents. Agents that read untrusted outside content with a shell, or run untrusted code, belong in a container or microVM backend. Most real risk is an agent misusing permissions it was given (exfiltration through an allowed domain, deleting its workspace), which only a narrow policy and logging address, on every backend.

### Seatbelt specifics (first backend)

- `compile` renders an `.sb` profile: `(allow default)`, then `(deny file-write*)` with writes allowed only to the sandbox home, workspace and temp folders; `(deny file-read*)` on a deny list (`~/.ssh`, `~/.aws`, `~/.config/gh`, other sandboxes' homes, other agents' config folders) with the sandbox's own home re-allowed (later rules win); `(deny network*)` with outbound allowed only to the sandbox's proxy port on localhost; optional `process-exec` allowlist when `shell = false`. [ADR 0006](adr/0006-seatbelt-deny-by-default.md) proposes starting from `(deny default)` instead; the milestone 2 prototype decides.
- `wrap` returns `/usr/bin/sandbox-exec -f <profile> -D HOME=<home> -- <cmd>` with `HTTPS_PROXY` and `HTTP_PROXY` set to the sandbox's proxy.
- A Seatbelt profile is fixed for the life of the process and its children. Network allowlist changes are live because the proxy enforces them; file, program and resource changes need a restart, which the CLI announces and offers.
- **Denials.** Two sources:
  1. The proxy log: every request with its domain, allowed or blocked. This is the main network view.
  2. The macOS unified log: the kernel logs Seatbelt denials, for example `Sandbox: python3(4182) deny(1) file-read-data /Users/x/.ssh/id_ed25519` and `deny(1) network-outbound 140.82.112.4:443`, readable with `log stream --predicate 'sender == "Sandbox"'`. Lines are attributed to a sandbox by process ID or a tag. macOS collapses repeated identical denials.
- **To prove in the prototype:** the exact log predicate and attribution method, whether streaming needs admin rights, and that Hermes (Python `httpx`/`requests`), Telegram polling and model calls work through `HTTPS_PROXY`.
- `sandbox-exec` is marked deprecated by Apple but still ships and is used by major tools. Track it as a risk.

### Unknown domains

The proxy can hold a request to a domain not on the list and ask: allow once, always, or deny (`enclos net pending`, or a notification). "Always" writes a policy change and an audit entry. This builds a policy for a new agent without guessing its endpoints upfront.

## 6. Policy format

A policy is TOML that extends a template and overrides only what differs. Layers resolve in order: built-in defaults, template, the sandbox's `policy.toml`. Lists replace (`allow = [...]`) or extend (`allow_add = [...]`).

```toml
# ~/.enclos/sandboxes/community/policy.toml
extends = "mcp-only"

[filesystem]
write = ["{home}", "{tmp}"]
read_deny_add = ["~/dev/work"]

[exec]
shell = false                      # only the listed programs run
allow = ["{runtime}/bin/python3", "node"]

[network]
allow = ["api.openai.com", "chatgpt.com", "api.telegram.org"]
unknown = "ask"                    # or "deny"
log = "metadata"                   # host, method, bytes; never bodies

[resources]
memory = "1G"
cpu = 1.0

[secrets]
env = { TELEGRAM_BOT_TOKEN = "secret:community/telegram" }
```

| Template | Files | Programs | Network | Use for |
| --- | --- | --- | --- | --- |
| `minimal` | own home | the runtime only | model provider only | a starting point |
| `mcp-only` | own home | runtime and its MCP servers | model provider + listed MCP endpoints | assistants working on outside data |
| `assistant` | own home, read-only documents folder | runtime, MCP servers | model provider, messaging, listed APIs | personal agents |
| `coding` | own home + one workspace read-write | any | model provider, Git hosts, package registries | Claude Code, Codex, a dev agent |

Network validation: no loopback, link-local or wildcard entries; private IP literals only with an explicit opt-in. Each agent adapter contributes the endpoints its runtime needs to work at all. Every change is stored as a version with author and time.

## 7. Component APIs

Sketches in Rust. The `Engine` is the only code that combines components.

**Models**

```rust
pub struct SandboxName(String);              // [a-z][a-z0-9-]{1,40}
pub enum BackendKind { Seatbelt, Bubblewrap, OpenShell, Libkrun }
pub enum AgentKind { Hermes, ClaudeCode, Codex, OpenClaw }

pub struct ProfileName(String);              // same rules; "default" for agents without profiles

pub struct SandboxSpec { pub name: SandboxName, pub backend: BackendKind, pub template: TemplateName,
                         pub workspace: Option<PathBuf>, pub agent: Option<AgentKind> }
pub struct SandboxRecord { pub spec: SandboxSpec, pub state: SandboxState, pub policy_version: u32,
                           pub profiles: Vec<ProfileRecord>, pub created_at: Timestamp }
pub struct ProfileRecord { pub name: ProfileName, pub autostart: bool, pub state: SandboxState,
                           pub proxy_port: u16 }          // per-profile listener, for the network log
pub enum SandboxState { Created, Running, Stopped, Failed { reason: String } }

pub struct Target { pub sandbox: SandboxName, pub profile: Option<ProfileName> }  // "community" or "community/support"

pub struct Policy { pub fs: FsPolicy, pub exec: ExecPolicy, pub net: NetPolicy,
                    pub resources: Resources, pub secrets: Vec<SecretGrant> }
pub enum Enforcement { Enforced, Partial { note: String }, Unsupported }
pub struct Capabilities { pub isolation: Isolation, pub fs: Enforcement, pub exec: Enforcement,
                          pub resources: Enforcement, pub live: Vec<PolicyArea> }
```

**Policy** (pure functions)

```rust
pub fn resolve(template: &PolicyFile, overrides: &PolicyFile) -> Result<Policy, PolicyError>;
pub fn validate(policy: &Policy, caps: &Capabilities) -> Vec<Finding>;
pub fn diff(before: &Policy, after: &Policy) -> PolicyDiff;
pub fn needs_restart(diff: &PolicyDiff, caps: &Capabilities) -> bool;
```

**Backend** (prepares and wraps; never supervises)

```rust
pub trait Backend {
    fn kind(&self) -> BackendKind;
    fn probe(&self) -> Probe;
    fn capabilities(&self) -> Capabilities;
    fn compile(&self, policy: &Policy, ctx: &SandboxContext) -> Result<Compiled>;   // pure
    fn prepare(&self, sb: &SandboxRecord, compiled: &Compiled) -> Result<()>;
    fn wrap(&self, sb: &SandboxRecord, cmd: &Command) -> Result<Command>;
    fn denials(&self, sb: &SandboxRecord, since: Timestamp) -> Result<Vec<Denial>>;
    fn teardown(&self, sb: &SandboxRecord, keep_data: bool) -> Result<()>;
    fn up(&self, _sb: &SandboxRecord) -> Result<()> { Ok(()) }     // a VM boots here
    fn down(&self, _sb: &SandboxRecord) -> Result<()> { Ok(()) }
}
```

**Egress proxy**

```rust
pub fn decide(net: &NetPolicy, host: &str, port: u16) -> Decision;   // Allow | Deny | Ask
pub struct ProxyConfig { pub sandbox: SandboxName, pub listen: SocketAddr, pub net: NetPolicy, pub events: PathBuf }
pub struct NetEvent { pub at: Timestamp, pub host: String, pub port: u16, pub verdict: Verdict,
                      pub bytes_up: u64, pub bytes_down: u64 }
pub enum ProxyRequest { Reload, Pending, Answer { id: u64, verdict: Verdict, remember: bool } }
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

**State store and audit log.** A write requires a `StateLock`, so writing outside the lock does not compile; an `AuditTicket` is consumed by `finish`.

```rust
pub trait StateStore {
    fn lock(&self) -> Result<StateLock>;
    fn get(&self, name: &SandboxName) -> Result<Option<SandboxRecord>>;
    fn list(&self) -> Result<Vec<SandboxRecord>>;
    fn put(&self, lock: &StateLock, rec: &SandboxRecord) -> Result<()>;
    fn remove(&self, lock: &StateLock, name: &SandboxName) -> Result<()>;
    fn save_policy(&self, lock: &StateLock, name: &SandboxName, file: &PolicyFile, by: &Actor) -> Result<PolicyVersion>;
    fn policy_history(&self, name: &SandboxName) -> Result<Vec<PolicyVersion>>;
}

pub trait AuditLog {
    fn begin(&self, lock: &StateLock, intent: Intent) -> Result<AuditTicket>;
    fn finish(&self, ticket: AuditTicket, outcome: Outcome) -> Result<()>;
    fn entries(&self, filter: &AuditFilter) -> Result<Vec<AuditEntry>>;
    fn verify(&self) -> Result<VerifyReport>;
}
```

**Agent adapter**

```rust
pub trait AgentAdapter {
    fn kind(&self) -> AgentKind;
    fn supports_profiles(&self) -> bool;                                        // Hermes: yes; Claude Code, Codex: no
    fn requirements(&self) -> PolicyFragment;
    fn install(&self, runtimes: &Path, version: &Version) -> Result<Runtime>;   // shared, read-only
    fn init_home(&self, sb: &SandboxRecord, runtime: &Runtime) -> Result<()>;

    fn add_profile(&self, sb: &SandboxRecord, profile: &ProfileSpec) -> Result<()>;    // model, skills, channels
    fn remove_profile(&self, sb: &SandboxRecord, profile: &ProfileName, keep_data: bool) -> Result<()>;
    fn configure(&self, sb: &SandboxRecord, profile: &ProfileName, cfg: &ProfileConfig) -> Result<ConfigDiff>;
    fn command(&self, sb: &SandboxRecord, profile: &ProfileName, mode: RunMode) -> Command;   // Service | Interactive
}
```

For Hermes, all profiles live under the sandbox's Hermes home and run the same shared Hermes install; `command` selects the profile.

**Engine** — the API every client calls. Reads are not audited. Every write takes the lock, opens an audit entry, does the work, saves state and closes the entry, also on failure. `Confirm::DryRun` returns the plan without changing anything.

```rust
impl Engine {
    pub fn list(&self) -> Result<Vec<SandboxView>>;
    pub fn show(&self, name: &SandboxName) -> Result<SandboxView>;
    pub fn policy(&self, name: &SandboxName, compiled: bool) -> Result<PolicyView>;
    pub fn net_log(&self, name: &SandboxName, since: Timestamp) -> Result<Vec<NetEvent>>;
    pub fn denials(&self, name: &SandboxName, since: Timestamp) -> Result<Vec<Denial>>;

    pub fn create(&self, by: &Actor, spec: SandboxSpec, confirm: Confirm) -> Result<Planned<SandboxRecord>>;
    pub fn add_profile(&self, by: &Actor, sandbox: &SandboxName, profile: ProfileSpec) -> Result<ProfileRecord>;
    pub fn remove_profile(&self, by: &Actor, target: &Target, keep_data: bool, confirm: Confirm) -> Result<Planned<()>>;
    pub fn start(&self, by: &Actor, target: &Target) -> Result<SandboxRecord>;   // a sandbox: its proxy + autostart profiles
    pub fn stop(&self, by: &Actor, target: &Target) -> Result<SandboxRecord>;
    pub fn remove(&self, by: &Actor, name: &SandboxName, keep_data: bool, confirm: Confirm) -> Result<Planned<()>>;
    pub fn change_policy(&self, by: &Actor, name: &SandboxName, change: PolicyChange, confirm: Confirm) -> Result<Planned<PolicyApplied>>;
    pub fn rollback_policy(&self, by: &Actor, name: &SandboxName, to: u32, confirm: Confirm) -> Result<Planned<PolicyApplied>>;
    pub fn answer_pending(&self, by: &Actor, name: &SandboxName, id: u64, verdict: Verdict, remember: bool) -> Result<()>;
    pub fn test_policy(&self, by: &Actor, name: &SandboxName) -> Result<TestReport>;
    pub fn connect(&self, by: &Actor, target: &Target) -> Result<Command>;   // a shell, or a profile's interactive session
    pub fn exec(&self, by: &Actor, name: &SandboxName, cmd: Command) -> Result<Command>;
    pub fn launch(&self, target: &Target) -> Result<Infallible>;   // called by a profile's service unit
}
```

**`enclos sandbox start community`, step by step**

1. Take the state lock; open an audit entry.
2. Load the record, resolve the policy, compile it, `prepare`.
3. Install and start the proxy unit with the sandbox's `NetPolicy` and one listener per profile.
4. `up` (nothing for Seatbelt); for each autostart profile, install and start its unit (`enclos launch community/<profile>`).
5. Wait for the units to report running; save each profile's state and the sandbox as `Running`; close the audit entry as ok.
6. On failure: stop what started, save `Failed { reason }` on what failed, close the audit entry as failed.

`enclos profile start community/support` does steps 1, 4 and 5 for one profile, starting the proxy first if it is not running.

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
  engine.rs        the API above; the only place components meet
  model/           sandbox.rs  policy.rs  net.rs  audit.rs
  policy/          resolve.rs  validate.rs  diff.rs  templates/*.toml
  backend/         mod.rs (trait)  seatbelt/{compile.rs, wrap.rs, denials.rs, base.sb}
  proxy/           decide.rs  server.rs  control.rs
  service/         mod.rs (trait)  launchd.rs  systemd.rs
  secrets/         mod.rs (trait)  keychain.rs  file.rs
  state/           mod.rs (trait)  sqlite.rs
  audit/           mod.rs (trait)  jsonl.rs
  agent/           mod.rs (trait)  hermes.rs  claude_code.rs  codex.rs
```

## 8. CLI

Every operation is `enclos <noun> <verb>`. Readable output in a terminal, JSON when piped or with `--json`. Exit codes: 0 ok, 1 error, 2 refused by policy, 3 needs confirmation. Changes print a diff and ask; `--yes` skips, `--dry-run` only shows. `--host <name>` runs the command on another host over SSH.

```text
enclos init | doctor
enclos backend list | probe <name>

enclos sandbox create <name> --backend seatbelt --template coding [--workspace ~/dev/x]
enclos sandbox list | show <name> | start | stop | restart    proxy + all autostart profiles
enclos sandbox rm <name> [--keep-data]
enclos connect <name>[/<profile>]             a shell, or a profile's interactive session
enclos exec <name> -- <cmd...>
enclos logs <name>[/<profile>] [-f]

enclos profile add <name>/<profile> [--model ...] [--no-autostart]
enclos profile list <name>
enclos profile start | stop | restart <name>/<profile>
enclos profile rm <name>/<profile> [--keep-data]

enclos policy show <name> [--compiled]
enclos policy edit <name>
enclos policy allow <name> <domain> | deny-read <name> <path>
enclos policy diff | history | rollback <name> [--to <version>]
enclos policy test <name>
enclos template list | show <template>

enclos agent install <type> --sandbox <name> [--version x]
enclos agent configure <name>[/<profile>] [--model ...] [--mcp-add name=url]
enclos agent login <name> --api-key secret:<ref> | --subscription

enclos secret set | list | rm <ref>
enclos net log <name>[/<profile>] [-f] | net pending <name>
enclos denials <name>

enclos state show | check | repair <name>
enclos audit [<name>] [--since 7d] | audit verify

enclos apply -f stack.toml
enclos ui
enclos mcp
```

Example: a dev sandbox with one Hermes profile and a shell, and a community sandbox with two Hermes profiles that reach data only through MCP.

```bash
enclos sandbox create dev --backend seatbelt --template coding --workspace ~/dev/app
enclos agent install hermes --sandbox dev
enclos profile add dev/coder
enclos agent login dev --subscription

enclos sandbox create community --backend seatbelt --template mcp-only
enclos agent install hermes --sandbox community
enclos profile add community/support
enclos profile add community/writer
enclos agent configure community --mcp-add data=http://127.0.0.1:8820/mcp   # every profile
enclos policy allow community api.telegram.org
enclos secret set community/telegram-support
enclos secret set community/telegram-writer

enclos policy test community        # ~/.ssh unreadable, curl refused, github.com blocked
enclos sandbox start dev community  # proxies + coder, support, writer
enclos net log community/support -f
```

## 9. State, audit and files

```text
~/.enclos/
  config.toml                  default backend, secret store, UI port, allowed UI actions
  state.db                     SQLite: sandbox records, policy versions, network log, denials
  audit.jsonl                  append-only, one hash-chained line per state-changing command
  runtimes/<agent>/<version>/  shared, read-only to every sandbox
  templates/                   user templates
  sandboxes/<name>/
    sandbox.toml               backend, agent, profiles (autostart, proxy port), created_at
    policy.toml                current policy (history in state.db)
    compiled/                  what the backend received (.sb, bwrap argv)
    home/                      the agent's home, with all its profiles
    logs/<profile>/
```

On Linux: `$XDG_DATA_HOME/enclos` and `$XDG_CONFIG_HOME/enclos`. Every state-changing command takes a lock, records its intent, does the work, then records result and new state. A crash leaves an unfinished entry; `enclos state check` compares records with reality (service units, processes, files, compiled policy).

## 10. Secrets and subscriptions

- Secrets live in the macOS Keychain, libsecret, or a `0600` file on a headless machine, referenced as `secret:<sandbox>/<name>`, and reach a sandbox only as environment variables at launch.
- **Subscriptions, v1 (host backends):** the runtime's own login stays in the sandbox home (Claude Code `setup-token`, Codex login, Hermes's Codex provider). It works, but the agent can read its own refresh token; enclos flags it.
- **Subscriptions, v2:** one refresh owner on the host keeps the renewable credential; sandboxes get only short-lived access tokens.

## 11. Milestones

1. **Skeleton** — CLI, `~/.enclos` layout, state, audit with hash chain, `Backend` trait, `init`, `doctor`, `audit`. Done when `enclos audit verify` passes.
2. **Seatbelt + proxy** — Seatbelt backend, per-sandbox proxy, templates, sandbox lifecycle, `connect`, `exec`, `policy edit/test`, `net log`, Hermes adapter with service mode. Profiles. Done when a Hermes sandbox runs two profiles on a Mac, a second sandbox runs a dev profile, and `policy test` passes on both.
3. **Coding agents** — Claude Code and Codex adapters (interactive), `coding` template, Keychain secrets.
4. **bubblewrap** — Linux backend with Landlock, seccomp, cgroups; the same policy file runs on Mac and Pi.
5. **UI** — `enclos ui`: sandboxes, detail with policy editor and live network log, denials, state, audit.
6. **More backends** — OpenShell, then a microVM (libkrun first: macOS and Linux). Host-owned subscription refresh.

## 12. Open decisions

Decided since the first draft: Rust as the language; a domain-level CONNECT proxy without TLS interception ([ADR 0007](adr/0007-network-through-a-proxy-per-sandbox.md)); one agent runtime per sandbox ([ADR 0003](adr/0003-sandbox-is-the-permission-boundary.md)); launchd and systemd user units ([ADR 0002](adr/0002-no-daemon.md)).

| Decision | Recommendation |
| --- | --- |
| Secrets per profile | Today secrets are granted per sandbox, so every profile can read them. Per-profile grants (each profile's unit gets only its own variables) are easy to add, but all profiles can still read the shared home. |
| Remote hosts | CLI over SSH. |
| Seatbelt denial attribution | Prove in the prototype: process ID vs profile tag. |
