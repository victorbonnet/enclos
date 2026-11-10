# enclos

*enclos* (French for an enclosure, said "ahn-KLOH") creates sandboxes on your machine, installs agent runtimes in them and runs agents there, with a policy and an audit log. It manages only the sandboxes it creates.

> **Status: first release, 0.1.0.** enclos runs [Hermes](https://hermes-agent.nousresearch.com) agents in Seatbelt sandboxes on an Apple silicon Mac. It is early software: read its [known gaps](docs/release-notes/0.1.0.md), and expect state may not carry over between 0.x releases.

## Why

Agents such as Hermes install tools, run code and reach the network on their own. enclos gives each runtime a sandbox of its own, so a misled agent cannot read your SSH keys, delete your files or talk to hosts you did not allow:

- **Files:** it writes only to its own home. It reads broadly, except a deny list of sensitive paths such as `~/.ssh`, cloud credentials and other tools' logins, keychains, password managers, browser data, mail and Apple apps' data, shell history, the configuration of your own assistant tools on the host (`~/.hermes`, `~/.claude`, `~/.codex` and others), other sandboxes and enclos's own files. Agents in the same sandbox share its home and can read each other's files.
- **Network:** it connects out only through its own proxy, which logs every connection it decides on (as long as enclos can write its state) and never connects to your Mac's own services, cloud metadata addresses or, unless you opt a host in, your local network. What Hermes's gateway serves is the exception, [below](#files-and-network-together). An agent may reach the public web (ports 80 and 443) by default, or only the domains you list if you set its policy to allowlist mode. You review what was refused and allow what you trust, without a restart.
- **The rest of your Mac:** opening apps, Apple Events, launchd jobs, preferences, the pasteboard and signals to other processes are blocked. One thing macOS lets every process of yours do, sandboxed or not: read the environment variables your other programs started with (Apple's own programs aside). Don't keep secrets in exported shell variables while sandboxes run. enclos gives a Hermes gateway its secrets through a file no other sandbox reads; a `connect` or `exec` session still gets them as variables, which other sandboxes can read while it runs.
- **A record:** every command that changes something is written to a hash-chained audit log.

enclos protects against accidental damage by agents you mostly trust ([threat model](docs/adr/0014-threat-model-accidental-damage.md)). It is not a defense against malicious code exploiting the kernel.

## The words

| Word | Meaning |
| --- | --- |
| **Sandbox** | A named, isolated environment with its own home folder, policy and proxy. The permission boundary. |
| **Runtime** | The software installed in a sandbox to run its agents, such as Hermes. One per sandbox. |
| **Agent** | A named identity of the runtime, with its own configuration, memory, skills, sessions and channels. Agents in a sandbox share its runtime, policy, proxy and secrets; each may also be granted its own, such as its bot's token. |
| **Policy** | What a sandbox may do with files, network and host services, stored as immutable snapshots. |

More in the [glossary](GLOSSARY.md).

## How it works

enclos adds no container and no VM. It uses the sandbox your operating system already has: on macOS, Seatbelt, through `sandbox-exec`. A session starts under its sandbox's compiled policy, and everything that session starts stays under it, whether a helper, an installer or a browser. On Linux, bubblewrap does the same in [milestone 3](docs/design.md#13-milestones), which is on `main` but in no release yet: there each sandbox has a network namespace of its own, and a Unix socket to its proxy. The rest of this section describes Seatbelt.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/sandbox-dark.svg">
  <img alt="The sandbox lab, on your Mac, holds Hermes and its agents, its home and any workspaces you grant, all read and write. From inside it, reading the rest of your disk is allowed. Reading the deny list, reaching host services and connecting anywhere but the proxy are refused. Connecting to the egress proxy, on the host outside the sandbox, is allowed, and the proxy connects to the public web or your allowlist, and refuses the host itself, cloud metadata and private addresses your policy has not opted in. Peers on your Mac and its network can connect to Hermes's gateway, which answers them without the proxy or the network log." src="docs/diagrams/sandbox-light.svg">
</picture>

### Files and network, together

Each limit needs the other. Without the file limits, an agent could read your SSH keys. Without the network limits, it could send what it reads anywhere. Reads are broad, so the two set what a mistake can cost: the deny list decides what an agent cannot read at all, and the network mode decides where the rest could go. That is the public web under the `assistant` template, and only the hosts you list in allowlist mode.

Seatbelt starts from `(deny default)`: a sandbox may do only what its compiled policy allows.

- **Writes are allow-only.** A sandbox writes to its own home and to the workspaces its policy names.
- **Reads are allowed, then denied.** A sandbox reads broadly, and the deny list overrides that. Protected paths, such as the state database, the audit log and other sandboxes, are denied whatever the policy says.
- **The network is allow-only.** The compiled policy denies the network, then allows the sandbox's proxy port on localhost and Unix sockets in its home. A runtime that declares a listening service, as Hermes does for its gateway, may also listen on any port outside enclos's proxy range, and its sessions reach that service's port.
- **Host services are refused.** So are Apple Events, launchd jobs, preferences, the pasteboard and signals to processes outside the sandbox.

The proxy runs on the host, one per sandbox, so a sandbox cannot change what it decides. A session's proxy variables point at it, and a program that ignores them connects nowhere. For each new connection it reads the active policy, checks the network mode, resolves the name itself, connects only to an address it has validated and logs the result. It never connects to loopback, link-local or cloud metadata addresses, and connects to a private one only for a host your policy both allows and names in its `private` opt-in. That is why `enclos policy allow` works without a restart. It sees where an HTTPS connection goes, not what it carries.

A listener is the exception to the proxy ([ADR 0028](docs/adr/0028-a-runtime-listens-and-its-sessions-reach-its-service.md)). On macOS, what a listening runtime serves can be reached from your Mac and from its network, and it answers the connections it accepts without the proxy or the network log; on Linux, the host reaches it only while `enclos dashboard` runs. `enclos status` names each listener, and `enclos policy show` and `enclos policy test` say that listening is open.

### From a policy to a session

1. **Resolve.** Four layers (built-in defaults, a template, the runtime's endpoints, the sandbox's own `policy.toml`) become an immutable policy snapshot, identified by its hash.
2. **Compile.** The backend turns the snapshot into its own file, for Seatbelt a `.sb` file.
3. **Start.** `enclos connect` starts the program under `sandbox-exec` (bubblewrap on Linux), with an emptied environment plus the sandbox's own variables. Background services are launchd agents on macOS and systemd user units on Linux; there is no enclos daemon.
4. **Record.** Sessions and the network log go to `state.db`, and each command that changes something to a hash-chained `audit.jsonl`.

`enclos policy test` then shows the result instead of assuming it: escape probes try each way out from inside the sandbox, and each counts only if its control, run outside, shows the route works there.

## Architecture

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/architecture-dark.svg">
  <img alt="Clients (the enclos CLI; a web UI and an MCP server later) go through one core library: state and audit, policy, runtime adapters and the backend API. Backends: Seatbelt on macOS and bubblewrap on Linux now; OpenShell and a microVM later. Seatbelt runs the runtime inside the sandbox, which connects out through its egress proxy to allowed domains, all run as services of launchd on macOS or systemd on Linux." src="docs/diagrams/architecture-light.svg">
</picture>

Every client calls the engine. A command that changes anything takes the state lock, opens an audit entry, does the work and closes the entry, also on failure. Each component sits behind one interface, so a new backend or runtime is one new implementation.

```text
src/
├── main.rs, cli/       # Commands, arguments and output
├── engine.rs, engine/  # Where the components meet: lock, audit, then the work
├── policy/             # Layers, snapshots and validation
├── backend/            # Compile a policy, wrap a command: seatbelt/, bubblewrap/
├── runtime/            # Runtime adapters: Hermes
├── service/            # The host's service manager: launchd or systemd
├── lifecycle/          # A session's members, and a safe stop
├── probes/             # Escape probes for enclos policy test
├── proxy/              # The egress proxy
├── relay.rs, relay/    # Linux: a session's 127.0.0.1 to its proxy's socket
├── net/                # Allowlist entries and address classes
├── secrets/            # The secret store: the Keychain, Secret Service or a file
├── state/              # state.db
├── audit/              # audit.jsonl
└── model/              # Typed records the components share
```

See [architecture](docs/architecture.md) for what runs on your Mac and a session step by step.

## Quick start

On an Apple silicon Mac running macOS 15 or later, with an account with a model provider Hermes supports:

```bash
curl -fsSL https://enclos.dev/install.sh | bash
enclos init
enclos sandbox create lab --template assistant   # the public web; minimal for only Hermes's hosts
enclos runtime install hermes --sandbox lab    # Hermes's own installer, inside the sandbox
enclos connect lab -- hermes -p default setup  # Hermes's own setup: your provider, its login, a model
enclos agent add lab/main
enclos policy test lab                         # escape probes; every one must fail
enclos sandbox start lab                       # proxy and gateway in the background
enclos connect lab -- main                     # talk to the agent, with Hermes's own command
enclos net log lab                             # what it connected to
```

The installer always takes the latest release: it checks the archive's SHA-256 checksum and the binary's version, then replaces `~/.local/bin/enclos` in one step. It never uses sudo, edits your shell startup files or creates enclos state. To build from a clone with Rust instead, run `cargo install --locked --path .`.

The [getting started guide](docs/getting-started.md) explains each step and what does not work yet; [releases](docs/releases.md) says how a release is built and checked.

## Commands

| Command | What it does |
| --- | --- |
| `enclos init` | Create `~/.enclos`, the state database and the audit log |
| `enclos status [<sandbox>]` | Every sandbox and agent, its size on disk, and what you could do, such as removing an unused sandbox |
| `enclos sandbox create \| list \| show \| start \| stop \| restart \| rm` | Manage sandboxes and their background services |
| `enclos runtime install` | Install a runtime in a sandbox |
| `enclos agent add \| list \| rm` | Manage a sandbox's agents, including ones made inside it with the runtime's own commands, or imported from an export made on your Mac (`--from`) |
| `enclos connect <sandbox> [-- <command>]` | Open a shell in a sandbox, or run a command there, such as the runtime's own to talk to an agent |
| `enclos policy show \| allow \| test` | Read or widen a sandbox's policy, and run its escape probes |
| `enclos net log \| denied` | The network log, and what was refused |
| `enclos logs <sandbox>` | The background services' logs |
| `enclos audit [verify]` | The audit log, and a check that nobody edited it |

## Documentation

- [Website](https://enclos.dev/): what enclos does, how to install it and its limits ([source](site/)).
- [Getting started](docs/getting-started.md): from install to talking to an agent.
- [Manual end-to-end test](docs/manual-e2e.md): every command, by hand, before a release.
- [Architecture](docs/architecture.md): what runs where, and the code's components.
- [Policy compilation](docs/policy-compilation.md): how a `policy.toml` becomes the Seatbelt file a session runs under, and [every setting](docs/policy-compilation.md#every-setting) it can hold.
- [Design](docs/design.md): what enclos is meant to be, the threat model, milestones and open questions.
- [Decisions](docs/adr/): one short record per architecture decision.
- [Glossary](GLOSSARY.md): the words enclos uses.
- [Security policy](SECURITY.md): how to report a vulnerability.

## Development

Rust, with the version pinned in `rust-toolchain.toml`. [just](https://github.com/casey/just) runs the same checks as CI:

```bash
just ci   # cargo fmt --check, clippy -D warnings, tests, cargo deny
```

On macOS, the Seatbelt tests run real `sandbox-exec`. Unit tests never touch your launchd: services go through a fake.

## License

[MIT](LICENSE).
