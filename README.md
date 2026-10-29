# enclos

*enclos* (French for an enclosure, said "ahn-KLOH") creates sandboxes on your machine, installs agent runtimes in them and runs agents there, with a policy and an audit log. It manages only the sandboxes it creates.

> **Status: early development.** Milestone 1 runs [Hermes](https://hermes-agent.nousresearch.com) agents in Seatbelt sandboxes on a Mac. Nothing is released yet, and state is not kept across development builds.

## Why

Agents such as Hermes install tools, run code and reach the network on their own. enclos gives each runtime a sandbox of its own, so a misled agent cannot read your SSH keys, delete your files or talk to hosts you did not allow:

- **Files:** it writes only to its own home. It reads broadly, except a deny list of sensitive paths such as `~/.ssh`, cloud credentials and other tools' logins, keychains, password managers, browser data, mail and Apple apps' data, shell history, the configuration of your own assistant tools on the host (`~/.hermes`, `~/.claude`, `~/.codex` and others), other sandboxes and enclos's own files. Agents in the same sandbox share its home and can read each other's files. Agents in the same sandbox share its home and can read each other's files.
- **Network:** its only way out is its own proxy, which logs every connection it decides on (as long as enclos can write its state) and never connects to your Mac's own services, your local network or cloud metadata addresses. An agent may reach the public web (ports 80 and 443) by default, or only the domains you list if you set its policy to allowlist mode. You review what was refused and allow what you trust, without a restart.
- **The rest of your Mac:** opening apps, Apple Events, launchd jobs, preferences, the pasteboard and signals to other processes are blocked. One thing macOS lets every process of yours do, sandboxed or not: read the environment variables your other programs started with (Apple's own programs aside). Don't keep secrets in exported shell variables while sandboxes run; enclos hands a sandbox's service its secrets through a file only that sandbox reads.
- **A record:** every command that changes something is written to a hash-chained audit log.

enclos protects against accidental damage by agents you mostly trust ([threat model](docs/adr/0014-threat-model-accidental-damage.md)). It is not a defense against malicious code exploiting the kernel.

## The words

| Word | Meaning |
| --- | --- |
| **Sandbox** | A named, isolated environment with its own home folder, policy and proxy. The permission boundary. |
| **Runtime** | The software installed in a sandbox to run its agents, such as Hermes. One per sandbox. |
| **Agent** | A named identity of the runtime, with its own configuration, memory, skills, sessions and channels. Agents in a sandbox share its runtime, policy, proxy and secrets. |
| **Policy** | What a sandbox may do with files, network and host services, stored as immutable snapshots. |

More in the [glossary](GLOSSARY.md).

## Architecture

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/diagrams/architecture-dark.svg">
  <img alt="Clients (the enclos CLI; a web UI and an MCP server later) go through one core library: state and audit, policy, runtime adapters and the backend API. Backends: Seatbelt on macOS now; bubblewrap, OpenShell and a microVM later. Seatbelt runs the runtime inside the sandbox, whose only way out is its egress proxy to allowed domains, all run as launchd services." src="docs/diagrams/architecture-light.svg">
</picture>

Each sandbox runs under macOS Seatbelt with a policy compiled from layers (defaults, a template, the runtime's endpoints, your overrides). Its only network route is an egress proxy on the host. Background services are plain launchd jobs; there is no enclos daemon. See [architecture](docs/architecture.md) for the components and a session step by step.

## Quick start

On an Apple silicon Mac running macOS 15 or later, with an account with a model provider Hermes supports:

```bash
curl -fsSL https://enclos.dev/install.sh | bash
enclos init
enclos sandbox create lab
enclos runtime install hermes --sandbox lab    # Hermes's own installer, inside the sandbox
enclos connect lab -- hermes -p default setup  # Hermes's own setup: your provider, its login, a model
enclos agent add lab/main
enclos policy test lab                         # escape probes; every one must fail
enclos sandbox start lab                       # proxy and gateway in the background
enclos connect lab -- main                     # talk to the agent, with Hermes's own command
enclos net log lab                             # what it connected to
```

The installer always takes the latest release: it checks the archive's SHA-256 checksum and the binary's version, then replaces `~/.local/bin/enclos` in one step. It never uses sudo, edits your shell startup files or creates enclos state. **No release is published yet:** until the first one, build from a clone with Rust instead, `cargo install --locked --path .`.

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

- [Website](https://enclos.dev/): a visual introduction, everyday examples and common questions ([source](site/)).
- [Getting started](docs/getting-started.md): from install to talking to an agent.
- [Architecture](docs/architecture.md): what runs where, and the code's components.
- [Policy compilation](docs/policy-compilation.md): how a `policy.toml` becomes the Seatbelt file a session runs under.
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
