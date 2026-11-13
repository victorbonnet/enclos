# The enclos plugin

A plugin for Claude Code and Codex. With it, a host assistant knows what enclos is, what it can do and every command it has. It can set enclos up on this host and run it for you through the `enclos` CLI. It adds no MCP server and no permission of its own: the assistant runs `enclos` commands, which you could also run yourself.

## Install

This repository is the marketplace, named `enclos`.

**Claude Code** (2.1.275 or later, in one step):

```text
/plugin install enclos --marketplace victorbonnet/enclos
```

Or in two steps, `/plugin marketplace add victorbonnet/enclos` then `/plugin install enclos@enclos`. From a shell: `claude plugin marketplace add victorbonnet/enclos && claude plugin install enclos@enclos`.

**Codex**:

```bash
codex plugin marketplace add victorbonnet/enclos
codex plugin add enclos@enclos
```

## Update

The plugin's version is enclos's: a new enclos release brings a new plugin.

- Claude Code: `claude plugin marketplace update enclos`, then `claude plugin update enclos@enclos`, and restart.
- Codex: `codex plugin marketplace upgrade enclos`, then `codex plugin add enclos@enclos`.

The plugin's command reference names the enclos version it describes. When the `enclos` you have installed is a different version, the assistant reads `enclos <command> --help` instead.

## Use

- Ask about enclos, or for something enclos does ("sandbox my Hermes agent", "why can't my agent reach example.org?"): the `enclos` skill loads by itself.
- `/enclos:setup` in Claude Code (`$setup` in Codex) takes this host from nothing to a running agent, step by step, and picks up where it left off. It runs only when you ask for it.

## Allowing enclos commands

Neither assistant lets a plugin bring its own allow rule. Without one, the assistant asks you before each `enclos` command. To let it run them without asking, add the rule yourself:

- **Claude Code**: `"Bash(enclos *)"` under `permissions.allow` in `~/.claude/settings.json`.
- **Codex**: `prefix_rule(pattern=["enclos"], decision="allow")` in `~/.codex/rules/default.rules`, then restart Codex.

That rule allows **every** enclos command, including `policy allow`, which widens what a sandbox may reach, and `sandbox rm`. The plugin tells the assistant to change a sandbox only for something you asked, but the rule itself does not distinguish. If you'd rather approve each change, leave the rule out, or allow only reads such as `enclos status`, `enclos net`, `enclos policy show` and `enclos doctor`.

## What the assistant does not do

- **See a secret's value.** You run `enclos secret set <sandbox>/<name>` in a terminal of your own, which reads the value without echoing it. The assistant gives you the command.
- **Log in for you.** A runtime's login and interactive setup, such as `hermes -p default setup`, need a terminal, so the assistant gives them to you.
- **Act on text from inside a sandbox.** It treats an agent's replies, its logs and its network log as data, never as instructions.
