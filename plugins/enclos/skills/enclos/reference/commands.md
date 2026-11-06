# enclos commands

Every command of enclos 0.2.0, rendered from its own definitions; `enclos <command> --help` says the same. When `enclos --version` prints another version, read `--help` instead of this file.

Create sandboxes, install agent runtimes in them and run agents there, with policy and an audit log

## Global options

Every command takes these.

- `--yes`: Make changes without asking for confirmation.
- `--json`: Print JSON, the result or the error, also in a terminal; the default when stdout is piped, except for `connect`, `exec` and `logs`. With it, `connect` and `exec` keep their command's output on stdout and give enclos's own messages as JSON lines on stderr (a dry run's plan is JSON on stdout); `logs` prints JSON Lines.
- `--text`: Print readable text, also when the output is piped; --json wins.
- `--dry-run`: Show what would change, and change nothing.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Done; or, for a check, nothing found. |
| 1 | An error, or a check that found something, such as `doctor`, `state check` or a `policy test` with a failed probe. |
| 2 | Refused: a policy whose problems are all refusals, or a backend this host cannot run. Nothing changed. |
| 3 | Needs confirmation: run it again with `--yes` to make the change, or with `--dry-run` to see the plan first. enclos never prompts for it. |
| 125 | `enclos exec` failed before, around or after its command; otherwise `exec` exits with its command's own code. |

## Commands

### `enclos init`

Create the enclos folders, state database and audit log. Safe to run again

```text
enclos init [OPTIONS]
```

### `enclos doctor`

Say whether this host runs each backend, whether each sandbox's active policy compiles as its next session would compile it, and which compiled policies enclos now writes differently. Exits 1 when no backend runs, enclos's records cannot be read, or for a sandbox its backend does not run, its next session cannot compile its policy, or doctor could not look at all of it

```text
enclos doctor [OPTIONS]
```

### `enclos audit`

List audit entries, or verify the audit log

```text
enclos audit [OPTIONS]
enclos audit <COMMAND>
```

- `--since <DURATION>`: Only entries from this far back, such as 30m, 12h, 7d or 2w.

#### `enclos audit verify`

Check that no line of the audit log was edited, deleted or reordered

```text
enclos audit verify [OPTIONS]
```

### `enclos sandbox`

Create, list, show, start, stop, restart or remove sandboxes

#### `enclos sandbox create`

Create a sandbox with its own home, policy and proxy port

```text
enclos sandbox create [OPTIONS] --template <TEMPLATE> <NAME>
```

- `<NAME>`
- `--backend <BACKEND>`: The isolation technology. Default: `seatbelt`.
- `--template <TEMPLATE>`: The policy it starts from, required so the widest is never picked by leaving it out: minimal (only what is listed; from `runtime install` on, the runtime's hosts) or assistant (the public web) (design §7)

#### `enclos sandbox list`

List sandboxes

```text
enclos sandbox list [OPTIONS]
```

#### `enclos sandbox show`

Show a sandbox: its state, policy version, sessions and their processes

```text
enclos sandbox show [OPTIONS] <NAME>
```

- `<NAME>`

#### `enclos sandbox start`

Run each sandbox's proxy and its runtime's services in the background, now and at each login

```text
enclos sandbox start [OPTIONS] <NAMES>...
```

- `<NAMES>...`
- `--accept-unenforced <FIELD>`: Run with this field not applied where this host does not enforce it, such as `memory` without the memory controller; recorded in the audit log, and kept until the field's value changes.

#### `enclos sandbox stop`

Stop every service, session and process of each sandbox

```text
enclos sandbox stop [OPTIONS] <NAMES>...
```

- `<NAMES>...`

#### `enclos sandbox restart`

Stop each sandbox, then start its services again under the active policy

```text
enclos sandbox restart [OPTIONS] <NAMES>...
```

- `<NAMES>...`

#### `enclos sandbox rm`

Remove a stopped sandbox and its secrets, and its home unless --keep-data

```text
enclos sandbox rm [OPTIONS] <NAME>
```

- `<NAME>`
- `--keep-data`: Keep the sandbox's folder and home on disk; its secrets go still.

### `enclos connect`

Open a shell, or run a command, inside a sandbox

```text
enclos connect [OPTIONS] <SANDBOX> [-- <COMMAND>...]
```

- `<SANDBOX>`
- `[COMMAND]...`: A command to run instead of a shell, after `--`, such as the runtime's own: `enclos connect lab -- hermes -p scout`.

### `enclos exec`

Run one command inside a sandbox, for a script or another program; exits with its code

```text
enclos exec [OPTIONS] <SANDBOX> -- <COMMAND>...
```

- `<SANDBOX>`
- `<COMMAND>...`: The command to run, after `--`: `enclos exec lab -- hermes -p scout chat -q "hello"`.

### `enclos secret`

Set, list or remove a sandbox's secrets, kept in the secret store

#### `enclos secret set`

Store a secret of a sandbox in the secret store, reading its value from the input: one line typed without echo at a terminal, or all of what is piped in, its final line ending left out

```text
enclos secret set [OPTIONS] <SECRET>
```

- `<SECRET>`: `<sandbox>/<name>`, such as `home/telegram`.

#### `enclos secret list`

List a sandbox's secrets and what its policy gives each as; never their values

```text
enclos secret list [OPTIONS] <SANDBOX>
```

- `<SANDBOX>`

#### `enclos secret rm`

Remove a secret of a sandbox from the secret store

```text
enclos secret rm [OPTIONS] <SECRET>
```

- `<SECRET>`

### `enclos state`

Check enclos's records against the host, or repair what it can

#### `enclos state check`

Say where enclos's records and the host differ; change nothing. Exits 1 when they differ. A sandbox it cannot look at is named among them; a failure that stops the whole check exits 1 with an error on stderr

```text
enclos state check [OPTIONS] [SANDBOX]
```

- `[SANDBOX]`: One sandbox; every sandbox, and folders with no record, when left out.

#### `enclos state repair`

Fix what `state check` finds that enclos can fix, and name the rest; with --dry-run, say what it would do. Exits 1 when something is left for you

```text
enclos state repair [OPTIONS] [SANDBOX]
```

- `[SANDBOX]`: One sandbox; every sandbox, and folders with no record, when left out.

### `enclos runtime`

Install a runtime in a sandbox, or configure an agent: its own secrets, its settings, a bot

#### `enclos runtime install`

Install a runtime in a sandbox with its own installer, run inside the sandbox

```text
enclos runtime install [OPTIONS] --sandbox <SANDBOX> <RUNTIME>
```

- `<RUNTIME>`
- `--sandbox <SANDBOX>`

#### `enclos runtime configure`

Set an agent up with the runtime's own commands: it reads the secrets the policy grants it under [secrets.agents.<agent>], then each --set, then, with --channel, a bot (ADR 0036)

```text
enclos runtime configure [OPTIONS] <TARGET>
```

- `<TARGET>`: The agent: a sandbox, such as `home`, for its built-in agent, or one of its agents, such as `home/main`.
- `--set <KEY=VALUE>`: A setting of the agent, as the runtime names it, such as `platforms.discord.token=${DISCORD_BOT_TOKEN}`: a secret only as `${VAR}`, which the policy grants the agent or the sandbox; repeat it for each setting.
- `--channel <CHANNEL>`: A bot on this messaging channel, its token a secret the policy grants the agent; or `app`, the enclos mobile app's channel, which enclos's bridge connects to.
- `--token-env <VAR>`: With --channel: the variable the policy grants the bot's token as; the channel's usual one (TELEGRAM_BOT_TOKEN) when left out. Hermes keeps only the usual one from the agents' commands.
- `--allow-user <ID>`: With --channel: someone the bot answers, a Telegram user's numeric id; repeat it for each person.

### `enclos agent`

Add, list or remove the runtime's agents

#### `enclos agent add`

Add an agent, such as `lab/main`: the runtime creates it in the sandbox, imports it with --from, or enclos tracks one the runtime already has there

```text
enclos agent add [OPTIONS] <AGENT>
```

- `<AGENT>`
- `--from <ARCHIVE>`: An export the runtime's own command made on the host (for Hermes, `hermes profile export`); the runtime imports it inside the sandbox.

#### `enclos agent list`

List a sandbox's agents, and report the ones made inside it that enclos does not track

```text
enclos agent list [OPTIONS] <SANDBOX>
```

- `<SANDBOX>`

#### `enclos agent rm`

Remove an agent and its files, with the runtime's own command; `--keep-data` keeps the files

```text
enclos agent rm [OPTIONS] <AGENT>
```

- `<AGENT>`
- `--keep-data`: Keep the agent's files in the sandbox home; remove only the record.

### `enclos app`

The enclos mobile app's side of this host: serve the bridge, pair, list devices, unpair, status, log, or chat with an agent through its app channel

#### `enclos app chat`

Talk to an agent through its app channel, from this terminal: each line typed is a message, and what the agent says is printed, including what it sends on its own, such as a cron job's output

```text
enclos app chat [OPTIONS] <TARGET>
```

- `<TARGET>`: The agent: `home` for the sandbox's built-in agent, or `home/main`.
- `--conversation <CONVERSATION>`: The conversation to go on with; a new one when left out.

#### `enclos app serve`

Run the bridge in this terminal: it serves paired devices on the host's loopback, for its transport to put on your network

```text
enclos app serve [OPTIONS]
```

- `--port <PORT>`: The loopback port to listen on. Default: `47100`.
- `--transport <TRANSPORT>`: How devices reach the bridge, and who it says each caller is; `tailscale`, through `tailscale serve`, is the only one for now. Default: `tailscale`.

#### `enclos app pair`

Pair a device: prints a QR code for the enclos app to scan, then asks you to confirm the device that used it

```text
enclos app pair [OPTIONS]
```

- `--url <URL>`: The bridge's address on your network; asked of the transport (`tailscale status`) when left out.
- `--transport <TRANSPORT>`: How devices reach the bridge: as `app serve --transport`. Default: `tailscale`.

#### `enclos app devices`

List the paired devices

```text
enclos app devices [OPTIONS]
```

#### `enclos app unpair`

Remove a paired device: it can no longer connect

```text
enclos app unpair [OPTIONS] <DEVICE>
```

- `<DEVICE>`

#### `enclos app status`

Who can reach the agents, from which devices, and when each was last seen

```text
enclos app status [OPTIONS]
```

#### `enclos app log`

The bridge's log: connections, disconnections and refusals

```text
enclos app log [OPTIONS]
```

- `-n <LINES>`: How many lines, the newest last. Default: `50`.

### `enclos policy`

Show, widen, edit, apply, discard, refresh, diff, roll back or test a sandbox's policy, or list its history

#### `enclos policy show`

Show the sandbox's active policy, and the change pending if there is one

```text
enclos policy show [OPTIONS] <SANDBOX>
```

- `<SANDBOX>`
- `--pending`: Show the pending policy in full instead.
- `--compiled`: Show what the active policy compiles to for the sandbox's backend.

#### `enclos policy allow`

Let the sandbox reach a destination: host, host:port or *.domain. Applies at once, or waits with a pending change it cannot be separated from

```text
enclos policy allow [OPTIONS] <SANDBOX> <DESTINATION>
```

- `<SANDBOX>`
- `<DESTINATION>`

#### `enclos policy edit`

Edit the sandbox's policy.toml in $VISUAL or $EDITOR, then apply it: at once, or pending while sessions run under rules it changes

```text
enclos policy edit [OPTIONS] <SANDBOX>
```

- `<SANDBOX>`
- `--accept-unenforced <FIELD>`: Run with this field not applied where this host does not enforce it, such as `memory` without the memory controller; recorded in the audit log, and kept until the field's value changes.

#### `enclos policy apply`

Restart the sandbox into its pending policy

```text
enclos policy apply [OPTIONS] <SANDBOX>
```

- `<SANDBOX>`

#### `enclos policy discard`

Drop the pending policy, and any edit of policy.toml not applied

```text
enclos policy discard [OPTIONS] <SANDBOX>
```

- `<SANDBOX>`

#### `enclos policy history`

List every version of the sandbox's policy

```text
enclos policy history [OPTIONS] <SANDBOX>
```

- `<SANDBOX>`

#### `enclos policy diff`

Show what one policy version changes from another: by default the pending policy from the active one, or the active one from the one before

```text
enclos policy diff [OPTIONS] <SANDBOX>
```

- `<SANDBOX>`
- `--from <VERSION>`: The version compared from: by default the active one when the pending policy is compared, else the version before the one compared.
- `--to <VERSION>`: The version compared: by default the pending policy, when there is one and --from is not given or is the active version; else the active version.

#### `enclos policy rollback`

Make an earlier version's policy the sandbox's again, as a new version

```text
enclos policy rollback [OPTIONS] --to <VERSION> <SANDBOX>
```

- `<SANDBOX>`
- `--to <VERSION>`
- `--accept-unenforced <FIELD>`: Run with this field not applied where this host does not enforce it, such as `memory` without the memory controller; recorded in the audit log, and kept until the field's value changes.

#### `enclos policy refresh`

Resolve the active policy's policy.toml again against this enclos's templates, built-in defaults and the runtime's adapter; with --yes, apply what that changes, in place of a pending change

```text
enclos policy refresh [OPTIONS] <SANDBOX>
```

- `<SANDBOX>`
- `--accept-unenforced <FIELD>`: Run with this field not applied where this host does not enforce it, such as `memory` without the memory controller; recorded in the audit log, and kept until the field's value changes.

#### `enclos policy test`

Try each way out of the sandbox from inside it; every probe must fail

```text
enclos policy test [OPTIONS] <SANDBOX>
```

- `<SANDBOX>`
- `--host-services`: Also probe the backend's host-service routes (`policy test` lists them), which could act on this host if a rule did not hold. For CI and VMs.

### `enclos net`

A sandbox's network log and refused destinations

#### `enclos net log`

Every connection the sandbox made: one row per HTTPS tunnel, never its contents

```text
enclos net log [OPTIONS] <SANDBOX>
```

- `<SANDBOX>`
- `--since <DURATION>`: Only connections from this far back, such as 30m, 12h or 7d.

#### `enclos net denied`

The destinations the sandbox was refused, to allow what you trust

```text
enclos net denied [OPTIONS] <SANDBOX>
```

- `<SANDBOX>`

### `enclos logs`

Show the logs of a sandbox's background services

```text
enclos logs [OPTIONS] <SANDBOX>
```

- `<SANDBOX>`
- `--follow`: Keep printing as the services write.

### `enclos dashboard`

Open the runtime's dashboard of a sandbox the host cannot reach, as on Linux, to you alone, until Ctrl-C

```text
enclos dashboard [OPTIONS] <SANDBOX>
```

- `<SANDBOX>`

### `enclos status`

What is on this host, what it costs on disk, and what you could do.

In JSON, sizes are in bytes, times in RFC 3339, and each fact read from a sandbox is `{"known": …}`, `"absent"`, `{"cannot_tell": why}` or `"not_provided"`.

```text
enclos status [OPTIONS] [SANDBOX]
```

- `[SANDBOX]`: Only this sandbox.
