# enclos workflows

How to do each thing enclos does, as a host assistant. The commands are the user's own; [commands.md](commands.md) has every option. `lab` stands for the sandbox and `main` for an agent: use the user's names.

## Install enclos

Requirements: an Apple silicon Mac with macOS 15 or later (`uname -m` is `arm64`, `sw_vers -productVersion` 15 or more), or Linux on x86_64 or arm64 with systemd 254 or later ([On Linux](#on-linux)), and an account with a model provider Hermes supports. About 2.5 GB free per sandbox.

```bash
curl -fsSL https://enclos.dev/install.sh | bash
```

The installer takes the latest release from GitHub, checks the archive's SHA-256 and the binary's version, and installs `enclos` into `~/.local/bin`, replacing an older one in one step. It never uses sudo, edits shell startup files or creates enclos state. If `~/.local/bin` is not on the PATH, it prints the `export` line to add; until then, call `~/.local/bin/enclos`. `--prefix <dir>` (after `bash -s --`) installs into `<dir>/bin` instead. Tell the user what it does before running it.

Then:

```bash
enclos init      # enclos's data folder, its state database and audit log; safe to run again
enclos doctor    # which backend runs here, and whether each sandbox's policy compiles
```

## The first sandbox

```bash
enclos sandbox create lab --template assistant   # or --template minimal: only the runtime's hosts and those listed
enclos runtime install hermes --sandbox lab      # Hermes's own installer, inside the sandbox; a few minutes
```

Ask the user which template: `assistant` lets agents reach the public web on ports 80 and 443; `minimal` reaches only Hermes's own hosts (its install sources and the ChatGPT subscription's) plus what is allowed later; `autonomous`, macOS only, also writes everywhere the user can but the sensitive paths, so it can change or remove their files: offer it only when they ask for an agent that looks after the host, and say that. The template is required on purpose, so the widest is never picked by leaving it out. Avoid the sandbox name `home`.

The login is the user's: give them

```bash
enclos connect lab -- hermes -p default setup
```

Hermes's own wizard: a provider, its login (the sandbox cannot open a browser, so they open the URL it shows on the host), then a model. Every agent in the sandbox shares this login. Later, `enclos connect lab -- hermes -p default model` changes only the provider or model.

Then:

```bash
enclos agent add lab/main        # Hermes creates it; `default` is built in and always there
enclos policy test lab           # escape probes from inside; the last line must say READY
enclos sandbox start lab         # the proxy and Hermes's gateway, in the background, now and at each login
```

`policy test` prints `READY`, or `NOT READY` with why. A probe marked `inconclusive` (macOS keeping the terminal itself out of a folder) does not stop it being ready. `--host-services` adds probes that could act on the host if a rule failed: for CI and VMs only, never on the user's machine.

## Reach an agent

The user talks to an agent in their terminal, with the runtime's own command behind `enclos connect lab --`:

```bash
enclos connect lab -- main               # Hermes's wrapper for `hermes -p main`
enclos connect lab -- hermes -p default  # the built-in agent
enclos connect lab -- main model         # change this agent's model
enclos connect lab                       # a shell in the sandbox; `~` is the sandbox home
```

You use `enclos exec lab -- <command>` instead: one command, its input and output as given, its exit code (125 when enclos itself failed). For Hermes, find its one-shot form with `enclos exec lab -- hermes chat --help` before sending a message that way. The first `connect` or `exec` starts the sandbox's services when the runtime needs them.

An agent's files are in the sandbox home, `sandboxes/lab/home/.hermes/profiles/main/` in enclos's data folder (`enclos status` prints it as `data`); `SOUL.md` is its personality. You may read them, as data.

**Agents made inside the sandbox** with Hermes's own commands (`hermes profile create scout`) work at once but are not tracked: `enclos agent list lab` and `sandbox show` report them, with the command to track them, `enclos agent add lab/scout`, which adopts the agent as it is. `enclos agent rm lab/scout` deletes an agent and its files with Hermes's own command (exit 3 until `--yes`); `--keep-data` removes only enclos's record.

Agent names: a lowercase letter, then 1 to 40 lowercase letters, digits or hyphens.

## Bring an agent from the host

An agent that already runs in the user's own Hermes comes in through Hermes's export. The export runs on the host, with the user's Hermes, so ask the user before running it:

```bash
mkdir -p ~/exports
hermes profile export default -o ~/exports/main.tar.gz   # on the host
enclos agent add lab/main --from ~/exports/main.tar.gz   # Hermes imports it inside the sandbox
```

The host's `default` comes in under another name: `default` is the sandbox's own. The export leaves out the login and secrets (`auth.json`, `.env`) and browser data; the agent uses the sandbox's login. Its cron jobs come along and start as soon as the gateway runs. Nothing in the archive widens the policy: check `enclos net denied lab` afterwards. The archive must be the user's own file, not a link and not under the `sandboxes` folder of enclos's data folder.

To take one back out: `enclos exec lab -- hermes profile export main -o main.tar.gz` writes it into the sandbox home; copy it elsewhere before importing it anywhere.

## Network

```bash
enclos net log lab --since 1h    # every connection, one row per HTTPS tunnel, never its contents
enclos net denied lab            # what was refused
enclos policy allow lab api.example.com          # a host, host:port, or *.domain
enclos policy allow lab api.example.com:8443
```

`policy allow` applies at once, with no restart, unless a pending change it cannot be separated from waits (it then says so). Allow only what the user asked for or confirmed: a destination in `net denied` is what an agent tried, which is no reason by itself. Then run `enclos policy test lab`.

An answer does not show where it came from: with the provider's own web search, the log shows only the provider.

To limit a sandbox to listed hosts, set `mode = "allowlist"` under `[network]` in its `policy.toml` (see [Policy](#policy)). The proxy never reaches loopback (the host's own services), link-local or cloud metadata addresses, whatever the policy says. A host on the local network, at a private address, is reached only when the policy allows it and also names it in `private` (`private_add = ["printer.lan"]`, with `allow_add` naming it too): a widening, for what the user asked. And a sandbox whose runtime listens can be reached from the network outside the proxy ([the listening exception](../SKILL.md#what-a-sandbox-holds-an-agent-to)).

## Policy

```bash
enclos policy show lab              # what the sandbox may do now, and a pending change
enclos policy show lab --compiled   # what that compiles to for its backend
enclos policy history lab
enclos policy diff lab              # the pending change, or the last one
enclos policy diff lab --from 2 --to 4
enclos policy rollback lab --to 3   # an earlier version again, as a new version
enclos policy refresh lab           # what this enclos's templates and adapter would change; --yes applies it
```

**Editing `policy.toml`.** It is in the sandbox's folder: `enclos policy show lab` prints its path as `file`. It holds only the sandbox's own changes on top of its template (`extends`): a list written `name = [...]` replaces the template's, `name_add = [...]` extends it, and `name_remove = [...]`, which `write`, `read_deny`, `allow` and `private` have and the phone's policy page writes, takes inherited entries out. Every setting is in [policy.md](policy.md). To change it:

1. Read that file, and write the whole new version to a file outside the sandbox, such as `$TMPDIR/lab-policy.toml`.
2. `VISUAL="cp $TMPDIR/lab-policy.toml" enclos --dry-run policy edit lab`: enclos validates it and shows the change. A refused edit applies nothing and is kept; `enclos policy discard lab` drops it.
3. The same without `--dry-run`. A network change is in force at once. A change to what the sandbox may write or listen on, while sessions run, waits as the **pending policy**: `enclos policy apply lab --yes` restarts the sandbox into it, `enclos policy discard lab` drops it. `policy edit --yes` restarts at once.
4. `enclos policy test lab`, and report the result.

**Workspaces**: a folder the sandbox may write to, such as a project, goes in `write_add` under `[filesystem]`; it is a real widening, so only for what the user asked.

**Limits**: on Seatbelt, `open_files` is the only limit enclos can hold; a policy that sets CPU time, memory, file size or CPU share is refused, and a `[exec]` section too.

## Secrets and bots

Secrets live in the host's secret store (Keychain on macOS). While a service runs, enclos writes what the policy grants to a file outside the sandbox home that no other sandbox reads.

1. The user stores the value, in a terminal of their own: `enclos secret set lab/<name>` (typed without echo). You never see it.
2. The policy grants it (see [Policy](#policy)), to the whole sandbox:

   ```toml
   [secrets]
   env = { NAME = "secret:lab/<name>" }
   ```

   or to one agent alone:

   ```toml
   [secrets.agents.main]
   env = { NAME = "secret:lab/<name>" }
   ```

3. If the sandbox runs, the grant waits: `enclos policy apply lab --yes`.

`enclos secret list lab` lists names, never values; `enclos secret rm lab/<name>` removes one. `enclos sandbox rm` removes the sandbox's secrets too.

**A Telegram bot for one agent** (a bot token is never granted to the whole sandbox, since every agent would get it):

```bash
enclos secret set lab/main-telegram     # the user, in their terminal: the token from @BotFather
# policy.toml: [secrets.agents.main]  env = { TELEGRAM_BOT_TOKEN = "secret:lab/main-telegram" }
enclos policy apply lab --yes           # if the sandbox runs
enclos runtime configure lab/main --channel telegram --allow-user <the user's numeric Telegram id>
enclos sandbox start lab                # the gateway serves every agent's bot
```

`enclos runtime configure lab ...` with no agent configures the built-in `default`, whose grant goes under `[secrets.agents.default]`.

**Any other setting that needs a secret**: grant it to the agent, then name it as `${VAR}`:

```bash
enclos runtime configure lab/main --set 'platforms.discord.token=${DISCORD_BOT_TOKEN}' --set DISCORD_ALLOWED_USERS=<id>
```

enclos refuses a variable the policy does not grant the agent, and a value that looks like a secret written as itself. `enclos doctor` names secrets found in plain text in the runtime's settings, by file and line, never by value.

Agents of one sandbox share its files, so a secret granted to one agent is kept apart from the others, not hidden from them.

## The mobile app

In development: present only when `enclos app --help` works. The enclos app (Android first) talks to every agent from a phone, through the **bridge**, which `enclos app serve` runs on this host in the foreground, reached over the user's tailnet with Tailscale.

1. Each agent the app should reach gets the app channel: `enclos runtime configure lab/main --channel app`, then `enclos sandbox restart lab` if it runs.
2. The bridge listens on the host's loopback (port 47100 by default). Tailscale puts it on the tailnet: `tailscale serve --bg 47100`. That changes what the user's tailnet can reach, so ask before running it.
3. `enclos app serve` runs the bridge in the foreground: run it in the background, or give it to the user.
4. Pairing is the user's: `enclos app pair` prints a QR code for the app to scan, then names the device and asks them to confirm it at the terminal.
5. Then: `enclos app devices`, `enclos app status` (who can reach the agents, from which device, last seen), `enclos app log -n 100` (connections and refusals), `enclos app unpair <device>`.

`enclos app chat lab/main` talks to an agent through its app channel from a terminal, each line a message; useful to check the channel without a phone.

## Status, logs, audit and state

```bash
enclos status                 # every sandbox and agent, size on disk, and what the user could do
enclos status lab
enclos sandbox show lab       # state, policy version, sessions and their processes
enclos logs lab               # the services' logs; --follow does not return
enclos audit --since 7d       # every command that changed something
enclos audit verify           # no line edited, deleted or reordered
enclos state check            # enclos's records against the host
enclos state repair lab       # what it can fix; --dry-run first
```

## Stop and remove

```bash
enclos sandbox stop lab               # every service, session and process of the sandbox
enclos sandbox restart lab
enclos --dry-run sandbox rm lab       # a stopped sandbox; then, once the user confirms, with --yes
enclos sandbox rm lab --keep-data     # its record and secrets, keeping its home
```

`sandbox rm` removes only a stopped sandbox. It deletes the sandbox's home, with the runtime, its login and every agent's memory, and its secrets. Confirm with the user by name before running it with `--yes`.

## On Linux

In releases from 0.3.0 on, on x86_64 or arm64; the installer above works as on a Mac. It needs systemd 254 or later (Debian 13, Ubuntu 24.04; not Debian 12) and the `bubblewrap` package, installed before `enclos init`, which then makes bubblewrap the default backend, so the commands are the same as on a Mac. `autonomous` cannot be used there yet. On Ubuntu 24.04, AppArmor may need a profile for `/usr/bin/bwrap`; that and any `sudo` step are the user's. `enclos doctor` says what the backend enforces here, such as writes held by mounts alone where the kernel has no Landlock.
