# Getting started on a Mac

This guide runs Hermes agents in a sandbox on your Mac, with milestone 1 of enclos. It creates a sandbox called `lab` with two agents, `main` and `scout`. Pick any name you like for the sandbox; avoid `home`, which makes paths such as `sandboxes/home/home` hard to read.

The words used here:

- **Sandbox:** an isolated environment with its own home folder, policy and network proxy.
- **Runtime:** the software installed in a sandbox, here Hermes. One per sandbox.
- **Agent:** a named identity of that runtime, with its own configuration, memory, skills, sessions and channels. Agents in one sandbox share its runtime, policy, proxy and login.

## Before you start

- An Apple silicon Mac running macOS 15 or later.
- An account with a model provider Hermes supports, for its login.
- About 2.5 GB of free disk space per sandbox: each sandbox gets its own Hermes install.

## Install enclos

```bash
curl -fsSL https://enclos.dev/install.sh | bash
```

The installer always takes the latest release from [GitHub Releases](https://github.com/victorbonnet/enclos/releases): it checks the archive's SHA-256 checksum and the binary's version, then installs `enclos` into `~/.local/bin`, replacing an older one in one step. If that folder is not on your PATH, run the `export` line it prints. It never uses sudo, edits your shell startup files or creates sandboxes. To install elsewhere, pass a prefix: `curl -fsSL https://enclos.dev/install.sh | bash -s -- --prefix "$HOME/tools"`, which installs into `~/tools/bin`. To check where a release was built, run `gh attestation verify` on its archive ([releases](releases.md)).

**No release is published yet.** Until the first one, the installer says so and installs nothing. Build from a clone instead, with Rust installed through [rustup](https://rustup.rs) (it picks the version pinned in `rust-toolchain.toml`):

```bash
cargo install --locked --path .
```

## Create a sandbox and install Hermes

```bash
enclos init                                    # the ~/.enclos folder, state database and audit log
enclos sandbox create lab --template assistant # Seatbelt backend, the public web
enclos runtime install hermes --sandbox lab    # Hermes's own installer, run inside the sandbox; takes a few minutes
enclos connect lab -- hermes -p default setup  # Hermes's own setup: your provider and its login, then a model
```

`enclos runtime install` downloads Hermes's installer on your Mac, as Hermes serves it, and records its SHA-256 in the audit log. The install runs inside the sandbox, through its proxy, so it can write only to the sandbox's home.

`enclos connect lab -- hermes -p default setup` runs Hermes's own setup wizard inside the sandbox, in your terminal, for its root profile, whose login every agent shares (`-p default` names it, since a bare `hermes` uses whichever profile `hermes profile use` last picked): pick your provider, log in the way Hermes asks, then pick a model. enclos has no login command of its own: whatever a runtime's documentation says to run, put `enclos connect lab --` in front of it. The sandbox cannot open a browser, so when the login shows a URL, open it in your browser on the Mac. Every agent in the sandbox shares this login. To change only the provider or the model later, run `enclos connect lab -- hermes -p default model`.

The sandbox reaches the public web through its proxy, on ports 80 and 443, so any provider's login and API work, and every connection is logged as long as enclos can write its state. It never reaches your Mac's own services, your local network or cloud metadata addresses. To limit `lab` to the hosts you list, run `enclos policy edit lab`, which opens a copy of its `policy.toml` in your editor (`$VISUAL`, else `$EDITOR`, else `vi`), and set `mode = "allowlist"` under `[network]`; the edit applies when the editor closes. A sandbox can also start that way, with `enclos sandbox create lab --template minimal` (`mcp-only` is the same for now, for agents that reach listed remote MCP servers): from `enclos runtime install` on, it reaches the hosts the Hermes adapter lists (those its install, login and model calls used in the prototype), `chatgpt.com` and `auth.openai.com` among them for a ChatGPT subscription; another provider is reached only once you allow its hosts with `enclos policy allow`. A change to what the sandbox may write or listen on, made while sessions run in it, waits as its pending policy until `enclos policy apply lab` restarts the sandbox (or run `policy edit` with `--yes` to restart at once); `enclos policy discard lab` drops it. `enclos policy history lab` lists every version of the policy, `enclos policy diff lab` shows what the latest change does, and `enclos policy rollback lab --to <version>` brings an earlier one back. The hosts Hermes needs to install, log in and run stay allowed, and `enclos policy show lab` lists them.

## Add agents

Hermes already has one agent once it is installed: its built-in `default`, the root of its home, which `hermes` uses when you name no agent, unless `hermes profile use` picked another. `enclos agent add` adds more:

```bash
enclos agent add lab/main
enclos agent add lab/scout
enclos agent list lab        # lab/default  built in, then lab/main and lab/scout
```

enclos lists `default` but neither adds nor removes it: it exists as long as Hermes is installed in the sandbox.

## Reach an agent

You reach the sandbox with `enclos connect lab`: a shell, or the command you put after `--`. To talk to an agent or change it, run Hermes's own commands that way:

```bash
enclos connect lab -- hermes -p default  # talk to the built-in agent default
enclos connect lab -- main               # talk to the agent main (Hermes's wrapper for `hermes -p main`)
enclos connect lab -- scout model        # change the model of the agent scout
enclos connect lab -- hermes -p scout    # the same agent, without the wrapper
enclos connect lab                       # a shell in the sandbox, for anything else
```

enclos does not need to know how a runtime picks an agent: whatever its documentation shows, put `enclos connect lab --` in front of it. From a script, or anything else that is not you at a terminal, use `enclos exec lab -- <command>`: it runs one command as a session of its own, with the input and output it is given, and exits with the command's code, or with 125 when enclos itself fails. Like `connect`, it first starts the sandbox's services when the runtime needs them; enclos's own messages go to stderr.

The first `connect` or `exec` starts the sandbox's services, the Hermes gateway among them, since Hermes's own clients need it: it serves scheduled jobs and messaging for every agent. They come back at each login until `enclos sandbox stop lab`.

Hermes prints its own next steps after creating an agent, such as `main setup` and `main chat`. Run them the same way. In that shell, `~` is the sandbox's home (`~/.enclos/sandboxes/lab/home` on your Mac), so `~/.hermes/profiles/main/SOUL.md` is the agent's personality file. `main setup` is optional: every agent already uses the sandbox's login.

### Agents made inside the sandbox

You can also create an agent with Hermes's own commands, from a shell in the sandbox (`enclos connect lab`, then `hermes profile create scout`). It works right away (`enclos connect lab -- scout`), but enclos has no record of it yet, so `enclos agent list lab` would not show it. enclos tells you when it sees one, at the end of the `connect` session (on stderr, prefixed with `enclos:`), in `enclos agent list lab` and in `enclos sandbox show lab`:

```text
lab/scout: Hermes has this agent; enclos does not track it. Track it with `enclos agent add lab/scout`.
```

`enclos agent add lab/scout` then adopts it as it is, without creating it again. If you delete an agent inside the sandbox, enclos reports it the same way and `enclos agent rm` removes its record.

`enclos agent rm lab/scout` deletes an agent with its files, using Hermes's own command, after asking you to confirm (`--yes`); `--keep-data` removes only enclos's record and leaves the files, so Hermes still has the agent and enclos reports it as one it does not track. Agent names in enclos are a lowercase letter, then 1 to 40 lowercase letters, digits or hyphens; `agent list` and `sandbox show` also report a Hermes agent named otherwise (`my_bot`), which enclos cannot track. If enclos cannot read Hermes's list, because something in the sandbox replaced `~/.hermes` with a link for example, these commands say so instead of showing nothing, and `agent add` refuses until you have looked.

### Bring an agent from your Mac

To test an agent that already runs on your Mac, export it there with Hermes's own command, then add it to the sandbox from the archive:

```bash
mkdir -p ~/exports                                        # Hermes needs the folder to exist
hermes profile export default -o ~/exports/main.tar.gz   # on your Mac, with your own Hermes
enclos agent add lab/main --from ~/exports/main.tar.gz   # Hermes imports it inside the sandbox
enclos connect lab -- hermes -p main
```

Hermes's export of `default` carries the agent's configuration, personality, skills, cron jobs and memories, and leaves out its secrets and login (`auth.json`, `.env`, the browser's data), its databases, logs and caches. Its `sessions/` folder comes along, but Hermes keeps conversation history in `state.db`, which this export leaves out. An export of a named agent (`hermes profile export scout`) leaves out the same secrets and the browser's data but carries its database, history and logs. That is Hermes's doing, by its code, and not shown by a prototype yet (design §14). enclos never looks inside the archive: it copies it beside the sandbox home, Hermes imports it inside the sandbox under its policy, and enclos records the agent with the archive's SHA-256 in the audit log, once when the copy is made and once with the record. `default` is the sandbox's own built-in agent, so your Mac's `default` comes in under another name, such as `main`. The archive must be a file of your own: not a link, and not under a sandbox's folder (`~/.enclos/sandboxes`), even through a link.

Three things do not come in with the archive. Your login: enclos copies none in, so the agent should use the sandbox's, made with `enclos connect lab -- hermes -p default setup`. If its configuration names another provider, it asks for that login inside the sandbox; until enclos grants secrets per sandbox (milestone 2), values it needs, such as a bot token, go in its files inside the sandbox, with Hermes's own commands. Network grants: nothing in the archive widens the sandbox's policy, so what the agent reaches shows in `enclos net log lab` and what was refused in `enclos net denied lab`, where you decide. Your own Hermes: enclos never runs it, and never reads `~/.hermes` on its own.

Its cron jobs come along and start acting as soon as the sandbox's gateway runs, at once if `lab` is already started (`enclos sandbox start lab`). That they run there, and that the imported agent uses the sandbox's login, is still to verify (design §14). To take an agent back out, run the export inside the sandbox, where `connect` starts in the sandbox's home: `enclos connect lab -- hermes profile export main -o main.tar.gz` writes `~/.enclos/sandboxes/lab/home/main.tar.gz` on your Mac. Copy it to a folder of your own before importing it elsewhere: enclos refuses an archive under a sandbox's folder.

## Check the sandbox

```bash
enclos policy test lab
```

This runs escape probes from inside the sandbox: reading `~/.ssh` and other sensitive files, writing outside its home, reaching an unlisted site, connecting around the proxy, signalling a process outside, reading the pasteboard, and more. Every probe must fail. On your Mac it runs only probes that cannot change anything if a rule did not hold; CI runs the rest (`--host-services`). The last line says whether the sandbox is ready: `READY` when no probe got out, or `NOT READY` with why. A probe marked `inconclusive` could not be checked on your Mac, as when macOS keeps your terminal itself out of a folder such as `~/Library/Mail`; it does not stop the sandbox being ready.

## Run it

```bash
enclos sandbox start lab     # the proxy and the Hermes gateway, in the background, now and at each login
enclos connect lab -- main   # talk to the agent main
```

Ask it something that needs the web, such as the current weather in three cities. Then look at what it reached:

```bash
enclos net log lab           # every connection the sandbox made
enclos net denied lab        # what the sandbox was refused
```

An answer alone does not show where it came from: Hermes may answer from the model, or through the model provider's own web search, in which case the log shows only the provider. The public web needs no grant; another port, or any host in allowlist mode, does. If something you trust was refused, allow it from your Mac; it applies at once, without a restart:

```bash
enclos policy allow lab api.example.com:8443
```

The agent cannot allow anything itself.

## Look around

```bash
enclos status                # every sandbox and agent, what it costs on disk, what you could do
enclos sandbox show lab      # state, policy version, sessions and their processes
enclos logs lab -f           # the background services' logs
enclos policy show lab       # what the sandbox may do
enclos audit                 # every command that changed something
enclos audit verify          # check that nobody edited the audit log
```

To add a second sandbox, repeat the steps with another name. Each sandbox has its own Hermes install, login, policy and proxy, and cannot read the other's files.

## Stop and remove

```bash
enclos sandbox stop lab      # every service, session and process of the sandbox
enclos sandbox rm lab        # the sandbox and its home, with Hermes and its login
```

## What does not work yet

- **Browser tools:** Chromium does not start inside the sandbox yet, so Hermes's browser tools are unavailable.
- **Messaging:** each agent can have a Telegram bot of its own. Store its token with `enclos secret set lab/main-telegram`, grant it to that agent with `enclos policy edit lab` (`[secrets.agents.main] env = { TELEGRAM_BOT_TOKEN = "secret:lab/main-telegram" }`), then run `enclos runtime configure lab/main --channel telegram --allow-user <your Telegram id>`; `enclos runtime configure lab ...` does the same for the built-in agent, `default`, whose grant goes under `[secrets.agents.default]`. Start the sandbox with `enclos sandbox start lab` for its gateway to serve the bots. Agents of a sandbox share its files, so a bot token granted to one agent is kept apart from the others, not hidden from them. Secrets work already: `enclos secret set lab/<name>` stores one in the Keychain, and adding `[secrets] env = { NAME = "secret:lab/<name>" }` with `enclos policy edit lab` gives it to every session and service of the sandbox. `enclos sandbox rm` removes the sandbox's secrets too.

## If you used an earlier build

A build from before the runtime and agent names stored its state differently, and this one refuses it with a message saying so. Remove the old sandboxes with the old build first (`enclos sandbox stop <name>`, then `enclos sandbox rm <name>`), or move `~/.enclos` aside, then install this build and start again from `enclos init`.
