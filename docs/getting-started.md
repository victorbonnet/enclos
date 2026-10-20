# Getting started on a Mac

This guide runs Hermes agents in a sandbox on your Mac, with milestone 1 of enclos. It creates a sandbox called `lab` with two agents, `main` and `scout`. Pick any name you like for the sandbox; avoid `home`, which makes paths such as `sandboxes/home/home` hard to read.

The words used here:

- **Sandbox:** an isolated environment with its own home folder, policy and network proxy.
- **Runtime:** the software installed in a sandbox, here Hermes. One per sandbox.
- **Agent:** a named identity of that runtime, with its own configuration, memory, skills, sessions and channels. Agents in one sandbox share its runtime, policy, proxy and login.

## Before you start

- macOS 14 or later, with Rust installed through [rustup](https://rustup.rs).
- An account with a model provider Hermes supports, for its login.
- About 2.5 GB of free disk space per sandbox: each sandbox gets its own Hermes install.

Install enclos from a clone of the repository:

```bash
cargo install --path .
```

## Create a sandbox and install Hermes

```bash
enclos init                                    # the ~/.enclos folder, state database and audit log
enclos sandbox create lab                      # Seatbelt backend, `assistant` template
enclos runtime install hermes --sandbox lab    # Hermes's own installer, run inside the sandbox; takes a few minutes
enclos connect lab -- hermes -p default setup  # Hermes's own setup: your provider and its login, then a model
```

`enclos runtime install` downloads Hermes's installer on your Mac and runs it only if it is the version enclos was reviewed against. The install runs inside the sandbox, through its proxy, so it can write only to the sandbox's home.

`enclos connect lab -- hermes -p default setup` runs Hermes's own setup wizard inside the sandbox, in your terminal, for its root profile, whose login every agent shares (`-p default` names it, since a bare `hermes` uses whichever profile `hermes profile use` last picked): pick your provider, log in the way Hermes asks, then pick a model. enclos has no login command of its own: whatever a runtime's documentation says to run, put `enclos connect lab --` in front of it. The sandbox cannot open a browser, so when the login shows a URL, open it in your browser on the Mac. Every agent in the sandbox shares this login. To change only the provider or the model later, run `enclos connect lab -- hermes -p default model`.

The sandbox reaches the public web through its proxy, on ports 80 and 443, so any provider's login and API work, and every connection is logged. It never reaches your Mac's own services, your local network or cloud metadata addresses. To limit `lab` to the hosts you list, set `mode = "allowlist"` under `[network]` in its `policy.toml` (`enclos policy show lab` says which file); Hermes's own OpenAI hosts stay allowed.

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

enclos does not need to know how a runtime picks an agent: whatever its documentation shows, put `enclos connect lab --` in front of it.

Until you run the sandbox (below), only what you run in `connect` runs: the Hermes gateway, which serves scheduled jobs and messaging for every agent, is not running yet.

Hermes prints its own next steps after creating an agent, such as `main setup` and `main chat`. Run them the same way. In that shell, `~` is the sandbox's home (`~/.enclos/sandboxes/lab/home` on your Mac), so `~/.hermes/profiles/main/SOUL.md` is the agent's personality file. `main setup` is optional: every agent already uses the sandbox's login.

### Agents made inside the sandbox

You can also create an agent with Hermes's own commands, from a shell in the sandbox (`enclos connect lab`, then `hermes profile create scout`). It works right away (`enclos connect lab -- scout`), but enclos has no record of it yet, so `enclos agent list lab` would not show it. enclos tells you when it sees one, at the end of the `connect` session (on stderr, prefixed with `enclos:`), in `enclos agent list lab` and in `enclos sandbox show lab`:

```text
lab/scout: Hermes has this agent; enclos does not track it. Track it with `enclos agent add lab/scout`.
```

`enclos agent add lab/scout` then adopts it as it is, without creating it again. If you delete an agent inside the sandbox, enclos reports it the same way and `enclos agent rm` removes its record.

`enclos agent rm lab/scout` deletes an agent with its files, using Hermes's own command, after asking you to confirm (`--yes`); `--keep-data` removes only enclos's record and leaves the files, so Hermes still has the agent and enclos reports it as one it does not track. Agent names in enclos are a lowercase letter, then 1 to 40 lowercase letters, digits or hyphens; `agent list` and `sandbox show` also report a Hermes agent named otherwise (`my_bot`), which enclos cannot track. If enclos cannot read Hermes's list, because something in the sandbox replaced `~/.hermes` with a link for example, these commands say so instead of showing nothing, and `agent add` refuses until you have looked.

## Check the sandbox

```bash
enclos policy test lab
```

This runs escape probes from inside the sandbox: reading `~/.ssh` and other sensitive files, writing outside its home, reaching an unlisted site, connecting around the proxy, signalling a process outside, reading the pasteboard, and more. Every probe must fail. On your Mac it runs only probes that cannot change anything if a rule did not hold; CI runs the rest (`--host-services`).

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
- **Messaging and secrets:** Telegram and secrets from the Keychain come in milestone 2.
- **Pending policies:** a policy change applies at once or not at all; saving one for later comes in milestone 2.

## If you used an earlier build

A build from before the runtime and agent names stored its state differently, and this one refuses it with a message saying so. Remove the old sandboxes with the old build first (`enclos sandbox stop <name>`, then `enclos sandbox rm <name>`), or move `~/.enclos` aside, then install this build and start again from `enclos init`.
