# Getting started on a Mac

This guide runs Hermes agents in a sandbox on your Mac, with milestone 1 of enclos. It creates a sandbox called `lab` with two agents, `main` and `scout`. Pick any name you like for the sandbox; avoid `home`, which makes paths such as `sandboxes/home/home` hard to read.

The words used here:

- **Sandbox:** an isolated environment with its own home folder, policy and network proxy.
- **Runtime:** the software installed in a sandbox, here Hermes. One per sandbox.
- **Agent:** a named identity of that runtime, with its own configuration, memory, skills, sessions and channels. Agents in one sandbox share its runtime, policy, proxy and login.

## Before you start

- macOS 14 or later, with Rust installed through [rustup](https://rustup.rs).
- A ChatGPT subscription, for Hermes's login.
- About 2.5 GB of free disk space per sandbox: each sandbox gets its own Hermes install.

Install enclos from a clone of the repository:

```bash
cargo install --path .
```

## Create a sandbox and install Hermes

```bash
enclos init                                  # the ~/.enclos folder, state database and audit log
enclos sandbox create lab                    # Seatbelt backend, `assistant` template
enclos runtime install hermes --sandbox lab  # Hermes's own installer, run inside the sandbox; takes a few minutes
enclos runtime login lab                     # Hermes's login: pick OpenAI Codex, then open the URL and enter the code
```

`enclos runtime install` downloads Hermes's installer on your Mac and runs it only if it is the version enclos was reviewed against. The install runs inside the sandbox, through its proxy, so it can write only to the sandbox's home.

`enclos runtime login` runs Hermes's own login in your terminal. It prints a URL and a code: open the URL in your browser on the Mac and enter the code. Then pick a model from the list Hermes shows; it lists the ones your account can use. Every agent in the sandbox shares this login.

## Add agents

```bash
enclos agent add lab/main
enclos agent add lab/scout
enclos agent list lab
```

## Reach an agent

You reach the sandbox with `enclos connect lab`: a shell, or the command you put after `--`. To talk to an agent or change it, run Hermes's own commands that way:

```bash
enclos connect lab -- main                # talk to the agent main (Hermes's wrapper for `hermes -p main`)
enclos connect lab -- scout model         # change the model of the agent scout
enclos connect lab -- hermes -p scout     # the same agent, without the wrapper
enclos connect lab                        # a shell in the sandbox, for anything else
```

enclos does not need to know how a runtime picks an agent: whatever its documentation shows, put `enclos connect lab --` in front of it.

Hermes prints its own next steps after creating an agent, such as `main setup` and `main chat`. Run them the same way. In that shell, `~` is the sandbox's home (`~/.enclos/sandboxes/lab/home` on your Mac), so `~/.hermes/profiles/main/SOUL.md` is the agent's personality file. `main setup` is optional: every agent already uses the sandbox's login.

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

An answer alone does not show where it came from: Hermes may answer from the model, or through the model provider's own web search, in which case the log shows only the provider. If a site you trust was refused, allow it from your Mac; it applies at once, without a restart:

```bash
enclos policy allow lab api.open-meteo.com
```

The agent cannot allow anything itself.

## Look around

```bash
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
