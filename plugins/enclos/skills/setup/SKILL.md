---
name: setup
description: Set enclos up on this host, step by step, from nothing to an agent running in a sandbox; picks up where the host already is. Run only when the user asks for it.
argument-hint: "[sandbox name]"
disable-model-invocation: true
---

# Set up enclos on this host

Take this host from wherever it is to a Hermes agent answering in an enclos sandbox. The `enclos` skill holds what enclos is, how to drive its CLI and the rules you follow: read its `SKILL.md` first if it is not loaded, and keep to its rules here, above all that a secret's value and a login are the user's, never yours.

Work one step at a time. Before each step, say in a line what it does; after it, say what enclos reported. Skip every step the host has already done: find out with the checks given, never by assuming. If a step fails, stop, show the user enclos's message, and use the `enclos` skill's [troubleshooting](../enclos/reference/troubleshooting.md) before going on.

The sandbox's name is `$ARGUMENTS` if the user gave one; otherwise ask, suggesting `lab` (not `home`). Below it is `<sandbox>`.

## 1. The host

- `uname -s`, `uname -m`, and on macOS `sw_vers -productVersion`. enclos's releases run on Apple silicon (`arm64`) with macOS 15 or later, and on Linux on `x86_64` or `aarch64` with systemd 254 or later (`systemctl --version`). On Linux, read the `enclos` skill's [Linux section](../enclos/reference/workflows.md#on-linux) first: bubblewrap must be installed before `enclos init`, and that and any `sudo` step are the user's.
- Anything else: say enclos does not run here, and stop.

## 2. enclos itself

- `enclos --version`, else `~/.local/bin/enclos --version`.
- Missing: tell the user what the installer does (the latest release from GitHub, its checksum and version checked, into `~/.local/bin`, no sudo, no shell file edited), then run `curl -fsSL https://enclos.dev/install.sh | bash`. If `~/.local/bin` is not on the PATH, give the user the `export` line it printed and use `~/.local/bin/enclos` meanwhile.
- Compare the version with the first line of the `enclos` skill's [reference/commands.md](../enclos/reference/commands.md); when they differ, check each command below with `--help` before running it.

## 3. State and backend

- `enclos status`. "not initialized": run `enclos init`.
- `enclos doctor`. It must say a backend runs here; if none does, show the user why and stop.
- From `enclos status`, note each sandbox's `state`, `runtime` and `agents`, and the `suggestions`: they say what comes next for a sandbox that exists.

## 4. The sandbox

If `<sandbox>` exists, go on to step 5. Otherwise ask the user which template, and explain the choice:

- `assistant`: its agents reach the public web (ports 80 and 443), logged. The usual choice for an assistant that searches or browses.
- `minimal`: only Hermes's own hosts (its install sources and the ChatGPT subscription's), and what the user allows later. Their model provider may need `enclos policy allow` if it is not ChatGPT.

Then `enclos sandbox create <sandbox> --template <template>`. It uses the default backend `enclos init` chose: Seatbelt on a Mac, bubblewrap on Linux.

## 5. Hermes

If the sandbox's `runtime` is null: `enclos runtime install hermes --sandbox <sandbox>`. It runs Hermes's own installer inside the sandbox and takes a few minutes; tell the user so before starting it.

## 6. The login (the user's)

Hermes needs a model provider and a login, which only the user can give, at a terminal. Ask whether the sandbox is already logged in. If not, give them this to run in a terminal of their own, and wait for them to say it is done:

```bash
enclos connect <sandbox> -- hermes -p default setup
```

What to expect: Hermes's own wizard asks for a provider, then shows a login (a URL to open in the browser on this host, since the sandbox cannot open one), then asks for a model. Every agent in the sandbox shares this login.

## 7. An agent

`enclos agent list <sandbox>` shows `default`, which is built in. Ask the user for an agent's name (a lowercase letter, then lowercase letters, digits or hyphens; such as `main`), or whether they want to bring one from their own Hermes on this host (the `enclos` skill's [importing](../enclos/reference/workflows.md#bring-an-agent-from-the-host)). Then `enclos agent add <sandbox>/<agent>`.

## 8. Check the sandbox

`enclos policy test <sandbox>`. Its last line must say `READY`. If it says `NOT READY`, stop: tell the user what it printed, and don't start the sandbox.

## 9. Run it

`enclos sandbox start <sandbox>`: the proxy and Hermes's gateway, in the background, now and at each login.

**Check that the agent answers.** A running gateway and a `READY` policy test do not show that the provider, the model and the login work: one message does.

1. Find how this Hermes takes a single message without a terminal: `enclos exec <sandbox> -- hermes chat --help` (and `enclos exec <sandbox> -- hermes --help` if `chat` has no such option). Look for an option that takes the message as an argument, prints the answer and exits, such as a query or quiet mode; use what the installed version shows, not what you remember.
2. Send one short message to the agent with it, through `exec`, naming the agent with `-p <agent>`, such as asking it to reply with one word. `exec` exits with Hermes's own code.
3. The check passes when the command exits 0 and prints an answer. Otherwise, show the user what it printed: a login or provider error goes back to step 6, a refused destination shows in `enclos net denied <sandbox>`. If this Hermes has no one-shot form, say so, and ask the user to confirm the agent answers in their own terminal before you call the setup done.

Then give the user the line to talk to their agent in their terminal:

```bash
enclos connect <sandbox> -- <agent>
```

Suggest a first question that needs the web, such as the weather in three cities. Once they have asked it, run `enclos net log <sandbox> --since 15m` and `enclos net denied <sandbox>`, and tell them what the sandbox reached and what was refused.

## 10. What else (ask; do none of it unprompted)

- **A Telegram bot for the agent**: the `enclos` skill's [secrets and bots](../enclos/reference/workflows.md#secrets-and-bots). The token is set by the user, in their terminal.
- **The mobile app**: [the mobile app](../enclos/reference/workflows.md#the-mobile-app), where this build has `enclos app`.
- **Allowing enclos commands without a prompt**: the plugin's README, which says what such a rule allows.

End with a short summary: the sandbox, its template, its agents, the result of `policy test`, whether the agent answered through `exec`, and the commands the user will want (`enclos status`, `enclos connect <sandbox> -- <agent>`, `enclos net log <sandbox>`, `enclos sandbox stop <sandbox>`).
