# Mobile channel prototype: a Hermes channel on a Unix socket

Throwaway code that answers the first questions of the mobile app channel ([victorbonnet/enclos#145](https://github.com/victorbonnet/enclos/issues/145), "To verify"), before enclos's code depends on them. Nothing here is enclos code: a minimal Hermes channel plugin, `enclos`, that listens on a Unix socket in the sandbox home, and a bridge script that the host runs to talk to it.

**Status: answered on a Mac by the channel itself, not by this code.** This plugin was written against Hermes's source (main, `9302ba9e`, 2026-11-03: `hermes_cli/plugins.py`, `gateway/platform_registry.py`, `plugins/platforms/ntfy/`) and never loaded by a real Hermes; `bridge.py` was checked only against a stand-in agent that echoes each line. The questions were answered instead by the first runs of enclos's own channel plugin (`channels/hermes/`, written into the sandbox by `enclos runtime configure --channel app`) and its bridge, which follow the same design: see Results. Linux stays open.

## Questions

| # | Question | How this answers it |
| --- | --- | --- |
| Q1 | Under Seatbelt, can the gateway bind a Unix socket in the sandbox home, and can a program on the host connect to it? | The plugin logs `Listening on …` or `Cannot listen on …`; `bridge.py` on the host connects or not |
| Q2 | Does a plugin in the built-in agent's home (`~/.hermes/plugins/`) serve every agent, or does each agent's home need its own copy? | Step 4: a second agent with the socket set and no plugin of its own |
| Q3 | Does a cron job created in a conversation deliver back to that conversation through the plugin? | Step 5 |
| Q4 | Does `hermes plugins enable` need to run for a plugin in the home, or is dropping it there enough? | Step 2 |

Linux questions (Landlock's right to make a socket in the home, a socket reached across the sandbox's network namespace) are still open; the same steps answer them on a host where milestone 3's bubblewrap sandboxes run. Whether Hermes keeps memory per person (for sharing) is a later prototype.

## Files

| File | What it does |
| --- | --- |
| `plugin/enclos/` | The Hermes channel: `plugin.yaml`, `__init__.py`, `adapter.py`. On when the agent's environment sets `ENCLOS_SOCKET`. One JSON object per line each way: `message.in` (`conversation`, `person`, `text`) from the bridge, `message.out` (`conversation`, `text`) from the agent |
| `bridge.py` | Run on the host. `chat SOCKET [--conversation ID]` sends each typed line to the agent in one conversation and prints what comes back; `listen SOCKET` only prints. Standard library only |

Prototype gaps, on purpose: no token (anything that can reach the socket can talk to the agent), nothing queued while no bridge is connected (a reply then is dropped and the gateway's log says so), no attachments, no typing indicator, and `ENCLOS_ALLOW_ALL_USERS` accepts every person the bridge names.

## Running it

On a Mac with enclos 0.2.0 and a Hermes sandbox, here `lab` with the agents `main` and `scout`, set up as in [getting started](../../docs/getting-started.md). The sandbox home is `~/.enclos/sandboxes/lab/home` on the host (`$ENCLOS_HOME/sandboxes/lab/home` with `ENCLOS_HOME` set), and `$HOME` inside the sandbox.

A Unix socket's path is at most 104 bytes on macOS. The socket goes in `~/.enclos-app/` of the sandbox home, which keeps the host's path short; with a long user name or `ENCLOS_HOME`, check that `~/.enclos/sandboxes/lab/home/.enclos-app/main.sock` stays under it.

1. **Copy the plugin into the built-in agent's home.** The host writes into the sandbox home here, which enclos itself never does for files the sandbox can change; this is a prototype step only.

   ```bash
   mkdir -p ~/.enclos/sandboxes/lab/home/.hermes/plugins
   ```

   ```bash
   cp -R prototype/m4/plugin/enclos ~/.enclos/sandboxes/lab/home/.hermes/plugins/
   ```

2. **Turn the channel on for `main`** by giving it a socket path, then see whether Hermes loads the plugin (Q4). Its `.env` changing restarts the gateway ([ADR 0031](../../docs/adr/0031-a-service-restarts-when-its-runtime-settings-change.md)).

   ```bash
   enclos exec lab -- sh -c 'printf "ENCLOS_SOCKET=%s\nENCLOS_ALLOW_ALL_USERS=true\n" "$HOME/.enclos-app/main.sock" >> "$HOME/.hermes/profiles/main/.env"'
   ```

   ```bash
   enclos sandbox start lab
   ```

   ```bash
   enclos exec lab -- hermes plugins list
   ```

   ```bash
   enclos logs lab
   ```

   The gateway's log should say `[enclos] Listening on …/main.sock` (Q1, inside), or `Cannot listen on …` with the error. If `plugins list` shows `enclos` disabled, run `enclos exec lab -- hermes plugins enable enclos`, note it for Q4, and restart with `enclos sandbox restart lab`.

3. **Connect from the host** (Q1, outside):

   ```bash
   python3 prototype/m4/bridge.py chat ~/.enclos/sandboxes/lab/home/.enclos-app/main.sock --conversation c-1
   ```

   Type a question; the agent's answer comes back as `[c-1] …`. Start a second bridge with `--conversation c-2`: it should be a new session, with no memory of `c-1`'s turn.

4. **A second agent** (Q2): repeat step 2 for `scout` with `scout.sock`, without copying the plugin into `~/.hermes/profiles/scout/`. If `scout.sock` appears, the default home's plugin serves every agent; if not, copy the plugin into `~/.hermes/profiles/scout/plugins/` and note it.

5. **Cron back to its conversation** (Q3). In the `c-1` bridge, ask the agent for a job that sends something in two minutes ("in 2 minutes, send me the time"). Leave a second terminal on:

   ```bash
   python3 prototype/m4/bridge.py listen ~/.enclos/sandboxes/lab/home/.enclos-app/main.sock
   ```

   The job's output should arrive as `[c-1] …`. Check what Hermes stored with `enclos exec lab -- hermes -p main cron list`: its `origin` should name the `enclos` platform and `c-1`. Then stop both bridges before the next job fires: the gateway's log should say the reply was dropped, which is what the real plugin's queue is for.

6. **Clean up**: `enclos sandbox stop lab`, then remove the two lines from each agent's `.env` and `~/.hermes/plugins/enclos` from the sandbox home.

## Results

Shown on a Mac (macOS 27.2) in a sandbox `lab` with the agents `main` and `coder`, from 2026-11-05 to 2026-11-08, with Hermes from its main branch as the Hermes installer served it then (Hermes records no version on disk; `docs/design.md` §14). Read from the gateway's logs, Hermes's cron records and the sandbox home afterwards. Not with this prototype's code: with enclos's channel plugin and bridge (above), which answer the same questions.

| # | Result |
| --- | --- |
| Q1 | **macOS: yes.** Under Seatbelt the gateway bound each agent's socket in the sandbox home (`~/.enclos-app/main.sock`, `coder.sock`, mode `0600`), and the bridge on the host connected to it and exchanged messages both ways (the log's `[Enclos] Listening for the bridge`, `Bridge connected`, and replies sent to the bridge's conversations). **Linux: open** (Landlock's right to make the socket in the home, the host reaching it across the sandbox's network namespace). |
| Q2 | **Not tried as asked.** The channel takes the other way: a copy of the plugin in each agent's own home (`~/.hermes/profiles/<agent>/plugins/enclos/`), which loaded for both agents. Whether one copy in the built-in agent's home serves every agent stays unknown, and nothing depends on it now. |
| Q3 | **Yes.** Three cron jobs asked for in conversations of the channel (2026-11-05 and 2026-11-06) were stored with `origin` naming the `enclos` platform and that conversation's id, and `deliver: origin`; each ran, and Hermes logged it `delivered to enclos:<conversation> via live adapter` and recorded the delivery as `delivered`. |
| Q4 | **Enabling works; dropping alone was not tried.** `runtime configure` runs `hermes -p <agent> plugins enable enclos`, which lists `enclos` under `plugins.enabled` in the agent's `config.yaml`, and the plugin then loads. Hermes's source loads a home plugin only once it is enabled; that a plugin merely dropped there stays off was not checked. |
