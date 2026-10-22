---
status: accepted
---

# A service restarts when its runtime's settings change

Some of a runtime's settings take effect only when its service starts. Hermes's gateway connects to Telegram with the token in `~/.hermes/.env` once, as it starts, so a token added later does nothing until the gateway restarts. Hermes then asks for a restart, but none of its own ways reach a gateway enclos runs. The agent may not restart the gateway it runs in: Hermes refuses `hermes gateway restart` from inside it, to avoid restart loops. From a `connect` session, `hermes gateway restart` and the setup wizard signal the gateway, and Seatbelt refuses a signal from one `sandbox-exec` to another (`deny(1) signal others`, shown in a VM with macOS 26.6.2 and Hermes 0.22.4). Only `/restart` in chat works, and only when the user knows to send it.

So `enclos launch`, which runs outside the sandbox and started the service's program, also watches the files its adapter names in the sandbox home. Once one of them has changed and stayed the same for a few seconds, and no `connect` session's program runs in the sandbox (checked under the state lock, under which `connect` starts and records its program, so none starts in between), `launch` records an audit entry and sends the program the adapter's restart signal, checking first that it is still the same process. It waits for the sessions because a person may not be done: Hermes's setup wizard saves each answer as it is given, and its TUI is served by the gateway, which a restart would cut off. A restart that could not be recorded or sent is asked again after the next change, or a minute later, then two, four and so on up to about an hour. The program drains and exits, and `launch` exits non-zero, so the service manager starts the service again under the same snapshot. The files are read as other files in the home are ([0023](0023-agents-made-inside-a-sandbox.md)): without following a link, with a size limit. They are compared by content, so a file rewritten with the same content, or changed and changed back, restarts nothing. A file that cannot be read counts by its reason, so a file that becomes a link counts as a change. For Hermes, the files are `config.yaml` and `.env` of the home and of each agent present when the gateway started, and the signal is `USR1`, Hermes's graceful restart for a gateway run with `--external-supervisor`. In the VM, a line added to `.env` from a `connect` session restarted the gateway once: `launch` sent `USR1`, the gateway drained and exited 75, and launchd started it again. A gateway left alone for a minute, before and after, was not restarted, so Hermes does not rewrite these files as it starts. A `connect` session that wrote `.env`, then `config.yaml` 20 seconds later, was not cut off: the gateway restarted once, a second after the session ended, for both files. A runtime without such files names none, and its services are never restarted this way. A runtime without a graceful restart gets `TERM`.

The sandbox could already restart its own service, by ending its program, so a sandbox that writes these files gains nothing. Nothing about the restart depends on Seatbelt or launchd: the files are read the same way on Linux, and the systemd units that will run `launch` there (milestone 3) need `Restart=on-failure`, as launchd's `SuccessfulExit` is `false` here.

## Considered options

- **Allowing signals between a sandbox's `sandbox-exec` instances:** Seatbelt's `signal` filter has `same-sandbox` or `others`, nothing narrower, so a sandbox could signal every process of the user.
- **Hermes's control socket (`pause-for-update`) from a `connect` session:** works (shown in the VM), but enclos would have to replace Hermes's own `hermes gateway restart`, and the setup wizard restarts from inside Hermes, which no wrapper reaches.
- **Restarting when Hermes reports a restart is needed:** Hermes records no such state; its dashboard works it out for each messaging platform.

## Consequences

- A restart closes the gateway's connections for a few seconds; by default Hermes drops the Telegram messages sent meanwhile when it starts again (`platforms.telegram.extra.drop_pending_on_cold_boot`, which can be set to `false`).
- A change Hermes would apply without a restart also restarts the gateway, after the turns running then have finished.
- One gateway serves every agent of the home, so a change to one agent's settings restarts them all.
- While a `connect` session stays open, such as a TUI left running, a change waits for it; `/restart` in chat restarts sooner.
- An agent created after the gateway started is not watched until the gateway's next start; Hermes serves a new agent without a restart.
