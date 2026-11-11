# Channel plugins

The mobile app's channel for each runtime (`docs/protocol.md`, [ADR 0042](../docs/adr/0042-a-bridge-on-each-host-serves-the-mobile-app.md), proposed): the code that runs inside a sandbox, in the runtime's own process, and listens for enclos's bridge on a Unix socket in the sandbox home.

| Folder | Runtime | What it is |
| --- | --- | --- |
| `hermes/enclos/` | Hermes | A gateway platform plugin. `protocol.py`, `outbox.py` and `lines.py` use the standard library only and are tested with the `enclos-protocol` crate's fixtures and their own tests (`just hermes-plugin`); `adapter.py` is Hermes's side |

enclos's binary is meant to carry these and write them into a sandbox (`runtime configure <sandbox>/<agent> --channel app`, the next step of milestone 4); nothing installs them yet. `prototype/m4/README.md` records what this plugin's first runs in a real Hermes showed, on a Mac: the socket, the plugin's loading and cron delivery. Linux is still to run.
