# Channel plugins

The mobile app's channel for each runtime (`docs/protocol.md`, [ADR 0042](../docs/adr/0042-a-bridge-on-each-host-serves-the-mobile-app.md), proposed): the code that runs inside a sandbox, in the runtime's own process, and listens for enclos's bridge on a Unix socket in the sandbox home.

| Folder | Runtime | What it is |
| --- | --- | --- |
| `hermes/enclos/` | Hermes | A gateway platform plugin. `protocol.py`, `outbox.py` and `lines.py` use the standard library only and are tested with the `enclos-protocol` crate's fixtures and their own tests (`just hermes-plugin`); `adapter.py` is Hermes's side |

enclos's binary carries these files and writes them into the agent's sandbox with `enclos runtime configure <sandbox>/<agent> --channel app`. `prototype/m4/README.md` records what this plugin's first runs in a real Hermes showed, on a Mac: the socket, the plugin's loading and cron delivery. Linux is still to run.

The channel's `PLATFORM_HINT` in `protocol.py` tells the agent what the app renders: markdown, attachments and [static HTML artefacts](../docs/protocol.md#files). For a page, the agent writes one self-contained UTF-8 `.html` file and sends `MEDIA:/absolute/path/page.html` on its own line. The viewer supports inline CSS and data images or fonts; scripts, remote assets, relative files, forms and automatic outgoing navigation are unavailable. Same-page anchors stay in the viewer; when the person taps a main-frame HTTP(S) link, the app shows its host and address and, once confirmed, opens the website in the preferred browser's Custom Tab on Android where supported. Automatic navigation is meant not to launch it. HTML in message text stays literal. Keep this hint and the app's rendering contract together when changing the capability.
