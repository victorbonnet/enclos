# Channel plugins

The mobile app's channel for each runtime (`docs/protocol.md`, [ADR 0042](../docs/adr/0042-a-bridge-on-each-host-serves-the-mobile-app.md), proposed): the code that runs inside a sandbox, in the runtime's own process, and listens for enclos's bridge on a Unix socket in the sandbox home.

| Folder | Runtime | What it is |
| --- | --- | --- |
| `hermes/enclos/` | Hermes | A gateway platform plugin. `protocol.py` and `outbox.py` use the standard library only and are tested with the `enclos-protocol` crate's fixtures (`just hermes-plugin`); `adapter.py` is Hermes's side |

enclos's binary carries these files and writes them into the agent's sandbox with `enclos runtime configure <sandbox>/<agent> --channel app`. `prototype/m4/` records the first socket, plugin loading and cron-delivery checks.

The channel's `PLATFORM_HINT` in `protocol.py` tells the agent what the app renders: markdown, attachments and [static HTML artefacts](../docs/protocol.md#files). For a page, the agent writes one self-contained UTF-8 `.html` file and sends `MEDIA:/absolute/path/page.html` on its own line. The viewer supports inline CSS and data images or fonts; scripts, remote assets, relative files, forms and automatic outgoing navigation are unavailable. Same-page anchors stay in the viewer; the person can deliberately tap a main-frame HTTP(S) link to open a website in the preferred browser's Custom Tab on Android where supported. Automatic navigation cannot launch it. HTML in message text stays literal. Keep this hint and the app's rendering contract together when changing the capability.

Native questions use Hermes's `send_clarify` adapter hook and public clarify registry. The plugin saves a card's exact native entry and session key, resolves an explicit `question.answer` into that waiter, and sends durable `question.update` settlement; an answer never becomes another chat turn. A question's native event and the retirement hook close expired, skipped, answered and cancelled cards. Reconnect sync reaffirms live entries and expires cards missing after a Hermes restart. Older bridges or runtimes receive the same complete numbered question through bounded text chunks. The ordinary composer remains an answer path for older apps.

The bundled model-invoked [`app-questions` skill](hermes/enclos/skills/app-questions/SKILL.md) is explicitly registered when Hermes supports plugin skills; the always-loaded hint retains essential `clarify` guidance. Runtime packaging includes the Python module and skill in each configured agent's own plugin folder.
