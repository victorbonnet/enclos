---
status: proposed
---

# A dashboard on macOS uses a private inherited socket

This proposes superseding ADR 0028's consequence that Hermes's gateway is a usable browser dashboard, and ADR 0040's macOS exception. The gateway withholds its browser token; opening it produces repeated 401s and reloads. A plain `hermes dashboard` publishes the token on shared loopback. Putting an owner-checked proxy before it leaves that raw TCP port reachable, including through another sandbox's stale service-port allowance.

Decision (proposed; implemented in this PR): use `enclos dashboard <sandbox>` on macOS as well as Linux. On Seatbelt, enclos binds a Unix listener in its host-only run folder and passes that descriptor only to the dashboard session, under the marker's spawn lock. That session is excluded from the normal TCP-listening allowance and cannot bind TCP. Unix sockets inside its own home remain available for IPC. An adapter starts Hermes with its own dependency launcher, supplies the inherited listener to Uvicorn, and maps its authenticated Unix peer to the loopback identity Hermes requires for WebSockets. Changes to the runtime that require a TCP listener fail closed. Adapter source is copied into the runtime from inside the sandbox; it is never imported on the host.

The host binds a free port in enclos's proxy range, excluding this install's reserved sandbox ports, reads each TCP client's uid with bounded `lsof`, and rejects another or unknown owner before forwarding. A random 256-bit URL path capability also protects against another install's same-uid sandbox retaining access to a reused proxy port. It lives in the host-only dashboard lock and the URL enclos prints, never runtime stdout. Every local HTTP request must name that path; enclos removes it and supplies `X-Forwarded-Prefix`. Ordinary requests close their connection; WebSocket upgrades become a byte relay. The adapter adds `Referrer-Policy: no-referrer` to keep that path out of outgoing navigation headers. Treat the full URL as a credential.

The existing dashboard lock, audited start and end, session policy, secrets, limits, and Ctrl-C cleanup apply. On macOS the runtime files, running sandbox and listening gateway are prerequisites; failure starts no services. Status offers the command only for an installed, running runtime, and uses no sandbox-printed URL. Linux keeps ADR 0040's namespace relay and owner check.

CLI JSON moves to schema 2: the unused `dashboard` URL fact and `RuntimeListener::page` are removed; consumers use `dashboard_command`, which may be null when prerequisites are absent. State, audit-file and app-protocol schemas do not change.

Kernel tests on the development Mac show inherited-socket acceptance, refusal of TCP binds and direct socket-path connections; real Hermes serves HTML, assets, authenticated APIs and WebSockets through the protected path. Owner parsing and missing/incorrect capabilities have regression tests. A second-user test, with a working loopback control, runs on the macOS CI runners; local noninteractive sudo is unavailable, so that scenario remains for CI to verify.
