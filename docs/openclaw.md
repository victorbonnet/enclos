# OpenClaw on a Mac

This guide uses the M5 OpenClaw CLI adapter, checked against OpenClaw 2026.11.2.
It creates sandbox `claw` with agents `main` and `scout`. Use the Mac requirements
and enclos installation steps in [Getting started](getting-started.md). Allow disk
space for a private Node/runtime, package downloads and provider runtime packages.

These are operator instructions for the implemented stack, not a declaration that
M5 acceptance is complete. [The M5 plan](m5-openclaw.md) and
[issue #218](https://github.com/victorbonnet/enclos/issues/218) track the remaining
gates; [the macOS prototype](../prototype/m5/README.md) records its actual probes.
Live Linux acceptance is the final step on the new host. The Pi is not required.

## Create and install

```bash
enclos init
enclos sandbox create claw --template assistant
```

Before installing, protect any OpenClaw state you already use on the host.
Built-in rules deny the host's `~/.openclaw` and `~/.openclaw-dev`. Named profiles
such as `~/.openclaw-work`, or state/configuration relocated with
`OPENCLAW_HOME`, `OPENCLAW_STATE_DIR` or `OPENCLAW_CONFIG_PATH`, need their exact
paths added with `enclos policy edit claw`:

```toml
[filesystem]
read_deny_add = ["~/.openclaw-work", "/Volumes/Private/openclaw-state"]
```

Merge entries into existing sections. Paths are literal: `~/.openclaw-*` is not a
profile wildcard. Existing sandboxes keep immutable policy snapshots after an
upgrade; review `enclos policy refresh SANDBOX`, then apply its changes with
`enclos --yes policy refresh SANDBOX`. See [policy protection and refresh](policy-compilation.md).

```bash
enclos runtime install openclaw --sandbox claw
enclos agent add claw/main
enclos agent add claw/scout
enclos agent list claw
```

The official installer runs inside the sandbox through its proxy, with a private
prefix, private Node and onboarding disabled. The wrapper keeps native state and
configuration under the sandbox's own `~/.openclaw`. It does not reuse a host
OpenClaw install or install an OpenClaw-owned host service.

Fresh OpenClaw has an implicit `main`; `agent add claw/main` adopts it. `scout` is
created through the native CLI. `main` is an ordinary native identity, not an
immutable built-in agent. Commands with an omitted agent resolve the native
selected default; use explicit `claw/main` or `claw/scout` while setting up.

## Give the managed Gateway its credential

Generate a token directly into enclos's secret store; on macOS this is the
Keychain. Its value never becomes a command argument:

```bash
openssl rand -hex 32 | enclos secret set claw/gateway
enclos policy edit claw
```

Add this grant to the policy:

```toml
[secrets]
env = { OPENCLAW_GATEWAY_TOKEN = "secret:claw/gateway" }
```

Use the exact variable `OPENCLAW_GATEWAY_TOKEN`. Native clients recognize that
name; a generic `GATEWAY_TOKEN` can leave a file-reference Gateway running while
client commands cannot authenticate. Keep the CLI grant and native reference on
the same secret. If the policy change is pending, apply it before configuring:

```bash
enclos --yes policy apply claw
enclos runtime configure claw/main \
  --set gateway.mode=local \
  --set gateway.auth.mode=token \
  --set 'gateway.auth.token=${OPENCLAW_GATEWAY_TOKEN}'
```

The quoted `${…}` is a reference, not shell interpolation. enclos translates it
to a native file SecretRef and maintains a protected JSON credential file outside
the sandbox home. The background Gateway reads that file; its token is not kept
in its startup environment or ordinary configuration. Interactive CLI sessions
receive their policy grants. Never replace the reference with a literal token.

## Sign in and select a model

`connect` and `exec` start the sandbox's required services, including its managed
Gateway. Use the native credential-only ChatGPT device flow:

```bash
enclos connect claw -- openclaw models auth login --provider openai --device-code --agent main
enclos connect claw -- openclaw models auth list --provider openai --agent main
enclos connect claw -- openclaw models list --provider openai --agent main
```

Open the displayed URL in your Mac's browser and enter the device code there.
OpenClaw owns the resulting provider login inside the sandbox. Do not paste its
access/refresh tokens into policy, `--set` arguments or chat. Auth selection is
per native agent: inspect `scout` with the same commands and `--agent scout`, and
sign it in if OpenClaw reports missing credentials.

Login preserves model selection. Omit `--set-default`: the native online login
rejects it while the Gateway owns this state. After choosing a model available
to your account, replace `PROVIDER/MODEL` below with its exact native reference:

```bash
enclos connect claw -- openclaw models set PROVIDER/MODEL
enclos connect claw -- openclaw models status --agent main
enclos connect claw -- openclaw tui --session agent:main:main
```

`models set` changes native agent defaults and may prepare a provider's runtime
package. To set an explicit agent override through enclos, use a plain setting,
for example `enclos runtime configure claw/scout --set
agents.entries.scout.model.primary=PROVIDER/MODEL`. Ordinary settings use native
keys; secrets still require granted `${VAR}` references. A saved login or a
successful status check does not establish that a model request succeeds.

On macOS, the current wrapper supplies the readable public system CA bundle to
native Codex through `CODEX_CA_CERTIFICATE` when neither it nor `SSL_CERT_FILE`
is already set. This fixes the observed confined `UnknownIssuer` failure while
retaining TLS verification and explicit CA overrides.

For scripts, use `enclos exec claw -- openclaw agent --agent main --message
'Your prompt'`. All native clients, provider helpers and SDK calls stay inside
recorded sandbox sessions.

## Add Telegram bots

Use a different bot token for each agent. Store values through the protected
terminal input, not arguments:

```bash
enclos secret set claw/main-telegram
enclos secret set claw/scout-telegram
enclos policy edit claw
```

```toml
[secrets.agents.main]
env = { TELEGRAM_BOT_TOKEN = "secret:claw/main-telegram" }

[secrets.agents.scout]
env = { TELEGRAM_BOT_TOKEN = "secret:claw/scout-telegram" }
```

Apply a pending policy, then replace `TELEGRAM_ID` with your numeric user id:

```bash
enclos --yes policy apply claw
enclos runtime configure claw/main --channel telegram --allow-user TELEGRAM_ID
enclos runtime configure claw/scout --channel telegram --allow-user TELEGRAM_ID
```

Configuration disables the account first, sets its allowed people, disables
groups, writes the protected token reference and binds that account to its agent
before enabling it. Repeat `--allow-user` for another allowed person. Do not grant
bot tokens under sandbox-wide `[secrets]`. Per-agent grants provide routing;
agents in one sandbox still share its permission boundary and files. Real
two-bot delivery and unlisted-person refusal remain acceptance checks.

## Operate and diagnose

```bash
enclos status
enclos sandbox show claw
enclos doctor
enclos logs claw -f
enclos net denied claw
enclos audit verify
enclos sandbox restart claw
enclos sandbox stop claw
```

enclos owns service start/stop/restart. The wrapper selects a sandbox-specific
loopback port and the engine verifies its listener; do not start another native
Gateway, install a native host service or send Hermes's restart signal. Native
hot reload handles supported settings changes. A pending sandbox policy requires
`policy apply`; restarting alone does not apply it.

The `assistant` template permits the public web through the proxy. For an
allowlist sandbox, use `--template minimal`; the adapter adds observed install
and OpenAI login destinations. Other providers and tools can need additional
hosts. Inspect refusals, then allow an intended destination with `enclos policy
allow claw HOST`. An agent cannot grant itself network or filesystem access.

For a native dashboard handoff, run `enclos connect claw -- openclaw dashboard
--json` and use its native `browserUrl` locally. This is privileged, short-lived
material; keep it out of logs and issue reports. enclos does not manufacture an
unauthenticated dashboard URL.

Removal uses the native owner helper and requires the authenticated managed
Gateway to be ready: `enclos agent rm claw/scout`. If a deletion is unconfirmed,
refresh native discovery with `enclos agent list claw` before retrying; no
destructive request is automatically replayed. `--keep-data` removes only the
enclos record. OpenClaw per-agent archive import through `agent add --from` is
unsupported; native Claws and whole-install backups are not Hermes agent exports.

## Mobile app, from M5-07 onward

The CLI/Telegram adapter in M5-06 does not install the app channel. The following
stacked PRs add it through `runtime configure … --channel app`, using a distinct
granted `MOBILE_APP_TOKEN` per agent and the existing paired-device bridge. See
the [M5 feature matrix and order](m5-openclaw.md#implementation-order).

For this native version, stop the managed Gateway before channel installation or
reconfiguration: its live CLI configuration writer cannot authenticate file
SecretRefs. `runtime configure` can run with the proxy alone. Keep the distinct
per-agent `MOBILE_APP_TOKEN` grants in force, then run:

```bash
enclos --yes sandbox stop claw
enclos runtime configure claw/main --channel app
enclos runtime configure claw/scout --channel app
enclos connect claw -- openclaw health
```

One linked plugin package lives at `~/.enclos-openclaw` in the sandbox; native
accounts have separate sockets, protected credential paths and durable state.
The canonical binder preserves unrelated bindings and rejects another agent's
claim on the exact route. Accounts are enabled only after binding succeeds.

The completed channel stack supplies direct/Home/group conversations, native
events, files/static HTML, titles, exact cancellation and negotiated native
approval scopes through the existing app. It does not expose Gateway admin
credentials or general native RPC to the phone. Native questions retain readable
text and trusted Control UI flows ([richer cards #225](https://github.com/victorbonnet/enclos/issues/225));
the app's native routine inventory is read-only
([mutation follow-up #226](https://github.com/victorbonnet/enclos/issues/226)).
These implemented interfaces still need the end-to-end acceptance recorded by
M5; source/fixture tests and a successful install do not establish every live
model, bot, scheduled-delivery or paired-phone flow.
