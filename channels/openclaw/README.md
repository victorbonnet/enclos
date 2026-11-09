# OpenClaw enclos channel

One channel package runs inside a sandbox's OpenClaw gateway. Each configured
account belongs to an agent and listens on that agent's Unix socket. The host's
bridge dials in and presents the agent's token; the sandbox gains no outbound
route to the host. Text and unsolicited output are baseline. Typing, native
command discovery, files, exact tool events and sandbox policy requests are negotiated
only when their native adapters/hooks have been registered.

The package is tested against **OpenClaw 2026.11.2**. `PluginRuntime.version` is
checked before activation: an untested version gets an actionable failure. The
SDK is experimental. This does not change enclos's installer-as-served policy.
There are no runtime dependencies besides Node's standard library and the host's
public `openclaw/plugin-sdk/channel-core` entry point.

## Configuration

enclos writes the package and native settings, then enables the channel last:

```json
{
  "plugins": {
    "load": { "paths": ["/sandbox/home/.enclos-openclaw"] },
    "entries": { "enclos": { "enabled": true } }
  },
  "channels": {
    "enclos": {
      "enabled": true,
      "accounts": {
        "main": {
          "enabled": true,
          "agentId": "main",
          "socket": "/sandbox/home/.enclos-app/main/channel.sock",
          "tokenFile": "/protected/sandbox/secrets/main.env",
          "home": "home.lab.main"
        }
      }
    }
  },
  "bindings": [{ "agentId": "main", "match": { "channel": "enclos", "accountId": "main" } }]
}
```

Use the actual paths enclos supplies. The token file is the host-owned protected
**JSON** secret file, despite the legacy `.env` filename. It contains
`MOBILE_APP_TOKEN`; no value is copied into channel settings, argv or persistent
channel state. Reads require a private single-link regular file and reject a
symlink. Token rotation closes a connection using the old value at its next
message. Multiple accounts require explicit account selection; they do not
silently choose an agent.

`stateDir` optionally selects a sandbox-local folder; otherwise it is
`openclaw-state/` beside the socket. The socket and its folder are private.
An occupied socket is probed before stale-socket removal; a live listener or
non-socket is refused. Shutdown removes only the socket created by that account.

## Native dispatch and delivery

The public account lifecycle supplies `channelRuntime`. Inbound uses that exact
runtime's ingress resolver, context builder and dispatcher. An explicit native
account binding must select the configured agent. A stable digest of person and
conversation becomes the peer under `per-account-channel-peer`; distinct direct
conversations and bridge group members never collapse into the native main
session. Home has its own deterministic account/agent/conversation route even
before a person first speaks there. Its first authenticated inbound message binds
the owner without replacing that native session or inventing a human identity
for earlier output. The exact ingress result is passed to the native context builder.
Bridge groups remain direct per-member contexts; OpenClaw's broadcast coordinator
is not enabled for them. Account authority is rechecked after asynchronous
preparation and before dispatch/delivery.

Outbound messages are atomically persisted and synced before a native send
returns. They keep their ids and ordering across reconnect/restart until bridge
acknowledgement. Native scheduled/proactive sends use the same outbound adapter;
`home` selects the bridge-owned Home. The bridge still owns conversation history,
names, photos, read state and archives.

Ingress ids are persisted before native dispatch. Repeated ids with the same
content share active work or acknowledge a completed delivery; reuse with other
content is refused. A crash or error after dispatch begins leaves an uncertain
receipt. It is **not replayed automatically**: the bridge receives
`agent_unavailable`, and the person must refresh before intentionally sending a
new message. The plugin does not claim an atomic transaction with OpenClaw's
native execution. Its acknowledgement follows native dispatcher settlement.
State is bounded: 1,000 unacknowledged replies, 10,000 ingress receipts, 4,096
conversation routes and 16 MiB total. A full registry refuses new work rather
than deleting deduplication evidence. A corrupted state file refuses startup.

Typing follows the native dispatcher and is cleared on settlement/error. The
command catalog comes from the installed public native registry. Tool events
retain native call ids and session attribution and disclose no raw tool arguments;
observation never changes a native guard or result. Absolute `read`/`write`/`edit`
permission failures may request that exact path, while `enclos_request_access`
requests an explicit typed scope through a V2 invocation guard. No shell text is
parsed. Requests grant nothing. Bounded, persisted `policy.context` is added to
matching future native prompts; the bridge retains approval authority.

The native scoped media loader reads permitted local files, preserving native
local-root/reader policy. Remote output URLs are not fetched automatically. Files
are copied into the existing media folder with opaque names before a reply is
queued; HTML is an ordinary `text/html` attachment whose bytes are preserved.
Inbound metadata names only a bounded regular file of that same media folder,
never a path or symlink. There are at most ten files and 25 MiB total per message.
The prompt explains markdown, files and the app's static HTML behavior. The app
continues to own rendering and blocking scripts/network assets in artefacts.

Routines use the public Gateway service's lifecycle-scoped `getCron()` facade.
Only explicitly agent-owned jobs enter its bounded inventory; supported full
definitions are read-only. `options.operations=["get"]` hides creation and
mutation controls. Native unknown fields and external destinations are never
rewritten. Unsupported native schedules or incomplete definitions report
`unsupported`. The public facade does not provide atomic definition
preconditions for changes/removal/manual runs or complete agent-targeted
creation, so all writes are refused before scheduler access. See the
[source evidence](../../docs/research/openclaw-routines.md).
Read-only inventory/details are M5's agreed scope; mutation parity is tracked
in [enclos#226](https://github.com/victorbonnet/enclos/issues/226).

Native question presentations retain the complete public text fallback, including
batches and multiple selections. Credential requests retain their native trusted
Control UI guidance. No structured question capability is advertised; see
[the tested native question boundary](NATIVE_QUESTIONS.md) for the supported
subset and the public APIs needed for richer controls.

Titles/rename, structured questions, runtime approvals and typed
interruption remain separate work. Unsupported controls return `unsupported`.
Structured native
control modules can gate live sends and durable replay with `canDeliver`; the
retained bridge hello excludes its token.

## Validation

```sh
node channels/openclaw/scripts/build.mjs --check
node --test channels/openclaw/tests/*.test.js
ENCLOS_OPENCLAW_PACKAGE=/path/to/installed/openclaw node --test channels/openclaw/tests/native-sdk.test.js
```

The build uses Node's type stripper to emit `index.js` from `index.ts`; the emitted
JavaScript ships with enclos. No TypeScript compiler or upstream development
dependencies are installed. The transport tests use disposable Unix sockets and
fake secrets, and read the Rust/Hermes wire fixtures. Native SDK registration and
session-key checks are optional when the exact installed package is unavailable.
Live gateway/plugin loading, Seatbelt socket reachability and real model/scheduled
output are recorded separately in `prototype/m5/`; source/fixture tests alone do
not establish those behaviors.
