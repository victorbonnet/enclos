# OpenClaw enclos channel

One channel package runs inside a sandbox's OpenClaw gateway. Each configured
account belongs to an agent and listens on that agent's Unix socket. The host's
bridge dials in and presents the agent's token; the sandbox gains no outbound
route to the host. This first implementation advertises baseline text delivery
only. Unsolicited output is baseline, not a capability.

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
session. The exact ingress result is passed to the native context builder.
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

Titles/rename, native command catalog, typing/tool steps, files/HTML, policy
requests, routines, questions, approvals and typed interruption are separate
capabilities to implement and verify. They are not advertised here; an unsupported
control returns `unsupported`. The prompt hint reflects text-only delivery.

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
