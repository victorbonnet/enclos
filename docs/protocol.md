# The mobile app protocol

Status: **proposed, version 1 draft**, with [ADR 0042](adr/0042-a-bridge-on-each-host-serves-the-mobile-app.md) and [ADR 0043](adr/0043-sharing-an-agent-is-not-hosting-it.md). Nothing here is implemented yet, and no part of it is tested. Its words are the glossary's: host, sandbox, agent, runtime, bridge, paired device, person, share, conversation.

The protocol has two legs, one message format:

```
paired device ──WebSocket over the tailnet, Noise inside──► bridge ──Unix socket in the sandbox home──► channel plugin ──► runtime
```

- **The device leg**: the enclos app and the host's bridge. The bridge listens on the host's loopback, reached through `tailscale serve`. Every frame after the handshake is a Noise transport message.
- **The plugin leg**: the bridge and one agent's channel plugin, inside the sandbox. A Unix socket the plugin listens on in the sandbox home, one per agent; JSON lines, no encryption (it never leaves the host).

It describes conversations, people and capabilities, never one runtime's words: a runtime's own features (Hermes's kanban, OpenClaw's nodes) stay out, or come as an optional capability.

## Messages

Every message is one JSON object: UTF-8, at most 1 MiB, with these fields first.

| Field | Type | Meaning |
| --- | --- | --- |
| `v` | integer | The protocol version, `1` |
| `type` | string | What the message is (below) |
| `id` | string | Unique per sender, a UUID; used to acknowledge and to drop duplicates |

Unknown fields are ignored. An unknown `type` is answered with an `error` of code `unknown_type` and otherwise ignored, so a newer peer can send optional messages to an older one. A message the receiver cannot use (not JSON, too big, a field missing or wrong) is answered with an `error` of code `bad_message`, its `of` naming the message's `id` when one could be read, and the receiver goes on reading: one bad message never ends the connection. Two things do: a `v` the receiver does not speak, answered with `version` ([Errors](#errors)), and, on the plugin leg, a line over 1 MiB, which the receiver stops reading at the limit and answers with `bad_message` without `of`, so a sender checks the size of each message before it sends it. On the device leg a frame that does not decrypt ends the connection too (below).

On the plugin leg, one message per line (`\n`, never inside a message). On the device leg, one message per WebSocket binary frame, inside a Noise transport message.

A Noise transport message holds at most 65,535 bytes, its 16-byte tag included, and this protocol defines no fragmentation. So **on the device leg a message is at most 65,519 bytes**, as it is sealed: its JSON and the line break after it. The 1 MiB limit holds on the plugin leg only.

- **An agent's text that does not fit** (`message.out`, or a cron job's output) is split by the bridge, at character boundaries, into several `message`s of the same conversation, each with the next `seq` and stored as it is sent. A device sees them in order, as consecutive messages from the agent; the plugin and the runtime see one message.
- **A person's text is one message:** the app refuses, before sealing, a `message.send` whose text would not fit as a `message` (its echo, with the conversation's other fields), and keeps the person's text; `enclos-protocol`'s `split_text` giving one piece is the test. The bridge answers one that gets through with `bad_message` and stores nothing, and closes a connection whose frame does not decrypt, so a larger one ends it.

### Names

Every id and name a message carries (`id`, `of`, `conversation`, `person`, and a plugin `hello`'s `runtime` and `agent`) is not empty, at most 128 bytes, and holds no control character; an `error`'s `message` holds no control character either. A message that breaks this is a bad message. The host prints some of them, so text from the sandbox can neither move a terminal's cursor nor break a log's line.

- **An agent** is `<sandbox>/<agent>` on one host, as enclos names it. The app adds the host it reached.
- **A conversation** is a UUID the app makes. The plugin gives it to the runtime as the chat's id, so a new conversation is a new chat for the runtime, and a cron job created in it remembers it as its origin.
- **A person** is a tailnet login, as Tailscale's WhoIs gives it (`alice@example.com`). In version 1 the only person is the host's user; the field is there from the start so sharing (ADR 0043) changes no stored history.

## The plugin leg

The plugin listens; the bridge connects. Several bridges never connect at once: the plugin refuses a second connection while one is open. The plugin has 10 s to answer the bridge's `hello`, and 10 s to read what the bridge writes; past either, the bridge ends that connection and opens a new one on its next try, and other agents' plugins do not wait for it.

1. **`hello`, bridge to plugin, first:** `{"v":1,"type":"hello","id":…,"token":"…"}`. The token is the agent's, a secret granted to that agent ([ADR 0036](adr/0036-an-agent-has-its-own-bot.md)). The plugin compares it in constant time and closes the socket, saying nothing, on any other first message or token.

   **What the token proves, and what it does not.** It keeps the host's other programs, and other sandboxes, off the agent's socket, and nothing more. The token is in the sandbox, where the agent and anything it runs can read it, as they can every secret of the agent's (ADR 0036), and the socket is in the sandbox home. So a program in the sandbox can connect to its own plugin while the bridge is not connected and send it any message the bridge sends, and a program that listens on the socket's path gets the token from the bridge. Hence the rule: **no message from the bridge to the plugin carries authority the agent must not have.** A message the plugin passes on is what a person said, never a decision the runtime then trusts more than the agent's own words; a decision that must come from the person needs its own proof, which version 1 does not define.
2. **`hello`, plugin to bridge:** `{"v":1,"type":"hello","id":…,"runtime":"hermes","agent":"main","capabilities":[…]}`.
3. Then, in either direction:

| `type` | From | Fields | Meaning |
| --- | --- | --- | --- |
| `message.in` | bridge | `conversation`, `person`, `text`, `attachments`? (reserved; version 1 defines none, and a receiver ignores it) | A person's message to the agent |
| `message.out` | plugin | `conversation`, `text`, `kind` (`reply` or `notify`), `reply_to`? | What the agent says: a reply, or `notify` for one nobody asked for now (a cron job, background work) |
| `typing` | plugin | `conversation`, `on` (boolean) | The agent is working on an answer |
| `ack` | either | `of` (the acknowledged `id`) | Received and stored |
| `error` | either | `of`?, `code`, `message` | See [Errors](#errors) |

**What the agent says is markdown.** The `text` of a `message.out` is CommonMark with GitHub's tables, strikethrough and bare links; a device draws it, and fetches and runs nothing in it: an image shows as its alt text, a link to it, and is never loaded; HTML shows as its text; and only `http`, `https` and `mailto` links open (the app's [ADR 0002](https://github.com/victorbonnet/enclos-app/blob/main/docs/adr/0002-messages-are-markdown-drawn-by-the-app.md), proposed). A plugin tells its runtime so (Hermes: the platform's `platform_hint`), so that the agent formats when it helps. What a person sends (`message.in`) is plain text, shown as typed.

**Delivery is at least once.** The plugin keeps each `message.out` on disk, in the sandbox home, until the bridge's `ack` for it, and sends what it kept again after each `hello`. The bridge drops an `id` it has already stored. The bridge acknowledges a `message.in` it sent only once it has stored it; the plugin acknowledges it once the runtime has it.

## The device leg

### Pairing

`enclos app pair` prints a QR code holding:

```
enclos://pair?v=1&host=<host name>&url=https://<host>.<tailnet>.ts.net&key=<bridge static key>&code=<one-time secret>&exp=<unix time>
```

- `key`: the bridge's static X25519 public key, base64url, which the app pins.
- `code`: 128 random bits, base64url, single use, valid until `exp` (5 minutes).

The app makes its **device key**, a P-256 key in the phone's hardware (Android Keystore, StrongBox where the phone has it; Secure Enclave on iOS, which holds only P-256), and its own static X25519 key, kept encrypted under a hardware key. It runs the Noise handshake below as a device the bridge does not know yet, then sends, instead of `auth`:

| `type` | From | Fields |
| --- | --- | --- |
| `auth` | device | `device`, `sig` (base64url DER signature of `enclos auth v1` ‖ the handshake hash) |
| `authenticated` | bridge | `person` |
| `pair.request` | device | `name` (the device's model), `device_key` (P-256 public key, SEC1, base64url), `proof` (HMAC-SHA256 of `enclos pair proof v1` ‖ the handshake hash, keyed with `code`), `sig` (base64url DER signature, by `device_key`, of `enclos pair v1` ‖ the handshake hash), `push` (`{"kind":"fcm","token":…}`)? |
| `pair.accepted` | bridge | `device` (its id on this host), `push_key` (32 bytes, base64url) |
| `pair.refused` | bridge | `reason`: `expired`, `used`, `bad_proof`, `bad_signature`, `declined` |

The bridge checks `proof`, and `sig` with `device_key`, so the device holds the key it asks to pair; then it shows at the terminal the device's name, its tailnet person and node (WhoIs), and asks to confirm. Only then does it store the device: both public keys, the person, the node, `push_key`, and writes an audit entry. A code works once, whatever the answer. The device chose its `name`, so the bridge keeps it plain before the terminal shows it: without the characters `enclos-protocol`'s `visible` rule calls hidden (controls, bidirectional and invisible marks), white space made single spaces, at most 64 characters. While the person decides, the device's pings count as hearing from it.

### Handshake

`Noise_IK_25519_ChaChaPoly_SHA256`, the device as initiator, the bridge's static key known from pairing, with the prologue `enclos/device/1` on both sides, so a handshake of another version never yields this one's hash; the handshake messages carry no payload, and one that does is refused. The device's first message once it is done is `auth` (or `pair.request` while pairing): its id on this host and an ECDSA P-256 signature, by the device key, DER as the phone's keystore gives it, of a fixed label and the **handshake hash**, which binds it to this session's ephemeral keys. The bridge then:

1. knows the device by its static key, or refuses it (unless pairing);
2. checks `sig` with the device key it stored, and answers `authenticated` with the person the device speaks for;
3. asks Tailscale who is calling, and refuses a person or a node other than the device's own;
4. writes each refusal, with its reason, in the bridge's log (`enclos app log`).

Any login of the tailnet gets as far as the first message, so the bridge keeps callers that are not authenticated yet few and short: at most 16 at once (one more is closed at once), 30 s from connecting to its first message, and no WebSocket message or frame larger than one Noise message (65,535 bytes). It logs at most 10 refusals per caller address and minute; past them, that address's connections are closed that minute without a log line or a question to Tailscale. The log keeps its newest 10,000 lines. Once authenticated, a session with nothing from the device, not even a ping, for 75 s ends: the enclos app pings every 30 s. When a device connects again while its old connection is still open, the new connection is the one messages go to.

The hardware key signs two things only, each a fixed label then the handshake hash: `enclos auth v1` for `auth`, `enclos pair v1` for `pair.request`. A signature for one is never one for the other, nor for anything outside this protocol.

### Messages after the handshake

| `type` | From | Fields | Meaning |
| --- | --- | --- | --- |
| `agents` | device | (none) | List what this person may reach |
| `agents.list` | bridge | `agents`: `[{"agent":"lab/main","runtime":"hermes","capabilities":[…],"abilities":["read","chat"]}]` | The list, filtered to what is shared with the person |
| `conversation.new` | device | `conversation`, `agent` | Start one; its owner is the device's person |
| `message.send` | device | `conversation`, `text` | A message to the conversation's agent |
| `message` | bridge | `conversation`, `agent`, `from` (`agent` or the person), `text`, `kind`, `time` (seconds since the Unix epoch, when the bridge stored it), `seq` | A message of a conversation, sent and received alike, in order |
| `typing` | bridge | `conversation`, `on` | As on the plugin leg |
| `sync` | device | `since` (a `seq`, or 0) | Every `message` of the person's conversations after `since`, then `synced` |
| `synced` | bridge | `seq` | The newest `seq` sent |
| `status` | device | (none) | The person's devices and, for the host's user, every person's access and devices; read only |
| `status.report` | bridge | as `enclos app status --json` | |
| `push.token` | device | `kind`, `token` | A new push token for this device |
| `ack`, `error` | either | as on the plugin leg | |

`seq` is the bridge's, increasing per host, so one number lets a device catch up after being away.

### Notifications

Not built yet: the bridge sends no push. `enclos-protocol`'s `preview` seals and opens a preview as below; nothing in the bridge calls it, and no FCM client exists.

When a `message` arrives for a conversation whose owner has no device connected, the bridge sends a push to each of the owner's devices through FCM: a high-priority data message whose payload is

```json
{"v":1,"host":"<host name>","seq":1234,"preview":"<base64url: nonce ‖ ciphertext>"}
```

`preview` is XChaCha20-Poly1305 under the device's `push_key`, over `{"agent":"lab/main","conversation":…,"text":"<at most 120 characters>"}`, padded to 2,048 bytes (the byte `0x80`, then zeros) so its length does not tell the text's. Its associated data are `v`, `host` and `seq`, so a preview opens only with the ones it was sealed with: one kept by the push service cannot come back under another `seq`. The app drops a `seq` it has already shown. Google sees the host's name, a number and ciphertext of one size. The app decrypts it, shows the notification, and fetches the message with `sync` over the tailnet when it can.

## Capabilities

A plugin's `hello` and each agent of `agents.list` name what the runtime does, and the app shows only that:

| Capability | Meaning |
| --- | --- |
| `notify` | The runtime may send on its own (`kind: notify`): cron output, background work. Without it, the agent only answers |
| `typing` | It reports working on an answer |
| `stream` | It sends a reply in parts, batched (never one message per word); version 1 defines no parts message yet |
| `attachments` | It takes and sends files; version 1 defines none yet |
| `approval` | It asks before running something; reserved, no messages in version 1 |
| `abort` | It can stop an answer; reserved, no messages in version 1 |

Hermes and OpenClaw are meant to have `notify` and `typing`. A runtime reached through `enclos exec` (Claude Code, Codex) has none, and the bridge sends a `message` of `kind: notify` when its turn ends.

## Errors

`{"v":1,"type":"error","id":…,"of":"<id or absent>","code":"…","message":"<for people, may be shown>"}`

| Code | Meaning |
| --- | --- |
| `unknown_type` | The receiver does not know this `type` |
| `bad_message` | Not JSON, too big, or a required field is missing |
| `version` | `v` is one the receiver does not speak; it answers this, then closes the connection |
| `not_allowed` | The person may not do this (no share, or not that ability) |
| `unknown_agent`, `unknown_conversation` | No such agent or conversation for this person |
| `agent_unavailable` | The plugin is not reachable (sandbox stopped, plugin not connected); the message is kept and sent when it is |

## Versions

`v` is the protocol's version, not enclos's or the app's. A change that an older peer would misread raises it; adding an optional field, `type` or capability does not. A bridge speaks its version and the one before it for at least one release, and a device that receives `error` of code `version` tells the person to update the app.
