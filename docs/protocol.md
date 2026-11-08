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

Unknown fields are ignored. An unknown `type` is answered with an `error` of code `unknown_type` and otherwise ignored, so a newer peer can send optional messages to an older one.

On the plugin leg, one message per line (`\n`, never inside a message). On the device leg, one message per WebSocket binary frame, inside a Noise transport message.

### Names

- **An agent** is `<sandbox>/<agent>` on one host, as enclos names it. The app adds the host it reached.
- **A conversation** is a UUID the app makes. The plugin gives it to the runtime as the chat's id, so a new conversation is a new chat for the runtime, and a cron job created in it remembers it as its origin.
- **A person** is a tailnet login, as Tailscale's WhoIs gives it (`alice@example.com`). In version 1 the only person is the host's user; the field is there from the start so sharing (ADR 0043) changes no stored history.

## The plugin leg

The plugin listens; the bridge connects. Several bridges never connect at once: the plugin refuses a second connection while one is open.

1. **`hello`, bridge to plugin, first:** `{"v":1,"type":"hello","id":…,"token":"…","home":"home.lab.main"}`. The token is the agent's, a secret granted to that agent alone ([ADR 0036](adr/0036-an-agent-has-its-own-bot.md)). The plugin compares it in constant time and closes the socket, saying nothing, on any other first message or token. `home`, optional, is the agent's [Home](#home) conversation.
2. **`hello`, plugin to bridge:** `{"v":1,"type":"hello","id":…,"runtime":"hermes","agent":"main","capabilities":[…]}`.
3. Then, in either direction:

| `type` | From | Fields | Meaning |
| --- | --- | --- | --- |
| `message.in` | bridge | `conversation`, `person`, `text`, `attachments`? | A person's message to the agent |
| `message.out` | plugin | `conversation`, `text`, `kind` (`reply`, `notify` or `status`), `reply_to`?, `attachments`? (`[{file, mime, name, size}]`, see [Files](#files)) | What the agent says: a reply, or `notify` for one nobody asked for now (a cron job, background work), which every runtime may send; `status` is the runtime about itself (Hermes's gateway online or shutting down), not the agent |
| `typing` | plugin | `conversation`, `on` (boolean) | The agent is working on an answer |
| `conversation.title` | plugin | `conversation`, `title` (one line, at most 100 characters) | The runtime's short name for the conversation, from what was said in it |
| `conversation.rename` | bridge | `conversation`, `title` (empty: no name) | The person named the conversation, or cleared its name |
| `tool` | plugin | `conversation`, `call` (the runtime's id of the call), `name`, `phase` (`start` or `end`), `label`? (at the start: what it does, one line), `ok`? and `duration_ms`? (at the end) | A tool the agent starts or ends while it works on an answer |
| `commands` | plugin | `commands`: `[{name, description, args?}]` (`name` without its `/`; `args` what follows it, as the runtime writes it: `[name]`, `<prompt>`) | The commands a person may type to the runtime, the whole list: after the `hello`, and again when it changes |
| `ack` | either | `of` (the acknowledged `id`) | Received and stored |
| `error` | either | `of`?, `code`, `message` | See [Errors](#errors) |

**A conversation's name.** The bridge keeps one name per conversation and who gave it. The runtime's (`conversation.title`, for one of its own agent's conversations) replaces the runtime's; the person's (`conversation.rename` from a device) replaces any, and the runtime's no longer replaces it until the person clears it. The bridge passes the person's name on to the plugin, so the runtime can keep it too (Hermes: the session's title, with the user's authority). Hermes names every session on its own and tells no plugin, so its plugin reads the title after each reply, and a little later, and sends it when it changed.

**Home.** Each agent has one Home conversation ([ADR 0044](adr/0044-each-agent-has-a-home-conversation.md), proposed): id `home.<sandbox>.<agent>`, made by the bridge, owned by the host's person (as the transport names the host's own user; else the first person who connects), named Home by them. It is the runtime's home channel: `runtime configure` gives it to the runtime (Hermes: `MOBILE_APP_HOME_CHANNEL`), and the bridge's `hello` names it. A `message.out` for a conversation the bridge does not know, or for another agent's, is stored in this agent's Home. A device may not start a conversation with a Home's id. Hermes's plugin makes Home its gateway's home channel when the bridge says so, answers `/sethome` itself, and sends the gateway's notices about itself as `kind: status`.

**What the agent does while it works.** A `tool` step is passed on live to the devices of the conversation's owner, for a conversation of the plugin's own agent, and not kept: a device that was away does not get it at the next `sync`. Hermes reports its tools to plugin hooks (`pre_tool_call`, `post_tool_call`) with the call's id, its arguments and its outcome; its plugin finds the conversation in the turn's session context, labels the step as Hermes does (`build_tool_preview`), and returns at once, as `pre_tool_call` may also block a tool. A label shows a command or a search as the agent wrote it, to the conversation's owner only.

### Files

An agent sends a file (an image it made, a chart, a document) with a `message.out`. The plugin first copies it into the channel's `media` folder, beside its socket in the sandbox home, under a name of its own, and names it there in `attachments`. Hermes calls its adapter for each file it finds in a reply (a `MEDIA:/path` tag, a bare absolute path); a markdown image whose source is a path to a file in the agent's Hermes home is sent as a file too, out of the text.

The bridge takes a file only by its plain name in that folder, opened without following a link, a regular file of at most 25 MiB; it moves it into its own media folder (beside its database), under an id, and records it with the message. A device gets each message's `attachments` (`id`, `mime`, `name`, `size`) and fetches the bytes with `attachment.get`, over the same Noise session: never from an address, and only for its person's own conversations.

**What the agent says is markdown.** The `text` of a `message.out` is CommonMark with GitHub's tables, strikethrough and bare links; a device draws it, and fetches and runs nothing in it: an image in it shows as a link (a file the agent sends comes as an attachment, [Files](#files)), HTML as its text, and only `http`, `https` and `mailto` links open (the app's [ADR 0002](https://github.com/victorbonnet/enclos-app/blob/main/docs/adr/0002-messages-are-markdown-drawn-by-the-app.md), proposed). A plugin tells its runtime so (Hermes: the platform's `platform_hint`), so that the agent formats when it helps. What a person sends (`message.in`) is plain text, shown as typed.

**Delivery is at least once.** The plugin keeps each `message.out` on disk, in the sandbox home, until the bridge's `ack` for it, and sends what it kept again after each `hello`. The bridge drops an `id` it has already stored. The bridge acknowledges a `message.in` it sent only once it has stored it; the plugin acknowledges it once the runtime has it.

## The device leg

### Pairing

`enclos app pair` prints a QR code holding:

```
enclos://pair?v=1&host=<host name>&url=https://<host>.<tailnet>.ts.net&key=<bridge static key>&code=<one-time secret>&exp=<unix time>
```

- `key`: the bridge's static X25519 public key, base64url, which the app pins.
- `code`: 128 random bits, base64url, single use, valid until `exp` (5 minutes).

It also prints that link, and an https link to open on the phone: `https://<host>.<tailnet>.ts.net/pair#v=1&host=…` (the same parameters, after `#`). A chat or a note opens an https link, not an app's own scheme. The bridge answers `GET /pair` with one static page, the same for everyone, which reads the parameters in the browser, shows the host and the time left, and opens the `enclos://pair` link in the app on a tap. A browser never sends what follows `#`: the code does not reach the bridge, its transport or a log. Every other request is a device's WebSocket.

The app makes its **device key**, a P-256 key in the phone's hardware (Android Keystore, StrongBox where the phone has it; Secure Enclave on iOS, which holds only P-256), and its own static X25519 key, kept encrypted under a hardware key. It runs the Noise handshake below as a device the bridge does not know yet, then sends, instead of `auth`:

| `type` | From | Fields |
| --- | --- | --- |
| `auth` | device | `device`, `sig` (base64url DER signature of the handshake hash) |
| `authenticated` | bridge | `person` |
| `pair.request` | device | `name` (the device's model), `device_key` (P-256 public key, SEC1, base64url), `proof` (HMAC-SHA256 of the handshake hash, keyed with `code`), `push` (`{"kind":"fcm","token":…}`)? |
| `pair.accepted` | bridge | `device` (its id on this host), `push_key` (32 bytes, base64url) |
| `pair.refused` | bridge | `reason`: `expired`, `used`, `bad_proof`, `declined` |

The bridge checks `proof`, then shows at the terminal the device's name, its tailnet person and node (WhoIs), and asks to confirm. Only then does it store the device: both public keys, the person, the node, `push_key`, and writes an audit entry. A code works once, whatever the answer.

### Handshake

`Noise_IK_25519_ChaChaPoly_SHA256`, the device as initiator, the bridge's static key known from pairing; the handshake messages carry no payload. The device's first message once it is done is `auth` (or `pair.request` while pairing): its id on this host and an ECDSA P-256 signature, by the device key, DER as the phone's keystore gives it, of the **handshake hash**, which binds it to this session's ephemeral keys. The bridge then:

1. knows the device by its static key, or refuses it (unless pairing);
2. checks `sig` with the device key it stored, and answers `authenticated` with the person the device speaks for;
3. asks Tailscale who is calling, and refuses a person or a node other than the device's own;
4. writes each refusal, with its reason, in the bridge's log (`enclos app log`).

The hardware key never signs anything but handshake hashes and pairing requests.

### Messages after the handshake

| `type` | From | Fields | Meaning |
| --- | --- | --- | --- |
| `agents` | device | (none) | List what this person may reach |
| `agents.list` | bridge | `agents`: `[{"agent":"lab/main","runtime":"hermes","capabilities":[…],"abilities":["read","chat"]}]` | The list, filtered to what is shared with the person |
| `conversation.new` | device | `conversation`, `agent` | Start one; its owner is the device's person |
| `message.send` | device | `conversation`, `text` | A message to the conversation's agent |
| `conversation.rename` | device | `conversation`, `title` (empty: no name) | Name one of the person's conversations, or clear its name |
| `conversation.read` | device | `conversation`, `seq` | The person read it up to that message, on this device |
| `conversation` | bridge | `conversation`, `agent`, `title`?, `titled_by`? (`agent` or `person`), `read`? (the `seq` of the last message read), `home`? (`true` for the agent's [Home](#home)), `members`? (a [group](#groups)'s agents, `sandbox/agent` each; `agent` is then the sandbox alone) | One of the person's conversations: each at `sync`, before the messages (so one with no message yet is known too), and again when it starts, its name changes or it was read further |
| `message` | bridge | `conversation`, `agent` (in a group, the member who spoke, or the person's message's group), `from` (`agent` or the person), `text`, `kind`, `time` (seconds since the Unix epoch, when the bridge stored it), `seq`, `attachments`? (`[{id, mime, name, size}]`) | A message of a conversation, sent and received alike, in order |
| `attachment.get` | device | `attachment` (its id), `offset` | The bytes of a file of one of the person's messages, from `offset` |
| `attachment.data` | bridge | `attachment`, `offset`, `size` (the file's), `data` (base64url, at most 45,000 bytes) | One part of it: a Noise message holds 64 KiB. A device asks for the next `offset` until it has `size` |
| `typing` | bridge | `conversation`, `on` | As on the plugin leg |
| `tool` | bridge | as on the plugin leg | A tool the agent starts or ends, live; not kept, not synced |
| `commands` | bridge | `agent`, `commands` (as on the plugin leg) | An agent's commands, for the person to pick from as they type `/`: after `agents.list`, one for each agent whose plugin listed them, and again when a plugin lists them anew |
| `sync` | device | `since` (a `seq`, or 0) | Every `conversation` of the person's, then every `message` of them after `since`, then `synced` |
| `synced` | bridge | `seq` | The newest `seq` sent |
| `status` | device | (none) | The person's devices and, for the host's user, every person's access and devices; read only |
| `status.report` | bridge | as `enclos app status --json` | |
| `push.token` | device | `kind`, `token` | A new push token for this device |
| `group.new` | device | `conversation`, `members` (two to six agents of one sandbox, `sandbox/agent` each), `title`? | Start a [group](#groups) with those agents; its owner is the device's person |
| `group.stop` | device | `conversation` | Stop the group's discussion: queued turns are cancelled and a running one stopped; what was said stays |
| `group.state` | bridge | `conversation`, `state` (`working`, `settled`, `bounded`, `stopped` or `failed`), `round`, `max_rounds`, `members`: `[{agent, turn}]` (`turn`: `queued`, `working`, `replied`, `passed`, `failed`, `cancelled`, or none), `reason`? | Where the group's discussion is: at `sync` for each group, and whenever it changes |
| `device.forget` | device | (none) | The person forgot this host on the device: the bridge unpairs the device, as `enclos app unpair` does, sends `ack` and ends the connection. The conversations stay on the host |
| `ack`, `error` | either | as on the plugin leg | |

`seq` is the bridge's, increasing per host, so one number lets a device catch up after being away.

**An agent's commands** are the runtime's, which the bridge passes on without running or checking them: a command is a message like any other, sent with `message.send`. The bridge keeps the last list of each agent while it runs and gives a device each name once (lower case letters, digits, `_` and `-`, at most 32), each description on one line of at most 120 characters and `args` of at most 60, in the plugin's order until they fill 60,000 bytes, so the message fits a Noise message. When a device asks for the agents, the bridge also opens the plugin connections not yet open, so it learns the commands without waiting for a first message.

### Groups

A group is one conversation between a person and two to six agents of **one sandbox** ([ADR 0045](adr/0045-group-conversations-are-the-bridges-among-one-sandboxs-agents.md), proposed): a sandbox is enclos's boundary, and a group across two would carry one's conversation into the other. The bridge keeps its log, in order with every other message, and runs its turns; the device shows them and sends the person's messages (`message.send`), as in any conversation. Each member keeps its own session for the group in its runtime: the bridge gives the plugin the group's id as the conversation, apart from the member's one-to-one conversations, and never copies those into the group.

**Addressing.** A member's handle is its name in the sandbox (`main`, `coder`), matched whatever the case. `@handle` addresses that member, several mentions those members, `@all` and `@everyone` every member, and a message with none every member. In an agent's message, a mention of another member asks it for a follow-up turn.

**Turns.** One at a time per group; groups run side by side. A person's message starts a discussion: its first round is the members it addresses, in the group's order; each next round is the members an agent's message mentioned since and who have not spoken since. For each turn the bridge sends the member a `message.in` whose text gives the group's name, the member's handle and the others', the group's messages the member has not seen, oldest first (at most 24, each with its speaker: `User (<person>):` or `@handle:`), and the rules: reply once if there is something new to add, else reply exactly `(pass)`; mention a member to bring it in; never reveal what was said in a private conversation. A member the person addressed by name, its handle or `@all` ("a response from all"), is told to answer or say what blocks it, not to pass, and a pass from it fails its turn; a message naming no one invites every member, who may pass. The turn ends with the member's `reply` to that message: `(pass)` is stored as no message, anything else as the member's message (and what it sent before the reply, `notify` in the meantime, as its messages too). A turn with no reply after 15 minutes fails. The discussion ends **settled** when a round brings no new message, or **bounded** after 3 rounds or 10 agent messages; a new message of the person's waits behind the running turn, then starts a new discussion, and the turns queued for the old one are cancelled.

**What lasts.** Messages, turns and each member's position (the last message of the group it has been given) are in the bridge's database; turns have ids made from the group, the person's message, the round and the member, so a retry does not run one twice. A turn running when the bridge stops is failed when it starts again, unless the member's reply comes (a plugin sends again what was not acknowledged), and the discussion goes on from there. `group.stop` cancels what is queued, and a running turn is sent `/stop` (Hermes interrupts it); its reply, if it comes, is dropped. `group.state` says where the discussion is, to every device of the owner, at `sync` and whenever it changes.

**How far a conversation was read** is the bridge's too, not the runtime's: the agent does not see what the person reads in the app. A device sends `conversation.read` when the person opens the conversation or reads a message arriving in it; the bridge keeps the highest `seq`, from the conversation's owner only and never past its newest message, and sends the `conversation` again to all of the person's devices. A device that syncs, a new one or one that was away, so counts as unread only the agent's messages after `read`.

### Notifications

When a `message` arrives for a conversation whose owner has no device connected, the bridge sends a push to each of the owner's devices through FCM: a high-priority data message whose payload is

```json
{"v":1,"host":"<host name>","seq":1234,"preview":"<base64url: nonce ‖ ciphertext>"}
```

`preview` is XChaCha20-Poly1305 under the device's `push_key`, over `{"agent":"lab/main","conversation":…,"text":"<at most 120 characters>"}`. Google sees the host's name, a number and ciphertext. The app decrypts it, shows the notification, and fetches the message with `sync` over the tailnet when it can.

## Capabilities

A plugin's `hello` and each agent of `agents.list` name what the runtime does, and the app shows only that. Sending on its own (`kind: notify`) is not a capability: every runtime may, and a device shows such a message whichever runtime sent it. Version 1 first listed it as `notify`; a plugin that still announces it is read as announcing nothing more.

| Capability | Meaning |
| --- | --- |
| `typing` | It reports working on an answer |
| `stream` | It sends a reply in parts, batched (never one message per word); version 1 defines no parts message yet |
| `attachments` | It takes and sends files; version 1 defines none yet |
| `approval` | It asks before running something; reserved, no messages in version 1 |
| `abort` | It can stop an answer; reserved, no messages in version 1 |
| `titles` | It names conversations (`conversation.title`) and keeps the person's names |
| `tools` | It reports the tools it runs while it works (`tool`) |
| `commands` | It lists the commands a person may type to it (`commands`) |

Hermes and OpenClaw are meant to have `typing`; the Hermes plugin also has `titles` and `tools`, and `commands` when it can read the gateway's: Hermes's own that are not for its terminal only and those its plugins register, as its Telegram and Slack menus list them, without `/sethome` (which the plugin answers), `/start` and `/topic` (Telegram's). A runtime reached through `enclos exec` (Claude Code, Codex) has none, and the bridge sends a `message` of `kind: notify` when its turn ends.

## Errors

`{"v":1,"type":"error","id":…,"of":"<id or absent>","code":"…","message":"<for people, may be shown>"}`

| Code | Meaning |
| --- | --- |
| `unknown_type` | The receiver does not know this `type` |
| `bad_message` | Not JSON, too big, or a required field is missing |
| `version` | `v` is one the receiver does not speak; it then closes |
| `not_allowed` | The person may not do this (no share, or not that ability) |
| `unknown_agent`, `unknown_conversation` | No such agent or conversation for this person |
| `agent_unavailable` | The plugin is not reachable (sandbox stopped, plugin not connected); the message is kept and sent when it is |

## Versions

`v` is the protocol's version, not enclos's or the app's. A change that an older peer would misread raises it; adding an optional field, `type` or capability does not. A bridge speaks its version and the one before it for at least one release, and a device that receives `error` of code `version` tells the person to update the app.
