# Export and import agents

An Enclos export carries the agent's runtime data, runtime-held logins, Enclos-granted credentials, display name, image and direct mobile-app conversation history, including attachments and historical questions and approvals. The runtime adapter owns its data format; shared engine code streams opaque bytes and never extracts the runtime archive on the host.

```sh
enclos agent export old/comptoir-dev --to gege.enclos
# Stop the source before activating another copy of its bots or scheduled work.
enclos sandbox stop old
enclos agent import new/comptoir-dev --from gege.enclos
```

Exports contain credentials in plaintext. They are created with mode `0600`, published only after writing completes, and must be kept private. Values never appear in CLI results, dry-run plans or audit entries. An export briefly pauses the source sandbox's runtime services to copy its data, then resumes those previously installed, including when export fails. Interactive writers should be stopped separately; a detected file change refuses the export.

Import works between hosts and between sandboxes on one host. The destination must have the same runtime installed and the destination agent name must be fresh. An exported Hermes built-in agent can be restored under a fresh named agent; an existing built-in agent is not overwritten. Neither operation deletes the source. A host receiving app history must already be paired: the destination's host person owns the imported conversations, without transferring any source person's access.

Enclos restores granted credentials under newly allocated destination secret names and gives their environment bindings only to the imported agent. It retains the destination's network, filesystem, resource and other agents' policy. The source policy is carried as reference information, not applied as authority. Runtime settings and app-channel sockets are regenerated for the destination. The app-channel token is rotated and the destination's signing key is retained.

App conversations, messages, questions and attachments receive new destination identifiers and message sequences. The runtime adapter receives the conversation mapping so it can rebase its session routing. Existing destination history and phone caches stay valid. Pending questions become expired history, answered questions are confirmed as history, and policy requests become closed and unavailable; no pending delivery or execution grant is replayed. Source conversation titles, timestamps, archived state and read positions are preserved.

A running destination runtime is paused for import and resumes only after runtime data, credentials, history and presentation succeed. A failed import can leave a partially imported agent; its runtime stays stopped and the error says to inspect it before restarting. Export files and the source remain available for recovery. `--dry-run` validates checksums, metadata, destination availability and history ownership without importing anything.

To restore only presentation on an agent already migrated:

```sh
enclos agent import new/comptoir-dev --from gege.enclos --metadata-only
```

## What belongs to the host

An agent export is not a whole-host backup. Device pairings, private bridge/signing keys, host access grants, shared group conversations and other agents' histories remain with their host. Files outside the sandbox home and external services are dependencies to migrate or grant separately. Credentials that were never granted to the exported agent are not collected from Enclos's secret store.

Hermes exports preserve raw profile files, memories, skills, plugin source, runtime sessions and databases, including committed SQLite WAL data. Shared runtime logins, plugins and skills are made available in the imported profile without replacing the destination's global runtime login. Shared user files from the sandbox home are included; conflicting destination files are refused rather than overwritten. Rebuilt installations, caches, virtual environments, dependency downloads, shell startup files, older runtime backup folders and live process/socket state are omitted. Foreign executable bytes are retained outside the imported agent's executable paths and may need a native replacement. Expired or revoked provider logins still require signing in again.

## Format, version 2

The framing remains the ASCII prefix `ENCLOS_AGENT_EXPORT_V1\n`, a four-byte big-endian header length and UTF-8 JSON of that length. The header is at most 64 KiB. Its `schema_version` is `2`, and it contains:

- `runtime`, `source_agent` and `presentation` (nullable normalized display name and base64url JPEG/PNG).
- `runtime_format`: an opaque adapter-owned format identifier, such as `hermes-data-v1`.
- `state`: the byte length and SHA-256 of the following Enclos JSON data section.
- `payload_bytes` and `payload_sha256`: the length and SHA-256 of the opaque runtime payload after that section.

The Enclos section contains credential bindings, logical app history and attachments, and source policy context. It is bounded at 256 MiB; each app attachment is at most 25 MiB. An export exceeding a bound fails explicitly and does not publish a partial file. Runtime payloads are streamed independently of this bound. Unsupported versions/formats, unknown fields, invalid names/images, invalid cross-references, truncation, checksum mismatches and trailing bytes are refused before restoring data. Checksums detect corruption; they do not authenticate an export's author.

Version 1 presentation-only exports remain readable. They do not acquire credentials or app history that were absent when written. Raw runtime imports through `agent add --from` retain the runtime's own export/import behavior, including any runtime redaction.
