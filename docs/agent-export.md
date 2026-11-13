# Export and import agents

Enclos exports include the runtime's own export, the shared display name and the image. The runtime adapter owns its data format; Enclos does not inspect or unpack the runtime archive on the host.

```sh
enclos agent export old/comptoir-dev --to gege.enclos
enclos agent import new/comptoir-dev --from gege.enclos
```

This works between sandboxes of one host and between hosts. The destination sandbox must already have the same runtime installed. You can choose a different destination agent identifier; “Gégé Commit” and its image are preserved. Import refuses an existing runtime agent, and export refuses an existing destination file. Neither deletes the source agent. Start the new agent when ready to switch; scheduled work belongs to each runtime's imported data.

To restore only presentation on an agent already migrated:

```sh
enclos agent import new/comptoir-dev --from gege.enclos --metadata-only
```

`--dry-run` validates the whole import, including the payload checksum, without changing files or state. Enclos does not add credentials, policy grants, device pairings or bridge conversations. What the runtime's export includes or redacts remains that runtime's responsibility. Use `agent add --from` for a raw runtime export without Enclos metadata.

## Format, version 1

The file starts with the ASCII bytes `ENCLOS_AGENT_EXPORT_V1\n`, a four-byte big-endian header length, UTF-8 JSON of that length, then the opaque runtime export. The header is at most 64 KiB and contains:

- `schema_version`: `1`.
- `runtime`: the adapter's runtime identifier.
- `source_agent`: the original `sandbox/agent` identifier; it is provenance, never a path to extract.
- `presentation`: `display_name` and base64url `avatar`, each nullable. Images obey the same size and decoding limits as agent photos in the mobile app.
- `payload_bytes` and `payload_sha256`: exact length and lowercase SHA-256 of the runtime export.

Unsupported versions, unknown fields, invalid names/images, truncation, checksum mismatches and trailing bytes are refused before importing runtime data. The runtime export is staged in Enclos's protected data, then passed through the existing runtime import path so only the sandbox extracts it. Metadata is applied after a successful runtime import; if that last step fails, the error says how to retry with `--metadata-only`. Name and image are restored in one database transaction, with destination revisions rather than source cache revisions.
