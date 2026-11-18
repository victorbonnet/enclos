---
status: proposed
---

# Agent exports carry complete agent-owned data

A runtime-only export lost Enclos presentation, credentials and app history during a real host migration; Hermes's own redaction also changed plugin source and omitted logins. This amends [0026](0026-agents-imported-through-the-runtimes-own-export.md): `agent export` carries adapter-owned runtime data together with agent-owned Enclos state in one private, versioned file. Shared engine code streams an opaque runtime payload; an adapter owns exporting and restoring complete runtime data, including runtime-held logins and consistent databases. Later runtimes, including OpenClaw, use the same outer format without runtime paths in the engine.

This also proposes a narrow exception to [0022](0022-secrets-granted-per-sandbox.md): an explicit export copies the values actually granted to that agent into the private export, never into logs or command results. Import allocates new secret names and restores only that agent's bindings, retaining destination host policy. The app-channel token is rotated and bridge keys and device pairings stay local. The file is unencrypted, mode `0600`, with atomic publication; users must keep it private.

Import can rename the agent or move it into another sandbox of the same host. Logical app histories receive local identifiers and sequences and belong to the destination host person; adapters receive the conversation mapping for runtime session routing. Questions and approvals are restored only as history, never as executable pending decisions. Shared group conversations, host access grants and external workspaces are host-owned, outside the agent export. Runtime installations, caches and live process state are rebuilt rather than transferred. Raw runtime imports and version 1 presentation exports remain supported.
