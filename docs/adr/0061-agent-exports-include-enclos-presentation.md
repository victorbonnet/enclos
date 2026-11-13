---
status: proposed
---

# Agent exports include Enclos presentation

Moving an agent between hosts or sandboxes through only its runtime's export loses the display name and image, which belong to Enclos's bridge. This amends [0026](0026-agents-imported-through-the-runtimes-own-export.md): Enclos may wrap that runtime export with versioned, bounded presentation metadata. The runtime adapter still owns both runtime commands and the payload's format; the host streams the payload without extracting it. OpenClaw and later runtimes use the same outer format through their adapters, without core code knowing their layouts.

`agent export` produces one portable file; `agent import` restores its runtime data and presentation under the destination identifier. The source stays in place, including for moves to another sandbox of the same host. Destination policies, secret grants, runtime logins and paired devices are not copied by Enclos. Raw runtime imports through `agent add --from` remain supported. An explicit metadata-only import can repair presentation on an agent already moved. Revisions are local to the destination, so imported images and names invalidate its existing caches.
