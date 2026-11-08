---
status: proposed
---

# Artefacts are static HTML attachments

An agent can make a page that is easier to read as a document than as a message. The mobile app already receives files through its conversation's authenticated connection; publishing a page or exposing a sandbox's HTTP listener would give the same content another delivery and access path.

Decision (proposed): an **artefact** is a self-contained UTF-8 HTML file, sent through the existing attachment path (`MEDIA:/absolute/path/page.html` in Hermes). The app opens it separately from the conversation, in an offline viewer with Back, its name and Share. Its rendering contract is HTML, inline CSS and embedded data images or fonts. JavaScript, network requests, filesystem and content access, forms, outgoing navigation and native bridges are unavailable. HTML inside message text stays literal. The runtime's channel hint names this capability and its limits.

Reason: attachments keep the bridge's existing ownership checks, storage and delivery, while the separate viewer gives a page its own layout without making conversation text executable. There is no new protocol message, capability flag, page service or artefact database. Interactive pages, external assets and multi-file sites need a later decision. The app records its rendering choice in [its ADR 0005](https://github.com/victorbonnet/enclos-app/blob/codex/mobile-artefact-viewer/docs/adr/0005-static-html-artefacts-open-in-a-separate-viewer.md); platform probes must show the restrictions before they are described as verified.
