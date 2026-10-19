---
status: accepted
---

# Milestone 1 installs each runtime inside its sandbox's home

ADR 0015 planned one shared runtime under `runtimes/`, read-only to every sandbox. Hermes does not fit that yet: its installer puts its code, its own Python and Node, and its browser tools inside the Hermes home, and Hermes updates itself there. In milestone 1 each sandbox therefore gets its own install, made by the runtime's own installer running inside the sandbox, under its compiled policy and through its proxy. enclos downloads the installer on the host and runs it only if its SHA-256 is the one reviewed; a changed installer is refused until enclos is updated.

## Consequences

- An install takes about 2.4 GB per sandbox (Hermes 0.22.2 with its browser tools) and several minutes.
- Agents can modify their runtime's installation, since it lives in the writable home. That is within the threat model ([0014](0014-threat-model-accidental-damage.md)): it can damage only its own sandbox.
- The adapter's endpoints include the installer's download hosts (GitHub, PyPI, npm, nodejs.org, the browser downloads). Some are broad, and allowing them grants what they serve.
- A shared, read-only runtime stays the goal (ADR 0015) for when a runtime can run from one.
