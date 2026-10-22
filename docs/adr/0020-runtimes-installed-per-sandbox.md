---
status: accepted
---

# Milestone 1 installs each runtime inside its sandbox's home

ADR 0015 planned one shared runtime under `runtimes/`, read-only to every sandbox. Hermes does not fit that yet: its installer puts its code, its own Python and Node, and its browser tools inside the Hermes home, and Hermes updates itself there. In milestone 1 each sandbox therefore gets its own install, made by the runtime's own installer running inside the sandbox, under its compiled policy and through its proxy. enclos downloads the installer on the host and runs it only if its SHA-256 is the one reviewed; a changed installer is refused until enclos is updated. (Superseded by [0029](0029-runtime-installers-run-as-served.md): the installer runs as the runtime serves it, and the audit entry names its SHA-256.)

## Consequences

- In the prototype, an install took about 2.4 GB per sandbox (Hermes 0.22.2 with its browser tools) and several minutes. The installer script was pinned until [0029](0029-runtime-installers-run-as-served.md); the Hermes version it installs never was: it is whatever the stable channel serves at install time.
- Agents can modify their runtime's installation, since it lives in the writable home. That is within the threat model ([0014](0014-threat-model-accidental-damage.md)): it can damage only its own sandbox.
- The adapter's endpoints include the installer's download hosts (GitHub, PyPI, npm, nodejs.org, the browser downloads). Some are broad, and allowing them grants what they serve.
- The runtime is recorded as installed only once its installer exits 0. A failed install leaves the record as before, and the policy is resolved again from `policy.toml` with the runtime it records: a failed first install leaves no runtime and takes the adapter's destinations out of the policy again; a failed reinstall keeps the runtime recorded and its destinations in the policy. Edits to `policy.toml` the install applied stay applied, and files written in the home stay.
- A shared, read-only runtime stays the goal (ADR 0015) for when a runtime can run from one.
