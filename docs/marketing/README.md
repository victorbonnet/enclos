# Enclos marketing and help page

A standalone, responsive page explaining the project's value: one local CLI to manage and see the agents in Enclos-created sandboxes, alongside clear file and network boundaries. It covers the current sandbox behavior and how to try the development build. Open `index.html` directly in a browser, or preview it from the repository root:

```bash
python3 -m http.server 8765 --bind 127.0.0.1 --directory docs/marketing
```

Then visit <http://127.0.0.1:8765>. There is no build step, package installation, external font, analytics, or runtime service dependency. The examples are illustrations; they never contact a sandbox. Native HTML disclosures provide the FAQ. JavaScript enhances the boundary examples and copies only the local installer command, rather than interactive login, conversation, or policy-probe steps.

The install card previews the eventual `curl … | bash` command. The public command is explicitly marked unavailable, and its button is disabled, until the root [install.sh](../../install.sh) is published on `main` and a binary release exists. The default `bash install.sh` always installs the latest published release, even next to a checkout. The working development path before the first release is `bash install.sh --source .`. When the public script and first release are available, verify its raw URL and release assets, remove the pending-publication copy, and enable copying that one-line command. The release asset contract and workflow are documented in [Publishing releases](../releases.md). Do not advertise Linux or Windows installation before those backends ship.

The page builds on the development stack through [PR #30](https://github.com/victorbonnet/enclos/pull/30), with marketing and installer changes on `codex/marketing-release-installer`. Its GitHub documentation links point to that branch for review; update them when it is merged or renamed. Keep current functionality separate from future work, and check claims against:

- [Project overview](../../README.md)
- [Getting started](../getting-started.md)
- [Architecture](../architecture.md)
- [Supported platforms](../adr/0013-supported-platforms.md)
- [Threat model](../adr/0014-threat-model-accidental-damage.md)
- [File access defaults](../../src/policy/templates/defaults.toml)

The page deliberately explains broad host reads, shared access between agents in one sandbox, connection-metadata visibility, and the limits of allowed remote services. The visual mark and enclosure diagram are local SVG/HTML/CSS assets.
