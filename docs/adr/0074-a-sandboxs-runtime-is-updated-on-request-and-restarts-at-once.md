---
status: proposed
---

# A sandbox's runtime is updated on request, and its service restarts at once

Amends [0064](0064-the-hosts-person-can-provision-sandboxes-from-a-paired-phone.md), which keeps service startup a host operation, and departs from [0031](0031-a-service-restarts-when-its-runtime-settings-change.md)'s wait for running work, for this one action.

enclos installs a sandbox's runtime once, with the installer as served ([0029](0029-runtime-installers-run-as-served.md)), and never looks at it again. Runtimes release often (OpenClaw several times a week, Hermes a stable release every few days), and enclos follows their latest releases, so a sandbox drifts behind without its person noticing (#335).

**Seeing it.** For each sandbox, `enclos status` and the app show the runtime's installed version, its latest release, and whether this enclos release was checked with that release.

- The installed version is the runtime's own: Hermes's install stamp (`hermes-agent/install-stamp.json`, `baseVersion`), which Hermes reads for its own version, read live as other home files are ([0023](0023-agents-made-inside-a-sandbox.md)); for OpenClaw, whose package path names the Node version it runs on, the answer of `openclaw --version`, asked in the sandbox after each install and update and recorded with the sandbox.
- The latest release is the one the runtime's installer installs by default: Hermes's latest GitHub release, OpenClaw's npm `latest`. enclos looks it up on the host, over HTTPS, and keeps the answer for a few hours, so `status` reaches the network at most that often. A lookup that fails is "cannot tell", never "up to date".
- "Checked with this enclos" means the release is in a list built into the enclos binary: the runtime versions enclos's runtime tests passed with before that enclos release. A release enclos was not checked with is still offered, marked "not checked yet": enclos adapts to the runtime ([0029](0029-runtime-installers-run-as-served.md)), and the person decides.

**Updating.** `enclos runtime update <sandbox>` updates the runtime the runtime's own way: Hermes with `hermes update`, since its installer leaves an existing checkout to it, and OpenClaw by running its installer again as served, which installs npm's `latest` into the same prefix (or the `OPENCLAW_VERSION` the sandbox's policy passes), then `openclaw doctor --fix --non-interactive`, which migrates its agents' databases: without it, an upgraded gateway failed on the old schema (2026.11.3 to 2026.11.5, on a Linux host, 2026-11-19). It stops the sandbox's services first, runs the updater as a session under the active policy, records the version the runtime then reports, and starts the services again. It does not wait for running turns or tasks, as a settings restart does: the person asked for the update and was told what it interrupts, and running work may never end. A failed update is reported with the updater's log; the previous version stays recorded, and the services start again on what the updater left. There is no rollback, and no automatic update.

**From the phone.** The host's person can update a runtime from a paired device, as they provision ([0064](0064-the-hosts-person-can-provision-sandboxes-from-a-paired-phone.md)): the bridge runs `enclos runtime update` in a separate process with no terminal input, under a time limit, and states what it interrupts before the person confirms. The audit log records the sandbox, the versions before and after, and the person and device.

## Considered options

- **A list of checked releases enclos publishes**, updated when a new runtime release passes its checks: it would mark more releases as checked between enclos releases, but it is a service to run and trust. A list built into the binary can be replaced by one later.
- **Running Hermes's installer again:** on an existing checkout it keeps the checkout and leaves the move to `hermes update`.
- **Waiting for running work, as a settings restart does:** an update could wait for good, and the person would not know when it happens.
