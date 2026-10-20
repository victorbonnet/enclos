---
status: accepted
---

# Seatbelt blocks delegation to host services, proven by escape probes

A sandboxed macOS process can ask a host service to do something for it, and the service acts outside the sandbox: LaunchServices (`open`) launches apps and opens URLs, Apple Events (`osascript`) can tell Terminal to run a command, and launchd can be asked to run a job. Whatever baseline the compiled Seatbelt policy uses ([0006](0006-seatbelt-deny-by-default.md) is still open), it must deny these routes with the operation that actually governs each one (`mach-lookup` for named services, `appleevent-send` for Apple Events, and whatever blocks launchd job submission through the bootstrap port), not only by denying the matching executables, because a process can call the services directly. Other host services act for the caller in the same way: cfprefsd writes preferences outside the sandbox, WindowServer accepts synthetic keyboard and mouse events, ServiceManagement registers login items, and mDNSResponder resolves names, which would let the sandbox leak data through DNS.

Every compiled Seatbelt policy is checked by escape probes in `enclos policy test`. Each probe tries one route from inside the sandbox and must fail: opening an app or a URL through LaunchServices, sending an Apple Event to another app, submitting or bootstrapping a launchd job, writing a LaunchAgent, using `at` or `crontab`, writing preferences through cfprefsd, posting synthetic input events, registering a login item, resolving a name through mDNSResponder, connecting to Unix sockets such as the SSH agent or the Docker socket, and reaching the Keychain.

## Consequences

- The milestone 1 prototype found the operation that governs each route and showed most of them closed (design §5): `lsopen` for LaunchServices, `appleevent-send` for Apple Events, `job-creation` for launchd jobs, `user-preference-write` for cfprefsd, the network rules for host sockets and mDNSResponder, and setuid exec being refused for `at` and `crontab`. Posting synthetic input and registering a login item are not shown yet; those probes run in a disposable macOS VM.
- Signals and the terminal are routes too: under `(allow default)` a sandboxed process can signal every process of the user, and type into its terminal with `TIOCSTI`. The compiled policy allows signals only within the sandbox and denies `TIOCSTI`.
- macOS privacy permissions (TCC) are not a sandbox: a process started from Terminal inherits Terminal's grants. The rules must hold without relying on them.
- Flows that normally open a browser, such as a subscription login, must use a device code: the runtime prints a URL and a code for the user to open on the host.
- A probe's exit code is not always evidence. `open -R` exits 0 inside the sandbox although Finder reveals nothing: a throwaway CI experiment during milestone 1 read Finder's front window from outside to see it, and that workflow is not kept in the repository. So the LaunchServices probe uses `open <folder>`, which reports the refusal, and counts as closed only with the refusal the rule gives (-54). Likewise a failed Apple Event is not proof: a refusal by TCC (-1743) or a timeout waiting on Finder (-1712) means the event left the sandbox, so the probe counts both as open, as the prototype did, and it counts as closed only on Seatbelt's refusal (-600) while Finder runs.
- A failure proves a route closed only when the policy caused it. Each probe has a proof: a harmless control run on the host first (the same read or connection, or a read-only check that the host service is there), or, for the proxy probe, the proxy's 403. Without it a probe is inconclusive, not closed.
- The probes cover part of the routes listed above so far; `enclos policy test` names the ones no probe tries yet, and design §14 lists them.
- Passing probes show that the listed routes are closed, not that no route exists. New routes found later become new probes.
- Linux has equivalent routes (the D-Bus session bus, the `systemd --user` manager, host sockets). They are masked by the bubblewrap backend and probed the same way when it is built.
