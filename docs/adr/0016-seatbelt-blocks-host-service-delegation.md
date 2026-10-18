---
status: accepted
---

# Seatbelt blocks delegation to host services, proven by escape probes

A sandboxed macOS process can ask a host service to do something for it, and the service acts outside the sandbox: LaunchServices (`open`) launches apps and opens URLs, Apple Events (`osascript`) can tell Terminal to run a command, and launchd can be asked to run a job. Whatever baseline the compiled Seatbelt policy uses ([0006](0006-seatbelt-deny-by-default.md) is still open), it must deny these routes, at the Mach service level (`mach-lookup`) and not only by denying the matching executables, because a process can call the services directly.

Every compiled Seatbelt policy is checked by escape probes in `enclos policy test`. Each probe tries one route from inside the sandbox and must fail: opening an app or a URL through LaunchServices, sending an Apple Event to another app, submitting or bootstrapping a launchd job, writing a LaunchAgent, using `at` or `crontab`, connecting to Unix sockets such as the SSH agent or the Docker socket, and reaching the Keychain.

## Consequences

- The exact list of denied services is not known yet. The milestone 2 prototype produces it, together with the probes, and records which routes were tested. Until then the design lists the routes, not a verified rule set.
- Flows that normally open a browser, such as a subscription login, must print the URL or device code for the user to open on the host.
- Passing probes show that the listed routes are closed, not that no route exists. New routes found later become new probes.
- Linux has equivalent routes (the D-Bus session bus, the `systemd --user` manager, host sockets). They are masked by the bubblewrap backend and probed the same way when it is built.
