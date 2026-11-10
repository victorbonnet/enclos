---
status: accepted
---

# Landlock's TCP bind right is not built; `listen = false` stays declared on bubblewrap

Supersedes the last sentence of [0041](0041-listen-false-on-bubblewrap-runs-declared-and-said-at-each-start.md)'s decision.

0041 planned that milestone 3's M3-16, which has a sandbox's sessions share one network namespace ([0039](0039-a-bubblewrap-sandbox-has-one-network-namespace-its-sessions-join.md)), would add Landlock's TCP bind right (ABI 4, `LANDLOCK_ACCESS_NET_BIND_TCP`), so that `listen = false` would hold where the kernel has it. M3-16 shipped the shared namespace without it: the Landlock rules handle ABI 6's filesystem rights and scopes and no network right, and [0040](0040-on-linux-enclos-dashboard-opens-a-sandboxs-service-to-its-user.md) still has bind and listen open in the namespace. So a listener in one session is reached by the sandbox's other sessions, and nothing refuses it.

Decision: on bubblewrap, `listen = false` stays declared not held, on every host and kernel, as the rest of 0041 has it: listed in the compiled file's `unenforced`, said by `doctor`'s capabilities and by the line each session's start prints, with no acceptance asked. Landlock's TCP bind right is later work, planned for no milestone yet.

Reason: the owner chose to record what shipped rather than hold milestone 3 for a rule that needs 0040 amended and that no run has shown under bubblewrap. The line at each start already tells the user the field is not held, and it stays true until the right is built.
