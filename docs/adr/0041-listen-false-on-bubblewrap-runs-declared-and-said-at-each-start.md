---
status: accepted
---

# `listen = false` on bubblewrap runs declared, and said at each start

Amends [0009](0009-refuse-what-cannot-be-enforced.md) for one field, and settles what [0040](0040-on-linux-enclos-dashboard-opens-a-sandboxs-service-to-its-user.md) left open on `listen = false`.

0009 refuses a policy field the backend enforces only partly unless the user accepts it, so it would ask that acceptance of `listen = false` on Linux. Nothing in a bubblewrap session refuses `bind` or `listen`: seccomp cannot read `bind`'s address, and refusing `listen()` outright would stop Unix sockets too. Every template leaves `listen` false, so an acceptance would be asked of every bubblewrap sandbox, for a control that holds little while each session has a network namespace of its own: a listener there is reached by nothing outside that session.

Decision: on bubblewrap, `listen = false` is declared not held, and no acceptance is asked. The compiled file lists it in `unenforced`, `doctor`'s capabilities say so, and each session's start prints one line saying it is not held on bubblewrap. Seatbelt holds the field, and nothing changes there. Milestone 3's M3-16, which has a sandbox's sessions share one namespace ([0039](0039-a-bubblewrap-sandbox-has-one-network-namespace-its-sessions-join.md)), adds Landlock's TCP bind right (ABI 4), so that the field holds where the kernel has it and stays declared below ABI 4 or without Landlock.

Reason: an acceptance every sandbox needs tells the user nothing a line at each start does not, and the gap matters only once a listener is reachable from another session, which is when M3-16 closes it where the kernel can.
