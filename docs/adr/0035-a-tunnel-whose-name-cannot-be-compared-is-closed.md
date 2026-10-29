---
status: accepted
---

# A tunnel whose server name cannot be compared is closed

Amends [0007](0007-network-through-a-proxy-per-sandbox.md), which let a TLS tunnel with no visible server name through, and one whose hello carries Encrypted Client Hello (ECH) under another visible name.

Both left the server name check open to any client that wanted out of it. A tunnel opened for an allowed host name with no name in its ClientHello reaches whichever site the validated address serves by default, another tenant of a shared host, and a client could claim ECH, real or not, so that its name was never compared. Neither is needed by the agents enclos runs: their HTTP clients name the server, and none of them sends real ECH.

So the proxy now closes, with nothing to allow: a tunnel opened for a host name whose hello names no server (`no-server-name`); one whose hello carries ECH under a visible name other than its host, or none (`encrypted-hello`); and an SSLv2-format hello, which can name no server (`hello-unreadable`). A hello with ECH and the host's own name (GREASE, as browsers send) is compared like any other, and a tunnel opened for an address, for which a client names no server, goes on with no name. The hello must also be whole within 30 seconds, however its bytes trickle in.

A browser that sends real ECH, or GREASE ECH with no name to an address, is refused; browsers in a sandbox are deferred (design §14), and this is to look at again when one is supported.
