---
status: proposed
---

# On Linux, `enclos dashboard` opens a sandbox's dashboard to the user running it

Amends [0028](0028-a-runtime-listens-and-its-sessions-reach-its-service.md) for the bubblewrap backend.

0028's consequences say that the host can reach a runtime's listener: Hermes's dashboard works in the host's browser, and a listener bound to every address serves the host's network. On Linux a sandbox has its own network namespace ([0004](0004-linux-bubblewrap-and-landlock.md), [0039](0039-a-bubblewrap-sandbox-has-one-network-namespace-its-sessions-join.md), proposed), so the host cannot reach a listener there, on 127.0.0.1 or on every address (ECONNREFUSED; `prototype/m3/README.md`). The gateway's own port does not help: through a path to it the page loads, but Hermes withholds the session token there, so `/api/auth/me` gets 401 and `/api/ws` 403. `hermes dashboard` publishes the token in its page, to anyone who connects, and has no auth on loopback, which every user of the host shares.

Decision (proposed), on the bubblewrap backend:

- **`enclos dashboard <sandbox>` is the way in.** It starts `hermes dashboard --no-open --isolated --port 0` as a recorded session under the sandbox's policy, reads the port that session holds from the host, opens a listener on the host's 127.0.0.1 at the sandbox's reserved port, and prints the URL. Each connection goes through a Unix socket in the host-only `run/<sandbox>/` to a relay in the sandbox's network namespace, then to that port.
- **A bubblewrap sandbox's proxy serves its Unix socket alone, with no TCP listener.** Its sessions reach it through that socket and the relay, and none of them can reach the host's loopback, so a TCP listener there would serve no sandbox, only any local program, as an egress proxy logged as the sandbox's. So the sandbox's reserved port stays free for `enclos dashboard`.
- **It serves only the user running it.** The listener reads the owner of each connection's socket and closes any other's before a byte reaches the service. Loopback and the owner check are hard-coded, with no setting. On a remote host the user runs it over ssh with `-L`.
- **It lives as long as the command.** Ctrl-C ends the session and the listener and records the end. Start and end are audited, and a second run on the same sandbox is refused, naming the first.
- **Its server is its own.** A plain `hermes dashboard` reports one another session left open and exits 0, so `--isolated` and `--port 0` keep that session, and any session holding Hermes's default port, from stopping the command.
- **`status` names the command, with no URL.** It says to run `enclos dashboard <sandbox>`, and over ssh with `-L` on a remote host. On macOS it shows the dashboard as before.
- **Listening.** `policy show` and `policy test` say that the sandbox may listen, and that its listeners are reachable from its own sessions and, through `enclos dashboard`, by the user running it. No rule needs to keep the sandbox off enclos's proxy ports: those ports are on the host's loopback, which a sandbox's namespace does not share. `status` naming listeners beyond loopback stays as 0028 has it, since none of them serve the host's network on Linux.

Reason: the network namespace that keeps the sandbox off the host's loopback and network (0004) also keeps the host off the sandbox's listeners, and on this path nothing else looks at who connects, so the check on the owner is what keeps the token from another local user. Milestone 4.1's host-service forward is a different thing, which gives a sandbox a port of the host. The prototype measured the path with Hermes's real dashboard: the page, its assets and WebSockets served to this user, also through `ssh -L`, and a second user refused with no byte and no token, itself and through its own tunnel.

## Considered options

- **The dashboard from inside the sandbox alone:** no path from the host to open, but no browser on the host, which is where the user has one.
- **The gateway's port behind the same listener:** the page loads and does not work.
- **A port of its own for the dashboard** (a second reservation, or port 0 with the URL printed): it leaves the proxy's TCP listener on the host's loopback, which serves no bubblewrap sandbox and lets any local program use the sandbox's proxy.

## Consequences

- 0028's consequence that a listener bound to every address serves the host's network does not hold on Linux, and the host's browser reaches the dashboard only while `enclos dashboard` runs.
- The listener runs inside the command, so nothing but the command opens it, and the service's port it serves comes from the host's reading, never from a file the sandbox writes.
- The Chat tab's terminal is not shown working. On a session's compiled environment it cannot reach its backend until its session has `NO_PROXY` for loopback, and an answer is not shown even then (§14; M3-20).
- `listen = false` is not held in a sandbox's own network namespace; how that is reported is open (§15).
- macOS behaves as 0028 says; this ADR changes nothing there.
