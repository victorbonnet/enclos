# M3-03: the §15 row on network and PID namespaces is not settled

The first `namespaces-prototype` run (PR #114, GitHub's Ubuntu 24.04 runners, x86_64 and arm64, kernel 7.0.0-1017-azure, bubblewrap 0.9.0, AppArmor's user-namespace restriction on) leaves the row open. It also confirms one of the conflicts with ADR 0028 that I said would stop me. So I have written no ADR and decided nothing. Full results: `prototype/m3/README.md`, "M3-03", Results.

## What the run shows

Both runners agree on every row.

1. **No session joined a network namespace enclos made first.** A holder in bubblewrap makes the sandbox's user, PID and network namespaces and hands them out over a socket; that part works. But every way a session tried to join them was refused before its command ran, with Landlock and without:
   - `nsenter` into the holder's user namespace, then its network namespace (three ways): `nsenter: reassociate to namespace 'ns/net' failed: Operation not permitted`.
   - bubblewrap with `--userns` and `--pidns` (two ways): `bwrap: Setting pidns failed: Operation not permitted`. This happens before the network namespace is ever tried.

   What refuses each one, AppArmor's restriction or a missing capability, is not established.
2. **A network namespace per session isolates the sessions, Hermes included.** Another session of the same sandbox reaches neither the service's ports nor its abstract socket, and does not see its process. Hermes's chat in a second session exits with `Error: Gateway connection failed; no local fallback`, as design §14 predicts.
3. **The host cannot reach a listener in a sandbox's network namespace.** From the host, the service's port gets ECONNREFUSED, both on 127.0.0.1 and on `0.0.0.0`. This holds for any design that gives the sandbox its own network namespace (ADR 0004), whichever way the row is decided. It contradicts ADR 0028's consequence that "Hermes's dashboard works in the host's browser", and design §5's "`status` showing the dashboard", on Linux.
4. **Without bubblewrap's AppArmor profile, a user namespace cannot be set up on Ubuntu 24.04.** `unshare --user --map-current-user` fails with `write failed /proc/self/uid_map: Operation not permitted`. Whatever makes the sandbox's namespaces has to be bubblewrap, or a program with a profile of its own.
5. **Not shown: the PID side.**
   - Whether Hermes's clients find a gateway in another PID namespace: no such session started. Hermes's source checks gateway liveness through `gateway.pid` and `gateway.lock` records, `_pid_exists` and process start times. It also names a health-probe path that does not rely on PIDs. What it does across PID namespaces is not shown.
   - Whether a shared PID namespace ends with its holder: not shown.
   - Whether a chat that cannot reach its gateway starts one of its own: inconclusive. The process count matched the relay's command line, not Hermes's gateway.

## The two conflicts still to settle

- **The dashboard from the host (shown, item 3).** ADR 0028's consequence does not hold on Linux. Options:
  - (a) Accept it and say so: on Linux the dashboard is reached only from inside the sandbox, or through a host-service forward (milestone 4.1). `status` names the listener but gives no URL that works from the host.
  - (b) Give the host a forward to the service's port, e.g. through the proxy service, which already runs per sandbox. That is a new path from the host into the sandbox, with its own audit and decision.

  Either way, ADR 0028 needs a superseding or amending ADR for Linux. That decision is yours.
- **Every port of the sandbox, not just the service's (not shown yet).** If the sessions share a network namespace, each one reaches every port anything in the sandbox listens on. ADR 0028 on macOS allows the service's port alone. Under ADR 0014's threat model this may be acceptable, since it stays within one sandbox (ADR 0003, the sandbox is the boundary). But it is a change to ADR 0028's rule and needs your decision, if option 1 below is taken.

## Options for the row

1. **One network and PID namespace per sandbox, made by a holder and joined by every session** (design §15's current recommendation). Not shown possible: every join tried was refused. Three ways remain untried:
   - 1a. bubblewrap with `--userns` only, without `--pidns`, so the session keeps a PID namespace of its own; then `inside.py` enters the network namespace with the capability bubblewrap kept, drops every capability, and applies Landlock and seccomp. The runs never reached this step, because `--pidns` was refused first.
   - 1b. The holder starts each session's bubblewrap from inside its own namespaces. `connect` hands it the terminal's descriptors over the holder's socket. Sessions are then the holder's children, not `connect`'s, which touches the marker scheme (ADR 0030) and `--die-with-parent`.
   - 1c. `nsenter` under an AppArmor `userns` profile of its own. This mainly diagnoses the refusal; as a design, it adds a second AppArmor rule that `doctor` must check and explain.

   If 1a works, PIDs stay per session, which keeps sessions apart (no signals or environment reads between them), and the Hermes PID question goes away.
2. **A network and PID namespace per session, with the service's port relayed** (design §15's other option). Each session keeps today's isolated namespaces, which the run shows hold. The service session also serves its port on a Unix socket in the sandbox's `run/` folder. Every other session's relay listens on 127.0.0.1 at that same port number and forwards to it, as the proxy relay does. Not tried yet. It keeps ADR 0028's "the service's port alone" on Linux. Its cost:
   - a second relay per session;
   - the port must be known when the session starts, as on macOS;
   - a service restart changes the port, as ADR 0028's consequences already state for macOS.

## Recommendation

Don't decide the row yet. Run one more experiment on the runners first, covering option 1a and option 2. I can add both to the existing scripts as two more ways in `nsjoin.py` and the checks, plus Hermes's chat against each, and fix the gateway count so it matches Hermes's process rather than the relay.

- If 1a works and Hermes's chat reaches its gateway through it: per sandbox, as §15 recommends, with PIDs per session.
- If not, option 2: it keeps ADR 0028's rule as it is, and the run already shows the namespaces it relies on hold.

Separately, the dashboard question (conflict 1) needs your decision whatever the row becomes. My recommendation is option (a) for milestone 3: state it in a new ADR amending ADR 0028 for Linux, and leave a forward to milestone 4.1's host-service forwards.

Should I add the second experiment (1a and 2)? And which way for the dashboard, (a) or (b)?
