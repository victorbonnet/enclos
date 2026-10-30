---
status: proposed
---

# A bubblewrap session has its own namespaces, and its service's port is relayed

On Linux each session runs in its own network namespace ([0004](0004-linux-bubblewrap-and-landlock.md)). So a session cannot reach the port its runtime's service listens on, which [0028](0028-a-runtime-listens-and-its-sessions-reach-its-service.md) gives every session of the sandbox. Hermes's chat in another session than its gateway fails with `Gateway connection failed; no local fallback` (shown by the M3-03 prototype, `prototype/m3/README.md`).

Design §15 preferred one network and PID namespace per sandbox, joined by every session. The M3-03 prototype could not build that on GitHub's Ubuntu 24.04 runners, x86_64 and arm64. A holder in bubblewrap made the sandbox's namespaces and handed them out, but every way tried of joining them was refused with EPERM:

- `nsenter`;
- bubblewrap's `--userns` with `--pidns`;
- `--userns` alone with `setns` into the network namespace afterwards.

The refusals were the same with AppArmor's restriction on unprivileged user namespaces turned off, and the kernel logged no denial. A process holding every capability in the user namespace the holder handed out was still refused the network and PID namespaces, so they belong to another user namespace.

Review correction: the original holder used `--dev /dev`, so bubblewrap nested its user namespace and exported the wrong owner for the network/PID namespaces. Those EPERM results do not establish that one namespace per sandbox is unavailable. The corrected holder drops `--dev /dev` and the full join-plus-bubblewrap experiment is rerun; the following proposal remains provisional pending those results.

Decision (proposed, not accepted):

- **Namespaces per session.** Every session, a service's included, keeps its own network, PID and IPC namespaces, as M3-02 compiled them.
- **The service's port, relayed.** For a runtime that declares a listening service:
  - Before the service's session starts, enclos makes a Unix socket in the sandbox's `run/` folder on the host and passes it in, listening.
  - enclos's program run first inside that session takes each connection on the socket to 127.0.0.1, at the port enclos records for the service in `run/` once it listens.
  - enclos reads that port from the host, by 0028's rule: the one TCP port on 127.0.0.1 in the ephemeral range that the service's program holds. On Linux it reads it from the service's `/proc/<pid>/net/tcp` and the program's socket descriptors, not from `lsof`.
  - The sandbox reads `run/` and never writes it, so no process inside can change the socket or the port.
- **Other sessions.** A session started while the service listens gets that port. Its relay listens on 127.0.0.1 at the same port in the session's own namespace and passes each connection to the socket, as the proxy's relay does. A session started while the service does not listen gets none, as on macOS.

Reason:

- It is the option the prototype showed working. Through the relay, another session reached the service's port and nothing else it listened on, with Landlock and without. Hermes's chat in another session, and another PID namespace, reached its gateway and went on to the model without starting a gateway of its own.
- It keeps what the per-session namespaces were shown to hold. Each session sees only its own processes, so another session's signals, ptrace and start-up environment are out of reach. Abstract sockets stay within the session.
- It keeps 0028's rule that a session reaches its sandbox's service port and no other port.

## Considered options

- **One network and PID namespace per sandbox, joined by every session:** sessions would reach their service as on macOS, and every other port the sandbox listens on. It was refused in every way tried, and why the holder's namespaces belong to another user namespace was not established. A holder made without bubblewrap's nested user namespace, or one that starts each session's bubblewrap itself, was not tried. Should either be shown working, a new ADR can supersede this one.
- **A holder made by enclos itself, with `unshare`:** refused on Ubuntu 24.04 without an AppArmor profile of its own (`unshare` cannot write its user mapping; the kernel logs `capable` `sys_admin` denied under `unprivileged_userns`). That would add a second AppArmor rule beside bubblewrap's.

## Consequences

- When the service restarts, it listens on another port. enclos records the new one, but a session opened before keeps its relay at the old port number, and Hermes's clients then dial the new one. Such a session reaches the service again only once it is opened again, as 0028 states for macOS. Unlike on macOS, the old port never reaches another program: it is in the session's own namespace and leads only to the service's socket.
- The relay is part of enclos inside the session, as the proxy's relay is. A session can stop or replace it, which reaches nothing but the service's socket.
- Any process of the sandbox can connect to the service's socket, since the sandbox reads its own `run/` folder. That is the same reach 0028 gives its sessions. Other sandboxes do not mount this sandbox's folder.
- Each session runs two relays where the runtime declares a service, one for the proxy and one for the service. Each holds a port in the session's own namespace.
- Shown in CI only, with a stand-in service and with Hermes's chat stopped at the model for want of a login. A logged-in chat, a service restart, and the service's own children reaching it are left to M3-16 and M3-20.
