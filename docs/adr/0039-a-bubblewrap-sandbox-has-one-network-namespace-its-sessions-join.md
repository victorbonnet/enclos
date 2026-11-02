---
status: proposed
---

# A bubblewrap sandbox has one network namespace, which its sessions join

Amends [0028](0028-a-runtime-listens-and-its-sessions-reach-its-service.md) for the bubblewrap backend: a session reaches what any session of its sandbox listens on, not only its service's port.

A session with a network namespace of its own cannot reach the port its runtime's service listens on, which 0028 gives every session of the sandbox: Hermes's chat in another session than its gateway fails with `Gateway connection failed; no local fallback`. bubblewrap can make a network namespace but has no option to join one. The M3-03 prototype (`prototype/m3/README.md`) shows that a session can join one all the same, on GitHub's Ubuntu 24.04 runners, x86_64 and arm64, and Ubuntu 26.04 runner, x86_64. Its first two runs were refused with EPERM only because the holder was started with `--dev /dev`, which nests a second user namespace: the holder handed out the inner one, while its network namespace belonged to the outer.

Decision (proposed, not accepted):

- **One network namespace per sandbox, kept by a holder.** The holder runs in bubblewrap, without `--dev /dev`, in user, PID and network namespaces of its own. It keeps the network namespace in being, runs the sandbox's relay to the proxy on its 127.0.0.1, and hands its namespaces out as descriptors over a Unix socket.
- **Each session joins it the `nsenter` way.** `nsenter` enters the holder's user and network namespaces, then bubblewrap makes the session's nested user namespace. Every session, a service's included, keeps its own PID and IPC namespaces.
- **The service's port is not relayed.** A session reaches the service on 127.0.0.1, as on macOS, and a runtime's client finds it as it does there.
- **enclos reads that port from the host**, by 0028's rule and the socket's holder: in a shared namespace another session can listen in the ephemeral range too, so it is the port the service's own program holds, read from the holder's `/proc/<pid>/net/tcp` and the program's socket descriptors, not from `lsof`.
- **The holder is a service of its own**, `enclos.<install>.<sandbox>.holder`. `connect` installs it when it is not installed, also for a runtime with no service, and it stays until `sandbox stop`. A runtime that declares a service named `holder` is refused. The code for that is M3-16's.

Reason:

- Sessions reach their service as on macOS, and a service restart costs them nothing: with a gateway restarted, an open session reached the new port with no help. With a namespace per session and the port relayed, which also worked, it would keep a relay at the old port until opened again.
- Processes stay apart. In the prototype another session of the sandbox could not find the service's process, so its signals, ptrace and start-up environment were out of reach.
- A joined session kept the rest: seccomp, `--disable-userns` (ENOSPC with seccomp off), no capability over the namespace and no namespace descriptor left open, with Landlock and without.

## Considered options

- **A namespace per session, the service's port relayed through a Unix socket:** it worked, with Hermes's chat, and reached nothing but that port. A session opened before a service restart stays on the old port, and each session runs two relays.
- **`nsenter` also into the holder's PID namespace:** sessions listed the host's processes.
- **bubblewrap's `--userns`, with `--pidns` or alone, then `setns`:** each needs `CAP_SYS_ADMIN` while the session is set up, and without `--pidns` there is no `--disable-userns`.
- **A holder made by enclos itself, with `unshare`:** refused on Ubuntu 24.04 without an AppArmor profile of its own, a second rule beside bubblewrap's.

## Consequences

- Sessions of a sandbox share what a network namespace holds. Each reaches what another listens on and can take a port there. Their abstract sockets are shared too, and only Landlock's scope separates them: EPERM with Landlock, connected without it. So where the kernel has no Landlock ([0037](0037-landlock-where-the-kernel-has-it.md), proposed), as on Raspberry Pi OS, sessions of a sandbox reach each other's abstract sockets.
- 0028's rule that a session reaches its service's port and no other does not hold on Linux. A session still reaches nothing on the host's loopback and nothing of another sandbox.
- A holder restart splits the sandbox. The open sessions and the service live on in the old namespace, cut off from the proxy, and a new session is in a new one without the service; once the relay is gone a session can bind its port itself. So the holder restarts only when the sandbox's sessions and services do.
- A session cannot signal the relay, which is outside its PID namespace, and the relay reaches nothing but the proxy's socket.
- enclos needs `nsenter`, from util-linux, on the host; `doctor` names it when it is missing.
- A chat started in a session while the service is down starts a gateway of its own there, as 0028 says, outside the service and in that session's PID namespace.
- Shown in CI only, with a stand-in service and with Hermes's chat stopped at the model for want of a login. A logged-in chat, the service's own children reaching it, and a kernel without Landlock are left to M3-16 and M3-20.
