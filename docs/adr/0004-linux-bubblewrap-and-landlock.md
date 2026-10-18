---
status: accepted
---

# Linux: bubblewrap with Landlock and seccomp

On Linux, the sandbox is built with bubblewrap: a mount namespace where denied paths are simply not mounted, a network namespace with no network except a Unix socket to the sandbox's proxy, Landlock to restrict writes and which programs can run, seccomp to block dangerous system calls, and cgroups (through `systemd-run --user`) for CPU and memory limits.

## Considered options

- **Landlock and seccomp without namespaces:** no AppArmor setup, but Landlock restricts network access by port, not by address, so the only way to force traffic through the proxy is a network namespace. Once a user namespace is needed for that, bubblewrap's mount namespace comes at no extra cost and gives a stronger read deny (the path does not exist) than Landlock's.
- **Containers or microVMs (OpenShell, libkrun):** stronger isolation, planned as additional backends for agents that run untrusted code, but too heavy as the default.

## Consequences

- On Ubuntu 24.04+, AppArmor blocks capabilities inside unprivileged user namespaces unless bubblewrap has a profile that allows them. `enclos doctor` must detect this and say how to fix it.
- Reads are broad ([0015](0015-broad-reads-narrow-writes.md)), but a network namespace does not block Unix sockets on the filesystem and a read-only mount does not prevent connecting to one. bubblewrap must mask `/run/user/<uid>` (the session bus and the `systemd --user` manager), the Docker socket and the SSH agent socket, and the escape probes must cover them.
- Landlock must be enabled in the kernel. This is unconfirmed on Raspberry Pi OS and must be checked (`cat /sys/kernel/security/lsm`) before the Linux backend is built in milestone 4.
