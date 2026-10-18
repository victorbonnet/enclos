# Linux: Landlock and seccomp for the filesystem sandbox

On Linux, enclos restricts filesystem access with Landlock and blocks dangerous system calls with seccomp. Both work without root or user namespaces, so they run unchanged on Ubuntu 24.04+, where AppArmor blocks capabilities inside unprivileged user namespaces and breaks namespace-based tools such as bubblewrap.

## Considered options

- **Namespaces (bubblewrap):** a private mount view is flexible, but it adds an external dependency and needs an AppArmor profile on recent Ubuntu.
- **Containers (Docker, Podman):** heavy, need a runtime, and the agent no longer works on the user's real files and tools.

## Consequences

- Landlock must be built into the kernel (5.13+) and enabled at boot. Distribution kernels usually have it, but Raspberry Pi OS is unconfirmed; see [0008](0008-fail-closed.md) for what happens when it is missing.
- Filesystem rules are allow-lists of paths. Landlock cannot hide a path, only deny access to it.
- Network isolation is a separate mechanism; see [0004](0004-network-proxy-and-namespace.md).
