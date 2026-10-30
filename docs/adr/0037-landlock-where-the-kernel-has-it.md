---
status: proposed
---

# Landlock where the kernel has it, and its absence stated

Qualifies [0004](0004-linux-bubblewrap-and-landlock.md), which builds the bubblewrap backend with Landlock applied first inside the sandbox, and [0009](0009-refuse-what-cannot-be-enforced.md), which gives Landlock missing from the kernel as its example of a backend not available on the host.

The milestone 3 host survey found that 64-bit Raspberry Pi OS's kernel does not build Landlock at all (`prototype/m3/README.md`). `CONFIG_SECURITY_LANDLOCK` is unset in every Raspberry Pi OS kernel build examined (6.12.75 and 6.18.50, `-v8` and `-2712`), measured on Raspberry Pi OS 64-bit, kernel 6.18.50, so no boot option turns it on. Under 0004 and 0009, the bubblewrap backend would refuse to run on Raspberry Pi OS, one of the platforms [0013](0013-supported-platforms.md) supports.

Decision (proposed): Landlock is optional on Linux.

- **Where the kernel has it**, the backend applies it, as 0004 says.
- **Where it is missing, or its ABI is older than the backend's rules need**, the backend still runs. Writes are held by bubblewrap's mounts alone (the home and workspaces bound writable, everything else read-only or not mounted), and the backend means to apply the same seccomp filter; no run has shown that it holds on a kernel without Landlock. Shown on Raspberry Pi OS: the kernel offers seccomp filters (`CONFIG_SECCOMP_FILTER=y`, with its actions in `/proc/sys/kernel/seccomp/actions_avail`, read by the survey) and bubblewrap starts (`bwrap --ro-bind / / /usr/bin/true`, exit 0). The no-Landlock mode has only been run with Landlock switched off on GitHub's Azure kernel, which has it, so a kernel without Landlock is still unproven. Whether the rules an older ABI does support are still applied as an extra layer is left to the code that applies them.
- **Capabilities.** The backend's capabilities then depend on the host's kernel, not on the backend alone, and declare the weaker execute control ([0008](0008-layered-policy-with-declared-enforcement.md)): programs are allowed by what is mounted, with no Landlock execute rules.
- **`[exec]`.** A policy with an `[exec]` section is accepted there, its rules not applied, with an explicit acceptance recorded in the audit log, as 0009 allows. The mechanism is [0038](0038-a-memory-limit-the-host-cannot-hold-runs-unapplied-once-accepted.md)'s `--accept-unenforced exec`, and `policy test`'s verdict follows 0038's rule, which also covers a host with no Landlock and no `[exec]` section.

`enclos doctor` reports each case in full: what is not enforced, the risk, and the fix (design §5, Degraded controls on Linux).

- **What is not enforced, and the risk.** Without Landlock, any program the sandbox can read can be run, including one it downloaded or wrote into its home or a workspace. Writes outside the home and workspaces rest on one layer, the mount layout, with no second check if a path is mounted writable by mistake. Landlock's refusal of host Unix sockets (ABI 9) is not there to back up their masking.
- **The fix.** A kernel built with `CONFIG_SECURITY_LANDLOCK=y` and `landlock` in its active LSM list. For too old an ABI, the ABI needed and the kernel version that brings it.

Reason: writes, which matter most for [0014](0014-threat-model-accidental-damage.md)'s accidental damage, are held by the mounts with or without Landlock. Landlock is their second layer, and the only control on what runs. A Raspberry Pi OS install gets a sandbox whose gaps are named, rather than none, and every host whose kernel has a recent enough Landlock keeps it.

## Considered options

- **Keep Landlock required:** Raspberry Pi OS would need a kernel built by hand, or another distribution's, so milestone 3's Raspberry Pi OS target would not run the backend as installed.
- **Ask Raspberry Pi to build Landlock in:** worth doing, but not in enclos's hands, and it settles nothing for milestone 3.
