---
status: proposed
---

# Landlock where the kernel has it, and its absence stated

Qualifies [0004](0004-linux-bubblewrap-and-landlock.md), which builds the bubblewrap backend with Landlock applied first inside the sandbox, and [0009](0009-refuse-what-cannot-be-enforced.md), which gives Landlock missing from the kernel as its example of a backend not available on the host.

The milestone 3 host survey found that 64-bit Raspberry Pi OS's kernel does not build Landlock at all (`CONFIG_SECURITY_LANDLOCK` unset in every Raspberry Pi kernel installed, measured on a Raspberry Pi 5 with kernel 6.18.50; `prototype/m3/README.md`), so no boot option turns it on. Under 0004 and 0009, the bubblewrap backend would refuse to run on a Raspberry Pi, one of the platforms [0013](0013-supported-platforms.md) supports.

Decision (proposed): Landlock is optional on Linux. Whenever the kernel has it, the backend applies it, as 0004 says. Where it is missing, the backend still runs: writes are held by bubblewrap's mounts alone (the home and workspaces bound writable, everything else read-only or not mounted), and the seccomp filter is unchanged. The backend's capabilities, which then depend on the host's kernel and not on the backend alone, declare the weaker execute control ([0008](0008-layered-policy-with-declared-enforcement.md)): programs are allowed by what is mounted, with no Landlock execute rules. A policy that needs the stronger control, one with an `[exec]` section, is refused there, as 0009 refuses a field the backend enforces only partly.

`enclos doctor` states the risk plainly when Landlock is absent: what is not enforced and why it matters. Without Landlock, any program the sandbox can read can be run, including one it downloaded or wrote into its home or a workspace; writes outside the home and workspaces rest on one layer, the mount layout, with no second check if a path is mounted writable by mistake; and Landlock's refusal of host Unix sockets (ABI 9) is not there to back up their masking.

Reason: writes, the protection [0014](0014-threat-model-accidental-damage.md)'s accidental damage turns on most, are held by the mounts with or without Landlock; Landlock is their second layer and the only control on what runs. A Raspberry Pi user gets a sandbox whose gaps are named, rather than none, and every host whose kernel has Landlock keeps it.

## Considered options

- **Keep Landlock required:** the Pi would need a kernel the user builds, or another distribution's, so the milestone's Raspberry Pi host would not run the backend as installed.
- **Ask Raspberry Pi to build Landlock in:** worth doing, but not in enclos's hands, and it settles nothing for milestone 3.
