---
status: proposed
---

# A memory limit the host cannot hold runs unapplied, once accepted

Amends [0033](0033-a-limit-the-backend-cannot-enforce-is-refused-outright.md), which refuses outright, with no acceptance, a limit the backend cannot enforce as written.

On bubblewrap, `memory` is held by the session's cgroup, which needs the memory controller in the kernel and delegated to the user's systemd manager. The milestone 3 host survey found Raspberry Pi OS's firmware turning that controller off (`cgroup_disable=memory`; `prototype/m3/README.md`). So whether bubblewrap enforces `memory` depends on the host, not on the backend alone, as Landlock does ([0037](0037-landlock-where-the-kernel-has-it.md)). Under 0033, a policy that sets `memory` could not be stored on such a host.

Decision (proposed): on a host where the memory controller is missing from the kernel's root cgroup, or not delegated to the user's manager, a policy that sets `memory` is accepted, and the sandbox runs with the limit not applied. This takes it back from 0033's outright refusal to [0009](0009-refuse-what-cannot-be-enforced.md)'s acceptance. The same mechanism, and nothing more, serves an `[exec]` section on a kernel without Landlock or with too old a Landlock (0037). It makes the gap loud:

- **Create, store, start.** Storing such a policy, or creating or starting its sandbox, on such a host is refused unless `--accept-unenforced <field>` (`memory`, `exec`) is passed. The refusal names the field, why the host does not enforce it, and `enclos doctor`.
- **Audit.** The acceptance is an audit entry naming the sandbox, the field, the policy version and the host's reason. It is kept with the sandbox, so later starts need none until the field's value changes. Every `sandbox start` and session start while it applies prints one line saying the limit is not applied, and `sandbox start`'s audit entry lists the fields not enforced.
- **doctor.** `enclos doctor` lists each sandbox running with a field not enforced, beside the host's own report on the missing control (design §5, Degraded controls on Linux).

Reason: a sandbox that needs to run on Raspberry Pi OS runs, and the stored policy cannot mislead anyone. Nothing is applied silently, the acceptance is explicit and audited, as 0009 asks, and every start says so. When the host gains the controller, the limit holds with no change to the policy.
