# Open questions for M3-01 (PR #112)

## What `policy test` reports where an accepted field is not enforced

**The question.** Milestone 3's acceptance wants two things of Raspberry Pi OS without `cgroup_enable=memory`. Step 2: a policy that sets `memory` is stored with `--accept-unenforced memory`, and `policy test` shows it not in force ([ADR 0038](docs/adr/0038-a-memory-limit-the-host-cannot-hold-runs-unapplied-once-accepted.md), proposed). Step 5: `policy test` is READY on both hosts. ADR 0038 says nothing about the verdict, and the same case comes up for an `[exec]` section accepted on a kernel without Landlock ([ADR 0037](docs/adr/0037-landlock-where-the-kernel-has-it.md), proposed).

Today `policy test` ends in `READY: no probe got out of sandbox …` or `NOT READY: …` (`src/cli/policy.rs`), so READY speaks of escape routes. A limit that is not applied is not an escape route, so the two steps can both hold, but only if that reading is written down.

| Option | What the host reports | For | Against |
| --- | --- | --- | --- |
| **A. READY with a named warning** | `READY: no probe got out…`, then a required line such as `memory: not enforced (accepted)`, also a `not_enforced` list in `--json` | Keeps READY's present meaning (what was probed), adds no verdict, and steps 2 and 5 stand with one added sentence | A script reading only the verdict or the exit status sees success |
| **B. A distinct DEGRADED verdict** | `DEGRADED: no probe got out…; not enforced: memory (accepted)` | Loudest, in keeping with ADR 0038 making the gap loud; a script cannot miss it | A third verdict and exit status for every backend to define; step 5 must change to "READY, or DEGRADED on Raspberry Pi OS", and DEGRADED has to say whether an open probe still wins |
| **C. NOT READY** | `NOT READY: memory not enforced` | Simplest to state; no chance of over-claiming | A stock Raspberry Pi OS install could never pass step 5, so the accepted path ADR 0038 proposes would end in "do not use it"; and it says the sandbox leaks when no probe got out |

**Recommendation: A**, with the line required whenever a field is accepted and not applied, and the `not_enforced` list in `--json`. It says exactly what was tested, never that every policy field holds, and keeps the audited acceptance as the place where the gap is agreed to. If you expect scripts to gate on the verdict alone, choose B.

**Whichever is chosen:** add the rule to ADR 0038 while it is still proposed, then change steps 2 and 5 in `docs/design.md` §13. This needs ADR 0038 accepted first; until then, step 2's override does not exist, and §15's row stays open.
