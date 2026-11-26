---
status: proposed
---

# A paused host is a recorded state, and the host's person may set it

Amends [0042](0042-a-bridge-on-each-host-serves-the-mobile-app.md)'s read-only consequence and [design §2](../design.md#2-scope)'s remote-control non-goal, as [0046](0046-the-hosts-person-approves-sandbox-policy-scopes-from-the-phone.md), [0047](0047-the-hosts-person-manages-sandbox-policy-from-the-phone.md) and [0064](0064-the-hosts-person-can-provision-sandboxes-from-a-paired-phone.md) already do, for pausing and resuming a host's work, all of it or named sandboxes. It records that [0047](0047-the-hosts-person-manages-sandbox-policy-from-the-phone.md)'s phone screen-lock requirement is **not** extended to pause, and leaves [0021](0021-one-runtime-service-per-sandbox.md)'s "no per-agent start or stop" in force. Issues: enclos #372 and enclos-app #95.

Today the only way to stop a host's autonomous spending is `enclos sandbox stop <name>...`, one sandbox at a time, and a stopped sandbox cannot be told from a broken one: `SandboxState` is `created`, `running`, `stopped` or `failed`. A person who parks work for a week, or spends the tokens of one organization first, must be able to say so once, see that it holds, and come back without remembering what was running.

This ADR is the whole decision. It is built in three slices (§ Slices); **slice A, the record and the command, is what this pull request builds**. The guarantee (the refusals and the drain) and the phone are later slices, so what they decide is written here as *proposed, not built*, and nothing below describes security behaviour as enforced until code and a run show it.

## Decision (proposed)

1. **A pause is a record on the host, not a sandbox state.** A pause in force is one row in `host_pause`; each sandbox it covers by name is one row in `sandbox_pauses`, naming the runtime services it stopped and the sandbox's other services that kept running. The row also carries two facts that make coverage derivable: `host_pause.pause_all` (the pause was asked for the whole host; once set it is never cleared by a later pause) and `sandbox_pauses.released` (set when a member's resume is *asked*, before its services are installed). `sandboxes.state` keeps its four values and its meaning: pausing removes the runtime's service and leaves the sandbox's record as it was. The record is written from the first commit at host level, never into `sandboxes.state`.
2. **The person is shown a derived word.** `status`, `sandbox list`, `sandbox show` and the phone present a sandbox as **paused** and the host as **Paused**, **Partly paused** (naming what still runs or still owes a restart) or **Running**. The word is computed in one place at the moment of display from the record and from what actually runs; it is never stored, and a record that cannot be read is said to be unreadable, never guessed.
3. **The guarantee is keyed on coverage (proposed; built in the guarantee slice, not this one).** While a pause is in force, a *new* session that could do the host's work is refused — `enclos connect`, `enclos exec`, `enclos sandbox start`, `runtime install` — naming `enclos sandbox resume`, for **every sandbox the pause covers**: every member it holds, every member whose resume did not take, and, under a host-wide pause, every sandbox of the host, including one created after the pause ran. A sandbox a resume released is not covered and is not refused; that is what a resume is for. enclos's own read-only commands keep working, including `enclos usage`, whose reader session is exempt by name.
4. **A resume writes its intent before it installs, and says truthfully when it could not.** `released` is set first, so a resume that fails leaves a *named, still-covered* member; the host keeps reading Partly paused and the command exits non-zero. A sandbox that was already stopped when the pause ran is never marked paused, and a resume leaves it stopped.
5. **The same two commands, one field, two forms.** `enclos sandbox pause|resume [--all | <name>...]`; never both forms in one command; neither is a usage error. There is no bare top-level `pause`. On the wire a single optional `sandboxes` field on `pause` and `resume` means the named subset; absent means every sandbox.
6. **The host's person, and only the host's person, may pause or resume from a still-paired device**, under the same stored identity and per-request recheck as `sandboxes` and `sandbox.create`, with one audit entry per command naming the person and the device. **No phone screen-lock prompt is required**: a pause grants no access and changes no policy, and it is pressed when the person is away from the host's keyboard.
7. **The state reaches the phone additively.** A bridge advertises `pause`, and `pause.subset` for the subset field, to the host's person alone; a device declares `pause` to receive `pause.state`. A device that declares nothing gets nothing new (see `docs/protocol.md`).
8. **A pause names what it will cost before it costs it** (proposed, guarantee slice): an answer a runtime is still waiting on is lost by a pause, so the pause reports pending questions, held-task cards still held and any interactive session left open, filtered to the named sandboxes for a subset pause.

## Reason

The state has to be a record because a paused sandbox's services are *removed*: nothing distinguishes it from a sandbox stopped by `sandbox stop` or a crash, and nothing is loaded at login on a rebooted host (ADR 0002's own consequence), so an inferred pause would evaporate when it is most needed. It has to be a *host* record because a pause is a fact about the host that outlives any sandbox in it, and a pause asked when nothing runs is still one the phone must hold and resume. It must not be written into `sandboxes.state`, because `sandbox_row` maps that text to an enum and refuses anything else as corrupt: a new value there would make an older enclos refuse the sandbox, and reversing it later is a data migration. The authority is the host's person because stopping work is availability, not confidentiality: it is the one control whose harm falls on everyone sharing the host.

## Considered options

- `state: "paused"` written into `sandboxes.state`. Rejected: an older enclos reads the row as corrupt, and this enclos's own total match cannot write it.
- A pause inferred from "services absent". Rejected: it cannot tell a pause from `sandbox stop`, a crash or a host that is down, and `state check` would call it drift.
- A pause as a fifth lifecycle state in the CLI and protocol only. Rejected: the CLI's JSON and the protocol's `state` are the same fixed set, so the value would still reach an older peer, with no record behind it.
- A per-agent pause. Rejected, out of scope: one gateway serves every agent of a sandbox and there is no per-agent stop (ADR 0021).
- A supervisor holding the pause. Rejected: ADR 0002 forbids a daemon for this, and a record plus removed units needs none.
- A second ADR for the per-sandbox form. Rejected: it adds a field, a capability and two record facts to decisions about the same record, authority and state machine; two documents would drift.

## The state machine

### What is recorded, and what is derived

| Thing | Where | Values |
| --- | --- | --- |
| A sandbox's lifecycle state (unchanged) | `sandboxes.state` | `created`, `running`, `stopped`, `failed` |
| A pause in force on the host | `host_pause` (at most one row) | its `revision`, `pause_all`, its actor and time |
| A sandbox the pause names | `sandbox_pauses` row, key the sandbox | `labels` it stopped (empty when it found none), `kept` services, `released` |
| **Member** | derived | a sandbox with a `sandbox_pauses` row |
| **Covered** | derived | a member not released; a member whose resume did not take (owed); under `pause_all`, any sandbox with no row |
| **Owed** | derived | a member with labels, `released` set, and no runtime service installed again |
| **Paused** (presented) | derived | a member not released, with labels, state `running`, no runtime service installed |
| **Presented host word** | derived | `Running`, `Paused`, `Partly paused` |

All of a sandbox's agents are paused together; there is no per-agent state (ADR 0021).

### Membership, coverage and the reason a sandbox is not paused

A member is decided when the pause runs. A sandbox with runtime services installed is stopped and marked paused. One with none (already stopped, created, or failed) is *covered but not paused*: left exactly as it was, named so, and a later resume says it left it as it was. When no record is in force, a subset pause writes a record **only when it stopped something** (or was asked for the whole host), so a subset over sandboxes that all lack services writes no record and leaves the host's word unchanged; when a record is already in force, a subset pause grows membership to include newly named stopped sandboxes (with empty `labels`) and clears `released` on previously released members. A sandbox *created* while a host-wide pause is in force has no row and is covered, because `pause_all` is never cleared by a later pause.

A sandbox that is not paused carries exactly one of five words, `why`, in `pause.state` and in the CLI's JSON: `not_covered`, `released`, `nothing_to_pause`, `would_not_stop`, `would_not_start`. `released` persists after a resume (its row stays, with `released` set) until the record ends, so the reason survives a reconnect.

### Legal transitions

| From | Event | To | What is written, in what order |
| --- | --- | --- | --- |
| host: not in force | `sandbox pause --all` | in force, `pause_all` | (1) the audit entry opens; (2) the `host_pause` row (with a new `revision`) and all member rows are written together in **one transaction** **before** any service is removed, so a database failure rolls back wholly and a crash leaves a pause that is *named* rather than a stop nobody can undo |
| host: not in force | `sandbox pause <name>...` | in force if a named sandbox had services, else unchanged | as above; the named sandboxes with no services become members with empty `labels` |
| host: in force | `sandbox pause` again | membership grows; `pause_all` set when `--all` | never shrinks; a released member paused again has `released` cleared |
| member: covered | a service will not stop | member named, host Partly paused | the row stays; the audit entry closes `failed` naming it |
| member: covered | `sandbox resume <name>` | `released` written **before** the install; out of coverage once its services are back | a failure leaves it owed and covered |
| host: in force | `sandbox resume --all` | the whole record deleted when no covered sandbox remains held or owed | per member, `released` first, then the install |
| host: in force, `pause_all` | `sandbox resume <name>` | the record stays | only `resume --all` ends a host-wide pause |
| member: paused | `sandbox stop <name>` | the row stays; the sandbox reads stopped, not paused | the record no longer claims a restart is owed; a later resume leaves it stopped |
| member: any | `sandbox rm <name>` | row gone (cascade) | a later `resume --all` names only the members it finds |
| host: in force | a crash, restart, or upgrade of enclos | unchanged | nothing runs at login (units are removed), the rows survive in `state.db` |
| host: in force | a lost `state.db` commit (`synchronous=NORMAL`) | possibly no row, services gone | the sandbox reads stopped and `state check` flags it: the truthful residual |

A subset request reaches the same record through the same two transitions as the whole host.

## Where the state lives

Migration 14 (appended; migrations 1–13 are untouched) in `src/state/sqlite/schema.rs`:

```sql
CREATE TABLE host_pause (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    revision  INTEGER NOT NULL,
    pause_all INTEGER NOT NULL,
    by_user   TEXT NOT NULL,
    by_host   TEXT NOT NULL,
    at        TEXT NOT NULL
) STRICT;
CREATE TABLE sandbox_pauses (
    sandbox  TEXT PRIMARY KEY REFERENCES sandboxes (name) ON DELETE CASCADE,
    labels   TEXT NOT NULL,   -- JSON array: the runtime service labels this pause stopped
    kept     TEXT NOT NULL,   -- JSON array: the other service labels that kept running
    released TEXT,            -- set when a resume is asked; NULL while the pause holds it
    at       TEXT NOT NULL,
    by_user  TEXT NOT NULL,
    by_host  TEXT NOT NULL
) STRICT;
```

The stopped labels are stored, not derived: an upgrade may change what a runtime adapter declares, and then a resume would start something the pause never stopped. `kept` is what lets a resume tell that `sandbox stop` stopped the sandbox meanwhile, moved from one process's memory into the record.

**`revision`** is an equality token for the fence, not a counter; a device must compare it for equality only and must never order it. It changes whenever the record changes: the new value is `max(previous + 1, unix milliseconds now)`, where no live record presents `0`; `0` means no record exists (including after deletion) or, after a failed read, unknown, while a non-zero `revision` with `Running` means a record remains that reaches no sandbox (`pause_all = 0` with no covered member: after a failed resume clean-up, after `sandbox rm` or `sandbox stop` of the last covered member, or after `sandbox start` of the only owed member). In that state `status` and `sandbox list` show no pause line (the host reads `Running`) — a lingering record is visible only through its non-zero `revision`; running `resume` clears it, and the next `pause` supersedes it. Avoiding reuse across record lifetimes depends on the host's clock not running far backwards between a deletion and the next creation; a stale fence from before such a step could match a newer pause. That residual is stated, not removed.

**Reversal.** The migration is additive. To return a database to schema 13, `DROP TABLE sandbox_pauses; DROP TABLE host_pause; PRAGMA user_version = 13;` — and `enclos init` applies migration 14 again. A pause in force is lost by it, and the services it removed stay removed.

**What an older enclos does.** It refuses to work at all, as it does for any newer schema: `open()` compares `user_version` with `schema::current()` and returns `NewerSchema`. Observed with an enclos that knows schema 13 on a `state.db` at 14, for `sandbox list`, `status` and `state check`: `…state.db uses schema 14, written by a newer enclos (this one knows 13). Upgrade enclos`, exit 1. The pause adds no half-understood state: nothing of it lives in a column, value or table an older enclos reads. A downgrade must therefore finish or abandon the pause with the new binary. After the reversal above, the older binary works again (observed).

**Host restart while paused.** The record is a row in the same WAL database as the sandboxes, so it survives a reboot, a log-out and a crash. Two residuals are named, not assumed: on Linux with lingering on, a unit a *partial* pause left installed could come back with the host (which is why Partly paused names the sandbox still running); and a `state.db` that loses its last commits can lose the rows while the units are gone.

## The protocol

The rule that decides every field: an optional field, `type` or capability does not raise `v`; a new *value* of a fixed-set field is legal only behind a capability on both legs. `sandboxes.state` and the CLI's `state` are fixed sets, so the pause is carried by an optional sibling (`paused`, `why`) and capability-guarded messages, never a new wording of `state`. The messages are specified in [protocol.md](../protocol.md):

- `pause` and `resume`: an optional `revision` (one fence, host-wide, for both forms) and an optional `sandboxes` (absent means every sandbox; present means exactly those names; present but empty or explicit `null` is `bad_message`; duplicate names are deduplicated in first-occurrence order). A name that is malformed is `bad_message`; a name this host has no sandbox of is `not_found`, and the whole request is refused with nothing carried out.
- `pause.subset`: a second capability, advertised beside `pause` to the host's person only, and required of the device before it may send `sandboxes`. An older bridge that does not advertise it never receives a subset request.
- `pause.state`: canonical, no `of`, with a row per sandbox carrying `paused`, `state` and, exactly when not paused, `why`; `by` carries only the person's name or login without device or request identifiers.
- `pause.result`: correlated by `of`, carrying a row per named sandbox, never inferred from `pause.state`. An `error` is sent when an engine error kept the operation from starting, or when after the work the state lock could not be taken for about a minute (about two minutes in all on a resume, which retries once for record clean-up and once to finish the audit entry; leaving the audit entry unfinished, listed by `audit verify`). If a resume's post-work record clean-up fails after the resume ran, or if the host's state cannot be read back after the work completes, `pause.result` is still sent with the per-sandbox rows (`paused: false`, `partly: true`, and the derived `revision` when the record is readable, or `0` when unreadable), the error is written to the bridge's standard error, and the `pause.state` broadcast is still attempted. By design, after a failed resume clean-up under `pause_all = 0`, `pause.result` carries `partly: true` (meaning "the clean-up failed, run resume again") even when the `pause.state` broadcast at the same revision reads `Running` (`paused: false, partly: false`); the broadcast is canonical for the host's state. On a clean-up failure, the CLI exits non-zero, says the services were resumed (or that the resume ran when none was resumed) and tells the person to run resume again, and the audit entry closes `failed` naming the error while leaving the record as far as the clean-up got (one transaction per stopped-meanwhile row and then the record's deletion, never a half-written row).

## Authority and audit

The CLI is the local user, as every command. The phone is the host's person on a device still paired, re-read on every request; with no host's person recorded both requests are refused. One audit entry per command, written by the engine: `sandbox pause` / `sandbox resume`, naming the actor (for the phone `<person> (device <id>)`), with the scope as its subject, **opened before the first row is written** and closed `ok` or `failed`. The services the pause stops or starts write their own nested `services` entries. A device that is not the host's person receives the paused state of the covered sandboxes only if it declared `pause`, sees no control, and is answered `not_allowed`.

## Durability and truthful reporting

- **A pause interrupted part-way** leaves a named pause: the host row and all member rows are written together in one transaction before services are removed, so the host reads Partly paused naming the member still running; a later pause finishes it and is idempotent. Every error path after the audit entry opens closes it `failed`; an unfinished entry remains only on a crash or when the state lock cannot be taken for about a minute (about two minutes in all on a resume), which `audit verify` lists.
- **A failed pause leaves no unnamed half-state.** A name, fence, lock, database-write or audit failure writes no row. A service that will not stop leaves its member *named and covered*, the host Partly paused, and the command non-zero.
- **A resume that fails on one sandbox** keeps that member owed and covered and exits non-zero; the members that did resume are released. The message names `enclos sandbox resume`, not `sandbox start`.
- **Presented words.** Paused: the record says so and nothing of the host runs. Partly paused: it names what still runs and what is owed — never "paused". `Paused · nothing to pause: every sandbox is already stopped` for a host-wide pause over nothing. Never Paused while anything runs. A sandbox "runs" when its record state is `running` and it is not paused, so a running sandbox with no runtime service keeps the host Partly paused and is named with `nothing_to_pause`.
- **Cannot tell** is said as such, never as zero, as Running, or as not paused: an unreadable `host_pause` or `sandbox_pauses` row is reported as unreadable in `status`, `sandbox list`, `sandbox show` and `state check` (which treats the pause state as unknown and does not flag paused services as missing or offer `RecordStopped`). A failed post-work record clean-up or host read still returns the per-sandbox report: on a clean-up failure, the CLI exits non-zero, says the services were resumed (or that the resume ran when none was resumed) and tells the person to run resume again, the bridge writes the error to its standard error and sends `pause.result` with `paused: false`, `partly: true` (meaning "the clean-up failed, run resume again", even when the canonical `pause.state` broadcast at the same revision reads `Running`) and the derived `revision` (`0` only when unreadable), the audit entry closes `failed` naming the error, and the record is left as far as the clean-up got (one transaction per stopped-meanwhile row and then the record's deletion, so some stopped-meanwhile rows may already be cleared, never a half-written row; a record that reaches nothing reads `Running` with its non-zero `revision`, never plain `Paused`).

## Testable invariants

| # | Invariant | Shown by |
| --- | --- | --- |
| I1 | No sandbox row holds a state word outside the four | slice A: `state_check`/engine tests; `sandboxes.state` is never written by a pause |
| I2 | A paused sandbox's record says running or stopped, and `state check` is quiet for it | slice A: engine test |
| I3 | The presented state is derived, not stored | slice A: derivation tests over what runs |
| I4 | An already-stopped sandbox inside a pause cannot be `connect`ed | guarantee slice |
| I5 | Resume restores per sandbox; the already-stopped one is named as left as it was | slice A |
| I6 | A resume that fails leaves the host Partly paused, never Running | slice A |
| I7 | `enclos usage` and every read-only command still work while paused | guarantee slice |
| I8 | Nothing that starts a session or installs a service runs while covered | guarantee slice |
| I9 | A pause and a resume are each one audit entry naming the actor | slice A (the engine; the bridge names the device) |
| I10 | A pause never writes into a sandbox home and never runs a runtime command | slice A (the engine calls only the service manager and the state) |
| I11 | An older device gets no new `type`; a device that declares `pause` and is not the host's person gets no control | slice A (bridge tests; the app side is slice C) |
| I12 | A pause asked when nothing runs is recorded and reported, not refused | slice A |
| I13 | A subset pause over sandboxes that all lack services writes no record and leaves the host word unchanged | slice A |
| I14 | A named, already-stopped sandbox in a mixed subset pause is covered and not paused | slice A (the refusal half is the guarantee slice) |
| I15 | The host never reads Paused while something of it runs | slice A |
| I16 | A released member is not covered and its reason survives a reconnect | slice A (record and derivation); the connectable half is the guarantee slice |
| I17 | A resume that fails leaves the member covered and the host Partly paused naming it | record and word in slice A; the refusal is the guarantee slice |

Proof obligations still to run: **P1** (slice A) the derived word and the record stay honest on a host with a running, a stopped and a failed sandbox: pause, `state check` quiet, resume — the engine tests show the logic with a stand-in service manager, and the real service-manager run belongs in `enclos-dev`; **P2** (guarantee slice, the largest unproven item) a pause during a running turn lets the turn finish on both platforms — the graceful path is Hermes's own restart signal, which ADR 0031 sends so the manager starts the service *again*, the opposite of a pause; **P3–P5** the exemptions, the cost list and the absence of a routine backlog; **P6–P7** the skipped-run count and older/newer interoperation (the phone slice).

## Slices

**Slice A — the record and the command (this pull request).** Migration 14; the engine's pause and resume over `pause_runtime`/`resume_runtime` with the rows written intent-first; `sandbox pause|resume [--all|<name>...]`; the presented state in `status`, `sandbox list`, `sandbox show`; `state check` knowing the tables; the audit entries; and the wire both forms use (`sandboxes`, `pause.subset`, `pause.state` with `why`, `pause.result` with rows) in the bridge and `docs/protocol.md`. It is proved by P1 and I13–I16 (I1–I3, I5, I6, I9, I10, I12 also hold here).

**Slice B — the guarantee.** The refusals keyed on coverage (I4, I8, I17), the bounded drain (P2), the naming of what a pause costs, filtered to the named sandboxes, and the amendment to ADR 0028 below.

**Slice C — the phone.** The app's controls, including the per-sandbox one, after the design gate.

**What slice A forecloses, deliberately.** (i) Writing the pause into `sandboxes.state`. (ii) A per-sandbox-only pause with no host-level record. (iii) A daemon holding the pause. (iv) A bare `enclos pause`. **What it does not foreclose:** a per-agent pause (still an ADR 0021 change) and a scheduled pause.

## Conflicts with other text

| Text | Status | Effect |
| --- | --- | --- |
| ADR 0021 | accepted | Respected; a subset is the same operation on fewer sandboxes, as `sandbox stop <names>` already is |
| ADR 0002 | accepted | Respected; a record plus removed units, no new process; the pause works with no bridge running |
| ADR 0010 | accepted | Followed; migration 14 stays appended and the two new facts are columns of tables it creates |
| **ADR 0028** — "`connect` starts the sandbox's services when the runtime is installed and its service is neither installed nor running" | **accepted** | **Contradicted by the guarantee as written, and amended in the guarantee slice, not this one.** `connect` would otherwise install and start a covered sandbox's services: the pause's exact inverse. Until that slice lands, a covered sandbox can still be connected, and this ADR makes no claim that it cannot |
| ADR 0031 | accepted | Reused with the opposite intent: a pause must drain and not let the manager start the service again (P2) |
| ADR 0042 | proposed | Amended: the host's person may also stop and start the host's work from a paired device, for all or named sandboxes |
| ADR 0046 | proposed | Followed, including the one host-wide fence |
| ADR 0047 | proposed | Followed; its screen-lock requirement is **not** extended to pause |
| ADR 0064 | proposed | Followed for the authority pattern; its sentence that service startup and removal remain host operations is narrowed for start and stop *as a pause* |
| ADR 0074 | proposed | Referenced, not amended: `runtime install` installs and restarts a service, which is why it is in the guarantee's refusal set |
| [design §2](../design.md#2-scope) non-goal | text | Amended in this pull request |

## Where this refines the product spec

Where this section and the spec disagree, **this section governs**.

1. The spec's evidence for "no work" says no session of the sandbox is open, but a pause keeps the sandbox's proxy and any interactive session open. The evidence is **no runtime service session and no runtime process runs**, plus the runtime's own records. An open interactive session is a place the person can start the gateway again, so the pause should name it (guarantee slice).
2. The spec's guarantee is keyed on the sandbox being paused; it is keyed on **coverage** (decision 3), so a stopped sandbox inside a pause and a sandbox created during a host-wide pause are both covered, and a deliberately resumed one is not.
3. The spec asks that an older app also read "paused"; the protocol cannot do that without a new value in a fixed-set field. **An older app shows what it shows today** (a stopped sandbox, no control, nothing new claimed); the host's person's updated app shows the honest wording (an older app degrading quietly wins over it reading "paused").
4. "Every agent" is delivered as every sandbox's runtime service, the only mechanism ADR 0021 allows: a pause cannot park one agent while its sandbox's others keep working.

## Open risks

- **P2's ordering** may need a new engine primitive and is unproven on both platforms. It is the largest late-change risk and belongs to the guarantee slice.
- **`runtime install` while paused** is refused by recommendation (it starts a session and restarts a service), not by a settled requirement.
- **A sandbox created while a host-wide pause is in force** is covered by `pause_all`; a person who pauses and then provisions must resume before setting the new sandbox up. This is one rule with no hole.
- **Slice A leaves the pause unguarded.** Until the guarantee slice, `connect`, `exec` and `sandbox start` still work on a covered sandbox and can bring its services back, so a paused host is a *record plus removed services*, not a refusal. The presented word is truthful (a sandbox that starts again reads running, and the host reads Partly paused — or Running under `pause_all = 0` if it was the only covered member and was owed), but nothing prevents it.
- **Slice A runs the engine across the service manager outside the state lock** (stopping a service records session ends and nested audit entries, which take the lock), so two concurrent pause or resume commands can interleave. Each write is intent-first and one transaction, so the record stays consistent and named; the later command's report reflects what it found.
- **The revision's clock assumption** (above) and **a pause across a reboot or log-out on a Linux host with lingering on** are to verify by a run.
- **Not settled here:** the wording and placement of the app's control (the design gate), and how a change made on the host with the CLI reaches a connected phone before its next sync (a periodic tick is not built).
