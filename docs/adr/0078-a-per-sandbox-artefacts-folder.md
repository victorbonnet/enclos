---
status: proposed
---

# A per-sandbox artefacts folder the bridge publishes from

Amends [0042](0042-a-bridge-on-each-host-serves-the-mobile-app.md) (the phone
changes nothing in enclos's state) and
[0048](0048-artefacts-are-static-html-attachments.md) (its reason says no new
protocol message, capability flag or delivery path exists). Extends GLOSSARY's
"Artefact", which today means a page.

An agent that builds something for the person has one way to hand it over: a
message. The file then lives in the conversation that carried it, is invisible
on the sandbox's page, and — for an APK — cannot be saved on the phone at all,
so it cannot be installed (enclos#373, enclos-app#96).

Decision (proposed):

- **A folder**, `<sandbox home>/.enclos-app/artefacts/`, beside the plugin's
  `media`, writable by any process of that sandbox, as everything in its home
  is (0003: the sandbox is the boundary, the agent is not). The bridge reads
  it; nothing outside the sandbox writes it except the host's person's Delete.
- **The bridge publishes; the sandbox's file is never served as a path.** At
  each list the bridge opens the folder from the sandbox home one component at
  a time without following a link, and a file is eligible only if it is a
  regular file, with no other link to it, one name of the folder, not hidden,
  of at most 120 characters with no control or hidden character, and of at most
  25 MiB. Everything else is left out and written once per
  `(sandbox, file, reason)` per bridge run, until 8192 distinct refusals are
  remembered and then the memory restarts, to the bridge's standard error (the
  terminal of `enclos app serve` or its service journal), not to
  `enclos app log`.
- **A fetch is of one copy.** The bridge copies the file for that fetch, hashing
  it while it copies, and serves every part from the copy; each part carries the
  digest of the whole file, so the phone verifies what it assembled. A part is
  served only while the folder still holds that file with the same identity.
- **Limits, enforced where the bridge is**: 25 MiB a file, 256 files a sandbox,
  1 GiB a sandbox. Reaching one leaves the file out of the list and writes it
  once per `(sandbox, file, reason)` per bridge run, until 8192 distinct
  refusals are remembered and then the memory restarts, to the bridge's
  standard error (the terminal of `enclos app serve` or its service journal),
  not to `enclos app log`; the sandbox's own writes are not restricted (a
  limit that bounds what the host publishes and what the phone receives, not
  what an agent may keep in its own home).
- **A small protocol**: the bridge advertises `artefacts`; a device asks
  `artefacts` for one sandbox and gets `artefacts.list`; it fetches bytes with
  `artefact.get` and gets `artefact.data`, as `attachment.get` already does.
  Nothing is sent unasked, so no protocol version rises.
- **Who may do what**: list and fetch go to any person the bridge lists at least
  one agent of that sandbox to; Delete goes to the host's person alone and is
  the only thing here that writes into a sandbox.
- **No record.** No table in `state.db` (which the bridge never writes) and none
  in `app.db`: the folder is the truth for what exists, the list is derived from
  it, and no migration follows. `enclos state check` gains nothing.

Reason: the phone has nowhere to look for what a sandbox produced and no way to
save a file; the smallest thing that gives it both is a folder the bridge
already knows how to read safely, with the phone asking for it rather than being
pushed. Publishing from the bridge rather than serving the sandbox's path keeps
one rule for both of the bridge's file paths. Keeping no record keeps the
feature reversible and `state check` quiet. The costs, stated: a published file
is readable by everyone who can reach that sandbox (a wider audience than a
message attachment, which only a conversation's owner sees); Delete is a new
phone-driven write inside a sandbox; and a fetch copies up to 25 MiB before its
first bytes.

## Considered options

- **A permanent mirror in the bridge's storage** (every listed file copied and
  kept beside `app-media`). Strongest invariant, but doubles the disk a quota
  bounds, needs a durable `name → id/revision/digest` record to know whether its
  copy is current (a migration), and adds a sweep and a reconciliation. The
  digest travelling with the parts buys the same phone-side guarantee without
  any of that.
- **Serving the sandbox's file in place, part by part.** No copy at all, but the
  bytes of one download can span two versions of the file and the only
  protection is that the phone's digest check fails — a rare race turned into a
  failed download. Rejected because a file the person installs deserves an
  invariant, not a detection.
- **A policy-granted workspace** instead of the home. A policy surface, a new
  field and a migration for something that is not a write boundary.
- **Broadcasting "a new artefact" when a file appears.** Reaches every device
  unasked, needs a device opt-in (the `task_events` exception), and interrupts
  someone for a file they did not ask for. The section's own refresh is one tap.
- **Expiring artefacts by age.** Makes the list a queue and makes "the person
  kept this" unanswerable.

## Consequences

- A published file is readable by everyone who can reach that sandbox, not only
  by the person the agent was talking to. Security confirms this rule
  independently.
- Delete is a bridge write into the sandbox home (through the folder it opened,
  by the name it listed, only while that name still refers to the same file).
  It is recorded in the bridge's log, not illegitimately: it changes no enclos
  state (0054's reasoning).
- Existing message attachments are untouched: `attachment.get`/`attachment.data`,
  their shape, part size and 25 MiB cap, the `media` folder being copied out and
  emptied, and the fixed handoff list (app 0008) all stay as they are.
- Nothing new runs on the phone and the sandbox gets no new way in or out.
- This change builds the read path (the folder, the walk, the list, the fetch
  and the limits); Delete — the one part that writes into a sandbox — lands on
  its own card and amends 0042 then.
