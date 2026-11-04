# Policy compilation

How a sandbox's `policy.toml` becomes the compiled policy that `sandbox-exec` applies to a session, on the Seatbelt backend. The [design](design.md) (§5, §7, §8) says what the policy is meant to do and the [ADRs](adr/) record why; this page follows the code. Words such as policy snapshot, active policy, compiled policy, workspace and protected path are defined in the [glossary](../GLOSSARY.md).

## Overview

A policy goes through two stages, at two different times:

1. **Resolve and validate**, when the policy changes. The layers are merged into one policy, checked, and stored as an immutable policy snapshot that becomes the sandbox's active policy ([ADR 0018](adr/0018-immutable-policy-snapshots.md)). Paths stay as written (`~/…`, `{home}`), and nothing is written for the backend yet.
2. **Compile**, each time a program starts in the sandbox. The active snapshot's paths are expanded and resolved on the host as it is now, and the backend turns the policy into its own file: a Seatbelt `.sb` file under `~/.enclos/sandboxes/<name>/compiled/`.

```mermaid
flowchart TB
  subgraph resolve["1. Resolve and validate: sandbox create, runtime install, policy allow"]
    defaults["built-in defaults<br/>templates/defaults.toml"]
    template["template<br/>templates/assistant.toml"]
    adapter["runtime adapter's endpoints<br/>(once a runtime is installed)"]
    toml["sandbox's policy.toml"]
    merge["policy::resolve<br/>merge the layers in order, normalize"]
    check["validate::validate<br/>refused or malformed"]
    store[("state.db<br/>snapshot + new policy version")]
    defaults --> merge
    template --> merge
    adapter --> merge
    toml --> merge
    merge --> check --> store
  end

  subgraph compile["2. Compile: connect, exec, launch, policy test"]
    active["the active snapshot, as stored"]
    pre["check_before_compile<br/>home is a folder; write checks again"]
    sb["seatbelt::compile<br/>expand and resolve paths, render SBPL"]
    file[["compiled/HASH.sb, named by its content<br/>reused when identical"]]
    wrap["sandbox-exec -D … -f file program"]
    active --> pre --> sb --> file --> wrap
  end

  store --> active
  store -.->|"network section, read for each connection"| proxy["egress proxy"]
```

The compiled policy does not hold the network allowlist. It only sends every connection to the sandbox's proxy, and the proxy reads the active snapshot's `[network]` section from `state.db` for each new connection. That is why a network change applies at once and a file change needs a new session.

| Stage | Runs when | Code | Result |
| --- | --- | --- | --- |
| Resolve | `sandbox create`, `runtime install`, `policy allow` | `src/policy/mod.rs`, `src/policy/file.rs` | a `PolicySnapshot` |
| Validate | the same, before anything is stored | `src/policy/validate.rs` | refused or malformed problems, or nothing |
| Store | the same | `Engine::store_policy` in `src/engine/policy.rs` | `policy.toml` written, a new policy version in `state.db` |
| Compile | `connect` and `exec`, `enclos launch` for a service, `policy test`; `sandbox show` in memory only | `src/engine/compile.rs`, `src/backend/seatbelt/compile.rs` | `compiled/<hash>.sb` |
| Apply | the same, right after compiling | `src/backend/seatbelt/wrap.rs` | `sandbox-exec` running the program |

## The templates

A sandbox starts from a template, named when it is created (`--template`) and kept in `extends`. Change `extends` with `enclos policy edit <sandbox>` to move it to another. The two differ only in what the sandbox reaches on the network:

| Can it… | `minimal` | `assistant` |
| --- | --- | --- |
| Write to its own home | yes | yes |
| Write to other folders | only those added | only those added |
| Read your files, except sensitive paths | yes | yes |
| Read sensitive paths, such as SSH keys | no | no |
| Run programs, and install them in its home | yes | yes |
| Reach what its runtime needs, once installed | yes | yes |
| **Reach the public web** | **only what is listed** | **yes, ports 80 and 443** |
| Reach other ports | only if listed | only if listed |
| Reach a host on your local network | only if listed and in `private` | only if listed and in `private` |
| Reach your computer's own services or cloud metadata | no | no |
| Open apps, send Apple Events or signal other processes | no | no |

- **`minimal`** reaches nothing until a runtime is installed, then only what that runtime needs and what you list. For Hermes that is its install sources and the ChatGPT subscription's hosts; another model provider's hosts need `enclos policy allow`. Use it when an agent should reach only what you name, such as one working on outside data through remote MCP servers: allow each server's host with `enclos policy allow`, then tell the runtime of it with its own commands.
- **`assistant`** adds any public address on ports 80 and 443, so any model provider works without a grant. Use it for personal agents that browse, research and call public APIs. It can send what it reads to a public website: for sensitive work, use an allowlist.

Under every template, each connection goes through the sandbox's proxy and is logged, as long as enclos can write its state. A runtime may also ask to listen on TCP, as Hermes does, and then anything in the sandbox can serve your network. The allowed hosts of a runtime can be broad: Hermes's include `github.com` and `storage.googleapis.com`, which could carry data out.

A `coding` template is planned (design §7) and does not exist yet.

## Every setting

A `policy.toml` holds what differs from its template. These are all the keys there are: any other key or section is an error. Change a sandbox's file with `enclos policy edit <sandbox>`; `enclos policy show <sandbox>` prints the policy in force.

```toml
extends = "assistant"

[filesystem]
write_add = ["~/Documents/notes"]
read_deny_add = ["~/work"]

[network]
mode = "allowlist"
allow_add = ["api.example.com", "api.example.com:8443", "*.example.org", "printer.lan"]
private_add = ["printer.lan"]
log = "metadata"

[resources]
open_files = 1024

[secrets]
env_add = { API_TOKEN = "secret:lab/api" }

[secrets.agents.main]
env_add = { TELEGRAM_BOT_TOKEN = "secret:lab/main-telegram" }
```

**At the top level:**

| Setting | Accepts | Notes |
| --- | --- | --- |
| `extends` | `minimal`, `assistant` | Required. The template this policy builds on ([the templates](#the-templates)). |

**`[filesystem]`.** A path starts with `/`, `~`, `{home}` or `{tmp}`, and may not hold `"` or `\`. While sessions run, a change waits as the pending policy until `enclos policy apply` restarts the sandbox into it.

| Setting | Accepts | Default | Notes |
| --- | --- | --- | --- |
| `write` | a list of paths | `["{home}"]` | Replaces the folders the sandbox may write. The home stays writable either way. |
| `write_add` | a list of paths | none | Adds folders. Each must exist before the sandbox uses it. Refused: enclos's own folders, and a folder inside the home or another workspace. Malformed: a folder at or inside a deny-list path. |
| `read_deny` | a list of paths | the built-in sensitive list | Replaces the list, and must keep every built-in entry, so use `read_deny_add`. |
| `read_deny_add` | a list of paths | none | Adds paths the sandbox may neither read nor write. |

There is no `read` list and no `write_deny` ([ADR 0015](adr/0015-broad-reads-narrow-writes.md)). Reads are open except `read_deny`, since agents and the tools they install read paths nobody can list upfront. Writes are closed except `write`, so there is nothing to deny, and a `read_deny` path refuses writes too.

**`[network]`.** A change to `mode`, the lists or `log` applies at once, unless the same edit changes files, `listen`, secrets or limits: then it all waits as the pending policy while sessions run, as a change to `listen` does. A destination is a full domain name or an IP address, or `*.domain` for its subdomains, with `:port` when it is not 443. A wildcard over everything (`*`) or a public suffix (`*.com`), and `localhost`, loopback or link-local addresses, are refused; a private address needs `private`, and a single-label name such as `intranet` is malformed.

| Setting | Accepts | Default | Notes |
| --- | --- | --- | --- |
| `mode` | `public`, `allowlist` | from the template: `assistant` is `public`, `minimal` is `allowlist` | `public` reaches any public address on ports 80 and 443, as well as what is listed. `allowlist` reaches only what is listed. |
| `allow` | a list of destinations | none | Replaces the list, the runtime adapter's endpoints too, so its install, login and model calls may stop working. Prefer `allow_add`. |
| `allow_add` | a list of destinations | none | Adds destinations, as `enclos policy allow` does. |
| `private` | a list of hosts | none | Replaces the list of hosts that may resolve to private addresses. Each must also be allowed. |
| `private_add` | a list of hosts | none | Adds to that list. |
| `log` | `metadata` | `metadata` | The only value: host, port, address, verdict, bytes and duration, never contents. |
| `listen` | `true`, `false` | `false`; the Hermes adapter sets `true` | Whether the sandbox may listen on TCP, on any port but the proxy ports. Leave it to the adapter: `false` here wins over it, and Hermes's gateway exits if it cannot listen. |

**`[resources]`.** A limit is fixed when a process starts. While sessions run, a change waits as the pending policy until `enclos policy apply` restarts the sandbox into it. A limit the backend cannot enforce is refused ([ADR 0033](adr/0033-a-limit-the-backend-cannot-enforce-is-refused-outright.md)).

| Setting | Accepts | On Seatbelt |
| --- | --- | --- |
| `open_files` | 16 to 1048576 | Enforced. Above macOS's own ceiling for a process (`kern.maxfilesperproc`), it is refused. |
| `file_size` | bytes, or `512K`, `100M`, `1G` | Refused. |
| `cpu_seconds` | a number of seconds | Refused. |
| `memory` | any value | Refused. |
| `cpu` | any value | Refused. |

**`[secrets]` and `[secrets.agents.<agent>]`.** Each grant maps a variable to `secret:<sandbox>/<name>`, a secret of this sandbox already stored with `enclos secret set`. A variable uses letters, digits and `_`, and not one enclos sets itself, such as `PATH`. While sessions run, a change waits as the pending policy until `enclos policy apply` restarts the sandbox into it.

| Setting | Accepts | Notes |
| --- | --- | --- |
| `env` | a table of grants | Replaces what the layers below grant every session and service of the sandbox. |
| `env_add` | a table of grants | Adds to them. |
| `agents.<agent>.env` | a table of grants | Replaces what one agent is granted. A bot's token goes here, never to the whole sandbox. |
| `agents.<agent>.env_add` | a table of grants | Adds to them. |

A variable granted to the whole sandbox cannot also be granted to an agent. An `[exec]` section is an error: no backend enforces rules on programs yet.

## Stage 1: resolving the layers

`policy::resolve(overrides, adapter)` reads four layers, each a TOML file of the same shape (`PolicyFile`), and applies them in order on top of an empty policy:

| # | Layer | Where it comes from | What it may set |
| --- | --- | --- | --- |
| 1 | Built-in defaults | `src/policy/templates/defaults.toml`, compiled into enclos | everything: `write = ["{home}"]`, the sensitive read-deny list, `mode = "allowlist"`, `log = "metadata"` |
| 2 | Template | `src/policy/templates/<name>.toml`, compiled into enclos: `minimal` and `assistant` | everything but `extends` (a template cannot extend another) |
| 3 | Runtime adapter's endpoints | the installed runtime's adapter (`RuntimeAdapter::endpoints`) | only `[network] allow_add` and `listen` ([ADR 0028](adr/0028-a-runtime-listens-and-its-sessions-reach-its-service.md), proposed); anything else is refused |
| 4 | The sandbox's `policy.toml` | `~/.enclos/sandboxes/<name>/policy.toml` | everything; `extends` names the template, and a file without it is an error (`names no template`) |

**How a layer applies** (`PolicyFile::apply`):

- A list written `name = [...]` replaces what the layers below set; `name_add = [...]` adds to it. If one layer writes both, the replacement comes first, then the additions. The lists are `filesystem.write`, `filesystem.read_deny`, `network.allow` and `network.private`.
- `secrets.env` replaces the secrets the layers below grant, and `secrets.env_add` adds to them, by variable; `secrets.agents.<agent>.env` and `.env_add` do the same for what one agent is granted (ADR 0036). An adapter's layer may not grant any. Each grant must read `secret:<sandbox>/<name>`, or the file is refused as it is read.
- A single value (`network.mode`, `network.log`, `network.listen`, each of `[resources]`) is set by the last layer that names it. So a sandbox's `policy.toml` with `listen = false` wins over the Hermes adapter's `listen = true`. An adapter's layer may not set `[resources]`; `cpu_seconds`, `memory`, `cpu` and `file_size` are refused on Seatbelt, and every limit on a backend not built yet.
- Unknown keys and sections are errors (`deny_unknown_fields`). That is how enclos refuses `[exec]`, which it cannot enforce yet ([ADR 0009](adr/0009-refuse-what-cannot-be-enforced.md)), and how it catches a misspelling such as `alow`.

**Normalizing.** After the last layer, `normalize` puts the policy in one canonical form, so the same grants always give the same snapshot: each `network.allow` entry is rewritten in its canonical form (lowercase, default port dropped), each `network.private` entry the same way, and the four lists are sorted with repeats removed.

**The snapshot.** The result is a `PolicySnapshot`: the resolved `Policy`, the `PolicyInputs` it came from (enclos version, SHA-256 of the built-in defaults, the template's name and hash, the adapter's runtime, version and hash, and the hash of `policy.toml`), and an id, the SHA-256 of the JSON of both. Identical inputs and policy give the same id, so storing a policy equal to the active one records no new version.

Paths in a snapshot are kept as written: `~/work`, `{home}`, `{tmp}/cache`. They are expanded only when the policy is compiled, against the user's home and the sandbox home on the host then.

**Example.** A new sandbox starts with this `policy.toml` (`policy::initial_overrides`):

```toml
extends = "assistant"

[filesystem]
write_add = []
read_deny_add = []

[network]
allow_add = []
```

It resolves to `write = ["{home}"]`, the built-in read-deny list, `mode = "public"` (from the `assistant` template, [ADR 0025](adr/0025-public-web-by-default-for-assistants.md)) and an empty allowlist. Once Hermes is installed, its adapter adds its endpoints to `network.allow` and sets `listen = true`.

## Stage 2: validating

`validate::validate` checks the resolved policy against the sandbox's paths (`ValidationContext`: the user's home, the sandbox home, and enclos's data and config folders). Each problem it finds is one of two kinds:

- **Refused**: the policy is well written, but enclos does not grant it. When every problem is a refusal, the command exits 2 with `refused by policy:` (design §10).
- **Malformed**: an entry that does not parse, or one that contradicts another. Any malformed entry makes the whole result an error (`the policy is not valid:`), since what the policy means is not known until it is fixed.

| Check | Problem | Why |
| --- | --- | --- |
| A path does not start with `/`, `~`, `{home}` or `{tmp}`, or a placeholder is not followed by `/` | malformed | every path must be absolute once expanded |
| A write grant covers enclos's data or config folder, or sits inside it outside the sandbox's own home, also through `~`, `/`, `..` or a symlink | refused | protected paths ([ADR 0010](adr/0010-sqlite-state-and-jsonl-audit.md)) |
| A workspace inside the sandbox home or inside another workspace | refused | the compiled policy keeps only each granted folder's own path in place (below) |
| A workspace reached through a symlink that sits inside the home or a workspace | refused | the sandbox could point the link elsewhere, and the next compile would follow it |
| A path holding `"` or `\`, or not valid UTF-8 | refused | it cannot be put in a Seatbelt rule without changing the rule |
| `read_deny = [...]` that leaves out a built-in entry | refused | a policy may add to the sensitive list, never drop from it; use `read_deny_add` |
| A `network.allow` entry that does not parse (`exa mple.com`, port 0) | malformed | |
| A `network.allow` entry for loopback, link-local, `localhost`, `*` or a wildcard over a public suffix (`*.co.uk`) | refused | [ADR 0017](adr/0017-proxy-connects-only-to-validated-addresses.md) |
| A private address in `network.allow` without the same host in `network.private` | refused | private ranges need an explicit opt-in |
| A `network.private` entry whose host is not in `network.allow` | malformed | an opt-in that unlocks nothing |

**Where it runs.** `Engine::checked_policy_with` resolves and validates, and `Engine::store_policy` stores:

- `sandbox create` resolves the initial `policy.toml` against the template, with no adapter.
- `runtime install` resolves the sandbox's `policy.toml` as it is on disk now, with the new runtime's adapter, and shows the destinations it adds and any other difference before installing.
- `policy allow` adds the entry to `[network] allow_add` (keeping the file's comments), then resolves the whole file against the current template and adapter. When the result changes more than that entry (edits to `policy.toml` not stored yet, or a newer template or built-in defaults), it lists each change and asks first.
- `policy edit` opens a copy of `policy.toml` (`policy.toml.edit`, beside it, with the file it started from in `policy.toml.edit.base`) in the user's editor, then resolves the copy. An edit not applied (refused, an editor that failed, a dry run) stays, and the next `policy edit` opens it again, unless `policy.toml` changed since it began: then it is refused, as it would undo that change, and so is an edit whose `policy.toml` changed while the editor was open. `policy discard` drops a kept edit.

`allow` and `edit` record the result through `Engine::propose` (`src/engine/pending.rs`): it becomes the active version at once, unless it changes the rules a session keeps from its start (`Policy::same_at_launch`: the filesystem rules, `listen`, the secrets granted and the limits) while a session runs under a compiled policy. Then it is saved as the pending policy, beside the active one; a change of network rules alone (a destination `policy allow` adds, or a `policy edit` that touches only the network while a change waits) still applies at once, resolved from the active snapshot's `policy.toml` with that change, provided the result differs from the active policy by exactly it; it is part of the pending one too. Without `--yes` nothing is asked interactively, so such a change waits; with `--yes`, a change that itself brings the rules sessions keep restarts the sandbox into it (`Engine::restart_into`: `sandbox stop`, then the pending policy made active, then `sandbox start` when services were installed). `policy apply` does the same for a change already waiting, and `policy discard` drops it, writing back the `policy.toml` the active snapshot was resolved from (each snapshot keeps that text) and keeping the replaced file as `policy.toml.discarded`. `runtime install` is refused while a change waits, since it resolves `policy.toml` on its own. `store_policy` writes `policy.toml` first and records the version second; if recording fails, the file goes back to what it was.

## Stage 3: compiling

`Engine::compile_policy(name, proxy_port)` in `src/engine/compile.rs` runs every time a program starts in the sandbox: `connect`, `exec`, the installers and agent commands, and a runtime service (`enclos launch`), all through `Engine::start_session`, and `policy test` before its probes. `sandbox show` calls `compiled_file`, the same steps without writing, to tell which sessions run under an older compiled policy.

1. **Pick the backend.** The sandbox's recorded backend must be in this build and its probe must say it runs on this host; otherwise the command fails, with no override ([ADR 0009](adr/0009-refuse-what-cannot-be-enforced.md)).
2. **Load the active snapshot as stored.** The policy is not resolved again: a newer template or enclos version changes no grant until a command stores a new snapshot (design §7, Updates).
3. **Check the paths as they are now** (`check_before_compile`). The sandbox home must still be a real folder, not a symlink, a file or missing. The write checks of stage 2 run again (`validate_writes`), because a symlink on the way to a workspace may have changed since the policy was stored. The other checks are not repeated.
4. **Build the context** (`SandboxContext::new`): the sandbox's name, folder and home, the user's home, the protected folders, the files and folders no sandbox may read (`state.db`, `state.lock`, `audit.jsonl`, `config.toml`, `run/`), the folder of all sandboxes, and the sandbox's proxy port.
5. **Compile** (`Backend::compile`, pure). Seatbelt first expands every path and resolves it to where it really is (`FsPaths::of`, `real_path`): symlinks followed, a dangling link followed to what it points to, `..` taken after resolving. Seatbelt matches real paths, so `/tmp` must be written `/private/tmp`. Then it renders the file (next section).
6. **Store by content.** The file is named after the first 16 hex digits of the SHA-256 of its text: `compiled/<hash>.sb`. A file already there is reused only when it holds exactly that text, since a cut-off Seatbelt file can still load and leave out every rule after the cut. Otherwise the text is written to a temporary file (mode `0600`), synced, and renamed into place. Older files are left where they are: sessions started under them still name them.
7. **Wrap** (`Backend::wrap`). The session runs `/usr/bin/sandbox-exec -f <file> <program> <args>` with an emptied environment (design §5). Two values that differ between sessions are passed as parameters, not compiled in, so every session of a sandbox runs under one file:
   - `-D ENCLOS_TERMINAL=<device>`: the terminal the session runs in, for a session started in a terminal.
   - `-D ENCLOS_SERVICE=localhost:<port>`: the port where the runtime's service listens, for a session started while it listens (ADR 0028).

The session record keeps the snapshot and the compiled file it started under. `sandbox show` flags a session as needing a restart when that file differs from the one the active policy compiles to now.

Since the file is named by its content, a new file appears whenever any input to the text changes: a new snapshot, a new enclos version whose rules differ, a different proxy port, or a symlink that now resolves elsewhere. An upgrade that tightens enclos's own rules therefore reaches new sessions without a policy change (design §8, step 2).

## The Seatbelt file, section by section

`src/backend/seatbelt/compile.rs` writes the sections below in this order. Order matters: in Seatbelt's language the last rule that matches an operation decides it, so each deny that must hold whatever the policy grants comes after the allows it overrides. Every deny carries `(with message "enclos:<sandbox>")`, which the macOS unified log repeats, so a denial can be traced to its sandbox (design §5, Denials).

| # | Section | Rules | From the policy? |
| --- | --- | --- | --- |
| 1 | Header | `(version 1)`, `(deny default)` with the sandbox's tag, then `deny-default.sb`: what a sandbox may do on that baseline, each rule one a workload or a test needed or looked up ([ADR 0006](adr/0006-seatbelt-deny-by-default.md); [its evidence](../prototype/adr-0006/README.md) says which failed without it). Every section below narrows or grants as it did on milestone 1's `(allow default)`, which `ENCLOS_SEATBELT_BASELINE=allow-default` still compiles, only for tests that compare the two. | no |
| 2 | Writes | `(deny file-write*)`, then allow the sandbox home, each `filesystem.write` path, and the device files every runtime writes (`/dev/null`, `/dev/tty`, `/dev/fd/N`, …). | `filesystem.write` |
| 3 | Terminals | Deny every `/dev/ttysN`, then allow back only the session's own (the `ENCLOS_TERMINAL` parameter) and those the sandbox opens itself through `/dev/ptmx`; the sandbox may not issue itself the pty extension for another one. Then allow reading the home. | no |
| 4 | Sensitive paths | `(deny file-read* file-write*)` on every `filesystem.read_deny` path, after every allow above, so no write grant reopens one. An entry that holds the home (such as `~`) leaves the home out. | `filesystem.read_deny` |
| 5 | Folders that cannot move | `(deny file-write-unlink file-clone)` on the exact path of the home, each workspace, and each folder inside them that holds a deny-list entry. Deny rules match paths, so a renamed or cloned folder would carry a denied file to a path no rule names. Files and folders inside still work as usual. | `filesystem.write`, `filesystem.read_deny` |
| 6 | Network | The proxy port must be in enclos's range (41000 to 41999), or compiling fails. `(deny network*)`, then allow outbound TCP to `localhost:<proxy port>` only, and Unix sockets inside the home. With `listen = true`: allow binding TCP on any port, deny binding each of the 1000 proxy-range ports again (one rule a port, since Seatbelt has no ranges), and allow outbound to the `ENCLOS_SERVICE` port on 127.0.0.1. | `network.listen` only |
| 7 | Host services | `host-services.sb`, copied in with the sandbox's tag: LaunchServices, Apple Events, launchd jobs, preference writes, synthetic input and the pasteboard, login items, the Keychain services, DNS-SD, `TIOCSTI`, and signals outside the sandbox ([ADR 0016](adr/0016-seatbelt-blocks-host-service-delegation.md)). | no |
| 8 | enclos's own files | Deny writes under the data and config folders except the sandbox's own home; deny reads of `state.db`, `state.lock`, `audit.jsonl` and `config.toml` (each with every file whose name starts with it, such as `state.db-wal`) and of `run/`; deny reads inside other sandboxes' folders. Last but one, so no rule above overrides them. | no |
| 9 | The home and workspaces themselves | `(deny file-write-unlink file-write-create)` on the exact path of the home and each workspace: the sandbox may change what is inside, never remove, rename or replace the folder, which stays the one this file was compiled for. So a workspace must exist before the sandbox uses it. | `filesystem.write` |

`network.mode`, `network.allow`, `network.private` and `network.log` do not appear in the file: the proxy enforces them from the active snapshot.

A path is put in a rule between double quotes and never escaped: a path holding `"` or `\` is refused, by validation when the policy is stored and by the compiler again, since a mistake there would change the rule.

### Example

The policy of a sandbox `lab` for the user `alice`, with the built-in defaults, a workspace and one extra deny entry inside it:

```toml
[filesystem]
write = ["{home}", "~/work"]
read_deny_add = ["~/work/project/secrets"]
```

compiles to this file, shortened where marked with `…` (generated by `seatbelt::compile`; the home is listed twice in the write grants because the policy lists `{home}` and the compiler always adds the home, which Seatbelt accepts):

```scheme
;; enclos compiled policy for sandbox lab. Generated: edit policy.toml instead.
(version 1)
(deny default (with message "enclos:lab"))
;; ---- Deny by default (ADR 0006): what a sandbox may do
…
(allow process-fork)
(allow process-exec*)
(allow file-read*)
…
(allow mach-lookup
  (global-name "com.apple.system.opendirectoryd.membership")
  …
  (global-name "com.apple.trustd.agent")
  (global-name "com.apple.TrustEvaluationAgent"))
(allow ipc-posix-shm-read-data (ipc-posix-name "apple.shm.notification_center"))

;; ---- Writes: the sandbox home, granted workspaces and device files
(deny file-write* (with message "enclos:lab"))
(allow file-write*
  (subpath "/Users/alice/.enclos/sandboxes/lab/home")
  (subpath "/Users/alice/.enclos/sandboxes/lab/home")
  (subpath "/Users/alice/work")
  (literal "/dev/null")
  …
  (regex #"^/dev/fd/[0-9]+$"))

;; ---- Terminals: the session's own and those the sandbox opens, no other
(deny file-read* file-write* (with message "enclos:lab") (regex #"^/dev/ttys[0-9]+$"))
(deny file-issue-extension (with message "enclos:lab") (extension-class "com.apple.sandbox.pty"))
(allow file-read* file-write* (require-all (regex #"^/dev/ttys[0-9]+$") (extension "com.apple.sandbox.pty")))
(if (param "ENCLOS_TERMINAL")
  (allow file-read* file-write* (require-all (regex #"^/dev/ttys[0-9]+$") (literal (param "ENCLOS_TERMINAL")))))
(allow file-read* (subpath "/Users/alice/.enclos/sandboxes/lab/home"))

;; ---- Sensitive paths: neither read nor written, whatever a grant covers (ADR 0015)
(deny file-read* file-write* (with message "enclos:lab")
  (subpath "/Users/alice/.ssh")
  (subpath "/Users/alice/.gnupg")
  …
  (subpath "/Users/alice/work/project/secrets"))

;; ---- Writable folders that cannot move, so no rename or clone carries a denied path elsewhere
(deny file-write-unlink file-clone (with message "enclos:lab")
  (literal "/Users/alice/.enclos/sandboxes/lab/home")
  (literal "/Users/alice/work")
  (literal "/Users/alice/work/project"))

;; ---- Network: only the sandbox's proxy, and Unix sockets in its home (ADR 0007)
(deny network* (with message "enclos:lab"))
(allow network-outbound (remote tcp "localhost:41000"))
(allow network-bind network-inbound (local unix-socket (subpath "/Users/alice/.enclos/sandboxes/lab/home")))
(allow network-outbound (remote unix-socket (subpath "/Users/alice/.enclos/sandboxes/lab/home")))

;; ---- Host services (design §5, ADR 0016)
(deny lsopen (with message "enclos:lab"))
…
(deny signal (with message "enclos:lab"))
(allow signal (target same-sandbox))

;; ---- enclos's own files, whatever the policy says (ADR 0010)
(deny file-write* (with message "enclos:lab")
  (require-all (subpath "/Users/alice/.enclos") (require-not (subpath "/Users/alice/.enclos/sandboxes/lab/home"))))
(deny file-read* (with message "enclos:lab")
  (regex #"^/Users/alice/\.enclos/state\.db")
  (regex #"^/Users/alice/\.enclos/state\.lock")
  (regex #"^/Users/alice/\.enclos/audit\.jsonl")
  (regex #"^/Users/alice/\.enclos/config\.toml")
  (subpath "/Users/alice/.enclos/run"))
(deny file-read* (with message "enclos:lab")
  (require-all (subpath "/Users/alice/.enclos/sandboxes") (require-not (literal "/Users/alice/.enclos/sandboxes")) (require-not (subpath "/Users/alice/.enclos/sandboxes/lab"))))

;; ---- The home and each workspace themselves: never removed, renamed or replaced
(deny file-write-unlink file-write-create (with message "enclos:lab")
  (literal "/Users/alice/.enclos/sandboxes/lab/home")
  (literal "/Users/alice/work"))
```

## The bubblewrap file

`src/backend/bubblewrap/compile.rs` is pure and writes one JSON file, `compiled/<hash>.json`, from the policy and the `SandboxContext`. A bubblewrap sandbox compiles to it, and `wrap` (`src/backend/bubblewrap/wrap.rs`) reads it at each launch; the [design](design.md) (§5, §15) says what it holds and which cases stay open. `bubblewrap` holds bubblewrap's arguments in the order `wrap` joins them, which the design gives with its reason: `wrap` makes `root_masks`'s `denied` from what the home holds at that launch, binds each file enclos staged in the sandbox's `installers/` that the launch reads (read-only, at its own path), binds each of `unmovable` on itself, masks `in_sandbox_home` and `in_workspace`, which a later `--bind` would uncover, then seals each folder it made and each of `sealed` with `--remount-ro`.

| Field | Holds |
| --- | --- |
| `bubblewrap.root` | `--ro-bind / /` |
| `bubblewrap.root_masks` | `home`, the user's; `denied`, for a tmpfs on each folder holding one, made from what the home holds at each launch, with its other entries bound back; `denied_elsewhere`, each masked over the `/` bind |
| `bubblewrap.mounts` | devices, `/proc`, the sandbox's own tmpfs, the protected folders outside the user's home, the writable binds, what is bound read-only |
| `bubblewrap.grant_masks` | `unmovable`, the folders above the masks below, each bound on itself before them; `in_sandbox_home` and `in_workspace`, each masked after its folder's bind, whether or not it exists; `workspaces`, as written, which `wrap` resolves at each launch to mask an entry a workspace reaches through a link |
| `bubblewrap.sealed` | the protected folders outside the user's home, each a tmpfs in `mounts`, sealed with `--remount-ro` once the staged files' mount points are made in them |
| `bubblewrap.options` | the namespaces, `--die-with-parent`, `--chdir`; no `--clearenv`, since `wrap` empties bubblewrap's own environment and sets the session's there, so no secret is on its command line |
| `landlock`, `seccomp` | what `enclos inside`, the program bubblewrap runs first, applies |
| `relay` | the proxy's port, as a session's variables name it, its socket, and the log its notices go to |
| `unenforced` | the fields nothing holds, and on which hosts |

The snapshot tests compile the `assistant` and `minimal` templates on every system, against `src/backend/bubblewrap/<template>.snapshot`, and a layout resolved as on Linux, with its data outside the home, a workspace and a deny entry in it, against `resolved-linux.snapshot`. Their fixture paths exist on no host. To change them, regenerate with `ENCLOS_WRITE_SNAPSHOTS=1 cargo test bubblewrap` and read the difference: it is the change to what a sandbox may do. The two are the same today, since the templates differ only in what the proxy enforces.

## When a change reaches a sandbox

| Change | New sessions | Sessions already running |
| --- | --- | --- |
| `network.allow`, `network.private`, `network.mode` | the new active snapshot | at once: the proxy reads the active snapshot for each new connection |
| `filesystem.*`, `network.listen`, secrets, `resources` | a new compiled file or the new grants and limits, once the change is active: while sessions run, it waits as the pending policy | keep the file they started with until `policy apply` restarts them; `sandbox show` flags them when the active policy compiles to another file than the one they started with |
| A new enclos version with changed compiler rules | a new compiled file, from the same snapshot | keep the file they started with |
| A new enclos version with a changed template or built-in defaults | nothing until a command stores a new snapshot, which lists the change | nothing |

A change to the filesystem rules, `listen`, the secrets or the limits reaches running sessions only through `policy apply`, or the change made with `--yes`; `sandbox restart` restarts them under the active policy, leaving a pending change waiting. After an upgrade, `policy refresh` resolves the active policy's `policy.toml` again against the new templates, defaults and adapter, and lists what that changes before applying it; until then, or until another command stores a new snapshot (which lists the change), nothing changes. `policy rollback --to <version>` makes an earlier snapshot active again as a new version, through the same restart rules.

## Errors

| Message starts with | Stage | Cause |
| --- | --- | --- |
| `cannot read the <layer> policy` | resolve | TOML that does not parse, an unknown key, or a section this build does not enforce |
| `unknown template` | resolve | `extends` names a template this build does not ship |
| `a template cannot extend another` | resolve | a template layer sets `extends` |
| `names no template` | resolve | the sandbox's `policy.toml` has no `extends` |
| `the <runtime> adapter's layer may only add network destinations` | resolve | an adapter's layer sets more than `allow_add` and `listen` |
| `refused by policy:` | validate | every problem is a refusal (exit 2) |
| `the policy is not valid:` | validate | at least one entry is malformed |
| ``sandbox `<name>` uses the <backend> backend, which this host cannot run`` | compile | the sandbox's backend is not in this build or does not run on this host |
| ``the home of sandbox `<name>` is not a real folder`` | compile | the sandbox home was removed, or replaced by a file or a symlink |
| ``the active policy of sandbox `<name>` no longer passes enclos's write checks`` | compile | a write check fails on the paths as they are now, usually a symlink changed after the policy was stored |
| `cannot compile the policy for seatbelt` | compile | a path the file cannot hold, or a proxy port outside 41000 to 41999 |

## Looking at a compiled policy

- `enclos policy show <sandbox>` prints the active snapshot: its version, short id, template, write grants, deny list and network.
- `ls ~/.enclos/sandboxes/<sandbox>/compiled/` lists the compiled files: the one the active policy compiles to, and those older sessions started under. `enclos sandbox show <sandbox>` says which sessions need a restart to run under the active one.
- `enclos policy test <sandbox>` compiles the active policy and runs the escape probes against it from inside the sandbox; `--host-services` also probes the host-service routes.
- `enclos policy show <sandbox> --compiled` prints what the active policy compiles to now, without writing it.
- `log stream --predicate 'sender == "Sandbox" AND eventMessage CONTAINS "enclos:<sandbox>"'` shows the denials as they happen (admin users only).

## Changing the compiler

- **A new built-in deny entry**: add it to `src/policy/templates/defaults.toml` and to the list in the test `the_defaults_hide_…` in `src/policy/mod.rs`, which guards against an entry being dropped, then regenerate `src/policy/resolved.snapshot` and `resolved-hermes.snapshot` with `ENCLOS_WRITE_SNAPSHOTS=1 cargo test` (the run writes them and passes; the next run compares). One list serves every system: an entry never depends on the host, so a policy resolves to the same thing on each.
- **A new policy field**: the model in `src/model/policy.rs`; the layer field and `apply` in `src/policy/file.rs`, and `beyond_destinations` if an adapter may not set it; `normalize` if it is a list; its checks in `src/policy/validate.rs`; its rules in `src/backend/seatbelt/compile.rs`, or the proxy if it is a network rule; how a change is worded in `differences` (`src/engine/policy.rs`); and its line in `policy show`. A field the backend cannot enforce is refused, never stored and ignored ([ADR 0009](adr/0009-refuse-what-cannot-be-enforced.md)).
- **A new rule**: place it by the last-rule-wins order above, and give each deny the tag. `src/backend/seatbelt/compile.rs` tests the order of the sections; `src/backend/seatbelt/tests.rs` runs rules under `sandbox-exec`. Security behavior counts as enforced only once a backend test or an escape probe shows it (CLAUDE.md).
- **A bubblewrap rule**: in `src/backend/bubblewrap/compile.rs`, keeping it free of the host, or in `proposed.rs` if it rests on a proposed ADR; then regenerate its snapshots (above).
- **A new backend**: implement `Backend::compile` and `Backend::wrap` in `src/backend/`. Start from `FsPaths::of`, which both the compiler and `policy test` use, so the probes check the paths the rules name.
