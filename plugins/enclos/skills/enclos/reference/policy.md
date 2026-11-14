# Policy: the templates and every setting

From `docs/policy-compilation.md` in enclos's repository, as of enclos 0.4.0. Read a sandbox's own policy with `enclos policy show <sandbox>`; widen it with `enclos policy allow`, or edit it with `enclos policy edit` and `enclos policy apply`.

## The templates

A sandbox starts from a template, named when it is created (`--template`) and kept in `extends`. Change `extends` with `enclos policy edit <sandbox>` to move it to another. `minimal` and `assistant` differ only in what the sandbox reaches on the network; `autonomous` also writes everywhere ([ADR 0058](https://github.com/victorbonnet/enclos/blob/main/docs/adr/0058-an-autonomous-template-writes-everywhere-but-keys.md), proposed):

| Can it… | `minimal` | `assistant` | `autonomous` (Seatbelt only) |
| --- | --- | --- | --- |
| Write to its own home | yes | yes | yes |
| **Write to other folders** | only those added | only those added | **everywhere you can, your own files included** |
| Change your shell's startup files (`~/.zshrc`, …) | no | no | no: read-only |
| Read your files, except sensitive paths | yes | yes | yes |
| Read or write sensitive paths, such as SSH keys | no | no | no |
| Write enclos's own files or its program | no | no | no |
| Run programs, and install them in its home | yes | yes | yes, and anywhere it writes |
| Reach what its runtime needs, once installed | yes | yes | yes |
| **Reach the public web** | **only what is listed** | **yes, ports 80 and 443** | **yes, any port** |
| Reach other ports | only if listed | only if listed | yes |
| Reach a host on your local network | only if listed and in `private` | only if listed and in `private` | only if listed and in `private` |
| Reach your computer's own services or cloud metadata | no | no | no |
| Use your computer's services, such as opening apps or Apple Events on macOS or the session bus on Linux, or signal other processes | no | no | no |

- **`minimal`** reaches nothing until a runtime is installed, then only what that runtime needs and what you list. For Hermes that is its install sources and the ChatGPT subscription's hosts; another model provider's hosts need `enclos policy allow`. Use it when an agent should reach only what you name, such as one working on outside data through remote MCP servers: allow each server's host with `enclos policy allow`, then tell the runtime of it with its own commands.
- **`assistant`** adds any public address on ports 80 and 443, so any model provider works without a grant. Use it for personal agents that browse, research and call public APIs. It can send what it reads to a public website: for sensitive work, use an allowlist.
- **`autonomous`** is for an agent that looks after the host: sorting and moving your media, tidying folders, installing tools. It writes everywhere you can (`write = ["/"]`), except the sensitive paths, enclos's own files and program, and the read-only paths, by default your shell's startup files, since your next terminal would run what is written there. It reaches any public address on any port. Higher risk: nothing stops it changing or removing your own files, so keep backups, and anything your Mac later runs from a file it wrote, such as a program on your `PATH`, a Git hook or an app, runs outside the sandbox. Commands are not filtered: what `rm -rf` can remove is what the policy lets it write. `sandbox create` says so. Only the Seatbelt backend builds it: bubblewrap cannot keep a path unchanged inside a folder the sandbox writes yet, so it refuses a write grant of `/` and a read-only path inside a folder the sandbox writes. Narrow it in `policy.toml`: `write = [...]` to list the folders it may write instead, `read_only_add` to keep more paths unchanged, `public_ports = "web"` or `mode = "allowlist"` for the network.

Under every template, each connection goes through the sandbox's proxy and is logged, as long as enclos can write its state. A runtime may also ask to listen on TCP, as Hermes does. On macOS, anything in the sandbox can then serve your network; on Linux, only the sandbox's own sessions reach it, and you, through `enclos dashboard`. The allowed hosts of a runtime can be broad: Hermes's include `github.com` and `storage.googleapis.com`, which could carry data out.

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
| `extends` | `minimal`, `assistant`, `autonomous` (proposed) | Required. The template this policy builds on ([the templates](https://github.com/victorbonnet/enclos/blob/main/docs/policy-compilation.md#the-templates)). |

**`[filesystem]`.** A path starts with `/`, `~`, `{home}` or `{tmp}`, and may not hold `"` or `\`. While sessions run, a change waits as the pending policy until `enclos policy apply` restarts the sandbox into it.

| Setting | Accepts | Default | Notes |
| --- | --- | --- | --- |
| `write` | a list of paths | `["{home}"]`; `autonomous` is `["/"]` | Replaces the folders the sandbox may write. The home stays writable either way. `/` grants the whole filesystem but `/dev` (proposed in [ADR 0058](https://github.com/victorbonnet/enclos/blob/main/docs/adr/0058-an-autonomous-template-writes-everywhere-but-keys.md)), with enclos's own files and program, the deny list, `read_only` and every link on the way to them still kept after it. Only Seatbelt builds that: bubblewrap cannot keep a path unchanged inside a folder the sandbox writes yet, so it refuses `/`, and a grant that holds enclos's program, for now. |
| `write_add` | a list of paths | none | Adds folders. Each must exist before the sandbox uses it. Refused: enclos's own folders, and a folder inside the home or another workspace. Malformed: a folder at or inside a deny-list path. |
| `write_remove` | a list of paths | none | Takes these entries out of the list the layers below set (the template's or the built-in defaults'), and leaves the rest inherited. Each is compared as written; one the list does not hold removes nothing. The phone's policy page writes it when the host's person removes an inherited folder ([ADR 0047](https://github.com/victorbonnet/enclos/blob/main/docs/adr/0047-the-hosts-person-manages-sandbox-policy-from-the-phone.md), proposed). |
| `read_deny` | a list of paths | the built-in sensitive list | Replaces the list, and must keep every built-in entry, so use `read_deny_add`. |
| `read_deny_add` | a list of paths | none | Adds paths the sandbox may neither read nor write. |
| `read_deny_remove` | a list of paths | none | Takes entries out of the list, as `write_remove` does. A built-in entry cannot go: the policy is then refused, as a `read_deny` that leaves one out is, and the phone shows built-in entries locked. |
| `read_only` | a list of paths | none; `autonomous` lists the shell's startup and logout files | Replaces the paths the sandbox may read but never change, remove, rename or create, although a write grant covers them, proposed in [ADR 0058](https://github.com/victorbonnet/enclos/blob/main/docs/adr/0058-an-autonomous-template-writes-everywhere-but-keys.md). Malformed: one holding a write grant, which could then change nothing. On bubblewrap, one inside a folder the sandbox writes is refused for now. |
| `read_only_add` | a list of paths | none | Adds to that list. |

There is no `read_only_remove`: a `read_only` entry the template sets goes only by replacing the list.

There is no `read` list ([ADR 0015](https://github.com/victorbonnet/enclos/blob/main/docs/adr/0015-broad-reads-narrow-writes.md)). Reads are open except `read_deny`, since agents and the tools they install read paths nobody can list upfront. Writes are closed except `write`, and a `read_deny` path refuses writes too; `read_only` keeps paths unchanged inside a grant as broad as `autonomous`'s ([ADR 0058](https://github.com/victorbonnet/enclos/blob/main/docs/adr/0058-an-autonomous-template-writes-everywhere-but-keys.md), proposed).

**`[network]`.** A change to `mode`, the lists or `log` applies at once, unless the same edit changes files, `listen`, secrets or limits: then it all waits as the pending policy while sessions run, as a change to `listen` does. A destination is a full domain name or an IP address, or `*.domain` for its subdomains, with `:port` when it is not 443. A wildcard over everything (`*`) or a public suffix (`*.com`), and `localhost`, loopback or link-local addresses, are refused; a private address needs `private`, and a single-label name such as `intranet` is malformed.

| Setting | Accepts | Default | Notes |
| --- | --- | --- | --- |
| `mode` | `public`, `allowlist` | from the template: `assistant` and `autonomous` are `public`, `minimal` is `allowlist` | `public` reaches any public address on ports 80 and 443 (on any port with `public_ports = "any"`), as well as what is listed. `allowlist` reaches only what is listed. |
| `public_ports` | `web`, `any` | `web`; `autonomous` is `any` | The ports `public` mode opens to any public address, proposed in [ADR 0058](https://github.com/victorbonnet/enclos/blob/main/docs/adr/0058-an-autonomous-template-writes-everywhere-but-keys.md): `web`, 80 and 443, or `any`. Loopback, link-local and metadata addresses stay closed either way, and private ones open only per host through `private`. Outside `public` mode it opens nothing, and is stored as `web`. A runtime adapter may not set it. The proxy holds it, on either backend. |
| `allow` | a list of destinations | none | Replaces the list, the runtime adapter's endpoints too, so its install, login and model calls may stop working. Prefer `allow_add`. |
| `allow_add` | a list of destinations | none | Adds destinations, as `enclos policy allow` does. |
| `allow_remove` | a list of destinations | none | Takes destinations out of the list the layers below set, the template's or the runtime adapter's, compared as written, before the list is normalized, and leaves the rest inherited. The phone's policy page writes it when the host's person removes an inherited destination (ADR 0047, proposed). |
| `private` | a list of hosts | none | Replaces the list of hosts that may resolve to private addresses. Each must also be allowed. |
| `private_add` | a list of hosts | none | Adds to that list. |
| `private_remove` | a list of hosts | none | Takes hosts out of that list, as `allow_remove` does. |
| `log` | `metadata` | `metadata` | The only value: host, port, address, verdict, bytes and duration, never contents. |
| `listen` | `true`, `false` | `false`; the Hermes adapter sets `true` | Whether the sandbox may listen on TCP, on any port but the proxy ports. Leave it to the adapter: `false` here wins over it, and Hermes's gateway exits if it cannot listen. On bubblewrap, `false` is declared, not held: a listener in one session is reached by the sandbox's other sessions, never by your host's network, and each session's start says so ([ADR 0041](https://github.com/victorbonnet/enclos/blob/main/docs/adr/0041-listen-false-on-bubblewrap-runs-declared-and-said-at-each-start.md), [ADR 0057](https://github.com/victorbonnet/enclos/blob/main/docs/adr/0057-landlocks-tcp-bind-right-is-not-built.md)). |

**`[resources]`.** A limit is fixed when a process starts. While sessions run, a change waits as the pending policy until `enclos policy apply` restarts the sandbox into it. A limit the backend cannot enforce is refused when the policy is stored, whatever its value ([ADR 0033](https://github.com/victorbonnet/enclos/blob/main/docs/adr/0033-a-limit-the-backend-cannot-enforce-is-refused-outright.md)). `open_files` holds each process; `memory` and `cpu` hold the sandbox as a whole, its sessions and services together, on its systemd slice (design §7).

| Setting | Accepts | On Seatbelt | On bubblewrap |
| --- | --- | --- | --- |
| `open_files` | 16 to 1048576 | Enforced, on each process. Above macOS's own ceiling for a process (`kern.maxfilesperproc`), it is refused. | Enforced, on each process. |
| `file_size` | bytes, or `512K`, `100M`, `1G` | Refused. | Refused. |
| `cpu_seconds` | a number of seconds | Refused. | Refused. |
| `memory` | a size, written as `file_size` is, from `64M` | Refused. | Enforced, on the sandbox as a whole, with no swap past it. Where the host has no memory controller, as Raspberry Pi OS leaves it, it runs not applied, and only once you accept that with `--accept-unenforced memory`, which the audit log records ([ADR 0038](https://github.com/victorbonnet/enclos/blob/main/docs/adr/0038-a-memory-limit-the-host-cannot-hold-runs-unapplied-once-accepted.md)). |
| `cpu` | a number of cores with at most two decimals, from 0.01 to 1024, such as `0.5` | Refused. | Enforced, on the sandbox as a whole. |

**`[secrets]` and `[secrets.agents.<agent>]`.** Each grant maps a variable to `secret:<sandbox>/<name>`, a secret of this sandbox already stored with `enclos secret set`. A variable uses letters, digits and `_`, and not one enclos sets itself, such as `PATH`. While sessions run, a change waits as the pending policy until `enclos policy apply` restarts the sandbox into it.

| Setting | Accepts | Notes |
| --- | --- | --- |
| `env` | a table of grants | Replaces what the layers below grant every session and service of the sandbox. |
| `env_add` | a table of grants | Adds to them. |
| `agents.<agent>.env` | a table of grants | Replaces what one agent is granted. A bot's token goes here, never to the whole sandbox. |
| `agents.<agent>.env_add` | a table of grants | Adds to them. |

A variable granted to the whole sandbox cannot also be granted to an agent. An `[exec]` section is an error: no backend enforces rules on programs yet.

