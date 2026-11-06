# Policy: the templates and every setting

From `docs/policy-compilation.md` in enclos's repository, as of enclos 0.2.0. Read a sandbox's own policy with `enclos policy show <sandbox>`; widen it with `enclos policy allow`, or edit it with `enclos policy edit` and `enclos policy apply`.

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
| `extends` | `minimal`, `assistant` | Required. The template this policy builds on ([the templates](https://github.com/victorbonnet/enclos/blob/main/docs/policy-compilation.md#the-templates)). |

**`[filesystem]`.** A path starts with `/`, `~`, `{home}` or `{tmp}`, and may not hold `"` or `\`. While sessions run, a change waits as the pending policy until `enclos policy apply` restarts the sandbox into it.

| Setting | Accepts | Default | Notes |
| --- | --- | --- | --- |
| `write` | a list of paths | `["{home}"]` | Replaces the folders the sandbox may write. The home stays writable either way. |
| `write_add` | a list of paths | none | Adds folders. Each must exist before the sandbox uses it. Refused: enclos's own folders, and a folder inside the home or another workspace. Malformed: a folder at or inside a deny-list path. |
| `read_deny` | a list of paths | the built-in sensitive list | Replaces the list, and must keep every built-in entry, so use `read_deny_add`. |
| `read_deny_add` | a list of paths | none | Adds paths the sandbox may neither read nor write. |

There is no `read` list and no `write_deny` ([ADR 0015](https://github.com/victorbonnet/enclos/blob/main/docs/adr/0015-broad-reads-narrow-writes.md)). Reads are open except `read_deny`, since agents and the tools they install read paths nobody can list upfront. Writes are closed except `write`, so there is nothing to deny, and a `read_deny` path refuses writes too.

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

**`[resources]`.** A limit is fixed when a process starts. While sessions run, a change waits as the pending policy until `enclos policy apply` restarts the sandbox into it. A limit the backend cannot enforce is refused ([ADR 0033](https://github.com/victorbonnet/enclos/blob/main/docs/adr/0033-a-limit-the-backend-cannot-enforce-is-refused-outright.md)).

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

