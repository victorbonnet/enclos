---
status: proposed
---

# An `autonomous` template writes everywhere but keys and enclos's own paths

Supersedes, for the `autonomous` template only, the narrow writes of [0015](0015-broad-reads-narrow-writes.md) and the web ports of [0025](0025-public-web-by-default-for-assistants.md).

Some agents are there to look after the host itself: sort and rename the user's media, tidy folders, install and update tools with Homebrew, clean caches. Under `assistant` each of those folders has to be granted as a workspace first, and anything off ports 80 and 443 has to be listed. For such an agent, keeping it out of the user's files is not the point. Keeping it away from keys and credentials is. Users who want this agent would otherwise run it with no sandbox at all, losing the deny list, the logged proxy, the host-service rules and `sandbox stop`.

## Decision

A third shipped template, `autonomous`:

- **Writes:** everywhere the user can write (`write = ["/"]`), the user's own files and media included. `/dev` keeps the baseline's rules, so other terminals stay closed.
- **Still never writable:**
  - the sensitive deny list, which also refuses reads: SSH, cloud and Git credentials, keychains, browser data, password managers, `~/Library/LaunchAgents` and the user's systemd units;
  - the protected paths: enclos's own files and other sandboxes;
  - a new list of **read-only paths**, which the sandbox reads but cannot change. By default it holds the shell startup files (`~/.zshrc`, `~/.zshenv`, `~/.zprofile`, `~/.zlogin`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.config/fish`), since the user's next terminal would run what the agent wrote there outside the sandbox.
- **Network:** `public` mode on every port (`public_ports = "any"`), still through the sandbox's proxy, which logs every connection. Loopback, link-local and metadata addresses are never reachable, and private addresses only per host, as [0017](0017-proxy-connects-only-to-validated-addresses.md) says.
- **Unchanged:** the host-service denials of [0016](0016-seatbelt-blocks-host-service-delegation.md) (`open`, Apple Events, launchd jobs, the Keychain, signals outside the sandbox). The sandbox stays a set of processes that `sandbox stop` ends, with nothing left running on the host.

A sandbox's `policy.toml` overrides it as it overrides any template:
- `write` narrows the writes back to named folders;
- `read_only` replaces the read-only list, and `read_only_add` adds to it;
- `mode` and `public_ports` narrow the network;
- `read_deny_add` hides more.

Built-in deny-list entries still cannot be dropped. To allow a grant that holds the protected paths, they are denied after every write allow, as deny-list paths already are, rather than refused when the policy is stored.

Commands are not filtered. A sandbox sees file operations, not command lines, so `rm -rf /` is limited by what the policy lets the sandbox write, not by its text. Run as the user, it cannot remove system files. Under `autonomous` it can remove the user's own files.

## Considered options

- **`assistant` plus workspaces:** keeps writes narrow, but every folder must be granted before the agent uses it, and an agent sorting media touches many.
- **Blocking dangerous commands by pattern:** cannot be enforced. The same deletion has many spellings (`find -delete`, a script), and enclos never claims a protection it does not enforce ([0009](0009-refuse-what-cannot-be-enforced.md)).
- **Also opening host services:** would let the agent leave work running outside the sandbox, which `sandbox stop` could not end.

## Consequences

- Accidental damage to the user's files, which [0014](0014-threat-model-accidental-damage.md) names as the main thing enclos prevents, is not prevented in this template. Recovery comes from the user's backups. `enclos sandbox create --template autonomous` says so.
- Anything the host later runs from a file the sandbox wrote runs outside the sandbox. Examples include a program in a folder on the user's `PATH` (`/opt/homebrew/bin`, `~/.local/bin`), a Git hook or config, and an app in `/Applications`. The read-only list covers only the shell's startup files, and a policy adds others with `read_only_add`.
- A write allow on `/` followed by denials must be shown to keep every escape probe, terminal rule and deny-list probe closed on Seatbelt. On bubblewrap, read-only binds over the protected and read-only paths have to hold under a writable root. Landlock cannot carve them out of an allowed tree, so there the mounts alone would refuse those writes. Both are listed in design §14 until shown.
