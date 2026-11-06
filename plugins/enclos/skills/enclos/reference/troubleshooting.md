# enclos troubleshooting

Start with the two checks, which change nothing:

```bash
enclos doctor        # can each backend run here; does each sandbox's policy compile; secrets in plain text
enclos state check   # where enclos's records and the host differ
```

Both exit 1 when they find something, and say what to do. `enclos state repair` fixes what it can (`--dry-run` first) and names the rest.

## By exit code

| Code | What it means | What to do |
| --- | --- | --- |
| 1 | An error, or a check found something. | Read `error.message` (JSON) or the text; it usually names the next command. |
| 2 | Refused: a policy setting the backend cannot enforce, or a backend this host cannot run. Nothing changed. | Don't look for a way around it: enclos refuses what it cannot enforce. Tell the user what was refused and why. |
| 3 | Needs confirmation. | `--dry-run` to see the plan, tell the user, then `--yes`. |
| 125 | `enclos exec` failed itself, before or around its command. | Its own message is on stderr, prefixed `enclos:`. |

## Common situations

- **`enclos: command not found`.** Not installed, or `~/.local/bin` not on the PATH: try `~/.local/bin/enclos --version`, else install ([workflows](workflows.md#install-enclos)).
- **The state is from another build.** enclos refuses state an earlier build stored differently, and says so. The user removes the old sandboxes with the old build (`sandbox stop`, `sandbox rm`), or moves `~/.enclos` aside, then runs `enclos init`. State may not carry over between 0.x releases: the release notes say when.
- **`unknown template`.** A sandbox made from `mcp-only` under 0.1.0: edit its policy and set `extends = "minimal"`.
- **An agent cannot reach a site.** `enclos net denied <sandbox>`: if the destination is there and the user wants it, `enclos policy allow`. If it is not there, the agent did not try through the proxy, or reached it through the model provider's own tools.
- **A policy change did nothing.** It may be pending, waiting for sessions to restart: `enclos policy show <sandbox>` says so; `enclos policy apply <sandbox> --yes` restarts into it.
- **`policy edit` reopens an old edit, or refuses because `policy.toml` changed.** A refused or dry-run edit is kept in `policy.toml.edit`. `enclos policy discard <sandbox>` drops it.
- **A bot does not answer.** Its token must be granted under `[secrets.agents.<agent>]`, applied (`policy apply`) and the agent configured (`runtime configure ... --channel telegram --allow-user <id>`), with the sandbox started. `enclos logs <sandbox>` shows the gateway's view; `enclos doctor` names a `${VAR}` the policy does not grant.
- **An agent made inside the sandbox is missing from `agent list`.** It is reported as not tracked; `enclos agent add <sandbox>/<agent>` adopts it.
- **A service will not start.** `enclos logs <sandbox>`, then `enclos sandbox show <sandbox>`. A proxy socket path that is too long: set `ENCLOS_HOME` to a shorter folder, or use a shorter sandbox name.
- **Hermes's browser tools fail.** Chromium does not start in a sandbox yet: a known gap.
- **`policy test` says NOT READY.** Something got out. Do not start the sandbox's agents; tell the user the line it printed, and suggest opening an issue at https://github.com/victorbonnet/enclos/issues.

## Known gaps

From the release notes (https://github.com/victorbonnet/enclos/tree/main/docs/release-notes); read the latest ones there when they matter.

- **Threat model:** accidental damage by agents the user mostly trusts; not malicious code exploiting the kernel.
- **Platforms:** Apple silicon Macs in releases; Linux in development. Hermes is the only runtime.
- **Environment variables:** any process of the user's can read another's start-up environment, sandboxed or not, Apple's own programs aside. A Hermes gateway gets its secrets through a file, but a `connect` or `exec` session gets them as variables. Advise against keeping secrets in exported shell variables while sandboxes run.
- **Processes are visible:** a sandbox can list what runs on the host.
- **Agents share a sandbox's files:** isolation is per sandbox; a secret granted to one agent is kept apart from the others, not hidden from them.
- **Browser tools:** Chromium does not start in a sandbox.
- **Limits:** on Seatbelt, `open_files` is the only limit enclos can hold; the others are refused.
- **Programs:** a policy cannot say which programs may run; an `[exec]` section is refused.
- **A process that detaches carefully** (closes its descriptors, leaves its group and parent) is not found by `sandbox stop`. It keeps its sandbox restrictions, and `state check` names it when its program is in the sandbox's folder.
- **Network log:** a connection is logged as long as enclos can write its state.
- **Not notarized:** the macOS binary has no Apple Developer ID signature; the installer's download runs without a prompt, a browser download would be blocked.
