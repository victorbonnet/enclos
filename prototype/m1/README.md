# Milestone 1 prototype: Hermes under Seatbelt and a proxy

Throwaway scripts that answer the milestone 1 questions in `docs/design.md` §14 (issue #5). Nothing here is enclos code. Results are from one Mac: macOS 26.5.2, Apple silicon, admin user, Hermes Agent 0.22.2 (stable).

Everything the prototype creates lives in `.work/` (gitignored): the sandbox home, the compiled policy, logs. The sandbox home is `.work/home`; Hermes's own home is `.work/home/.hermes`.

## Files

| File | What it does |
| --- | --- |
| `sb/*.sb` | Fragments of the compiled policy, concatenated in order by `sbx.sh`. Each says what was shown about it. |
| `sbx.sh` | Runs a command in the sandbox: compiled policy, environment pointed at the sandbox home, proxy variables. `SBX_WITHOUT="41 44"` leaves fragments out, `SBX_EXTRA_RULES` appends rules, `SBX_POLICY=none` uses plain `(allow default)`. |
| `shims/mktemp` | On the sandbox `PATH`: makes `mktemp` honour `TMPDIR` (see "System temp"). |
| `run-capped.sh` | Runs a sandboxed command with a time cap in its own process group, and signals only that group, from a leader that is still alive. Nothing found by searching is ever signalled. |
| `proxy.py`, `proxy.sh`, `allow.txt` | The CONNECT proxy: allowlist, or `--learn` to allow any public destination and log it. |
| `hermes-install.sh` | Runs the Hermes installer (read first, pinned by SHA-256) in the sandbox. |
| `gateway-test.sh` | Runs the gateway, capped, and a chat for a profile alongside it. |
| `login-reach.sh` | Starts the device-code login, captures the endpoints, stops at the cap (code redacted). |
| `report.sh` | Endpoints from the proxy log; Seatbelt denials from `log show` (capped). |
| `probes/clients.sh` | Python, uv, git, Node, npm and curl through the proxy with DNS denied. |
| `probes/browser.sh` | Headless Chromium in the sandbox, with and without its own sandbox. |
| `probes/unix-local.sh` | Bind and connect a Unix socket inside the sandbox home. |
| `probes/routes.sh`, `probes/probe.c` | Host-service escape probes. **Run only in a disposable macOS VM** (guarded). |
| `members.sh` | Member-tracking experiment. **Disabled** (see the warning in the file). |
| `trace-ops.sh` | Lists the Mach services (or another operation) a tool uses, from a capped `log show`. |

## Safety rules for running this on a real Mac

An earlier version of `members.sh` treated a refuted membership test as true and sent SIGTERM to most of the user's processes. Since then:

- Only process groups created by `run-capped.sh`, or the proxy pid recorded by `proxy.sh` (checked against its command line), are signalled.
- Logs are read with a capped `log show`, never a `log stream` into a file.
- Escape probes and member-tracking experiments run only in a VM.
- The installer runs with `--non-interactive --skip-computer-use`: no `hermes setup`, no `gateway install` (no launchd job), no computer-use driver.

## Findings

### Host-service routes (escape probes, run before the VM rule)

Each route was probed with and without its rule. These results predate fragments `31-local-unix.sb` and `48-signals.sb`, and should be re-run in the VM.

| Route | Rule that closes it | Shown |
| --- | --- | --- |
| LaunchServices (`open`) | `(deny lsopen)` | `open -g <url>` fails with -54. Denying the coreservicesd and launchservicesd lookups alone did not stop it. |
| Apple Events | `(deny appleevent-send)`, or denying the lookup of `com.apple.coreservices.appleevents` | Either rule alone: an event to Finder fails with -600. |
| launchd jobs | `(deny job-creation)` | `launchctl submit`, `bootstrap` and `load` fail. `(allow default)` already refuses them; an explicit `(allow job-creation)` opens them. |
| cfprefsd | `(deny user-preference-write)` | Without it, `defaults write` wrote the real `~/Library/Preferences` although `HOME` pointed elsewhere. |
| Keychain | read deny on `~/Library/Keychains`, or denying `com.apple.SecurityServer` | `security show-keychain-info` fails under either. A missing-item lookup is not a valid probe: it says "not found" either way. |
| SSH agent, Docker socket | `(deny network*)` plus the proxy-port allow | `connect()` refused. |
| DNS | `(deny network*)` (closes the `/var/run/mDNSResponder` socket) | `getaddrinfo` and `dscacheutil` fail. Denying `com.apple.dnssd.service` alone does not stop them; port 53 is closed too. |
| `at`, `crontab` | any Seatbelt policy | exec of setuid binaries fails with EPERM (`sudo` too). |
| Synthetic input, pasteboard | `44-input.sb` | Lookups refused and `pbpaste` fails. **Posting an event was not tested**; `CGEventSourceCreate` still succeeds. |
| Login items | `45-login-items.sb` | Only the lookups were shown refused. |

### Denials in the unified log

- `(with message "<tag>")` on a rule puts the tag in the denial, so lines can be attributed to a sandbox.
- `log stream --predicate 'sender == "Sandbox"'` showed the kernel's denial lines without sudo for an admin user. A non-admin user was not tested.
- `log show` (the persisted log) keeps sandboxd's violation reports for some operations (seen for `mach-lookup`), but **not** the kernel's file-write denials: a refused write was absent from it. A history of denials therefore needs a live, bounded consumer of the stream.
- In zsh, `log` is a builtin: call `/usr/bin/log`.

### Members (macOS)

- A child that calls `setsid` leaves the session's process group (shown).
- A per-sandbox marker checked with `sandbox_check(pid, ...)` is useless: on another pid it returned 1 for every process tried, sandboxed or not, `launchd` included (shown). Refuted.
- `hermes gateway run` without `--external-supervisor` spawns a detached replacement on an in-chat restart or update (its help text; not shown). enclos's service should pass the flag.

### Installing Hermes in the sandbox

- The installer respects `HOME`. Everything (checkout, uv, Python 3.14, node 26, npm, ffmpeg, ripgrep, agent-browser, Chrome for Testing, the venv) lands under `~/.hermes` in the sandbox home, 2.4 GB in all. It appends a `PATH` line to the sandbox home's `.zshrc` and `.zprofile`. It completed inside the compiled policy through the proxy, once the `mktemp` shim was in place.
- Endpoints the install needed (proxy in learn mode): `github.com`, `api.github.com`, `release-assets.githubusercontent.com`, `releases.astral.sh`, `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`, `nodejs.org`, `cdn.playwright.dev`, `storage.googleapis.com`, `ffmpeg.martin-riedl.de`.

### System temp

- `/usr/bin/mktemp` with no template, `-d` or `-t` ignores `TMPDIR` and writes in `_CS_DARWIN_USER_TEMP_DIR` (`/var/folders/../T`), as its man page says. The installer failed there. The `shims/mktemp` on the sandbox `PATH` fixes shell scripts.
- Foundation's `NSTemporaryDirectory()` also returns `/var/folders/../T` with `TMPDIR` set.
- Chrome for Testing (from Hermes's browser tools) did not start: it could not create its ProcessSingleton socket directory, with or without `--no-sandbox`. That fits the temp directory above, but the denial is not in the persisted log, so the cause is not confirmed. Granting writes there would put sandbox state in the host's shared temp folder, so it was not tried here. **Open:** whether the browser runs at all under the write rules, and whether it needs its own sandbox disabled.

### DNS denied, clients through the proxy

With the full compiled policy (no DNS), these all worked through `HTTPS_PROXY`: curl, Python `urllib`, `httpx` and `requests` (Hermes's venv), `uv pip compile`, `git ls-remote`, Node `fetch` with `NODE_USE_ENV_PROXY=1`, `npm view`. Node's `https.get` ignores the proxy variables and hung until the 60 s cap instead of failing.

### Profiles

- `hermes profile create <name>` makes `~/.hermes/profiles/<name>/` (config, `.env`, `SOUL.md`, skills) and a wrapper `~/.local/bin/<name>` that runs `hermes -p <name>`. A profile is selected with `-p <name>`, the wrapper, or `HERMES_HOME`. Shown.
- Logins (source and docs, **not yet shown**): a profile with no credential of its own for a provider reads it from the root `~/.hermes/auth.json`, and refreshes are written back there under a lock. `hermes -p <name> auth add <provider>` gives a profile its own login, which then shadows the root one. So one login per sandbox should serve every profile.

### Gateway

- **Hermes 0.22.2 runs one gateway per Hermes root, not per profile.** `hermes -p main gateway run` with no gateway running refuses (exit 78): "Exactly one gateway per host is the inbound process for every profile". The default profile's gateway serves every profile. `gateway.standalone: true` in a profile's config is a temporary compatibility shim. Shown.
- With no messaging platform, `hermes gateway run` starts, runs the cron scheduler for every profile (`default`, `main`, `research`), the kanban dispatcher and housekeeping, opens no TCP port, and on SIGTERM shuts down cleanly and exits 1 "so the service manager can revive the gateway". Shown.
- It needs Unix sockets under `HERMES_HOME` (a control socket, a loop-tick socket). `30-network.sb` refuses every bind; `31-local-unix.sb` allows binding and connecting inside the sandbox home (shown with `probes/unix-local.sh`). The path must also fit in 104 bytes: with the prototype's long home path, the bind failed with `AF_UNIX path too long`, and Hermes's fallbacks (`TMPDIR`, then `/tmp`) were too long or not writable. Because of that, `hermes -p main gateway run` beside the running gateway could not attach (exit 75, "has not published its served set").
- A chat for profile `main` ran alongside the gateway up to the point where it needs a model provider. A model call waits on the login.

### Hermes looking at the host

Inside the sandbox, `hermes gateway status` read the host's own `~/Library/LaunchAgents/ai.hermes.gateway.plist`: Hermes's launchd helper takes the home from the password database, not `$HOME`. It also listed the PIDs of the host's own Hermes gateway. Nothing was written. In response:

- `20-read-deny.sb` now denies `~/Library/LaunchAgents`;
- `48-signals.sb` allows signals only within the sandbox. Under `(allow default)`, a sandboxed `hermes gateway run --replace` could stop a host gateway.

Both rules compile, and signals inside the sandbox still work. Neither has been probed across the boundary yet (VM).

### Device-code login

`hermes auth add openai-codex --no-browser` inside the sandbox reached `auth.openai.com` through the proxy, and printed `https://auth.openai.com/codex/device` and a code. That was the only host contacted before the user's approval. The login was stopped at the cap; the code was never approved. The source names `auth.openai.com/oauth/token` for refresh and `chatgpt.com/backend-api/codex` for model calls; both are still to be seen in the proxy log after a real login.

## Logging in (the user runs this)

From a terminal on the Mac, in this folder:

```bash
./proxy.sh --learn                                         # proxy in learn mode (logs every endpoint)
./sbx.sh -- hermes auth add openai-codex --no-browser      # prints a URL and a code; open the URL, enter the code
```

This logs in the sandbox's root Hermes home, which every profile in it should share.
