# ADR 0006: evidence for the Seatbelt baseline

The evidence [ADR 0006](../../docs/adr/0006-seatbelt-deny-by-default.md) asked for, gathered on macOS 26.5.2 (Apple Silicon) on 2026-10-22, and how. The ADR records the decision; this folder is how to run it again.

## Method

- Each workload ran through enclos itself, in sandboxes of a throwaway enclos home outside `~/.claude` and every other deny-list folder (a home under a denied folder makes `git` fail under either baseline). `ENCLOS_SEATBELT_BASELINE=allow-default` compiled the earlier baseline for the comparison; without it, enclos compiles `(deny default)` with [`deny-default.sb`](../../src/backend/seatbelt/deny-default.sb).
- [`trace.py`](trace.py) ran each command while a bounded `log stream` collected the denials tagged with the sandbox's name, then counted them by operation and argument. Before enclos compiled the new baseline, the first allowances came from a compiled policy edited by hand and run with `sandbox-exec`, and from `(allow <operation> (with report))` traces under `(allow default)`, read with a capped `log show`.
- An allowance went into the list only when a workload or one of enclos's tests failed without it: pseudo-terminals and `ioctl` came from the tests (a session's own terminal), the rest from the workloads. Signals need none: the host-service rules allow the sandbox's own.

## Workloads and results

| Workload | `(allow default)` | `(deny default)` |
|---|---|---|
| A shell, `ls`, Python with `ssl`, `git --version`, `curl` through the proxy | runs | runs, once the libinfo, `configd` and notification memory are allowed |
| `git clone` over HTTPS through the proxy | runs | runs |
| `enclos runtime install hermes` (its installer, `uv`, Python, Node, npm, ripgrep, ffmpeg, `agent-browser`, Chrome for Testing's download) | all 20 steps, 90 s | all 20 steps, 85 s, once `com.apple.trustd.agent` is allowed |
| `hermes --version`, `profile list`, `config get model`, `doctor` | the same output | the same output |
| `enclos agent add <sandbox>/main` (`hermes profile create`) | made | made |
| The gateway, started by launchd | runs, no error in its log | runs, no error in its log |

The gateway's `(allow default)` run used a build that passed `ENCLOS_SEATBELT_BASELINE` to the services it installs. enclos no longer does, so that run cannot be repeated with this switch: a service now always compiles `(deny default)`.
| `agent-browser open https://example.com` | Chrome cannot create its socket folder | Chrome exits before it starts |
| `enclos policy test` | READY: 72 closed, 10 inconclusive | READY: 72 closed, 10 inconclusive |
| Every test of enclos (real Seatbelt sessions, services, probes, limits) | passed before | passes, once pseudo-terminals and `ioctl` are allowed |
| `ps` | cannot run: it is setuid, which Seatbelt refuses under any policy | the same |

The 10 inconclusive probes read folders macOS's privacy protection hides outside the sandbox too (Mail, Messages, Safari, Contacts and the like), and the crontab, of which there was none. The probes that act on the host if a rule fails run only in CI, on its macOS 15 and macOS 26 runners, under both baselines: `every_escape_probe_fails_in_a_new_sandbox` under `(deny default)` and `every_escape_probe_fails_under_allow_by_default_too` under `(allow default)`. The allowances were gathered on macOS 26.5.2; macOS 15 runs the same tests on the same list.

Refused under `(deny default)`, and done without: `com.apple.SystemConfiguration.DNSConfiguration` and `com.apple.coreservices.launchservicesd` (Node), `com.apple.analyticsd` and `system-fsctl (_IO "A" 20)` (`codesign`, run by the installer), `mach-priv-task-port` on itself (Python). Refused under both: the deny list's paths (reads of their metadata by `hermes doctor` and the gateway), `com.apple.SecurityServer` (the keychain rules), and connections to `mDNSResponder` (names resolve through the proxy).

## Not shown

- What Chrome for Testing needs under `(deny default)`: it starts under neither baseline until the write rules let it create its folders (design §14).
- A model call, and the gateway answering on Telegram: both need a login these runs had not.
