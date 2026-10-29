# Milestone 3 prototype: the host survey and the bubblewrap sandbox

Throwaway scripts that answer the milestone 3 questions in `docs/design.md` §14 (issue #102). Nothing here is enclos code. The first part, M3-01, surveys the target hosts: Landlock and its ABI, unprivileged user namespaces and AppArmor, the bubblewrap each distribution packages, the cgroup controllers delegated to the user, and `systemd --user` at logout. The second, M3-02, builds a bubblewrap sandbox as the backend would and probes it: see [M3-02: the bubblewrap prototype](#m3-02-the-bubblewrap-prototype) below.

## Files (M3-01)

| File | What it does |
| --- | --- |
| `survey.sh` | Prints one `key: value` line per fact. **Read-only**: it reads `/sys`, `/proc`, the kernel's build configuration, package versions and logind's properties; it runs no bubblewrap, creates no namespace and changes nothing, so it is safe on any host. The Landlock ABI comes from `landlock_create_ruleset(NULL, 0, VERSION)`, which returns a number and restricts nothing. |
| `bwrap-check.sh` | Runs bubblewrap as the user as installed, then with an AppArmor profile that lets `/usr/bin/bwrap` alone make user namespaces, then with AppArmor's restriction off, restoring each setting. **Acts on the host**: refuses to run outside a GitHub-hosted runner. |
| `logout-check.sh` | Logs in over ssh to localhost, starts a `systemd --user` unit, logs out, and checks the unit and the user manager past logind's stop delay, without then with lingering. **Acts on the host** (installs sshd, changes lingering): refuses to run outside a GitHub-hosted runner. |
| `.github/workflows/host-survey.yml` | Runs the three on `ubuntu-latest` and `ubuntu-24.04-arm`, on a pull request that touches this folder or by hand, and writes their output to the job summary. It does not gate merges. |

## Results

Each cell says where it comes from: **measured (Raspberry Pi OS arm64)** (on the install described below), **documented** (a page or file fetched on 2026-10-29, listed under Sources), or **to measure** (by the CI job above, in a VM for what CI cannot show, or on Raspberry Pi OS for what needs its kernel). Nothing in a "documented" cell has been run.

The install measured: 64-bit Raspberry Pi OS (image "Raspberry Pi reference 2026-04-13", which reports itself as Debian 13 trixie in `os-release`), kernel `6.18.50+rpt-rpi-2712`, arm64. Measured with `survey.sh` and read-only commands only; bubblewrap was not run on it.

Ubuntu 24.04's x86_64 and arm64 builds have the same values for every setting below in the kernel configuration and the same package versions, so they share a column; GitHub's runners use Azure kernels with a configuration of their own, so they have theirs.

| | Ubuntu 24.04 (x86_64, arm64) | Debian 12 bookworm | Debian 13 trixie | Raspberry Pi OS (64-bit, arm64) | GitHub runners (`ubuntu-latest`, `ubuntu-24.04-arm`) |
| --- | --- | --- | --- | --- | --- |
| Kernel | to measure (VM) | to measure (VM) | to measure (VM) | `6.18.50+rpt-rpi-2712` (measured (Raspberry Pi OS arm64); `6.12.75` also installed) | `7.0.0-1017-azure` on x86_64, image 20261026.354.1 (documented [1]); `6.14.0-1017-azure` on arm64, 24.04.3 (documented [2], may lag the image) |
| Landlock built (`CONFIG_SECURITY_LANDLOCK`) | `y` on amd64 and arm64 (documented [3]) | `y` (documented [4]) | `y` (documented [5]) | **not built**: `# CONFIG_SECURITY_LANDLOCK is not set` in all four installed kernel configurations (`6.12.75` and `6.18.50`, `-2712` and `-v8`) (measured (Raspberry Pi OS arm64)) | to measure (CI: `survey.sh`) |
| Landlock in the default LSM list (`CONFIG_LSM`) | `landlock,lockdown,yama,integrity,apparmor` (documented [3]) | `landlock,lockdown,yama,loadpin,safesetid,integrity,apparmor,selinux,smack,tomoyo,bpf` (documented [4]) | as bookworm, plus `ipe` (documented [5]) | `CONFIG_LSM=""` (measured (Raspberry Pi OS arm64)) | to measure (CI) |
| Active LSMs (`/sys/kernel/security/lsm`) | to measure (VM) | to measure (VM) | to measure (VM) | `capability` only; no `lsm=` on the command line (measured (Raspberry Pi OS arm64)) | to measure (CI) |
| Landlock ABI | to measure (VM) | to measure (VM) | to measure (VM) | none: the call fails with `ENOSYS` (measured (Raspberry Pi OS arm64)) | to measure (CI) |
| Unprivileged user namespaces in the kernel | `CONFIG_USER_NS=y` (documented [3]) | `CONFIG_USER_NS=y`; Debian's `kernel.unprivileged_userns_clone` defaults to 1, allowed (documented [4], [6]); the bubblewrap package also sets it to 1 (`/usr/lib/sysctl.d/50-bubblewrap.conf`, measured (Raspberry Pi OS arm64, trixie's package)) | as bookworm (documented [5], [6]) | `CONFIG_USER_NS=y`, `max_user_namespaces` 16035; Raspberry Pi OS's kernel has no `unprivileged_userns_clone` sysctl (measured (Raspberry Pi OS arm64)) | to measure (CI) |
| AppArmor's restriction on unprivileged user namespaces | **on**: the `apparmor` package installs `/usr/lib/sysctl.d/10-apparmor.conf` with `kernel.apparmor_restrict_unprivileged_userns = 1` (documented [7]) | not set by Debian's `apparmor` 3.0.8 (documented [8]) | not set by Debian's `apparmor` 4.1.0, which installs the `unprivileged_userns` profile but no sysctl file (documented [8]) | none: AppArmor is built but not active (`apparmor.enabled=N`, not in the LSM list), and the sysctl does not exist (measured (Raspberry Pi OS arm64)) | the restriction is reported on, and `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` as the workaround (documented [9]); to measure (CI: `bwrap-check.sh`) |
| AppArmor rule for `/usr/bin/bwrap` | none installed: `bwrap-userns-restrict` is in the source's `extras` and not in `apparmor.install` (documented [7]); a profile in Ubuntu's own form (`flags=(unconfined) { userns, }`, as for `chrome`) is what `bwrap-check.sh` tries | not needed while the restriction is off | not needed while the restriction is off | not needed (AppArmor inactive) | to measure (CI) |
| bubblewrap runs as the user | expected refused while the restriction is on and no rule names it; to measure (VM) | to measure (VM) | to measure (VM) | not run; nothing measured stands in its way: user namespaces on, no AppArmor, `/usr/bin/bwrap` not setuid (`-rwxr-xr-x root`) (measured (Raspberry Pi OS arm64)); to measure (on Raspberry Pi OS) | to measure (CI: as installed, with a `userns` profile, with the restriction off) |
| bubblewrap package | `0.9.0-1ubuntu0.3` (noble-updates and -security) (documented [10]) | `0.8.0-2+deb12u1` (documented [11]) | `0.12.0-1~deb13u1` (documented [11]) | `0.12.0-1~deb13u1`, installed, from Debian's trixie archive (measured (Raspberry Pi OS arm64)) | noble's (documented [10]); the job installs it |
| cgroup controllers at the root | to measure (VM) | to measure (VM) | to measure (VM) | `cpuset cpu io pids`: **no `memory`**, which the firmware turns off (`cgroup_disable=memory` in the device tree's `bootargs`, not in `cmdline.txt`); the kernel has `CONFIG_MEMCG=y` (measured (Raspberry Pi OS arm64)). Raspberry Pi OS's kernel accepts `cgroup_enable=memory` to turn it back on (documented [12]; not tried) | to measure (CI) |
| Controllers delegated to the user (`user@.service`) | `Delegate=pids memory cpu` in systemd's unit (documented [13]) | to measure (VM) | `Delegate=pids memory cpu` (measured (Raspberry Pi OS arm64), trixie's systemd package) | `cpu pids` reach the user manager: `memory` is delegated but absent (measured (Raspberry Pi OS arm64)) | to measure (CI) |
| systemd | `255.4-1ubuntu8.18` on the x86_64 runner (documented [1]) | `252.39-1~deb12u2` (documented [14]) | `257.13-1~deb13u1` (documented [14]) | `257.13-1~deb13u1` (measured (Raspberry Pi OS arm64)) | as Ubuntu 24.04 |
| `KillUserProcesses` | `no`: built with `-Ddefault-kill-user-processes=false` (documented [15]) | `no` (documented [16]) | `no` (documented [16]) | `false`, and no `logind.conf` override (measured (Raspberry Pi OS arm64)) | to measure (CI) |
| `systemd --user` at the last logout | `user@.service` is kept after logout only for a lingering user (documented [17]); it stops `UserStopDelaySec` after the last session ends, 10 s by default (documented [17]); what happens to a sandbox's unit then: to measure (CI: `logout-check.sh`) | as Ubuntu (documented [17], systemd 257's manual; bookworm has 252); to measure (VM) | as Ubuntu (documented [17]); to measure (VM) | `UserStopDelayUSec` 10 s (measured (Raspberry Pi OS arm64)); what happens to a unit at logout, without and with lingering: to measure (on Raspberry Pi OS) | to measure (CI: without and with lingering) |
| glibc (for M3-21's oldest target) | `2.39-0ubuntu8.9` (documented [10]) | `2.36-9+deb12u14` (documented [11]) | `2.41-12+deb13u4` (documented [11]) | `2.41` (measured (Raspberry Pi OS arm64)) | as Ubuntu 24.04 |

### What this shows

- **Landlock is not in Raspberry Pi OS's kernel.** It is not active, and not even built: `CONFIG_SECURITY_LANDLOCK` is unset in every Raspberry Pi kernel installed (6.12 and 6.18, the `-v8` and `-2712` builds), so no `lsm=` boot option can turn it on. ADR 0004 asked for this check before the backend is built. Under ADR 0004 as written, the bubblewrap backend could not run on a stock Raspberry Pi OS. Decided since, in [ADR 0037](../../docs/adr/0037-landlock-where-the-kernel-has-it.md) (proposed): Landlock is applied wherever the kernel has it, and where it is missing the backend still runs, its writes held by bubblewrap's mounts alone and the seccomp filter unchanged; its capabilities declare the weaker execute control, a policy with an `[exec]` section is accepted there only with an explicit, audited acceptance and not applied, and `doctor` gives what is not enforced, the risk and the fix (design §5, Degraded controls on Linux). The same holds for a Landlock ABI older than the backend's rules need. That the mounts alone hold the writes is still to show (design §14).
- **The memory controller is off on Raspberry Pi OS** by the firmware's own boot arguments, so a session's cgroup cannot hold a `memory` limit there; `cpu` and `pids` are delegated. Decided since, in [ADR 0038](../../docs/adr/0038-a-memory-limit-the-host-cannot-hold-runs-unapplied-once-accepted.md) (proposed), amending ADR 0033: there a policy that sets `memory` is accepted only with an explicit, audited acceptance, runs with the limit not applied, and every start says so; `doctor` gives the fix.
- **The fix for the memory controller, checked against the kernel's source, untried.** `cgroup_disable=memory` comes from the firmware's device-tree boot arguments (`/proc/device-tree/chosen/bootargs`), not from `/boot/firmware/cmdline.txt`, whose contents follow them in `/proc/cmdline` (measured (Raspberry Pi OS arm64)), so there is nothing to remove from `cmdline.txt`. Raspberry Pi OS's kernels define `cgroup_enable=`, which turns a subsystem back on (`static_branch_enable` in `kernel/cgroup/cgroup.c`, on `rpi-6.12.y` at `5bd564aa` and `rpi-6.18.y` at `b3495ea4`; added by [12]), and parse it after the firmware's arguments, so adding `cgroup_enable=memory` to `cmdline.txt` and rebooting should bring the controller back. `cgroup_memory=1`, often suggested, is not a parameter of either kernel: the only one near it is `cgroup.memory=` in `mm/memcontrol.c`, which takes `nosocket`, `nokmem` and `nobpf` [18]. Where the controller is there but not delegated, a `Delegate=` drop-in for `user@.service` is the fix, needed only where its `Delegate=` leaves `memory` out; Debian 13's (measured (Raspberry Pi OS arm64), trixie's systemd package) and Ubuntu 24.04's [13] already delegate `pids memory cpu`.
- **Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor and ships no rule for bubblewrap**, so bubblewrap is expected to fail there as installed; whether a profile naming `/usr/bin/bwrap` is enough is what `bwrap-check.sh` tries on the runners. Debian turns neither the restriction nor a bwrap rule on.
- **The oldest bubblewrap among the targets is Debian 12's 0.8.0**, then Ubuntu 24.04's 0.9.0. Whether each has every option the backend uses waits for M3-02's list of options.

## To measure

- **In CI** (the `host-survey` workflow, both runners): every "to measure (CI)" cell. Its first run is the result for the runners, and the table and design §14 are updated from it.
- **In a VM** (Ubuntu 24.04 x86_64 and arm64, Debian 12 and 13): `survey.sh` for the "to measure (VM)" cells, then `bwrap-check.sh`'s steps by hand (it refuses outside a runner by design).
- **Without Landlock** (in a VM booted with Landlock left out of the active LSM list, then on Raspberry Pi OS): that bubblewrap's mounts alone refuse every write outside the home and workspaces (ADR 0037, design §14).
- **`doctor`'s fixes** (design §14): `cgroup_enable=memory` on Raspberry Pi OS, which needs a reboot; the `Delegate=` drop-in and `lsm=landlock,…` in a VM.
- **On Raspberry Pi OS** (they act on the host, so not on one in use): whether bubblewrap runs as an unprivileged user, and what a logout does to a unit, without and with lingering.

## Sources

Fetched on 2026-10-29.

1. GitHub Actions runner images, `images/ubuntu/Ubuntu2404-Readme.md` (image 20261026.354.1): <https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md>
2. GitHub partner runner images (arm64), `images/Ubuntu2404-Readme.md`: <https://github.com/actions/partner-runner-images/blob/main/images/Ubuntu2404-Readme.md>
3. Ubuntu noble kernel, `debian.master/config/annotations`: <https://git.launchpad.net/~ubuntu-kernel/ubuntu/+source/linux/+git/noble/plain/debian.master/config/annotations>
4. Debian kernel 6.1 (bookworm), `debian/config/config`: <https://salsa.debian.org/kernel-team/linux/-/raw/debian/6.1/bookworm/debian/config/config>
5. Debian kernel 6.12 (trixie), `debian/config/config`: <https://salsa.debian.org/kernel-team/linux/-/raw/debian/6.12/trixie/debian/config/config>
6. Debian's kernel patch `add-sysctl-to-disallow-unprivileged-CLONE_NEWUSER-by-default.patch` (`unprivileged_userns_clone = 1`), on both branches above: <https://salsa.debian.org/kernel-team/linux/-/raw/debian/6.12/trixie/debian/patches/debian/add-sysctl-to-disallow-unprivileged-CLONE_NEWUSER-by-default.patch>
7. Ubuntu's `apparmor` package, noble-updates: `debian/usr/lib/sysctl.d/10-apparmor.conf`, `debian/apparmor.install`, `profiles/apparmor.d/chrome` and `profiles/apparmor/profiles/extras/`: <https://git.launchpad.net/ubuntu/+source/apparmor/tree/?h=applied/ubuntu/noble-updates>
8. Debian's `apparmor` package, tag `debian/4.1.0-1`, `debian/apparmor.install` and `debian/` (no sysctl file): <https://salsa.debian.org/apparmor-team/apparmor/-/tree/debian/4.1.0-1/debian>; versions from <https://qa.debian.org/madison.php?package=apparmor>
9. actions/runner-images issue #10443, "ubuntu-24.04 Error during unshare(...): Operation not permitted" (closed), with the sysctl workaround; the PR to apply it in the image, #11489, was closed: <https://github.com/actions/runner-images/issues/10443>
10. Launchpad, published sources for `bubblewrap` and `glibc` in Ubuntu: <https://launchpad.net/ubuntu/+source/bubblewrap>, <https://launchpad.net/ubuntu/+source/glibc>
11. Debian madison for `bubblewrap` and `glibc`: <https://qa.debian.org/madison.php?package=bubblewrap>, <https://qa.debian.org/madison.php?package=glibc>
12. raspberrypi/linux PR #6524, "cgroup: Add cgroup_enable option" (merged 2024-12-09): <https://github.com/raspberrypi/linux/pull/6524>
13. Ubuntu's `systemd` package, noble-updates, `units/user@.service.in`: <https://git.launchpad.net/ubuntu/+source/systemd/plain/units/user@.service.in?h=applied/ubuntu/noble-updates>
14. Debian madison for `systemd`: <https://qa.debian.org/madison.php?package=systemd>
15. Ubuntu's `systemd` package, noble-updates, `debian/rules`: <https://git.launchpad.net/ubuntu/+source/systemd/plain/debian/rules?h=applied/ubuntu/noble-updates>
16. Debian's `systemd` package, `debian/rules` on the `debian/bookworm` and `debian/trixie` branches: <https://salsa.debian.org/systemd-team/systemd/-/raw/debian/trixie/debian/rules>
17. `logind.conf(5)` (`KillUserProcesses=`, `UserStopDelaySec=`) and `loginctl(1)` (`enable-linger`), systemd 257's manual pages, as packaged in Debian trixie and read on Raspberry Pi OS.
18. raspberrypi/linux `kernel/cgroup/cgroup.c` and `mm/memcontrol.c` on `rpi-6.12.y` (`5bd564aa`) and `rpi-6.18.y` (`b3495ea4`): <https://github.com/raspberrypi/linux/blob/rpi-6.18.y/kernel/cgroup/cgroup.c>, <https://github.com/raspberrypi/linux/blob/rpi-6.18.y/mm/memcontrol.c>
19. The kernel's Landlock documentation, `Documentation/userspace-api/landlock.rst` ("Boot time configuration": `lsm=landlock,[...]`): <https://github.com/torvalds/linux/blob/master/Documentation/userspace-api/landlock.rst>

## M3-02: the bubblewrap prototype

A bubblewrap sandbox built as the backend would build it (design §5, ADR 0004, ADR 0037), and probed: broad reads with the deny list not mounted, writes to the home and a workspace only, Landlock and seccomp applied by a small program run first inside, the relay from `127.0.0.1:<port>` to a proxy on a Unix socket, the host's Unix sockets, Hermes's installer and Chromium. Nothing here is enclos code; the compile step, the program run inside and the relay are drafts of M3-13, M3-14 and M3-09.

**Where it runs.** Every check acts on the host (it runs bubblewrap, makes user namespaces, plants files in the home, installs packages, changes an AppArmor setting), so `lib.sh` refuses to run anywhere but a GitHub-hosted runner, or a VM for the manual steps below: there `ENCLOS_PROTO_DISPOSABLE_VM=1` must be set and `systemd-detect-virt --vm` must name a hypervisor, so a machine that is not a VM is refused either way. The `bwrap-prototype` workflow runs the checks on `ubuntu-latest` (x86_64) and `ubuntu-24.04-arm` (arm64), on a pull request that touches this folder or by hand. Each check writes a Markdown result to `m3-results/`; the job shows them in its summary and uploads the folder as the artifact `m3-results-<runner>`.

### Files (M3-02)

| File | What it does |
| --- | --- |
| `compile.py` | The compile step: the prototype's policy (the user's home, the sandbox's folder, a workspace, the deny list) becomes bubblewrap's arguments, the Landlock rules and the seccomp filter, in one JSON file. Pure apart from listing the folders that hold a denied path. |
| `test_compile.py` | Tests of `compile.py` on a temporary folder: denied paths not mounted, the folders that hide them read-only after every mount, writes to the home and workspaces only, the namespaces, the seccomp list, a deny entry outside the home refused. Runs anywhere (`python3 -I prototype/m3/test_compile.py`), and first in the workflow. |
| `inside.py` | The program bubblewrap runs first inside: applies the Landlock rules where the kernel has Landlock (through its system calls, with ctypes), then the seccomp filter (libseccomp's Python binding, `python3-seccomp`), then starts the relay and runs the command. `--landlock off` and `--seccomp off` leave either out, to show what each adds. |
| `relay.py` | The relay: each TCP connection on `127.0.0.1:<port>` inside the sandbox forwarded to the proxy's Unix socket, and nothing else. |
| `unix-proxy.py` | The milestone 1 prototype's proxy (`../m1/proxy.py`) served on the sandbox's Unix socket: same allowlist, `--learn` mode and JSON log. |
| `sbx.sh` | Runs a command in the sandbox: compiles, runs bubblewrap, then `inside.py`. `SBX_LANDLOCK=off`, `SBX_SECCOMP=off`, `SBX_RELAY=1`, `SBX_NEW_SESSION=1`. |
| `probe.py` | The probes, each printing the probe, `ok` or the error's name, and a detail; run on the host as their control, then in the sandbox. Writes are undone, a ptrace attach is detached at once, and the only signal is signal 0. |
| `pty-run.py`, `table.py`, `lib.sh` | A terminal of its own for the TIOCSTI probe; the result tables; what the scripts share, the guard included. |
| `setup-runner.sh` | Installs bubblewrap and what the checks use, and finds the least setting that lets bubblewrap run under AppArmor (none, a `userns` profile for `/usr/bin/bwrap`, or the restriction off). |
| `sandbox-check.sh` | Files, programs and system calls, in five modes: the host; bubblewrap only; with seccomp but no Landlock (what ADR 0037 runs where the kernel has none); with Landlock but no seccomp; full. TIOCSTI also with `--new-session`. |
| `sockets-check.sh` | Every Unix socket the host lists (`/proc/net/unix`), named and abstract, connected to from the host and from the sandbox: the runner as it is, then with an X server (Xvfb), a session bus, GNOME Keyring, an ssh agent, a socket in the home and an abstract socket added. |
| `relay-check.sh` | curl, Python `urllib`, `httpx` and `requests`, pip, uv, git, Node `fetch` and npm through the relay, with no DNS in the sandbox, and a destination the allowlist leaves out. |
| `hermes-check.sh` | Hermes's installer in the sandbox through the relay and a proxy in `--learn` mode: endpoints, `sudo` or system packages, `hermes --version`. |
| `chromium-check.sh` | A headless Chromium (Hermes's, or Playwright's when Hermes left none) loading a page through the relay, with its own sandbox on and off. |
| `options-check.sh` | Whether Debian 12's, Ubuntu 24.04's and Debian 13's bubblewrap have every option the compiled arguments use, from each one's `bwrap --help` in a container of that distribution. |
| `.github/workflows/bwrap-prototype.yml` | Runs the above on both Ubuntu runners and uploads `m3-results/`. It does not gate merges. |

### Results

**No cell below holds a result yet.** "to measure (CI)" cells are filled from the `bwrap-prototype` workflow's artifacts once it has run; "to measure (VM)" cells need a disposable VM, and "to measure (Raspberry Pi OS)" a Raspberry Pi OS install not in use. A cell gets a value only from a run's output, with the run named.

| Question (design §14) | Check | `ubuntu-latest` (x86_64) | `ubuntu-24.04-arm` (arm64) | Elsewhere |
| --- | --- | --- | --- | --- |
| The setting bubblewrap needs on the runners | `setup-runner.sh` | to measure (CI) | to measure (CI) | Ubuntu 24.04 desktop: to measure (VM) |
| A denied path does not exist in the sandbox (ENOENT), the rest of the home reads | `sandbox-check.sh` | to measure (CI) | to measure (CI) | |
| Writes in the home and workspace work; the rest of the home, the checkout, `compiled/` and `run/` refuse (EROFS), full and without Landlock | `sandbox-check.sh` | to measure (CI) | to measure (CI) | |
| A file the sandbox leaves in its `/tmp` is not in the host's | `sandbox-check.sh` | to measure (CI) | to measure (CI) | |
| The home and workspace cannot be renamed from inside | `sandbox-check.sh` | to measure (CI) | to measure (CI) | |
| A program in the workspace: refused with Landlock, runs without (ADR 0037) | `sandbox-check.sh` | to measure (CI) | to measure (CI) | |
| The seccomp list refused (keyctl, bpf, perf_event_open, userfaultfd, mount, io_uring, namespaces), and what bubblewrap alone already refuses | `sandbox-check.sh` | to measure (CI) | to measure (CI) | |
| TIOCSTI refused by seccomp without `--new-session`; refused by `--new-session` alone | `sandbox-check.sh` | to measure (CI) | to measure (CI) | |
| No user namespace inside (`--disable-userns`, then seccomp) | `sandbox-check.sh` | to measure (CI) | to measure (CI) | |
| Processes outside hidden: signal 0, ptrace, another process's start-up environment | `sandbox-check.sh` | to measure (CI) | to measure (CI) | |
| The host's loopback, the network and DNS out of reach | `sandbox-check.sh` | to measure (CI) | to measure (CI) | |
| Host Unix sockets reachable from the sandbox, server install | `sockets-check.sh` | to measure (CI) | to measure (CI) | Debian, Raspberry Pi OS Lite: to measure (VM) |
| Host Unix sockets reachable from the sandbox, desktop install | `sockets-check.sh` (Xvfb, session bus, GNOME Keyring, ssh agent only) | to measure (CI, partial) | to measure (CI, partial) | a real desktop session (Wayland, PipeWire, the user's systemd manager, a graphical login): to measure (VM) |
| Abstract sockets out of reach | `sockets-check.sh` | to measure (CI) | to measure (CI) | |
| The clients through the relay, with no DNS; a destination not allowed refused | `relay-check.sh` | to measure (CI) | to measure (CI) | |
| Hermes's installer: endpoints, `sudo` or system packages, `hermes` runs | `hermes-check.sh` | to measure (CI) | to measure (CI) | |
| The device-code login and a model call through the relay | manual, below | cannot run in CI (needs an account) | cannot run in CI | to measure (VM) |
| Chromium with its own sandbox, and with `--no-sandbox` | `chromium-check.sh` | to measure (CI) | to measure (CI) | Hermes's browser tool driving it: to measure (VM) |
| Hermes, its installer, uv, Node and Chromium run under the seccomp filter | the three above, full mode | to measure (CI) | to measure (CI) | |
| Each distribution's bubblewrap has every option used | `options-check.sh` | to measure (CI) | to measure (CI) | |
| A kernel without Landlock: the mounts alone hold the writes, a program in the home runs | `sandbox-check.sh` without Landlock shows the mounts alone on a kernel that has it | to measure (CI) | to measure (CI) | a kernel without it: to measure (Raspberry Pi OS; or a VM booted with Landlock left out of `lsm=`) |
| What Landlock and seccomp refusals leave for the user to read | none yet | | | to measure (VM) |

### Manual steps for a VM: the login and a model call

These need an account, so they cannot run in CI. In a disposable VM (Ubuntu 24.04 or Debian 13, x86_64 or arm64), with this repository checked out:

1. `export ENCLOS_PROTO_DISPOSABLE_VM=1`, then `bash prototype/m3/setup-runner.sh`, which installs the packages and finds the AppArmor setting, and `bash prototype/m3/hermes-check.sh`, which installs Hermes in the sandbox's home (`~/.enclos/sandboxes/proto/home`).
2. Start the proxy in `--learn` mode on the sandbox's socket: `python3 -I prototype/m3/unix-proxy.py --socket ~/.enclos/sandboxes/proto/run/proxy.sock --learn --log login.jsonl &`
3. Open a shell in the sandbox, full mode, with the relay: `SBX_RELAY=1 prototype/m3/sbx.sh -- /bin/bash`. Its first lines say what `inside.py` applied.
4. In it, `export PATH="$HOME/.local/bin:$PATH"`, then the device-code login, as the milestone 1 prototype ran it: `hermes auth add openai-codex --no-browser`. Open the URL it prints on another machine and enter the code.
5. A model call: `hermes -z "Reply with exactly one word: ok" --provider openai-codex -m <a model the account offers>`.
6. Record, in the results table above: whether each step worked, the endpoints from `login.jsonl` (host, port, verdict), and whatever refused, never the code or a token.
7. Then the same in the mode without Landlock (`SBX_LANDLOCK=off`), and, for a desktop install, `bash prototype/m3/sockets-check.sh` from a graphical login.

### Draft: what M3-13 compiles

**Draft until measured.** This is what `compile.py` and `inside.py` produce; `compile.py` is the reference if the two disagree. Nothing in it is shown to hold until the results above are in.

**bubblewrap's arguments**, in this order (bubblewrap applies them in order):

| Arguments | Why |
| --- | --- |
| `--ro-bind / /` | Broad reads (ADR 0015). |
| for each folder that holds a denied path, from the home down: `--tmpfs <folder>`, then `--ro-bind <entry> <entry>` for each of its other entries (`--symlink` for a link) | The deny list not mounted: a denied path does not exist. An entry made on the host after the session starts does not appear in such a folder; the alternative, an empty tmpfs or `/dev/null` over each denied path, keeps the rest live but leaves the path there, empty. |
| `--dev /dev`, `--proc /proc` | The sandbox's own devices and, with its own PID namespace, its own processes. |
| `--tmpfs /tmp`, `--tmpfs /var/tmp`, `--tmpfs /run`, `--tmpfs /dev/shm` | Its own, empty temporary places; they hide `/run/user/<uid>` (the session bus, `systemd --user`, Wayland), the system bus, systemd-resolved, the Docker socket and `/tmp/.X11-unix`. |
| `--bind <sandbox home> <same>`, `--bind <workspace> <same>` | The only writable places besides the above. |
| `--ro-bind <sandbox>/run <same>`, `--ro-bind <sandbox>/compiled <same>` | The proxy's socket (connecting needs no write access to its mount, ADR 0004) and the compiled policy `inside.py` reads. M3-13 adds the sandbox's `secrets/` folder here, read-only, for this sandbox alone (ADR 0034). |
| `--remount-ro <folder>` for each tmpfs made to hide a denied path | They were writable while bubblewrap made mount points in them. |
| `--unshare-user --disable-userns` | A user namespace for the sandbox, and none made inside it. |
| `--unshare-pid --unshare-net --unshare-ipc --unshare-uts --unshare-cgroup-try` | Its own processes, an empty network (loopback only), IPC, host name and cgroup view. Whether a sandbox's sessions share one network and PID namespace is M3-03's question. |
| `--die-with-parent` | Ends with the session. |
| `--new-session` (option) | Its own session, no controlling terminal: closes TIOCSTI, and costs an interactive shell its job control. Measured with and without above. |
| `--clearenv`, `--setenv` for `HOME`, `PATH`, `TMPDIR`, `LANG`, `TERM`, the proxy variables (`HTTPS_PROXY`, `HTTP_PROXY` and lower case, to the relay), `NO_PROXY` empty, `NODE_USE_ENV_PROXY=1`, `ENCLOS_PROXY_SOCKET` | The emptied environment. |
| `--chdir <sandbox home>` | |

**Landlock rules**, applied by `inside.py` where the kernel has Landlock (ADR 0037). Every right of the kernel's ABI is handled (ABI 1's thirteen, `REFER` from ABI 2, `TRUNCATE` from 3, `IOCTL_DEV` from 5), so whatever no rule grants is refused:

| Beneath | Rights |
| --- | --- |
| `/` | read files, read folders |
| `/usr`, `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`, `/libx32`, `/opt`, `/snap` (those that exist), and the sandbox's home | read, execute |
| the sandbox's home, each workspace, `/tmp`, `/var/tmp`, `/dev/shm` | read, write files, make and remove files and folders, sockets, FIFOs and links, `REFER`, `TRUNCATE` (not execute in the workspaces and temporary places) |
| `/dev` | read, write files, `TRUNCATE`, `IOCTL_DEV` |
| `/proc` | read, write files (the sandbox's own processes) |
| scopes (ABI 6) | abstract Unix sockets and signals limited to the sandbox |

Not used: Landlock's network rights (the network namespace holds the network), and the Unix-socket right of ABI 9 (design §5), whose value the prototype does not set. Programs run from the home because the runtime installs itself there; a policy's `[exec]` section would narrow that.

**The seccomp filter**, applied by `inside.py` after Landlock; anything not listed is allowed, and a system call of another architecture's ABI (such as 32-bit x86 on x86_64) ends the process, libseccomp's default:

- refused with `EPERM`: `keyctl`, `add_key`, `request_key`; `bpf`, `perf_event_open`, `userfaultfd`; `mount`, `umount2`, `pivot_root`, `move_mount`, `open_tree`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr`; `setns`; `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `reboot`, `swapon`, `swapoff`, `acct`, `quotactl`, `quotactl_fd`, `ioperm`, `iopl`, `open_by_handle_at`, `uselib`; `io_uring_setup`, `io_uring_enter`, `io_uring_register` (seccomp does not see io_uring's operations). Calls not on an architecture (`ioperm`, `iopl` on arm64) are skipped, and `inside.py` says which.
- `ioctl` refused with `EPERM` when its request's low 32 bits are `TIOCSTI` (`0x5412`) or `TIOCLINUX` (`0x541C`).
- `unshare` and `clone` refused with `EPERM` when their flags hold any of `CLONE_NEWNS`, `CLONE_NEWUSER`, `CLONE_NEWPID`, `CLONE_NEWNET`, `CLONE_NEWIPC`, `CLONE_NEWUTS`, `CLONE_NEWCGROUP`, `CLONE_NEWTIME`.
- `clone3` refused with `ENOSYS`, since its flags are in memory seccomp cannot read; the C library then falls back to `clone`.
- `ptrace` is not refused: the PID namespace leaves nothing outside to trace (the probe tries a host process), and debuggers inside keep working.

The errno is a choice for M3-14: `EPERM` reads like the kernel's own refusals, so the probes tell the filter from bubblewrap by comparing the modes, not by the error.
