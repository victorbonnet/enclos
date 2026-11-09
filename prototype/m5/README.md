# OpenClaw on macOS (M5-02)

This disposable experiment runs every installer and OpenClaw command through a recorded enclos session with Seatbelt and the sandbox's proxy. It does not install a host OpenClaw service or reuse host runtime state. It starts from M5-01's host-state protection. Linux acceptance remains the final M5 step on the new host.

## Reproduce

Build enclos from this stack, then run:

```sh
ENCLOS_BIN=/absolute/path/to/enclos sh prototype/m5/probe.sh install
```

Keep the printed `M5_WORK_DIR`. Evidence stays beneath it; subsequent commands require it:

```sh
export M5_WORK_DIR=/private/tmp/e5.REPLACE
export ENCLOS_BIN=/absolute/path/to/enclos
sh prototype/m5/probe.sh inspect
sh prototype/m5/probe.sh exec agents add scout \
  --workspace "$M5_WORK_DIR/state/sandboxes/m5openclaw/home/.openclaw/workspaces/scout" \
  --non-interactive --json
```

The prototype needs roughly 1.2 GiB for the private Node/runtime and npm's download cache, in addition to build space. The upstream installer is downloaded as data into the test home, hashed, and executed only inside the sandbox with `--npm --runtime-only --no-onboard`. Its served version is not pinned, consistent with ADR 0029; record the actual version/hash on each run.

For a foreground gateway experiment, allow its listener with the normal policy editor. This is an explicit policy change: Seatbelt allows listening beyond loopback too, as ADR 0028 states.

```sh
export ENCLOS_HOME="$M5_WORK_DIR/state"
EDITOR="$PWD/prototype/m5/enable-listener.sh" "$ENCLOS_BIN" --yes policy edit m5openclaw
python3 prototype/m5/setup-gateway.py "$M5_WORK_DIR" "$ENCLOS_BIN"
sh prototype/m5/probe.sh exec gateway run --port 43002 --bind loopback
```

Set `ENCLOS_HOME="$M5_WORK_DIR/state"` for direct enclos commands such as `policy edit`. The setup helper generates a test-only token in the sandbox's protected outside-home `secrets/gateway.json`, mode `0600`, and uses native settings commands to save only its file SecretRef. It never places the value in launch arguments or environment. The helper intentionally refuses to replace an existing test token. The example port is a test candidate, not a reservation or proof of ownership: check it before use and corroborate the recorded process's listener. The production adapter assigns a separate port per sandbox.

This early prototype has no registered runtime service. Its gateway is an `exec` session, so enclos does not give another session its port. A second sandboxed gateway client is therefore not a production readiness test here; M5-05/06 provide that integration. A TCP listener alone does not establish authenticated RPC readiness.

Stop or remove only this experiment:

```sh
sh prototype/m5/probe.sh stop
sh prototype/m5/probe.sh remove
```

Removal retains the evidence directory. `setup-gateway.py` and `enable-listener.sh` are prototype helpers, not production setup paths.

## Observed on 2026-11-09

On macOS 27.2, build 26B123, arm64:

- The official installer completed inside Seatbelt through the enclos proxy: private Node 24.22.1 and OpenClaw 2026.11.2 (`b556fdf`). It reported native service refresh skipped because of runtime-only mode. The observed installer SHA-256 was `2218bac9796a5da99f6be8e7cc838420e282aca7897bea80a8f40dab0f6bfc3d`.
- Installation reached `nodejs.org` and `registry.npmjs.org` in the proxy log. This is an observed install endpoint set, not proof that every provider, optional tool or later release needs only those destinations.
- A fresh native roster selected implicit `main`. Native noninteractive creation of `scout` succeeded. The writer produced `agents.entries` with `main` and `scout`, explicit ownership and `agents.defaults.systemAgent.agentId = main`; this differs from older `agents.list` examples.
- The foreground gateway reached its native `ready` log in about 9.5 seconds with a file-backed auth reference outside its home. Its recorded session root held both `127.0.0.1:43002` and `[::1]:43002`; test-owned worker processes remained session members. No ownership broadening is needed for that listener.
- The generated token was absent from the gateway root's startup environment and ordinary runtime configuration. The protected file had mode `0600`. These checks reported booleans only, without publishing the token.
- `audit verify` reported 28 entries, an intact chain, no torn tail and no unfinished entries after these probes.

The checked-in results are a small sanitized record. Raw logs and test-only auth remain in the disposable experiment, not the repository.

## Remaining verification

The install/foreground results do not complete M5 acceptance. Still to verify through production interfaces: authenticated client/dashboard handoff; external supervision/restart; default deletion/adoption/partial-failure handling; per-agent provider/bot secrets and two-bot allowed-person routing; loaded channel plugin, separate conversation context, durable replay and scheduled delivery; real model replies; native question/approval exact receipts; and safe routine mutations. Native source findings remain in [the research note](../../docs/research/m5-openclaw-runtime.md).

Host state beyond default/development roots needs explicit literal deny entries, as [policy compilation](../../docs/policy-compilation.md) explains. Dangerous escape/member probes belong in disposable VMs/CI, not this development host. No Linux property was established by this run.
