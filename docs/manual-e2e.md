# Manual end-to-end test

A walk through every enclos command and what it should do, to run by hand on a Mac before a release. Each step gives the commands, then what to expect; tick the box when it matches. Anything else is a finding: note the step, the command and its output.

It takes about an hour, a quarter of it Hermes's installs. It uses a throwaway enclos home, so your own `~/.enclos` and its sandboxes stay as they are, and it removes everything it made at the end. The steps that need no login, no bot and no logout were run on macOS 26.5.2 with the release build of commit 06ad972; what they print is quoted where it helps.

## 0. Before you start

You need:

- An Apple silicon Mac on macOS 15 or later, logged in at its screen (the services run under your login session).
- The build to test on your PATH: `cargo install --locked --path .` from a clone at the commit to release (the release archive is built only once the tag is pushed, after this test). `enclos --version` names it.
- A model provider account Hermes supports, for its login.
- Two Telegram bots made with [@BotFather](https://t.me/BotFather), each with its token, and your own Telegram user id (from [@userinfobot](https://t.me/userinfobot)).
- An editor: `policy edit` opens `$VISUAL`, else `$EDITOR`, else `vi`.

In every terminal you use for this test:

```bash
export ENCLOS_HOME="$HOME/enclos-e2e"   # every command below uses this home
```

Then, once:

```bash
enclos --version
enclos sandbox list                      # left from an earlier run of this test?
```

If an earlier run left sandboxes in this home, remove each first (`enclos sandbox stop <name>`, then `enclos --yes sandbox rm <name>`): that also removes their launchd job files and Keychain items, which deleting the folder would leave behind. Then:

```bash
rm -rf "$ENCLOS_HOME"                    # start clean
```

enclos names its launchd jobs and Keychain items after the home (`enclos.<8 hex>.…`), so this home's never touch your own install's. A terminal shows text; piped (`| cat`), the same commands print JSON (§13).

enclos never asks a question: a command that needs your confirmation, such as one that deletes something or ends a session you started, stops with exit 3 and says what it would do; run it again with `--yes` to do it, or with `--dry-run` to see the plan. The steps below show both.

## 1. Set up and look at an empty host

```bash
enclos init
enclos init                 # again
enclos doctor; echo "exit $?"
enclos status
enclos sandbox list
```

- [ ] `init` creates the folders, `state.db` and `audit.jsonl` under `$ENCLOS_HOME`, with seatbelt as the default backend; the second run creates nothing.
- [ ] `doctor` says seatbelt runs here, what it enforces (files and network yes; limits and tracking every process partly; programs no), and exits 0.
- [ ] `status` and `sandbox list` show no sandbox, without an error.

## 2. Sandboxes and templates

```bash
enclos sandbox create lab; echo "exit $?"           # no template
enclos sandbox create --help | grep -A3 template
enclos sandbox create lab --template assistant
enclos sandbox create scout --template minimal
enclos sandbox create tools --template mcp-only
enclos --dry-run sandbox create extra --template minimal
enclos sandbox list
enclos sandbox show lab
enclos policy show scout
cat "$ENCLOS_HOME/sandboxes/lab/policy.toml"
```

- [ ] Without `--template`, `create` is a usage error (exit 1) naming `--template`, and creates nothing; its help names the three templates.
- [ ] `lab`, `scout` and `tools` are created, each with its own proxy port; the dry run says `Would create sandbox extra`, and `extra` is not in the list.
- [ ] `sandbox show lab`: `created`, policy v1, `no sessions running`.
- [ ] `policy show scout` shows a network allowlist with nothing on it; `lab`'s `policy.toml` says `extends = "assistant"` and has empty `write_add`, `read_deny_add` and `allow_add` lists, which is where your changes go.

## 3. Hermes in a sandbox

```bash
enclos --dry-run runtime install --sandbox lab hermes
enclos runtime install --sandbox lab hermes          # about five minutes
enclos connect lab -- hermes -p default setup        # provider, login, model; skip its messaging sections
enclos audit | grep -i runtime
enclos doctor
```

- [ ] The dry run lists the 13 hosts it would allow, that `lab` may listen on TCP (ADR 0028), the installer it would download and record, and changes nothing.
- [ ] The install ends `Hermes is installed in sandbox lab (policy v2)`; `enclos audit` has `runtime installer lab` and `runtime installed lab hermes`, and the installer's SHA-256 is in the first one's summary.
- [ ] Setup runs in your terminal. When the login shows a URL and a code, open the URL in your browser on the Mac and enter the code. Skip Hermes's own messaging setup: a token Hermes writes to `~/.hermes/.env` makes `runtime configure` refuse (§9).
- [ ] `doctor` says `lab`'s next session compiles policy v2, and exits 0.

## 4. Agents

```bash
enclos agent add lab/main
enclos agent add lab/scout
enclos agent add lab/Bad_Name; echo "exit $?"
enclos agent list lab
enclos connect lab -- hermes profile create helper   # made inside, not through enclos
enclos agent list lab
enclos agent add lab/helper
enclos agent rm lab/scout; echo "exit $?"           # needs confirmation
enclos --yes agent rm lab/scout
enclos agent rm lab/helper --keep-data --yes
enclos agent list lab
```

- [ ] `agent list`: `lab/default  built in`, `lab/main`, `lab/scout`. `Bad_Name` is refused before anything runs (exit 1), with the naming rule.
- [ ] After `profile create`, both the end of the `connect` session (on stderr) and `agent list` say `lab/helper: Hermes has this agent; enclos does not track it`, with the command to track it.
- [ ] `agent add lab/helper` says `Tracked agent lab/helper, which Hermes already had`.
- [ ] `agent rm lab/scout` without `--yes` exits 3, saying it would delete the agent's files; with it, Hermes lists what it deletes, then `Removed agent lab/scout and its files`. With `--keep-data`, only the record goes, and `helper` is reported untracked again.

If you have your own Hermes, bring an agent from it. Its cron jobs come along and run from the sandbox once its gateway runs, beside your own Hermes's: export a profile without scheduled jobs, or remove them in the sandbox right after (`enclos connect lab -- hermes -p mine cron list`).

```bash
mkdir -p ~/exports && hermes profile export default -o ~/exports/mine.tar.gz
enclos agent add lab/mine --from ~/exports/mine.tar.gz
enclos connect lab -- hermes -p mine
```

- [ ] Imported inside the sandbox; `enclos audit` shows the archive's SHA-256; the agent answers with the sandbox's login.

## 5. Connect and exec

```bash
enclos connect lab                       # a shell: run `pwd; ls; exit`
enclos connect lab -- main               # talk to main; ask something that needs the web
enclos exec lab -- /bin/sh -c 'echo out; exit 7'; echo "exit $?"
echo piped | enclos exec lab -- /bin/cat
enclos exec nosuch -- /bin/ls; echo "exit $?"
enclos exec lab; echo "exit $?"
enclos --dry-run exec lab -- /bin/ls
```

- [ ] The shell starts in the sandbox's home (`$ENCLOS_HOME/sandboxes/lab/home`). The first `connect` also starts the sandbox's services, and says so.
- [ ] `main` answers.
- [ ] `exec` prints `out` and exits 7; `piped` comes back; an unknown sandbox and a missing command exit 125 with enclos's message on stderr; the dry run says `Would run /bin/ls in sandbox lab under policy v…`.
- [ ] Run `enclos exec lab -- /bin/sleep 60` in a second terminal: `enclos sandbox show lab` lists an `exec` session with its process; Ctrl-C ends it, and `show` no longer lists it.

## 6. Policy

Allow, at once:

```bash
enclos policy allow scout example.com
enclos exec scout -- /usr/bin/curl -sS -o /dev/null -w '%{http_code}\n' https://example.com
enclos exec scout -- /usr/bin/curl -sS -o /dev/null -w '%{http_code}\n' https://wikipedia.org
enclos net denied scout
```

- [ ] The allow is in force at once (policy v2). `example.com` answers `200`; `wikipedia.org` fails with `CONNECT tunnel failed, response 403`, and `net denied scout` lists it as `not-allowed`.

A change that waits, then applies. Keep `enclos exec lab -- /bin/sleep 120` running in a second terminal, then:

```bash
mkdir -p ~/enclos-e2e-work
enclos policy edit lab          # set: write_add = ["/Users/<you>/enclos-e2e-work"]; save, quit
enclos policy show lab | head -8
enclos policy diff lab
enclos policy apply lab; echo "exit $?"   # ends the sleep: needs confirmation
enclos --yes policy apply lab
enclos policy history lab
```

- [ ] The edit says `A change waits as the pending policy of sandbox lab`, since a session runs under the rules it changes; `policy diff` shows `let it write …/enclos-e2e-work`.
- [ ] `policy apply` without `--yes` exits 3, since it would end the `sleep` session you started; with it, it stops the sandbox, ending the `sleep` (its terminal says `ended by signal 15`), and the sandbox runs under the new version from then on; `history` lists every version, who made it and when.

Discard, rollback, refresh:

```bash
enclos exec lab -- /bin/sleep 120 &       # a session again
enclos policy edit lab                    # set write_add back to []
enclos policy discard lab
enclos policy show lab | head -8
kill %1; enclos sandbox stop lab          # nothing runs: a change is in force at once
enclos policy rollback lab --to 2
enclos policy history lab
enclos policy refresh lab
enclos --yes policy refresh lab
```

- [ ] `discard` drops the pending change; the folder is still writable in `policy show`.
- [ ] With `lab` stopped, `rollback --to 2` makes v2's policy a new version at once, listing what it takes back; `history` lists that new version (`--json` gives it `"restores": 2`). While sessions run, a rollback that changes their rules waits as the pending policy instead, as an edit does.
- [ ] `refresh` shows what resolving the policy again would change (usually nothing) and changes only with `--yes`.

Refusals. Each must change nothing; `refused` exits 2, input that does not parse exits 1:

```bash
enclos policy allow lab 127.0.0.1;        echo "exit $?"
enclos policy allow lab 169.254.169.254;  echo "exit $?"
enclos policy allow lab '*';              echo "exit $?"
enclos policy allow lab '*.com';          echo "exit $?"
enclos policy allow lab 'not a host';     echo "exit $?"
```

Then the refusals of an edit, one at a time. A refused edit is kept, and the next `policy edit` opens it again ("Continuing the edit kept in …"), refused lines included, so drop it each time:

```bash
enclos policy edit lab      # write_add = ["<the path echo $ENCLOS_HOME prints>"]
enclos policy discard lab
enclos policy edit lab      # add: [resources] then cpu_seconds = 60
enclos policy discard lab
enclos policy edit lab      # add: [resources] then memory = "1G"
enclos policy discard lab
enclos policy edit lab      # add: [resources] then open_files = 100000000
enclos policy discard lab
enclos policy edit lab      # add: [resources] then open_files = 256  (accepted)
```

Edit `policy.toml` only through `enclos policy edit`: saving the file in another editor records nothing, and neither `policy apply` nor a session sees it until `policy edit` does (`EDITOR=true enclos policy edit lab` records what the file holds as it is).

- [ ] Loopback, link-local, `*` and `*.com` are refused (exit 2), each saying why; `not a host` is not a host name (exit 1).
- [ ] Writing enclos's own home: refused, `would let the sandbox write enclos's own files`. CPU time: refused, a process may ignore SIGXCPU. Memory: refused, macOS refuses to set one. `open_files` above the Mac's ceiling: refused, naming the ceiling (`kern.maxfilesperproc`). Each exits 2 and keeps the edit for you.
- [ ] `open_files = 256` is accepted: a new version while `lab` is stopped, as it is after the rollback above (while sessions run, it would wait as the pending policy); `history` has no version for a refused change.

Escape probes:

```bash
enclos policy test lab
enclos policy test scout
```

- [ ] Both end `READY: no probe got out of sandbox …`, with how many probes were shown closed, one of them by Seatbelt itself, and none open. The inconclusive ones say why: folders macOS keeps your terminal out of, too.

## 7. Network

```bash
enclos connect lab -- main     # ask for the weather in three cities
enclos net log lab
enclos net log lab --since 10m
enclos net denied lab
```

- [ ] `net log` has a row per connection: host, port, address, bytes, never their contents; `--since` narrows it.

The proxy checks which server a TLS tunnel asks for. From inside `lab`, open a tunnel to one host and ask for another:

```bash
enclos exec lab -- /usr/bin/python3 -c '
import os, socket, ssl
host, port = os.environ["https_proxy"].rsplit("/", 1)[1].split(":")
s = socket.create_connection((host, int(port)))
s.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
print(s.recv(200).split(b"\r\n")[0])
try:
    ssl.create_default_context().wrap_socket(s, server_hostname="wikipedia.org")
    print("TLS went through: a finding")
except Exception as e:
    print("closed:", type(e).__name__)
'
enclos net denied lab
```

- [ ] `b'HTTP/1.1 200 Connection established'`, then `closed: SSLEOFError`; `net denied lab` lists `example.com` with reason `name-mismatch`, and `net log lab` shows the name asked for, `wikipedia.org`.

## 8. Secrets

```bash
enclos secret set lab/demo                       # type a value; it does not echo
printf 'other' | enclos secret set lab/piped
enclos secret list lab
enclos connect lab -- /usr/bin/true            # starts lab's services, so the grant below waits
enclos policy edit lab                           # add at the end:  [secrets]
                                                 #                  env = { DEMO = "secret:lab/demo" }
enclos --yes policy apply lab
enclos exec lab -- /bin/sh -c 'test -n "$DEMO" && echo "DEMO is set"'
enclos secret rm lab/piped; echo "exit $?"       # needs confirmation
enclos --yes secret rm lab/piped
enclos secret list lab
```

- [ ] `secret set` says where it stored the secret and that no session gets it until the policy grants it; `secret list` shows `not granted`, then `$DEMO` once granted, never a value.
- [ ] Granting it while `lab`'s services run waits as a pending change, since they started without it; `policy apply` restarts them into it (`policy edit --yes` does both at once). Then a session gets `DEMO` and prints `DEMO is set`.
- [ ] `secret rm` without `--yes` exits 3, since the value is kept nowhere else.
- [ ] The value is in your login Keychain: `security find-generic-password -s enclos.<8 hex> -a lab/demo` finds it (the hex is in the service names `sandbox show lab` prints, `enclos.<8 hex>.lab.gateway`); after `secret rm`, `lab/piped` is gone from both.

## 9. Telegram bots and agent settings

Two bots in `lab`, one for the built-in agent and one for `main`, each granted to its agent alone (ADR 0036). First give each agent a prefix, so a reply says which agent wrote it:

```bash
enclos connect lab -- /bin/sh -c 'echo "Start every reply with [default]." >> ~/.hermes/SOUL.md'
enclos connect lab -- /bin/sh -c 'echo "Start every reply with [main]." >> ~/.hermes/profiles/main/SOUL.md'
enclos secret set lab/telegram          # the first token
enclos secret set lab/main-telegram     # the second token
enclos policy edit lab                  # add at the end:
                                        #   [secrets.agents.default]
                                        #   env = { TELEGRAM_BOT_TOKEN = "secret:lab/telegram" }
                                        #   [secrets.agents.main]
                                        #   env = { TELEGRAM_BOT_TOKEN = "secret:lab/main-telegram" }
enclos --yes policy apply lab
enclos policy show lab | grep -A3 '^Secrets'
enclos secret list lab
enclos runtime configure lab --channel telegram --allow-user <your id>
enclos runtime configure lab/main --channel telegram --allow-user <your id>
enclos logs lab | grep -i telegram
```

- [ ] In the editor, put the first token under `[secrets]` first and save: it is refused, saying a bot's token goes under `[secrets.agents.default]`, and the editor opens again for you to move it.
- [ ] `policy show` lists `$DEMO = secret:lab/demo  (every session and agent)`, then `$TELEGRAM_BOT_TOKEN` twice, `(agent default)` and `(agent main)`; `secret list` gives `telegram` as `$TELEGRAM_BOT_TOKEN for agent default` and `main-telegram` as `… for agent main`.
- [ ] Each `configure` says `Agent lab/<agent> reads the secrets the policy grants it under [secrets.agents.<agent>]`, then that its Telegram bot is set up, its token read from `$TELEGRAM_BOT_TOKEN`, answering 1 user. Without `policy apply` first, it refuses until the grant is in force. (Run on a stopped sandbox, Hermes also prints `helper failed … no secrets applied` for each command: the agent's secrets file exists only while the services run. Harmless.)
- [ ] The gateway's log has two Telegram connections and no `same credential` refusal.
- [ ] Message each bot from your account: each answers, the first with `[default]`, the second with `[main]`. From an account not in `--allow-user`, neither does.
- [ ] While the gateway runs, `$ENCLOS_HOME/sandboxes/lab/secrets/` holds `.env`, `default.env` and `main.env`, each `-rw-------` in a `drwx------` folder, and only `main.env` holds the second token; after `enclos sandbox stop lab` the files are gone. (`sandbox start lab` again after checking.)
- [ ] Once the bots have answered, no file of this home holds a token but the secrets files: `grep -ral "<the part of a token after its colon>" "$ENCLOS_HOME" | grep -v /secrets/` finds nothing, for each token, the services' logs included.
- [ ] From another sandbox: `enclos exec scout -- /bin/cat "$ENCLOS_HOME/sandboxes/lab/secrets/main.env"` and `enclos exec scout -- /bin/ls "$ENCLOS_HOME/sandboxes/lab/home"` both say `Operation not permitted`.

Any other setting works the same way, a secret named only as `${VAR}`:

```bash
enclos runtime configure lab/main --set 'e2e.demo=${DEMO}'
enclos connect lab -- /usr/bin/grep -n e2e -A1 .hermes/profiles/main/config.yaml
enclos runtime configure lab/main --set 'e2e.token=${NOT_GRANTED}'; echo "exit $?"
enclos runtime configure lab/main --set 'e2e.token=12345:abcdef'; echo "exit $?"
enclos runtime configure lab/nosuch --set 'e2e.demo=${DEMO}'; echo "exit $?"
enclos --dry-run runtime configure lab/main --set 'e2e.demo=${DEMO}'
```

- [ ] The first says `Set: e2e.demo.`; the agent's `config.yaml` has `demo: ${DEMO}`, not the value.
- [ ] A variable the policy grants neither `main` nor the whole sandbox is refused; so is `e2e.token` with no `${…}`, which `looks like a secret`; so is an agent enclos does not track, with the `agent add` command to track it. Each exits 1 and changes nothing.
- [ ] The dry run lists the `hermes -p main config set …` commands it would run, and runs none.

## 10. Services

```bash
enclos sandbox show lab
enclos logs lab -f                         # Ctrl-C to stop
enclos connect lab -- /bin/sh -c 'echo "# e2e" >> ~/.hermes/config.yaml'
enclos logs lab | grep changed
enclos sandbox restart lab
enclos sandbox stop lab scout
enclos sandbox start lab scout
```

- [ ] `show` lists the proxy and gateway sessions with their processes, and both services `running (pid …)`.
- [ ] Changing `~/.hermes/config.yaml` inside the sandbox: the log says `~/.hermes/config.yaml changed: asked the gateway service to restart`.
- [ ] `restart`, then `stop` and `start` with two names, each say what they did per sandbox.
- [ ] Save your work in other apps (a logout quits them), then log out of the Mac and back in: `lab` and `scout` run again and both bots answer. After `enclos sandbox stop lab`, a logout and login leave it stopped.

## 11. State check and repair

```bash
enclos state check; echo "exit $?"
mkdir "$ENCLOS_HOME/sandboxes/stray"
mv "$ENCLOS_HOME/sandboxes/scout/policy.toml" /tmp/scout-policy.toml
enclos state check; echo "exit $?"
enclos --dry-run state repair
enclos state repair; echo "exit $?"
rmdir "$ENCLOS_HOME/sandboxes/stray"
enclos state check; echo "exit $?"
```

- [ ] The first check says `enclos's records match the host`, exit 0.
- [ ] The second names `scout`'s missing `policy.toml` (repair: write it again from the active policy's text) and the `stray` folder with no record (for you: `sandbox create stray` takes it up, or remove it), exit 1.
- [ ] The dry run names the repair it would make; `repair` makes it and leaves the folder to you (exit 1); after `rmdir`, the check matches again (exit 0).

With `lab` started, unload its gateway's launchd job by hand (the label from `sandbox show lab`):

```bash
launchctl bootout "gui/$(id -u)/enclos.<8 hex>.lab.gateway"
enclos state check lab; echo "exit $?"
enclos sandbox stop lab && enclos sandbox start lab
enclos state check lab
```

- [ ] The check says the service is installed and not loaded, and how to load it again (exit 1); after stop and start, the records match.

## 12. Audit

```bash
enclos audit
enclos audit --since 1h
enclos audit verify
cp "$ENCLOS_HOME/audit.jsonl" /tmp/audit-backup.jsonl
sed -i '' '3s/"/'"'"'/' "$ENCLOS_HOME/audit.jsonl"   # change one character of line 3
enclos audit verify; echo "exit $?"
enclos policy allow scout example.org; echo "exit $?"
cp /tmp/audit-backup.jsonl "$ENCLOS_HOME/audit.jsonl"
enclos audit verify
```

- [ ] `audit` lists every command that changed something, who ran it, and how it ended; `--since` narrows it; `verify` says the log is intact.
- [ ] After the edit, `verify` says line 3 was changed after it was written (exit 1), and a command that changes something refuses until the log is repaired, saying how; with the file put back, `verify` is intact again.

## 13. Output for scripts

```bash
enclos sandbox list | cat                 # piped: JSON
enclos --text sandbox list | cat          # piped, but text
enclos --json sandbox show lab
enclos --json sandbox show nosuch; echo "exit $?"
enclos --json sandbox start lab nosuch; echo "exit $?"
enclos --text audit | head -1
enclos --json logs lab | head -3
enclos --json exec lab -- /bin/sh -c 'echo hi; exit 3'; echo "exit $?"
```

- [ ] Piped, each command prints one JSON document with `"schema_version": 1`; `--text` keeps it readable; `--json` gives JSON in a terminal.
- [ ] An unknown sandbox: `{"error": {"exit_code": 1, "kind": "error", "message": "there is no sandbox named …"}}`, exit 1. With two names, one unknown, the same error and nothing started.
- [ ] `| head -1` ends quietly, with no panic message.
- [ ] `logs --json` prints a `{"line": …}` object per line; `exec --json` prints `hi`, then `{"schema_version":1,"session":{"exit":3,…}}` on stderr, and exits 3.

## 14. Isolation spot checks

Each of these runs in `lab` and must fail (the paths expand on your Mac, before enclos runs the command):

```bash
enclos exec lab -- /bin/ls "$HOME/.ssh"
enclos exec lab -- /bin/ls "$ENCLOS_HOME/sandboxes/scout/home"
enclos exec lab -- /usr/bin/touch "$HOME/Desktop/from-the-sandbox"
enclos exec lab -- /bin/cat "$ENCLOS_HOME/state.db" > /dev/null
enclos exec lab -- /usr/bin/curl -sS --noproxy '*' -o /dev/null https://example.com
enclos exec lab -- /usr/bin/curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:22
enclos exec lab -- /usr/bin/curl -sS --noproxy '*' -o /dev/null http://127.0.0.1:22
enclos exec lab -- /usr/bin/pbpaste > /dev/null; echo "pbpaste exit $?"
```

- [ ] `Operation not permitted` for the files; `Could not resolve host` without the proxy; `403` from the proxy for loopback; `Couldn't connect to server` for loopback without it; `pbpaste` exits 1. Nothing appears on your Desktop.

## 15. Remove everything

```bash
enclos sandbox stop lab scout tools
enclos sandbox rm lab; echo "exit $?"       # needs confirmation
enclos --yes sandbox rm lab
enclos --yes sandbox rm scout
enclos --yes sandbox rm tools
enclos status
launchctl list | grep "enclos\.<8 hex>\."
ls ~/Library/LaunchAgents | grep "enclos\.<8 hex>\."
security find-generic-password -s enclos.<8 hex> -a lab/telegram
security find-generic-password -s enclos.<8 hex> -a lab/main-telegram
rm -rf "$ENCLOS_HOME" ~/enclos-e2e-work; unset ENCLOS_HOME
```

- [ ] `sandbox rm` without `--yes` exits 3, naming the home and the secrets it would delete; with it, it removes them.
- [ ] `status` shows no sandbox; neither `launchctl list` nor `~/Library/LaunchAgents` has a job of this home; `security` no longer finds either bot's token (exit 44 each).

## Known gaps: not findings

These are stated in the design and the release notes, so a test that shows them is expected:

- Another process of yours can read a sandbox's start-up environment, and a sandbox can list your Mac's processes (design §5). Secrets reach Hermes's gateway through its secrets file instead.
- Hermes's browser tools do not start in a sandbox.
- CPU time, memory and file size limits are refused: Seatbelt cannot hold them.
- Agents of one sandbox share its files: an agent's secrets reach it alone, but another agent of the same sandbox can read its secrets file (ADR 0036). Isolation is per sandbox.
- Linux is milestone 3.
