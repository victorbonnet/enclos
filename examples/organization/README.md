# An organization of three sandboxes

An integration test of enclos's security model: three Hermes agents with
different responsibilities, each in its own sandbox, set up from CLI commands
only and checked from inside the sandboxes.

| Role | Sandbox | Talks to | May reach | May write |
| --- | --- | --- | --- | --- |
| Manager | `manager` | the owner, on Telegram (one allowed user) | the model provider, `api.telegram.org` | its own home |
| Developer | `dev` | you, through `enclos connect dev -- hermes` | the model provider, GitHub, Supabase | its own home (repositories cloned there) |
| Community manager | `community` | anyone, in a Telegram group and private chats | the model provider, `api.telegram.org`, the MCP server the developer hosts | its own home |

The developer's deliverable is a remote MCP server, for example a Supabase Edge
Function, and the community manager's only task-specific capability is that
server. The manager cannot reach the other two agents: enclos isolates and
governs agents and never routes work between them (design §1), so the owner
relays. What this test proves is the boundary between the roles, not
coordination across them.

Every agent is its sandbox's built-in `default` agent. Hermes runs one gateway
per home and it serves every agent of that home with the same Telegram bot,
secrets and policy, so one agent per sandbox is what gives each role its own
bot, its own tokens and its own allowlist (ADR 0003, 0021, 0022).

## Feasible today, with these substitutions

Checked against the current stack (`enclos status` and the built-in agent
included) and against the `lab` sandbox already on this Mac, where Hermes polls
`api.telegram.org` through its proxy under launchd and is logged in with an
OpenAI subscription.

| Needed | Design | Today | Used here instead |
| --- | --- | --- | --- |
| Telegram bot tokens, API tokens | `enclos secret set`, `[secrets] env` (milestone 2) | not implemented | Hermes's own `hermes config set KEY value`, run inside the sandbox, which writes the sandbox's `~/.hermes/.env`. The secret lives in that home only: other sandboxes cannot read it. |
| A community sandbox limited to MCP | the `mcp-only` template (milestone 2) | only `assistant` exists | `assistant` plus Hermes's `agent.disabled_toolsets` (no terminal, files, browser, code execution, skills, cron, delegation). enclos enforces the files and the network; the tool list is Hermes's setting. |
| Per-agent channel and MCP settings | `enclos runtime configure` | not implemented | Hermes's own commands through `enclos connect <sandbox> -- hermes ...`, as ADR 0024 intends. |
| A project folder for the developer | `--workspace` (milestone 3) | not implemented | the developer clones under its own home. |
| An MCP server on this Mac | a host-service forward (milestone 3.1) | not implemented | the server runs remotely, over HTTPS. Allowing it grants "remote fetching through that service" (ADR 0007). |
| The developer's terminal in a sandbox | | | Hermes's `local` terminal backend, which runs inside enclos's Seatbelt sandbox. Hermes's docker, ssh and cloud backends need host sockets or unlisted hosts and are refused. |

Each sandbox needs its own Hermes install (about 2.4 GB, a few minutes) and its
own device-code login, so three logins. Hermes's `models.dev` catalog and its
update checks are refused by default and appear in `enclos net denied`; nothing
here needs them.

## What is proved, and what is not

`check.sh` shows, from inside the sandboxes:

- every escape probe fails in each sandbox (`enclos policy test`);
- no sandbox reads another's Hermes configuration, nor enclos's state and audit log;
- each role opens tunnels only to its own services: the manager and community
  manager to Telegram but not Supabase, the developer to Supabase but not
  Telegram, the community manager alone to the MCP host, nobody to an unlisted
  site;
- the audit log is intact and holds every command of the setup.

Not proved, and worth saying so:

- **The community manager's tool list is Hermes's, not enclos's.** Its home is
  writable, so anything running there could edit `config.yaml`. With no terminal
  or file tool it has no way to, but the boundary enclos holds is files and
  network, and the `mcp-only` template with a program allowlist is still to come.
- **Hermes's install sources are open in every sandbox.** The adapter allows
  `github.com`, `pypi.org`, `registry.npmjs.org`, `storage.googleapis.com` and
  others under every template, since the installer needs them (ADR 0020). So the
  community manager can reach GitHub; `check.sh` lists it as a known gap.
- **Secrets are not in the Keychain.** Tokens sit in each sandbox's `.env`, like
  the runtime's own login (ADR 0022 flags this). `setup.sh` passes them to the
  sandbox on standard input, so they are not in the host's command line, but
  they are in the arguments of `hermes config set` inside the sandbox for the
  time it runs.
- **A Postgres connection does not go through the proxy.** The developer uses
  the Supabase CLI and HTTP APIs, not `psql`.
- **Whether `hermes config set`, `hermes mcp add` and `TELEGRAM_ALLOW_ALL_USERS`
  behave as expected inside the sandbox** has not been run yet. Telegram itself
  and the OpenAI login have (the `lab` sandbox). The first run of `setup.sh`
  settles the rest; what it finds belongs in design §14.

## Run it

Prerequisites: an Apple silicon Mac with enclos installed (`bash install.sh
--source .` from the checkout, or `cargo install --locked --path .`), two
Telegram bots from @BotFather, your Telegram user id (from @userinfobot), and,
when the developer has shipped it, the MCP server's URL.

```bash
cp examples/organization/.env.example examples/organization/.env   # ignored by git
$EDITOR examples/organization/.env

bash examples/organization/setup.sh       # creates, installs, configures, logs in, probes, starts
bash examples/organization/check.sh       # the boundaries, from inside each sandbox
```

`setup.sh` is safe to run again: it skips what exists and applies what is new.
Run it once more after filling in the MCP URL, which the developer produces
during the test. Logins are interactive: Hermes prints a URL and a code, you
open the URL on the Mac. Without a terminal, `setup.sh` prints the command for
each sandbox that is not logged in.

## The test

1. Message the manager bot on Telegram. Ask for a small MCP server for the
   community, say a tool that answers the current time in a city and a tool that
   lists the group's rules. The manager writes the task for the developer.
2. Give the developer that task: `enclos connect dev -- hermes`. It clones or
   creates a repository under its home, deploys the function to the Supabase
   project in `SUPABASE_PROJECT_REF`, and gives you the URL.
3. Put the URL in `.env` as `COMMUNITY_MCP_URL`, run `setup.sh` again: it allows
   the host for the community sandbox only and registers the server with Hermes.
4. In the Telegram group, mention the community bot and ask for the time in a
   city. It can answer only through the MCP tools. Ask it to run a command or
   read a file: it has no tool for that. Then look at the network:

```bash
enclos net log community        # Telegram, the model provider, the MCP host, nothing else
enclos net denied community     # what it tried beyond that
enclos net log dev              # GitHub and Supabase
enclos audit                    # every command above, in order
```

5. Ask the developer to change the server (a new tool) and redeploy; the
   community manager picks it up on its next MCP session, with no change to
   enclos's policy, since the host is the same.

While the manager is talking to you, `enclos sandbox show manager` lists its
gateway's session and the policy it started under; a message to the bot from
another Telegram account gets no answer.

## Clean up

```bash
bash examples/organization/teardown.sh          # asks before each removal
bash examples/organization/teardown.sh --yes
```
