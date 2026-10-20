#!/usr/bin/env bash
# Three Hermes sandboxes with different responsibilities, from CLI commands only:
# a manager on Telegram, a developer with GitHub and Supabase, and a community
# manager on a Telegram group with MCP tools only. See README.md.
#
# Safe to run again: it skips what exists and applies what is new, so run it
# once more after filling in another value of .env or after a login.

# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"

[ -x "$ENCLOS" ] || die "enclos not found: install it (bash install.sh --source .) or set ENCLOS in $ENV_FILE"
[ -f "$ENV_FILE" ] || note "no $ENV_FILE: tokens and endpoints are skipped (copy .env.example to .env)"

say "enclos"
run "$ENCLOS" init

say "Sandboxes: one per role, since the sandbox is the permission boundary"
for sandbox in "${SANDBOXES[@]}"; do
    if sandbox_exists "$sandbox"; then
        note "$sandbox exists"
    else
        # The only template today. `mcp-only` (milestone 2) would fit the community manager.
        run "$ENCLOS" sandbox create "$sandbox" --template assistant
    fi
done

say "Hermes in each sandbox (its own installer, run inside the sandbox: minutes and about 2.4 GB each)"
for sandbox in "${SANDBOXES[@]}"; do
    if runtime_installed "$sandbox"; then
        note "$sandbox: installed"
    else
        run "$ENCLOS" runtime install hermes --sandbox "$sandbox"
    fi
done

say "Network: what each role may reach, beyond what the Hermes adapter allows everywhere"
note "The adapter allows the model provider, its login and Hermes's install sources in every sandbox."
allow "$MANAGER" api.telegram.org
allow "$DEV" raw.githubusercontent.com codeload.github.com objects.githubusercontent.com \
    api.supabase.com supabase.com '*.supabase.co'
allow "$COMMUNITY" api.telegram.org
if [ -n "${COMMUNITY_MCP_URL:-}" ]; then
    allow "$COMMUNITY" "$(url_host "$COMMUNITY_MCP_URL")"
else
    note "no COMMUNITY_MCP_URL yet: the community manager has no MCP server to reach"
fi

say "Personalities: each sandbox's SOUL.md, written through the sandbox"
write_home_file "$MANAGER" .hermes/SOUL.md < "$HERE/souls/manager.md"
write_home_file "$DEV" .hermes/SOUL.md < "$HERE/souls/developer.md"
write_home_file "$COMMUNITY" .hermes/SOUL.md < "$HERE/souls/community.md"

say "Manager: Telegram, answering only the owner"
if [ -n "${MANAGER_TELEGRAM_BOT_TOKEN:-}" ]; then
    printf '%s' "$MANAGER_TELEGRAM_BOT_TOKEN" | hermes_set_stdin "$MANAGER" TELEGRAM_BOT_TOKEN
else
    note "skipped: MANAGER_TELEGRAM_BOT_TOKEN is empty"
fi
if [ -n "${TELEGRAM_USER_ID:-}" ]; then
    hermes_set "$MANAGER" TELEGRAM_ALLOWED_USERS "$TELEGRAM_USER_ID"
else
    note "skipped: TELEGRAM_USER_ID is empty, so the manager would answer nobody"
fi

say "Developer: a terminal inside the sandbox, GitHub and Supabase over HTTPS"
# Hermes's other terminal backends (docker, ssh, modal, ...) need host sockets or
# unlisted hosts, which the sandbox denies. `local` runs inside enclos's sandbox.
hermes_set "$DEV" terminal.backend local
if [ -n "${DEV_GITHUB_TOKEN:-}" ]; then
    printf '%s' "$DEV_GITHUB_TOKEN" | hermes_set_stdin "$DEV" GITHUB_TOKEN
    printf '%s' "$DEV_GITHUB_TOKEN" | hermes_set_stdin "$DEV" GH_TOKEN
    # Git over HTTPS with the token, in the sandbox's own ~/.gitconfig.
    printf '%s' "$DEV_GITHUB_TOKEN" | in_sandbox "$DEV" sh -c \
        'git config --global url."https://x-access-token:$(cat)@github.com/".insteadOf https://github.com/'
else
    note "skipped: DEV_GITHUB_TOKEN is empty"
fi
if [ -n "${DEV_SUPABASE_ACCESS_TOKEN:-}" ]; then
    printf '%s' "$DEV_SUPABASE_ACCESS_TOKEN" | hermes_set_stdin "$DEV" SUPABASE_ACCESS_TOKEN
else
    note "skipped: DEV_SUPABASE_ACCESS_TOKEN is empty"
fi
if [ -n "${DEV_SUPABASE_PROJECT_REF:-}" ]; then
    hermes_set "$DEV" SUPABASE_PROJECT_REF "$DEV_SUPABASE_PROJECT_REF"
fi

say "Community manager: Telegram for everyone, MCP tools only"
# Hermes's own setting, inside a home the sandbox can write: it is not an enclos
# boundary. enclos enforces the files and the network above (README, "What is proved").
hermes_set "$COMMUNITY" agent.disabled_toolsets \
    "[terminal, file, browser, code_execution, skills, cronjob, delegation, web, computer_use]"
if [ -n "${COMMUNITY_TELEGRAM_BOT_TOKEN:-}" ]; then
    printf '%s' "$COMMUNITY_TELEGRAM_BOT_TOKEN" | hermes_set_stdin "$COMMUNITY" TELEGRAM_BOT_TOKEN
else
    note "skipped: COMMUNITY_TELEGRAM_BOT_TOKEN is empty"
fi
if [ "${COMMUNITY_OPEN:-true}" = true ]; then
    hermes_set "$COMMUNITY" TELEGRAM_ALLOW_ALL_USERS true
elif [ -n "${TELEGRAM_USER_ID:-}" ]; then
    hermes_set "$COMMUNITY" TELEGRAM_ALLOWED_USERS "$TELEGRAM_USER_ID"
fi
# In a group, answer when mentioned or replied to, not to every message.
hermes_set "$COMMUNITY" TELEGRAM_REQUIRE_MENTION true
if [ -n "${COMMUNITY_GROUP_CHAT_ID:-}" ]; then
    hermes_set "$COMMUNITY" TELEGRAM_GROUP_ALLOWED_CHATS "$COMMUNITY_GROUP_CHAT_ID"
fi
if [ -n "${COMMUNITY_MCP_URL:-}" ]; then
    if ! in_sandbox "$COMMUNITY" hermes mcp add tools --url "$COMMUNITY_MCP_URL" --connect-timeout 30; then
        note "Hermes could not add the MCP server (is it up?). Later: enclos connect $COMMUNITY -- hermes mcp add tools --url $COMMUNITY_MCP_URL"
    fi
fi

say "Logins: Hermes's own device-code login, one per sandbox (each sandbox has its own Hermes home)"
for sandbox in "${SANDBOXES[@]}"; do
    if logged_in "$sandbox"; then
        note "$sandbox: logged in"
    elif [ -t 0 ] && [ -t 1 ]; then
        note "$sandbox: pick the provider (OpenAI Codex for a ChatGPT subscription), open the URL on this Mac, then pick the model."
        run in_sandbox "$sandbox" hermes model
    else
        note "$sandbox: not logged in. In a terminal: enclos connect $sandbox -- hermes model"
    fi
done

say "Escape probes: every probe must fail"
for sandbox in "${SANDBOXES[@]}"; do
    run "$ENCLOS" policy test "$sandbox"
done

say "Services: each sandbox's proxy and Hermes gateway under launchd, now and at each login"
for sandbox in "${SANDBOXES[@]}"; do
    if "$ENCLOS" sandbox list | awk -v s="$sandbox" 'NR > 1 && $1 == s' | grep -q running; then
        # Already running: restart so the gateway reads the settings above.
        run "$ENCLOS" sandbox restart "$sandbox"
    else
        run "$ENCLOS" sandbox start "$sandbox"
    fi
done

say "Done"
cat <<EOF
   enclos status                          what is here
   bash $HERE/check.sh                    what the boundaries hold
   enclos connect $DEV -- hermes          talk to the developer in this terminal
   enclos net denied <sandbox>            what a sandbox was refused; allow with enclos policy allow
   enclos logs <sandbox> -f               the gateway's log (Telegram, MCP)
EOF
