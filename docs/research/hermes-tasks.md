# Hermes's kanban board, for the `tasks` capability

Read from Hermes's default branch at `8b4c5343` (2026-11-15), for [ADR 0067](../adr/0067-tasks-and-agent-activity-are-reported-not-controlled.md) (proposed). Source reading only: nothing here was run against a gateway (design §14).

## Where the work runs

- One board serves every profile: `kanban_home()` is `HERMES_KANBAN_HOME`, else Hermes's root, not a profile's `HERMES_HOME` (`hermes_cli/kanban_db.py:401-408`). The default board is `<root>/kanban.db`; named boards are `<root>/kanban/boards/<slug>/kanban.db` (`kanban_db.py:411-420`, `kanban_db_boards.py:122` `list_boards`).
- The dispatcher runs in a gateway (`gateway/kanban_watchers.py:257`, on by default, every 60 s: `kanban_watchers_dispatcher.py:49`), in one gateway per machine, chosen by a lock (`kanban_watchers.py:236-251`): not necessarily the assignee's.
- The worker it spawns runs no agent: `hermes_cli/kanban_worker_client.py` submits the claim to the assignee profile's gateway (`kanban.run`, `gateway/session_kanban.py:14-40`). **The task's turn runs as a session in the assignee's gateway**, where its channel plugin is loaded.

## Hooks are not a complete source

- `on_kanban_task_updated` fires from `assign_task`, `_set_task_override`, `edit_task` and the dashboard (`kanban_db.py:212-232`), with field names only. Claimed, spawned, exited, stale-claim and dispatch-tick hooks fire in the dispatching process (`kanban_db.py:2202`, `kanban_db_dispatch.py:2155,1343-1364`, `kanban_db.py:2423`, `kanban_db.py:243-275`). `kanban_task_completed` and `kanban_task_blocked` fire in whichever process completes or blocks it (`kanban_db.py:2743`, `3211`).
- Plugins load lazily in every Hermes process, the CLI included (`hermes_cli/plugins.py:982-1012`).
- No hook fires for a crash, timeout or orphan put back to `ready` (`kanban_db_dispatch.py:888`), giving up (`1476-1491`), `unblock_task` (`kanban_db.py:3557`), `archive_task` (`3789`), `promote_task` (`3478`) or `recompute_ready` (`2036`).

So a plugin cannot follow a task from hooks alone. Hermes's own notifier reads `task_events` above a cursor every 5 s (`gateway/kanban_watchers.py:60-121`); the enclos adapter does the same, read-only (a `mode=ro` URI, as `gateway/session_kanban.py:30` does: `kanban_db_connect.connect()` creates and migrates the database).

## What a task holds

`Task` (`kanban_db.py:595-640`): `id`, `title`, `body`, `assignee` (a profile name, normalized: `kanban_db.py:1022`), `status`, `created_by` (a profile name), `created_at`, `started_at`, `completed_at`, `result`, `consecutive_failures`, `last_failure_error`, `block_kind`, `session_id` (the creating session's `HERMES_SESSION_ID`, null from the CLI or dashboard), among others. `list_tasks(conn, *, assignee, status, …, include_archived=False)` (`kanban_db.py:1422`) and `get_task` (`1402`).

The chat a task was asked from is not on `tasks`: `kanban_create` subscribes it in `kanban_notify_subs (task_id, platform, chat_id, thread_id, …)` (`kanban_db.py:957-972`), which Hermes's notifier uses to wake the creator. A row with `platform = "enclos"` names the enclos conversation.

Statuses (`hermes_cli/kanban_workflow.py:111-142`): `triage`, `todo`, `scheduled`, `ready`, `running`, `blocked`, `review`, `done`, `archived`. A crash, timeout or stale claim puts the task back to `ready` and counts a failure; past the limit (2 by default, `kanban_db_dispatch.py:38`) it becomes `blocked` with a `gave_up` event. `done` can be reopened.

## The creating tool

`kanban_create` (`tools/kanban_tools.py:1328`) takes `title` and `assignee`, and answers JSON with `task_id` (`kanban_tools.py:1172`). `post_tool_call` gets `tool_name`, `args`, `result`, `session_id` and `conversation_id` (`model_tools.py:700-723`), but it runs in the creator's gateway, not the assignee's, so the adapter reads the subscription instead.

## Mapping

| Hermes | `tasks` |
| --- | --- |
| `triage`, `todo`, `scheduled`, `ready` (a retry included) | `queued` |
| `running` | `running` |
| `blocked`, `review` (both wait for someone) | `blocked` |
| `done` | `done`, its `result` as the summary |
| `archived` | dropped: the next `tasks` list leaves it out |

Hermes has no failed or cancelled state: work that gave up is `blocked`.
