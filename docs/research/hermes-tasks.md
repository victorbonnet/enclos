# Hermes's kanban board, for the `tasks` capability

Read from Hermes's default branch at `8b4c5343` (2026-11-15), for [ADR 0068](../adr/0068-tasks-and-agent-activity-are-reported-not-controlled.md) (proposed). Source reading only: nothing here was run against a gateway (design §14).

## Where the work runs

- One board serves every profile: `kanban_home()` is `HERMES_KANBAN_HOME`, else Hermes's root, not a profile's `HERMES_HOME` (`hermes_cli/kanban_db.py:401-408`). The default board is `<root>/kanban.db`; named boards are `<root>/kanban/boards/<slug>/kanban.db` (`kanban_db.py:411-420`, `kanban_db_boards.py:122` `list_boards`).
- The dispatcher runs in a gateway (`gateway/kanban_watchers.py:257`, on by default, every 60 s: `kanban_watchers_dispatcher.py:49`), in one gateway per machine, chosen by a lock (`kanban_watchers.py:236-251`): not necessarily the assignee's.
- The worker it spawns runs no agent: `hermes_cli/kanban_worker_client.py` submits the claim to the assignee profile's gateway (`kanban.run`, `gateway/session_kanban.py:14-40`). **The task's turn runs as a session in the assignee's gateway**, where its channel plugin is loaded.

## Hooks are not a complete source

- `on_kanban_task_updated` fires from `assign_task`, `_set_task_override`, `edit_task` and the dashboard (`kanban_db.py:212-232`), with field names only. Claimed, spawned, exited, stale-claim and dispatch-tick hooks fire in the dispatching process (`kanban_db.py:2202`, `kanban_db_dispatch.py:2155,1343-1364`, `kanban_db.py:2423`, `kanban_db.py:243-275`). `kanban_task_completed` and `kanban_task_blocked` fire in whichever process completes or blocks it (`kanban_db.py:2743`, `3211`).
- Plugins load lazily in every Hermes process, the CLI included (`hermes_cli/plugins.py:982-1012`).
- No hook fires for a crash, timeout or orphan put back to `ready` (`kanban_db_dispatch.py:888`), giving up (`1476-1491`), `unblock_task` (`kanban_db.py:3557`), `archive_task` (`3789`), `promote_task` (`3478`) or `recompute_ready` (`2036`).

So a plugin cannot follow a task from hooks alone. Hermes's own notifier reads `task_events` above a cursor every 5 s (`gateway/kanban_watchers.py:60-121`); the enclos adapter looks at the newest event's id every 5 s instead and, when it moved, reads the agent's tasks again, read-only (a `mode=ro` URI, as `gateway/session_kanban.py:30` does: `kanban_db_connect.connect()` creates and migrates the database).

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

## A task's detail

Read from Hermes's default branch at `081e8d9b` (2026-11-16), for issue #318 ([wire contract](../protocol.md#task-details)). Source reading, plus the adapter's tests against boards Hermes's own functions write; not run in a gateway.

- `tasks.body` holds what the task asks. `task_links (parent_id, child_id)` links tasks: a child waits for its parents (`kanban_db.py:880`).
- `task_comments (id, task_id, author, body, created_at)` (`kanban_db.py:886`); `add_comment` (`1671`) also writes a `commented` event. `author` is a profile name, or whatever the CLI or dashboard was given.
- `task_runs` is one row per attempt (`kanban_db.py:910`): `profile`, `started_at`, `ended_at`, and `outcome` (`completed`, `blocked`, `crashed`, `timed_out`, `spawn_failed`, `gave_up`, `reclaimed`, or null while it runs), with `summary` and `error`. Events carry the `run_id` of their attempt, which orders an attempt among the events of the same second.
- Of about 25 event kinds, a person reads `created`, `blocked` (`block_task` routes a block to `blocked`, `dependency_wait` for a dependency, or `block_loop_detected` after repeated blocks: `_route_block`, `kanban_db.py:3218`), `unblocked` (`3590`), `review_requested` and `completed`. `blocked` carries `reason` in its payload; `initial_status` is Hermes's own reason for a task created blocked. When a timeout, crash or reclaim exhausts the retry budget, the run closes with that outcome and `_record_task_failure(..., end_run=False)` (`kanban_db_dispatch.py:1372-1491`) blocks the task writing only `gave_up`, whose payload has `failures` and `error` but no `reason`; the adapter shows it as a block. The rest (`claimed`, `spawned`, `heartbeat`, `worker_registered`, `reclaimed`, `promoted`...) are the board's workings.
- **A comment steers a running worker.** `inject_new_comments_from_env` (`tools/kanban_tools.py:636`) looks for new comments on the worker's task every 6 seconds and steers them into the live turn as "notes ... from the operator. Take it into account for the work you're doing right now", and `_ctx_comments` (`kanban_db_context.py:220`) puts the newest into every later attempt's context. Writing a comment is therefore a control, not a report.
