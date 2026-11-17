"""The agent's tasks on Hermes's kanban board, and what the agent is doing
(docs/protocol.md, Tasks and agent activity; ADR 0068, proposed).

Hermes's board hooks fire in whichever process wrote the board, and several
changes fire none (docs/research/hermes-tasks.md), so the board itself is the
source: every board is read, read-only, for the tasks assigned to this agent's
profile, and its event log is watched every few seconds. A hook is only a cue
to look sooner. Nothing here writes the board, nor opens it through Hermes's
`connect()`, which creates and migrates the database.

Nothing is kept either: the bridge acknowledges a task once stored, and ends
the connection when it cannot, so the list sent after the next hello repairs
whatever was lost. A task it refuses is sent again at the next reading.
"""

import asyncio
import collections
import contextlib
import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from . import protocol, visible

logger = logging.getLogger(__name__)

# Hermes's statuses, as the protocol's states. An archived task, or a status a
# later Hermes adds, is left out: the next `tasks` list drops it.
STATES = {
    "triage": "queued", "todo": "queued", "scheduled": "queued", "ready": "queued",
    "running": "running",
    # Both wait for someone: a person, or the work it depends on.
    "blocked": "blocked", "review": "blocked",
    "done": "done",
}
ENDED = ("done", "failed", "cancelled")

# How often the boards' event logs are looked at, as Hermes's own notifier does.
POLL_SECONDS = 5
# The bridge's bounds (`enclos_protocol::task`), kept here too so a list it
# would cut is not sent whole.
MAX_TASKS = 100
ENDED_SECONDS = 3 * 24 * 3600
MAX_TITLE_CHARS = 120
MAX_SUMMARY_CHARS = 500
MAX_DOING = 16
# The task messages the bridge has not answered yet, by message id: as many
# as fit, the oldest forgotten first.
MAX_UNANSWERED = 1024

# Hermes's hooks after a board write, taken as a cue to read it again.
HOOKS = ("kanban_task_claimed", "kanban_task_completed", "kanban_task_blocked", "on_kanban_task_updated")

# What is read of a task: its row, when its state last changed (its newest
# event, and its newest claim for a run), and the enclos conversation it was
# asked from, which `kanban_create` subscribes to it.
_TASKS = """
SELECT t.id, t.title, t.status, t.created_by, t.created_at, t.started_at, t.completed_at, t.result,
       (SELECT MAX(e.created_at) FROM task_events e WHERE e.task_id = t.id) AS changed_at,
       (SELECT MAX(e.created_at) FROM task_events e WHERE e.task_id = t.id AND e.kind = 'claimed') AS claimed_at,
       (SELECT s.chat_id FROM kanban_notify_subs s WHERE s.task_id = t.id AND s.platform = ?
         ORDER BY s.created_at LIMIT 1) AS conversation,
       (SELECT COUNT(*) FROM task_comments c WHERE c.task_id = t.id) AS comments
  FROM tasks t
 WHERE t.assignee = ? AND t.status != 'archived'
"""

# What a `task.detail` carries at most (`enclos_protocol::task_detail`): the
# bridge cuts it again itself, and fits it into one frame for a phone.
MAX_BODY_CHARS = 4000
MAX_COMMENTS = 20
MAX_COMMENT_CHARS = 1000
MAX_AUTHOR_CHARS = 64
MAX_RELATED = 20
MAX_HISTORY = 30
MAX_HISTORY_TEXT_CHARS = 300

# How an attempt ended (`task_runs.outcome`), as the protocol's outcome. One
# Hermes adds later is left without an outcome: the app reads it as ended.
OUTCOMES = {"completed": "completed", "blocked": "blocked", "crashed": "crashed", "timed_out": "timed_out",
            "gave_up": "gave_up", "spawn_failed": "failed", "reclaimed": "stopped"}
# The events of a task's log its history shows; the others (claimed, spawned,
# heartbeat, worker bound...) are the board's own workings, and an attempt's
# start and end come from its run.
EVENTS = {"created": "created", "blocked": "blocked", "dependency_wait": "blocked",
          "block_loop_detected": "blocked", "gave_up": "blocked", "unblocked": "unblocked",
          "review_requested": "review", "completed": "done"}
# What a block that waits for other tasks says, when Hermes gives no reason.
WAITS_FOR_TASKS = "Waits for the tasks it depends on"
# What the block says when Hermes stopped retrying: its `gave_up` event is the
# only trace, as the failed run keeps its own outcome (a timeout, a crash).
GAVE_UP = "Stopped retrying"


def _gave_up(payload: dict[str, Any]) -> str:
    """Why Hermes stopped retrying, from its `gave_up` event's payload."""
    failures = payload.get("failures")
    text = GAVE_UP
    if isinstance(failures, int) and not isinstance(failures, bool) and failures > 0:
        text += f" after {failures} failed attempt" + ("s" if failures > 1 else "")
    error = _line(payload.get("error"), MAX_HISTORY_TEXT_CHARS)
    return f"{text}: {error}" if error else text

# One task of this profile's, on one board: where its detail is read.
_ONE = "SELECT id, body, created_by, created_at FROM tasks WHERE id = ? AND assignee = ? AND status != 'archived'"
_RELATED = """
SELECT t.id, t.title, t.status, t.assignee, 'parent' AS relation
  FROM task_links l JOIN tasks t ON t.id = l.parent_id WHERE l.child_id = ?1
UNION ALL
SELECT t.id, t.title, t.status, t.assignee, 'child' AS relation
  FROM task_links l JOIN tasks t ON t.id = l.child_id WHERE l.parent_id = ?1
"""
_COMMENTS = "SELECT author, body, created_at FROM task_comments WHERE task_id = ? ORDER BY id DESC LIMIT ?"
_COMMENT_COUNT = "SELECT COUNT(*) FROM task_comments WHERE task_id = ?"
_RUNS = "SELECT id, profile, started_at, ended_at, outcome, summary, error FROM task_runs WHERE task_id = ? ORDER BY id"
# Every event, in the order the board wrote them: an attempt takes its place
# at its run's first event, so things of one second keep their order.
_EVENTS = "SELECT kind, payload, created_at, run_id FROM task_events WHERE task_id = ? ORDER BY id"
# A board whose events name no run.
_EVENTS_WITHOUT_RUNS = "SELECT kind, payload, created_at, NULL AS run_id FROM task_events WHERE task_id = ? ORDER BY id"


def _epoch(value: Any) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return max(0, int(value))


def _lossy(value: bytes) -> str:
    return value.decode("utf-8", "replace")


def _line(value: Any, chars: int) -> str:
    # A BLOB cell comes as bytes, which `str` would show as b'...'.
    if isinstance(value, bytes):
        value = _lossy(value)
    return " ".join(str(value or "").split())[:chars].rstrip()


def read_only(path: Any) -> sqlite3.Connection:
    """A board's database, opened read-only (a `mode=ro` URI, as Hermes's own
    `gateway/session_kanban.py` reads it): never created nor migrated, as
    Hermes's `connect()` would."""
    conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
    conn.row_factory = sqlite3.Row
    # As Hermes reads its board: a cell of invalid UTF-8 would otherwise
    # fail the whole read, and with it every task's report.
    conn.text_factory = _lossy
    return conn


def task_of(row: Any, agent: str) -> Optional[dict[str, Any]]:
    """The task a board row is on the plugin leg, or None when it has none: an
    archived task, a status this plugin does not know, an id the bridge would
    refuse or a blank title. `agent` is the name the plugin's hello gives."""
    state = STATES.get(row["status"])
    title = _line(row["title"], MAX_TITLE_CHARS)
    task_id = row["id"]
    # The bridge's id rule, a routine's: at most 128 bytes, not blank, nothing hidden.
    if (state is None or not title or not isinstance(task_id, str) or not task_id.strip()
            or len(task_id.encode("utf-8")) > protocol.MAX_ID_BYTES or visible.has_hidden(task_id)):
        return None
    # When it entered its current state: its end, the claim of its current
    # run (Hermes keeps the first one's `started_at`), or the last change the
    # event log shows (a retry put back to ready, a block, an unblock).
    created = _epoch(row["created_at"])
    if state == "done":
        since = _epoch(row["completed_at"]) or _epoch(row["changed_at"]) or created
    elif state == "running":
        since = _epoch(row["claimed_at"]) or _epoch(row["started_at"]) or created
    else:
        since = _epoch(row["changed_at"]) or created
    task: dict[str, Any] = {"id": task_id, "title": title, "assignee": agent, "state": state, "since": since or 0}
    asked_by = _line(row["created_by"], protocol.MAX_ID_BYTES)
    if asked_by:
        task["asked_by"] = asked_by
    try:
        task["conversation"] = protocol.check_id(row["conversation"], "conversation")
    except ValueError:
        pass
    summary = _line(row["result"], MAX_SUMMARY_CHARS) if state == "done" else ""
    if summary:
        task["summary"] = summary
    comments = row["comments"]
    if isinstance(comments, int) and not isinstance(comments, bool):
        task["comments"] = comments
    return task


def _text(value: Any, chars: int) -> str:
    """A longer text from the board, its lines kept (the bridge cleans it again)."""
    if isinstance(value, bytes):
        value = _lossy(value)
    lines = [line.rstrip() for line in str(value or "").replace("\r\n", "\n").split("\n")]
    return "\n".join(lines).strip()[:chars].rstrip()


def _payload(value: Any) -> dict[str, Any]:
    try:
        payload = json.loads(value) if isinstance(value, (str, bytes)) else None
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _optional(conn: sqlite3.Connection, sql: str, args: tuple) -> list:
    """Rows of a table an older board may not have: none then."""
    try:
        return conn.execute(sql, args).fetchall()
    except sqlite3.OperationalError:
        return []


def detail_of(conn: sqlite3.Connection, row: Any) -> dict[str, Any]:
    """The `task.detail` of the task `row` of the board `conn`: its body, the
    tasks linked to it, its newest comments, and its history from its runs
    and the few events a person reads, oldest first."""
    task_id = row["id"]
    detail: dict[str, Any] = {}
    body = _text(row["body"], MAX_BODY_CHARS)
    if body:
        detail["body"] = body
    related = []
    for linked in _optional(conn, _RELATED, (task_id,)):
        title = _line(linked["title"], MAX_TITLE_CHARS)
        linked_id = linked["id"]
        if not title or not isinstance(linked_id, str) or visible.has_hidden(linked_id):
            continue
        entry: dict[str, Any] = {"id": linked_id, "title": title, "relation": linked["relation"]}
        state = STATES.get(linked["status"])
        if state:
            entry["state"] = state
        assignee = _line(linked["assignee"], protocol.MAX_ID_BYTES)
        if assignee:
            entry["assignee"] = assignee
        related.append(entry)
    if related:
        detail["related"] = related[:MAX_RELATED]
    comments = []
    for comment in reversed(_optional(conn, _COMMENTS, (task_id, MAX_COMMENTS))):
        text = _text(comment["body"], MAX_COMMENT_CHARS)
        author = _line(comment["author"], MAX_AUTHOR_CHARS)
        if text and author:
            comments.append({"author": author, "time": _epoch(comment["created_at"]) or 0, "text": text})
    if comments:
        detail["comments"] = comments
    counted = _optional(conn, _COMMENT_COUNT, (task_id,))
    detail["comments_total"] = max(int(counted[0][0]) if counted else 0, len(comments))
    attempts: dict[Any, dict[str, Any]] = {}
    for run in _optional(conn, _RUNS, (task_id,)):
        entry = {"kind": "attempt", "time": _epoch(run["started_at"]) or 0}
        ended = _epoch(run["ended_at"])
        if ended is not None:
            entry["until"] = ended
            outcome = OUTCOMES.get(run["outcome"])
            if outcome:
                entry["outcome"] = outcome
        by = _line(run["profile"], protocol.MAX_ID_BYTES)
        if by:
            entry["by"] = by
        text = _line(run["error"] or run["summary"], MAX_HISTORY_TEXT_CHARS)
        if text:
            entry["text"] = text
        attempts[run["id"]] = entry
    try:
        events = conn.execute(_EVENTS, (task_id,)).fetchall()
    except sqlite3.OperationalError:
        events = _optional(conn, _EVENTS_WITHOUT_RUNS, (task_id,))
    history = []
    for event in events:
        attempt = attempts.pop(event["run_id"], None)
        if attempt:
            history.append(attempt)
        if event["kind"] not in EVENTS:
            continue
        kind = EVENTS[event["kind"]]
        payload = _payload(event["payload"])
        entry = {"kind": kind, "time": _epoch(event["created_at"]) or 0}
        by = _line(row["created_by"] if kind == "created" else payload.get("actor"), protocol.MAX_ID_BYTES)
        if by:
            entry["by"] = by
        reason = payload.get("reason")
        text = _line(reason if isinstance(reason, str) and reason != "initial_status" else "",
                     MAX_HISTORY_TEXT_CHARS)
        if not text and event["kind"] == "dependency_wait":
            text = WAITS_FOR_TASKS
        if event["kind"] == "gave_up":
            text = _line(_gave_up(payload), MAX_HISTORY_TEXT_CHARS)
        if text:
            entry["text"] = text
        history.append(entry)
    # Attempts no event names (an older board's) go by their time.
    history.extend(attempts.values())
    if not any(e["kind"] == "created" for e in history) and _epoch(row["created_at"]) is not None:
        created = {"kind": "created", "time": _epoch(row["created_at"])}
        by = _line(row["created_by"], protocol.MAX_ID_BYTES)
        if by:
            created["by"] = by
        history.insert(0, created)
    # Oldest first; a stable sort keeps the board's order within one second.
    history.sort(key=lambda e: e["time"])
    if history:
        detail["history"] = history[-MAX_HISTORY:]
    return detail


def listed(tasks: list[dict[str, Any]], now: int) -> list[dict[str, Any]]:
    """What a `tasks` list carries of `tasks` (newest first): every one still
    going, an ended one for 3 days, at most MAX_TASKS."""
    kept = [t for t in tasks if t["state"] not in ENDED or now - t["since"] <= ENDED_SECONDS]
    return kept[:MAX_TASKS]


class Board:
    """Hermes's kanban boards, read for the tasks of one profile. `files` gives
    each board's database, `platform` is this channel's, for the conversation."""

    def __init__(self, profile: str, files: Callable[[], list[str]], platform: str, held_boards=None, default_board=None):
        self.profile = profile
        self.files = files
        self.platform = platform
        self.held_boards = held_boards
        self.default_board = default_board

    @staticmethod
    def _open(path: str) -> sqlite3.Connection:
        return read_only(path)

    def cursor(self) -> tuple:
        """Each board's newest event: it changes whenever a board does."""
        found = []
        for path in self.files():
            with contextlib.closing(self._open(path)) as conn:
                found.append((path, conn.execute("SELECT MAX(id) FROM task_events").fetchone()[0]))
        return tuple(found)

    def read(self, agent: str) -> tuple[tuple, list[dict[str, Any]]]:
        """The cursor, then every task of the profile's on every board, newest
        first; a task id two boards share is taken from the newest. Raises on
        any board it cannot read: a list without that board's tasks would make
        the bridge drop them."""
        cursor = self.cursor()
        rows = []
        for path, _ in cursor:
            with contextlib.closing(self._open(path)) as conn:
                rows.extend(conn.execute(_TASKS, (self.platform, self.profile)).fetchall())
        rows.sort(key=lambda row: (_epoch(row["created_at"]) or 0, str(row["id"])), reverse=True)
        tasks, seen = [], set()
        for row in rows:
            task = task_of(row, agent)
            if task and task["id"] not in seen:
                seen.add(task["id"])
                tasks.append(task)
        return cursor, tasks

    def detail(self, task_id: str) -> Optional[dict[str, Any]]:
        """The detail of task `task_id` of the profile's, from the newest board
        that has it; None when no board has it as this profile's (another
        profile's task, or archived). Raises on a board it cannot read."""
        newest: Optional[tuple[int, dict[str, Any]]] = None
        for path in self.files():
            with contextlib.closing(self._open(path)) as conn:
                row = conn.execute(_ONE, (task_id, self.profile)).fetchone()
                if row is None:
                    continue
                created = _epoch(row["created_at"]) or 0
                if newest is None or created > newest[0]:
                    newest = (created, detail_of(conn, row))
        return newest[1] if newest else None

    def held_detail(self, reference: str) -> Optional[dict[str, Any]]:
        """Read exactly the board/id the creator reported as held; never search another board."""
        if not self.held_boards or not self.default_board:
            return None
        board, task_id = reference.split("/", 1) if "/" in reference else (self.default_board, reference)
        for slug, path in self.held_boards():
            if slug != board:
                continue
            with contextlib.closing(self._open(path)) as conn:
                row = conn.execute(_ONE.replace("assignee = ?", "created_by = ?"), (task_id, self.profile)).fetchone()
                return detail_of(conn, row) if row is not None else None
        return None


def hermes_board(home: Optional[Path], platform: str) -> Optional[Board]:
    """The board of the Hermes this plugin runs in, for the profile whose home
    is `home`; None when this Hermes has no board, which turns `tasks` off."""
    try:
        from hermes_cli import kanban_db
        from hermes_constants import profile_name_for_home
        if not (callable(getattr(kanban_db, "list_tasks", None)) and callable(getattr(kanban_db, "list_boards", None))):
            logger.info("Tasks are off for this Hermes: it has no kanban board's list_tasks and list_boards")
            return None
        profile = profile_name_for_home(home) if home else None
        if not profile:
            logger.info("Tasks are off: %s is not a Hermes profile's home", home)
            return None
    except Exception as error:
        logger.info("Tasks are off for this Hermes: %s: %s", type(error).__name__, error)
        return None

    def files() -> list[str]:
        found: list[str] = []
        for board in kanban_db.list_boards(include_archived=False):
            path = str(board.get("db_path") or "")
            # A board with no database yet has no task.
            if path and path not in found and os.path.isfile(path):
                found.append(path)
        return found

    default_board = getattr(kanban_db, "DEFAULT_BOARD", None)
    def held_boards():
        return [(str(board.get("slug") or default_board), str(board.get("db_path")))
                for board in kanban_db.list_boards(include_archived=False)
                if board.get("db_path") and os.path.isfile(str(board["db_path"]))]
    return Board(profile, files, platform, held_boards=held_boards, default_board=default_board)


class Reporter:
    """Reports the agent's activity and tasks to the bridge, on the adapter's
    loop: `answering` from its turns, `connected` after each bridge hello, and
    a watch over the board between them. `write` sends one message."""

    def __init__(self, agent: str, write: Callable[[dict[str, Any]], Awaitable[bool]],
                 board: Optional[Board] = None):
        self.agent = agent
        self.board = board
        self._write = write
        # What the bridge's hello says it reads.
        self.bridge: frozenset[str] = frozenset()
        # The conversations with a turn in progress, and the running tasks.
        self._answering: dict[str, None] = {}
        self._running: list[str] = []
        self._doing: list[dict[str, str]] = []
        self._since = 0
        # The tasks the bridge was last given, by id, and the board's cursor then.
        self._sent: dict[str, dict[str, Any]] = {}
        # By message id: the task ids each task message carried, until the
        # bridge answers it.
        self._unanswered: collections.OrderedDict[str, list[str]] = collections.OrderedDict()
        self._cursor: Optional[tuple] = None
        # One reading and sending at a time, so an older list never follows a newer one.
        self._lock = asyncio.Lock()
        self._cue = asyncio.Event()
        self._watching: Optional[asyncio.Task] = None
        self._failure_told = False

    @property
    def capabilities(self) -> tuple[str, ...]:
        if not self.board:
            return ("activity",)
        extra = ("held_task_details",) if getattr(self.board, "held_boards", None) and getattr(self.board, "default_board", None) else ()
        return ("activity", "tasks", "task_details") + extra

    async def detail(self, message: dict[str, Any]) -> None:
        """Answers the bridge's `task.get`: the task's detail, read from the
        board read-only, or an `error` (`not_found` for a task that is not this
        agent's). Nothing is kept: the next request reads the board again."""
        of = message["id"]
        if not self.board:
            await self._write(protocol.error("unsupported", "This agent's runtime has no task board.", of))
            return
        try:
            reader = self.board.held_detail if message.get("held") is True else self.board.detail
            detail = await asyncio.to_thread(reader, message["task"])
        except Exception as error:
            logger.warning("Cannot read task %s's detail from the kanban board: %s: %s",
                           message["task"], type(error).__name__, error)
            await self._write(protocol.error("internal", "The runtime's task board could not be read.", of))
            return
        if detail is None:
            await self._write(protocol.error("not_found", "This agent has no such task on its board.", of))
        else:
            await self._write(protocol.message("task.detail", of=of, detail=detail))

    def start(self) -> None:
        if self.board and self._watching is None:
            self._watching = asyncio.ensure_future(self._watch())

    async def stop(self) -> None:
        if self._watching is not None:
            self._watching.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._watching
            self._watching = None

    def cue(self) -> None:
        """A board changed, by a hook's word: look now rather than at the next poll."""
        self._cue.set()

    def acknowledged(self, of: Optional[str]) -> None:
        """The bridge's `ack` of message `of`: the tasks it carried are its."""
        self._unanswered.pop(of, None)

    def refused(self, of: Optional[str]) -> None:
        """The bridge's `error` for message `of`. When it carried tasks, they
        are taken as not sent, so the next reading sends them again: one
        refused because the sandbox had 100 tasks still going goes once the
        board changes again, perhaps with room."""
        for task_id in self._unanswered.pop(of, ()):
            self._sent.pop(task_id, None)

    async def connected(self) -> None:
        """After a bridge hello: the agent's whole state, which the bridge
        replaces its own with."""
        if self.board:
            async with self._lock:
                # The last connection's answers will not come.
                self._unanswered.clear()
                await self._refresh(whole=True)
        await self._send_activity()

    async def answering(self, conversation: str, on: bool) -> None:
        """A turn in `conversation` began (`on`) or ended."""
        if on == (conversation in self._answering):
            return
        if on:
            self._answering[conversation] = None
        else:
            del self._answering[conversation]
        if self._update_doing():
            await self._send_activity()

    def _update_doing(self) -> bool:
        """Recomputes the activity; True when it changed."""
        doing = [{"kind": "answering", "conversation": c} for c in self._answering]
        doing += [{"kind": "task", "task": t} for t in self._running]
        doing = doing[:MAX_DOING]
        if doing == self._doing:
            return False
        self._doing = doing
        self._since = int(time.time()) if doing else 0
        return True

    async def _send_activity(self) -> None:
        if "activity" in self.bridge:
            await self._write(protocol.message("agent.activity", doing=list(self._doing), since=self._since))

    async def _watch(self) -> None:
        while True:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._cue.wait(), POLL_SECONDS)
            self._cue.clear()
            try:
                cursor = await asyncio.to_thread(self.board.cursor)
            except Exception as error:
                self._cannot_read(error)
                continue
            if cursor != self._cursor:
                async with self._lock:
                    if await self._refresh(whole=False):
                        await self._send_activity()

    async def _refresh(self, whole: bool) -> bool:
        """Reads the board and sends what changed: the whole list when `whole`
        or when a task left it, else each task that changed. On a failure,
        nothing: what the bridge has stays until the board reads again. True
        when the activity changed, for the caller to send."""
        try:
            cursor, tasks = await asyncio.to_thread(self.board.read, self.agent)
        except Exception as error:
            self._cannot_read(error)
            return False
        self._failure_told = False
        self._cursor = cursor
        now = int(time.time())
        current = listed(tasks, now)
        messages = []
        if "tasks" in self.bridge:
            if whole or set(self._sent) - {t["id"] for t in current}:
                messages.append(protocol.message("tasks", tasks=current))
            else:
                messages.extend(protocol.message("task.update", task=t) for t in current
                                if self._sent.get(t["id"]) != t)
        # Taken as sent before the first write: the bridge's `error` for one
        # can be read while the next is on its way.
        self._sent = {t["id"]: t for t in current}
        for message in messages:
            carried = message["tasks"] if message["type"] == "tasks" else [message["task"]]
            self._unanswered[message["id"]] = [t["id"] for t in carried]
            while len(self._unanswered) > MAX_UNANSWERED:
                self._unanswered.popitem(last=False)
            await self._write(message)
        self._running = [t["id"] for t in tasks if t["state"] == "running"]
        return self._update_doing()

    def _cannot_read(self, error: Exception) -> None:
        """Said once until the board reads again, so a Hermes that moves its
        board shows why tasks stopped, without a line every few seconds."""
        if not self._failure_told:
            self._failure_told = True
            logger.warning("Cannot read the kanban board; no task is reported until it reads again: %s: %s",
                           type(error).__name__, error)
