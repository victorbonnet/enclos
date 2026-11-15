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
         ORDER BY s.created_at LIMIT 1) AS conversation
  FROM tasks t
 WHERE t.assignee = ? AND t.status != 'archived'
"""


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
    return task


def listed(tasks: list[dict[str, Any]], now: int) -> list[dict[str, Any]]:
    """What a `tasks` list carries of `tasks` (newest first): every one still
    going, an ended one for 3 days, at most MAX_TASKS."""
    kept = [t for t in tasks if t["state"] not in ENDED or now - t["since"] <= ENDED_SECONDS]
    return kept[:MAX_TASKS]


class Board:
    """Hermes's kanban boards, read for the tasks of one profile. `files` gives
    each board's database, `platform` is this channel's, for the conversation."""

    def __init__(self, profile: str, files: Callable[[], list[str]], platform: str):
        self.profile = profile
        self.files = files
        self.platform = platform

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

    return Board(profile, files, platform)


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
        return ("activity", "tasks") if self.board else ("activity",)

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
