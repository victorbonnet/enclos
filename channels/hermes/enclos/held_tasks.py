"""Held tasks (ADR 0066; docs/protocol.md, Held tasks): this agent's blocked
tasks on Hermes's kanban board, reported to the bridge whole and resumed with
Hermes's own unblock.

Hermes's board is shared by the sandbox's profiles, and an enclos agent is
the Hermes profile of the same name (its socket's name): a held task is a
`blocked` task whose creator (`created_by`, the profile Hermes recorded) is
this agent. This is apart from the `tasks` capability (`tasks.py`, ADR 0068),
which reports the tasks assigned to the agent; both read the same boards.

Every live board is read, as Hermes's gateway notifier reads them
(`list_boards`, each resolved through Hermes's pins and read once per
database file): a task of the `default` board is reported by its id, one of
another board as `<board>/<id>`, since two boards can hold the same id. A
board with no database yet is skipped. Boards are read read-only (a `mode=ro`
URI, `tasks.read_only`), never through Hermes's `connect()`, which creates and
migrates the database: only a resume opens Hermes's writer, for its
`unblock_task`.

What a task says comes from the board's rows and its `task_events`, never
from the text Hermes wakes the agent with: the reason of the latest
`blocked` or `gave_up` event, and the id of the task's latest event as the
revision a resume names. Reads run off the gateway's loop, in a fresh
context (as Hermes runs its own board services), prompted by Hermes's
board hooks, its dispatcher tick and a timer; no hook waits on them.
"""

import asyncio
import contextlib
import contextvars
import dataclasses
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from . import protocol, tasks, visible

logger = logging.getLogger(__name__)

# The most tasks one list carries (the bridge refuses more): the newest.
MAX_TASKS = 32
# How often the board is read again when nothing prompts it.
REFRESH_SECONDS = 30
# How often a board that still cannot be read, or a reading that still
# fails, is said again in the log.
RETELL_SECONDS = 600
# What Hermes's unblock does, said on the card.
RESUME = "Runs it again with a fresh retry budget."
# The bridge's own bounds (`HeldTask::normalized`), kept here too so a list
# stays far below a message's 1 MiB whatever the board holds.
MAX_TITLE_CHARS = 200
MAX_ASSIGNEE_CHARS = 64
MAX_REASON_CHARS = 1_000
MAX_ERROR_CHARS = 2_000
# The protocol's `since`, an i64 the bridge reads.
MAX_SINCE = 2**63 - 1
# The events that hold a task: a block (a worker's, or `hermes kanban
# block`), and the dispatcher giving up after its retry limit. The others
# bound which of them holds it now.
_HOLDS = ("blocked", "gave_up")
_BOUNDS = (*_HOLDS, "unblocked", "created")
# What is read of Hermes's kanban: its functions, the `Task` fields, and the
# `task_events` columns this module's own queries name.
_FUNCTIONS = ("list_tasks", "get_task", "unblock_task", "list_boards", "pin_first_board_resolution",
              "kanban_db_path")
_TASK_FIELDS = {"id", "title", "assignee", "status", "created_by", "created_at", "last_failure_error"}
_EVENT_COLUMNS = {"id", "task_id", "kind", "payload", "created_at"}


class Unavailable(Exception):
    """The Hermes this runs in has no board held tasks can use; says why."""


class HeldTaskError(Exception):
    """A resume the runtime did not make; `code` is the protocol's."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _columns(schema: str, table: str) -> set[str]:
    """The column names `schema` (Hermes's SCHEMA_SQL) gives `table`."""
    found = re.search(rf"CREATE TABLE(?: IF NOT EXISTS)?\s+{table}\s*\((.*?)\n\)", schema, re.S)
    if not found:
        return set()
    names = set()
    for part in found.group(1).split(","):
        words = part.split()
        if words and words[0].upper() not in ("PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT"):
            names.add(words[0])
    return names


def native() -> "Board":
    """The board of the Hermes this runs in, checked for what held tasks
    need (`_FUNCTIONS`, `_TASK_FIELDS`, `_EVENT_COLUMNS` and Hermes's
    `connect` for a resume). Raises Unavailable otherwise."""
    try:
        from hermes_cli import kanban_db as kb
        from hermes_cli.kanban_db_connect import connect
    except Exception as error:
        raise Unavailable(f"no Hermes kanban board ({type(error).__name__}: {error})") from None
    missing = [name for name in _FUNCTIONS if not callable(getattr(kb, name, None))]
    if not callable(connect):
        missing.append("kanban_db_connect.connect")
    if missing:
        raise Unavailable(f"hermes_cli.kanban_db has no {', '.join(missing)}")
    if not isinstance(getattr(kb, "DEFAULT_BOARD", None), str):
        raise Unavailable("hermes_cli.kanban_db has no DEFAULT_BOARD")
    task = getattr(kb, "Task", None)
    fields = {f.name for f in dataclasses.fields(task)} if dataclasses.is_dataclass(task) else set()
    if not _TASK_FIELDS <= fields:
        raise Unavailable(f"Hermes's kanban Task has no {', '.join(sorted(_TASK_FIELDS - fields))}")
    columns = _columns(str(getattr(kb, "SCHEMA_SQL", "")), "task_events")
    if not _EVENT_COLUMNS <= columns:
        raise Unavailable(f"Hermes's kanban task_events table has no {', '.join(sorted(_EVENT_COLUMNS - columns))}")
    return Board(kb, connect)


def _creator(task: Any) -> str:
    return _text(getattr(task, "created_by", None)).strip()


def _text(value: Any) -> str:
    """Text from the board as it can go on the wire: a sandbox writes the
    board, so a payload's JSON can hold a lone surrogate, which no UTF-8
    encoding takes; it reads as U+FFFD, as invalid UTF-8 does."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return str(value).encode("utf-8", "surrogatepass").decode("utf-8", "replace")


def _line(value: Any, limit: int) -> str:
    return " ".join(_text(value).split())[:limit]


def _cut(value: Any, limit: int) -> str:
    return _text(value).strip()[:limit].rstrip()


def _epoch(value: Any) -> Optional[int]:
    """Seconds since the epoch from a stored stamp (Hermes's are integers; an
    outside writer's may be text), or None when it is none the protocol's
    `since` can carry."""
    if isinstance(value, bool):
        return None
    try:
        seconds = int(float(value))
    except (TypeError, ValueError, OverflowError):
        return None
    return seconds if 0 <= seconds <= MAX_SINCE else None


def unusable(value: str) -> Optional[str]:
    """Why `value` cannot be a task id or revision on the wire, or None: the
    id rule, valid UTF-8 and no hidden character, so the one a device sends
    back is the one the runtime gave."""
    try:
        protocol.check_id(value, "id")
        value.encode("utf-8")
    except ValueError as error:
        return str(error)
    if visible.has_hidden(value):
        return "it holds a hidden character"
    return None


def _revision_number(revision: str) -> Optional[int]:
    found = re.fullmatch(r"e:(\d{1,19})", revision)
    return int(found.group(1)) if found else None


def _events(conn: Any, task_id: str) -> tuple[int, Optional[tuple[str, Any, Any]]]:
    """The id of the task's latest event (0 with none), and its latest event
    of `_BOUNDS` as (kind, payload, created_at)."""
    latest = conn.execute("SELECT MAX(id) FROM task_events WHERE task_id = ?", (task_id,)).fetchone()[0]
    marks = ", ".join("?" for _ in _BOUNDS)
    row = conn.execute(
        f"SELECT kind, payload, created_at FROM task_events WHERE task_id = ? AND kind IN ({marks}) "
        "ORDER BY id DESC LIMIT 1", (task_id, *_BOUNDS)).fetchone()
    if row is None:
        return int(latest or 0), None
    try:
        payload = json.loads(row[1]) if row[1] else None
    except (TypeError, ValueError, RecursionError):
        payload = None
    return int(latest or 0), (_text(row[0]), payload if isinstance(payload, dict) else {}, row[2])


def _reason(kind: str, payload: dict) -> str:
    """Why the task is held, in Hermes's words."""
    if kind == "gave_up":
        failures = payload.get("failures")
        if isinstance(failures, int) and not isinstance(failures, bool) and failures > 0:
            return f"Gave up after {failures} consecutive failure{'' if failures == 1 else 's'}."
        return "Gave up after repeated failures."
    reason = payload.get("reason")
    if isinstance(reason, str) and reason.strip():
        return reason
    block_kind = payload.get("kind")
    if isinstance(block_kind, str) and block_kind.strip():
        return block_kind.strip().replace("_", " ").capitalize() + "."
    return ""


class Board:
    """Hermes's kanban boards, through its own `kanban_db` (`kb`), read
    read-only; `connect` is Hermes's writer, for a resume alone. Blocking:
    called off the gateway's loop, one call at a time."""

    def __init__(self, kb: Any, connect: Callable[..., Any], read_only: Callable[[Any], Any] = tasks.read_only):
        self.kb = kb
        self.connect = connect
        self.read_only = read_only
        # Tasks already said to be unusable, said once.
        self._told: set[str] = set()
        # By board: its tasks at its last good reading, which stand while it
        # cannot be read, and since when (and when last said) it cannot be.
        self._last: dict[str, list[dict[str, Any]]] = {}
        self._failing: dict[str, float] = {}

    def _tell(self, key: str, text: str, *args: Any) -> None:
        if key not in self._told:
            self._told.add(key)
            logger.warning(text, *args)

    def _databases(self) -> list[tuple[str, Path]]:
        """(board, database) of each live board that has one, the default
        first, each database once."""
        found: list[tuple[str, Path]] = []
        seen: set[str] = set()
        with self.kb.pin_first_board_resolution():
            for meta in self.kb.list_boards(include_archived=False):
                slug = str(meta.get("slug") or self.kb.DEFAULT_BOARD)
                path = Path(meta.get("db_path") or self.kb.kanban_db_path(slug)).expanduser()
                try:
                    key = str(path.resolve())
                except OSError:
                    key = str(path)
                if key in seen or not path.is_file():
                    continue
                seen.add(key)
                found.append((slug, path))
        return found

    def _ref(self, slug: str, task_id: str) -> str:
        return task_id if slug == self.kb.DEFAULT_BOARD else f"{slug}/{task_id}"

    def _split(self, ref: str) -> tuple[str, str]:
        return tuple(ref.split("/", 1)) if "/" in ref else (self.kb.DEFAULT_BOARD, ref)

    def read(self, profile: str) -> list[dict[str, Any]]:
        """Every task held now that `profile` created, newest first, each
        once. A board that cannot be read stands with its tasks at its last
        good reading, said in the log; raises only when the boards cannot be
        listed: a list without a board's tasks would release their cards."""
        held: list[dict[str, Any]] = []
        for slug, path in self._databases():
            try:
                entries = self._read_board(slug, path, profile)
            except Exception as error:
                entries = self._last.get(slug, [])
                self._cannot_read(slug, error, len(entries))
            else:
                self._last[slug] = entries
                if self._failing.pop(slug, None) is not None:
                    logger.warning("The kanban board %s reads again", slug)
            held.extend(entries)
        held.sort(key=lambda entry: (-entry["since"], entry["task"]))
        seen: set[str] = set()
        unique = []
        for entry in held:
            if entry["task"] not in seen:
                seen.add(entry["task"])
                unique.append(entry)
        return unique

    def _cannot_read(self, slug: str, error: Exception, kept: int) -> None:
        now = time.monotonic()
        told = self._failing.get(slug)
        if told is None or now - told >= RETELL_SECONDS:
            self._failing[slug] = now
            logger.warning("Cannot read the kanban board %s (%s: %s); its %d held task(s) stand as last read",
                           slug, type(error).__name__, error, kept)

    def _read_board(self, slug: str, path: Path, profile: str) -> list[dict[str, Any]]:
        entries = []
        with contextlib.closing(self.read_only(path)) as conn:
            for task in self.kb.list_tasks(conn, status="blocked"):
                if _creator(task) == profile:
                    entry = self._describe(conn, slug, task, profile)
                    if entry is not None:
                        entries.append(entry)
        return entries

    def _describe(self, conn: Any, slug: str, task: Any, profile: str) -> Optional[dict[str, Any]]:
        task_id = _text(task.id)
        ref = self._ref(slug, task_id)
        latest, bound = _events(conn, task_id)
        revision = f"e:{latest}"
        why = unusable(ref) or unusable(revision)
        if not why and slug == self.kb.DEFAULT_BOARD and "/" in task_id:
            why = "a default-board id holding / reads as another board's task"
        if why:
            self._tell(f"task:{ref!r}", "Held task %r is not reported to the app: %s", ref, why)
            return None
        kind, payload, at = bound if bound else ("", {}, None)
        reason = _reason(kind, payload) if kind in _HOLDS else ""
        since = _epoch(at) if bound else None
        if since is None:
            if bound and at is not None:
                self._tell(f"since:{ref!r}", "Held task %r has an event time out of range (%r); its creation "
                           "time stands for it", ref, at)
            since = _epoch(getattr(task, "created_at", None)) or 0
        entry: dict[str, Any] = {
            "task": ref,
            "title": _line(task.title, MAX_TITLE_CHARS),
            "reason": _cut(reason, MAX_REASON_CHARS),
            "since": since,
            "revision": revision,
            "resume": RESUME,
        }
        assignee = _line(getattr(task, "assignee", None), MAX_ASSIGNEE_CHARS)
        if assignee and assignee != profile:
            entry["assignee"] = assignee
        error = getattr(task, "last_failure_error", None) or (payload.get("error") if kind == "gave_up" else None)
        if isinstance(error, (str, bytes)) and _text(error).strip():
            entry["last_error"] = _cut(error, MAX_ERROR_CHARS)
        return entry

    def _path(self, slug: str) -> Path:
        path = next((p for s, p in self._databases() if s == slug), None)
        if path is None:
            raise HeldTaskError("not_found", "This agent has no such held task.")
        return path

    def resume(self, profile: str, ref: str, revision: str) -> None:
        """Unblocks the task `ref` names while `profile` created it and it is
        still held at `revision`; raises HeldTaskError otherwise, or what
        Hermes raised when the task was not resumed.

        Hermes's `unblock_task` opens its own write transaction and refuses
        to run inside another, so the revision is checked just before it, not
        in the same transaction: a task unblocked by someone else in between
        is not changed (unblock changes only a still-blocked task, and this
        answers `conflict`), but one unblocked and blocked again in between
        is resumed at its newer hold."""
        slug, task_id = self._split(ref)
        if slug == self.kb.DEFAULT_BOARD and "/" in task_id:
            raise HeldTaskError("not_found", "This agent has no such held task.")
        path = self._path(slug)
        with contextlib.closing(self.read_only(path)) as conn:
            task = self.kb.get_task(conn, task_id)
            if task is None or _creator(task) != profile:
                raise HeldTaskError("not_found", "This agent has no such held task.")
            latest, _ = _events(conn, task_id)
            if task.status != "blocked" or f"e:{latest}" != revision:
                raise HeldTaskError("conflict", "The task changed since; it was not resumed.")
        try:
            with contextlib.closing(self.connect(db_path=path)) as conn:
                unblocked = self.kb.unblock_task(conn, task_id)
        except Exception:
            # Hermes checks its file after committing, and can raise then:
            # the task may well have resumed.
            if self._resumed(path, task_id, revision):
                logger.warning("Held task %s: Hermes raised after unblocking it", ref, exc_info=True)
                return
            raise
        if not unblocked:
            raise HeldTaskError("conflict", "The task is no longer held; it was not resumed.")

    def _resumed(self, path: Path, task_id: str, revision: str) -> bool:
        """Whether the task, read again, left its hold at `revision`: no longer
        blocked, or unblocked since."""
        number = _revision_number(revision)
        try:
            with contextlib.closing(self.read_only(path)) as conn:
                task = self.kb.get_task(conn, task_id)
                if task is None:
                    return False
                if task.status != "blocked":
                    return True
                return number is not None and conn.execute(
                    "SELECT 1 FROM task_events WHERE task_id = ? AND kind = 'unblocked' AND id > ? LIMIT 1",
                    (task_id, number)).fetchone() is not None
        except Exception:
            logger.warning("Cannot read the task again after Hermes failed to unblock it", exc_info=True)
            return False


def _fresh(function: Callable[..., Any], *args: Any) -> Any:
    """`function` in an empty context: none of the gateway's request-local
    state (a delegated child's marker would make Hermes refuse the write)."""
    return contextvars.Context().run(function, *args)


class Manager:
    """Held tasks of one agent's channel. `write` sends a message to the
    connected bridge (False when none is). `board` is Hermes's, found with
    `native()` when not given; None when this Hermes has none."""

    def __init__(self, agent: str, write: Callable[[dict[str, Any]], Awaitable[bool]],
                 board: Any = ..., refresh_seconds: float = REFRESH_SECONDS):
        self.agent = agent
        self.write = write
        self.refresh_seconds = refresh_seconds
        if board is ...:
            try:
                board = native()
            except Unavailable as why:
                logger.warning("Held tasks are off for this Hermes: %s", why)
                board = None
        self.board = board
        # Whether the connected bridge's hello announced `held_tasks`.
        self.bridge_supports = False
        # The list last sent on this connection, and its message's id.
        self._sent: Optional[list[dict[str, Any]]] = None
        self._sent_id: Optional[str] = None
        self._runner: Optional[asyncio.Task] = None
        self._wake: Optional[asyncio.Event] = None
        # One read or resume at a time, so a list read before a resume is
        # never sent after the list read after it.
        self._lock = asyncio.Lock()
        self._failure_told: Optional[float] = None
        # The ids left out of the last list for being past MAX_TASKS.
        self._cut: frozenset[str] = frozenset()
        # Resumes in progress, kept so that none is collected early.
        self.tasks: set[asyncio.Task] = set()

    @property
    def native(self) -> bool:
        """Whether this Hermes has what held tasks need: the plugin's hello says so."""
        return self.board is not None

    @property
    def available(self) -> bool:
        """Whether held tasks are reported and resumed on this connection."""
        return self.board is not None and self.bridge_supports

    def start(self) -> None:
        """After a hello: the whole list at once, then whenever it changes."""
        self.stop()
        if not self.available:
            return
        self._wake = asyncio.Event()
        self._runner = asyncio.create_task(self._run())
        self._runner.add_done_callback(self._ended)

    def stop(self) -> None:
        """The connection ended: nothing more is sent on it."""
        if self._runner is not None:
            self._runner.cancel()
            self._runner = None
        self._wake = None
        self._sent = self._sent_id = None

    async def close(self) -> None:
        self.stop()
        for task in list(self.tasks):
            task.cancel()

    def poke(self) -> None:
        """Read the board again soon (a board hook, or Hermes's dispatcher ticked). On the loop."""
        if self._wake is not None:
            self._wake.set()

    def refused(self, of: Optional[str], code: Optional[str]) -> None:
        """The bridge refused the message `of`: when it was the last list,
        the next read sends the list again, unless the bridge could not read
        it (`bad_message`), which the same list would meet again."""
        if of is not None and of == self._sent_id and code != "bad_message":
            self._sent = self._sent_id = None

    def track(self, task: asyncio.Task) -> None:
        """Keeps a resume running beside the connection, and logs how it failed."""
        self.tasks.add(task)
        task.add_done_callback(self._finished)

    def _finished(self, task: asyncio.Task) -> None:
        self.tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            logger.error("A held task's resume failed", exc_info=task.exception())

    @staticmethod
    def _ended(task: asyncio.Task) -> None:
        if not task.cancelled() and task.exception() is not None:
            logger.error("Held tasks are no longer reported on this connection", exc_info=task.exception())

    async def _run(self) -> None:
        wake = self._wake
        while True:
            try:
                await self.refresh()
            except Exception:
                # Whatever failed, the next reading may not: said once, then
                # every RETELL_SECONDS while it goes on.
                self._failed("Held tasks could not be read and sent")
            try:
                await asyncio.wait_for(wake.wait(), self.refresh_seconds)
            except asyncio.TimeoutError:
                pass
            wake.clear()

    def _failed(self, text: str) -> None:
        now = time.monotonic()
        if self._failure_told is None or now - self._failure_told >= RETELL_SECONDS:
            self._failure_told = now
            logger.exception(text)
        else:
            logger.debug(text, exc_info=True)

    async def refresh(self, force: bool = False) -> None:
        """Reads the board and sends the list when it differs from the last
        one sent on this connection (or always, `force`)."""
        async with self._lock:
            await self._refresh(force)

    async def _refresh(self, force: bool) -> None:
        if not self.available:
            return
        try:
            held = await asyncio.to_thread(_fresh, self.board.read, self.agent)
        except Exception:
            # The last list stands: one without a board's tasks would
            # release their cards.
            self._failed("Cannot list the kanban boards for held tasks")
            return
        self._failure_told = None
        listed = held[:MAX_TASKS]
        cut = frozenset(entry["task"] for entry in held[MAX_TASKS:])
        if cut and cut != self._cut:
            logger.warning("%d tasks are held; the app is sent the newest %d, and the older ones read there as "
                           "no longer held: %s", len(held), MAX_TASKS, ", ".join(sorted(cut)))
        self._cut = cut
        if not force and listed == self._sent:
            return
        message = protocol.held_tasks(listed)
        reason = protocol.unsendable(message)
        if reason:
            logger.warning("The held tasks cannot be sent: %s", reason)
            return
        if await self.write(message):
            self._sent, self._sent_id = listed, message["id"]

    async def resume(self, message: dict[str, Any]) -> None:
        """The bridge's `held_task.resume`: Hermes's unblock, then the answer
        and a fresh list."""
        of, ref = message["id"], message["task"]
        if not self.available:
            await self.write(protocol.error("unsupported", "This agent does not report held tasks.", of))
            return
        async with self._lock:
            logger.info("Held task %s: resume asked by %s from device %s", ref, message["person"], message["device"])
            try:
                await asyncio.to_thread(_fresh, self.board.resume, self.agent, ref, message["revision"])
            except HeldTaskError as error:
                logger.info("Held task %s was not resumed (%s): %s", ref, error.code, error)
                answer = protocol.error(error.code, str(error), of)
            except Exception:
                logger.exception("Held task %s: Hermes failed to unblock it", ref)
                answer = protocol.error("internal", "The runtime could not resume the task.", of)
            else:
                logger.info("Held task %s was resumed", ref)
                answer = protocol.held_task_resumed(of)
            if not await self.write(answer):
                logger.warning("Held task %s: the answer to the resume could not be sent (%s); the bridge "
                               "reads its outcome from the next list", ref, answer["type"])
            await self._refresh(force=True)
