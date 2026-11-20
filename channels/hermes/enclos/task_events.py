"""Task events (ADR 0071, proposed; docs/protocol.md, Task events): Hermes's
kanban pings, sent to the app as task lines rather than as the agent talking.

Hermes subscribes the conversation that asks for a task (`notify+wake`), and
its gateway's notifier (`gateway/kanban_watchers_notifier.py`) sends that
conversation a one-line text ping for each of the task's events it reports
(done, ready for review, changes requested, blocked, gave up, crashed, timed
out, sent to triage by its loop breaker, another status change), through the
platform's `send()` like anything the agent says. Its `metadata` holds only
the subscription's routing keys (Hermes 0.23.x), so the ping is told here:

- by its text, which begins as one of Hermes's ping templates
  (`gateway.kanban.ping.*`: an emoji, an optional `[board]` and `@assignee`,
  then `Kanban <task id>` and the words of that kind of event), read from
  Hermes's translations in the language of the context `send()` runs in
  (that this is the ping's language is to verify, design §14), or the
  English ones below when they cannot be read; and
- by the board: a subscription of this platform and chat to that task, on
  one of the sandbox's boards (the one the ping names), that delivers pings
  (not `wake` alone), with an event of that kind that Hermes has claimed for
  it (at most its `last_event_id`) and not yet recorded as pinged (above its
  `last_ping_event_id`, which Hermes's `record_notify_ping` writes only once
  `send()` has returned). The ping is about the oldest such event. A Hermes
  without `last_ping_event_id` gives the newest claimed one of that kind.

What the line says (the task's title, its assignee, its state) is read from
the board, read-only (`tasks.read_only`), never cut from the ping's text.
Anything else, an agent's sentence that starts like a ping included, stays
the agent's message, and so does a second text matching an event already
told as a line. Should Hermes mark its pings in `send()`'s metadata (enclos
asks it to, ADR 0071), the adapter would read that mark first, in
`EnclosAdapter._task_event`, called from its `send()`, and keep this match
for older releases.
"""

import collections
import contextlib
import functools
import itertools
import json
import logging
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Optional

from . import protocol, tasks, visible

logger = logging.getLogger(__name__)

# Hermes's event kinds the notifier pings for, each with its template's key
# and what the protocol calls it (`enclos_protocol::task_event`). `archived`
# and `unblocked` are claimed but never pinged.
PINGS = {
    "completed": ("gateway.kanban.ping.completed", "done"),
    "review_requested": ("gateway.kanban.ping.review_requested", "review"),
    "changes_requested": ("gateway.kanban.ping.changes_requested", "changes_requested"),
    "block_loop_detected": ("gateway.kanban.ping.triage", "triage"),
    "gave_up": ("gateway.kanban.ping.gave_up", "gave_up"),
    "timed_out": ("gateway.kanban.ping.timed_out", "timed_out"),
    "blocked": ("gateway.kanban.ping.blocked", "blocked"),
    "crashed": ("gateway.kanban.ping.crashed", "crashed"),
    "status": ("gateway.kanban.ping.status", "changed"),
}
HEAD_KEY = "gateway.kanban.ping.head"
BOARD_TAG_KEY = "gateway.kanban.ping.board_tag"
ASSIGNEE_TAG_KEY = "gateway.kanban.ping.assignee_tag"

# Hermes's English templates (its `locales/en.yaml`, 0.23.x), for when its
# translations cannot be read.
ENGLISH = {
    "gateway.kanban.ping.completed": "✔ {head} done — {title}{handoff}",
    "gateway.kanban.ping.review_requested": "👀 {head} ready for review — {title}{handoff}",
    "gateway.kanban.ping.changes_requested":
        "🛑 {board_tag}Kanban {task_id} review requested changes/BLOCK: {reason}{provenance}",
    "gateway.kanban.ping.triage": "🛑 {head} routed to TRIAGE — {why}{recurrences}{reason}",
    "gateway.kanban.ping.gave_up": "⛔ {head} is now blocked: {count}{last}. Fix the cause, then "
        "`hermes kanban unblock {task_id}` (or `hermes kanban reassign {task_id}`). Logs: `hermes kanban log {task_id}`.",
    "gateway.kanban.ping.timed_out": "⏱ {head} ran past {span} and was stopped; it will be retried automatically.",
    "gateway.kanban.ping.blocked": "⏸ {head} blocked{reason}",
    "gateway.kanban.ping.crashed": "✖ {head} — its worker stopped unexpectedly; it will be retried automatically.",
    "gateway.kanban.ping.status": "🔄 {head} → {status}",
    HEAD_KEY: "{board_tag}{assignee_tag}Kanban {task_id}",
    BOARD_TAG_KEY: "[{board}] ",
    ASSIGNEE_TAG_KEY: "@{assignee} ",
}

# What the line carries at most, as the bridge keeps it (`enclos_protocol::task`).
MAX_TITLE_CHARS = tasks.MAX_TITLE_CHARS

_PLACEHOLDER = re.compile(r"\{(\w+)\}")

# The subscriptions of this chat to the task: what each delivers, the last
# event Hermes claimed for it, and the last it recorded as pinged.
_SUBSCRIPTION = """
SELECT delivery_mode, last_event_id, last_ping_event_id FROM kanban_notify_subs
 WHERE task_id = ? AND LOWER(platform) = LOWER(?) AND chat_id = ?
"""
# The same, for a Hermes that records no pings (no `last_ping_event_id`).
_SUBSCRIPTION_UNRECORDED = """
SELECT delivery_mode, last_event_id, NULL FROM kanban_notify_subs
 WHERE task_id = ? AND LOWER(platform) = LOWER(?) AND chat_id = ?
"""
_TASK = "SELECT id, title, assignee, status FROM tasks WHERE id = ?"
# The event a ping is about: the oldest of its kind claimed and not yet
# recorded as pinged. Hermes sends a batch's pings oldest first and records
# each once `send()` returns, so a later text, such as the agent's answer in
# its wake turn, finds none.
_EVENT = ("SELECT id, payload FROM task_events WHERE task_id = ? AND kind = ? AND id > ? AND id <= ?"
          " ORDER BY id ASC LIMIT 1")
# Without that record: the newest claimed event of that kind.
_LATEST_EVENT = ("SELECT id, payload FROM task_events WHERE task_id = ? AND kind = ? AND id <= ?"
                 " ORDER BY id DESC LIMIT 1")
# How many (chat, task, event) told as lines are remembered, so that a second
# text matching one stays the agent's message.
MAX_TOLD = 512
# How many different read failures are logged, each once.
MAX_FAILURES_LOGGED = 64


def _translations() -> Optional[Callable[[str], str]]:
    """Hermes's `t`, when this runs in a Hermes: called with a key alone, it
    gives the template in the gateway's current language, unformatted."""
    try:
        from agent.i18n import t  # Hermes's; absent outside the gateway
    except Exception:
        return None
    return t


def _templates(key: str) -> list[str]:
    """`key`'s template in the gateway's language, then in English."""
    found = []
    t = _translations()
    if t is not None:
        try:
            text = str(t(key))
        except Exception:
            text = ""
        if text and text != key:
            found.append(text)
    if ENGLISH[key] not in found:
        found.append(ENGLISH[key])
    return found


def _part(template: str, names: dict[str, str]) -> str:
    """`template` as a regular expression: its text escaped, each placeholder
    named in `names` replaced by that pattern."""
    out, at = [], 0
    for found in _PLACEHOLDER.finditer(template):
        out.append(re.escape(template[at:found.start()]))
        out.append(names.get(found.group(1), re.escape(found.group(0))))
        at = found.end()
    out.append(re.escape(template[at:]))
    return "".join(out)


@functools.lru_cache(maxsize=64)
def _pattern(template: str, head: str, board_tag: str, assignee_tag: str) -> Optional[re.Pattern]:
    """A ping's beginning as `template` renders it, as a regular expression:
    its optional board and assignee tags and its task id, then the words up to
    its next placeholder, which say what kind of event it is. None when the
    template names no task id, or no words follow it to tell where it ends."""
    groups = {
        "board_tag": "(?:" + _part(board_tag, {"board": r"(?P<board>[^\]\s]+)"}) + ")?",
        "assignee_tag": "(?:" + _part(assignee_tag, {"assignee": r"(?P<assignee>\S+)"}) + ")?",
        # Up to the words that follow it: an id holds no space.
        "task_id": r"(?P<task>\S+?)",
    }
    whole = template.replace("{head}", head, 1)
    parts: list[str] = []
    seen: set[str] = set()
    at = 0
    for found in _PLACEHOLDER.finditer(whole):
        literal = whole[at:found.start()]
        if "task_id" in seen:
            return _compiled(parts, literal)
        name = found.group(1)
        if name not in groups or name in seen:
            return None
        parts += [re.escape(literal), groups[name]]
        seen.add(name)
        at = found.end()
    return _compiled(parts, whole[at:]) if "task_id" in seen else None


def _compiled(parts: list[str], words: str) -> Optional[re.Pattern]:
    """`parts`, then `words` (the text after the task id), when there are any."""
    if not words.strip():
        return None
    try:
        return re.compile("".join(parts) + re.escape(words))
    except re.error:
        return None


def candidates(text: str) -> list[dict[str, Optional[str]]]:
    """Each way `text` begins as one of Hermes's pings: its event kind
    (Hermes's), the task id, and the board and assignee it names, if any.
    Several when templates overlap; none for most text."""
    stripped = text.strip()
    if not stripped:
        return []
    heads = _templates(HEAD_KEY)
    board_tags = _templates(BOARD_TAG_KEY)
    assignee_tags = _templates(ASSIGNEE_TAG_KEY)
    found = []
    for kind, (key, _) in PINGS.items():
        for template in _templates(key):
            for head, board_tag, assignee_tag in itertools.product(heads, board_tags, assignee_tags):
                pattern = _pattern(template, head, board_tag, assignee_tag)
                match = pattern.match(stripped) if pattern else None
                if match is None:
                    continue
                groups = match.groupdict()
                entry = {"kind": kind, "task": groups.get("task"), "board": groups.get("board"),
                         "assignee": groups.get("assignee")}
                if entry not in found:
                    found.append(entry)
    return found


def _state(status: Any) -> Optional[str]:
    return tasks.STATES.get(status) if isinstance(status, str) else None


class Recogniser:
    """Tells Hermes's pings for a chat of this platform from the rest, with
    the board: `boards` gives each live board's (slug, database). Blocking:
    called off the gateway's loop, from any thread."""

    def __init__(self, boards: Callable[[], list[tuple[str, Path]]], platform: str,
                 read_only: Callable[[Any], sqlite3.Connection] = tasks.read_only):
        self.boards = boards
        self.platform = platform
        self.read_only = read_only
        self._lock = threading.Lock()
        # Each (chat, task, event id) told as a line, oldest first.
        self._told: collections.OrderedDict[tuple[str, str, int], None] = collections.OrderedDict()
        # Each read failure logged so far, and the boards that fail now ("" for the list).
        self._failures_logged: set[tuple[str, str, str]] = set()
        self._failing: set[str] = set()

    def recognise(self, chat_id: str, text: str) -> Optional[dict[str, Any]]:
        """The task event `text`, sent to `chat_id`, is, or None when it is the
        agent's own message. Its templates are read in the caller's context,
        whose language they are read in."""
        return self.read(chat_id, candidates(text))

    def read(self, chat_id: str, found: list[dict[str, Optional[str]]]) -> Optional[dict[str, Any]]:
        """The task event of the first of `found` (`candidates`) that the
        board confirms for `chat_id`, or None. A board that cannot be read
        confirms nothing (said in the log); a fault of this code raises."""
        if not found:
            return None
        try:
            boards = self.boards()
        except Exception as error:
            self._cannot_read("", error, "Cannot list the kanban boards")
            return None
        for candidate in found:
            for slug, path in boards:
                if candidate["board"] is not None and candidate["board"] != slug:
                    continue
                try:
                    claimed = self._read(path, chat_id, candidate)
                except (sqlite3.Error, OSError) as error:
                    self._cannot_read(slug, error, f"Cannot read the kanban board {slug!r}")
                    continue
                self._reads_again(slug)
                if claimed is None:
                    continue
                task, event_id, payload = claimed
                event = self._event(task, candidate["kind"], payload)
                if event is not None and self._first_time((chat_id, event["task"], event_id)):
                    return event
        return None

    def _read(self, path: Any, chat_id: str,
              candidate: dict[str, Optional[str]]) -> Optional[tuple[Any, int, Any]]:
        """The task, and the id and payload of the event a ping of
        `candidate`'s kind to `chat_id` is about, or None when the board
        shows no such ping. Database reads only."""
        task_id = candidate["task"] or ""
        kind = candidate["kind"]
        with contextlib.closing(self.read_only(path)) as conn:
            keys = (task_id, self.platform, chat_id)
            try:
                subscriptions = conn.execute(_SUBSCRIPTION, keys).fetchall()
            except sqlite3.OperationalError as error:
                if "last_ping_event_id" not in str(error):
                    raise
                subscriptions = conn.execute(_SUBSCRIPTION_UNRECORDED, keys).fetchall()
            # Pinged: not `wake` alone, which sends no text.
            pinged = [(int(row[1] or 0), row[2]) for row in subscriptions if (row[0] or "notify") != "wake"]
            if not pinged:
                return None
            task = conn.execute(_TASK, (task_id,)).fetchone()
            if task is None:
                return None
            rows = [conn.execute(_LATEST_EVENT, (task_id, kind, claimed)).fetchone() if recorded is None
                    else conn.execute(_EVENT, (task_id, kind, int(recorded), claimed)).fetchone()
                    for claimed, recorded in pinged]
        rows = [row for row in rows if row is not None]
        if not rows:
            return None
        row = min(rows, key=lambda found: int(found[0]))
        return task, int(row[0]), row[1]

    def _event(self, task: Any, kind: str, payload: Any) -> Optional[dict[str, Any]]:
        """The line's fields: the task's, and for a status change the status
        that the event chosen for the ping announced (`_read`)."""
        task_id = task["id"]
        title = " ".join(str(task["title"] or "").split())[:MAX_TITLE_CHARS]
        if not isinstance(task_id, str) or not title or _unusable(task_id):
            return None
        event: dict[str, Any] = {"task": task_id, "title": title, "event": PINGS[kind][1]}
        assignee = " ".join(str(task["assignee"] or "").split())
        if assignee and not _unusable(assignee) and "/" not in assignee:
            event["assignee"] = assignee
        state = _state(task["status"])
        if kind == "status":
            # The status that event announced, when the board still knows it.
            try:
                announced = json.loads(payload).get("status") if payload else None
            except (TypeError, ValueError, AttributeError, RecursionError):
                announced = None
            state = _state(announced) or state
        if state:
            event["state"] = state
        return event

    def _first_time(self, key: tuple[str, str, int]) -> bool:
        """Whether the event `key` names is told as a line for the first time
        in this chat; remembered. A second text matching it, such as the
        agent repeating the ping before Hermes records it, is a message."""
        with self._lock:
            if key in self._told:
                return False
            self._told[key] = None
            while len(self._told) > MAX_TOLD:
                self._told.popitem(last=False)
            return True

    def _cannot_read(self, board: str, error: Exception, what: str) -> None:
        """Logged once for each board and error: pings are messages meanwhile."""
        signature = (board, type(error).__name__, str(error))
        with self._lock:
            self._failing.add(board)
            if signature in self._failures_logged or len(self._failures_logged) >= MAX_FAILURES_LOGGED:
                return
            self._failures_logged.add(signature)
        logger.warning("%s to tell Hermes's kanban pings (%s: %s); until it reads, they are sent as the "
                       "agent's messages", what, type(error).__name__, error, exc_info=True)

    def _reads_again(self, board: str) -> None:
        with self._lock:
            if board not in self._failing and "" not in self._failing:
                return
            self._failing.discard(board)
            self._failing.discard("")
        logger.info("The kanban board %r reads again: Hermes's pings on it are task lines again", board)


def _unusable(value: str) -> bool:
    try:
        protocol.check_id(value, "id")
    except ValueError:
        return True
    return visible.has_hidden(value)


def hermes(platform: str) -> Optional[Recogniser]:
    """The recogniser for the Hermes this runs in, or None when it has no
    kanban board to read (`hermes_cli.kanban_db`'s `list_boards`): its pings
    then stay messages, as before task events."""
    try:
        from hermes_cli import kanban_db as kb
    except Exception as error:
        logger.info("Task events are off for this Hermes: %s: %s", type(error).__name__, error)
        return None
    if not callable(getattr(kb, "list_boards", None)):
        logger.info("Task events are off for this Hermes: its kanban board has no list_boards")
        return None
    return Recogniser(lambda: tasks.board_databases(kb), platform)
