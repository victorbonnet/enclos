"""What an agent writes for the person when it hands a held task to them
(ADR 0073; docs/protocol.md, Held tasks): the decision as one question,
what is blocked, up to four choices and the one it recommends. The app
shows it first on the task's card, and the person answers there with one
tap; the answer comes back to the agent as the person's message.

The agent calls `enclos_ask_person` for a task it created that is held now,
and `enclos_person_answered` when the person answered in the conversation
instead. An ask is kept for the hold it was given for (the task and its
`since`), in a file beside the agent's socket so a gateway restart keeps
it, attached to that task in each `held_tasks` (`held_tasks.Manager`) and
forgotten once the task is no longer held or is held anew.
"""

import json
import logging
import os
import tempfile
import threading
import time
from typing import Any, Callable, Optional

from . import held_tasks, visible

logger = logging.getLogger(__name__)

# The bridge's bounds (`HeldTaskAsk::normalized`), checked here so the agent
# is told rather than cut.
MAX_DECISION_CHARS = 120
MAX_BLOCKED_CHARS = 400
MAX_CHOICES = 4
MAX_CHOICE_CHARS = 80

# Told to the agent in each turn where held tasks are on: short, since it is
# in every turn.
HINT = (
    "When a kanban task you created is stopped and needs the person's decision, call enclos_ask_person with "
    "its id, the decision as one short question, one or two plain sentences on what is blocked and why, and "
    "up to four choices that each say what happens (give the index of the one you recommend). The person "
    "answers on the task's card in the enclos app; the answer comes back to you as their message naming the "
    "task. If they answer in the conversation instead, call enclos_person_answered. Write for the person: "
    "no run numbers, hashes or board terms."
)


def context(**_) -> dict[str, str]:
    """The `pre_llm_call` context telling the agent how to hand a held task to the person."""
    return {"context": HINT}


class Asks:
    """The asks of one agent's channel, by task, in a JSON file. Calls come
    from Hermes's tool threads and the channel's loop alike."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()

    def _read(self) -> dict[str, Any]:
        """The asks kept, none when there is no file yet; raises when the
        file cannot be read, so that no write replaces the others with nothing."""
        try:
            with open(self.path, encoding="utf-8") as file:
                data = json.load(file)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as error:
            raise OSError(f"the held tasks' asks cannot be read ({error})") from error
        if not isinstance(data, dict):
            raise OSError("the held tasks' asks are not a JSON object")
        return data

    def _write(self, data: dict[str, Any]) -> None:
        folder = os.path.dirname(self.path) or "."
        handle, temporary = tempfile.mkstemp(dir=folder, prefix=".held-asks.")
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as file:
                json.dump(data, file)
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        except BaseException:
            with _quiet():
                os.unlink(temporary)
            raise

    def put(self, task: str, since: int, ask: dict[str, Any]) -> None:
        """Keeps `ask` for `task`'s hold since `since`, replacing any earlier
        one, stamped `asked` so the same words asked again read as a new
        question to the bridge."""
        with self._lock:
            data = self._read()
            now = time.time()
            data[task] = {"since": since, "at": now, "ask": {**ask, "asked": int(now * 1000)}}
            self._write(data)

    def settle(self, task: str, since: int, title: str, reason: str = "") -> None:
        """The person answered `task`'s hold in the conversation: its ask is
        `settled`. When the agent never asked, the task's own title and
        reason stand for it, as the card already shows them."""
        with self._lock:
            data = self._read()
            kept = data.get(task)
            if not isinstance(kept, dict) or kept.get("since") != since or not isinstance(kept.get("ask"), dict):
                kept = {"since": since, "at": time.time(),
                        "ask": {"decision": title or task, "blocked": reason[:MAX_BLOCKED_CHARS], "choices": []}}
            kept["ask"]["settled"] = True
            data[task] = kept
            self._write(data)

    def attach(self, held: list[dict[str, Any]], read_at: float = 0.0) -> list[dict[str, Any]]:
        """`held`, the agent's held tasks as read from `read_at` on, each with
        the ask kept for its hold. An ask for a task no longer held, or held
        anew, is forgotten, unless it was kept after that reading began: the
        reading may predate the hold it is for. Raises when the asks cannot
        be read."""
        with self._lock:
            data = self._read()
            current = {entry["task"]: entry["since"] for entry in held}

            def usable(value: Any) -> bool:
                return isinstance(value, dict) and isinstance(value.get("ask"), dict)

            matching = {task: value for task, value in data.items()
                        if usable(value) and current.get(task) == value.get("since")}
            kept = {task: value for task, value in data.items()
                    if task in matching or (usable(value) and isinstance(value.get("at"), (int, float))
                                            and value["at"] >= read_at)}
            if kept != data:
                try:
                    self._write(kept)
                except OSError as error:
                    logger.warning("The held tasks' asks cannot be saved (%s)", error)
        return [{**entry, "ask": matching[entry["task"]]["ask"]} if entry["task"] in matching else entry
                for entry in held]


class _quiet:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return True


def _line(value: Any, what: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Give {what}.")
    value = value.strip()
    if "\n" in value or visible.has_hidden(value):
        raise ValueError(f"{what.capitalize()} must be one visible line.")
    if len(value) > limit:
        raise ValueError(f"{what.capitalize()} holds at most {limit} characters.")
    return value


def validate(args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """The task and the ask `enclos_ask_person` was called with; ValueError says what is wrong."""
    task = _line(args.get("task"), "the task's id", 256)
    decision = _line(args.get("decision"), "the decision", MAX_DECISION_CHARS)
    blocked = args.get("blocked", "")
    if not isinstance(blocked, str) or not blocked.strip():
        raise ValueError("Say in one or two sentences what is blocked and why.")
    blocked = blocked.strip()
    if visible.has_hidden(blocked, lines=True) or len(blocked) > MAX_BLOCKED_CHARS:
        raise ValueError(f"What is blocked must be visible text of at most {MAX_BLOCKED_CHARS} characters.")
    choices = args.get("choices") or []
    if not isinstance(choices, list) or len(choices) > MAX_CHOICES:
        raise ValueError(f"Offer at most {MAX_CHOICES} choices.")
    seen: set[str] = set()
    kept = []
    for choice in choices:
        choice = _line(choice, "each choice", MAX_CHOICE_CHARS)
        if visible.bare(choice) in seen:
            raise ValueError("Each choice must differ from the others.")
        seen.add(visible.bare(choice))
        kept.append(choice)
    ask: dict[str, Any] = {"decision": decision, "blocked": blocked, "choices": kept}
    recommended = args.get("recommended")
    if recommended is not None:
        if isinstance(recommended, bool) or not isinstance(recommended, int) or not 0 <= recommended < len(kept):
            raise ValueError("`recommended` is the index of one of the choices, from 0.")
        ask["recommended"] = recommended
    return task, ask


def register(ctx, adapters: list, current_agent: Callable[[], Optional[str]]) -> None:
    """Registers the two tools. `adapters` are the connected channels; a call
    acts for the one of the agent (Hermes profile) it runs for."""

    def channel():
        agent = current_agent()
        for adapter in list(adapters):
            if adapter._agent == agent:
                return adapter
        raise ValueError("This agent is not connected to the enclos app.")

    def held_now(adapter, task: str) -> dict[str, Any]:
        manager = adapter._held
        if manager.board is None:
            raise ValueError("This Hermes has no kanban board the app can read.")
        for entry in held_tasks._fresh(manager.board.read, adapter._agent):
            if entry["task"] == task:
                return entry
        raise ValueError(f"Task {task} is not held now, or you did not create it. Nothing was sent.")

    def ask(args, **_):
        try:
            task, wanted = validate(args)
            adapter = channel()
            entry = held_now(adapter, task)
            adapter._asks.put(task, entry["since"], wanted)
            adapter._loop.call_soon_threadsafe(adapter._held.poke)
            logger.info("Held task %s: handed to the person", task)
            return json.dumps({"status": "asked", "message": (
                "The person sees this on the task's card in the enclos app and can answer with one tap. Their "
                "answer comes back to you as their message naming the task; act on it then. Do not repeat the "
                "question in the conversation.")})
        except Exception as error:
            logger.info("A held task was not handed to the person: %s", error)
            return json.dumps({"error": str(error) or type(error).__name__})

    def answered(args, **_):
        try:
            task = _line(args.get("task"), "the task's id", 256)
            adapter = channel()
            entry = held_now(adapter, task)
            adapter._asks.settle(task, entry["since"], entry.get("title", ""), entry.get("reason", ""))
            adapter._loop.call_soon_threadsafe(adapter._held.poke)
            return json.dumps({"status": "answered", "message": "The task's card no longer waits on the person."})
        except Exception as error:
            return json.dumps({"error": str(error) or type(error).__name__})

    ctx.register_tool(
        name="enclos_ask_person", toolset="enclos", handler=ask,
        description="Hand a stopped kanban task you created to the person: a question with one-tap choices on its card in the enclos app.",
        schema={"name": "enclos_ask_person",
                "description": ("Use when a kanban task you created is stopped (blocked, given up, or in triage) and "
                                "only the person can decide. Write for the person in plain words: no run numbers, "
                                "hashes or board terms. Their answer comes back as their message naming the task."),
                "parameters": {"type": "object", "properties": {
                    "task": {"type": "string", "description": "The task's id, as the board names it (board/id off the default board)."},
                    "decision": {"type": "string", "description": "The decision as one short question, at most 120 characters."},
                    "blocked": {"type": "string", "description": "One or two plain sentences: what is stopped and why it needs the person. At most 400 characters."},
                    "choices": {"type": "array", "items": {"type": "string"}, "maxItems": MAX_CHOICES,
                                "description": "Up to four answers, each one line saying what happens. None asks for a free answer."},
                    "recommended": {"type": "integer", "description": "The index, from 0, of the choice you recommend."}},
                    "required": ["task", "decision", "blocked"]}})
    ctx.register_tool(
        name="enclos_person_answered", toolset="enclos", handler=answered,
        description="Say the person answered a held task's question in the conversation, so its card stops waiting on them.",
        schema={"name": "enclos_person_answered",
                "description": "Call after the person answered, in the conversation, a held task you handed to them.",
                "parameters": {"type": "object", "properties": {
                    "task": {"type": "string", "description": "The task's id."}}, "required": ["task"]}})
