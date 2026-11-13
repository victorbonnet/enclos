"""Native Hermes clarify cards; Hermes owns the wait, this channel owns delivery."""

import asyncio
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import protocol, visible

MAX_DEFINITION_BYTES = 24 * 1024
MAX_ANSWER_BYTES = 8 * 1024
MAX_CHOICES = 12
MAX_NATIVE_CHOICES = 4
TEXT_CHUNK_BYTES = 24 * 1024
# What the channel calls in Hermes's clarify registry (`tools/clarify_gateway.py`).
NATIVE_FUNCTIONS = ("get_pending", "resolve_gateway_clarify", "mark_awaiting_text")
NATIVE_SENTINELS = ("SKIPPED", "CANCELLED")
logger = logging.getLogger(__name__)


def _size(value) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _text(value, name, lines):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be nonblank text")
    if visible.has_hidden(value, lines):
        raise ValueError(f"{name} holds a hidden or control character")
    return value


def validate_definition(value):
    if not isinstance(value, dict):
        raise ValueError("question must be an object")
    protocol.check_id(value.get("id"), "question.id")
    _text(value.get("text"), "question.text", lines=True)
    choices = value.get("choices", [])
    if not isinstance(choices, list) or len(choices) > MAX_CHOICES:
        raise ValueError("question supports at most 12 choices")
    for index, label in enumerate(choices):
        _text(label, "choice", lines=False)
        if visible.bare(label) in (visible.bare(other) for other in choices[:index]):
            raise ValueError("choice labels must be distinct")
    if not isinstance(value.get("multiple", False), bool):
        raise ValueError("multiple must be a boolean")
    if _size(value) > MAX_DEFINITION_BYTES:
        raise ValueError("question exceeds 24 KiB")
    return value


def validate_answer(value, definition=None):
    if not isinstance(value, dict) or _size(value) > MAX_ANSWER_BYTES:
        raise ValueError("answer must be an object of at most 8 KiB")
    kind = value.get("kind")
    if kind == "skip" and set(value) == {"kind"}:
        return value
    if kind == "text" and set(value) == {"kind", "text"}:
        _text(value.get("text"), "answer.text", lines=True)
        return value
    if kind != "choices" or set(value) != {"kind", "indices"}:
        raise ValueError("answer must select choices, supply text or skip")
    indices = value.get("indices")
    if (not isinstance(indices, list) or not indices or len(indices) > MAX_CHOICES
            or any(type(i) is not int or i < 0 or i >= MAX_CHOICES for i in indices)
            or len(set(indices)) != len(indices)):
        raise ValueError("select distinct choice indices")
    if definition is not None:
        if any(i >= len(definition["choices"]) for i in indices):
            raise ValueError("choice index is out of range")
        if not definition["multiple"] and len(indices) != 1:
            raise ValueError("select exactly one choice")
    return {"kind": "choices", "indices": sorted(indices)}


_warned_native = False


def _native():
    """Hermes's clarify registry, when it has everything the channel calls; else None,
    said once in the log, and questions go as text."""
    global _warned_native
    try:
        from tools import clarify_gateway
    except ImportError:
        clarify_gateway = None
    missing = [name for name in NATIVE_FUNCTIONS if not callable(getattr(clarify_gateway, name, None))]
    missing += [name for name in NATIVE_SENTINELS if not isinstance(getattr(clarify_gateway, name, None), str)]
    if clarify_gateway is not None and not missing:
        return clarify_gateway
    if not _warned_native:
        _warned_native = True
        logger.warning("Hermes's clarify registry lacks %s: app questions are sent as text",
                       ", ".join(missing) if clarify_gateway is not None else "tools.clarify_gateway")
    return None


def _hermes_text(key, default, **values):
    """Hermes's own translated text for `key`, or `default` where it has none."""
    try:
        from agent.i18n import t
        text = t(key, **values)
        return default if not isinstance(text, str) or text == key else text
    except Exception:
        return default


def _card_text(question):
    # Only Hermes's exact translated suffix is presentation, never prose/markdown inference.
    suffix = _hermes_text("gateway.clarify.skip_hint", "")
    return question.removesuffix("\n" + suffix) if suffix else question


def _chunks(text):
    chunk, size = [], 0
    for char in text:
        width = len(char.encode("utf-8"))
        if size + width > TEXT_CHUNK_BYTES:
            yield "".join(chunk)
            chunk, size = [], 0
        chunk.append(char)
        size += width
    if chunk:
        yield "".join(chunk)


@dataclass
class Card:
    definition: dict
    conversation: str
    native_id: str
    session_key: str
    entry: Any
    native: Any
    ask_id: str
    state: str = "pending"
    answer: dict | None = None
    update: dict | None = None
    queued: bool = False


class Manager:
    """Questions of one channel. `outbox` keeps what the bridge has not acknowledged,
    `write` sends a message to the connected bridge, `send` delivers chat text."""

    def __init__(self, outbox, write, send, native=_native):
        self.outbox = outbox
        self.write = write
        self.send = send
        self.native = native
        self.bridge_supports = False
        self.cards: dict[str, Card] = {}
        self.tasks: set[asyncio.Task] = set()
        self.orphan_retries: set[str] = set()

    @property
    def available(self):
        return self.bridge_supports and self.native() is not None

    def _queue(self, message):
        try:
            return self.outbox.put(message)
        except OSError:
            logger.warning("A question update could not be saved", exc_info=True)
            return False

    async def _emit(self, message):
        if not self._queue(message):
            return False
        if self.bridge_supports:
            await self.write(message)
        return True

    def _track(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def ask(self, chat_id, question, choices, clarify_id, session_key, metadata=None):
        native = self.native()
        if not self.available:
            return await self.text_fallback(chat_id, question, choices, clarify_id, metadata)
        entry = native.get_pending(clarify_id)
        if entry is None:
            return True  # An interrupt already retired the native wait before delivery.
        if entry.session_key != session_key or list(entry.choices or []) != list(choices or []):
            # Not the waiter Hermes describes: no card to bind, but the person still sees it.
            logger.warning("A clarify call does not match its pending entry: sent as text")
            return await self.text_fallback(chat_id, question, choices, clarify_id, metadata)
        definition = {"id": protocol.new_id(), "text": _card_text(question),
                      "choices": list(choices or []), "multiple": bool(entry.multi_select)}
        try:
            if len(definition["choices"]) > MAX_NATIVE_CHOICES:
                raise ValueError("native clarify supports at most four choices")
            validate_definition(definition)
        except ValueError:
            return await self.text_fallback(chat_id, question, choices, clarify_id, metadata)
        message = protocol.message("question.ask", conversation=chat_id, question=definition)
        card = Card(definition, chat_id, clarify_id, session_key, entry, native, message["id"])
        self.cards[definition["id"]] = card
        if not await self._emit(message):
            self.cards.pop(definition["id"], None)
            return False
        # The entry stays as Hermes made it: a choice question takes an option's number
        # or text, or "skip", from the composer, and other prose cancels it (the app's
        # Other answers through `question.answer`); an open question takes any text.
        self._track(self._watch(card))
        return True

    async def text_fallback(self, chat_id, question, choices, clarify_id, metadata=None):
        """Hermes's own numbered text (`BasePlatformAdapter.send_clarify`), with every
        label whole: an oversized question is split across messages, never cut."""
        native = self.native()
        if choices:
            entry = None
            if native is not None:
                native.mark_awaiting_text(clarify_id)
                entry = native.get_pending(clarify_id)
            else:
                try:
                    from tools.clarify_gateway import mark_awaiting_text
                    mark_awaiting_text(clarify_id)
                except ImportError:
                    pass
            multi = bool(getattr(entry, "multi_select", False))
            hint = (_hermes_text("gateway.clarify.hint_multi",
                                 "Reply with choice numbers (for example 1,3), or type your answer.")
                    if multi else _hermes_text("gateway.clarify.hint_single",
                                               "Reply with a choice number, or type your answer."))
            numbered = [_hermes_text("gateway.clarify.option_line", f"{i}. {c}", index=i, choice=c)
                        for i, c in enumerate(choices, start=1)]
            body = "\n".join([_hermes_text("gateway.clarify.question", question, question=question),
                              "", *numbered, "", hint])
        else:
            body = _hermes_text("gateway.clarify.question", question, question=question)
        for chunk in _chunks(body):
            result = await self.send(chat_id, chunk, metadata=metadata)
            if not result.success:
                return False
        return True

    def _live(self, card):
        return (card.native.get_pending(card.native_id) is card.entry
                and card.entry.session_key == card.session_key and not card.entry.event.is_set()
                and list(card.entry.choices or []) == card.definition["choices"]
                and bool(card.entry.multi_select) == card.definition["multiple"])

    def _observed(self, card):
        raw = card.entry.response
        if raw == card.native.SKIPPED:
            return "skipped", None
        if raw == card.native.CANCELLED:
            return "cancelled", None
        if raw is None:
            return "expired", None
        labels = card.definition["choices"]
        selected = None
        if card.definition["multiple"]:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list) and parsed and all(isinstance(label, str) and label in labels for label in parsed):
                    selected = [labels.index(label) for label in parsed]
            except (ValueError, TypeError):
                pass
        elif raw in labels:
            selected = [labels.index(raw)]
        answer = {"kind": "choices", "indices": selected} if selected else {"kind": "text", "text": raw}
        try:
            answer = validate_answer(answer, card.definition)
        except ValueError:
            # Hermes accepted text outside the app's bounded contract: the agent has its
            # answer, so the card says answered, without the text it cannot carry.
            return "answered", None
        return "answered", answer

    async def _settle(self, card, state, answer=None, of=None):
        if card.state == "pending":
            card.state, card.answer = state, answer
        fields = {"question": card.definition["id"], "state": card.state}
        if card.answer is not None:
            fields["answer"] = card.answer
        if of is not None:
            fields["of"] = of
        update = protocol.message("question.update", **fields)
        card.update = update
        card.queued = self._queue(update)
        if card.queued and self.bridge_supports:
            await self.write(update)
        return card.queued

    async def _watch(self, card):
        try:
            while card.state == "pending":
                if not self._live(card):
                    await self._settle(card, *self._observed(card))
                    break
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Hermes's entry is no longer what this channel reads (an upgrade changed it):
            # the card closes instead of staying open with nothing to answer it.
            logger.exception("A question's native entry could not be read; its card is cancelled")
            await self._settle(card, "cancelled")
        # A refused card has no update: the bridge never kept it.
        while card.update is not None and not card.queued:
            await asyncio.sleep(0.25)
            card.queued = self._queue(card.update)
            if card.queued and self.bridge_supports:
                await self.write(card.update)

    async def answer(self, message):
        card = self.cards.get(message["question"])
        if card is None or card.conversation != message["conversation"]:
            await self.write(protocol.error("not_found", "Question is not available.", message["id"]))
            return
        try:
            answer = validate_answer(message["answer"], card.definition)
        except ValueError as error:
            await self.write(protocol.error("bad_message", str(error), message["id"]))
            return
        if card.state != "pending":
            await self._settle(card, card.state, card.answer, of=message["id"])
            return
        if not self._live(card):
            await self._settle(card, *self._observed(card), of=message["id"])
            return
        if answer["kind"] == "skip":
            raw, state, confirmed = card.native.SKIPPED, "skipped", None
        elif answer["kind"] == "text":
            raw, state, confirmed = answer["text"], "answered", answer
        else:
            labels = [card.entry.choices[i] for i in answer["indices"]]
            raw = json.dumps(labels, ensure_ascii=False) if card.entry.multi_select else labels[0]
            state, confirmed = "answered", answer
        if card.native.resolve_gateway_clarify(card.native_id, raw):
            await self._settle(card, state, confirmed, of=message["id"])
        else:
            await self._settle(card, *self._observed(card), of=message["id"])

    async def refused(self, of):
        """The bridge refused the message `of`. A refused ask (a conversation it does not
        know, too many questions waiting) would leave the agent waiting on a question
        nobody sees: the card is dropped and the question goes as Hermes's text."""
        card = next((c for c in self.cards.values() if c.ask_id == of), None)
        if card is None:
            return
        self.cards.pop(card.definition["id"], None)
        card.state = "refused"
        if self._live(card):
            entry = card.entry
            await self.text_fallback(card.conversation, entry.question, entry.choices, card.native_id)

    async def sync(self, ids):
        for question_id in ids:
            card = self.cards.get(question_id)
            if card is None:
                await self._emit(protocol.message("question.update", question=question_id, state="expired"))
            elif card.state != "pending":
                await self._settle(card, card.state, card.answer)
            elif self._live(card):
                await self._emit(protocol.message("question.update", question=question_id, state="pending"))
            else:
                await self._settle(card, *self._observed(card))

    def prepare_replay(self):
        pending = self.outbox.pending()
        settled = {m["question"] for m in pending if m["type"] == "question.update" and m["state"] != "pending"}
        # A restarted adapter has no watcher for an ask the bridge has never seen.
        # Put its expiry after the ask, so even a hello-time empty sync cannot strand it.
        for message in pending:
            if message["type"] == "question.ask":
                question_id = message["question"]["id"]
                if question_id not in self.cards and question_id not in settled:
                    update = protocol.message("question.update", question=question_id, state="expired")
                    if not self._queue(update) and question_id not in self.orphan_retries:
                        self.orphan_retries.add(question_id)
                        self._track(self._retry_orphan(update))
                    settled.add(question_id)
        return self.outbox.pending()

    async def _retry_orphan(self, update):
        try:
            while True:
                await asyncio.sleep(0.25)
                if self._queue(update):
                    if self.bridge_supports:
                        await self.write(update)
                    return
        finally:
            self.orphan_retries.discard(update["question"])

    async def fallback_cards(self):
        if not self.available:
            for card in self.cards.values():
                if card.state == "pending" and self._live(card):
                    await self.text_fallback(card.conversation, card.entry.question, card.entry.choices,
                                             card.native_id)

    def acknowledge(self, message_id):
        # Once the bridge persisted a terminal update, it no longer includes this
        # question in reconnect sync. Release completed cards' potentially long labels.
        for question_id, card in list(self.cards.items()):
            if card.state != "pending" and card.update and card.update["id"] == message_id:
                self.cards.pop(question_id)

    async def retire(self, native_id):
        for card in self.cards.values():
            if card.native_id == native_id and card.state == "pending":
                await self._settle(card, *self._observed(card))

    async def close(self):
        """The channel stops: a question still waiting is cancelled in Hermes too, so the
        agent is not left waiting on a card that says it was cancelled."""
        for card in self.cards.values():
            if card.state != "pending":
                continue
            if self._live(card):
                card.native.resolve_gateway_clarify(card.native_id, card.native.CANCELLED)
            await self._settle(card, *self._observed(card))
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


def register_skill(ctx):
    register = getattr(ctx, "register_skill", None)
    if callable(register):
        register("app-questions", Path(__file__).parent / "skills" / "app-questions" / "SKILL.md",
                 "Use when asking a person for a choice or missing information through the enclos mobile app.")
