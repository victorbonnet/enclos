"""Native Hermes clarify cards; Hermes owns the wait, this channel owns delivery."""

import asyncio
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import protocol, runtime_approvals

MAX_DEFINITION_BYTES = 24 * 1024
MAX_ANSWER_BYTES = 8 * 1024
MAX_CHOICES = 12
MAX_NATIVE_CHOICES = 4
TEXT_CHUNK_BYTES = 24 * 1024
MAX_APPROVAL_FRAME_BYTES = 24 * 1024
logger = logging.getLogger(__name__)


def _size(value) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be nonblank text")
    if any((ord(c) < 32 and c not in "\r\n\t") or 127 <= ord(c) <= 159 for c in value):
        raise ValueError(f"{name} contains a control character")
    return value


def validate_definition(value):
    if not isinstance(value, dict):
        raise ValueError("question must be an object")
    protocol._check_id(value.get("id"), "question.id")
    _text(value.get("text"), "question.text")
    choices = value.get("choices", [])
    if not isinstance(choices, list) or len(choices) > MAX_CHOICES:
        raise ValueError("question supports at most 12 choices")
    for label in choices:
        _text(label, "choice")
    if not isinstance(value.get("multiple", False), bool):
        raise ValueError("multiple must be a boolean")
    approval = value.get("approval")
    if approval is not None:
        if choices or value.get("multiple", False) or not isinstance(approval, dict):
            raise ValueError("runtime approvals have no question choices")
        _text(approval.get("command"), "approval.command")
        _text(approval.get("reason"), "approval.reason")
        actions = approval.get("actions")
        if (not isinstance(actions, list) or not actions or any(a not in runtime_approvals.ACTIONS for a in actions)
                or actions != [a for a in runtime_approvals.ACTIONS if a in actions] or "deny" not in actions
                or (actions != ["deny"] and "once" not in actions)
                or ("always" in actions and "session" not in actions)):
            raise ValueError("runtime approval actions must preserve the native order and scopes")
        if not isinstance(approval.get("smart_denied", False), bool):
            raise ValueError("smart_denied must be a boolean")
        if approval.get("smart_denied", False) and actions not in (["deny"], ["once", "deny"]):
            raise ValueError("smart deny only offers a one-operation override")
    if _size(value) > MAX_DEFINITION_BYTES:
        raise ValueError("question exceeds 24 KiB")
    return value


def validate_answer(value, definition=None):
    if not isinstance(value, dict) or _size(value) > MAX_ANSWER_BYTES:
        raise ValueError("answer must be an object of at most 8 KiB")
    kind = value.get("kind")
    approval = definition.get("approval") if definition else None
    if kind == "approval":
        if (set(value) != {"kind", "action"} or value.get("action") not in runtime_approvals.ACTIONS
                or (definition is not None and (approval is None or value["action"] not in approval["actions"]))):
            raise ValueError("select an offered native approval action")
        return value
    if approval is not None:
        raise ValueError("runtime approval requires an explicit native approval action")
    if kind == "skip" and set(value) == {"kind"}:
        return value
    if kind == "text" and set(value) == {"kind", "text"}:
        _text(value.get("text"), "answer.text")
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


def _native():
    try:
        from tools import clarify_gateway
        if all(callable(getattr(clarify_gateway, name, None)) for name in
               ("get_pending", "resolve_gateway_clarify", "mark_awaiting_text")) and all(
                   isinstance(getattr(clarify_gateway, name, None), str) for name in ("SKIPPED", "CANCELLED")):
            return clarify_gateway
    except ImportError:
        pass
    return None


def _card_text(question):
    # Only Hermes's exact translated suffix is presentation, never prose/markdown inference.
    try:
        from agent.i18n import t
        suffix = "\n" + t("gateway.clarify.skip_hint")
        return question.removesuffix(suffix)
    except ImportError:
        return question


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
    state: str = "pending"
    answer: dict | None = None
    update: dict | None = None
    queued: bool = False


class Manager:
    def __init__(self, adapter, native=_native, approvals_native=runtime_approvals.native_api):
        self.adapter = adapter
        self.native = native
        self.bridge_supports = False
        self.bridge_runtime_supports = False
        self.approvals_native = approvals_native
        self.approval_ids: set[str] = set()
        self.cards: dict[str, Card] = {}
        self.tasks: set[asyncio.Task] = set()
        self.orphan_retries: set[str] = set()

    @property
    def available(self):
        return self.bridge_supports and self.native() is not None

    @property
    def approvals_available(self):
        return self.bridge_runtime_supports and self.approvals_native() is not None

    def can_deliver(self, message):
        if not message["type"].startswith("question."):
            return True
        if message["type"] == "question.ask":
            return self.bridge_runtime_supports if message["question"].get("approval") else self.bridge_supports
        approval = (message.get("question") in self.approval_ids or message.get("state") == "resolved"
                    or (message.get("answer") or {}).get("kind") == "approval")
        if approval:
            return self.bridge_runtime_supports
        return self.bridge_supports or self.bridge_runtime_supports

    def _queue(self, message):
        try:
            return self.adapter._outbox.put(message)
        except OSError:
            logger.warning("A question update could not be saved", exc_info=True)
            return False

    async def _emit(self, message):
        if not self._queue(message):
            return False
        if self.can_deliver(message):
            await self.adapter._write(message)
        return True

    def _track(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def approval_text_fallback(self, prompt):
        def fits(text):
            return len(protocol.encode_line(protocol.message_out(prompt.chat_id, text))) <= MAX_APPROVAL_FRAME_BYTES
        for chunk in runtime_approvals.fallback_chunks(
                prompt, fits, getattr(self.adapter, "typed_command_prefix", "/")):
            result = await self.adapter.send(prompt.chat_id, chunk,
                metadata={**(prompt.metadata or {}), "is_approval_prompt": True})
            if not result.success:
                return False
        return True

    async def ask_approval(self, prompt):
        if not self.approvals_available or not getattr(prompt, "request_id", None):
            return await self.approval_text_fallback(prompt), None
        native = self.approvals_native()
        matching = [row for row in native.list_gateway_approvals(prompt.session_key)
                    if row.get("request_id") == prompt.request_id]
        if len(matching) != 1:
            return True, None  # Already withdrawn; never bind to another pending request.
        definition = runtime_approvals.definition(prompt, protocol.new_id())
        try:
            validate_definition(definition)
        except ValueError:
            return await self.approval_text_fallback(prompt), None
        binding = runtime_approvals.Binding(native, prompt, prompt.request_id, prompt.session_key, matching[0])
        if not binding.observe(asyncio.get_running_loop()):
            return True, None
        card = Card(definition, prompt.chat_id, prompt.request_id, prompt.session_key, binding, native)
        self.cards[definition["id"]] = card
        self.approval_ids.add(definition["id"])
        if not await self._emit(protocol._message("question.ask", conversation=prompt.chat_id, question=definition)):
            self.cards.pop(definition["id"], None)
            return False, None
        self._track(self._watch(card))
        return True, definition["id"]

    async def ask(self, chat_id, question, choices, clarify_id, session_key, metadata=None):
        native = self.native()
        if not self.available:
            return await self.text_fallback(chat_id, question, choices, clarify_id, metadata)
        entry = native.get_pending(clarify_id)
        if entry is None:
            return True  # An interrupt already retired the native wait before delivery.
        if entry.session_key != session_key or list(entry.choices or []) != list(choices or []):
            return False
        definition = {"id": protocol.new_id(), "text": _card_text(question),
                      "choices": list(choices or []), "multiple": bool(entry.multi_select)}
        try:
            if len(definition["choices"]) > MAX_NATIVE_CHOICES:
                raise ValueError("native clarify supports at most four choices")
            validate_definition(definition)
        except ValueError:
            return await self.text_fallback(chat_id, question, choices, clarify_id, metadata)
        card = Card(definition, chat_id, clarify_id, session_key, entry, native)
        message = protocol._message("question.ask", conversation=chat_id, question=definition)
        self.cards[definition["id"]] = card
        if not await self._emit(message):
            self.cards.pop(definition["id"], None)
            return False
        native.mark_awaiting_text(clarify_id)  # The ordinary composer also answers on older apps.
        self._track(self._watch(card))
        return True

    async def text_fallback(self, chat_id, question, choices, clarify_id, metadata=None):
        native = self.native()
        if choices:
            # BasePlatformAdapter uses the same capture path. Keep every complete label,
            # splitting the delivery rather than truncating an oversized card.
            if native is not None:
                native.mark_awaiting_text(clarify_id)
            else:
                try:
                    from tools.clarify_gateway import mark_awaiting_text
                    mark_awaiting_text(clarify_id)
                except ImportError:
                    pass
            entry = native.get_pending(clarify_id) if native else None
            multi = bool(getattr(entry, "multi_select", False))
            hint = "Reply with choice numbers (for example 1,3), or type your answer." if multi else (
                "Reply with a choice number, or type your answer.")
            body = "\n\n".join([question, "\n".join(f"{i + 1}. {c}" for i, c in enumerate(choices)), hint])
        else:
            body = question
        for chunk in _chunks(body):
            result = await self.adapter.send(chat_id, chunk, metadata=metadata)
            if not result.success:
                return False
        return True

    def _live(self, card):
        if card.definition.get("approval"):
            return card.entry.pending()
        return (card.native.get_pending(card.native_id) is card.entry
                and card.entry.session_key == card.session_key and not card.entry.event.is_set()
                and list(card.entry.choices or []) == card.definition["choices"]
                and bool(card.entry.multi_select) == card.definition["multiple"])

    def _observed(self, card):
        if card.definition.get("approval"):
            return card.entry.observed()
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
            # Hermes accepted text outside the app's bounded contract; the card can no
            # longer be answered, while the native tool retains its actual result.
            return "cancelled", None
        return "answered", answer

    async def _settle(self, card, state, answer=None, of=None):
        if card.state == "pending":
            card.state, card.answer = state, answer
        fields = {"question": card.definition["id"], "state": card.state}
        if card.answer is not None:
            fields["answer"] = card.answer
        if of is not None:
            fields["of"] = of
        update = protocol._message("question.update", **fields)
        card.update = update
        card.queued = self._queue(update)
        if card.queued and self.can_deliver(update):
            await self.adapter._write(update)
        return card.queued

    async def _watch(self, card):
        while card.state == "pending":
            observed = self._observed(card) if card.definition.get("approval") or not self._live(card) else None
            if observed is not None:
                await self._settle(card, *observed)
                break
            await asyncio.sleep(0.1)
        while not card.queued:
            await asyncio.sleep(0.25)
            card.queued = self._queue(card.update)
            if card.queued and self.can_deliver(card.update):
                await self.adapter._write(card.update)

    async def answer(self, message):
        card = self.cards.get(message["question"])
        if card is None or card.conversation != message["conversation"]:
            await self.adapter._write(protocol.error("not_found", "Question is not available.", message["id"]))
            return
        try:
            answer = validate_answer(message["answer"], card.definition)
        except ValueError as error:
            await self.adapter._write(protocol.error("bad_message", str(error), message["id"]))
            return
        if card.definition.get("approval"):
            await self._answer_approval(card, answer, message["id"])
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

    async def _answer_approval(self, card, answer, request_id):
        if card.state == "answered":
            await self._settle(card, card.state, card.answer, of=request_id)
            return
        if card.state == "pending" and self._live(card) and card.entry.resolve(answer["action"]):
            # No await separates the exact resolver from durable correlated settlement.
            await self._settle(card, "answered", answer, of=request_id)
            return
        observed = self._observed(card)
        if card.state == "pending" and observed is not None:
            await self._settle(card, *observed)
        await self.adapter._write(protocol.error("agent_unavailable",
            "The runtime approval was already resolved or is no longer available.", request_id))

    async def sync(self, ids):
        for question_id in ids:
            card = self.cards.get(question_id)
            if card is None:
                await self._emit(protocol._message("question.update", question=question_id, state="expired"))
            elif card.state != "pending":
                await self._settle(card, card.state, card.answer)
            elif self._live(card):
                await self._emit(protocol._message("question.update", question=question_id, state="pending"))
            else:
                observed = self._observed(card)
                if observed is not None:
                    await self._settle(card, *observed)

    def prepare_replay(self):
        pending = self.adapter._outbox.pending()
        settled = {m["question"] for m in pending if m["type"] == "question.update" and m["state"] != "pending"}
        # A restarted adapter has no watcher for an ask the bridge has never seen.
        # Put its expiry after the ask, so even a hello-time empty sync cannot strand it.
        for message in pending:
            if message["type"] == "question.ask":
                question_id = message["question"]["id"]
                if message["question"].get("approval"):
                    self.approval_ids.add(question_id)
                if question_id not in self.cards and question_id not in settled:
                    update = protocol._message("question.update", question=question_id, state="expired")
                    if not self._queue(update) and question_id not in self.orphan_retries:
                        self.orphan_retries.add(question_id)
                        self._track(self._retry_orphan(update))
                    settled.add(question_id)
        return self.adapter._outbox.pending()

    async def _retry_orphan(self, update):
        try:
            while True:
                await asyncio.sleep(0.25)
                if self._queue(update):
                    if self.can_deliver(update):
                        await self.adapter._write(update)
                    return
        finally:
            self.orphan_retries.discard(update["question"])

    async def fallback_cards(self):
        for card in self.cards.values():
            if card.state == "pending" and self._live(card):
                if card.definition.get("approval"):
                    if not self.approvals_available:
                        await self.approval_text_fallback(card.entry.prompt)
                elif not self.available:
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
            if card.native_id == native_id and card.state == "pending" and not card.definition.get("approval"):
                await self._settle(card, *self._observed(card))

    async def close(self):
        for card in self.cards.values():
            if card.state == "pending":
                observed = self._observed(card) if not self._live(card) else None
                await self._settle(card, *(observed or ("cancelled", None)))
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


def register_skill(ctx):
    register = getattr(ctx, "register_skill", None)
    if callable(register):
        register("app-questions", Path(__file__).parent / "skills" / "app-questions" / "SKILL.md",
                 "Use when asking a person for a choice or missing information through the enclos mobile app.")
