"""Hermes's command confirmations as question cards; optional real Hermes, temporary homes only."""

import asyncio
import collections
import importlib
import inspect
import logging
import os
import sys
import tempfile
import time
import types
import unittest
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enclos import protocol, questions, slash_confirms
from enclos.outbox import Outbox

# Hermes's `gateway.confirm.destructive_prompt`, as it formats it for `/new`.
PROMPT = ("⚠️ **Confirm /new**\n\nThis starts a fresh session and discards the current conversation "
          "history.\n\nChoose:\n• **Approve Once** — proceed this time only\n• **Always Approve** "
          "— proceed and silence this prompt permanently\n• **Cancel** — keep current conversation"
          "\n\n_Text fallback: reply `/approve`, `/always`, or `/cancel`._")
ENDS = "Reply yes, always or cancel."


async def until(condition, timeout=3.0):
    """Waits for `condition`, which the card's watcher makes true within a poll or two."""
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("the condition was not met in time")
        await asyncio.sleep(0.01)


class SlashConfirm:
    """What the channel calls in Hermes's `tools.slash_confirm`, as it behaves there."""
    DEFAULT_TIMEOUT_SECONDS = 300

    def __init__(self):
        self.pending = {}

    def register(self, session_key, confirm_id, command, handler, authority=None):
        self.pending[session_key] = {"confirm_id": confirm_id, "command": command, "handler": handler,
                                     "created_at": time.time(), "authority": authority}

    def get_pending(self, session_key):
        entry = self.pending.get(session_key)
        return dict(entry) if entry else None

    def clear(self, session_key):
        self.pending.pop(session_key, None)

    async def resolve(self, session_key, confirm_id, choice, timeout=DEFAULT_TIMEOUT_SECONDS):
        entry = self.pending.get(session_key)
        if not entry or entry["confirm_id"] != confirm_id:
            return None
        self.pending.pop(session_key)
        if time.time() - entry["created_at"] > timeout:
            return None
        result = await entry["handler"](choice)
        return result if isinstance(result, str) else None


def inbound(commands=None, words=None):
    """Hermes's `gateway.run_inbound`, with its reading of a typed reply to a confirmation."""
    module = types.ModuleType("gateway.run_inbound")

    class GatewayInboundMixin:
        _SLASH_CONFIRM_CMD_CHOICES = commands if commands is not None else {
            "approve": "once", "yes": "once", "always": "always", "cancel": "cancel"}

        def _slash_confirm_text_choices(self):
            return words if words is not None else {"yes": "once", "approve once": "once", "always": "always",
                                                    "nevermind": "cancel", "tak": "once"}
    module.GatewayInboundMixin = GatewayInboundMixin
    return {"gateway": types.ModuleType("gateway"), "gateway.run_inbound": module}


class Confirmations(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.native = SlashConfirm()
        self.scope = f"session-{uuid.uuid4()}"
        self.outbox = Outbox(self.temporary.name)
        self.write = AsyncMock(return_value=True)
        self.send = AsyncMock(return_value=types.SimpleNamespace(success=True))
        self.manager = questions.Manager(self.outbox, self.write, self.send, native=lambda: None,
                                         confirms_native=lambda: self.native)
        self.manager.bridge_supports = True
        self.addAsyncCleanup(self.manager.close)
        self.ran = []

    def register(self, command="new", confirm_id="1", release=None):
        async def handler(choice):
            self.ran.append(choice)
            if release is not None:
                await release.wait()
            return f"/{command}: {choice}"
        self.native.register(self.scope, confirm_id, command, handler, authority={"requester": "p"})

    async def confirm(self, command="new", confirm_id="1", message=PROMPT, title="/new", release=None):
        self.register(command, confirm_id, release)
        self.assertTrue(await self.manager.ask_confirm("c", title, message, self.scope, confirm_id))
        return list(self.manager.cards.values())[-1]

    def request(self, card, answer):
        return protocol._message("question.answer", conversation="c", question=card.definition["id"], answer=answer)

    async def answer(self, card, answer):
        request = self.request(card, answer)
        await self.manager.answer(request)
        await asyncio.gather(*self.manager.confirm_runs)
        return request

    def updates(self):
        return [m for m in self.outbox.pending() if m["type"] == "question.update"]

    def sent(self):
        return [call.args[1] for call in self.send.await_args_list]

    async def test_a_confirmation_is_a_card_that_says_what_it_does_and_what_it_is_not(self):
        card = await self.confirm()
        definition = card.definition
        self.assertEqual(definition["choices"], ["Approve once", "Always", "Cancel"])
        self.assertFalse(definition["multiple"])
        self.assertNotIn("approval", definition)
        questions.validate_definition(definition)
        self.assertTrue(definition["text"].startswith("⚠️ **Confirm /new**"))
        self.assertIn("discards the current conversation history", definition["text"])
        # Hermes's typed-reply line names `/approve`, which the app does not pass on.
        self.assertNotIn("/approve", definition["text"])
        self.assertIn(slash_confirms.NOTE, definition["text"])
        self.assertIn(slash_confirms.ALWAYS_NOTE, definition["text"])
        self.assertEqual([m["type"] for m in self.outbox.pending()], ["question.ask"])
        # Hermes's own confirmation stays: same id, command and who may answer it.
        entry = self.native.get_pending(self.scope)
        self.assertEqual((entry["confirm_id"], entry["command"], entry["authority"]), ("1", "new", {"requester": "p"}))

    async def test_a_model_switch_offers_no_always_since_hermes_writes_nothing_for_it(self):
        card = await self.confirm("model", message="⚠️ **Expensive model**\n\nIt costs more.",
                                  title="Expensive model")
        self.assertEqual(card.definition["choices"], ["Approve once", "Cancel"])
        self.assertNotIn(slash_confirms.ALWAYS_NOTE, card.definition["text"])
        await self.answer(card, {"kind": "choices", "indices": [1]})
        self.assertEqual(self.ran, ["cancel"])

    async def test_each_choice_runs_hermess_handler_with_its_own_word_and_is_confirmed(self):
        for index, choice in enumerate(slash_confirms.CHOICES):
            self.ran.clear()
            card = await self.confirm(confirm_id=str(index))
            request = await self.answer(card, {"kind": "choices", "indices": [index]})
            self.assertEqual(self.ran, [choice])
            update = self.updates()[-1]
            self.assertEqual((update["state"], update["answer"], update["of"]),
                             ("answered", {"kind": "choices", "indices": [index]}, request["id"]))
            # The command's reply follows, as Hermes's button adapters send it.
            self.assertEqual(self.send.await_args.args, ("c", f"/new: {choice}"))
            await self.answer(card, {"kind": "choices", "indices": [0]})
            self.assertEqual(self.ran, [choice])

    async def test_skip_cancels_the_command(self):
        card = await self.confirm()
        request = await self.answer(card, {"kind": "skip"})
        self.assertEqual(self.ran, ["cancel"])
        update = self.updates()[-1]
        self.assertEqual((update["state"], update["of"]), ("skipped", request["id"]))
        self.assertNotIn("answer", update)

    async def test_typed_text_is_read_as_hermes_reads_a_reply_or_refused(self):
        card = await self.confirm()
        with patch.dict(sys.modules, inbound()):
            request = await self.answer(card, {"kind": "text", "text": "maybe later"})
            self.assertEqual(self.write.await_args.args[0]["code"], "bad_message")
            self.assertEqual(self.write.await_args.args[0]["of"], request["id"])
            self.assertEqual(self.ran, [])
            self.assertEqual(card.state, "pending")
            request = await self.answer(card, {"kind": "text", "text": " Tak "})
        self.assertEqual(self.ran, ["once"])
        update = self.updates()[-1]
        self.assertEqual((update["answer"], update["of"]), ({"kind": "text", "text": " Tak "}, request["id"]))

    def test_hermess_command_spellings_come_before_its_words(self):
        offered = slash_confirms.CHOICES
        with patch.dict(sys.modules, inbound()):
            self.assertEqual(slash_confirms.typed_choice("/approve", offered), "once")
            self.assertEqual(slash_confirms.typed_choice("/ALWAYS@bot", offered), "always")
            self.assertEqual(slash_confirms.typed_choice("!always", offered), "always")
            self.assertEqual(slash_confirms.typed_choice("Nevermind", offered), "cancel")
            self.assertIsNone(slash_confirms.typed_choice("perhaps", offered))
            self.assertIsNone(slash_confirms.typed_choice("always", ("once", "cancel")))
        # Without Hermes's reading, no text answers it.
        with patch.dict(sys.modules, {"gateway.run_inbound": None}), self.assertLogs(slash_confirms.logger, "WARNING"):
            self.assertIsNone(slash_confirms.typed_choice("yes", offered))

    async def test_a_reply_typed_in_the_composer_closes_the_card_as_the_agents_report(self):
        card = await self.confirm()
        # Hermes reads the reply itself and resolves its own confirmation.
        self.assertEqual(await self.native.resolve(self.scope, "1", "always"), "/new: always")
        await until(lambda: card.state != "pending")
        self.assertEqual(card.state, "answered")
        update = self.updates()[-1]
        self.assertEqual(update["answer"], {"kind": "choices", "indices": [1]})
        self.assertNotIn("of", update)
        request = await self.answer(card, {"kind": "choices", "indices": [0]})
        self.assertEqual(self.ran, ["always"])
        self.assertEqual(self.updates()[-1]["of"], request["id"])

    async def test_a_reply_the_channel_keeps_from_hermes_while_a_turn_runs_is_answered_as_hermes_would(self):
        card = await self.confirm()
        with patch.dict(sys.modules, inbound()):
            self.assertFalse(await self.manager.answer_typed_confirm("c", ["other", self.scope], "perhaps"))
            self.assertEqual(self.ran, [])
            self.assertTrue(await self.manager.answer_typed_confirm("c", ["other", self.scope], "yes"))
        self.assertEqual(self.ran, ["once"])
        await until(lambda: card.state != "pending")
        update = self.updates()[-1]
        self.assertEqual(update["answer"], {"kind": "choices", "indices": [0]})
        self.assertNotIn("of", update)
        self.assertEqual(self.sent()[-1], "/new: once")
        # With no card (the bridge cannot show one), the same reply answers Hermes directly.
        self.register(confirm_id="2")
        with patch.dict(sys.modules, inbound()):
            self.assertTrue(await self.manager.answer_typed_confirm("c", [self.scope], "always"))
            self.assertFalse(await self.manager.answer_typed_confirm("c", [self.scope], "always"))
        self.assertEqual(self.ran, ["once", "always"])

    async def test_a_confirmation_hermes_drops_or_replaces_is_cancelled_and_runs_nothing(self):
        card = await self.confirm()
        self.native.clear(self.scope)  # a session reset
        await until(lambda: card.state != "pending")
        self.assertEqual(card.state, "cancelled")
        first = await self.confirm(confirm_id="2")
        second = await self.confirm(confirm_id="3")  # a newer confirmation of the session
        await until(lambda: first.state != "pending")
        self.assertEqual((first.state, second.state), ("cancelled", "pending"))
        request = await self.answer(first, {"kind": "choices", "indices": [0]})
        self.assertEqual(self.ran, [])
        self.assertEqual((self.updates()[-1]["state"], self.updates()[-1]["of"]), ("cancelled", request["id"]))
        self.assertEqual(self.native.get_pending(self.scope)["confirm_id"], "3")

    async def test_a_confirmation_past_hermess_five_minutes_expires_and_runs_nothing(self):
        card = await self.confirm()
        card.entry.created -= self.native.DEFAULT_TIMEOUT_SECONDS + 1
        self.native.pending[self.scope]["created_at"] -= self.native.DEFAULT_TIMEOUT_SECONDS + 1
        await until(lambda: card.state != "pending")
        self.assertEqual(card.state, "expired")
        await self.answer(card, {"kind": "choices", "indices": [0]})
        self.assertEqual(self.ran, [])

    async def test_an_answer_hermes_no_longer_takes_answers_with_the_cards_state(self):
        card = await self.confirm()
        # Expired in Hermes between the card's check and the resolver.
        self.native.pending[self.scope]["created_at"] -= self.native.DEFAULT_TIMEOUT_SECONDS + 1
        card.entry.created = time.time()
        request = self.request(card, {"kind": "choices", "indices": [0]})
        await self.manager.answer(request)
        card.entry.created -= self.native.DEFAULT_TIMEOUT_SECONDS + 1
        await asyncio.gather(*self.manager.confirm_runs)
        self.assertEqual(self.ran, [])
        self.assertEqual((self.updates()[-1]["state"], self.updates()[-1]["of"]), ("expired", request["id"]))

    async def test_two_answers_racing_keep_the_receipt_of_the_one_that_ran(self):
        release = asyncio.Event()
        card = await self.confirm(release=release)
        first, second = (self.request(card, {"kind": "choices", "indices": [0]}),
                         self.request(card, {"kind": "choices", "indices": [2]}))
        await self.manager.answer(first)
        await self.manager.answer(second)
        runs = list(self.manager.confirm_runs)
        # The first is running its command; the second found nothing left to resolve.
        await until(lambda: len(self.manager.confirm_runs) == 1)
        release.set()
        await asyncio.gather(*runs)
        self.assertEqual(self.ran, ["once"])
        by_request = {m.get("of"): m for m in self.updates()}
        self.assertEqual((by_request[first["id"]]["state"], by_request[first["id"]]["answer"]),
                         ("answered", {"kind": "choices", "indices": [0]}))
        self.assertEqual(by_request[second["id"]]["answer"], {"kind": "choices", "indices": [0]})

    async def test_a_card_the_bridge_refuses_goes_as_text_a_reply_answers(self):
        card = await self.confirm()
        await self.manager.refused(card.ask_id, "bad_message")
        self.assertFalse(self.manager.cards)
        text = self.sent()[-1]
        self.assertIn("discards the current conversation history", text)
        self.assertTrue(text.endswith(ENDS))
        self.assertIsNotNone(self.native.get_pending(self.scope))

    async def test_a_bridge_back_without_questions_gets_the_confirmation_as_text(self):
        card = await self.confirm()
        self.manager.bridge_supports = False
        await self.manager.fallback_cards()
        self.assertTrue(self.sent()[-1].endswith(ENDS))
        self.assertEqual(card.state, "pending")
        self.assertIsNotNone(self.native.get_pending(self.scope))

    async def test_where_no_card_can_show_it_the_channel_sends_its_own_text_not_hermess(self):
        self.register()
        # A bridge without questions.
        self.manager.bridge_supports = False
        self.assertTrue(await self.manager.ask_confirm("c", "/new", PROMPT, self.scope, "1"))
        self.assertTrue(self.sent()[-1].endswith(ENDS))
        self.assertNotIn("/approve", self.sent()[-1])
        # A confirmation that cannot be bound (Hermes's registry changed).
        self.manager.bridge_supports = True
        self.native.register = Mock(side_effect=RuntimeError("changed"))
        with self.assertLogs(slash_confirms.logger, "WARNING"):
            self.assertTrue(await self.manager.ask_confirm("c", "/new", PROMPT, self.scope, "1"))
        self.assertTrue(self.sent()[-1].endswith(ENDS))
        self.assertFalse(self.manager.cards)
        # Text that cannot be sent either: Hermes sends its own.
        self.send.return_value = types.SimpleNamespace(success=False, error="offline")
        with self.assertLogs(questions.logger, "WARNING") as logs:
            self.assertFalse(await self.manager.ask_confirm("c", "/new", PROMPT, self.scope, "1"))
        self.assertIn("conversation c", logs.output[-1])
        self.assertIn("confirmation 1", logs.output[-1])

    async def test_without_hermess_registry_or_a_pending_confirmation_hermes_sends_its_text(self):
        self.register()
        self.manager.confirms_native = lambda: None
        self.assertFalse(await self.manager.ask_confirm("c", "/new", PROMPT, self.scope, "1"))
        self.manager.confirms_native = lambda: self.native
        with self.assertLogs(questions.logger, "WARNING"):
            self.assertFalse(await self.manager.ask_confirm("c", "/new", PROMPT, self.scope, "other"))
        self.assertFalse(self.outbox.pending())
        self.send.assert_not_awaited()

    async def test_a_reply_that_cannot_be_sent_is_logged_with_the_command(self):
        card = await self.confirm()
        self.send.return_value = types.SimpleNamespace(success=False, error="offline")
        with self.assertLogs(questions.logger, "ERROR") as logs:
            await self.answer(card, {"kind": "choices", "indices": [0]})
        self.assertIn("/new", logs.output[-1])
        self.assertIn("confirmation 1", logs.output[-1])

    async def test_closing_the_channel_drops_the_confirmation_with_its_card(self):
        card = await self.confirm()
        await self.manager.close()
        self.assertIsNone(self.native.get_pending(self.scope))
        self.assertEqual(card.state, "cancelled")
        self.assertEqual(self.ran, [])

    async def test_a_confirmed_command_running_when_the_channel_closes_runs_to_its_end(self):
        release = asyncio.Event()
        card = await self.confirm(release=release)
        await self.manager.answer(self.request(card, {"kind": "choices", "indices": [0]}))
        runs = list(self.manager.confirm_runs)
        await until(lambda: self.ran == ["once"])
        await self.manager.close()
        self.assertFalse(any(run.done() for run in runs))
        release.set()
        await asyncio.gather(*runs)
        self.assertFalse(any(run.cancelled() for run in runs))
        self.assertEqual(self.sent()[-1], "/new: once")

    async def test_a_clarify_retirement_never_settles_a_confirmation(self):
        card = await self.confirm()
        await self.manager.retire(card.native_id)
        self.assertEqual(card.state, "pending")
        self.assertEqual(self.updates(), [])

    def test_a_registry_missing_a_function_is_said_once_and_confirmations_go_as_text(self):
        tools = types.ModuleType("tools")
        tools.slash_confirm = types.SimpleNamespace(register=Mock(), get_pending=Mock())
        with patch.dict(sys.modules, {"tools": tools, "tools.slash_confirm": tools.slash_confirm}), \
                patch.object(slash_confirms, "_warned", False), self.assertLogs(slash_confirms.logger, "WARNING") as logs:
            self.assertIsNone(slash_confirms.native())
            self.assertIsNone(slash_confirms.native())
        self.assertEqual(len(logs.records), 1)
        self.assertIn("resolve, clear", logs.output[0])


@unittest.skipUnless(os.environ.get("ENCLOS_HERMES_SOURCE"), "optional real Hermes checkout")
class NativeHermesSlashConfirms(unittest.IsolatedAsyncioTestCase):
    """The channel against Hermes's own confirmation flow: its gateway mixins ask,
    through the adapter's `send_slash_confirm`, and run the command's handler."""

    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        (self.home / "config.yaml").write_text("approvals:\n  timeout: 5\n")
        # Hermes's config writer sets up its logs in this home: they go with it.
        root, before = logging.getLogger(), list(logging.getLogger().handlers)

        def drop_hermes_logs():
            for handler in [h for h in root.handlers if h not in before]:
                root.removeHandler(handler)
                handler.close()
        self.addCleanup(drop_hermes_logs)
        self.env = patch.dict(os.environ, {"HERMES_HOME": str(self.home), "HERMES_RUNTIME_DIR": str(self.home / "run")})
        self.env.start()
        self.addCleanup(self.env.stop)
        source = os.environ["ENCLOS_HERMES_SOURCE"]
        sys.path.insert(0, source)
        self.addCleanup(sys.path.remove, source)
        self.native = importlib.import_module("tools.slash_confirm")
        base = importlib.import_module("gateway.platforms.base")
        self.EphemeralReply = base.EphemeralReply
        config = importlib.import_module("gateway.config")
        event = importlib.import_module("gateway.platforms.event")
        self.MessageEvent, self.MessageType = event.MessageEvent, event.MessageType
        sys.modules.pop("enclos.adapter", None)
        adapter_module = importlib.import_module("enclos.adapter")
        self.addCleanup(sys.modules.pop, "enclos.adapter", None)
        self.adapter = adapter_module.EnclosAdapter.__new__(adapter_module.EnclosAdapter)
        base.BasePlatformAdapter.__init__(self.adapter, config.PlatformConfig(enabled=True), config.Platform.LOCAL)
        self.adapter._outbox = Outbox(str(self.home / "outbox"))
        self.adapter._write = AsyncMock(return_value=True)
        self.adapter._check_title_soon = Mock()
        self.adapter._suggested_replies = {}
        self.manager = questions.Manager(self.adapter._outbox, self.adapter._write, self.adapter.send)
        self.manager.bridge_supports = True
        self.adapter._questions = self.manager
        self.addAsyncCleanup(self.manager.close)
        self.scope = f"confirm-{uuid.uuid4()}"
        self.addCleanup(self.native.clear, self.scope)
        from gateway.run_busy import GatewayBusySessionMixin
        from gateway.run_inbound import GatewayInboundMixin
        from gateway.slash_commands import GatewaySlashCommandsMixin

        class Runner(GatewayBusySessionMixin, GatewayInboundMixin, GatewaySlashCommandsMixin):
            pass
        # Hermes's gateway routing, without a gateway: its own tests drive these
        # mixins on a bare runner too.
        self.runner = object.__new__(Runner)
        self.runner._session_key_for_source = lambda source: self.scope
        self.runner._delivery_adapter_for = lambda source: self.adapter
        self.runner._thread_metadata_for_source = lambda source, anchor=None: None
        self.runner._reply_anchor_for_event = lambda event: None
        self.runner.adapters = {}
        self.runner._profile_name_for_source = lambda source, adapter_profile=None: adapter_profile

    def event(self, text):
        source = self.adapter.build_source(chat_id="c", chat_name="c", chat_type="dm", user_id="p", user_name="p")
        return self.MessageEvent(text=text, message_type=self.MessageType.TEXT, source=source, message_id=str(uuid.uuid4()))

    async def ask_new(self, reply="A fresh session."):
        self.ran = []

        async def execute():
            self.ran.append("new")
            return reply
        # None: the channel showed it, so Hermes sends no text of its own.
        self.assertIsNone(await self.runner._maybe_confirm_destructive_slash(
            event=self.event("/new"), command="new", title="/new",
            detail="This starts a fresh session.", execute=execute))
        cards = list(self.manager.cards.values())
        return cards[-1] if cards else None

    async def answer(self, card, index):
        await self.manager.answer(protocol._message("question.answer", conversation="c", question=card.definition["id"],
                                                    answer={"kind": "choices", "indices": [index]}))
        await asyncio.gather(*self.manager.confirm_runs)

    def messages(self):
        return [m["text"] for m in self.adapter._outbox.pending() if m["type"] == "message.out"]

    def config(self):
        return (self.home / "config.yaml").read_text()

    def test_the_hook_and_registry_are_hermess(self):
        from gateway.platforms.base import BasePlatformAdapter
        self.assertEqual(list(inspect.signature(BasePlatformAdapter.send_slash_confirm).parameters),
                         ["self", "chat_id", "title", "message", "session_key", "confirm_id", "metadata"])
        with patch.object(slash_confirms, "_warned", False):
            self.assertIs(slash_confirms.native(), self.native)
        self.assertIn("authority", inspect.signature(self.native.register).parameters)

    async def test_always_runs_the_command_and_turns_the_confirmation_off_in_the_agents_settings(self):
        card = await self.ask_new()
        self.assertEqual(card.definition["choices"], ["Approve once", "Always", "Cancel"])
        self.assertIn("This starts a fresh session.", card.definition["text"])
        self.assertNotIn("/approve", card.definition["text"])
        await self.answer(card, 1)
        self.assertEqual(self.ran, ["new"])
        self.assertEqual(card.state, "answered")
        # What Hermes reads before each such command, left out of what restarts the
        # gateway (ADR 0069).
        self.assertIn("destructive_slash_confirm: false", self.config())
        self.assertTrue(self.messages()[-1].startswith("A fresh session."))
        self.assertIsNone(self.native.get_pending(self.scope))

    async def test_hermes_reads_the_opt_out_from_disk_before_each_command(self):
        (self.home / "config.yaml").write_text("approvals:\n  destructive_slash_confirm: false\n")
        ran = []

        async def execute():
            ran.append("new")
            return "A fresh session."
        reply = await self.runner._maybe_confirm_destructive_slash(
            event=self.event("/new"), command="new", title="/new", detail="This starts a fresh session.",
            execute=execute)
        self.assertEqual((reply, ran), ("A fresh session.", ["new"]))
        self.assertFalse(self.manager.cards)

    async def test_cancel_runs_nothing(self):
        card = await self.ask_new()
        await self.answer(card, 2)
        self.assertEqual(self.ran, [])
        self.assertIn("/new", self.messages()[-1])
        self.assertNotIn("destructive_slash_confirm", self.config())

    async def test_the_reply_of_new_hermes_marks_ephemeral_is_still_sent(self):
        card = await self.ask_new(self.EphemeralReply("A fresh session.", ttl_seconds=30))
        await self.answer(card, 0)
        self.assertEqual(self.messages()[-1], "A fresh session.")

    async def test_a_reply_typed_in_the_composer_is_read_by_hermes_and_closes_the_card(self):
        card = await self.ask_new()
        reply = await self.runner._hm_slash_confirm_reply(self.event("yes"), self.scope)
        self.assertEqual(reply, "A fresh session.")
        self.assertEqual(self.ran, ["new"])
        await until(lambda: card.state != "pending")
        self.assertEqual(card.state, "answered")
        update = [m for m in self.adapter._outbox.pending() if m["type"] == "question.update"][-1]
        self.assertEqual(update["answer"], {"kind": "choices", "indices": [0]})
        self.assertNotIn("of", update)

    async def test_without_the_bridges_questions_the_channels_text_is_answered_by_its_words(self):
        self.manager.bridge_supports = False
        for word, ran, written in (("yes", ["new"], False), ("cancel", [], False), ("always", ["new"], True)):
            self.assertIsNone(await self.ask_new())
            self.assertTrue(self.messages()[-1].endswith(ENDS), self.messages()[-1])
            self.assertNotIn("/approve", self.messages()[-1])
            self.assertIsNotNone(self.native.get_pending(self.scope))
            await self.runner._hm_slash_confirm_reply(self.event(word), self.scope)
            self.assertEqual(self.ran, ran, word)
            self.assertEqual("destructive_slash_confirm: false" in self.config(), written, word)
            self.assertIsNone(self.native.get_pending(self.scope))

    async def test_a_reply_while_a_turn_runs_is_answered_by_the_channel_not_hermes(self):
        card = await self.ask_new()
        self.adapter.gateway_runner = self.runner
        self.adapter._active_sessions[self.scope] = asyncio.Event()
        self.adapter._seen, self.adapter._last_in = collections.OrderedDict(), {}
        self.adapter._interrupts = types.SimpleNamespace(admit=lambda event: None, complete=lambda event: None)
        self.adapter.handle_message = AsyncMock()
        await self.adapter._on_message(protocol._message("message.in", conversation="c", person="p", text="Yes"))
        self.adapter.handle_message.assert_not_awaited()
        self.assertEqual(self.ran, ["new"])
        await until(lambda: card.state != "pending")
        self.assertEqual(self.messages()[-1], "A fresh session.")

    def test_typed_text_is_read_with_hermess_own_words(self):
        offered = slash_confirms.CHOICES
        for text, choice in (("yes", "once"), (" Approve Once ", "once"), ("/always", "always"),
                             ("remember", "always"), ("nevermind", "cancel"), ("/cancel", "cancel"),
                             ("maybe", None)):
            self.assertEqual(slash_confirms.typed_choice(text, offered), choice, text)

    async def test_reload_mcp_asks_with_hermess_own_explanation(self):
        self.runner._execute_mcp_reload = AsyncMock(return_value="Reloaded.")
        self.assertIsNone(await self.runner._handle_reload_mcp_command(self.event("/reload-mcp")))
        card = list(self.manager.cards.values())[-1]
        self.assertEqual(len(card.definition["choices"]), 3)
        self.assertIn("prompt cache", card.definition["text"])
        self.assertNotIn("/approve", card.definition["text"])
        await self.answer(card, 1)
        self.runner._execute_mcp_reload.assert_awaited_once()
        self.assertTrue(self.messages()[-1].startswith("Reloaded."))
        self.assertIn("mcp_reload_confirm: false", self.config())

    async def test_undo_asks_through_hermess_own_command(self):
        self.runner._handle_undo_command = AsyncMock(return_value="Undone.")
        handled, reply = await self.runner._hm_cmd_undo(self.event("/undo 2"), None, self.scope)
        self.assertEqual((handled, reply), (True, None))
        card = list(self.manager.cards.values())[-1]
        self.assertEqual(card.definition["choices"], ["Approve once", "Always", "Cancel"])
        await self.answer(card, 0)
        self.runner._handle_undo_command.assert_awaited_once()
        self.assertEqual(self.messages()[-1], "Undone.")

    async def test_a_model_guards_confirmation_offers_no_always(self):
        handler = AsyncMock(return_value="Switched.")
        # The path Hermes's `/model` guard takes (`slash_commands_model.py`).
        self.assertIsNone(await self.runner._request_slash_confirm(
            event=self.event("/model big"), command="model", title="Expensive model",
            message="⚠️ **Expensive model**\n\nIt costs more.\n\n_Text fallback: reply `/approve` to switch._",
            handler=handler))
        card = list(self.manager.cards.values())[-1]
        self.assertEqual(card.definition["choices"], ["Approve once", "Cancel"])
        self.assertNotIn("/approve", card.definition["text"])
        await self.answer(card, 0)
        handler.assert_awaited_once_with("once")


if __name__ == "__main__":
    unittest.main()
