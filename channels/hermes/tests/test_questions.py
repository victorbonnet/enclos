"""Question delivery/control contracts; optional real Hermes registry, temporary homes only."""

import asyncio
import importlib
import inspect
import json
import os
import re
import sys
import tempfile
import threading
import types
import unittest
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enclos import protocol, questions, visible
from enclos.outbox import Outbox


class Native:
    SKIPPED, CANCELLED = "\0skipped", "\0cancelled"

    def __init__(self):
        self.entries = {}
        self.resolutions = []

    def register(self, native_id, session_key, question, choices, multi_select=False):
        entry = types.SimpleNamespace(clarify_id=native_id, session_key=session_key, question=question,
                                      choices=choices, multi_select=multi_select,
                                      event=threading.Event(), response=None, awaiting_text=not choices)
        self.entries[native_id] = entry
        return entry

    def get_pending(self, native_id):
        entry = self.entries.get(native_id)
        return entry if entry and not entry.event.is_set() else None

    def resolve_gateway_clarify(self, native_id, response):
        entry = self.get_pending(native_id)
        if entry is None:
            return False
        self.resolutions.append((native_id, response))
        entry.response = response
        entry.event.set()
        return True

    def mark_awaiting_text(self, native_id):
        entry = self.get_pending(native_id)
        if entry:
            entry.awaiting_text = True
        return entry is not None


class QuestionProtocol(unittest.TestCase):
    def decode(self, kind, **fields):
        return protocol.decode_from_bridge(protocol.encode_line(protocol._message(kind, **fields)))

    def test_new_and_old_hello_capabilities(self):
        self.assertNotIn("capabilities", self.decode("hello", token="t"))
        self.assertEqual(self.decode("hello", token="t", capabilities=["questions"])["capabilities"], ["questions"])
        with self.assertRaises(protocol.DecodeError):
            self.decode("hello", token="t", capabilities="questions")

    def test_response_and_sync_are_typed_controls(self):
        pasted = {"kind": "text", "text": "Line one\nLine two end"}
        self.assertEqual(self.decode("question.answer", conversation="c", question="q", answer=pasted)["answer"], pasted)
        self.assertEqual(self.decode("question.answer", conversation="c", question="q",
                                     answer={"kind": "choices", "indices": [0]})["type"], "question.answer")
        self.assertEqual(self.decode("question.sync", questions=["q"])["questions"], ["q"])
        for answer in ({"kind": "choices", "indices": []}, {"kind": "choices", "indices": [True]},
                       {"kind": "choices", "indices": [1, 1]}, {"kind": "text", "text": "\0skipped"},
                       {"kind": "text", "text": "\0cancelled"},
                       {"kind": "text", "text": "hello\x85"}, {"kind": "skip", "text": "x"},
                       {"kind": "text", "text": " "}, {"kind": "text", "text": "x" * 8192},
                       # A CR or a tab is not seen either: the app sends plain newlines.
                       {"kind": "text", "text": "Line one\r\nLine two"}, {"kind": "text", "text": "tab\there"}):
            with self.subTest(answer=str(answer)[:100]), self.assertRaises(protocol.DecodeError):
                self.decode("question.answer", conversation="c", question="q", answer=answer)
        with self.assertRaises(protocol.DecodeError):
            self.decode("question.sync", questions=["q"] * 129)

    def test_definition_bounds_preserve_labels_and_normalize_selection_order(self):
        value = {"id": "q", "text": "Which?", "choices": [f"C{i}" for i in range(12)], "multiple": True}
        self.assertEqual(questions.validate_definition(value), value)
        self.assertEqual(questions.validate_answer({"kind": "choices", "indices": [2, 0]}, value),
                         {"kind": "choices", "indices": [0, 2]})
        for changed in ({**value, "choices": value["choices"] + ["extra"]},
                        {**value, "text": "x" * (24 * 1024)}, {**value, "choices": [" "]}):
            with self.assertRaises(ValueError):
                questions.validate_definition(changed)

    def test_skill_is_explicitly_registered_and_optional(self):
        ctx = types.SimpleNamespace(register_skill=Mock())
        questions.register_skill(ctx)
        name, path, description = ctx.register_skill.call_args.args
        self.assertEqual(name, "app-questions")
        self.assertTrue(path.is_file())
        self.assertIn('"multi_select":true', path.read_text())
        self.assertNotIn("disable-model-invocation", path.read_text())
        self.assertIn(f"description: {description}", path.read_text())
        self.assertIn("choice or missing information", description)
        self.assertIn("answering a question does not change policy", path.read_text())
        questions.register_skill(object())

    def test_missing_public_native_query_disables_native_cards_and_says_so_once(self):
        fake_tools = types.ModuleType("tools")
        fake_tools.clarify_gateway = types.SimpleNamespace(resolve_gateway_clarify=lambda *_: True)
        with patch.dict(sys.modules, {"tools": fake_tools}), patch.object(questions, "_warned_native", False):
            with self.assertLogs(questions.logger, "WARNING") as logs:
                self.assertIsNone(questions._native())
                self.assertIsNone(questions._native())
            self.assertEqual(len(logs.records), 1)
            self.assertIn("get_pending", logs.output[0])
            self.assertIn("SKIPPED", logs.output[0])

    def test_hidden_characters_and_duplicate_labels_follow_the_protocol_rule(self):
        # The characters of enclos-protocol's `visible` tests, and the same verdicts.
        for code in (0x202E, 0x2066, 0x200B, 0x200E, 0xFEFF, 0x061C, 0x0007, 0x0085, 0x00AD,
                     0x034F, 0x115F, 0x3164, 0xFFA0, 0x2800, 0x2028, 0x2029, 0x206A, 0xFFF9,
                     0xFE00, 0xE0041, 0xE007F, 0xE0100, 0x200D):
            self.assertTrue(visible.is_hidden(chr(code)), hex(code))
            self.assertTrue(visible.has_hidden("a" + chr(code) + "b", True), hex(code))
        for char in "a\u00e9\u00df\u4e2d\U0001f600 -\u06cc":
            self.assertFalse(visible.is_hidden(char), char)
        value = {"id": "q", "text": "Which?", "choices": ["Allow", "Deny"], "multiple": False}
        for changed in ({**value, "choices": ["Deny\u202Ewolla", "Allow"]},
                        {**value, "choices": ["Allow\u200B", "Allow"]},
                        {**value, "choices": ["Allow\U000E0041", "Allow"]},
                        {**value, "choices": ["\u2764", "\u2764\uFE0F"]},
                        {**value, "choices": ["Allow\u2028"]},
                        {**value, "choices": ["\u3164"]},
                        {**value, "choices": ["Allow", "Allow"]},
                        {**value, "choices": ["Two\nlines"]},
                        {**value, "choices": ["Tab\there"]},
                        {**value, "text": "Which\u2066?"}, {**value, "text": "Which\r\n?"},
                        {**value, "text": "Which\t?"}):
            with self.subTest(changed=str(changed)), self.assertRaises(ValueError):
                questions.validate_definition(changed)
        self.assertEqual(questions.validate_definition({**value, "text": "Which?\nPick one."})["text"],
                         "Which?\nPick one.")
        for text in ("ok\u200D", "a\tb", "a\r\nb", "\u00AD"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                questions.validate_answer({"kind": "text", "text": text}, value)
        # Persian spelling, a joined emoji and an emoji's presentation selector are text.
        for text in ("\u0645\u06CC\u200C\u062E\u0648\u0627\u0647\u0645", "\U0001F469\u200D\U0001F4BB",
                     "\u2764\uFE0F"):
            with self.subTest(text=text):
                self.assertEqual(questions.validate_answer({"kind": "text", "text": text}, value)["text"], text)
                self.assertEqual(questions.validate_definition({**value, "text": text})["text"], text)
                questions.validate_definition({**value, "choices": [text, "Deny"]})


class AdapterControls(unittest.IsolatedAsyncioTestCase):
    async def test_typed_answer_and_sync_never_become_a_chat_turn(self):
        config = types.ModuleType("gateway.config")
        config.Platform = config.PlatformConfig = Mock
        shared = types.ModuleType("gateway.platforms._shared")
        shared.get_scoped_secret = Mock(return_value="")
        base = types.ModuleType("gateway.platforms.base")
        base.BasePlatformAdapter = object
        base.SendResult = Mock
        event = types.ModuleType("gateway.platforms.event")
        event.MessageEvent = event.MessageType = Mock
        modules = {"gateway": types.ModuleType("gateway"), "gateway.config": config,
                   "gateway.platforms": types.ModuleType("gateway.platforms"),
                   "gateway.platforms._shared": shared, "gateway.platforms.base": base,
                   "gateway.platforms.event": event}
        with patch.dict(sys.modules, modules):
            sys.modules.pop("enclos.adapter", None)
            adapter_module = importlib.import_module("enclos.adapter")
            adapter = adapter_module.EnclosAdapter.__new__(adapter_module.EnclosAdapter)
            adapter._questions = types.SimpleNamespace(answer=AsyncMock(), sync=AsyncMock())
            adapter._on_message = AsyncMock()
            adapter._write = AsyncMock(return_value=True)
            answer = protocol._message("question.answer", conversation="c", question="q", answer={"kind": "skip"})
            await adapter._on_line(protocol.encode_line(answer))
            adapter._questions.answer.assert_awaited_once_with(answer)
            adapter._on_message.assert_not_awaited()
            sync = protocol._message("question.sync", questions=["q"])
            await adapter._on_line(protocol.encode_line(sync))
            adapter._questions.sync.assert_awaited_once_with(["q"])
            self.assertEqual(adapter._write.call_args.args[0]["of"], sync["id"])
            adapter._questions.refused = AsyncMock()
            adapter.name = "enclos"
            adapter._outbox = types.SimpleNamespace(set_aside=lambda of: False)
            refusal = protocol.error("bad_message", "Too many questions are waiting.", "ask-1")
            await adapter._on_line(protocol.encode_line(refusal))
            adapter._questions.refused.assert_awaited_once_with("ask-1", "bad_message")
        sys.modules.pop("enclos.adapter", None)


class QuestionDelivery(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.native = Native()
        self.scope = f"session-{uuid.uuid4()}"
        self.adapter = types.SimpleNamespace(_outbox=Outbox(self.temporary.name),
                                             _write=AsyncMock(return_value=True),
                                             send=AsyncMock(return_value=types.SimpleNamespace(success=True)))
        self.manager = questions.Manager(self.adapter._outbox, self.adapter._write, self.adapter.send, native=lambda: self.native)
        self.manager.bridge_supports = True
        self.addAsyncCleanup(self.manager.close)

    async def ask(self, choices=None, multiple=False, question="Which?", native_id=None):
        native_id = native_id or str(uuid.uuid4())
        entry = self.native.register(native_id, self.scope, question, choices, multi_select=multiple)
        self.assertTrue(await self.manager.ask("c", question, choices, native_id, self.scope))
        return entry, list(self.manager.cards.values())[-1]

    def answer(self, card, answer, **fields):
        return protocol._message("question.answer", conversation="c", question=card.definition["id"],
                                 answer=answer, **fields)

    def updates(self):
        return [m for m in self.adapter._outbox.pending() if m["type"] == "question.update"]

    async def test_single_choice_unblocks_exact_wait_and_confirms_canonical_answer(self):
        entry, card = await self.ask(["First (Recommended)", "Second"])
        waiting = asyncio.create_task(asyncio.to_thread(entry.event.wait, 2))
        request = self.answer(card, {"kind": "choices", "indices": [1]})
        await self.manager.answer(request)
        self.assertTrue(await waiting)
        self.assertEqual(entry.response, "Second")
        self.assertEqual(self.updates()[-1]["of"], request["id"])
        self.assertEqual(self.updates()[-1]["answer"], {"kind": "choices", "indices": [1]})
        # A native card leaves Hermes's prose rule alone: typed prose cancels, not answers.
        self.assertFalse(entry.awaiting_text)
        self.adapter.send.assert_not_awaited()
        await self.manager.answer(self.answer(card, {"kind": "choices", "indices": [0]}))
        self.assertEqual(entry.response, "Second")
        self.assertEqual(self.updates()[-1]["answer"]["indices"], [1])

    async def test_multi_other_and_skip_route_native_shapes(self):
        entry, card = await self.ask(["One", "Two", "Three"], True)
        await self.manager.answer(self.answer(card, {"kind": "choices", "indices": [2, 0]}))
        self.assertEqual(json.loads(entry.response), ["One", "Three"])
        self.assertEqual(self.updates()[-1]["answer"]["indices"], [0, 2])
        entry, card = await self.ask(["One", "Two"], True)
        await self.manager.answer(self.answer(card, {"kind": "text", "text": "Other\nanswer"}))
        self.assertEqual(entry.response, "Other\nanswer")
        entry, card = await self.ask()
        await self.manager.answer(self.answer(card, {"kind": "skip"}))
        self.assertEqual(entry.response, self.native.SKIPPED)
        self.assertEqual(self.updates()[-1]["state"], "skipped")
        self.assertNotIn("answer", self.updates()[-1])

    async def test_forged_scope_identity_or_sentinel_never_resolves_any_wait(self):
        entry, card = await self.ask(["One", "Two"])
        for request in ({**self.answer(card, {"kind": "choices", "indices": [0]}), "conversation": "foreign"},
                        self.answer(card, {"kind": "text", "text": self.native.CANCELLED}),
                        self.answer(card, {"kind": "choices", "indices": [2]}),
                        self.answer(card, {"kind": "choices", "indices": [0, 1]})):
            await self.manager.answer(request)
        self.assertFalse(entry.event.is_set())
        replacement = self.native.register(card.native_id, "another-session", "Other?", ["Else"])
        await self.manager.answer(self.answer(card, {"kind": "choices", "indices": [0]}))
        self.assertFalse(replacement.event.is_set())
        self.assertEqual(card.state, "expired")

    async def test_native_typed_answer_and_timeout_or_reset_retire_without_extra_turn(self):
        entry, card = await self.ask(["One", "Two", "Three"], True)
        self.native.resolve_gateway_clarify(card.native_id, '["Three", "One"]')
        await self.manager.retire(card.native_id)
        self.assertEqual(self.updates()[-1]["answer"], {"kind": "choices", "indices": [0, 2]})
        entry, card = await self.ask(["One", "Two"])
        entry.event.set()
        await asyncio.sleep(0.15)
        self.assertEqual(card.state, "expired")
        entry, card = await self.ask()
        self.native.resolve_gateway_clarify(card.native_id, self.native.CANCELLED)
        await self.manager.retire(card.native_id)
        self.assertEqual(card.state, "cancelled")

    async def test_a_typed_answer_the_app_cannot_carry_is_still_answered(self):
        # Hermes accepts any composer text; the agent has it, so the card is not cancelled.
        entry, card = await self.ask()
        self.native.resolve_gateway_clarify(card.native_id, "ok" + chr(0x202E) + "kc")
        await self.manager.retire(card.native_id)
        self.assertEqual(card.state, "answered")
        self.assertEqual(self.updates()[-1]["state"], "answered")
        self.assertNotIn("answer", self.updates()[-1])

    async def test_watcher_first_still_gets_exact_correlated_confirmation(self):
        entry, card = await self.ask(["One", "Two"])
        self.native.resolve_gateway_clarify(card.native_id, "One")
        await self.manager.retire(card.native_id)
        self.assertNotIn("of", self.updates()[-1])
        for indices in ([0], [1]):
            request = self.answer(card, {"kind": "choices", "indices": indices})
            await self.manager.answer(request)
            update = self.updates()[-1]
            self.assertEqual(update["of"], request["id"])
            self.assertEqual(update["answer"], {"kind": "choices", "indices": [0]})
        self.assertEqual(entry.response, "One")

    async def test_reconnect_replays_durable_ask_and_settlement_then_restart_expires_missing(self):
        entry, card = await self.ask(["One", "Two"])
        replayed = Outbox(self.temporary.name).pending()
        self.assertEqual(replayed[0]["type"], "question.ask")
        await self.manager.sync([card.definition["id"]])
        self.assertEqual(self.updates()[-1]["state"], "pending")
        await self.manager.answer(self.answer(card, {"kind": "skip"}))
        for message in self.adapter._outbox.pending():
            self.adapter._outbox.acknowledge(message["id"])
        await self.manager.sync([card.definition["id"]])
        self.assertEqual(self.updates()[-1]["state"], "skipped")
        self.assertNotIn("of", self.updates()[-1])
        restarted = questions.Manager(self.adapter._outbox, self.adapter._write, self.adapter.send, native=lambda: self.native)
        await restarted.sync([card.definition["id"]])
        self.assertEqual(self.updates()[-1]["state"], "expired")

    async def test_older_bridge_and_oversized_card_keep_all_native_text(self):
        self.manager.bridge_supports = False
        self.assertFalse(self.manager.available)
        labels = ["é" * 8000 + str(i) for i in range(4)]
        entry = self.native.register("fallback", self.scope, "Long?", labels)
        self.assertTrue(await self.manager.ask("c", "Long?", labels, "fallback", self.scope))
        output = "".join(call.args[1] for call in self.adapter.send.await_args_list)
        for label in labels:
            self.assertIn(label, output)
        self.assertTrue(all(len(call.args[1].encode()) <= questions.TEXT_CHUNK_BYTES
                            for call in self.adapter.send.await_args_list))
        self.assertTrue(entry.awaiting_text)
        self.assertFalse(self.manager.cards)
        self.manager.bridge_supports = True
        self.adapter.send.reset_mock()
        self.assertTrue(await self.manager.ask("c", "Long?", labels, "fallback", self.scope))
        self.assertFalse(self.manager.cards)
        self.assertGreater(self.adapter.send.await_count, 1)

    async def test_full_outbox_never_publishes_or_registers_a_card(self):
        self.adapter._outbox._limit = 0
        entry = self.native.register("full", self.scope, "Q?", ["One"])
        self.assertFalse(await self.manager.ask("c", "Q?", ["One"], "full", self.scope))
        self.assertFalse(self.manager.cards)
        self.assertFalse(entry.event.is_set())

    async def test_restart_expires_an_unseen_durable_ask_after_replay(self):
        entry, card = await self.ask(["One", "Two"])
        restarted = questions.Manager(self.adapter._outbox, self.adapter._write, self.adapter.send, native=lambda: self.native)
        replay = restarted.prepare_replay()
        self.assertEqual([m["type"] for m in replay], ["question.ask", "question.update"])
        self.assertEqual(replay[-1]["state"], "expired")
        self.assertEqual(replay[-1]["question"], card.definition["id"])
        self.assertEqual(restarted.prepare_replay(), replay)

    async def test_ack_lost_ask_replay_is_ordered_before_orphan_expiry(self):
        entry, card = await self.ask(["One", "Two"])
        ask = self.adapter._outbox.pending()[0]
        await self.manager.answer(self.answer(card, {"kind": "choices", "indices": [1]}))
        # Only the terminal update ACK arrived; the bridge already has canonical
        # answered state. It must ignore this later unsolicited expiry immutably.
        self.adapter._outbox.acknowledge(self.updates()[-1]["id"])
        restarted = questions.Manager(self.adapter._outbox, self.adapter._write, self.adapter.send, native=lambda: self.native)
        replay = restarted.prepare_replay()
        self.assertEqual(replay[0], ask)
        self.assertEqual(replay[1]["state"], "expired")
        self.assertNotIn("of", replay[1])
        self.assertEqual(entry.response, "Two")

    async def test_full_replay_outbox_retries_orphan_expiry_after_ask_ack(self):
        entry, card = await self.ask(["One", "Two"])
        self.adapter._outbox._limit = 1
        restarted = questions.Manager(self.adapter._outbox, self.adapter._write, self.adapter.send, native=lambda: self.native)
        restarted.bridge_supports = True
        self.addAsyncCleanup(restarted.close)
        replay = restarted.prepare_replay()
        self.assertEqual(len(replay), 1)
        restarted.prepare_replay()
        self.assertEqual(len(restarted.tasks), 1)
        self.adapter._outbox.acknowledge(replay[0]["id"])
        await asyncio.sleep(0.4)
        self.assertEqual(self.updates()[-1]["state"], "expired")
        self.assertEqual(self.updates()[-1]["question"], card.definition["id"])

    async def test_legacy_bridge_reconnect_restores_existing_card_as_complete_text(self):
        entry, card = await self.ask(["One", "Two"])
        self.manager.bridge_supports = False
        self.adapter._write.reset_mock()
        await self.manager.fallback_cards()
        output = "".join(call.args[1] for call in self.adapter.send.await_args_list)
        self.assertIn("1. One", output)
        self.assertIn("2. Two", output)
        await self.manager.answer(self.answer(card, {"kind": "skip"}))
        self.assertEqual(self.updates()[-1]["state"], "skipped")
        self.adapter._write.assert_not_awaited()

    async def test_settlement_is_retried_after_an_outbox_capacity_failure(self):
        entry, card = await self.ask(["One", "Two"])
        self.adapter._outbox._limit = 1
        await self.manager.answer(self.answer(card, {"kind": "skip"}))
        self.assertTrue(entry.event.is_set())
        self.assertFalse(card.queued)
        self.adapter._outbox.acknowledge(self.adapter._outbox.pending()[0]["id"])
        await asyncio.sleep(0.4)
        self.assertTrue(card.queued)
        self.assertEqual(self.updates()[-1]["state"], "skipped")

    async def test_terminal_ack_releases_card_after_bridge_persistence(self):
        entry, card = await self.ask(["One", "Two"])
        ask_id = self.adapter._outbox.pending()[0]["id"]
        self.manager.acknowledge(ask_id)
        self.assertIn(card.definition["id"], self.manager.cards)
        await self.manager.answer(self.answer(card, {"kind": "skip"}))
        self.manager.acknowledge(self.updates()[-1]["id"])
        self.assertNotIn(card.definition["id"], self.manager.cards)

    def sent_text(self):
        return "".join(call.args[1] for call in self.adapter.send.await_args_list)

    async def test_a_refused_ask_is_shown_as_text_instead_of_waiting_unseen(self):
        entry, card = await self.ask(["One", "Two"])
        await self.manager.refused("not-an-ask")
        self.adapter.send.assert_not_awaited()
        await self.manager.refused(card.ask_id)
        self.assertNotIn(card.definition["id"], self.manager.cards)
        self.assertIn("1. One", self.sent_text())
        self.assertIn("2. Two", self.sent_text())
        # Hermes's own text fallback: a typed answer is captured.
        self.assertTrue(entry.awaiting_text)
        self.assertFalse(entry.event.is_set())
        # The bridge never kept it, so nothing more is said about it.
        before = len(self.updates())
        await asyncio.sleep(0.15)
        self.assertEqual(len(self.updates()), before)

    async def test_a_call_that_does_not_match_its_entry_is_still_shown(self):
        native_id = str(uuid.uuid4())
        self.native.register(native_id, "another-session", "Which?", ["One"])
        self.assertTrue(await self.manager.ask("c", "Which?", ["One"], native_id, self.scope))
        self.assertFalse(self.manager.cards)
        self.assertIn("1. One", self.sent_text())

    async def test_duplicate_or_hidden_labels_never_become_a_card(self):
        for choices in (["Allow", "Allow"], ["Allow\u202E", "Deny"]):
            native_id = str(uuid.uuid4())
            self.native.register(native_id, self.scope, "Which?", choices)
            self.assertTrue(await self.manager.ask("c", "Which?", choices, native_id, self.scope))
        self.assertFalse(self.manager.cards)
        self.assertEqual(self.adapter.send.await_count, 2)

    async def test_an_unreadable_native_entry_cancels_its_card(self):
        entry, card = await self.ask(["One", "Two"])
        del entry.event  # Hermes changed what an entry holds.
        with self.assertLogs(questions.logger, "ERROR"):
            await asyncio.sleep(0.15)
        self.assertEqual(card.state, "cancelled")
        self.assertEqual(self.updates()[-1]["state"], "cancelled")

    async def test_closing_the_channel_cancels_the_native_wait_too(self):
        entry, card = await self.ask(["One", "Two"])
        await self.manager.close()
        self.assertTrue(entry.event.is_set())
        self.assertEqual(entry.response, self.native.CANCELLED)
        self.assertEqual(card.state, "cancelled")
        self.assertEqual(self.updates()[-1]["state"], "cancelled")


@unittest.skipUnless(os.environ.get("ENCLOS_HERMES_SOURCE"), "optional real Hermes checkout")
class NativeHermesQuestions(QuestionDelivery):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.profile = Path(self.temporary.name) / "profile"
        self.profile.mkdir()
        self.env = patch.dict(os.environ, {"HERMES_HOME": str(self.profile), "HERMES_RUNTIME_DIR": str(self.profile / "run")})
        self.env.start()
        self.addCleanup(self.env.stop)
        source = os.environ["ENCLOS_HERMES_SOURCE"]
        sys.path.insert(0, source)
        self.addCleanup(sys.path.remove, source)
        self.native = importlib.import_module("tools.clarify_gateway")
        self.addCleanup(self.native.clear_session, self.scope)
        self.manager.native = lambda: self.native

    async def test_an_unreadable_native_entry_cancels_its_card(self):
        entry, card = await self.ask(["One", "Two"])
        event = entry.event
        del entry.event  # Hermes changed what an entry holds.
        with self.assertLogs(questions.logger, "ERROR"):
            await asyncio.sleep(0.15)
        entry.event = event  # So that Hermes's own cleanup can run.
        self.assertEqual(card.state, "cancelled")

    # What the channel relies on in Hermes: a change there fails here, in CI's
    # `hermes-latest` job, rather than turning questions into text unnoticed.

    def test_the_registry_has_every_native_function_the_channel_calls(self):
        with patch.object(questions, "_warned_native", False):
            self.assertIs(questions._native(), self.native)
        entry = self.native.register("probe", self.scope, "Which?", ["One"], multi_select=False)
        for field in ("session_key", "choices", "multi_select", "event", "response", "question"):
            self.assertTrue(hasattr(entry, field), field)

    def test_the_clarify_timeout_enclos_sets_is_the_key_hermes_reads(self):
        source = (Path(__file__).resolve().parents[3] / "src" / "runtime" / "hermes.rs").read_text()
        seconds = int(re.search(r"const CLARIFY_TIMEOUT_SECONDS: u32 = (\d+);", source).group(1))
        self.assertIn('"agent.clarify_timeout"', source)
        self.assertEqual(self.native.resolve_clarify_timeout({"agent": {"clarify_timeout": seconds}}), seconds)

    def test_the_adapter_hooks_match_hermes(self):
        from gateway.platforms.base import BasePlatformAdapter
        parameters = list(inspect.signature(BasePlatformAdapter.send_clarify).parameters)
        self.assertEqual(parameters, ["self", "chat_id", "question", "choices", "clarify_id",
                                      "session_key", "metadata"])
        gateway = Path(os.environ["ENCLOS_HERMES_SOURCE"]) / "gateway"
        calls = "".join(p.read_text(errors="replace") for p in gateway.rglob("*.py"))
        self.assertIn("retire_clarify_card", calls)

    def test_the_card_text_drops_exactly_hermess_skip_hint(self):
        hint = questions._hermes_text("gateway.clarify.skip_hint", "")
        self.assertTrue(hint)
        self.assertEqual(questions._card_text("Which?\n" + hint), "Which?")


if __name__ == "__main__":
    unittest.main()
