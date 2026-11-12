"""Runtime approvals: typed transport and optional pinned native-source/Event harness."""

import asyncio
import collections
import importlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enclos import protocol, questions, runtime_approvals, visible
from enclos.outbox import Outbox


def prompt(command="echo test", actions=("once", "session", "always", "deny"), **fields):
    return types.SimpleNamespace(chat_id="c", session_key="session", request_id="request-1",
        text="A command needs approval; no answer means it will not run.", command=command,
        description="Native test reason", smart_denied=False, metadata=None,
        actions=[(a.title(), a, "") for a in actions], **fields)


SNAPSHOT = {"request_id": "request-1", "command": "echo test", "description": "Native test reason",
            "pattern_key": "package install scripts", "pattern_keys": ["package install scripts", "pipe to shell"]}


class RuntimeApprovalPatternsAndDisplay(unittest.TestCase):
    def test_session_and_always_name_the_native_patterns_or_are_not_offered(self):
        definition = runtime_approvals.definition(prompt(), "q", SNAPSHOT)
        questions.validate_definition(definition)
        self.assertEqual(definition["approval"]["patterns"], ["package install scripts", "pipe to shell"])
        self.assertEqual(definition["approval"]["actions"], list(runtime_approvals.ACTIONS))
        self.assertEqual(runtime_approvals.patterns({"pattern_key": "recursive delete"}), ["recursive delete"])
        for snapshot in (None, {}, {"pattern_keys": [], "pattern_key": ""}):
            narrowed = runtime_approvals.definition(prompt(), "q", snapshot)
            questions.validate_definition(narrowed)
            self.assertEqual(narrowed["approval"]["actions"], ["once", "deny"])
            self.assertNotIn("patterns", narrowed["approval"])
        deny_only = runtime_approvals.definition(prompt(actions=("deny",)), "q", SNAPSHOT)
        self.assertNotIn("patterns", deny_only["approval"])

    def test_pattern_metadata_is_bounded_visible_and_required_for_grants(self):
        definition = runtime_approvals.definition(prompt(), "q", SNAPSHOT)
        for named in ([], [""], ["a\u202Eb"], ["a", "a"], [f"p{i}" for i in range(17)], "pattern"):
            with self.subTest(named=named), self.assertRaises(ValueError):
                questions.validate_definition({**definition, "approval": {**definition["approval"], "patterns": named}})
        hidden = {**definition["approval"], "command": "\u200B" * 2800}
        with self.assertRaises(ValueError):
            questions.validate_definition({**definition, "approval": hidden})

    def test_revealed_matches_the_shared_rule(self):
        self.assertEqual(runtime_approvals.revealed, visible.revealed)
        self.assertEqual(visible.revealed("ls\u202E -la\tx\ny\r"), "ls⟨U+202E⟩ -la⟨tab⟩x\ny⟨U+000D⟩")
        self.assertEqual(visible.revealed("echo ok é 中"), "echo ok é 中")
        # What the first rule missed: tags, variation selectors, separators, fillers.
        for code in (0x202E, 0x200B, 0xE0041, 0xFE00, 0x2028, 0x2029, 0x206A, 0xFFF9, 0x115F, 0x3164, 0xFFA0):
            self.assertEqual(visible.revealed("rm" + chr(code) + "x"), "rm⟨U+%04X⟩x" % code)
        # A joiner beside ASCII is shown; a joined emoji is text.
        self.assertEqual(visible.revealed("rm\u200Dx"), "rm⟨U+200D⟩x")
        self.assertEqual(visible.revealed("\U0001F469\u200D\U0001F4BB"), "\U0001F469\u200D\U0001F4BB")

    def test_a_long_command_is_numbered_part_by_part(self):
        command = "echo " + "x" * 300
        chunks = list(runtime_approvals.fallback_chunks(prompt(command=command), lambda text: len(text) < 120))
        headed = [c for c in chunks if c.startswith("Command, part ")]
        self.assertGreater(len(headed), 1)
        for number, chunk in enumerate(headed, start=1):
            self.assertTrue(chunk.startswith("Command, part %d of %d:\n" % (number, len(headed))), chunk)
        self.assertEqual("".join(c.split("\n")[2] for c in headed), command)
        self.assertFalse(any(c.startswith("Complete command:") for c in chunks))
        short = list(runtime_approvals.fallback_chunks(prompt(), lambda text: True))
        self.assertIn("Complete command:\n```\necho test\n```", short)

    def test_text_fallback_reveals_flags_and_names_what_a_grant_covers(self):
        tricky = prompt(command="ls #\u202Efr- mr\ncurl https://exаmple.com")
        tricky.text = "A command needs approval:\nls #\u202Efr- mr"
        chunks = list(runtime_approvals.fallback_chunks(tricky, lambda text: len(text) < 4000, "/",
                                                        ["pipe to shell"]))
        text = "\n".join(chunks)
        self.assertNotIn("\u202E", text)
        self.assertIn("ls #⟨U+202E⟩fr- mr", text)
        self.assertIn("outside ASCII", text)
        self.assertIn("every command matching: pipe to shell", text)
        self.assertIn("command_allowlist", text)
        plain = "\n".join(runtime_approvals.fallback_chunks(prompt(actions=("once", "deny")),
                                                            lambda text: True, "/", ["pipe to shell"]))
        self.assertNotIn("outside ASCII", plain)
        self.assertNotIn("every command matching", plain)


class RuntimeApprovalBinding(unittest.IsolatedAsyncioTestCase):
    def binding(self, rows):
        native = types.SimpleNamespace(list_gateway_approvals=Mock(side_effect=lambda session: rows))
        return runtime_approvals.Binding(native, prompt(), "request-1", "session", dict(SNAPSHOT))

    def test_bookkeeping_added_to_the_native_entry_keeps_the_card_live(self):
        rows = [{**SNAPSHOT, "timeout_s": 300, "acknowledged": True}]
        self.assertTrue(self.binding(rows).pending())
        self.assertFalse(self.binding([{**SNAPSHOT, "command": "rm -rf /"}]).pending())
        self.assertFalse(self.binding([{**SNAPSHOT, "pattern_keys": ["other"]}]).pending())

    def test_a_request_gone_without_an_observation_expires_only_after_the_grace(self):
        rows = []
        binding = self.binding(rows)
        clock = iter([100.0, 100.0, 103.0, 106.0])
        now = lambda: next(clock)
        self.assertIsNone(binding.observed(now))
        self.assertIsNone(binding.observed(now))
        self.assertEqual(binding.observed(now), ("expired", None))
        # An observation that does arrive always wins over the guess.
        late = self.binding([])
        late.reason = "resolved"
        self.assertEqual(late.observed(), ("resolved", None))

    async def test_an_unbindable_request_is_sent_as_text_not_reported_delivered(self):
        for rows in ([], [dict(SNAPSHOT), dict(SNAPSHOT)]):
            adapter = types.SimpleNamespace(send=AsyncMock(return_value=types.SimpleNamespace(success=True)),
                                            _outbox=Outbox(tempfile.mkdtemp()), _write=AsyncMock())
            native = types.SimpleNamespace(list_gateway_approvals=Mock(return_value=rows))
            manager = questions.Manager(getattr(adapter, "_outbox", None), getattr(adapter, "_write", None), adapter.send, approvals_native=lambda: native)
            manager.bridge_runtime_supports = True
            self.assertEqual(await manager.ask_approval(prompt()), (True, None))
            text = "\n".join(call.args[1] for call in adapter.send.await_args_list)
            self.assertIn("echo test", text)
            self.assertIn("/deny", text)
            self.assertFalse(manager.cards)

    async def test_an_unobservable_request_is_sent_as_text_not_reported_delivered(self):
        adapter = types.SimpleNamespace(send=AsyncMock(return_value=types.SimpleNamespace(success=True)),
                                        _outbox=Outbox(tempfile.mkdtemp()), _write=AsyncMock())
        native = types.SimpleNamespace(list_gateway_approvals=Mock(return_value=[dict(SNAPSHOT)]),
                                       observe_gateway_settle=Mock(return_value=False))
        manager = questions.Manager(getattr(adapter, "_outbox", None), getattr(adapter, "_write", None), adapter.send, approvals_native=lambda: native)
        manager.bridge_runtime_supports = True
        self.assertEqual(await manager.ask_approval(prompt()), (True, None))
        self.assertTrue(adapter.send.await_args_list)
        self.assertFalse(manager.cards)

    async def test_an_answer_to_a_closed_card_replays_its_state_against_that_request(self):
        adapter = types.SimpleNamespace(send=AsyncMock(), _outbox=Outbox(tempfile.mkdtemp()), _write=AsyncMock())
        native = types.SimpleNamespace(list_gateway_approvals=Mock(return_value=[dict(SNAPSHOT)]),
                                       observe_gateway_settle=Mock(return_value=True),
                                       resolve_gateway_approval_card=Mock(return_value=1))
        manager = questions.Manager(getattr(adapter, "_outbox", None), getattr(adapter, "_write", None), adapter.send, approvals_native=lambda: native)
        manager.bridge_runtime_supports = True
        saved, question = await manager.ask_approval(prompt())
        self.assertTrue(saved)
        card = manager.cards[question]
        card.entry.reason = "timeout"
        await manager._settle(card, *card.entry.observed())
        request = protocol._message("question.answer", question=question, conversation="c",
                                    answer={"kind": "approval", "action": "once"})
        await manager.answer(request)
        native.resolve_gateway_approval_card.assert_not_called()
        update = adapter._write.call_args.args[0]
        self.assertEqual((update["type"], update["state"], update["of"]), ("question.update", "expired", request["id"]))
        self.assertNotIn("answer", update)
        await manager.close()


class RuntimeApprovalRefusals(unittest.IsolatedAsyncioTestCase):
    def manager(self, write=None):
        adapter = types.SimpleNamespace(send=AsyncMock(return_value=types.SimpleNamespace(success=True)),
                                        _outbox=Outbox(tempfile.mkdtemp()), _write=write or AsyncMock())
        native = types.SimpleNamespace(list_gateway_approvals=Mock(return_value=[dict(SNAPSHOT)]),
                                       observe_gateway_settle=Mock(return_value=True),
                                       resolve_gateway_approval_card=Mock(return_value=1))
        manager = questions.Manager(getattr(adapter, "_outbox", None), getattr(adapter, "_write", None), adapter.send, approvals_native=lambda: native)
        manager.bridge_runtime_supports = True
        return manager, adapter, native

    def sent(self, adapter):
        return "\n".join(call.args[1] for call in adapter.send.await_args_list)

    async def test_an_ask_refused_where_no_one_may_decide_is_denied_at_once(self):
        manager, adapter, native = self.manager()
        saved, question = await manager.ask_approval(prompt())
        ask = adapter._outbox.pending()[0]
        await manager.refused(ask["id"], "not_allowed")
        native.resolve_gateway_approval_card.assert_called_once_with("session", "deny", "request-1")
        self.assertIn("cannot be answered here", self.sent(adapter))
        self.assertNotIn("/approve", self.sent(adapter))
        self.assertFalse(manager.cards)
        self.assertNotIn(question, manager.approval_ids)
        await asyncio.sleep(0.15)  # Its watcher ends without an update to send.
        self.assertFalse([m for m in adapter._outbox.pending() if m["type"] == "question.update"])
        await manager.close()

    async def test_an_ask_refused_otherwise_goes_as_typed_text(self):
        manager, adapter, native = self.manager()
        await manager.ask_approval(prompt())
        await manager.refused(adapter._outbox.pending()[0]["id"], "bad_message")
        native.resolve_gateway_approval_card.assert_not_called()
        self.assertIn("/approve always", self.sent(adapter))
        self.assertIn("echo test", self.sent(adapter))
        self.assertFalse(manager.cards)
        # Another message's refusal changes nothing.
        await manager.refused("unrelated", "not_allowed")
        await manager.close()

    async def test_an_ask_that_could_not_be_sent_leaves_nothing_behind(self):
        manager, adapter, native = self.manager()
        with patch.object(adapter._outbox, "put", side_effect=OSError("full")), \
                self.assertLogs(questions.logger, "WARNING"):
            self.assertEqual(await manager.ask_approval(prompt()), (False, None))
        self.assertFalse(manager.cards)
        self.assertFalse(manager.approval_ids)

    def test_approval_commands_are_read_with_hermes_own_parser_and_aliases(self):
        def event(name):
            return types.SimpleNamespace(get_command=lambda: name)
        for name in ("approve", "deny", "yolo", "approvals"):
            self.assertTrue(runtime_approvals.approval_command(event(name)), name)
        for name in (None, "", "new", "approved"):
            self.assertFalse(runtime_approvals.approval_command(event(name)), name)
        commands = types.ModuleType("hermes_cli.commands")
        commands.resolve_command = lambda name: types.SimpleNamespace(name="approve") if name == "ok" else None
        with patch.dict(sys.modules, {"hermes_cli": types.ModuleType("hermes_cli"), "hermes_cli.commands": commands}):
            self.assertTrue(runtime_approvals.approval_command(event("ok")))
            self.assertTrue(runtime_approvals.approval_command(event("yolo")))
            self.assertFalse(runtime_approvals.approval_command(event("new")))

    def test_message_in_says_whether_its_person_is_the_hosts(self):
        base = {"conversation": "c", "person": "guest@example.com", "text": "/approve"}
        for host in (True, False):
            line = protocol.encode_line(protocol._message("message.in", host=host, **base))
            self.assertIs(protocol.decode_from_bridge(line)["host"], host)
        self.assertNotIn("host", protocol.decode_from_bridge(protocol.encode_line(protocol._message("message.in", **base))))
        with self.assertRaises(protocol.DecodeError):
            protocol.decode_from_bridge(protocol.encode_line(protocol._message("message.in", host="yes", **base)))


class AdapterApprovalCommands(unittest.IsolatedAsyncioTestCase):
    async def test_an_approval_command_from_anyone_but_the_hosts_person_never_reaches_hermes(self):
        config = types.ModuleType("gateway.config")
        config.Platform = config.PlatformConfig = Mock
        shared = types.ModuleType("gateway.platforms._shared")
        shared.get_scoped_secret = Mock(return_value="")
        base = types.ModuleType("gateway.platforms.base")
        base.BasePlatformAdapter = object
        base.SendResult = Mock
        event = types.ModuleType("gateway.platforms.event")

        class MessageEvent:
            # Hermes's own reading, as `MessageEvent.get_command` does it.
            def __init__(self, text, **_):
                self.text = text

            def get_command(self):
                text = self.text.lstrip()
                return text.split(maxsplit=1)[0][1:].lower().split("@", 1)[0] if text.startswith("/") else None

        event.MessageEvent, event.MessageType = MessageEvent, Mock()
        modules = {"gateway": types.ModuleType("gateway"), "gateway.config": config,
                   "gateway.platforms": types.ModuleType("gateway.platforms"),
                   "gateway.platforms._shared": shared, "gateway.platforms.base": base,
                   "gateway.platforms.event": event}
        with patch.dict(sys.modules, modules):
            sys.modules.pop("enclos.adapter", None)
            adapter_module = importlib.import_module("enclos.adapter")
            adapter = adapter_module.EnclosAdapter.__new__(adapter_module.EnclosAdapter)
            adapter._last_in = {}
            adapter._seen = collections.OrderedDict()
            adapter.build_source = Mock()
            adapter.handle_message = AsyncMock()
            adapter.send = AsyncMock()
            adapter._write = AsyncMock(return_value=True)
            adapter._questions = types.SimpleNamespace(refused=AsyncMock())
            adapter._answers = {}
            adapter._interrupts = types.SimpleNamespace(admit=lambda event: None, complete=lambda event: None)
            adapter.name = "enclos"
            # Python's split takes U+001F for whitespace, as Hermes does.
            for text in ("/yolo", chr(0x1F) + "/approve always", "/approvals off", "/DENY"):
                message = protocol._message("message.in", conversation="c", person="guest@example.com",
                                            text=text, host=False)
                await adapter._on_message(message)
                adapter.handle_message.assert_not_awaited()
                self.assertEqual(adapter.send.await_args.args[1], runtime_approvals.NOT_HOST_ANSWER)
                self.assertEqual(adapter._write.call_args.args[0]["of"], message["id"])
            passed = [{"text": "/approve", "host": True}, {"text": "/approve"}, {"text": "hello", "host": False}]
            for fields in passed:
                await adapter._on_message(protocol._message("message.in", conversation="c", person="p", **fields))
            self.assertEqual(adapter.handle_message.await_count, len(passed))
            error = protocol.error("not_allowed", "Only the host's person decides.", "ask-1")
            await adapter._on_line(protocol.encode_line(error))
            adapter._questions.refused.assert_awaited_once_with("ask-1", "not_allowed")
        sys.modules.pop("enclos.adapter", None)


class RuntimeApprovalProtocol(unittest.TestCase):
    def test_approval_definitions_and_answers_are_separate_from_questions(self):
        definition = runtime_approvals.definition(prompt(), "q", SNAPSHOT)
        self.assertEqual(questions.validate_definition(definition), definition)
        answer = {"kind": "approval", "action": "once"}
        self.assertEqual(questions.validate_answer(answer, definition), answer)
        self.assertEqual(protocol.decode_from_bridge(protocol.encode_line(protocol._message(
            "question.answer", question="q", conversation="c", answer=answer)))["answer"], answer)
        for other in ({"kind": "skip"}, {"kind": "text", "text": "/approve"},
                      {"kind": "choices", "indices": [0]}):
            with self.assertRaises(ValueError):
                questions.validate_answer(other, definition)
        with self.assertRaises(ValueError):
            questions.validate_answer(answer, {"id": "q", "text": "Q?", "choices": [], "multiple": False})

    def test_action_order_flags_and_deny_only_are_preserved(self):
        for actions in (("deny",), ("once", "deny"), ("once", "session", "deny"), runtime_approvals.ACTIONS):
            definition = runtime_approvals.definition(prompt(actions=actions), "q", SNAPSHOT)
            questions.validate_definition(definition)
            self.assertEqual(definition["approval"]["actions"], list(actions))
        for actions in (("once",), ("once", "always", "deny"), ("deny", "once"), ("once", "once", "deny"), ("wat", "deny")):
            with self.subTest(actions=actions), self.assertRaises(ValueError):
                questions.validate_definition(runtime_approvals.definition(prompt(actions=actions), "q", SNAPSHOT))
        definition = runtime_approvals.definition(prompt(actions=("deny",)), "q", SNAPSHOT)
        with self.assertRaises(ValueError):
            questions.validate_answer({"kind": "approval", "action": "once"}, definition)
        definition["approval"]["smart_denied"] = True
        questions.validate_definition(definition)
        definition["approval"]["actions"] = list(runtime_approvals.ACTIONS)
        with self.assertRaises(ValueError):
            questions.validate_definition(definition)

    def test_controls_and_mixed_choice_metadata_are_rejected(self):
        definition = runtime_approvals.definition(prompt(), "q", SNAPSHOT)
        definition["approval"]["command"] = "a\r\nb\tc"
        questions.validate_definition(definition)
        for changes in ({"choices": ["allow"]}, {"multiple": True},
                        {"approval": {**definition["approval"], "command": "\0once"}},
                        {"approval": {**definition["approval"], "reason": " "}}):
            with self.assertRaises(ValueError):
                questions.validate_definition({**definition, **changes})
        for answer in ({"kind": "approval", "action": "\0once"},
                       {"kind": "approval", "action": "all"},
                       {"kind": "approval", "action": "deny", "indices": [0]}):
            with self.assertRaises(ValueError):
                questions.validate_answer(answer, definition)


class RuntimeApprovalFallback(unittest.IsolatedAsyncioTestCase):
    async def test_old_bridge_or_api_keeps_full_typed_native_fallback(self):
        adapter = types.SimpleNamespace(send=AsyncMock(return_value=types.SimpleNamespace(success=True)))
        native = Mock(return_value=None)
        manager = questions.Manager(getattr(adapter, "_outbox", None), getattr(adapter, "_write", None), adapter.send, approvals_native=native)
        self.assertFalse(manager.approvals_available)
        self.assertEqual(await manager.ask_approval(prompt()), (True, None))
        native.assert_not_called()
        manager.bridge_runtime_supports = True
        self.assertFalse(manager.approvals_available)
        self.assertEqual(await manager.ask_approval(prompt()), (True, None))
        text = "\n".join(call.args[1] for call in adapter.send.await_args_list)
        for command in ("/approve", "/approve session", "/approve always", "/deny", "echo test"):
            self.assertIn(command, text)
        self.assertFalse(manager.cards)
        self.assertTrue(all(call.kwargs["metadata"]["is_approval_prompt"] for call in adapter.send.await_args_list))


@unittest.skipUnless(os.environ.get("ENCLOS_HERMES_LEGACY_SOURCE"), "optional old Hermes source")
class NativeLegacyFallback(unittest.TestCase):
    def test_old_native_signature_and_missing_exact_apis_use_typed_fallback(self):
        script = """
import asyncio, os, sys
from pathlib import Path
from unittest.mock import AsyncMock, Mock
sys.path[:0] = [sys.argv[1], sys.argv[2], sys.argv[3]]
os.environ['HERMES_HOME'] = sys.argv[4]
os.environ['HERMES_RUNTIME_DIR'] = sys.argv[4] + '/run'
from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter
from enclos.adapter import EnclosAdapter
from enclos import questions, runtime_approvals
from enclos.outbox import Outbox
assert runtime_approvals.native_api() is None
async def check():
    adapter = EnclosAdapter.__new__(EnclosAdapter)
    BasePlatformAdapter.__init__(adapter, PlatformConfig(enabled=True), Platform.LOCAL)
    adapter._outbox = Outbox(sys.argv[4] + '/outbox')
    adapter._write = AsyncMock(return_value=True)
    adapter._check_title_soon = Mock()
    adapter._questions = questions.Manager(adapter._outbox, adapter._write, adapter.send)
    adapter._questions.bridge_runtime_supports = True
    result = await adapter.send_exec_approval(chat_id='c', command='echo not-executed', session_key='old')
    assert result.success
    messages = adapter._outbox.pending()
    assert all(m['type'] == 'message.out' for m in messages)
    text = '\\n'.join(m['text'] for m in messages)
    assert all(c in text for c in ['/approve', '/approve session', '/approve always', '/deny', 'echo not-executed'])
    assert not adapter._questions.cards
asyncio.run(check())
"""
        with tempfile.TemporaryDirectory() as home:
            result = subprocess.run([sys.executable, "-I", "-B", "-c", script,
                str(Path(__file__).resolve().parents[1]), os.environ["ENCLOS_HERMES_LEGACY_SOURCE"],
                os.environ.get("ENCLOS_HERMES_TEST_DEPS", ""), home], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)


@unittest.skipUnless(os.environ.get("ENCLOS_HERMES_APPROVAL_SOURCE"), "optional pinned Hermes approval source")
class NativeHermesRuntimeApprovals(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        (self.home / "config.yaml").write_text("approvals:\n  timeout: 5\n")
        self.env = patch.dict(os.environ, {"HERMES_HOME": str(self.home), "HERMES_RUNTIME_DIR": str(self.home / "run")})
        self.env.start()
        self.addCleanup(self.env.stop)
        for folder in (os.environ["ENCLOS_HERMES_APPROVAL_SOURCE"], os.environ.get("ENCLOS_HERMES_TEST_DEPS")):
            if folder:
                sys.path.insert(0, folder)
                self.addCleanup(sys.path.remove, folder)
        self.native = importlib.import_module("tools.approval")
        self.wait = importlib.import_module("tools.approval_gateway_wait")
        base = importlib.import_module("gateway.platforms.base")
        config = importlib.import_module("gateway.config")
        sys.modules.pop("enclos.adapter", None)
        self.adapter_module = importlib.import_module("enclos.adapter")
        self.addCleanup(sys.modules.pop, "enclos.adapter", None)
        self.adapter = self.adapter_module.EnclosAdapter.__new__(self.adapter_module.EnclosAdapter)
        base.BasePlatformAdapter.__init__(self.adapter, config.PlatformConfig(enabled=True), config.Platform.LOCAL)
        self.adapter._outbox = Outbox(str(self.home / "outbox"))
        self.adapter._write = AsyncMock(return_value=True)
        self.adapter._check_title_soon = Mock()
        self.adapter._local_image = Mock(side_effect=AssertionError("approval text must remain literal"))
        self.manager = questions.Manager(self.adapter._outbox, self.adapter._write, self.adapter.send)
        self.manager.bridge_supports = self.manager.bridge_runtime_supports = True
        self.adapter._questions = self.manager
        self.assertIs(runtime_approvals.native_api(), self.native)
        self.scope = f"native-test-{uuid.uuid4()}"
        self.workers = []
        self.addAsyncCleanup(self.cleanup_native)
        self.addAsyncCleanup(self.manager.close)

    async def cleanup_native(self):
        for row in self.native.list_gateway_approvals(self.scope):
            self.native.withdraw_gateway_approval(self.scope, row["request_id"], "test ended")
        for worker, result in self.workers:
            await asyncio.to_thread(worker.join, 3)
            self.assertFalse(worker.is_alive())
            self.assertNotIn("error", result, result.get("error"))

    async def start(self, command="echo not-executed", **flags):
        loop = asyncio.get_running_loop()
        published, result = threading.Event(), {}
        def notify(data):
            result["request"] = data
            result["core_reasons"] = []
            self.native.register_gateway_settle(self.scope, data["request_id"], result["core_reasons"].append)
            try:
                result["send"] = asyncio.run_coroutine_threadsafe(self.adapter.send_exec_approval(
                    chat_id="c", command=data["command"], description=data["description"],
                    session_key=self.scope, request_id=data["request_id"], **flags), loop).result(5)
            finally:
                published.set()
        def waiting_agent():
            try:
                result["decision"] = self.wait._await_gateway_decision(self.scope, notify,
                    {"command": command, "description": "Native test reason", "pattern_key": command,
                     "pattern_keys": [command], **flags})
            except BaseException as error:
                result["error"] = error
                published.set()
        worker = threading.Thread(target=waiting_agent)
        self.workers.append((worker, result))
        worker.start()
        self.assertTrue(await asyncio.to_thread(published.wait, 6))
        self.assertNotIn("error", result, result.get("error"))
        self.assertTrue(result["send"].success)
        card = next((c for c in self.manager.cards.values() if c.native_id == result["request"]["request_id"]), None)
        return card, result, worker

    def answer(self, card, action):
        return protocol._message("question.answer", question=card.definition["id"], conversation="c",
                                 answer={"kind": "approval", "action": action})

    def updates(self):
        return [m for m in self.adapter._outbox.pending() if m["type"] == "question.update"]

    async def test_own_exact_decision_unblocks_native_wait_with_correlated_receipt(self):
        card, result, worker = await self.start()
        request = self.answer(card, "session")
        await self.manager.answer(request)
        await asyncio.to_thread(worker.join, 2)
        self.assertEqual(result["decision"]["choice"], "session")
        self.assertEqual(result["core_reasons"], ["resolved"])
        self.assertEqual(self.updates()[-1]["of"], request["id"])
        self.assertEqual(self.updates()[-1]["answer"], {"kind": "approval", "action": "session"})
        await asyncio.sleep(0.15)
        self.assertEqual(card.state, "answered")

    async def test_stale_request_does_not_resolve_the_next_native_request(self):
        old, first, worker = await self.start("first-never-executed")
        self.native.withdraw_gateway_approval(self.scope, old.native_id, "withdrawn")
        await asyncio.to_thread(worker.join, 2)
        new, second, second_worker = await self.start("second-never-executed")
        await self.manager.answer(self.answer(old, "once"))
        self.assertTrue(second_worker.is_alive())
        self.assertEqual([p["request_id"] for p in self.native.list_gateway_approvals(self.scope)], [new.native_id])
        self.assertEqual(self.native.resolve_gateway_approval_card(self.scope, "once", old.native_id), 0)
        await self.manager.answer(self.answer(new, "deny"))
        await asyncio.to_thread(second_worker.join, 2)
        self.assertEqual(second["decision"]["choice"], "deny")

    async def test_external_decision_preserves_core_hook_and_has_no_invented_action(self):
        card, result, worker = await self.start()
        self.assertEqual(self.native.resolve_gateway_approval(self.scope, "always", request_id=card.native_id), 1)
        await asyncio.to_thread(worker.join, 2)
        await asyncio.sleep(0.15)
        self.assertEqual(result["core_reasons"], ["resolved"])
        self.assertEqual(card.state, "resolved")
        self.assertNotIn("answer", self.updates()[-1])
        request = self.answer(card, "always")
        await self.manager.answer(request)
        # The closed card's own state answers that request; it never names an action.
        self.assertEqual(self.updates()[-1]["of"], request["id"])
        self.assertEqual(self.updates()[-1]["state"], "resolved")
        self.assertNotIn("answer", self.updates()[-1])

    async def test_external_answer_during_publication_still_closes_the_published_exact_card(self):
        async def delivered(message):
            if message["type"] == "question.ask":
                card = self.manager.cards[message["question"]["id"]]
                self.assertEqual(self.native.resolve_gateway_approval(self.scope, "once", request_id=card.native_id), 1)
            return True
        self.adapter._write.side_effect = delivered
        card, result, worker = await self.start()
        await asyncio.to_thread(worker.join, 2)
        await asyncio.sleep(0.15)
        self.assertEqual(result["decision"]["choice"], "once")
        self.assertEqual(card.state, "resolved")
        self.assertEqual([m["type"] for m in self.adapter._outbox.pending()], ["question.ask", "question.update"])
        self.assertNotIn("answer", self.updates()[-1])

    async def test_smart_deny_and_native_visibility_deny_only_remain_restricted(self):
        card, result, worker = await self.start(smart_denied=True, allow_session=False, allow_permanent=False)
        self.assertEqual(card.definition["approval"]["actions"], ["once", "deny"])
        await self.manager.answer(self.answer(card, "always"))
        self.assertTrue(worker.is_alive())
        await self.manager.answer(self.answer(card, "deny"))
        await asyncio.to_thread(worker.join, 2)
        card, result, worker = await self.start("x" * 4000 + "```")
        self.assertEqual(card.definition["approval"]["actions"], ["deny"])
        self.assertEqual(self.native.resolve_gateway_approval_card(self.scope, "once", card.native_id), 0)
        await self.manager.answer(self.answer(card, "once"))
        self.assertTrue(worker.is_alive())
        await self.manager.answer(self.answer(card, "deny"))

    async def test_timeout_and_withdrawal_close_cards_without_authorizing(self):
        (self.home / "config.yaml").write_text("approvals:\n  timeout: 0\n")
        card, result, worker = await self.start()
        await asyncio.to_thread(worker.join, 2)
        await asyncio.sleep(0.15)
        self.assertFalse(result["decision"]["resolved"])
        self.assertEqual(card.state, "expired")

    async def test_oversized_literal_fallback_bounds_every_frame_and_keeps_all_command_bytes(self):
        command = 'echo "![x](/test-only/image.png)"\n' + ('"\\`~' * 22000)
        card, result, worker = await self.start(command)
        self.assertIsNone(card)
        messages = self.adapter._outbox.pending()
        self.assertTrue(messages)
        self.assertTrue(all(len(protocol.encode_line(m)) <= questions.MAX_APPROVAL_FRAME_BYTES for m in messages))
        self.assertTrue(all(m["type"] == "message.out" and not m.get("attachments") for m in messages))
        parts = []
        for message in messages:
            text = message["text"]
            if text.startswith("Complete command:\n") or text.startswith("Command, part "):
                block = text.split("\n", 1)[1]
                fence, rest = block.split("\n", 1)
                self.assertTrue(fence.startswith("```") or fence.startswith("~~~"))
                self.assertTrue(rest.endswith("\n" + fence))
                parts.append(rest[:-(len(fence) + 1)])
        self.assertEqual("".join(parts), command)
        self.assertEqual(messages[-1]["text"], "Reply with /deny.")
        self.assertEqual(self.native.resolve_gateway_approval_card(self.scope, "once", result["request"]["request_id"]), 0)
        self.native.resolve_gateway_approval_card(self.scope, "deny", result["request"]["request_id"])

    async def test_approval_send_preserves_markdown_image_and_notice_looking_command_literals(self):
        command = 'echo "![x](/test-only/image.png)"'
        self.manager.bridge_runtime_supports = False
        card, result, worker = await self.start(command)
        self.assertIsNone(card)
        self.assertTrue(any(command in m["text"] for m in self.adapter._outbox.pending()))
        self.assertTrue(all(m["kind"] == "notify" and not m.get("attachments") for m in self.adapter._outbox.pending()))
        self.native.resolve_gateway_approval(self.scope, "deny", request_id=result["request"]["request_id"])
        with patch.object(protocol, "is_notice", side_effect=AssertionError("approval text must not be classified")):
            result = await self.adapter.send("c", "♻️ Gateway online is literal text", metadata={"is_approval_prompt": True})
            self.assertTrue(result.success)
        before = len(self.adapter._outbox.pending())
        result = await self.adapter.send("c", "x" * 80000, metadata={"is_approval_prompt": True, "_interim_send": True})
        self.assertFalse(result.success)
        self.assertEqual(len(self.adapter._outbox.pending()), before)


if __name__ == "__main__":
    unittest.main()
