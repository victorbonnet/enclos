"""The adapter over a real Unix socket, with stand-ins for the Hermes classes
it uses: long messages, one bridge at a time, bad lines, and messages the
bridge cannot read."""

import asyncio
import json
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _hermes_stand_ins() -> dict:
    """Stand-ins for the gateway modules adapter.py imports, and no other
    Hermes module: where a real Hermes is importable too (the hermes-latest
    job), the adapter would list its commands after the hello, which these
    tests do not expect."""

    class Platform(str):
        pass

    class PlatformConfig:
        def __init__(self, extra=None):
            self.extra = extra or {}

    class SendResult:
        def __init__(self, success, message_id=None, error=None):
            self.success, self.message_id, self.error = success, message_id, error

    class BasePlatformAdapter:
        def __init__(self, config, platform):
            self.config, self.platform, self.name = config, platform, str(platform)
            self.received = []
            self.failures = []

        def _mark_connected(self):
            pass

        def _mark_disconnected(self):
            pass

        def _wire_plugin_handlers(self, _):
            pass

        def build_source(self, **fields):
            return fields

        async def handle_message(self, event):
            if self.failures:
                raise self.failures.pop(0)
            self.received.append(event)

    class MessageEvent:
        def __init__(self, **fields):
            self.__dict__.update(fields)

        def get_command(self):
            # Hermes's reading of a command message, in short.
            text = self.text.lstrip()
            return text.split(maxsplit=1)[0][1:].lower() if text.startswith("/") else None

    class MessageType:
        TEXT = "text"

    modules = {
        "gateway": types.ModuleType("gateway"),
        "gateway.config": types.ModuleType("gateway.config"),
        "gateway.platforms": types.ModuleType("gateway.platforms"),
        "gateway.platforms._shared": types.ModuleType("gateway.platforms._shared"),
        "gateway.platforms.base": types.ModuleType("gateway.platforms.base"),
        "gateway.platforms.event": types.ModuleType("gateway.platforms.event"),
    }
    modules["gateway.config"].Platform = Platform
    modules["gateway.config"].PlatformConfig = PlatformConfig
    modules["gateway.platforms._shared"].get_scoped_secret = lambda name, default: default
    modules["gateway.platforms.base"].BasePlatformAdapter = BasePlatformAdapter
    modules["gateway.platforms.base"].SendResult = SendResult
    modules["gateway.platforms.event"].MessageEvent = MessageEvent
    modules["gateway.platforms.event"].MessageType = MessageType
    # The other Hermes packages the plugin reaches for, absent as they are
    # outside a gateway.
    for name in ("agent", "cron", "hermes_cli", "hermes_constants", "hermes_state", "hermes_time", "tools", "toolsets"):
        modules[name] = None
    return modules


def setUpModule():
    # For this module's tests only: left in `sys.modules`, the stand-ins would
    # hide the real Hermes from every test that runs after these.
    #
    # Two things this relies on. Stopping the patch puts back `sys.modules` as
    # it was, so a module first imported during these tests is dropped while
    # the `enclos` package still names it: keep every `enclos` submodule the
    # adapter imports imported at module level by some test file, so that
    # discovery loads it before this runs (only `enclos.adapter` is imported
    # here, and a later test imports it again with `importlib`). And a `None`
    # hides a package, not its submodules already loaded: none of the Hermes
    # packages hidden here may be imported at module level by a test file.
    global EnclosAdapter, PlatformConfig
    stand_ins = patch.dict(sys.modules, _hermes_stand_ins())
    stand_ins.start()
    unittest.addModuleCleanup(stand_ins.stop)
    sys.modules.pop("enclos.adapter", None)
    from enclos.adapter import EnclosAdapter
    from gateway.config import PlatformConfig


from enclos import held_tasks, protocol  # noqa: E402

TOKEN = "t" * 64


def line(message_type: str, **fields) -> bytes:
    return (json.dumps({"v": 1, "type": message_type, "id": os.urandom(8).hex(), **fields}) + "\n").encode()


from enclos import suggested_replies

class AdapterTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "app", "main.sock")
        self.adapter = EnclosAdapter(PlatformConfig({"socket": self.path, "token": TOKEN}))
        self.assertTrue(await self.adapter.connect())

    async def asyncTearDown(self):
        # A connection the adapter failed to close would hold this up
        await asyncio.wait_for(self.adapter.disconnect(), 5)

    async def bridge(self):
        reader, writer = await asyncio.open_unix_connection(self.path, limit=protocol.MAX_MESSAGE_BYTES + 1)
        return reader, writer

    async def hello(self, reader, writer):
        writer.write(line("hello", token=TOKEN))
        await writer.drain()
        answer = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(answer["type"], "hello")

    async def test_suggested_replies_survive_outbox_replay_and_do_not_attach_to_notices(self):
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        now = asyncio.get_running_loop().time()
        self.adapter._last_in["c-1"] = ("m1", now)
        replies = ["Fix Inbox filters", "Keep paused"]
        self.adapter._suggested_replies["c-1"] = suggested_replies.Pending(("m1", now), now, replies)
        await self.adapter.send("c-1", "♻️ Gateway online", None)
        notice = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertNotIn("suggested_replies", notice)
        await self.adapter.send("c-1", "Inbox filters reset. Allow a fix?", "m1")
        sent = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(sent["suggested_replies"], replies)
        self.assertEqual(self.adapter._outbox.pending()[-1]["suggested_replies"], replies)
        await self.adapter.send("c-1", "Another message", "m1")
        following = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertNotIn("suggested_replies", following)
        writer.close()

    async def test_review_replies_remain_staged_after_outbox_rejection(self):
        for with_files in (False, True):
            now = asyncio.get_running_loop().time()
            self.adapter._last_in["c-review"] = ("m-review", now)
            self.adapter._suggested_replies["c-review"] = suggested_replies.Pending(("m-review", now), now, ["Fix it"])
            with patch.object(self.adapter._outbox, "put", return_value=False):
                result = await (self.adapter._send_files("c-review", [], "Decision", "m-review") if with_files
                                else self.adapter.send("c-review", "Decision", "m-review"))
            self.assertFalse(result.success)
            self.assertIn("c-review", self.adapter._suggested_replies)
            result = await self.adapter.send("c-review", "Decision", "m-review")
            self.assertTrue(result.success)
            self.assertEqual(self.adapter._outbox.pending()[-1]["suggested_replies"], ["Fix it"])
            self.assertNotIn("c-review", self.adapter._suggested_replies)

    async def test_a_message_longer_than_64_kib_reaches_the_runtime(self):
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        text = "x" * 70_000
        writer.write(line("message.in", conversation="c-1", person="alice@example.com", text=text))
        await writer.drain()
        ack = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(ack["type"], "ack")
        self.assertEqual([e.text for e in self.adapter.received], [text])
        writer.close()

    async def test_a_message_sent_again_reaches_the_runtime_once(self):
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        again = line("message.in", conversation="c-1", person="alice@example.com", text="hi")
        for _ in range(2):
            writer.write(again)
            await writer.drain()
            ack = json.loads(await asyncio.wait_for(reader.readline(), 5))
            self.assertEqual(ack["of"], json.loads(again)["id"])
        self.assertEqual([e.text for e in self.adapter.received], ["hi"])
        writer.close()

    async def test_a_line_over_the_limit_closes_the_connection(self):
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        writer.write(b"x" * (protocol.MAX_MESSAGE_BYTES + 10) + b"\n")
        await writer.drain()
        error = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual((error["type"], error["code"]), ("error", "bad_message"))
        self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")
        self.assertEqual(self.adapter.received, [])

    async def test_two_bridges_waiting_for_their_hello_do_not_both_get_in(self):
        first = await self.bridge()
        second = await self.bridge()
        # Both are past the first check before either says hello
        await asyncio.sleep(0.05)
        await self.hello(*first)
        second[1].write(line("hello", token=TOKEN))
        await second[1].drain()
        self.assertEqual(await asyncio.wait_for(second[0].read(), 5), b"")
        # The second one closing leaves the first one's connection in place
        await asyncio.sleep(0.05)
        self.assertIs(self.adapter._bridge is not None, True)
        result = await self.adapter.send("c-1", "hello", None)
        self.assertTrue(result.success)
        sent = json.loads(await asyncio.wait_for(first[0].readline(), 5))
        self.assertEqual((sent["type"], sent["text"]), ("message.out", "hello"))
        first[1].close()

    async def test_the_socket_is_the_users_alone(self):
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    async def test_a_first_line_over_the_limit_or_nested_too_deep_is_closed(self):
        for first in (b"x" * (protocol.MAX_MESSAGE_BYTES + 10) + b"\n", b"[" * 100_000 + b"\n"):
            with self.subTest(len(first)):
                reader, writer = await self.bridge()
                writer.write(first)
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")
                writer.close()
        # The slot is free: a bridge with the token still gets in
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        writer.close()

    async def test_a_line_nested_too_deep_after_the_hello_is_answered_and_the_connection_goes_on(self):
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        writer.write(b"[" * 100_000 + b"\n")
        await writer.drain()
        error = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual((error["type"], error["code"]), ("error", "bad_message"))
        writer.write(line("message.in", conversation="c-1", person="alice@example.com", text="still here"))
        await writer.drain()
        ack = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(ack["type"], "ack")
        writer.close()

    async def test_a_version_it_does_not_speak_ends_the_connection(self):
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        writer.write(b'{"v":2,"id":"m9","type":"ack","of":"m0"}\n')
        await writer.drain()
        error = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual((error["code"], error["of"]), ("version", "m9"))
        self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")
        writer.close()

    async def test_a_hermes_without_a_board_does_not_announce_held_tasks(self):
        reader, writer = await self.bridge()
        writer.write(line("hello", token=TOKEN, capabilities=["held_tasks"]))
        await writer.drain()
        hello = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertNotIn("held_tasks", hello["capabilities"])
        writer.close()

    async def test_a_held_task_resume_is_unsupported_not_a_second_hello(self):
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        writer.write(line("held_task.resume", task="t_1", revision="e:1", person="p@example.com", device="d1")
                     .replace(b'"id": "', b'"id": "resume-', 1))
        await writer.drain()
        while True:
            answer = json.loads(await asyncio.wait_for(reader.readline(), 5))
            if answer["type"] == "error" and answer.get("of", "").startswith("resume-"):
                break
        self.assertEqual(answer["code"], "unsupported")
        writer.close()

    async def test_a_message_the_runtime_did_not_take_is_not_a_duplicate_when_sent_again(self):
        self.adapter.failures.append(RuntimeError("the runtime is busy"))
        again = line("message.in", conversation="c-1", person="alice@example.com", text="hi")
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        writer.write(again)
        await writer.drain()
        # The runtime raised: no ack, and the connection ends
        with self.assertLogs("enclos.adapter", "ERROR"):
            self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")
        writer.close()
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        writer.write(again)
        await writer.drain()
        ack = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(ack["of"], json.loads(again)["id"])
        self.assertEqual([e.text for e in self.adapter.received], ["hi"])
        writer.close()

    async def test_a_value_error_of_the_runtime_is_not_taken_for_a_long_line(self):
        self.adapter.failures.append(ValueError("the runtime's own"))
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        writer.write(line("message.in", conversation="c-1", person="alice@example.com", text="hi"))
        await writer.drain()
        with self.assertLogs("enclos.adapter", "ERROR") as logs:
            self.assertEqual(await asyncio.wait_for(reader.read(), 5), b"")
        writer.close()
        self.assertNotIn("1 MiB", "\n".join(logs.output))
        self.assertIn("could not be handed to the runtime", logs.output[0])

    async def test_a_message_the_bridge_could_not_read_is_never_kept(self):
        for chat_id, text in (("", "hi"), ("c" * 129, "hi"), ("c-1\n", "hi"),
                              ("c-1", "x" * (protocol.MAX_MESSAGE_BYTES + 1))):
            with self.subTest(chat_id[:8]):
                with self.assertLogs("enclos.adapter", "WARNING"):
                    result = await self.adapter.send(chat_id, text, None)
                self.assertFalse(result.success)
                self.assertIn("cannot carry", result.error)
        self.assertEqual(self.adapter._outbox.pending(), [])

    async def test_a_message_the_bridge_refused_leaves_the_outbox(self):
        result = await self.adapter.send("c-1", "first", None)
        self.assertTrue(result.success)
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        sent = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(sent["text"], "first")
        with self.assertLogs("enclos.adapter", "WARNING") as logs:
            writer.write(line("error", of=sent["id"], code="bad_message", message="cannot read it"))
            await writer.drain()
            await asyncio.sleep(0.05)
        self.assertIn("set aside", logs.output[-1])
        writer.close()
        self.assertEqual(self.adapter._outbox.pending(), [])
        # The next bridge does not get it again
        await asyncio.sleep(0.05)
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        await self.adapter.send("c-1", "second", None)
        sent = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(sent["text"], "second")
        writer.close()

    async def test_activity_follows_typing_for_a_bridge_that_reads_it(self):
        reader, writer = await self.bridge()
        writer.write(line("hello", token=TOKEN, capabilities=["activity", "tasks"]))
        await writer.drain()
        hello = json.loads(await asyncio.wait_for(reader.readline(), 5))
        # No board in this Hermes: activity, and no tasks
        self.assertIn("activity", hello["capabilities"])
        self.assertNotIn("tasks", hello["capabilities"])
        idle = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual((idle["type"], idle["doing"], idle["since"]), ("agent.activity", [], 0))
        await self.adapter.send_typing("c-1")
        typing, activity = [json.loads(await asyncio.wait_for(reader.readline(), 5)) for _ in range(2)]
        self.assertEqual((typing["type"], typing["on"]), ("typing", True))
        self.assertEqual(activity["doing"], [{"kind": "answering", "conversation": "c-1"}])
        # The bridge acknowledges it, which changes nothing
        writer.write(line("ack", of=activity["id"]))
        await writer.drain()
        await self.adapter.stop_typing("c-1")
        typing, activity = [json.loads(await asyncio.wait_for(reader.readline(), 5)) for _ in range(2)]
        self.assertEqual((typing["on"], activity["doing"], activity["since"]), (False, [], 0))
        writer.close()

    async def test_an_older_bridge_gets_no_activity(self):
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        await self.adapter.send_typing("c-1")
        await self.adapter.stop_typing("c-1")
        sent = [json.loads(await asyncio.wait_for(reader.readline(), 5))["type"] for _ in range(2)]
        self.assertEqual(sent, ["typing", "typing"])
        writer.close()

    async def test_the_board_hooks_hermes_knows_are_registered_as_cues(self):
        adapter_module = sys.modules[EnclosAdapter.__module__]
        plugins = types.ModuleType("hermes_cli.plugins")
        # An older Hermes: two of the board's hooks, and not the others.
        plugins.VALID_HOOKS = {"pre_tool_call", "post_tool_call", "kanban_task_claimed", "on_kanban_task_updated"}
        package = types.ModuleType("hermes_cli")
        package.plugins = plugins
        ctx = Mock()
        with patch.dict(sys.modules, {"hermes_cli": package, "hermes_cli.plugins": plugins}):
            adapter_module.register(ctx)
        board_hooks = [c.args[0] for c in ctx.register_hook.call_args_list
                       if c.args[1] is adapter_module._board_changed]
        self.assertEqual(board_hooks, ["kanban_task_claimed", "on_kanban_task_updated"])
        self.assertTrue(set(board_hooks) <= set(adapter_module.tasks.HOOKS))

    async def test_a_board_hook_cues_each_connected_adapters_reporter(self):
        adapter_module = sys.modules[EnclosAdapter.__module__]
        self.assertFalse(self.adapter._reporter._cue.is_set())
        # From the thread that wrote the board, as Hermes calls it.
        await asyncio.to_thread(adapter_module._board_changed, task_id="t-1")
        for _ in range(100):
            if self.adapter._reporter._cue.is_set():
                break
            await asyncio.sleep(0.01)
        self.assertTrue(self.adapter._reporter._cue.is_set())

    async def test_a_bridge_error_for_a_task_message_has_it_sent_again(self):
        reporter = self.adapter._reporter
        reporter._unanswered["m-1"] = ["t-1"]
        reporter._sent["t-1"] = {"id": "t-1"}
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        with self.assertLogs("enclos.adapter", "WARNING"):
            writer.write(line("error", of="m-1", code="bad_message", message="the sandbox already has 100 tasks"))
            writer.write(line("ack", of="m-1"))
            await writer.drain()
            for _ in range(100):
                if "m-1" not in reporter._unanswered:
                    break
                await asyncio.sleep(0.01)
        self.assertNotIn("t-1", reporter._sent)
        writer.close()

    async def test_a_kept_message_the_bridge_could_not_read_is_set_aside_not_sent(self):
        bad = protocol.message_out("c" * 129, "kept by an older plugin")
        good = protocol.message_out("c-1", "fine")
        self.assertTrue(self.adapter._outbox.put(bad))
        self.assertTrue(self.adapter._outbox.put(good))
        reader, writer = await self.bridge()
        with self.assertLogs("enclos.adapter", "WARNING"):
            await self.hello(reader, writer)
            sent = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(sent["id"], good["id"])
        self.assertEqual([m["id"] for m in self.adapter._outbox.pending()], [good["id"]])
        writer.close()

    async def test_a_model_calls_usage_reaches_only_a_bridge_that_takes_it(self):
        module = sys.modules[type(self.adapter).__module__]
        env = {"HERMES_SESSION_PLATFORM": "enclos", "HERMES_SESSION_CHAT_ID": "c-42"}
        session = types.ModuleType("gateway.session_context")
        session.get_session_env = lambda name: env.get(name)
        # Hermes's buckets: `reasoning_tokens` not reported, and a count
        # that is not a whole number left out.
        call = {"input_tokens": 2104, "output_tokens": 96, "cache_read_tokens": 31744,
                "cache_write_tokens": True, "prompt_tokens": 33848}

        async def next_usage(reader):
            while True:
                message = json.loads(await asyncio.wait_for(reader.readline(), 5))
                if message["type"] == "usage":
                    return message

        def marker():
            # Sent last: if it comes next, nothing was sent before it.
            env.update({"HERMES_SESSION_PLATFORM": "enclos", "HERMES_SESSION_CHAT_ID": "marker"})
            module._usage(False, usage={"input_tokens": 1}, model="m")

        with patch.dict(sys.modules, {"gateway.session_context": session}), \
                patch.object(module, "_USAGE_HOOKS", True):
            reader, writer = await self.bridge()
            writer.write(line("hello", token=TOKEN, capabilities=["usage"]))
            await writer.drain()
            hello = json.loads(await asyncio.wait_for(reader.readline(), 5))
            self.assertIn("usage", hello["capabilities"])
            module._usage(False, usage=call, model="gpt-6.1-sol")
            message = await next_usage(reader)
            self.assertEqual(message["conversation"], "c-42")
            self.assertEqual(message["model"], "gpt-6.1-sol")
            self.assertEqual(message["tokens"], {"input": 2104, "output": 96, "cache_read": 31744})
            self.assertNotIn("background", message)
            # Another platform's turn is not an app conversation's, and a
            # failed call carries no usage.
            env["HERMES_SESSION_PLATFORM"] = "telegram"
            module._usage(True, usage=call, model="m")
            env["HERMES_SESSION_PLATFORM"] = "enclos"
            module._usage(True, usage=None, model="m")
            marker()
            self.assertEqual((await next_usage(reader))["conversation"], "marker")
            writer.close()
            # The bridge gone, the next one must say again that it takes usage.
            for _ in range(50):
                if not self.adapter._bridge_usage:
                    break
                await asyncio.sleep(0.02)
            self.assertFalse(self.adapter._bridge_usage)

            # A bridge that does not name `usage` gets none.
            reader, writer = await self.bridge()
            writer.write(line("hello", token=TOKEN))
            await writer.drain()
            await asyncio.wait_for(reader.readline(), 5)
            module._usage(False, usage=call, model="m")
            self.adapter._bridge_usage = True
            marker()
            self.assertEqual((await next_usage(reader))["conversation"], "marker")
            writer.close()

    async def test_a_call_outside_the_app_goes_to_its_agents_connection_alone(self):
        module = sys.modules[type(self.adapter).__module__]
        env = {"HERMES_SESSION_PLATFORM": "cron"}
        session = types.ModuleType("gateway.session_context")
        session.get_session_env = lambda name: env.get(name)
        call = {"input_tokens": 5120, "output_tokens": 240}

        async def next_usage(reader):
            while True:
                message = json.loads(await asyncio.wait_for(reader.readline(), 5))
                if message["type"] in ("usage", "usage.agent"):
                    return message

        with patch.dict(sys.modules, {"gateway.session_context": session}), \
                patch.object(module, "_USAGE_HOOKS", True), patch.object(module, "_AGENT_USAGE", True):
            reader, writer = await self.bridge()
            writer.write(line("hello", token=TOKEN, capabilities=["usage", "agent_usage"]))
            await writer.drain()
            hello = json.loads(await asyncio.wait_for(reader.readline(), 5))
            self.assertIn("agent_usage", hello["capabilities"])
            # A call of another agent of the gateway is not this one's.
            with patch.object(module, "_current_agent", lambda: "scout"):
                module._usage(False, usage=call, model="m")
            # This agent's routine: to its connection, with where it came from.
            with patch.object(module, "_current_agent", lambda: self.adapter._agent):
                module._usage(True, usage=call, model="gpt")
            message = await next_usage(reader)
            self.assertEqual(message["type"], "usage.agent")
            self.assertEqual(message["source"], "cron")
            self.assertEqual(message["model"], "gpt")
            self.assertTrue(message["background"])
            self.assertNotIn("conversation", message)
            self.assertEqual(message["tokens"], {"input": 5120, "output": 240})
            # An agent Hermes cannot name: nothing, and a warning says so;
            # an app call with no conversation: nothing either. Then an app
            # call shows nothing came before it.
            with patch.object(module, "_current_agent", lambda: None), \
                    patch.object(module, "_WARNED", set()), self.assertLogs("enclos.adapter", "WARNING") as said:
                module._usage(False, usage=call, model="m")
            self.assertIn("home of no agent", said.output[0])
            env.update({"HERMES_SESSION_PLATFORM": "enclos", "HERMES_SESSION_CHAT_ID": None})
            module._usage(True, usage=call, model="m")
            env.update({"HERMES_SESSION_PLATFORM": "enclos", "HERMES_SESSION_CHAT_ID": "c-1"})
            module._usage(False, usage=call, model="m")
            self.assertEqual((await next_usage(reader))["type"], "usage")
            writer.close()

            # A bridge that takes app usage but not the rest gets none of it.
            reader, writer = await self.bridge()
            writer.write(line("hello", token=TOKEN, capabilities=["usage"]))
            await writer.drain()
            await asyncio.wait_for(reader.readline(), 5)
            env.update({"HERMES_SESSION_PLATFORM": "cron", "HERMES_SESSION_CHAT_ID": None})
            with patch.object(module, "_current_agent", lambda: self.adapter._agent):
                module._usage(False, usage=call, model="m")
            env.update({"HERMES_SESSION_PLATFORM": "enclos", "HERMES_SESSION_CHAT_ID": "c-2"})
            module._usage(False, usage=call, model="m")
            self.assertEqual((await next_usage(reader))["conversation"], "c-2")
            writer.close()

    async def test_the_hooks_platform_names_a_call_whose_session_does_not(self):
        module = sys.modules[type(self.adapter).__module__]
        session = types.ModuleType("gateway.session_context")
        session.get_session_env = lambda name: None
        with patch.dict(sys.modules, {"gateway.session_context": session}), \
                patch.object(module, "_USAGE_HOOKS", True), patch.object(module, "_AGENT_USAGE", True), \
                patch.object(module, "_current_agent", lambda: self.adapter._agent):
            reader, writer = await self.bridge()
            writer.write(line("hello", token=TOKEN, capabilities=["usage", "agent_usage"]))
            await writer.drain()
            await asyncio.wait_for(reader.readline(), 5)
            module._usage(True, usage={"input_tokens": 1}, model="m", platform="cron")
            while True:
                message = json.loads(await asyncio.wait_for(reader.readline(), 5))
                if message["type"] == "usage.agent":
                    break
            self.assertEqual(message["source"], "cron")
            writer.close()

    async def test_a_plugin_names_only_the_usage_its_hermes_can_report(self):
        module = sys.modules[type(self.adapter).__module__]
        for hooks, agent, expected in ((False, False, []), (True, False, ["usage"]), (True, True, ["usage", "agent_usage"])):
            with patch.object(module, "_USAGE_HOOKS", hooks), patch.object(module, "_AGENT_USAGE", agent):
                reader, writer = await self.bridge()
                writer.write(line("hello", token=TOKEN))
                await writer.drain()
                hello = json.loads(await asyncio.wait_for(reader.readline(), 5))
                self.assertEqual([c for c in hello["capabilities"] if "usage" in c], expected)
                writer.close()
                for _ in range(50):
                    if self.adapter._bridge is None:
                        break
                    await asyncio.sleep(0.02)

    async def test_usage_is_not_sent_by_a_plugin_whose_hermes_lacks_the_hooks(self):
        module = sys.modules[type(self.adapter).__module__]
        with patch.object(module, "_USAGE_HOOKS", False), patch.object(module, "_ADAPTERS", {self.adapter}):
            self.adapter._bridge_usage = True
            with patch.object(self.adapter, "_write") as write:
                module._usage(False, usage={"input_tokens": 1}, model="m")
                write.assert_not_called()


class UsageHooks(unittest.TestCase):
    """Which hooks the plugin registers, by the hooks Hermes lists."""

    def register(self, hooks, names_agents=True):
        module = sys.modules["enclos.adapter"]
        recorded = []
        ctx = types.SimpleNamespace(register_hook=lambda name, callback: recorded.append(name))
        listing = {}
        if hooks is not None:
            plugins = types.ModuleType("hermes_cli.plugins")
            plugins.VALID_HOOKS = set(hooks)
            listing = {"hermes_cli": types.ModuleType("hermes_cli"), "hermes_cli.plugins": plugins}
        constants = types.ModuleType("hermes_constants")
        if names_agents:
            constants.get_hermes_home = lambda: None
            constants.profile_name_for_home = lambda home: None
        listing["hermes_constants"] = constants
        with patch.dict(sys.modules, listing), patch.object(module, "_USAGE_HOOKS", False), \
                patch.object(module, "_AGENT_USAGE", False):
            if hooks is None:
                sys.modules["hermes_cli"] = None
            module._register_usage_hooks(ctx)
            self.agent_usage = module._AGENT_USAGE
            return recorded, module._USAGE_HOOKS

    def test_both_hooks_where_hermes_has_both(self):
        self.assertEqual(self.register({"post_api_request", "post_auxiliary_call", "pre_tool_call"}),
                         (["post_api_request", "post_auxiliary_call"], True))

    def test_the_agents_calls_alone_where_hermes_has_no_background_hook(self):
        self.assertEqual(self.register({"post_api_request"}), (["post_api_request"], True))

    def test_calls_outside_the_app_only_where_hermes_can_name_their_agent(self):
        self.register({"post_api_request"})
        self.assertTrue(self.agent_usage)
        self.register({"post_api_request"}, names_agents=False)
        self.assertFalse(self.agent_usage)

    def test_none_and_no_usage_where_hermes_lacks_the_hook_or_lists_none(self):
        # Hermes would take an unknown name with a warning: it is not tried.
        self.assertEqual(self.register({"post_auxiliary_call"}), ([], False))
        self.assertEqual(self.register(None), ([], False))


class StubBoard:
    """A kanban board that holds what the test says (held_tasks.Board's methods)."""

    def __init__(self):
        self.tasks = [{"task": "t_1", "title": "Write the report", "reason": "Which client?", "since": 1,
                       "revision": "e:2", "resume": held_tasks.RESUME}]
        self.resumed = []

    def read(self, profile):
        return list(self.tasks) if profile == "main" else []

    def resume(self, profile, ref, revision):
        if revision != "e:2":
            raise held_tasks.HeldTaskError("conflict", "The task changed since; it was not resumed.")
        self.resumed.append((profile, ref))
        self.tasks = []


class HeldTasksOverTheSocket(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "app", "main.sock")
        self.board = StubBoard()
        with patch.object(held_tasks, "native", return_value=self.board):
            self.adapter = EnclosAdapter(PlatformConfig({"socket": self.path, "token": TOKEN}))
        self.assertTrue(await self.adapter.connect())

    async def asyncTearDown(self):
        await asyncio.wait_for(self.adapter.disconnect(), 5)

    async def connect(self, capabilities):
        reader, writer = await asyncio.open_unix_connection(self.path, limit=protocol.MAX_MESSAGE_BYTES + 1)
        writer.write(line("hello", token=TOKEN, capabilities=capabilities))
        await writer.drain()
        hello = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertIn("held_tasks", hello["capabilities"])
        return reader, writer

    async def next(self, reader):
        return json.loads(await asyncio.wait_for(reader.readline(), 5))

    async def test_one_list_after_the_hello_written_to_the_bridge_not_kept_in_the_outbox(self):
        reader, writer = await self.connect(["held_tasks"])
        self.assertEqual((await self.next(reader))["type"], "held_tasks")
        writer.write(line("message.in", conversation="c-1", person="alice@example.com", text="hi"))
        await writer.drain()
        # Nothing changed on the board: the next line is the message's ack
        self.assertEqual((await self.next(reader))["type"], "ack")
        self.assertEqual(self.adapter._outbox.pending(), [])
        writer.close()

    async def test_a_bridge_without_the_capability_gets_no_list(self):
        reader, writer = await self.connect([])
        writer.write(line("message.in", conversation="c-1", person="alice@example.com", text="hi"))
        await writer.drain()
        self.assertEqual((await self.next(reader))["type"], "ack")
        writer.close()

    async def test_the_list_after_the_hello_then_a_resume_and_a_fresh_list(self):
        reader, writer = await self.connect(["held_tasks"])
        listed = await self.next(reader)
        self.assertEqual((listed["type"], [t["task"] for t in listed["tasks"]]), ("held_tasks", ["t_1"]))
        resume = line("held_task.resume", task="t_1", revision="e:2", person="alice@example.com", device="d-1")
        writer.write(resume)
        await writer.drain()
        resumed = await self.next(reader)
        self.assertEqual((resumed["type"], resumed["of"]), ("held_task.resumed", json.loads(resume)["id"]))
        self.assertEqual((await self.next(reader))["tasks"], [])
        self.assertEqual(self.board.resumed, [("main", "t_1")])
        writer.close()

    async def test_a_kanban_tick_from_another_thread_reads_the_board_again(self):
        reader, writer = await self.connect(["held_tasks"])
        await self.next(reader)
        self.board.tasks = []
        ticked = sys.modules[EnclosAdapter.__module__]._kanban_ticked
        await asyncio.to_thread(ticked, board="default", profile_name="default", outcome="idle")
        self.assertEqual((await self.next(reader))["tasks"], [])
        writer.close()


class Registration(unittest.TestCase):
    def registered(self, valid_hooks):
        plugins = types.ModuleType("hermes_cli.plugins")
        plugins.VALID_HOOKS = set(valid_hooks)
        package = types.ModuleType("hermes_cli")
        package.plugins = plugins
        ctx = Mock()
        module = sys.modules[EnclosAdapter.__module__]
        with patch.dict(sys.modules, {"hermes_cli": package, "hermes_cli.plugins": plugins}):
            module.register(ctx)
        return {c.args[0]: c.args[1] for c in ctx.register_hook.call_args_list}

    def test_the_dispatch_tick_hook_is_registered_only_when_hermes_knows_it(self):
        module = sys.modules[EnclosAdapter.__module__]
        hooks = self.registered({"on_kanban_dispatch_tick"})
        self.assertIs(hooks["on_kanban_dispatch_tick"], module._kanban_ticked)
        with self.assertLogs("enclos.adapter", "INFO"):
            self.assertNotIn("on_kanban_dispatch_tick", self.registered(set()))

    def writing_hooks(self, valid_hooks, board=True):
        """The `pre_llm_call` callbacks registered, with or without a kanban board."""
        plugins = types.ModuleType("hermes_cli.plugins")
        plugins.VALID_HOOKS = set(valid_hooks)
        kanban_db = types.ModuleType("hermes_cli.kanban_db")
        if board:
            kanban_db.list_tasks = kanban_db.list_boards = lambda *a, **k: []
        package = types.ModuleType("hermes_cli")
        package.plugins, package.kanban_db = plugins, kanban_db
        ctx = Mock()
        module = sys.modules[EnclosAdapter.__module__]
        with patch.dict(sys.modules, {"hermes_cli": package, "hermes_cli.plugins": plugins,
                                      "hermes_cli.kanban_db": kanban_db}):
            module.register(ctx)
        return [c.args[1] for c in ctx.register_hook.call_args_list if c.args[0] == "pre_llm_call"]

    def test_an_agent_with_a_board_is_told_how_the_app_draws_its_tasks(self):
        tasks = sys.modules[EnclosAdapter.__module__].tasks
        self.assertIn(tasks.writing_context, self.writing_hooks({"pre_llm_call"}))
        self.assertEqual(tasks.writing_context(session_id="s", is_first_turn=False),
                         {"context": tasks.WRITING_HINT})

    def test_no_board_or_no_hook_means_no_task_hint(self):
        tasks = sys.modules[EnclosAdapter.__module__].tasks
        self.assertNotIn(tasks.writing_context, self.writing_hooks({"pre_llm_call"}, board=False))
        self.assertNotIn(tasks.writing_context, self.writing_hooks(set()))


if __name__ == "__main__":
    unittest.main()
