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
from unittest.mock import patch

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
    global EnclosAdapter, PlatformConfig
    stand_ins = patch.dict(sys.modules, _hermes_stand_ins())
    stand_ins.start()
    unittest.addModuleCleanup(stand_ins.stop)
    sys.modules.pop("enclos.adapter", None)
    from enclos.adapter import EnclosAdapter
    from gateway.config import PlatformConfig


from enclos import protocol  # noqa: E402

TOKEN = "t" * 64


def line(message_type: str, **fields) -> bytes:
    return (json.dumps({"v": 1, "type": message_type, "id": os.urandom(8).hex(), **fields}) + "\n").encode()


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


if __name__ == "__main__":
    unittest.main()
