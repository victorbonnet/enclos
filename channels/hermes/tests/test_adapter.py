"""The adapter over a real Unix socket, with stand-ins for the Hermes classes
it uses: the long-message and one-bridge-at-a-time paths."""

import asyncio
import json
import os
import sys
import tempfile
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _stub_hermes() -> None:
    """Stand-ins for the gateway modules adapter.py imports."""

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

        def _mark_connected(self):
            pass

        def _mark_disconnected(self):
            pass

        def _wire_plugin_handlers(self, _):
            pass

        def build_source(self, **fields):
            return fields

        async def handle_message(self, event):
            self.received.append(event)

    class MessageEvent:
        def __init__(self, **fields):
            self.__dict__.update(fields)

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
    sys.modules.update(modules)


_stub_hermes()

from enclos import protocol  # noqa: E402
from enclos.adapter import EnclosAdapter  # noqa: E402
from gateway.config import PlatformConfig  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
