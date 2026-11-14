"""The adapter in a real Hermes: the commands it lists to the bridge after
the hello. The adapter reads them from Hermes's command registry and lists
none when it cannot, so a change there would leave the phone without its
command menu and no error: this fails instead, in CI's `hermes-latest` job.
"""

import asyncio
import importlib
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TOKEN = "t" * 64


@unittest.skipUnless(os.environ.get("ENCLOS_HERMES_SOURCE"), "optional real Hermes checkout")
class NativeHermesCommands(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        profile = os.path.join(temporary.name, "profile")
        os.mkdir(profile)
        env = patch.dict(os.environ, {"HERMES_HOME": profile})
        env.start()
        self.addCleanup(env.stop)
        source = os.environ["ENCLOS_HERMES_SOURCE"]
        sys.path.insert(0, source)
        self.addCleanup(sys.path.remove, source)
        # Imported again, against the real gateway: `test_adapter` imported it
        # against stand-ins, and `enclos.adapter` may still name that copy.
        sys.modules.pop("enclos.adapter", None)
        self.adapter_module = importlib.import_module("enclos.adapter")
        from gateway.config import PlatformConfig
        from gateway.platform_registry import PlatformEntry, platform_registry

        # As the plugin's `register` does in a gateway: Hermes knows the
        # platform `enclos` only once it is registered.
        platform_registry.register(PlatformEntry(
            name=self.adapter_module.PLATFORM, label="enclos app",
            adapter_factory=self.adapter_module.EnclosAdapter, check_fn=lambda: True))
        self.addCleanup(platform_registry.unregister, self.adapter_module.PLATFORM)
        self.path = os.path.join(temporary.name, "app", "main.sock")
        self.adapter = self.adapter_module.EnclosAdapter(PlatformConfig(extra={"socket": self.path, "token": TOKEN}))
        self.assertTrue(await self.adapter.connect())

    async def asyncTearDown(self):
        await asyncio.wait_for(self.adapter.disconnect(), 5)

    def test_hermes_has_commands_to_list(self):
        listed = self.adapter_module._hermes_commands()
        self.assertTrue(listed, "no command read from Hermes's registry")
        for name, _description, _args in listed:
            self.assertTrue(str(name).strip(), listed)

    async def test_a_commands_message_follows_the_hello(self):
        reader, writer = await asyncio.open_unix_connection(self.path)
        writer.write((json.dumps({"v": 1, "type": "hello", "id": "h1", "token": TOKEN}) + "\n").encode())
        await writer.drain()
        hello = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(hello["type"], "hello")
        self.assertIn("commands", hello["capabilities"])
        listing = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(listing["type"], "commands")
        self.assertTrue(listing["commands"])
        self.assertTrue(all(row["name"] for row in listing["commands"]), listing)
        writer.close()
        await writer.wait_closed()


if __name__ == "__main__":
    unittest.main()
