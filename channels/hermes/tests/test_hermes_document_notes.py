"""Adapter delivery through Hermes's public MessageEvent contract.

ENCLOS_HERMES_SOURCE selects the real event module. A named invalid source
fails rather than skipping. No private gateway source is extracted or run.
"""

import importlib.util
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_adapter import _hermes_stand_ins  # noqa: E402

NAMED = os.environ.get("ENCLOS_HERMES_SOURCE")
HERMES = Path(NAMED) if NAMED else Path.home() / ".hermes" / "hermes-agent"
# What these tests read of it
SOURCES = ("gateway/platforms/event.py",)
@unittest.skipUnless(NAMED or all((HERMES / f).is_file() for f in SOURCES),
                     "no Hermes checkout named or installed")
class InstalledHermesDocumentNotesTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # A named checkout is never skipped: one without these files fails
        self.assertEqual([f for f in SOURCES if not (HERMES / f).is_file()], [],
                         f"the Hermes checkout at {HERMES} lacks the files these tests read")
        stand_ins = _hermes_stand_ins()
        stand_ins["gateway.session"] = types.SimpleNamespace(SessionSource=object)
        patcher = patch.dict(sys.modules, stand_ins)
        patcher.start()
        self.addCleanup(patcher.stop)
        # Hermes's own event classes, in place of the stand-ins
        spec = importlib.util.spec_from_file_location(
            "gateway.platforms.event", HERMES / "gateway" / "platforms" / "event.py")
        event = importlib.util.module_from_spec(spec)
        sys.modules["gateway.platforms.event"] = event
        spec.loader.exec_module(event)
        self.event = event
        sys.modules.pop("enclos.adapter", None)
        from enclos.adapter import EnclosAdapter
        from gateway.config import PlatformConfig
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.adapter = EnclosAdapter(PlatformConfig({"socket": os.path.join(self.dir.name, "main.sock"),
                                                     "token": "t" * 64}))
        self.adapter._write = AsyncMock()
        self.adapter._interrupts = Mock()

    async def received(self, text: str, files: list) -> object:
        """What Hermes gets of `text` with `files` (`(name, mime)`), written as the adapter writes them."""
        paths = []
        for n, (name, _) in enumerate(files, 1):
            paths.append(os.path.join(self.dir.name, f"{n}-{name}"))
            Path(paths[-1]).write_bytes(b"SENTINEL")
        media = (paths, [m for _, m in files], [n for n, _ in files]) if files else None
        message = {"id": os.urandom(8).hex(), "conversation": "c-1", "person": "alice@example.com", "text": text}
        await self.adapter._on_message(message, media)
        return self.adapter.received[-1]

    async def test_a_text_document_is_delivered_as_a_noninlined_file(self):
        event = await self.received("read it", [("notes.txt", "text/plain")])
        self.assertEqual(event.message_type, self.event.MessageType.DOCUMENT)
        self.assertEqual((event.media_text_inlined, event.media_filenames), ([False], ["notes.txt"]))

    async def test_a_photo_with_a_document_preserves_public_media_metadata(self):
        event = await self.received("both", [("Beach.JPG", "image/jpeg"), ("notes.md", "text/markdown")])
        self.assertEqual(event.message_type, self.event.MessageType.PHOTO)
        self.assertEqual(event.media_types, ["image/jpeg", "text/markdown"])
        self.assertEqual(event.media_text_inlined, [False, False])
        self.assertEqual(event.media_filenames, ["Beach.JPG", "notes.md"])

    async def test_a_message_or_a_photo_preserves_text(self):
        text = await self.received("hello", [])
        self.assertEqual((text.message_type, text.media_urls, text.media_text_inlined),
                         (self.event.MessageType.TEXT, [], []))
        self.assertEqual(text.text, "hello")
        photo = await self.received("look", [("dot.png", "image/png")])
        self.assertEqual((photo.message_type, photo.media_types), (self.event.MessageType.PHOTO, ["image/png"]))
        self.assertEqual(photo.text, "look")


if __name__ == "__main__":
    unittest.main()
