"""The adapter's media events read by the Hermes installed in this home: its own
`MessageEvent` and the gateway's note for each document a person sends
(`_prepend_inbound_document_notes`, with the helpers it calls), taken from its
source. A file the adapter writes is not inlined in the text: Hermes must say
so, and tell the agent to read it. Skipped where no Hermes is installed."""

import ast
import importlib.util
import os
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_adapter import _hermes_stand_ins  # noqa: E402

HERMES = Path.home() / ".hermes" / "hermes-agent"
NOT_INLINED = "Its content is not inlined here"
INLINED = "Its content has been included below"


def _defined(path: Path, names: set) -> list:
    """The top-level functions and assignments named `names` in `path`, and
    the methods of that name in its classes."""
    found = []
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.FunctionDef) and node.name in names:
            node.decorator_list = []
            found.append(node)
        elif isinstance(node, ast.Assign) and any(getattr(t, "id", None) in names for t in node.targets):
            found.append(node)
    return found


def _run(nodes: list, namespace: dict, where: str) -> dict:
    module = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(module, where, "exec"), namespace)
    return namespace


@unittest.skipUnless((HERMES / "gateway" / "run_inbound.py").is_file(), "no Hermes installed")
class InstalledHermesDocumentNotesTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
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

    def notes(self, event) -> str:
        """The text Hermes's gateway gives the agent for `event`, with its document notes."""
        run = _run(_defined(HERMES / "gateway" / "run.py", {
            "_event_media_type_at", "_event_media_kind_is", "_event_media_is_image", "_event_media_is_audio",
            "_event_media_is_video", "_build_document_context_note"}),
            {"MessageType": self.event.MessageType}, "<Hermes gateway/run.py>")
        inbound = _run(_defined(HERMES / "gateway" / "run_inbound.py", {
            "_RELAY_MEDIA_PREFIX", "_UNKNOWN_ATTACHMENT_NAME", "_inbound_attachment_display_name",
            "_prepend_inbound_document_notes"}),
            {"os": os, "re": re,"MessageEvent": self.event.MessageEvent,
             "clean_attachment_filename": self.event.clean_attachment_filename}, "<Hermes gateway/run_inbound.py>")
        gateway_run = types.ModuleType("gateway.run")
        gateway_run.__dict__.update(run)
        # Outside Docker, the agent sees the path as it is
        tools = types.ModuleType("tools.credential_files")
        tools.to_agent_visible_cache_path = lambda path: path
        runner = types.SimpleNamespace(_inbound_attachment_display_name=inbound["_inbound_attachment_display_name"])
        with patch.dict(sys.modules, {"gateway.run": gateway_run, "tools": types.ModuleType("tools"),
                                      "tools.credential_files": tools}):
            return inbound["_prepend_inbound_document_notes"](runner, event, event.text)

    async def test_a_text_document_is_noted_as_a_file_to_read(self):
        event = await self.received("read it", [("notes.txt", "text/plain")])
        notes = self.notes(event)
        self.assertNotIn(INLINED, notes)
        self.assertIn(f"[The user sent a text document: 'notes.txt'. It is saved at: {event.media_urls[0]}.", notes)
        self.assertIn(NOT_INLINED, notes)
        self.assertNotIn("SENTINEL", notes)
        self.assertTrue(notes.endswith("\n\nread it"))
        self.assertEqual(event.message_type, self.event.MessageType.DOCUMENT)
        self.assertEqual((event.media_text_inlined, event.media_filenames), ([False], ["notes.txt"]))

    async def test_a_photo_with_a_document_goes_to_vision_and_the_document_is_noted(self):
        event = await self.received("both", [("Beach.JPG", "image/jpeg"), ("notes.md", "text/markdown")])
        notes = self.notes(event)
        self.assertNotIn(INLINED, notes)
        self.assertIn(NOT_INLINED, notes)
        # One note, the document's: the photo is the vision step's
        self.assertEqual(notes.count("[The user sent"), 1)
        self.assertIn("'notes.md'", notes)
        self.assertNotIn("Beach", notes)
        self.assertEqual(event.message_type, self.event.MessageType.PHOTO)
        self.assertEqual(event.media_types, ["image/jpeg", "text/markdown"])
        self.assertEqual(event.media_text_inlined, [False, False])
        self.assertEqual(event.media_filenames, ["Beach.JPG", "notes.md"])

    async def test_a_message_or_a_photo_alone_has_no_note(self):
        text = await self.received("hello", [])
        self.assertEqual((text.message_type, text.media_urls, text.media_text_inlined),
                         (self.event.MessageType.TEXT, [], []))
        self.assertEqual(self.notes(text), "hello")
        photo = await self.received("look", [("dot.png", "image/png")])
        self.assertEqual((photo.message_type, photo.media_types), (self.event.MessageType.PHOTO, ["image/png"]))
        self.assertEqual(self.notes(photo), "look")


if __name__ == "__main__":
    unittest.main()
