"""Exact turn cancellation; optional execution of the pinned native public helper."""
import ast
import asyncio
import os
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enclos import interrupts, protocol


class NativeHarness:
    def __init__(self):
        self._active_sessions, self._session_tasks = {}, {}
        self.typing_stopped = []

    async def interrupt_session_activity(self, session_key, chat_id, metadata=None):
        if session_key in self._active_sessions:
            self._active_sessions[session_key].set()
        await self._stop_typing_quietly(chat_id, metadata)

    async def _stop_typing_quietly(self, chat_id, metadata):
        self.typing_stopped.append(chat_id)
        await asyncio.sleep(0)


def event(identifier="first", conversation="c"):
    return types.SimpleNamespace(message_id=identifier, text="original text", source=types.SimpleNamespace(chat_id=conversation),
        raw_message={"id": identifier, "type": "message.in", "conversation": conversation, "text": "original text"})


def abort(identifier="first", conversation="c"):
    return protocol._message("turn.abort", conversation=conversation, of=identifier)


class ExactInterruption(unittest.IsolatedAsyncioTestCase):
    adapter_type = NativeHarness

    async def test_only_the_original_native_guard_is_signalled(self):
        adapter = self.adapter_type()
        manager = interrupts.Manager(adapter, lambda e: e.source.chat_id)
        original, successor = event(), event("second")
        manager.admit(original)
        began, release = asyncio.Event(), asyncio.Event()
        guard = asyncio.Event()

        async def processing():
            adapter._active_sessions["c"] = guard
            adapter._session_tasks["c"] = asyncio.current_task()
            manager.start(original)
            began.set()
            await release.wait()
            manager.complete(original)

        task = asyncio.create_task(processing())
        try:
            await began.wait()
            await manager.abort(abort(conversation="different"))
            self.assertFalse(guard.is_set())
            await manager.abort(abort())
            self.assertTrue(guard.is_set())
            self.assertEqual(adapter.typing_stopped, ["c"])
            # A replacement native task/guard is never selected by the old id.
            replacement = asyncio.Event()
            adapter._active_sessions["c"] = replacement
            adapter._session_tasks["c"] = asyncio.current_task()
            await manager.abort(abort())
            self.assertFalse(replacement.is_set())
            manager.complete(original)
            manager.admit(successor)
            await manager.abort(abort())
            self.assertFalse(manager.pending["second"]["cancelled"])
        finally:
            release.set()
            await task

    async def test_cancel_before_native_start_and_merged_text_are_separate(self):
        adapter = self.adapter_type()
        manager = interrupts.Manager(adapter, lambda e: e.source.chat_id)
        original = event()
        manager.admit(original)
        await manager.abort(abort())
        with self.assertRaises(asyncio.CancelledError):
            manager.start(original)
        manager.complete(original)
        merged = event("merged")
        manager.admit(merged)
        await manager.abort(abort("merged"))
        merged.text += "\nA separately accepted ingress"
        manager.start(merged)  # No exact target: do not cancel the native batch.
        self.assertEqual(adapter.typing_stopped, [])
        manager.close()
        self.assertEqual(manager.pending, {})

    async def test_old_native_versions_have_no_cancel_capability(self):
        manager = interrupts.Manager(types.SimpleNamespace(), lambda e: "session")
        self.assertFalse(manager.available)
        with self.assertRaises(protocol.DecodeError) as raised:
            await manager.abort(abort())
        self.assertEqual(raised.exception.code, "unsupported")


@unittest.skipUnless(os.environ.get("ENCLOS_HERMES_APPROVAL_SOURCE"), "optional pinned Hermes source")
class PinnedNativeInterruption(ExactInterruption):
    @classmethod
    def setUpClass(cls):
        source = Path(os.environ["ENCLOS_HERMES_APPROVAL_SOURCE"]) / "gateway/platforms/base.py"
        parsed = ast.parse(source.read_text())
        base = next(node for node in parsed.body if isinstance(node, ast.ClassDef) and node.name == "BasePlatformAdapter")
        helper = next(node for node in base.body if isinstance(node, ast.AsyncFunctionDef) and node.name == "interrupt_session_activity")
        namespace = {}
        exec(compile(ast.Module(body=[helper], type_ignores=[]), str(source), "exec"), namespace)
        cls.adapter_type = type("PinnedNativeHarness", (NativeHarness,), {"interrupt_session_activity": namespace["interrupt_session_activity"]})


if __name__ == "__main__":
    unittest.main()
