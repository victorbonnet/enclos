"""The adapter over a real Unix socket, with stand-ins for the Hermes classes
it uses: long messages, one bridge at a time, bad lines, and messages the
bridge cannot read."""

import asyncio
import json
import os
import sys
import tempfile
import types
from pathlib import Path
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
        PHOTO = "photo"
        DOCUMENT = "document"

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


from enclos import held_tasks, protocol, task_events  # noqa: E402

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

    async def test_runtime_consumed_text_needs_no_file_receiver(self):
        from collections import OrderedDict
        from unittest.mock import AsyncMock
        from gateway.platforms.base import BasePlatformAdapter

        adapter = EnclosAdapter.__new__(EnclosAdapter)
        BasePlatformAdapter.__init__(adapter, PlatformConfig(), "enclos")
        adapter._seen = OrderedDict()
        adapter._last_in = {}
        adapter._interrupts = types.SimpleNamespace(admit=Mock(), complete=Mock())
        adapter._write = AsyncMock(return_value=True)

        async def consume(event):
            event._gateway_accepted = False
        adapter.handle_message = AsyncMock(side_effect=consume)
        message = protocol._message("message.in", conversation="c", person="person", text="yes please")
        self.assertFalse(hasattr(adapter, "_incoming"))
        await adapter._on_message(message)
        event = adapter.handle_message.call_args.args[0]
        adapter._interrupts.admit.assert_called_once_with(event)
        adapter._interrupts.complete.assert_called_once_with(event)
        self.assertIn(message["id"], adapter._seen)
        self.assertEqual(adapter._write.call_args.args[0]["type"], "ack")
        self.assertEqual(adapter._write.call_args.args[0]["of"], message["id"])
        # A repeated delivery retains the ordinary text deduplication contract.
        await adapter._on_message(message)
        adapter.handle_message.assert_awaited_once()
        self.assertEqual(adapter._write.await_count, 2)

    async def test_image_check_canonicalizes_in_owning_profile_scope(self):
        from contextlib import asynccontextmanager
        source = types.SimpleNamespace(profile=None)
        entered = []
        @asynccontextmanager
        async def scope(adapter, event):
            self.assertIs(event.source, source)
            source.profile = "secondary"
            entered.append(True)
            yield object()
            entered.pop()
        def check(actual):
            self.assertIs(actual, source)
            self.assertEqual(actual.profile, "secondary")
            self.assertEqual(entered, [True])
            return True
        self.adapter._images_available = check
        with patch.dict(sys.modules, {"gateway.platforms.webhook_ingress": types.SimpleNamespace(producer_scope=scope)}):
            self.assertTrue(await self.adapter._conversation_images_available(source))
        self.assertEqual(entered, [])

    async def test_disconnect_joins_cancelled_native_admission(self):
        started, release = asyncio.Event(), asyncio.Event()
        async def producer(adapter, event):
            started.set()
            await release.wait()
            return object()
        modules = {
            "gateway.platforms.webhook_ingress": types.SimpleNamespace(admit_producer=producer),
            "gateway.session_authority": types.SimpleNamespace(native_write_started=__import__("contextvars").ContextVar("writing", default=False)),
        }
        with patch.dict(sys.modules, modules), patch.object(self.adapter._incoming, "captured"):
            waiter = asyncio.create_task(self.adapter._admit_files(types.SimpleNamespace(media_urls=[])))
            await started.wait()
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter
            worker = next(iter(self.adapter._native_admissions))
            with patch.object(self.adapter, "_mark_disconnected") as teardown:
                closing = asyncio.create_task(self.adapter.disconnect())
                try:
                    await asyncio.sleep(0.03)
                    self.assertFalse(closing.done())
                    teardown.assert_not_called()
                finally:
                    release.set()
                    await closing
                self.assertTrue(worker.done())

    async def test_disconnect_native_timeout_retains_ownership(self):
        release = asyncio.Event()
        worker = asyncio.create_task(release.wait())
        self.adapter._native_admissions = {worker}
        with patch.object(self.adapter, "_mark_disconnected") as teardown:
            try:
                with self.assertRaises(TimeoutError):
                    await self.adapter.disconnect()
                teardown.assert_not_called()
                self.assertIn(worker, self.adapter._native_admissions)
                self.assertFalse(worker.done())
            finally:
                release.set()
                await worker
            await self.adapter.disconnect()

    async def test_unknown_admission_releases_completed_capture_for_expiry(self):
        from test_incoming import message_in, part
        from enclos import incoming
        import contextvars
        import time
        receiver = self.adapter._incoming
        self.assertTrue(receiver._capture_only)
        receiver.begin(message_in([{"name": "a.txt", "mime": "text/plain", "size": 5}]))
        _, paths, _, _ = receiver.part(part(0, 0, b"hello"))
        receiver.admit(paths)
        folder = Path(paths[0]).parent
        native = Path(self.dir) / "immutable-native.txt"
        writing = contextvars.ContextVar("writing", default=False)
        async def producer(adapter, event):
            native.write_bytes(Path(paths[0]).read_bytes())
            writing.set(True)
            raise RuntimeError("unknown outcome after capture")
        modules = {
            "gateway.platforms.webhook_ingress": types.SimpleNamespace(admit_producer=producer),
            "gateway.session_authority": types.SimpleNamespace(native_write_started=writing),
            "hermes_state_runtime": types.SimpleNamespace(RuntimeStoreError=type("RuntimeStoreError", (Exception,), {})),
        }
        with patch.dict(sys.modules, modules), patch.object(self.adapter, "send") as emit:
            with self.assertRaisesRegex(RuntimeError, "unknown outcome"):
                await self.adapter._admit_files(types.SimpleNamespace(media_urls=paths))
            self.assertFalse(self.adapter._native_admissions)
            self.assertTrue((folder / ".pending").exists())
            receiver.cleanup(now=time.time() + 86401)
            self.assertFalse(folder.exists())
            self.assertEqual(native.read_bytes(), b"hello")
            emit.assert_not_called()

    async def test_native_capture_cancellation_and_marker_failure(self):
        started, finish = asyncio.Event(), asyncio.Event()
        receipt = object()
        async def producer(adapter, event):
            started.set()
            await finish.wait()
            return receipt
        marks = []
        receiver = types.SimpleNamespace(
            captured=lambda paths, value: marks.append(value),
            admission_ended=lambda paths: None,
            release=lambda paths: self.fail("capture still owns staging"))
        owner = types.SimpleNamespace(_incoming=receiver, name="test")
        event = types.SimpleNamespace(media_urls=["staging"])
        modules = {
            "gateway.platforms.webhook_ingress": types.SimpleNamespace(admit_producer=producer),
            "gateway.session_authority": types.SimpleNamespace(native_write_started=__import__("contextvars").ContextVar("writing", default=False)),
        }
        with patch.dict(sys.modules, modules):
            task = asyncio.create_task(EnclosAdapter._admit_files(owner, event))
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(marks, [])
            finish.set()
            for _ in range(5):
                await asyncio.sleep(0)
            self.assertEqual(marks, [receipt])
            def marker_failure(*args):
                raise OSError("full marker disk after commit")
            receiver.captured = marker_failure
            self.assertIs(await EnclosAdapter._admit_files(owner, event), receipt)

    async def test_suggested_replies_survive_outbox_replay_and_do_not_attach_to_notices(self):
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        now = asyncio.get_running_loop().time()
        self.adapter._last_in["c-1"] = ("m1", now)
        replies = ["Fix Inbox filters", "Keep paused"]
        self.adapter._suggested_replies["c-1"] = suggested_replies.Pending(("m1", now), now, replies)
        await self.adapter.send("c-1", "♻️ Gateway online", None)
        notice = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(notice["kind"], "status")
        self.assertNotIn("suggested_replies", notice)
        await self.adapter.send("c-1", "💾 Self-improvement review: Skill 'sdlc-review' patched", None)
        review = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(review["kind"], "status")
        self.assertNotIn("suggested_replies", review)
        await self.adapter.send("c-1", "Inbox filters reset. Allow a fix?", "m1")
        sent = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(sent["suggested_replies"], replies)
        self.assertEqual(self.adapter._outbox.pending()[-1]["suggested_replies"], replies)
        await self.adapter.send("c-1", "Another message", "m1")
        following = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertNotIn("suggested_replies", following)
        writer.close()

    async def test_the_still_working_heartbeat_is_kept_back(self):
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        before = len(self.adapter._outbox.pending())
        result = await self.adapter.send("c-1", "⏳ Working — 3 min — iteration 2/60, receiving stream response")
        self.assertTrue(result.success)
        self.assertIsNone(result.message_id)
        self.assertEqual(len(self.adapter._outbox.pending()), before)
        await self.adapter.send("c-1", "Done.", "m1")
        sent = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(sent["text"], "Done.")
        writer.close()

    def kanban_pings(self):
        """A board on which this agent's chat `c-1` is subscribed to a task that
        Hermes's loop breaker routed to triage, and the plugin reading it."""
        from test_task_events import Scratch
        scratch = Scratch(self.dir)
        scratch.task("t_a09759c7", title="S2a", assignee="reviewer", status="triage")
        scratch.event("t_a09759c7", "block_loop_detected")
        scratch.subscribe("t_a09759c7", chat_id="c-1")
        self.adapter._pings = task_events.Recogniser(lambda: [("enclos-org", Path(scratch.path))], "enclos")

    async def test_a_kanban_ping_is_a_task_event_and_the_agents_own_words_stay_its_message(self):
        from test_task_events import TRIAGE
        self.kanban_pings()
        reader, writer = await self.bridge()
        writer.write(line("hello", token=TOKEN, capabilities=["task_events"]))
        await writer.drain()
        hello = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertIn("task_events", hello["capabilities"])
        now = asyncio.get_running_loop().time()
        self.adapter._suggested_replies["c-1"] = suggested_replies.Pending(("m1", now), now, ["Fix it"])
        await self.adapter.send("c-1", TRIAGE)
        ping = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual((ping["kind"], ping["text"]), ("task_event", TRIAGE))
        self.assertEqual(ping["task_event"], {"task": "t_a09759c7", "title": "S2a", "assignee": "reviewer",
                                              "event": "triage", "state": "queued"})
        self.assertNotIn("suggested_replies", ping)
        self.assertEqual(self.adapter._outbox.pending()[-1]["kind"], "task_event")
        # The same words for a chat with no subscription, or a task the board
        # never routed to triage: the agent's own.
        await self.adapter.send("c-2", TRIAGE)
        other = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(other["kind"], "notify")
        self.assertNotIn("task_event", other)
        await self.adapter.send("c-1", TRIAGE.replace("t_a09759c7", "t_00000000"))
        unknown = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(unknown["kind"], "notify")
        writer.close()

    async def test_an_older_bridge_gets_a_kanban_ping_as_a_notify_then_and_on_replay(self):
        from test_task_events import TRIAGE
        self.kanban_pings()
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        await self.adapter.send("c-1", TRIAGE)
        ping = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual((ping["kind"], ping["text"]), ("notify", TRIAGE))
        self.assertNotIn("task_event", ping)
        # Kept as the line it is: unacknowledged, it goes again after the next
        # hello, as the bridge then connected takes it.
        self.assertEqual(self.adapter._outbox.pending()[-1]["kind"], "task_event")
        writer.close()
        await asyncio.sleep(0.1)
        for capabilities, kind in (([], "notify"), (["task_events"], "task_event")):
            reader, writer = await self.bridge()
            writer.write(line("hello", token=TOKEN, capabilities=capabilities))
            await writer.drain()
            json.loads(await asyncio.wait_for(reader.readline(), 5))
            again = json.loads(await asyncio.wait_for(reader.readline(), 5))
            self.assertEqual((again["id"], again["kind"]), (ping["id"], kind))
            writer.close()
            await asyncio.sleep(0.1)

    async def test_a_reply_is_never_a_task_event(self):
        from test_task_events import TRIAGE
        self.kanban_pings()
        reader, writer = await self.bridge()
        writer.write(line("hello", token=TOKEN, capabilities=["task_events"]))
        await writer.drain()
        json.loads(await asyncio.wait_for(reader.readline(), 5))
        await self.adapter.send("c-1", TRIAGE, "m1")
        reply = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual((reply["kind"], reply["reply_to"]), ("reply", "m1"))
        self.assertNotIn("task_event", reply)
        writer.close()

    async def test_staged_suggested_replies_wait_past_a_ping_for_the_agents_next_message(self):
        from test_task_events import TRIAGE
        self.kanban_pings()
        reader, writer = await self.bridge()
        writer.write(line("hello", token=TOKEN, capabilities=["task_events"]))
        await writer.drain()
        json.loads(await asyncio.wait_for(reader.readline(), 5))
        now = asyncio.get_running_loop().time()
        self.adapter._last_in["c-1"] = ("m1", now)
        replies = ["Fix it", "Leave it"]
        self.adapter._suggested_replies["c-1"] = suggested_replies.Pending(("m1", now), now, replies)
        await self.adapter.send("c-1", TRIAGE)
        ping = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(ping["kind"], "task_event")
        self.assertNotIn("suggested_replies", ping)
        await self.adapter.send("c-1", "Task t_a09759c7 needs your call: fix it or leave it?", "m1")
        answer = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertEqual(answer["suggested_replies"], replies)
        writer.close()

    async def test_an_adapter_built_without_init_sends_a_ping_shaped_text_as_the_agents(self):
        from unittest.mock import AsyncMock
        from enclos.outbox import Outbox
        from test_task_events import TRIAGE
        adapter = EnclosAdapter.__new__(EnclosAdapter)
        adapter.name = "enclos"
        adapter._outbox = Outbox(os.path.join(self.dir, "bare-outbox"))
        adapter._write = AsyncMock(return_value=True)
        adapter._check_title_soon = Mock()
        adapter._suggested_replies, adapter._last_in = {}, {}
        result = await adapter.send("c-1", TRIAGE)
        self.assertTrue(result.success)
        [sent] = [call.args[0] for call in adapter._write.await_args_list]
        self.assertEqual((sent["kind"], sent["text"]), ("notify", TRIAGE))
        self.assertNotIn("task_event", sent)

    async def test_a_hermes_without_a_board_announces_no_task_events(self):
        self.assertIsNone(self.adapter._pings)
        reader, writer = await self.bridge()
        writer.write(line("hello", token=TOKEN, capabilities=["task_events"]))
        await writer.drain()
        hello = json.loads(await asyncio.wait_for(reader.readline(), 5))
        self.assertNotIn("task_events", hello["capabilities"])
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

    async def test_disconnect_joins_blocked_cleanup_before_teardown(self):
        import threading
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        def blocked():
            entered.set()
            release.wait()
            finished.set()
        # Replace the initial periodic pass with an exactly controlled pass.
        self.adapter._incoming_cleanup.cancel()
        await asyncio.gather(self.adapter._incoming_cleanup, return_exceptions=True)
        with patch.object(self.adapter._incoming, "cleanup", side_effect=blocked):
            self.adapter._incoming_cleanup = asyncio.create_task(self.adapter._expire_incoming())
            while not entered.is_set():
                await asyncio.sleep(0.001)
            task = asyncio.create_task(self.adapter.disconnect())
            try:
                await asyncio.sleep(0.03)
                self.assertFalse(task.done(), "disconnect returned with cleanup still running")
            finally:
                release.set()
                await task
            self.assertTrue(finished.is_set())

    async def test_disconnect_timeout_keeps_worker_owned_and_defers_teardown(self):
        import threading
        entered, release = threading.Event(), threading.Event()
        def blocked():
            entered.set()
            release.wait()
        self.adapter._incoming_cleanup.cancel()
        await asyncio.gather(self.adapter._incoming_cleanup, return_exceptions=True)
        with patch.object(self.adapter._incoming, "cleanup", side_effect=blocked):
            self.adapter._incoming_cleanup = asyncio.create_task(self.adapter._expire_incoming())
            while not entered.is_set():
                await asyncio.sleep(0.001)
            with patch.object(self.adapter, "_mark_disconnected") as teardown:
                try:
                    with self.assertRaises(TimeoutError):
                        await self.adapter.disconnect()
                    teardown.assert_not_called()
                    self.assertFalse(self.adapter._incoming_cleanup_pass.done())
                finally:
                    release.set()
                await self.adapter.disconnect()
                teardown.assert_called_once()
            self.assertIsNone(self.adapter._incoming_cleanup_pass)

    async def test_a_message_with_files_reaches_the_runtime_whole_with_its_media(self):
        # Transport fixture; native capture has separate public-runtime tests.
        self.adapter._admit_files = self.adapter.handle_message
        import base64
        files = [{"name": "doc.pdf", "mime": "application/pdf", "size": 3}]
        begin = line("message.in", conversation="c-1", person="alice@example.com", text="read", files=files)
        message_id = json.loads(begin)["id"]
        data = base64.urlsafe_b64encode(b"%PD").decode().rstrip("=")

        def part(data: str) -> bytes:
            return line("message.part", message=message_id, file=0, offset=0, data=data)

        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        root = os.path.join(self.dir, "app", "incoming", "main")
        # A part that cannot be read drops the whole message
        writer.write(begin + part("a+b/"))
        errors = [json.loads(await asyncio.wait_for(reader.readline(), 5)) for _ in range(2)]
        self.assertEqual((errors[1]["code"], errors[1]["of"]), ("bad_message", message_id))
        self.assertEqual(os.listdir(root), [])
        # The connection ends before the last byte: nothing reaches the runtime, nothing stays
        writer.write(begin + part(data[:2]))
        await writer.drain()
        writer.close()
        for _ in range(250):
            if self.adapter._bridge is None:
                break
            await asyncio.sleep(0.02)
        self.assertEqual(os.listdir(root), [])
        self.assertEqual(self.adapter.received, [])
        # Sent again whole, then once more after it was taken: one turn
        reader, writer = await self.bridge()
        await self.hello(reader, writer)
        for _ in range(2):
            writer.write(begin + part(data))
            await writer.drain()
            ack = json.loads(await asyncio.wait_for(reader.readline(), 5))
            self.assertEqual((ack["type"], ack["of"]), ("ack", message_id))
        [event] = self.adapter.received
        self.assertEqual((event.text, event.message_type, event.media_types), ("read", "document", ["application/pdf"]))
        with open(event.media_urls[0], "rb") as f:
            self.assertEqual(f.read(), b"%PD")
        self.assertTrue(event.media_urls[0].startswith(root + os.sep))
        self.adapter._incoming.cleanup(now=10**12)
        self.assertTrue(os.path.isfile(event.media_urls[0]))
        await self.adapter.on_processing_start(event)
        await self.adapter.on_processing_complete(event, None)
        self.adapter._incoming.cleanup(now=10**12)
        self.assertFalse(os.path.exists(event.media_urls[0]))
        self.assertEqual(os.listdir(root), [])
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
            module._usage(False, usage=call, model="gpt-6.1-sol", provider="openai-codex")
            message = await next_usage(reader)
            self.assertEqual(message["conversation"], "c-42")
            self.assertEqual(message["model"], "gpt-6.1-sol")
            self.assertEqual(message["model_provider"], "openai-codex")
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

    def writing_hooks(self, valid_hooks, board="board", profile="engineer"):
        """The `pre_llm_call` callbacks registered. `board` is "board", "no functions" (a
        `kanban_db` without `list_tasks` and `list_boards`) or "no module"; `profile` is what
        Hermes names the process's home, None when it is not a profile's."""
        plugins = types.ModuleType("hermes_cli.plugins")
        plugins.VALID_HOOKS = set(valid_hooks)
        package = types.ModuleType("hermes_cli")
        package.plugins = plugins
        modules = {"hermes_cli": package, "hermes_cli.plugins": plugins}
        if board != "no module":
            kanban_db = types.ModuleType("hermes_cli.kanban_db")
            if board == "board":
                kanban_db.list_tasks = kanban_db.list_boards = lambda *a, **k: []
            package.kanban_db = modules["hermes_cli.kanban_db"] = kanban_db
        constants = types.ModuleType("hermes_constants")
        constants.get_hermes_home = lambda: "/home/alice/.hermes/profiles/engineer"
        constants.profile_name_for_home = lambda home: profile
        modules["hermes_constants"] = constants
        ctx = Mock()
        module = sys.modules[EnclosAdapter.__module__]
        with patch.dict(sys.modules, modules):
            module.register(ctx)
        return [c.args[1] for c in ctx.register_hook.call_args_list if c.args[0] == "pre_llm_call"]

    def test_an_agent_with_a_board_is_told_how_the_app_draws_its_tasks(self):
        tasks = sys.modules[EnclosAdapter.__module__].tasks
        self.assertIn(tasks.writing_context, self.writing_hooks({"pre_llm_call"}))
        self.assertEqual(tasks.writing_context(session_id="s", is_first_turn=False),
                         {"context": tasks.WRITING_HINT})

    def test_the_hint_goes_only_where_tasks_are_on(self):
        tasks = sys.modules[EnclosAdapter.__module__].tasks
        for case in ({"board": "no functions"}, {"board": "no module"}, {"profile": None}):
            with self.subTest(**case), self.assertLogs("enclos.tasks", "INFO") as logs:
                self.assertNotIn(tasks.writing_context, self.writing_hooks({"pre_llm_call"}, **case))
            self.assertIn("Tasks are off", logs.output[0])
        self.assertNotIn(tasks.writing_context, self.writing_hooks(set()))


if __name__ == "__main__":
    unittest.main()
