"""The Hermes side of enclos's channel: a gateway platform adapter.

It listens on MOBILE_APP_SOCKET, a Unix socket in the sandbox home, for
enclos's bridge, which must open with a `hello` holding the agent's token
(MOBILE_APP_TOKEN). The token keeps the host's other programs out, and
nothing more: the agent can read it too (docs/protocol.md, the plugin
leg). Each conversation is a
Hermes chat, so a cron job created in one delivers back to it. What the
agent says is kept on disk until the bridge acknowledges it.

The bridge decides who may talk to the agent (docs/protocol.md), so every
person it names is accepted here: `register` sets the allow-all switch to
this channel's own variable, which `enclos runtime configure` turns on.
"""

import asyncio
import collections
import contextvars
import logging
import mimetypes
import os
import shutil
import socket
import uuid
from datetime import UTC, datetime
from typing import Any, Optional

from gateway.config import Platform, PlatformConfig
from gateway.platforms._shared import get_scoped_secret
from gateway.platforms.base import BasePlatformAdapter, SendResult
from gateway.platforms.event import MessageEvent, MessageType

from . import conversations
from . import incoming
from . import lines, protocol
from .outbox import Outbox
from . import approvals
from . import decisions
from . import asks
from . import held_tasks
from . import model, image_eligibility
from . import routines
from . import questions
from . import suggested_replies
from . import interrupts
from . import runtime_approvals
from . import tasks
from . import task_events

logger = logging.getLogger(__name__)

PLATFORM = "enclos"
HELLO_TIMEOUT_SECONDS = 10
_APPROVAL_SEND = contextvars.ContextVar("enclos_runtime_approval_send", default=False)
# The bridge sends a message again, with its id, until it has the ack: the
# ids of the last ones the runtime had, to drop one that comes again
SEEN_MESSAGES = 1024

# The connected adapters and their event loops, for the tool hooks, which
# Hermes calls from the agent's worker threads.
_ADAPTERS: "set[EnclosAdapter]" = set()


def _setting(config: Optional[PlatformConfig], key: str, env: str) -> str:
    extra = (getattr(config, "extra", None) or {}) if config else {}
    return str(extra.get(key) or get_scoped_secret(env, "") or "").strip()


def check_requirements() -> bool:
    return bool(_setting(None, "socket", "MOBILE_APP_SOCKET") and _setting(None, "token", "MOBILE_APP_TOKEN"))


def validate_config(config) -> bool:
    return bool(_setting(config, "socket", "MOBILE_APP_SOCKET") and _setting(config, "token", "MOBILE_APP_TOKEN"))


class FileAdmissionRefused(Exception):
    """The native ingress definitively did not admit this delivery."""


class EnclosAdapter(BasePlatformAdapter):
    # Defaults for an adapter that did not run `__init__` (enclos's tests build
    # it with EnclosAdapter.__new__): no kanban pings to tell apart, and a
    # bridge that does not take task events (ADR 0071).
    _pings: Optional["task_events.Recogniser"] = None
    _bridge_task_events = False

    def __init__(self, config: PlatformConfig):
        super().__init__(config=config, platform=Platform(PLATFORM))
        self._path = _setting(config, "socket", "MOBILE_APP_SOCKET")
        self._token = _setting(config, "token", "MOBILE_APP_TOKEN")
        # enclos names each agent's socket `<agent>.sock`; the process's own
        # environment would name the gateway's first agent for every one
        self._agent = os.path.basename(self._path).removesuffix(".sock") or "default"
        self._outbox = Outbox(os.path.join(os.path.dirname(self._path), f"{os.path.basename(self._path)}.outbox"))
        self._server: Optional[asyncio.base_events.Server] = None
        self._bridge: Optional[asyncio.StreamWriter] = None
        # Whether the connected bridge takes `usage` (its hello says so).
        self._bridge_usage = False
        self._bridge_agent_usage = False
        self._lock = asyncio.Lock()
        # By conversation: the title last sent to the bridge, and the pending look.
        self._titles: dict[str, str] = {}
        self._title_checks: dict[str, asyncio.Task] = {}
        # By conversation: the person's last message, and when it came, so a
        # file Hermes delivers after a reply (with no reply_to) answers it too.
        self._last_in: dict[str, tuple[str, float]] = {}
        self._suggested_replies: dict[str, suggested_replies.Pending] = {}
        # Whether a failure to read a session's title was logged at info already.
        self._title_failure_told = False
        self._seen: collections.OrderedDict[str, None] = collections.OrderedDict()
        # The files a person sends with a message, written beside the socket
        # (ADR 0076, proposed).
        self._incoming = incoming.Receiver(self._path, self._agent, capture_only=True)
        self._incoming_cleanup = None
        self._incoming_cleanup_pass = None
        # Work beside the connection (routine controls, deletions, the report
        # after a hello), kept so that none is collected early.
        self._routine_tasks: set[asyncio.Task] = set()
        self._conversation_home = conversations.capture_home()
        self._routines = routines.Manager(self._path)
        self._routines.dispatch = self._dispatch_routine
        self._routines.runtime = self._routine_runtime
        self._model = model.Manager(self._agent)
        # What checks the bridge's signature of each runtime-approval decision
        # (ADR 0060): its public key comes from `runtime configure`, never this
        # socket, which the agent can speak on too.
        self._questions = questions.Manager(
            self._outbox, self._write, self.send,
            decisions=decisions.load(_setting(config, "bridge_key", "MOBILE_APP_BRIDGE_KEY"),
                                     os.environ.get("ENCLOS_SANDBOX", ""), self._agent))
        # By message id: a policy request's tool call waiting for the bridge.
        self._answers: dict[str, asyncio.Future] = {}
        self._interrupts = interrupts.Manager(self, self._interrupt_session_key,
            lifecycle=all(callable(getattr(BasePlatformAdapter, hook, None))
                          for hook in ("on_processing_start", "on_processing_complete")))
        # This agent's blocked tasks on Hermes's kanban board (ADR 0066): the
        # agent is the Hermes profile its socket names.
        self._held = held_tasks.Manager(self._agent, self._write)
        # What the agent writes for the person on those tasks (ADR 0073),
        # kept beside its socket so a restart keeps it.
        self._asks = asks.Asks(f"{self._path}.held-asks.json")
        self._held.asks = self._asks
        # What the agent is doing, and its tasks on Hermes's board (ADR 0068).
        self._reporter = tasks.Reporter(self._agent, self._write,
                                        tasks.hermes_board(self._conversation_home, PLATFORM))
        # Hermes's kanban pings, told from the agent's messages (ADR 0071);
        # None when this Hermes has no board to read, and they stay messages.
        self._pings = task_events.hermes(PLATFORM)
        # Whether the connected bridge takes `kind: task_event` (its hello says so).
        self._bridge_task_events = False

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        if not (self._path and self._token):
            logger.warning("[%s] MOBILE_APP_SOCKET or MOBILE_APP_TOKEN not set", self.name)
            return False
        try:
            os.makedirs(os.path.dirname(self._path), mode=0o700, exist_ok=True)
            if os.path.exists(self._path):
                os.unlink(self._path)
            # Bound and made the user's alone before it listens, so no
            # connection gets in under the mode the process's umask gives
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(self._path)
                os.chmod(self._path, 0o600)
            except OSError:
                listener.close()
                raise
            # A line as long as the protocol allows, not asyncio's 64 KiB.
            self._server = await asyncio.start_unix_server(
                self._on_connection, sock=listener, limit=lines.LIMIT)
        except OSError as e:
            logger.error("[%s] Cannot listen on %s: %s", self.name, self._path, e)
            return False
        self._incoming_cleanup = asyncio.create_task(self._expire_incoming())
        self._mark_connected()
        self._loop = asyncio.get_running_loop()
        _ADAPTERS.add(self)
        self._reporter.start()
        self._wire_plugin_handlers(None)
        logger.info("[%s] Listening for the bridge", self.name)
        return True

    async def _expire_incoming(self):
        while True:
            try:
                self._incoming_cleanup_pass = asyncio.create_task(asyncio.to_thread(self._incoming.cleanup))
                await asyncio.shield(self._incoming_cleanup_pass)
            except Exception:
                logger.exception("Incoming expiry pass failed")
            await asyncio.sleep(60)

    async def disconnect(self) -> None:
        if self._incoming_cleanup is not None:
            self._incoming_cleanup.cancel()
            await asyncio.gather(self._incoming_cleanup, return_exceptions=True)
            self._incoming_cleanup = None
        if self._incoming_cleanup_pass is not None:
            # Cancellation of to_thread does not join its worker. Keep ownership
            # on timeout and fail before lifecycle teardown; a caller may retry.
            await asyncio.wait_for(asyncio.shield(self._incoming_cleanup_pass), 5)
            self._incoming_cleanup_pass = None
        admissions = tuple(getattr(self, "_native_admissions", ()))
        if admissions:
            # Join actual capture/admission, even if its original waiter was
            # cancelled. Timeout preserves ownership and defers resource teardown.
            await asyncio.wait_for(
                asyncio.shield(asyncio.gather(*admissions)), 5)
        _ADAPTERS.discard(self)
        self._interrupts.close()
        await self._reporter.stop()
        await self._questions.close()
        await self._held.close()
        self._mark_disconnected()
        if self._bridge:
            self._bridge.close()
            self._bridge = None
            self._bridge_usage = False
            self._bridge_agent_usage = False
            self._bridge_task_events = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self._path and os.path.exists(self._path):
            os.unlink(self._path)

    async def _on_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self._bridge is not None:
            writer.close()  # one bridge at a time
            return
        try:
            first = await asyncio.wait_for(reader.readline(), HELLO_TIMEOUT_SECONDS)
            hello = protocol.decode_from_bridge(first)
        except (asyncio.TimeoutError, protocol.DecodeError, ConnectionError, ValueError, RecursionError):
            # ValueError: a first line over the limit; RecursionError: one
            # nested too deep. Either way, said by whoever, without the token
            writer.close()
            return
        if hello["type"] != "hello" or not protocol.token_matches(hello.get("token"), self._token):
            logger.warning("[%s] A connection without the agent's token was closed", self.name)
            writer.close()
            return
        # Checked again once the hello is in: two connections may both have
        # passed the first check while waiting for theirs. Nothing awaits
        # between this check and taking the slot, so only one takes it.
        if self._bridge is not None:
            writer.close()
            return
        self._bridge = writer
        logger.info("[%s] Bridge connected", self.name)
        self._adopt_home(hello.get("home"))
        self._questions.bridge_supports = "questions" in hello.get("capabilities", [])
        self._questions.bridge_runtime_supports = "runtime_approvals" in hello.get("capabilities", [])
        self._held.bridge_supports = "held_tasks" in hello.get("capabilities", [])
        self._reporter.bridge = frozenset(hello.get("capabilities", []))
        # An older bridge would answer each `usage` as an unknown type.
        self._bridge_usage = "usage" in hello.get("capabilities", [])
        self._bridge_agent_usage = "agent_usage" in hello.get("capabilities", [])
        self._bridge_task_events = "task_events" in hello.get("capabilities", [])
        try:
            listed = _hermes_commands()
            capabilities = ["commands"] if listed else []
            if _USAGE_HOOKS:
                capabilities.append("usage")
                if _AGENT_USAGE:
                    capabilities.append("agent_usage")
            if conversations.available(self):
                capabilities.append("conversation_delete")
            if self._routines.available:
                capabilities.append("routines")
            if self._model.available:
                capabilities.append("model")
            if self._questions.available:
                capabilities.append("questions")
            if self._questions.approvals_available:
                capabilities.append("runtime_approvals")
            if self._interrupts.available:
                capabilities.append("abort")
            if self._held.native:
                capabilities.append("held_tasks")
            if self._pings is not None:
                capabilities.append("task_events")
            capabilities.extend(self._reporter.capabilities)
            if self._files_available():
                capabilities.append("incoming_files")
                if await asyncio.to_thread(self._images_available):
                    capabilities.append("incoming_images")
            await self._write(protocol.hello("hermes", self._agent, tuple(capabilities)))
            if listed:
                await self._write(protocol.commands(listed))
            for message in self._questions.prepare_replay():
                if not self._questions.can_deliver(message):
                    continue
                reason = protocol.unsendable(message)
                if reason:
                    # Sent again after every hello, it would be refused every time
                    logger.warning("[%s] Outbox: %s cannot be sent (%s); it was set aside",
                                   self.name, message.get("id"), reason)
                    self._outbox.set_aside(str(message.get("id")))
                    continue
                await self._write(protocol.for_bridge(message, self._bridge_task_events))
            await self._questions.fallback_cards()
            # The board is read beside the connection, so the bridge's
            # messages are read meanwhile.
            report = asyncio.create_task(self._reporter.connected())
            self._routine_tasks.add(report)
            report.add_done_callback(self._routine_tasks.discard)
            # The agent's held tasks, the whole list now when the bridge takes
            # them, then on changes.
            self._held.start()
            while True:
                try:
                    line = await lines.read_line(reader)
                except lines.TooLong as e:
                    # Said at once, naming it when its first bytes do, then
                    # the end: no message of the bridge's is this long, so
                    # the connection is not one to go on with
                    # (`docs/protocol.md`, Messages)
                    logger.warning("[%s] The bridge sent a line over 1 MiB; the connection was closed", self.name)
                    await self._write(protocol.error("bad_message", str(e), e.message_id))
                    break
                if not line or not await self._on_line(line):
                    break
        except ConnectionError:
            pass
        except Exception:
            # The runtime did not take a message: the bridge, not acknowledged,
            # sends it again on its next connection
            logger.exception("[%s] A message could not be handed to the runtime; the connection was closed",
                             self.name)
        finally:
            # Only the connection that holds the slot gives it back
            if self._bridge is writer:
                # A message whose bytes did not all come: the bridge sends it again
                self._incoming.drop()
                self._held.stop()
                self._bridge = None
                self._bridge_usage = False
                self._bridge_agent_usage = False
                self._bridge_task_events = False
            writer.close()
            logger.info("[%s] Bridge disconnected", self.name)

    def _adopt_home(self, home: Optional[str]) -> None:
        """Makes the agent's Home conversation, which the bridge names, this
        platform's home channel (ADR 0044): in the running gateway, where its
        notices and `send_message` look, in the environment, where cron looks
        first, and in Hermes's config, as /sethome would, so it holds after a
        restart. What a /sethome set before is replaced."""
        if not home:
            return
        self._routines.home_channel = home
        os.environ["MOBILE_APP_HOME_CHANNEL"] = home
        try:
            from gateway.config import HomeChannel, persist_home_channel
            channel = HomeChannel(platform=self.platform, chat_id=home, name="Home")
            config = getattr(getattr(self, "gateway_runner", None), "config", None)
            if config is not None:
                current = config.platforms.setdefault(self.platform, PlatformConfig(enabled=True))
                stale = getattr(current.home_channel, "chat_id", None) != home
                current.home_channel = channel
                if stale:
                    persist_home_channel(channel)
            if self.config is not None:
                self.config.home_channel = channel
        except Exception:
            # Hermes internals, not a plugin API: when a release moves them,
            # Hermes asks for /sethome again, and this line says why.
            logger.info("[%s] Cannot set Home as the home channel", self.name, exc_info=True)

    async def _write(self, message: dict[str, Any]) -> bool:
        writer = self._bridge
        if writer is None:
            return False
        async with self._lock:
            try:
                writer.write(protocol.encode_line(message))
                await writer.drain()
                return True
            except ConnectionError:
                return False

    async def _on_line(self, line: bytes) -> bool:
        """Acts on one line; False when the connection is to end."""
        try:
            message = protocol.decode_from_bridge(line)
        except protocol.DecodeError as e:
            await self._write(protocol.error(e.code, str(e), e.message_id))
            # A line unread, a bad part or any other, drops the message with files whole
            dropped = self._incoming.drop()
            if dropped is not None:
                await self._write(protocol.error("bad_message", "a line could not be read during its files", dropped))
            # A version this plugin does not speak ends the connection
            # (docs/protocol.md, Errors); any other bad message does not
            return e.code != "version"
        kind = message["type"]
        if kind == "ack":
            self._outbox.acknowledge(message["of"])
            self._questions.acknowledge(message["of"])
            approvals.answered(self._answers, message)
            self._reporter.acknowledged(message["of"])
        elif kind == "policy.context":
            approvals.save_context(self._path, message["text"])
            await self._write(protocol.ack(message["id"]))
        elif kind == "message.in":
            if message.get("files") and message["id"] not in self._seen:
                # Given to the runtime once its files' last byte came
                try:
                    self._incoming.begin(message)
                except incoming.Refused as e:
                    await self._write(protocol.error(e.code, str(e), e.message_id))
            else:
                await self._on_message(message)
        elif kind == "message.part":
            try:
                received = self._incoming.part(message)
            except incoming.Refused as e:
                await self._write(protocol.error(e.code, str(e), e.message_id))
                return True
            if received is not None:
                await self._on_message(received[0], received[1:])
        elif kind == "turn.abort":
            try:
                await self._interrupts.abort(message)
                await self._write(protocol.ack(message["id"]))
            except protocol.DecodeError as e:
                await self._write(protocol.error(e.code, str(e), message["id"]))
        elif kind == "conversation.delete":
            task = asyncio.create_task(conversations.handle(self, message))
            self._routine_tasks.add(task)
            task.add_done_callback(self._routine_tasks.discard)
        elif kind == "conversation.rename":
            await self._rename(message["conversation"], message["title"])
        elif kind == "question.answer":
            await self._questions.answer(message)
        elif kind == "question.sync":
            await self._questions.sync(message["questions"])
            await self._write(protocol.ack(message["id"]))
        elif kind == "routine.request":
            # A routine control can wait on Hermes's cron lock, its model
            # catalogue or its scheduler: it runs beside the connection, so
            # the person's messages and the bridge's acks are read meanwhile.
            task = asyncio.create_task(self._routine(message))
            self._routine_tasks.add(task)
            task.add_done_callback(self._routine_tasks.discard)
        elif kind == "model.request":
            # Hermes's inventory and model check can take a while: beside
            # the connection, as a routine control.
            task = asyncio.create_task(self._model_request(message))
            self._routine_tasks.add(task)
            task.add_done_callback(self._routine_tasks.discard)
        elif kind == "held_task.resume":
            # Hermes's unblock waits on the board's write lock: it runs
            # beside the connection, as a routine control does.
            self._held.track(asyncio.create_task(self._held.resume(message)))
        elif kind == "task.get":
            # A read of every board: beside the connection too.
            task = asyncio.create_task(self._reporter.detail(message))
            self._routine_tasks.add(task)
            task.add_done_callback(self._routine_tasks.discard)
        elif kind == "error":
            approvals.answered(self._answers, message)
            # A task it refused is sent again at the board's next reading.
            self._reporter.refused(message.get("of"))
            logger.warning("[%s] The bridge reported %s: %s", self.name, message["code"], message["message"])
            # A question or runtime approval the bridge refused would wait unseen: a
            # question goes as text, an approval is denied or sent as text.
            await self._questions.refused(message.get("of"), message.get("code"))
            self._held.refused(message.get("of"), message.get("code"))
            of = message.get("of")
            if message["code"] == "bad_message" and of and self._outbox.set_aside(of):
                # The bridge cannot read it: sent again, it would be refused again
                logger.warning("[%s] Outbox: %s was refused by the bridge; it was set aside", self.name, of)
        else:
            await self._write(protocol.error("bad_message", "hello comes once", message["id"]))
        return True

    async def _routine(self, message: dict[str, Any]) -> None:
        """Answers one routine control; the manager serializes them."""
        try:
            result = await asyncio.to_thread(self._routines.handle, message)
            await self._write(protocol._message("routine.response", of=message["id"], **result))
        except routines.RoutineError as error:
            await self._write(protocol.error(error.code, str(error), message["id"]))
        except Exception:
            logger.warning("[%s] A routine control could not answer", self.name, exc_info=True)
            await self._write(protocol.error(
                "unknown", "The operation's outcome is unknown. Refresh before trying again.", message["id"]))

    async def _model_request(self, message: dict[str, Any]) -> None:
        """Answers one request about the agent's model (`model.request`)."""
        try:
            result = await asyncio.to_thread(self._model.handle, message)
            sent = await self._write(protocol._message("model.response", of=message["id"], **result))
            if not sent and result.get("result") == "set":
                # The change is saved; only its confirmation is lost.
                logger.error("[%s] The agent's model was set to %s, but the bridge could not be told",
                             self.name, result.get("current"))
        except model.ModelError as error:
            await self._write(protocol.error(error.code, str(error), message["id"]))
        except Exception:
            logger.error("[%s] A model request could not answer", self.name, exc_info=True)
            await self._write(protocol.error("unknown", model.UNKNOWN, message["id"]))

    async def _on_message(self, message: dict[str, Any], media: Optional[tuple] = None) -> None:
        """Gives the runtime a person's message; `media` is its files' paths in
        the sandbox, their media types and their names, when it has files."""
        if message["id"] in self._seen:
            # The runtime has it: the ack was lost on the way
            await self._write(protocol.ack(message["id"]))
            return
        # enclos keeps the home channel (the agent's Home): /sethome is
        # answered here, not run, which would move it into this conversation.
        if protocol.is_home_command(message["text"]):
            # The bridge refuses files with it; any that came are said to go nowhere
            answer = protocol.HOME_ANSWER + (" The files sent with it were not given to the agent." if media else "")
            await self.send(message["conversation"], answer, reply_to=message["id"])
            await self._write(protocol.ack(message["id"]))
            return
        self._last_in[message["conversation"]] = (message["id"], asyncio.get_running_loop().time())
        source = self.build_source(
            chat_id=message["conversation"], chat_name=message["conversation"], chat_type="dm",
            user_id=message["person"], user_name=message["person"], message_id=message["id"])
        if media and any(t.startswith("image/") for t in media[1]) and not await self._conversation_images_available(source):
            await self._write(protocol.error("unsupported", "This conversation cannot receive images.", message["id"]))
            return
        if media:
            # As Hermes's own platforms hand it media: paths it reads, each with
            # its type, so a photo goes to vision and a document is noted by path
            paths, types, names = media
            kind = MessageType.PHOTO if any(t.startswith("image/") for t in types) else MessageType.DOCUMENT
            event = MessageEvent(
                text=message["text"], message_type=kind, source=source, message_id=message["id"],
                # The bridge supplies no producer timestamp. Native receipts hash
                # this field: use the producer contract's epoch convention so
                # a lost ACK/restart reconstructs the same immutable request.
                raw_message=message, timestamp=datetime.fromtimestamp(0, tz=UTC),
                media_urls=list(paths), media_types=list(types))
            if hasattr(event, "media_filenames"):
                # A newer Hermes shows the person's own names
                event.media_filenames = list(names)
            if hasattr(event, "media_text_inlined"):
                # None of their text is in `text`: unflagged, Hermes says it is
                event.media_text_inlined = [False] * len(paths)
        else:
            event = MessageEvent(
                text=message["text"], message_type=MessageType.TEXT, source=source, message_id=message["id"],
                raw_message=message, timestamp=datetime.now(tz=UTC))
        # Hermes reads its approval commands from whoever it is told speaks, and a
        # message carries no proof of its person: `host` is the bridge's word, which
        # any program with the token can send. So none is passed on, read with
        # Hermes's own parser: runtime approvals are decided with the app's buttons,
        # whose decisions the bridge signs (ADR 0060).
        if runtime_approvals.approval_command(event):
            await self.send(message["conversation"], runtime_approvals.TYPED_ANSWER, reply_to=message["id"])
            await self._write(protocol.ack(message["id"]))
            return
        try:
            self._interrupts.admit(event)
        except protocol.DecodeError as e:
            await self._write(protocol.error(e.code, str(e), message["id"]))
            return
        if media:
            self._incoming.admit(event.media_urls)
        try:
            if media:
                await self._admit_files(event)
            else:
                await self.handle_message(event)
        except FileAdmissionRefused:
            self._interrupts.complete(event)
            await self._write(protocol.error("unsupported", "The files could not be saved for the agent.", message["id"]))
            return
        except BaseException:
            self._interrupts.complete(event)
            raise
        if getattr(event, "_gateway_accepted", True) is False:
            self._interrupts.complete(event)
            if media:
                self._incoming.release(event.media_urls)
        # Only once the runtime has it: if handle_message raised, the bridge
        # sends it again and it must not read as a duplicate
        self._seen[message["id"]] = None
        while len(self._seen) > SEEN_MESSAGES:
            self._seen.popitem(last=False)
        await self._write(protocol.ack(message["id"]))

    def _files_available(self):
        try:
            from gateway.platforms.webhook_ingress import admit_producer
            return callable(admit_producer)
        except ImportError:
            return False

    async def _admit_files(self, event):
        # Receipt ingress captures independent immutable bytes before committing.
        # Handler return alone never establishes consumption of staging paths.
        paths = list(event.media_urls)
        async def admission():
            # Shield the entire capture, including its off-loop worker: cancellation
            # must not make staging collectible while the worker is still reading.
            try:
                from gateway.session_authority import native_write_started
                native_write_started.set(False)
                from gateway.platforms.webhook_ingress import admit_producer
                receipt = await admit_producer(self, event)
            except ImportError as error:
                # Once ingress is called, even an import error can follow a write.
                if 'admit_producer' in locals():
                    raise
                self._incoming.release(paths)
                raise FileAdmissionRefused() from error
            except OSError:
                # Prepared ingress restores its ContextVar on exit. A false
                # marker here cannot prove that a write never started.
                raise
            except Exception as error:
                from importlib.util import find_spec
                if find_spec("persistence_assembly") is not None:
                    from persistence.core.errors import AuthorityRefusal as RuntimeStoreError
                else:
                    from hermes_state_runtime import RuntimeStoreError
                if isinstance(error, RuntimeStoreError) and not native_write_started.get():
                    self._incoming.release(paths)
                    raise FileAdmissionRefused() from error
                # Unknown errors may follow a commit. Retain the diagnostic
                # marker; never announce definite failure.
                raise
            try:
                if receipt is not None:
                    self._incoming.captured(paths, receipt)
                else:
                    self._incoming.release(paths)
            except OSError:
                logger.warning("[%s] Admission completed; staging marker could not be saved", self.name)
            return receipt

        task = asyncio.create_task(admission())
        tasks = getattr(self, "_native_admissions", None)
        if tasks is None:
            tasks = self._native_admissions = set()
        tasks.add(task)
        def finished(done):
            tasks.discard(done)
            if not done.cancelled():
                done.exception()  # observe errors even after the caller disconnects
                self._incoming.admission_ended(paths)
        task.add_done_callback(finished)
        return await asyncio.shield(task)

    async def _conversation_images_available(self, source):
        try:
            from gateway.platforms.webhook_ingress import producer_scope
            from types import SimpleNamespace
            async with producer_scope(self, SimpleNamespace(source=source)):
                return await asyncio.to_thread(self._images_available, source)
        except Exception:
            return False

    def _images_available(self, source=None):
        return image_eligibility.available(self, source)

    def _interrupt_session_key(self, event) -> str:
        from gateway.session import build_session_key
        return build_session_key(event.source, profile=self._session_key_profile(event.source))

    async def on_processing_start(self, event) -> None:
        self._interrupts.start(event)
        native_hook = getattr(super(), "on_processing_start", None)
        if callable(native_hook):
            await native_hook(event)

    async def on_processing_complete(self, event, outcome) -> None:
        self._interrupts.complete(event)
        self._incoming.release(getattr(event, "media_urls", None))
        native_hook = getattr(super(), "on_processing_complete", None)
        if callable(native_hook):
            await native_hook(event, outcome)

    def _routine_runtime(self):
        runner = getattr(self, "gateway_runner", None)
        adapters = {self.platform: self}
        if runner is not None and callable(getattr(runner, "_adapters_for_profile", None)):
            try:
                from hermes_constants import profile_name_for_home
                scoped = runner._adapters_for_profile(profile_name_for_home(self._routines.home))
                if scoped.get(self.platform) is self:
                    adapters = scoped
            except Exception:
                # An older gateway's launch-profile map may name another
                # agent's adapter. App-owned jobs can always use this one.
                logger.debug("[%s] Using this app adapter for routine delivery", self.name)
        return adapters, self._loop

    def _dispatch_routine(self, provider, claimed) -> None:
        future = asyncio.run_coroutine_threadsafe(
            asyncio.to_thread(self._routines.execute, provider, claimed), self._loop)

        def finished(result):
            try:
                result.result()
            except Exception:
                logger.warning("[%s] A native routine worker could not finish", self.name, exc_info=True)

        future.add_done_callback(finished)

    async def send_clarify(self, chat_id, question, choices, clarify_id, session_key, metadata=None):
        saved = await self._questions.ask(chat_id, question, choices, clarify_id, session_key, metadata)
        return SendResult(success=saved, message_id=clarify_id if saved else None,
                          error=None if saved else "The question could not be saved.")

    async def retire_clarify_card(self, clarify_id, notice):
        await self._questions.retire(clarify_id)

    async def _send_exec_approval_prompt(self, prompt):
        saved, question_id = await self._questions.ask_approval(prompt)
        return SendResult(success=saved, message_id=question_id,
                          error=None if saved else "The runtime approval could not be saved.")

    async def send_exec_approval(self, *args, **kwargs):
        # Keep the native visibility/Deny-only flow and old call signatures. Its
        # ordinary full-command pre-send must stay literal and frame-bounded too.
        token = _APPROVAL_SEND.set(True)
        try:
            return await super().send_exec_approval(*args, **kwargs)
        finally:
            _APPROVAL_SEND.reset(token)

    # Files the agent sends. Hermes finds them in a reply (MEDIA:/path tags,
    # bare absolute paths) and calls the method for their kind; each is copied
    # at once into the channel's media folder, beside the socket, where the
    # bridge takes it (Hermes sweeps some of its caches after a day, and the
    # message may wait in the outbox longer).

    MAX_FILE_BYTES = 25 * 1024 * 1024
    # How long after the person's message a file without reply_to still answers it.
    FILES_ANSWER_SECONDS = 600

    def _stage(self, path: str, name: Optional[str] = None) -> Optional[dict[str, Any]]:
        """A copy of the file in the media folder, as an attachment; None if it cannot be sent."""
        try:
            size = os.path.getsize(path)
            if not os.path.isfile(path) or size > self.MAX_FILE_BYTES:
                logger.info("[%s] Not sent: %s is not a file of at most 25 MiB", self.name, path)
                return None
            media = os.path.join(os.path.dirname(self._path), "media")
            os.makedirs(media, mode=0o700, exist_ok=True)
            extension = os.path.splitext(path)[1].lower()[:10]
            file = f"{uuid.uuid4()}{extension}"
            # A new file of the folder, never through a link left there.
            fd = os.open(os.path.join(media, file), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with open(path, "rb") as source, os.fdopen(fd, "wb") as target:
                shutil.copyfileobj(source, target)
            mime = mimetypes.guess_type(path)[0] or "application/octet-stream"
            return protocol.attachment(file, mime, name or os.path.basename(path), size)
        except OSError as e:
            logger.info("[%s] Not sent: %s: %s", self.name, path, e)
            return None

    async def _send_files(self, chat_id: str, paths: list[tuple[str, Optional[str]]], text: str,
                          reply_to: Optional[str]) -> SendResult:
        staged = [(p, n, self._stage(p, n)) for p, n in paths]
        files = [a for _, _, a in staged if a]
        if not files and not text:
            return SendResult(success=False, error="the file could not be sent")
        # The person sees that a file is missing, not only the log.
        text = protocol.with_files_not_sent(
            text, [n or os.path.basename(p) for p, n, a in staged if not a])
        # Hermes delivers a reply's files apart from its text, without saying
        # what they answer: within minutes of the person's message, they answer
        # it; otherwise (a cron job's) they come on their own.
        if reply_to is None and chat_id in self._last_in:
            last, at = self._last_in[chat_id]
            if asyncio.get_running_loop().time() - at < self.FILES_ANSWER_SECONDS:
                reply_to = last
        message = protocol.message_out(chat_id, text, reply_to, files)
        pending_replies = suggested_replies.peek(self, chat_id, reply_to)
        replies = pending_replies.replies if pending_replies else []
        if replies:
            message["suggested_replies"] = replies
        if not self._outbox.put(message):
            return SendResult(success=False, error="too many messages waiting for the bridge")
        suggested_replies.consume(self, chat_id, pending_replies)
        await self._write(message)
        self._check_title_soon(chat_id)
        return SendResult(success=True, message_id=message["id"])

    async def send_image_file(self, chat_id: str, image_path: str, caption: Optional[str] = None,
                              reply_to: Optional[str] = None, metadata: Optional[dict[str, Any]] = None,
                              **kwargs) -> SendResult:
        return await self._send_files(chat_id, [(image_path, None)], caption or "", reply_to)

    async def send_document(self, chat_id: str, file_path: str, caption: Optional[str] = None,
                            file_name: Optional[str] = None, reply_to: Optional[str] = None,
                            metadata: Optional[dict[str, Any]] = None, **kwargs) -> SendResult:
        return await self._send_files(chat_id, [(file_path, file_name)], caption or "", reply_to)

    async def send_video(self, chat_id: str, video_path: str, caption: Optional[str] = None,
                         reply_to: Optional[str] = None, metadata: Optional[dict[str, Any]] = None,
                         **kwargs) -> SendResult:
        return await self._send_files(chat_id, [(video_path, None)], caption or "", reply_to)

    async def send_voice(self, chat_id: str, audio_path: str, caption: Optional[str] = None,
                         reply_to: Optional[str] = None, metadata: Optional[dict[str, Any]] = None,
                         **kwargs) -> SendResult:
        return await self._send_files(chat_id, [(audio_path, None)], caption or "", reply_to)

    def _local_image(self, path: str) -> Optional[str]:
        """A markdown image's file, when it is one Hermes may send: by its path,
        absolute or relative to the agent's Hermes home (where its tools save)."""
        try:
            from hermes_constants import get_hermes_home
            home = str(get_hermes_home())
        except Exception:
            home = os.environ.get("HERMES_HOME", "")
        candidate = path if os.path.isabs(path) else os.path.join(home, path) if home else ""
        if not candidate or os.path.splitext(candidate)[1].lower() not in (".png", ".jpg", ".jpeg", ".webp", ".gif"):
            return None
        safe = self.validate_media_delivery_path(candidate)
        return str(safe) if safe and os.path.isfile(str(safe)) else None

    async def send(
        self, chat_id: str, content: str, reply_to: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> SendResult:
        literal_approval = _APPROVAL_SEND.get() or bool((metadata or {}).get("is_approval_prompt"))
        if not literal_approval and protocol.is_heartbeat(content):
            # Kept back, said sent: the working indicator shows it. No id, so
            # Hermes does not try to edit it and sends the next one here too.
            return SendResult(success=True)
        if literal_approval and len(protocol.encode_line(protocol.message_out(chat_id, content, reply_to))) > questions.MAX_APPROVAL_FRAME_BYTES:
            # Refuse before persistence. Base's visibility gate then keeps Deny
            # alone; our fallback sends complete, independently fenced parts.
            return SendResult(success=False, error="The approval text exceeds one safe message frame.")
        # A local markdown image (`![x](cache/generated/images/y.png)`), which
        # Hermes does not take for a file: sent as one, out of the text.
        # An image Hermes may not send stays in the text, as the agent wrote it.
        sendable: dict[str, str] = {}

        def take(path: str) -> bool:
            found = self._local_image(path)
            if found:
                sendable[path] = found
            return found is not None

        rest, images = (content, []) if literal_approval else protocol.local_images(content, take)
        files = [(sendable[p], None) for _, p in images]
        if files:
            return await self._send_files(chat_id, files, rest, reply_to)
        # Hermes about itself (gateway online, shutting down): a quiet line.
        notice = False if literal_approval else protocol.is_notice(content)
        # Hermes about one of its tasks (its kanban ping): a task line, with
        # the task as the board has it (ADR 0071).
        event = None if literal_approval or notice or reply_to else await self._task_event(chat_id, content)
        message = protocol.message_out(chat_id, content, reply_to, kind="status" if notice else None,
                                       task_event=event)
        notice = notice or event is not None
        pending_replies = None
        if not notice and not literal_approval:
            pending_replies = suggested_replies.peek(self, chat_id, reply_to)
            if pending_replies:
                message["suggested_replies"] = pending_replies.replies
        reason = protocol.unsendable(message)
        if reason:
            # The bridge would refuse it, and kept, it would come first in
            # the outbox after every hello
            logger.warning("[%s] A message for %r was not sent: %s", self.name, chat_id, reason)
            return SendResult(success=False, error=f"the enclos app cannot carry this message: {reason}")
        if not self._outbox.put(message):
            return SendResult(success=False, error="too many messages waiting for the bridge")
        suggested_replies.consume(self, chat_id, pending_replies)
        # If it is not connected, it gets the message on its next hello
        await self._write(protocol.for_bridge(message, self._bridge_task_events))
        if not notice:
            self._check_title_soon(chat_id)
        return SendResult(success=True, message_id=message["id"])

    async def _task_event(self, chat_id: str, content: str) -> Optional[dict[str, Any]]:
        """The task event `content` is, when it is Hermes's kanban ping for a
        task this chat is subscribed to, read from the board off the loop;
        None for the agent's own text, or when the board cannot be read."""
        # Hermes does not mark its pings in `metadata` yet (ADR 0071); a mark
        # would be read here first. Told by their text, read in the language
        # of the context send() runs in (that this is the ping's language is
        # to verify, design §14), and by the board.
        if self._pings is None:
            return None
        try:
            found = task_events.candidates(content)
            if not found:
                return None
            return await asyncio.to_thread(held_tasks._fresh, self._pings.read, chat_id, found)
        except Exception:
            logger.warning("[%s] Cannot tell whether a message is a kanban ping; it is sent as the agent's message",
                           self.name, exc_info=True)
            return None

    # Conversation titles. Hermes names each session (a title cut from the
    # first message at once, then a model's summary about a second later) but
    # tells only its Telegram and Discord adapters when it does: the adapter
    # looks after each reply, and again a little later. What it reads goes
    # through the gateway's session store and database, which are not a
    # plugin API: when they are not there, the conversation has no title.

    # Seconds after a reply to look at the title: at once, and after the
    # model's summary usually lands.
    TITLE_LOOKS = (0, 5, 20)

    def _check_title_soon(self, chat_id: str) -> None:
        pending = self._title_checks.get(chat_id)
        if pending is not None and not pending.done():
            pending.cancel()
        self._title_checks[chat_id] = asyncio.ensure_future(self._look_for_title(chat_id))

    async def _look_for_title(self, chat_id: str) -> None:
        waited = 0
        for at in self.TITLE_LOOKS:
            await asyncio.sleep(at - waited)
            waited = at
            found = await self._session_title(chat_id)
            # The model's summary, or a name the person set in Hermes; not the
            # cut of the first message, which the summary replaces a second later.
            if found is None or found[1] not in ("llm", "user"):
                continue
            title = protocol.runtime_title(found[0])
            if title and title != self._titles.get(chat_id):
                if await self._write(protocol.title(chat_id, title)):
                    self._titles[chat_id] = title

    def _session_id(self, chat_id: str) -> Optional[str]:
        """The Hermes session behind a conversation now: it changes when Hermes
        compresses or resets one, so it is looked up each time."""
        try:
            from gateway.session import build_session_key
            source = self.build_source(chat_id=chat_id, chat_name=chat_id, chat_type="dm")
            self._canonicalize(source)
            key = build_session_key(source, profile=self._session_key_profile(source))
            store = getattr(self, "_session_store", None)
            if store is None:
                self._cannot_read_titles("the gateway has no session store")
                return None
            return store.peek_session_id(key)
        except Exception:
            self._cannot_read_titles(f"no session for {chat_id}")
            return None

    def _cannot_read_titles(self, why: str) -> None:
        """Titles are read through Hermes internals, not a plugin API: the first
        failure is logged at info, so a Hermes release that moves them shows why
        conversations stop getting names; later ones at debug."""
        if not self._title_failure_told:
            self._title_failure_told = True
            logger.info("[%s] Cannot read session titles (%s); conversations keep no name from Hermes", self.name, why, exc_info=True)
        else:
            logger.debug("[%s] Cannot read session titles (%s)", self.name, why, exc_info=True)

    async def _session_db_call(self, method: str, *args: Any) -> Any:
        db = getattr(getattr(self, "gateway_runner", None), "_session_db", None)
        call = getattr(db, method, None) if db is not None else None
        if call is None:
            raise LookupError("no session database")
        result = call(*args)
        return await result if asyncio.iscoroutine(result) else result

    async def _session_title(self, chat_id: str) -> Optional[tuple[str, str]]:
        session_id = self._session_id(chat_id)
        if not session_id:
            return None
        try:
            title = await self._session_db_call("get_session_title", session_id)
            source = await self._session_db_call("get_session_title_source", session_id)
        except Exception:
            self._cannot_read_titles(f"the title of {chat_id}")
            return None
        return (title, source or "") if title else None

    async def _rename(self, chat_id: str, title: str) -> None:
        """The person named the conversation in the app (or cleared its name): the
        session takes it with the person's authority, so Hermes names it no more."""
        self._titles[chat_id] = title
        session_id = self._session_id(chat_id)
        if not session_id:
            return
        try:
            from hermes_state import SessionDB
            await self._session_db_call("set_session_title", session_id, SessionDB.sanitize_title(title) or "")
        except Exception as e:
            # Another session holds that title (Hermes keeps them unique), or no
            # database: the app shows the bridge's name all the same.
            logger.info("[%s] The session keeps its title: %s", self.name, e)

    # Hermes keeps a turn's typing on until the turn ends, which is also what
    # the agent's activity says of the conversation.

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        await self._write(protocol.typing(chat_id, True))
        await self._reporter.answering(chat_id, True)

    async def stop_typing(self, chat_id: str) -> None:
        await self._write(protocol.typing(chat_id, False))
        await self._reporter.answering(chat_id, False)

    async def get_chat_info(self, chat_id: str) -> dict[str, Any]:
        return {"name": chat_id, "type": "dm"}


# The tools the agent runs. Hermes reports a tool's start and end to plugin
# hooks, with its name, arguments, call id and outcome, but not which chat it
# is for: that is the turn's session context, which the hooks run in. Hooks
# fire for every platform, the CLI and cron alike: only this channel's are
# kept. `pre_tool_call` is also a policy hook (a slow or failing one blocks the
# tool), so both only hand the step to the adapter's loop and return None.

def _hermes_commands() -> list[tuple[str, str, str]]:
    """(name, description, args) of the commands a person may type to this gateway: Hermes's
    own that are not for its terminal UI only, then those its plugins register, as its
    gateway's menus (Telegram, Slack) list them. Empty outside a gateway, or on any error."""
    try:
        from hermes_cli.commands import COMMAND_REGISTRY
    except Exception:
        return []
    rows: list[tuple[str, str, str]] = []
    try:
        for cmd in COMMAND_REGISTRY:
            if getattr(cmd, "cli_only", False):
                continue
            describe = getattr(cmd, "describe", None)
            description = describe() if callable(describe) else getattr(cmd, "description", "")
            rows.append((cmd.name, description, getattr(cmd, "args_hint", "")))
    except Exception:
        logger.debug("Cannot read Hermes's commands", exc_info=True)
        return []
    try:
        from hermes_cli.plugins import get_plugin_commands
        for name, meta in (get_plugin_commands() or {}).items():
            if isinstance(name, str) and isinstance(meta, dict):
                rows.append((name, str(meta.get("description") or ""), str(meta.get("args_hint") or "")))
    except Exception:
        logger.debug("Cannot read the plugins' commands", exc_info=True)
    return rows


def _tool_step(phase: str, tool_name: str = "", args: Any = None, tool_call_id: Optional[str] = None,
               status: Optional[str] = None, duration_ms: Any = None, **_: Any) -> None:
    try:
        from gateway.session_context import get_session_env
        if get_session_env("HERMES_SESSION_PLATFORM") != PLATFORM:
            return None
        chat_id = get_session_env("HERMES_SESSION_CHAT_ID")
        # Without the call's id, its end cannot be matched to its start, and
        # the app would show the step running for good: it is not sent.
        if not chat_id or not tool_call_id or not _ADAPTERS:
            return None
        label = None
        if phase == "start":
            from agent.display import build_tool_preview
            label = build_tool_preview(tool_name, args if isinstance(args, dict) else {}, max_len=protocol.MAX_TOOL_LABEL_CHARS)
        message = protocol.tool(
            chat_id, tool_call_id, tool_name, phase, label=label,
            # Hermes says ok, error or blocked (a policy refused it).
            ok=None if phase == "start" else status in (None, "ok"),
            duration_ms=duration_ms if phase == "end" and isinstance(duration_ms, (int, float)) else None)
        # Every connected adapter: the bridge keeps a step only for a
        # conversation of its connection's agent.
        for adapter in list(_ADAPTERS):
            adapter._loop.call_soon_threadsafe(lambda a=adapter: asyncio.ensure_future(a._write(message)))
    except Exception:
        logger.debug("[enclos] A tool step was not passed on", exc_info=True)
    return None


def _board_changed(**_: Any) -> None:
    """A kanban hook, in whichever thread wrote the board: a cue for each
    adapter to read it now. The board, not the hook, says what changed."""
    for adapter in list(_ADAPTERS):
        adapter._loop.call_soon_threadsafe(adapter._reporter.cue)
        adapter._loop.call_soon_threadsafe(adapter._held.poke)
    return None


def _kanban_ticked(**_: Any) -> None:
    """Hermes's kanban dispatcher ticked, in whichever thread runs it: each
    connected adapter reads its held tasks again, on its own loop. A task the
    dispatcher gave up on fires no hook (docs/research/hermes-tasks.md), and a
    worker's block fires its hook in the worker, so this and the held tasks'
    timer are what notice one. Returns at once."""
    for adapter in list(_ADAPTERS):
        try:
            adapter._loop.call_soon_threadsafe(adapter._held.poke)
        except Exception:
            logger.debug("[enclos] A kanban tick was not passed on", exc_info=True)
    return None


def _usage(background: bool, usage: Any = None, model: Any = None, platform: Any = None,
           provider: Any = None, **_: Any) -> None:
    """Passes on what a model call used, from Hermes's `post_api_request`
    (the agent's own calls) or `post_auxiliary_call` (a title, a summary of
    a long context: background). A call of a turn in an app conversation
    goes as `usage`, with its conversation. A call outside the app (a
    routine's run, a talk in the sandbox, another channel's chat) goes as
    `usage.agent`, to the connection of the agent whose home Hermes runs it
    in, when this Hermes can name that agent. An app call whose conversation
    is unknown, as a background call made off the turn's context may be, is
    not sent: it is neither the conversation's nor outside the app, and
    `enclos usage` still counts it from Hermes's records. A failed call
    carries no usage.

    It never fails the turn: what goes wrong is logged, as a warning the
    first time, so that a Hermes whose hooks changed says so once."""
    if not _USAGE_HOOKS:
        return None
    try:
        from gateway.session_context import get_session_env
        if usage is None or not _ADAPTERS:
            return None
        if not isinstance(usage, dict):
            _warn_once("usage", "[enclos] Hermes passed a model call's usage as %s, not a dict: "
                       "the app gets no usage", type(usage).__name__)
            return None
        # Hermes's normalized buckets (`agent/usage_pricing.CanonicalUsage`).
        tokens = {name: usage.get(name + "_tokens") for name in protocol.USAGE_TOKENS}
        model = model if isinstance(model, str) else None
        # The model provider Hermes called, so that the bridge prices the
        # call (`openai-codex`, a subscription, costs nothing in dollars).
        provider = provider if isinstance(provider, str) else None
        platform = get_session_env("HERMES_SESSION_PLATFORM") or platform
        chat_id = get_session_env("HERMES_SESSION_CHAT_ID")
        if platform == PLATFORM:
            if not chat_id:
                return None
            message = protocol.usage(chat_id, tokens, model=model, background=background,
                                     model_provider=provider)
            # Every connected adapter whose bridge takes them: the bridge
            # keeps usage only for a conversation of its connection's agent.
            for adapter in list(_ADAPTERS):
                if getattr(adapter, "_bridge_usage", False):
                    adapter._loop.call_soon_threadsafe(lambda a=adapter: asyncio.ensure_future(a._write(message)))
            return None
        if not _AGENT_USAGE:
            return None
    except Exception:
        _warn_once("app", "[enclos] A model call's usage was not passed on", exc_info=True)
        return None
    try:
        # Outside any app conversation: the agent whose home Hermes runs
        # this call in (one gateway serves every profile), to its own
        # connection alone, as the bridge counts it under that agent.
        agent = _current_agent()
        if agent is None:
            _warn_once("agent", "[enclos] Hermes ran a model call in a home of no agent: "
                       "its usage outside the app is not passed on")
            return None
        message = protocol.agent_usage(tokens, model=model, background=background,
                                       source=platform if isinstance(platform, str) else None,
                                       model_provider=provider)
        for adapter in list(_ADAPTERS):
            if adapter._agent == agent and getattr(adapter, "_bridge_agent_usage", False):
                adapter._loop.call_soon_threadsafe(lambda a=adapter: asyncio.ensure_future(a._write(message)))
    except Exception:
        _warn_once("outside", "[enclos] A model call's usage outside the app was not passed on",
                   exc_info=True)
    return None


def _current_agent() -> Optional[str]:
    """The agent (Hermes profile) a call runs for: the profile owning the
    home Hermes has for it, which a gateway serving several sets per turn."""
    from hermes_constants import get_hermes_home, profile_name_for_home
    return profile_name_for_home(get_hermes_home())


_WARNED: set = set()


def _warn_once(key: str, message: str, *args: Any, exc_info: bool = False) -> None:
    """Warns the first time, then logs at debug: a hook runs at every call."""
    if key in _WARNED:
        logger.debug(message, *args, exc_info=exc_info)
    else:
        _WARNED.add(key)
        logger.warning(message, *args, exc_info=exc_info)


# Whether this Hermes calls the plugin with the agent's model calls
# (`post_api_request`), so that its `hello` names `usage`.
_USAGE_HOOKS = False
# Whether it can also name the agent a call outside the app is for
# (`hermes_constants.profile_name_for_home`), so that its `hello` names
# `agent_usage`.
_AGENT_USAGE = False


def _register_usage_hooks(ctx) -> None:
    """Registers each hook this Hermes has. Hermes takes a hook name it does
    not know with only a warning (`track_hook`), so its list is read first:
    a Hermes without `post_api_request` registers nothing, and its plugin
    does not name `usage`."""
    global _USAGE_HOOKS, _AGENT_USAGE
    try:
        from hermes_constants import get_hermes_home, profile_name_for_home  # noqa: F401
        _AGENT_USAGE = True
    except Exception:
        logger.info("[enclos] This Hermes cannot name a call's agent: the app gets no usage outside it")
    try:
        from hermes_cli.plugins import VALID_HOOKS
    except Exception:
        logger.info("[enclos] This Hermes does not list its hooks: the app gets no usage")
        return
    if "post_api_request" not in VALID_HOOKS:
        logger.info("[enclos] This Hermes has no model call hooks: the app gets no usage")
        return
    try:
        ctx.register_hook("post_api_request", lambda **kwargs: _usage(False, **kwargs))
        _USAGE_HOOKS = True
        if "post_auxiliary_call" in VALID_HOOKS:
            ctx.register_hook("post_auxiliary_call", lambda **kwargs: _usage(True, **kwargs))
    except Exception:
        logger.warning("[enclos] The model call hooks could not be registered", exc_info=True)


def _env_enablement() -> dict | None:
    """On for an agent whose secrets give it a socket and a token."""
    socket_path = _setting(None, "socket", "MOBILE_APP_SOCKET")
    token = _setting(None, "token", "MOBILE_APP_TOKEN")
    if not (socket_path and token):
        return None
    seed: dict[str, Any] = {"socket": socket_path, "token": token}
    home = _setting(None, "home", "MOBILE_APP_HOME_CHANNEL")
    if home:
        seed["home_channel"] = {"chat_id": home, "name": "Home"}
    return seed


def register(ctx) -> None:
    questions.register_skill(ctx)
    suggested_replies.register(ctx, _ADAPTERS, PLATFORM)
    asks.register(ctx, _ADAPTERS, _current_agent)
    approvals.register(ctx, _ADAPTERS, lambda: _setting(None, "socket", "MOBILE_APP_SOCKET"), PLATFORM)
    ctx.register_platform(
        name=PLATFORM, label="enclos app", adapter_factory=lambda cfg: EnclosAdapter(cfg),
        check_fn=check_requirements, validate_config=validate_config,
        required_env=["MOBILE_APP_SOCKET", "MOBILE_APP_TOKEN"],
        install_hint="Set up with `enclos runtime configure <sandbox>/<agent> --channel app` on the host",
        env_enablement_fn=_env_enablement,
        cron_deliver_env_var="MOBILE_APP_HOME_CHANNEL",
        allow_all_env="MOBILE_APP_ALLOW_ALL",
        emoji="📱",
        platform_hint=protocol.PLATFORM_HINT)
    ctx.register_hook("pre_tool_call", lambda **kwargs: _tool_step("start", **kwargs))
    ctx.register_hook("post_tool_call", lambda **kwargs: _tool_step("end", **kwargs))
    try:
        from hermes_cli.plugins import VALID_HOOKS
    except Exception:
        VALID_HOOKS = ()
    for hook in tasks.HOOKS:
        # A Hermes without the board, or an older one, has not these hooks.
        if hook in VALID_HOOKS:
            ctx.register_hook(hook, _board_changed)
    if "on_kanban_dispatch_tick" in VALID_HOOKS:
        ctx.register_hook("on_kanban_dispatch_tick", _kanban_ticked)
    else:
        logger.info("[enclos] This Hermes has no kanban dispatch hook; held tasks are read on a timer only")
    # Every turn that may write a task gets it, wherever Hermes runs it: the
    # gateway's conversations, its cron runs and its board's tasks alike. Only
    # where tasks are on, for this process's own profile, as the adapter checks.
    if "pre_llm_call" in VALID_HOOKS and tasks.has_board(conversations.capture_home()):
        ctx.register_hook("pre_llm_call", tasks.writing_context)
        # And how to hand a held task to the person (ADR 0073).
        ctx.register_hook("pre_llm_call", asks.context)
    _register_usage_hooks(ctx)
