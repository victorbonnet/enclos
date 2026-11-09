"""The Hermes side of enclos's channel: a gateway platform adapter.

It listens on MOBILE_APP_SOCKET, a Unix socket in the sandbox home, for
enclos's bridge, which must open with a `hello` holding the agent's token
(MOBILE_APP_TOKEN, granted to this agent alone). Each conversation is a
Hermes chat, so a cron job created in one delivers back to it. What the
agent says is kept on disk until the bridge acknowledges it.

The bridge decides who may talk to the agent (docs/protocol.md), so every
person it names is accepted here: `register` sets the allow-all switch to
this channel's own variable, which `enclos runtime configure` turns on.
"""

import asyncio
import contextvars
import logging
import mimetypes
import os
import shutil
import uuid
from datetime import UTC, datetime
from typing import Any, Optional

from gateway.config import Platform, PlatformConfig
from gateway.platforms._shared import get_scoped_secret
from gateway.platforms.base import BasePlatformAdapter, SendResult
from gateway.platforms.event import MessageEvent, MessageType

from . import protocol
from .outbox import Outbox
from . import approvals
from . import routines
from . import questions
from . import interrupts

logger = logging.getLogger(__name__)

PLATFORM = "enclos"
HELLO_TIMEOUT_SECONDS = 10
_APPROVAL_SEND = contextvars.ContextVar("enclos_runtime_approval_send", default=False)

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


class EnclosAdapter(BasePlatformAdapter):
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
        self._lock = asyncio.Lock()
        # By conversation: the title last sent to the bridge, and the pending look.
        self._titles: dict[str, str] = {}
        self._title_checks: dict[str, asyncio.Task] = {}
        # By conversation: the person's last message, and when it came, so a
        # file Hermes delivers after a reply (with no reply_to) answers it too.
        self._last_in: dict[str, tuple[str, float]] = {}
        self._routines = routines.Manager(self._path)
        self._routines.dispatch = self._dispatch_routine
        self._routines.runtime = self._routine_runtime
        self._questions = questions.Manager(self)
        self._interrupts = interrupts.Manager(self, self._interrupt_session_key,
            lifecycle=all(callable(getattr(BasePlatformAdapter, hook, None))
                          for hook in ("on_processing_start", "on_processing_complete")))

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        if not (self._path and self._token):
            logger.warning("[%s] MOBILE_APP_SOCKET or MOBILE_APP_TOKEN not set", self.name)
            return False
        try:
            os.makedirs(os.path.dirname(self._path), mode=0o700, exist_ok=True)
            if os.path.exists(self._path):
                os.unlink(self._path)
            self._server = await asyncio.start_unix_server(self._on_connection, path=self._path)
            os.chmod(self._path, 0o600)
        except OSError as e:
            logger.error("[%s] Cannot listen on %s: %s", self.name, self._path, e)
            return False
        self._mark_connected()
        self._loop = asyncio.get_running_loop()
        _ADAPTERS.add(self)
        self._wire_plugin_handlers(None)
        logger.info("[%s] Listening for the bridge", self.name)
        return True

    async def disconnect(self) -> None:
        _ADAPTERS.discard(self)
        self._interrupts.close()
        await self._questions.close()
        self._mark_disconnected()
        if self._bridge:
            self._bridge.close()
            self._bridge = None
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
        except (asyncio.TimeoutError, protocol.DecodeError, ConnectionError):
            writer.close()
            return
        if hello["type"] != "hello" or not protocol.token_matches(hello.get("token"), self._token):
            logger.warning("[%s] A connection without the agent's token was closed", self.name)
            writer.close()
            return
        self._bridge = writer
        logger.info("[%s] Bridge connected", self.name)
        self._adopt_home(hello.get("home"))
        self._questions.bridge_supports = "questions" in hello.get("capabilities", [])
        self._questions.bridge_runtime_supports = "runtime_approvals" in hello.get("capabilities", [])
        try:
            listed = _hermes_commands()
            capabilities = ["commands"] if listed else []
            if self._routines.available:
                capabilities.append("routines")
            if self._questions.available:
                capabilities.append("questions")
            if self._questions.approvals_available:
                capabilities.append("runtime_approvals")
            if self._interrupts.available:
                capabilities.append("abort")
            await self._write(protocol.hello("hermes", self._agent, tuple(capabilities)))
            if listed:
                await self._write(protocol.commands(listed))
            for message in self._questions.prepare_replay():
                if not self._questions.can_deliver(message):
                    continue
                await self._write(message)
            await self._questions.fallback_cards()
            while line := await reader.readline():
                await self._on_line(line)
        except ConnectionError:
            pass
        finally:
            self._bridge = None
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
            logger.debug("[%s] Cannot set Home as the home channel", self.name, exc_info=True)

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

    async def _on_line(self, line: bytes) -> None:
        try:
            message = protocol.decode_from_bridge(line)
        except protocol.DecodeError as e:
            await self._write(protocol.error(e.code, str(e), e.message_id))
            return
        kind = message["type"]
        if kind == "ack":
            self._outbox.acknowledge(message["of"])
            self._questions.acknowledge(message["of"])
        elif kind == "policy.context":
            approvals.save_context(self._path, message["text"])
            await self._write(protocol.ack(message["id"]))
        elif kind == "message.in":
            await self._on_message(message)
        elif kind == "turn.abort":
            try:
                await self._interrupts.abort(message)
                await self._write(protocol.ack(message["id"]))
            except protocol.DecodeError as e:
                await self._write(protocol.error(e.code, str(e), message["id"]))
        elif kind == "conversation.rename":
            await self._rename(message["conversation"], message["title"])
        elif kind == "question.answer":
            await self._questions.answer(message)
        elif kind == "question.sync":
            await self._questions.sync(message["questions"])
            await self._write(protocol.ack(message["id"]))
        elif kind == "routine.request":
            try:
                result = await asyncio.to_thread(self._routines.handle, message)
                await self._write(protocol._message("routine.response", of=message["id"], **result))
            except routines.RoutineError as error:
                await self._write(protocol.error(error.code, str(error), message["id"]))
        elif kind == "error":
            logger.warning("[%s] The bridge reported %s: %s", self.name, message["code"], message["message"])
        else:
            await self._write(protocol.error("bad_message", "hello comes once", message["id"]))

    async def _on_message(self, message: dict[str, Any]) -> None:
        # enclos keeps the home channel (the agent's Home): /sethome is
        # answered here, not run, which would move it into this conversation.
        if protocol.is_home_command(message["text"]):
            await self.send(message["conversation"], protocol.HOME_ANSWER, reply_to=message["id"])
            await self._write(protocol.ack(message["id"]))
            return
        self._last_in[message["conversation"]] = (message["id"], asyncio.get_running_loop().time())
        source = self.build_source(
            chat_id=message["conversation"], chat_name=message["conversation"], chat_type="dm",
            user_id=message["person"], user_name=message["person"], message_id=message["id"])
        event = MessageEvent(
            text=message["text"], message_type=MessageType.TEXT, source=source, message_id=message["id"],
            raw_message=message, timestamp=datetime.now(tz=UTC))
        try:
            self._interrupts.admit(event)
        except protocol.DecodeError as e:
            await self._write(protocol.error(e.code, str(e), message["id"]))
            return
        try:
            await self.handle_message(event)
        except BaseException:
            self._interrupts.complete(event)
            raise
        if getattr(event, "_gateway_accepted", True) is False:
            self._interrupts.complete(event)
        await self._write(protocol.ack(message["id"]))

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
        files = [a for a in (self._stage(p, n) for p, n in paths) if a]
        if not files and not text:
            return SendResult(success=False, error="the file could not be sent")
        # Hermes delivers a reply's files apart from its text, without saying
        # what they answer: within minutes of the person's message, they answer
        # it; otherwise (a cron job's) they come on their own.
        if reply_to is None and chat_id in self._last_in:
            last, at = self._last_in[chat_id]
            if asyncio.get_running_loop().time() - at < self.FILES_ANSWER_SECONDS:
                reply_to = last
        message = protocol.message_out(chat_id, text, reply_to, files)
        if not self._outbox.put(message):
            return SendResult(success=False, error="too many messages waiting for the bridge")
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
        if literal_approval and len(protocol.encode_line(protocol.message_out(chat_id, content, reply_to))) > questions.MAX_APPROVAL_FRAME_BYTES:
            # Refuse before persistence. Base's visibility gate then keeps Deny
            # alone; our fallback sends complete, independently fenced parts.
            return SendResult(success=False, error="The approval text exceeds one safe message frame.")
        # A local markdown image (`![x](cache/generated/images/y.png)`), which
        # Hermes does not take for a file: sent as one, out of the text.
        rest, images = (content, []) if literal_approval else protocol.local_images(content)
        files = [(found, None) for found in (self._local_image(p) for _, p in images) if found]
        if files:
            return await self._send_files(chat_id, files, rest, reply_to)
        # Hermes about itself (gateway online, shutting down): a quiet line.
        notice = False if literal_approval else protocol.is_notice(content)
        message = protocol.message_out(chat_id, content, reply_to, kind="status" if notice else None)
        if not self._outbox.put(message):
            return SendResult(success=False, error="too many messages waiting for the bridge")
        await self._write(message)  # if it is not connected, it gets the message on its next hello
        if not notice:
            self._check_title_soon(chat_id)
        return SendResult(success=True, message_id=message["id"])

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
            return store.peek_session_id(key) if store is not None else None
        except Exception:
            logger.debug("[%s] No session for %s", self.name, chat_id, exc_info=True)
            return None

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
            logger.debug("[%s] Cannot read the title of %s", self.name, chat_id, exc_info=True)
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

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        await self._write(protocol.typing(chat_id, True))

    async def stop_typing(self, chat_id: str) -> None:
        await self._write(protocol.typing(chat_id, False))

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
        if not chat_id or not _ADAPTERS:
            return None
        label = None
        if phase == "start":
            from agent.display import build_tool_preview
            label = build_tool_preview(tool_name, args if isinstance(args, dict) else {}, max_len=protocol.MAX_TOOL_LABEL_CHARS)
        message = protocol.tool(
            chat_id, tool_call_id or f"{tool_name}-{id(args)}", tool_name, phase, label=label,
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
    approvals.register(ctx, _ADAPTERS, lambda: _setting(None, "socket", "MOBILE_APP_SOCKET"))
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
