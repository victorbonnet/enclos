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
import logging
import os
import socket
from datetime import UTC, datetime
from typing import Any, Optional

from gateway.config import Platform, PlatformConfig
from gateway.platforms._shared import get_scoped_secret
from gateway.platforms.base import BasePlatformAdapter, SendResult
from gateway.platforms.event import MessageEvent, MessageType

from . import protocol
from .outbox import Outbox

logger = logging.getLogger(__name__)

PLATFORM = "enclos"
HELLO_TIMEOUT_SECONDS = 10
# The bridge sends a message again, with its id, until it has the ack: the
# ids of the last ones the runtime had, to drop one that comes again
SEEN_MESSAGES = 1024


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
        # Whether a failure to read a session's title was logged at info already.
        self._title_failure_told = False
        self._seen: collections.OrderedDict[str, None] = collections.OrderedDict()

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
            # A line may hold a whole protocol message and its line break;
            # asyncio's default limit (64 KiB) would end the connection on
            # an ordinary long message
            self._server = await asyncio.start_unix_server(
                self._on_connection, sock=listener, limit=protocol.MAX_MESSAGE_BYTES + 1)
        except OSError as e:
            logger.error("[%s] Cannot listen on %s: %s", self.name, self._path, e)
            return False
        self._mark_connected()
        self._wire_plugin_handlers(None)
        logger.info("[%s] Listening for the bridge", self.name)
        return True

    async def disconnect(self) -> None:
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
        try:
            await self._write(protocol.hello("hermes", self._agent))
            for message in self._outbox.pending():
                reason = protocol.unsendable(message)
                if reason:
                    # Sent again after every hello, it would be refused every time
                    logger.warning("[%s] Outbox: %s cannot be sent (%s); it was set aside",
                                   self.name, message.get("id"), reason)
                    self._outbox.set_aside(str(message.get("id")))
                    continue
                await self._write(message)
            while True:
                try:
                    line = await reader.readline()
                except ValueError:
                    # A line past the protocol's limit: no message of the
                    # bridge's is, so the connection is not one to go on with
                    logger.warning("[%s] The bridge sent a line over 1 MiB; the connection was closed", self.name)
                    await self._write(protocol.error("bad_message", "larger than 1 MiB", None))
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
                self._bridge = None
            writer.close()
            logger.info("[%s] Bridge disconnected", self.name)

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
            # A version this plugin does not speak ends the connection
            # (docs/protocol.md, Errors); any other bad message does not
            return e.code != "version"
        kind = message["type"]
        if kind == "ack":
            self._outbox.acknowledge(message["of"])
        elif kind == "message.in":
            await self._on_message(message)
        elif kind == "conversation.rename":
            await self._rename(message["conversation"], message["title"])
        elif kind == "error":
            logger.warning("[%s] The bridge reported %s: %s", self.name, message["code"], message["message"])
            of = message.get("of")
            if message["code"] == "bad_message" and of and self._outbox.set_aside(of):
                # The bridge cannot read it: sent again, it would be refused again
                logger.warning("[%s] Outbox: %s was refused by the bridge; it was set aside", self.name, of)
        else:
            await self._write(protocol.error("bad_message", "hello comes once", message["id"]))
        return True

    async def _on_message(self, message: dict[str, Any]) -> None:
        if message["id"] in self._seen:
            # The runtime has it: the ack was lost on the way
            await self._write(protocol.ack(message["id"]))
            return
        source = self.build_source(
            chat_id=message["conversation"], chat_name=message["conversation"], chat_type="dm",
            user_id=message["person"], user_name=message["person"], message_id=message["id"])
        await self.handle_message(MessageEvent(
            text=message["text"], message_type=MessageType.TEXT, source=source, message_id=message["id"],
            raw_message=message, timestamp=datetime.now(tz=UTC)))
        # Only once the runtime has it: if handle_message raised, the bridge
        # sends it again and it must not read as a duplicate
        self._seen[message["id"]] = None
        while len(self._seen) > SEEN_MESSAGES:
            self._seen.popitem(last=False)
        await self._write(protocol.ack(message["id"]))

    async def send(
        self, chat_id: str, content: str, reply_to: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> SendResult:
        message = protocol.message_out(chat_id, content, reply_to)
        reason = protocol.unsendable(message)
        if reason:
            # The bridge would refuse it, and kept, it would come first in
            # the outbox after every hello
            logger.warning("[%s] A message for %r was not sent: %s", self.name, chat_id, reason)
            return SendResult(success=False, error=f"the enclos app cannot carry this message: {reason}")
        if not self._outbox.put(message):
            return SendResult(success=False, error="too many messages waiting for the bridge")
        await self._write(message)  # if it is not connected, it gets the message on its next hello
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

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        await self._write(protocol.typing(chat_id, True))

    async def stop_typing(self, chat_id: str) -> None:
        await self._write(protocol.typing(chat_id, False))

    async def get_chat_info(self, chat_id: str) -> dict[str, Any]:
        return {"name": chat_id, "type": "dm"}


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
