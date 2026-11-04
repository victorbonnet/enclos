"""Prototype enclos channel for Hermes (enclos prototype/m4). Not enclos code.

Listens on a Unix socket (ENCLOS_SOCKET, normally in the sandbox home). The
host's bridge connects and exchanges one JSON object per line:

  bridge -> agent  {"type": "message.in", "conversation": "<id>", "person": "<id>", "text": "..."}
  agent -> bridge  {"type": "message.out", "conversation": "<id>", "text": "..."}

A conversation id is the Hermes chat id, so a new id starts a new session, and
a cron job created in a conversation remembers it as its origin.

Prototype gaps, on purpose: no token (anything that can reach the socket can
talk to the agent), no queue while no bridge is connected (a reply is
dropped), no attachments, no typing indicator.
"""

import asyncio
import json
import logging
import os
import uuid
from datetime import UTC, datetime
from typing import Any, Optional

from gateway.config import Platform, PlatformConfig
from gateway.platforms._shared import get_scoped_secret
from gateway.platforms.base import BasePlatformAdapter, SendResult
from gateway.platforms.event import MessageEvent, MessageType

logger = logging.getLogger(__name__)

PLATFORM = "enclos"


def _socket_path(config: Optional[PlatformConfig] = None) -> str:
    extra = (getattr(config, "extra", None) or {}) if config else {}
    return (extra.get("socket") or get_scoped_secret("ENCLOS_SOCKET", "")).strip()


def check_requirements() -> bool:
    """Standard library only: available wherever a socket path is set."""
    return bool(_socket_path())


def validate_config(config) -> bool:
    return bool(_socket_path(config))


class EnclosAdapter(BasePlatformAdapter):
    """Unix socket in, the same socket out."""

    def __init__(self, config: PlatformConfig):
        super().__init__(config=config, platform=Platform(PLATFORM))
        self._path = _socket_path(config)
        self._server: Optional[asyncio.base_events.Server] = None
        self._writers: set[asyncio.StreamWriter] = set()

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        if not self._path:
            logger.warning("[%s] ENCLOS_SOCKET not set", self.name)
            return False
        try:
            os.makedirs(os.path.dirname(self._path), mode=0o700, exist_ok=True)
            if os.path.exists(self._path):
                os.unlink(self._path)  # left by a gateway that did not stop cleanly
            self._server = await asyncio.start_unix_server(self._on_client, path=self._path)
            os.chmod(self._path, 0o600)
        except OSError as e:
            # The answer to the prototype's first question shows here
            logger.error("[%s] Cannot listen on %s: %s", self.name, self._path, e)
            return False
        self._mark_connected()
        self._wire_plugin_handlers(None)
        logger.info("[%s] Listening on %s", self.name, self._path)
        return True

    async def disconnect(self) -> None:
        self._mark_disconnected()
        for writer in list(self._writers):
            writer.close()
        self._writers.clear()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self._path and os.path.exists(self._path):
            os.unlink(self._path)
        logger.info("[%s] Disconnected", self.name)

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        logger.info("[%s] Bridge connected", self.name)
        try:
            while line := await reader.readline():
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug("[%s] Not JSON, ignored", self.name)
                    continue
                if isinstance(msg, dict) and msg.get("type") == "message.in":
                    await self._on_message(msg)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            self._writers.discard(writer)
            writer.close()
            logger.info("[%s] Bridge disconnected", self.name)

    async def _on_message(self, msg: dict[str, Any]) -> None:
        conversation = str(msg.get("conversation") or "").strip()
        text = str(msg.get("text") or "").strip()
        if not conversation or not text:
            return
        person = str(msg.get("person") or "owner").strip()
        message_id = str(msg.get("id") or uuid.uuid4().hex)
        source = self.build_source(
            chat_id=conversation, chat_name=conversation, chat_type="dm",
            user_id=person, user_name=person, message_id=message_id)
        await self.handle_message(MessageEvent(
            text=text, message_type=MessageType.TEXT, source=source, message_id=message_id,
            raw_message=msg, timestamp=datetime.now(tz=UTC)))

    async def send(
        self, chat_id: str, content: str, reply_to: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> SendResult:
        if not self._writers:
            # A real plugin queues this on disk until the bridge connects
            logger.warning("[%s] No bridge connected; reply to %s dropped", self.name, chat_id)
            return SendResult(success=False, error="no bridge connected")
        message_id = uuid.uuid4().hex
        line = json.dumps({
            "type": "message.out", "id": message_id, "conversation": chat_id, "text": content,
            "reply_to": reply_to,
        }) + "\n"
        for writer in list(self._writers):
            try:
                writer.write(line.encode("utf-8"))
                await writer.drain()
            except ConnectionError:
                self._writers.discard(writer)
        return SendResult(success=True, message_id=message_id)

    async def get_chat_info(self, chat_id: str) -> dict[str, Any]:
        return {"name": chat_id, "type": "dm"}


def _env_enablement() -> dict | None:
    """The channel is on for an agent whose secrets set ENCLOS_SOCKET."""
    path = _socket_path()
    if not path:
        return None
    seed: dict[str, Any] = {"socket": path}
    home = get_scoped_secret("ENCLOS_HOME_CHANNEL", "").strip()
    if home:
        seed["home_channel"] = {"chat_id": home, "name": "Home"}
    return seed


def register(ctx) -> None:
    ctx.register_platform(
        name=PLATFORM, label="enclos app", adapter_factory=lambda cfg: EnclosAdapter(cfg),
        check_fn=check_requirements, validate_config=validate_config,
        required_env=["ENCLOS_SOCKET"], install_hint="Prototype: set ENCLOS_SOCKET",
        env_enablement_fn=_env_enablement,
        cron_deliver_env_var="ENCLOS_HOME_CHANNEL",
        allow_all_env="ENCLOS_ALLOW_ALL_USERS",
        emoji="📱",
        platform_hint="You are talking with the user through the enclos mobile app.")
