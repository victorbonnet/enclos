"""The plugin leg of enclos's protocol (docs/protocol.md), standard library only.

The same rules as the `enclos-protocol` crate: every message is one JSON
object on one line with `v`, `id` and `type`; unknown fields are ignored;
an unknown `type` is told apart from a known one with bad fields.
"""

import hmac
import json
import re
import uuid
from typing import Any

VERSION = 1
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_ID_BYTES = 128

FROM_BRIDGE_TYPES = ("hello", "message.in", "conversation.rename", "ack", "error")
CAPABILITIES = ("notify", "typing", "titles", "tools")
# The longest label of a tool step: a line on a phone.
MAX_TOOL_LABEL_CHARS = 120
# The longest conversation title sent (Hermes' own limit is 100 characters).
MAX_TITLE_CHARS = 100

# What the runtime tells the agent about this channel, in its system prompt
# (Hermes: the platform's `platform_hint`): where the person is, and what the
# app draws of the markdown it writes ("What the agent says is markdown" in
# docs/protocol.md). Short, as it is in every prompt; it changes when the
# app's list does.
PLATFORM_HINT = (
    "You are talking with the user through the enclos mobile app, on their phone. "
    "Markdown renders: bold, italic, strikethrough, inline code, headings, lists, quotes, "
    "fenced code blocks, tables and links. Use it when it makes a reply easier to read "
    "on a phone screen, and keep tables narrow. A single newline is a line break. "
    "To send an image or a file, write MEDIA:/absolute/path/to/file on its own line: an image "
    "shows in the conversation, another file as an attachment, and the person can share either. "
    "A remote image in markdown is not loaded: an image shows as its alt text, a link to it, and "
    "HTML shows as literal text."
)


HOME_COMMANDS = ("/sethome", "/set-home")
# The answer to /sethome: enclos keeps the agent's home channel (ADR 0044).
HOME_ANSWER = (
    "In the enclos app, this agent's home channel is its **Home** conversation, which enclos "
    "keeps: cron jobs that belong to no conversation, messages with no other place to go, and "
    "Hermes's own notices land there. There is nothing to set."
)

# Hermes's notices about itself (gateway online, shutting down, restarting,
# no home channel), by their keys in its translations, sent as `status`:
# Hermes marks them as such for Discord only, so they are told by their
# text, in the gateway's own language.
NOTICE_KEYS = (
    "gateway.startup.online",
    "gateway.shutdown.notice_shutdown",
    "gateway.shutdown.notice_restart",
    "gateway.restart.restarting",
    "gateway.notify.no_home_channel",
)
# Their English beginnings, for when Hermes's translations cannot be read.
NOTICE_STARTS = (
    "♻️ Gateway online",
    "⚠️ Hermes is shutting down",
    "⚠️ Hermes is restarting",
    "♻ Restarting gateway",
    "📬 No home channel is set",
)
_notice_starts: tuple[str, ...] | None = None


def _translated_starts() -> list[str]:
    """Each notice's text up to its first placeholder, from Hermes's `t`."""
    try:
        from agent.i18n import t  # Hermes's; absent outside the gateway
    except Exception:
        return []
    mark = "\x00"
    starts = []
    for key in NOTICE_KEYS:
        try:
            text = t(key, platform=mark, sethome_cmd=mark, name=mark, chat_id=mark)
        except Exception:
            continue
        start = str(text).split(mark)[0].strip()
        if len(start) >= 8 and start != key:
            starts.append(start)
    return starts


def is_notice(text: str) -> bool:
    """Whether `text` is one of Hermes's notices about itself."""
    global _notice_starts
    if _notice_starts is None:
        _notice_starts = tuple(dict.fromkeys([*_translated_starts(), *NOTICE_STARTS]))
    stripped = text.strip()
    return any(stripped.startswith(start) for start in _notice_starts)


def is_home_command(text: str) -> bool:
    """Whether the person's `text` is `/sethome` (or `/set-home`), with or without arguments."""
    words = text.strip().split()
    return bool(words) and words[0].lower() in HOME_COMMANDS


class DecodeError(Exception):
    """Why a line is not a message to act on. `code` is the protocol's."""

    def __init__(self, code: str, reason: str, message_id: str | None = None):
        super().__init__(reason)
        self.code = code
        self.message_id = message_id


def new_id() -> str:
    return str(uuid.uuid4())


def _check_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} is missing or empty")
    if len(value.encode("utf-8")) > MAX_ID_BYTES:
        raise ValueError(f"{field} is longer than {MAX_ID_BYTES} bytes")
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in value):
        raise ValueError(f"{field} holds a control character")
    return value


def _check_text(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} is not a string")
    return value


def _check_line(value: Any, field: str) -> str:
    """Text for people that the host may print: no control character."""
    _check_text(value, field)
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in value):
        raise ValueError(f"{field} holds a control character")
    return value


def decode_from_bridge(line: bytes) -> dict[str, Any]:
    """One message the bridge sent, checked; raises DecodeError."""
    if len(line) > MAX_MESSAGE_BYTES:
        raise DecodeError("bad_message", "larger than 1 MiB")
    try:
        message = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise DecodeError("bad_message", f"not JSON: {e}") from None
    except RecursionError:
        raise DecodeError("bad_message", "nested too deep") from None
    if not isinstance(message, dict):
        raise DecodeError("bad_message", "not a JSON object")
    raw_id = message.get("id") if isinstance(message.get("id"), str) else None
    if message.get("v") != VERSION:
        if isinstance(message.get("v"), int):
            raise DecodeError("version", f"version {message['v']} is not spoken here", raw_id)
        raise DecodeError("bad_message", "no version", raw_id)
    kind = message.get("type")
    if not isinstance(kind, str):
        raise DecodeError("bad_message", "no type", raw_id)
    if kind not in FROM_BRIDGE_TYPES:
        raise DecodeError("unknown_type", f"unknown type {kind!r}", raw_id)
    try:
        _check_id(message.get("id"), "id")
        if kind == "hello":
            _check_text(message.get("token"), "token")
            if message.get("home") is not None:
                _check_id(message.get("home"), "home")
        elif kind == "message.in":
            _check_id(message.get("conversation"), "conversation")
            _check_id(message.get("person"), "person")
            _check_text(message.get("text"), "text")
        elif kind == "conversation.rename":
            _check_id(message.get("conversation"), "conversation")
            _check_text(message.get("title"), "title")
        elif kind == "ack":
            _check_id(message.get("of"), "of")
        elif kind == "error":
            _check_text(message.get("code"), "code")
            _check_line(message.get("message"), "message")
            if message.get("of") is not None:
                _check_id(message.get("of"), "of")
    except ValueError as e:
        raise DecodeError("bad_message", str(e), raw_id) from None
    return message


def unsendable(message: dict[str, Any]) -> str | None:
    """Why the bridge would refuse this message of the plugin's, or None.

    The bridge's decoder refuses a conversation or id that breaks the id
    rule and a line over 1 MiB; such a message, kept in the outbox, would
    be sent again after every hello and refused every time.
    """
    try:
        _check_id(message.get("id"), "id")
        for field in ("conversation", "reply_to"):
            if message.get(field) is not None:
                _check_id(message.get(field), field)
    except ValueError as e:
        return str(e)
    if len(encode_line(message)) > MAX_MESSAGE_BYTES + 1:
        return "larger than 1 MiB"
    return None


def token_matches(presented: Any, expected: str) -> bool:
    """Constant-time; an empty expected token never matches."""
    if not expected or not isinstance(presented, str):
        return False
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def encode_line(message: dict[str, Any]) -> bytes:
    """Compact JSON and a line break; json.dumps escapes every line break inside."""
    return (json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _message(message_type: str, /, **fields: Any) -> dict[str, Any]:
    return {"v": VERSION, "id": new_id(), "type": message_type, **fields}


def hello(runtime: str, agent: str) -> dict[str, Any]:
    return _message("hello", runtime=runtime, agent=agent, capabilities=list(CAPABILITIES))


def message_out(conversation: str, text: str, reply_to: str | None = None,
                attachments: list[dict[str, Any]] | None = None,
                kind: str | None = None) -> dict[str, Any]:
    """A reply when it answers a message, `notify` otherwise (a cron job, background work),
    or the `kind` given (`status`: the runtime about itself); with the files it carries,
    each already in the channel's media folder (`attachment`)."""
    fields: dict[str, Any] = {"conversation": conversation, "text": text,
                              "kind": kind or ("reply" if reply_to else "notify")}
    if reply_to:
        fields["reply_to"] = reply_to
    if attachments:
        fields["attachments"] = attachments
    return _message("message.out", **fields)


def attachment(file: str, mime: str, name: str, size: int) -> dict[str, Any]:
    """A file of the media folder, by its name there, for message_out."""
    return {"file": file, "mime": mime, "name": name, "size": size}


# A markdown image whose source is not a web address: a file the agent made,
# by its path (`![Unicorn](cache/generated/images/x.png)`).
LOCAL_IMAGE = re.compile(r"!\[([^\]]*)\]\((?!https?://)([^)\s]+)\)")


def local_images(text: str) -> tuple[str, list[tuple[str, str]]]:
    """The text without its local markdown images, and each one's (alt, path)."""
    found = [(m.group(1), m.group(2)) for m in LOCAL_IMAGE.finditer(text)]
    rest = LOCAL_IMAGE.sub("", text)
    return re.sub(r"\n{3,}", "\n\n", rest).strip(), found


def typing(conversation: str, on: bool) -> dict[str, Any]:
    return _message("typing", conversation=conversation, on=on)


def title(conversation: str, text: str) -> dict[str, Any]:
    """The runtime's name for a conversation, on one line, at most MAX_TITLE_CHARS."""
    one_line = " ".join(text.split())[:MAX_TITLE_CHARS]
    return _message("conversation.title", conversation=conversation, title=one_line)


def tool(conversation: str, call: str, name: str, phase: str, label: str | None = None,
         ok: bool | None = None, duration_ms: int | None = None) -> dict[str, Any]:
    """A tool the agent starts (`phase` "start", with what it does as `label`)
    or ends ("end", with whether it worked and how long it took)."""
    fields: dict[str, Any] = {"conversation": conversation, "call": call, "name": name, "phase": phase}
    if label:
        fields["label"] = " ".join(label.split())[:MAX_TOOL_LABEL_CHARS]
    if ok is not None:
        fields["ok"] = ok
    if duration_ms is not None:
        fields["duration_ms"] = max(0, int(duration_ms))
    return _message("tool", **fields)


def runtime_title(text: str) -> str:
    """A Hermes session title as the app should show it: without the ` #2`
    Hermes adds to keep its titles unique, which says nothing to the person."""
    return re.sub(r"\s+#\d+$", "", " ".join(text.split()))


def ack(of: str) -> dict[str, Any]:
    return _message("ack", of=of)


def error(code: str, text: str, of: str | None = None) -> dict[str, Any]:
    fields: dict[str, Any] = {"code": code, "message": text}
    if of:
        fields["of"] = of
    return _message("error", **fields)
