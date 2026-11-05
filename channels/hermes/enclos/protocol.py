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
    "Images are not shown (an image link shows as its alt text) and HTML shows as literal text."
)


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


def decode_from_bridge(line: bytes) -> dict[str, Any]:
    """One message the bridge sent, checked; raises DecodeError."""
    if len(line) > MAX_MESSAGE_BYTES:
        raise DecodeError("bad_message", "larger than 1 MiB")
    try:
        message = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise DecodeError("bad_message", f"not JSON: {e}") from None
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
            _check_text(message.get("message"), "message")
    except ValueError as e:
        raise DecodeError("bad_message", str(e), raw_id) from None
    return message


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


def message_out(conversation: str, text: str, reply_to: str | None = None) -> dict[str, Any]:
    """A reply when it answers a message, `notify` otherwise (a cron job, background work)."""
    fields: dict[str, Any] = {"conversation": conversation, "text": text,
                              "kind": "reply" if reply_to else "notify"}
    if reply_to:
        fields["reply_to"] = reply_to
    return _message("message.out", **fields)


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
