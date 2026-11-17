"""Literal reply buttons for the next message in this exact conversation turn."""
import asyncio
import json
from . import approvals, visible

MAX_REPLIES = 4
MAX_REPLY_BYTES = 256


def validate(replies):
    if not isinstance(replies, list) or not 1 <= len(replies) <= MAX_REPLIES:
        raise ValueError("Offer between one and four replies.")
    seen = set()
    for reply in replies:
        if (not isinstance(reply, str) or not reply.strip()
                or len(reply.encode("utf-8")) > MAX_REPLY_BYTES
                or visible.has_hidden(reply) or visible.bare(reply) in seen):
            raise ValueError("Replies must be distinct, visible single lines of at most 256 UTF-8 bytes.")
        seen.add(visible.bare(reply))
    return list(replies)


def take(adapter, chat_id, reply_to=None):
    pending = adapter._suggested_replies.get(chat_id)
    if not pending:
        return []
    origin, at, replies = pending
    if origin != adapter._last_in.get(chat_id) or asyncio.get_running_loop().time() - at > 300:
        adapter._suggested_replies.pop(chat_id, None)
        return []
    if origin is not None and reply_to is not None and reply_to != origin[0]:
        return []
    adapter._suggested_replies.pop(chat_id, None)
    return replies


def register(ctx, adapters, platform):
    def suggest(args, **_):
        try:
            replies = validate(args.get("replies"))
            conversation = approvals.session(platform)
            through = approvals.routes(adapters, conversation) if conversation else []
            if not through:
                raise ValueError("No enclos conversation is active.")
            async def stage(adapter):
                adapter._suggested_replies[conversation] = (
                    adapter._last_in.get(conversation), asyncio.get_running_loop().time(), replies)
            for adapter in through:
                asyncio.run_coroutine_threadsafe(stage(adapter), adapter._loop).result(timeout=5)
            return json.dumps({"status": "ready", "message": "The next ordinary message in this conversation will offer these exact replies. Send a short explanation now. No permission has been granted."})
        except Exception as error:
            return json.dumps({"error": str(error)})
    ctx.register_tool(name="suggest_replies", toolset="enclos", handler=suggest,
        description="Offer up to four literal reply buttons below your next message in this app conversation. A tap sends the exact text as an ordinary message; it grants no access.",
        schema={"name": "suggest_replies", "description": "For a decision digest, write one or two simple sentences explaining what is blocked and why, with short actionable choices. Do not include paths, run IDs or internal workflow detail. This does not answer or bypass runtime approvals.",
                "parameters": {"type": "object", "properties": {"replies": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 4}}, "required": ["replies"]}})
