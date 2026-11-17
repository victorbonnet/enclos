"""Literal reply buttons for the next message in this exact conversation turn."""
import asyncio
import json
import dataclasses
import logging
import threading
from . import approvals, visible

logger = logging.getLogger(__name__)

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


@dataclasses.dataclass
class Batch:
    ready: threading.Event = dataclasses.field(default_factory=threading.Event)
    cancelled: threading.Event = dataclasses.field(default_factory=threading.Event)


@dataclasses.dataclass
class Pending:
    origin: object
    at: float
    replies: list[str]
    batch: Batch | None = None


def peek(adapter, chat_id, reply_to=None):
    pending = adapter._suggested_replies.get(chat_id)
    if not pending:
        return None
    if pending.batch:
        if pending.batch.cancelled.is_set():
            adapter._suggested_replies.pop(chat_id, None)
            return None
        if not pending.batch.ready.is_set():
            return None
    if pending.origin != adapter._last_in.get(chat_id) or asyncio.get_running_loop().time() - pending.at > 300:
        adapter._suggested_replies.pop(chat_id, None)
        return None
    if pending.origin is not None and reply_to is not None and reply_to != pending.origin[0]:
        return None
    return pending


def consume(adapter, chat_id, pending):
    if pending is not None and adapter._suggested_replies.get(chat_id) is pending:
        adapter._suggested_replies.pop(chat_id, None)


def take(adapter, chat_id, reply_to=None):
    pending = peek(adapter, chat_id, reply_to)
    consume(adapter, chat_id, pending)
    return pending.replies if pending else []


def register(ctx, adapters, platform):
    def suggest(args, **_):
        batch = Batch()
        futures = []
        through = []
        conversation = None
        try:
            replies = validate(args.get("replies"))
            conversation = approvals.session(platform)
            through = approvals.routes(adapters, conversation) if conversation else []
            if not through:
                raise ValueError("No enclos conversation is active.")
            async def stage(adapter):
                if not batch.cancelled.is_set():
                    adapter._suggested_replies[conversation] = Pending(
                        adapter._last_in.get(conversation), asyncio.get_running_loop().time(), replies, batch)
            for adapter in through:
                coro = stage(adapter)
                try:
                    future = asyncio.run_coroutine_threadsafe(coro, adapter._loop)
                except Exception:
                    coro.close()
                    raise
                futures.append(future)
                future.result(timeout=5)
            batch.ready.set()
            return json.dumps({"status": "ready", "message": "The next ordinary message in this conversation will offer these exact replies. Send a short explanation now. No permission has been granted."})
        except Exception as error:
            batch.cancelled.set()
            for future in futures:
                future.cancel()
            for adapter in through:
                def rollback(adapter=adapter):
                    pending = adapter._suggested_replies.get(conversation)
                    if pending is not None and pending.batch is batch:
                        adapter._suggested_replies.pop(conversation, None)
                try:
                    adapter._loop.call_soon_threadsafe(rollback)
                except Exception as cleanup_error:
                    # The cancelled batch stays inert even if its loop has stopped.
                    logger.warning("Suggested reply cleanup failed (%s)", type(cleanup_error).__name__)
            logger.warning("Suggested replies could not be staged (%s)", type(error).__name__)
            message = ("Timed out while preparing suggested replies. Try again." if isinstance(error, TimeoutError)
                       else str(error).strip() or f"Could not prepare suggested replies ({type(error).__name__}).")
            return json.dumps({"error": message})
    ctx.register_tool(name="suggest_replies", toolset="enclos", handler=suggest,
        description="Offer up to four literal reply buttons below your next message in this app conversation. A tap sends the exact text as an ordinary message; it grants no access.",
        schema={"name": "suggest_replies", "description": "For a decision digest, write one or two simple sentences explaining what is blocked and why, with short actionable choices. Do not include paths, run IDs or internal workflow detail. This does not answer or bypass runtime approvals.",
                "parameters": {"type": "object", "properties": {"replies": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 4}}, "required": ["replies"]}})
