"""Exact ingress interruption through Hermes's public processing lifecycle.

The native task/guard maps are read-only identity checks around its public
interrupt_session_activity helper. No command spelling or session-wide cancel
lookup can select a successor after an await.
"""
import asyncio

from . import protocol

MAX_PENDING = 4096


class Manager:
    def __init__(self, adapter, session_key, *, lifecycle=True):
        self.adapter, self.session_key = adapter, session_key
        self.lifecycle = lifecycle
        self.pending = {}

    @property
    def available(self):
        return (self.lifecycle and callable(getattr(self.adapter, "interrupt_session_activity", None))
                and isinstance(getattr(self.adapter, "_active_sessions", None), dict)
                and isinstance(getattr(self.adapter, "_session_tasks", None), dict))

    def admit(self, event):
        if not self.available:
            return
        if len(self.pending) >= MAX_PENDING:
            raise protocol.DecodeError("agent_unavailable", "native interruption registry is full", event.message_id)
        self.pending[event.message_id] = {"event": event, "cancelled": False}

    def _record(self, event):
        record = self.pending.get(getattr(event, "message_id", None))
        return record if record and record["event"] is event else None

    def start(self, event):
        record = self._record(event)
        if record is None:
            return
        raw = getattr(event, "raw_message", None)
        if not isinstance(raw, dict) or raw.get("text") != event.text:
            return  # Native batching/merging is not an exact original ingress.
        if record["cancelled"]:
            # The native processing-start hook runs before its message handler.
            raise asyncio.CancelledError()
        key = self.session_key(event)
        task = asyncio.current_task()
        guard = self.adapter._active_sessions.get(key)
        if task is None or self.adapter._session_tasks.get(key) is not task or not isinstance(guard, asyncio.Event):
            return
        record.update(key=key, task=task, guard=guard)

    def complete(self, event):
        record = self._record(event)
        if record is not None:
            self.pending.pop(event.message_id, None)

    async def abort(self, control):
        if not self.available:
            raise protocol.DecodeError("unsupported", "this Hermes version has no targeted interruption helper", control["id"])
        record = self.pending.get(control["of"])
        if record is None or record["event"].source.chat_id != control["conversation"]:
            return
        if "task" not in record:
            record["cancelled"] = True  # Native handler has not started this ingress.
            return
        key, task, guard = record["key"], record["task"], record["guard"]
        if (task.done() or self.adapter._session_tasks.get(key) is not task
                or self.adapter._active_sessions.get(key) is not guard):
            return
        # The native helper sets this exact guard synchronously before its first
        # await. All identity checks above and that signal share one event loop.
        await self.adapter.interrupt_session_activity(key, control["conversation"])

    def close(self):
        self.pending.clear()
