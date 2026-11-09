"""Exact Hermes approval bindings; durable cards and receipts stay in questions.Manager."""

import inspect
import re
from dataclasses import dataclass


ACTIONS = ("once", "session", "always", "deny")


def native_api():
    try:
        from tools import approval
        from gateway.platforms.base import BasePlatformAdapter, ExecApprovalPrompt
        fields = getattr(ExecApprovalPrompt, "__dataclass_fields__", {})
        if ("request_id" in fields and "request_id" in inspect.signature(BasePlatformAdapter.send_exec_approval).parameters
                and all(callable(getattr(approval, name, None)) for name in
                        ("resolve_gateway_approval_card", "list_gateway_approvals", "observe_gateway_settle"))):
            return approval
    except (ImportError, TypeError, ValueError):
        pass
    return None


def definition(prompt, question_id):
    return {"id": question_id, "text": "Hermes requests command approval", "choices": [], "multiple": False,
            "approval": {"command": prompt.command, "reason": prompt.description,
                         "actions": [row[1] for row in prompt.actions], "smart_denied": bool(prompt.smart_denied)}}


def _fenced(text):
    lengths = [(max((len(run) for run in re.findall(re.escape(char) + "+", text)), default=0), char)
               for char in ("`", "~")]
    length, char = min(lengths)
    fence = char * max(3, length + 1)
    return f"{fence}\n{text}\n{fence}"


def _bounded(text, render, fits):
    while text:
        lo, hi = 1, len(text)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if fits(render(text[:mid])):
                lo = mid
            else:
                hi = mid - 1
        if not fits(render(text[:lo])):
            raise ValueError("an approval text chunk cannot fit")
        yield render(text[:lo])
        text = text[lo:]


def fallback_chunks(prompt, fits, prefix="/"):
    # Every command part is a complete literal Markdown block, including when a
    # long backtick/tilde run or JSON escapes changes the available byte budget.
    if fits(prompt.text):
        yield prompt.text
    else:
        yield from _bounded(prompt.text, _fenced, fits)
    yield from _bounded(prompt.command, lambda part: "Complete command:\n" + _fenced(part), fits)
    commands = {"once": f"{prefix}approve", "session": f"{prefix}approve session",
                "always": f"{prefix}approve always", "deny": f"{prefix}deny"}
    choices = " · ".join(commands[row[1]] for row in prompt.actions if row[1] in commands)
    yield f"Reply with {choices}."


@dataclass
class Binding:
    native: object
    prompt: object
    request_id: str
    session_key: str
    snapshot: dict
    reason: str | None = None

    def pending(self):
        matching = [row for row in self.native.list_gateway_approvals(self.session_key)
                    if row.get("request_id") == self.request_id]
        # The ID was supplied by the native prompt; the snapshot only verifies it
        # remains the same immutable request. It never supplies a replacement ID.
        return len(matching) == 1 and matching[0] == self.snapshot and self.reason is None

    def observed(self):
        if self.reason is None:
            return None
        if self.reason == "resolved":
            return "resolved", None
        return ("expired" if self.reason == "timeout" else "cancelled"), None

    def observe(self, loop):
        def settled(reason):
            # Hermes invokes observers on the tool's waiting thread, outside its lock.
            loop.call_soon_threadsafe(setattr, self, "reason", reason)
        return self.native.observe_gateway_settle(self.session_key, self.request_id, settled)

    def resolve(self, action):
        return self.native.resolve_gateway_approval_card(self.session_key, action, self.request_id) == 1
