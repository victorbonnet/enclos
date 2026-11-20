"""Exact Hermes approval bindings; durable cards and receipts stay in questions.Manager."""

import inspect
import logging
import re
import time
from dataclasses import dataclass

from .visible import revealed


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


# Hermes's commands that decide or skip approvals: answering one, and turning the
# gate off for a session (`/yolo`) or for good (`/approvals off`). None is passed on,
# whoever the bridge says sent it: runtime approvals are decided with the app's
# buttons, whose decisions the bridge signs (ADR 0060).
APPROVAL_COMMANDS = frozenset(("approve", "deny", "yolo", "approvals"))
TYPED_ANSWER = ("Runtime approvals are decided with the enclos app's buttons, so this command was not "
                "passed to the agent.")
NOT_ANSWERABLE = ("A command needed runtime approval. Only the host's person decides runtime approvals, "
                  "and this conversation is not theirs, so it cannot be answered here: the command was denied.")
NOT_SIGNED = ("This decision does not carry the bridge's signature, so the agent's channel refused it and "
              "denied the command. If it happens again, run `enclos runtime configure <sandbox>/<agent> "
              "--channel app` on the host.")
NO_BUTTONS = ("This runtime approval cannot be decided in the app: it has no buttons here, and typed "
              "approval commands are not passed to the agent.")
DENIED = NO_BUTTONS + " It was denied."
WAITING = NO_BUTTONS + " The runtime denies it when it stops waiting."


def approval_command_name(event):
    """Which of `APPROVAL_COMMANDS` Hermes reads `event` as, or None: its own parser
    (`MessageEvent.get_command`) and its own aliases (`hermes_cli.commands.resolve_command`)."""
    name = event.get_command()
    if not name:
        return None
    try:
        from hermes_cli.commands import resolve_command
        found = resolve_command(name)
        if found is not None:
            name = found.name
    except ImportError:
        pass
    return name if name in APPROVAL_COMMANDS else None


def approval_command(event):
    """Whether Hermes reads `event` as one of `APPROVAL_COMMANDS`."""
    return approval_command_name(event) is not None


# While a runtime approval blocks the session key Hermes uses for a conversation, Hermes
# reads a bare word as a decision on it: its busy path (`gateway/run_busy.py`,
# `_route_plaintext_approval_while_busy`) rewrites "yes", "always", "👍", "no"... into
# `/approve [always|session]` or `/deny` and runs it. It reads the word some time after
# the channel hands it over (queue mode holds a burst of messages first), so whether an
# approval blocks when the channel looks says nothing of when Hermes reads it. The
# adapter therefore refuses such a word while an approval blocks, and, while a turn
# runs, hands it over as a message no gateway control reads
# (`allow_gateway_control = False`), which Hermes's route requires.
TYPED_WORD = ("A runtime approval is waiting, and it is decided with the enclos app's buttons, so this "
              "reply was not passed to the agent.")
TYPED_CONFIRM = ("`/approve` and `/deny` are kept for runtime approvals, which the enclos app's buttons decide, "
                 "so this command was not passed to the agent. To answer Hermes's confirmation of a command, "
                 "use its card in the app, or reply {words}.")
# Hermes's English words (`approval.inputs.approve`, `deny`, `always`, `session`, and its
# thumbs), refused when its own lists cannot be read: fail closed.
ENGLISH_WORDS = frozenset((
    "approve", "yes", "ok", "okay", "confirm", "y", "deny", "no", "reject", "cancel", "n",
    "always", "approve always", "always approve", "session", "approve session", "session approve",
    "\N{THUMBS UP SIGN}", "\N{THUMBS DOWN SIGN}"))
# No word of Hermes's lists is near this long: a longer message is never one.
MAX_WORD_CHARS = 64
logger = logging.getLogger(__name__)
_warned_words = False


def _hermes_words():
    """Every word Hermes reads as a decision, in every language it has: its own list in
    the language in force here (`GatewayBusySessionMixin._plaintext_approval_words`:
    English and the active language's `approval.inputs.*`, and the thumbs), and the same
    keys in each language Hermes supplies (`agent.i18n.supported_languages`), since the
    agent's profile may set another language than the gateway's. Normalised as Hermes
    normalises them (`approval_input_words`: split on commas, stripped, lower-cased)."""
    from agent.i18n import supported_languages, t
    from gateway.run_busy import GatewayBusySessionMixin as mixin
    words = set(mixin._plaintext_approval_words(mixin)) | set(mixin._PLAINTEXT_APPROVAL_EXTRA_WORDS)
    for language in supported_languages():
        for input_key, _ in mixin._PLAINTEXT_APPROVAL_INPUT_KEYS:
            key = f"approval.inputs.{input_key}"
            raw = t(key, lang=language)
            if raw != key:
                words.update(word.strip().lower() for word in raw.split(",") if word.strip())
    return frozenset(words)


def approval_words():
    """The words Hermes may read as a decision (`_hermes_words`); `ENGLISH_WORDS` when
    they cannot be read, said once in the log."""
    global _warned_words
    try:
        words = _hermes_words()
        if words:
            return words
        raise LookupError("Hermes's approval words are empty")
    except Exception:
        if not _warned_words:
            _warned_words = True
            logger.warning("Hermes's bare-word approval replies could not be read: the English ones are "
                           "refused while a runtime approval waits", exc_info=True)
    return ENGLISH_WORDS


def is_approval_word(event):
    """Whether `event`'s text, normalised as Hermes normalises it (`.strip().lower()`),
    is a word Hermes may read as a decision on a runtime approval."""
    text = (getattr(event, "text", None) or "")
    text = text.strip().lower() if isinstance(text, str) else ""
    return bool(text) and len(text) <= MAX_WORD_CHARS and text in approval_words()


def blocking(session_keys):
    """Whether a runtime approval blocks one of `session_keys` (Hermes's
    `tools.approval.has_blocking_approval`, the test its busy path makes). A Hermes
    without it has no bare-word decisions either."""
    try:
        from tools.approval import has_blocking_approval
    except ImportError:
        return False
    return any(has_blocking_approval(key) for key in session_keys if key)


MAX_PATTERNS = 16
PATTERN_GRANTS = ("session", "always")
# What a pending native request is: an entry still matching these is the one shown.
IDENTITY = ("request_id", "command", "description", "pattern_key", "pattern_keys")
# How long a request may be missing from Hermes before its card closes as expired.
MISSING_GRACE_SECONDS = 5.0


def patterns(snapshot):
    """The native pattern keys a session or always grant of this request records."""
    keys = list((snapshot or {}).get("pattern_keys") or [(snapshot or {}).get("pattern_key")])
    return list(dict.fromkeys(key for key in keys if isinstance(key, str) and key.strip()))


def definition(prompt, question_id, snapshot=None):
    named = patterns(snapshot)
    actions = [row[1] for row in prompt.actions]
    if not named:
        # A grant whose reach cannot be shown is not offered; Once and Deny stay.
        actions = [action for action in actions if action not in PATTERN_GRANTS]
    approval = {"command": prompt.command, "reason": prompt.description,
                "actions": actions, "smart_denied": bool(prompt.smart_denied)}
    if named and any(action in PATTERN_GRANTS for action in actions):
        approval["patterns"] = named
    return {"id": question_id, "text": "Hermes requests runtime approval", "choices": [], "multiple": False,
            "approval": approval}


def _fenced(text):
    lengths = [(max((len(run) for run in re.findall(re.escape(char) + "+", text)), default=0), char)
               for char in ("`", "~")]
    length, char = min(lengths)
    fence = char * max(3, length + 1)
    return f"{fence}\n{text}\n{fence}"


def _parts(text, render, fits):
    """`text` cut into the longest parts that each fit once rendered."""
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
        yield text[:lo]
        text = text[lo:]


def _bounded(text, render, fits):
    for part in _parts(text, render, fits):
        yield render(part)


# The longest heading a command part can have: parts are cut to fit under it.
_WIDEST_HEADING = "Command, part 9999 of 9999:\n"


def fallback_chunks(prompt, fits, denied=False):
    # Every command part is a complete literal Markdown block, including when a
    # long backtick/tilde run or JSON escapes changes the available byte budget.
    # Hidden characters are written out, so nothing in the command is hidden. No typed
    # command decides it (ADR 0060): the last part says it was `denied`, or will be.
    text = revealed(prompt.text)
    if fits(text):
        yield text
    else:
        yield from _bounded(text, _fenced, fits)
    # A long command is numbered, part i of n, so the first part is never read as all of it.
    parts = list(_parts(revealed(prompt.command), lambda part: _WIDEST_HEADING + _fenced(part), fits))
    if len(parts) == 1:
        yield "Complete command:\n" + _fenced(parts[0])
    else:
        for number, part in enumerate(parts, start=1):
            yield f"Command, part {number} of {len(parts)}:\n" + _fenced(part)
    if not prompt.command.isascii():
        yield "The command holds characters outside ASCII, some of which look like others. Check each one."
    yield DENIED if denied else WAITING


@dataclass
class Binding:
    native: object
    prompt: object
    request_id: str
    session_key: str
    snapshot: dict
    reason: str | None = None
    missing_since: float | None = None

    def _matching(self):
        return [row for row in self.native.list_gateway_approvals(self.session_key)
                if row.get("request_id") == self.request_id]

    def pending(self):
        matching = self._matching()
        # The ID was supplied by the native prompt; the snapshot only verifies it
        # remains the same request, by the fields that say what it would allow.
        # Bookkeeping Hermes may add to its entry later never makes a card dead.
        return (len(matching) == 1 and self.reason is None
                and all(matching[0].get(key) == self.snapshot.get(key) for key in IDENTITY))

    def observed(self, now=time.monotonic):
        if self.reason is None:
            # Hermes removes an entry before it calls its observers, so a missing
            # entry is only taken as gone (a teardown path that skips observers)
            # once it has stayed missing past the grace period: never a guess
            # standing in for a decision that is about to be reported.
            if self._matching():
                self.missing_since = None
                return None
            if self.missing_since is None:
                self.missing_since = now()
            return ("expired", None) if now() - self.missing_since >= MISSING_GRACE_SECONDS else None
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
