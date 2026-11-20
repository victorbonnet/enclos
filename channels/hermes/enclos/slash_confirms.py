"""Hermes's slash-command confirmations, shown as app questions.

Hermes asks the person before some commands run: `/new`, `/reset`, `/clear` and
`/undo` while `approvals.destructive_slash_confirm` is on, `/reload-mcp`, and a
`/model` switch its guard warns about. It calls an adapter's `send_slash_confirm`,
keeps one pending confirm per session in `tools.slash_confirm`, and runs the
command's handler when `resolve(session_key, confirm_id, choice)` is called with
"once", "always" or "cancel", as its own button adapters (Telegram, Slack, Discord)
do. A card is bound to that exact confirm, its session key and confirm id;
`questions.Manager` delivers it as an ordinary question. A confirm is not a runtime
approval: it changes no access, and the bridge does not sign it.
"""

import inspect
import logging
import time
from dataclasses import dataclass
from typing import Any

from . import visible

logger = logging.getLogger(__name__)

# What the channel calls in `tools.slash_confirm`.
NATIVE_FUNCTIONS = ("register", "get_pending", "resolve", "clear")
CHOICES = ("once", "always", "cancel")
LABELS = {"once": "Approve once", "always": "Always (restarts the agent)", "cancel": "Cancel"}
# A command whose "always" proceeds as "once" does, writing nothing (Hermes's model
# guard has no opt-out): its card offers no Always.
ONCE_ONLY = frozenset(("model",))
NOTE = "Hermes asks before it runs this command. This is not a runtime approval, and it changes no access."
ALWAYS_NOTE = ("Always also turns this question off in the agent's settings, and enclos restarts the agent "
               "when its settings change.")
UNKNOWN_ANSWER = "Answer with one of the card's choices."
_warned = False


def native():
    """Hermes's `tools.slash_confirm`, when it has everything the channel calls; else
    None, said once in the log, and Hermes sends its confirmations as text."""
    global _warned
    try:
        from tools import slash_confirm
    except ImportError:
        slash_confirm = None
    missing = [name for name in NATIVE_FUNCTIONS if not callable(getattr(slash_confirm, name, None))]
    if slash_confirm is not None and not missing:
        return slash_confirm
    if not _warned:
        _warned = True
        logger.warning("Hermes's slash-command confirmations lack %s: they are sent as text",
                       ", ".join(missing) if slash_confirm is not None else "tools.slash_confirm")
    return None


def typed_choice(text, offered):
    """The choice Hermes would take `text` for, typed as a reply to a confirm
    (`GatewayInboundMixin._hm_slash_confirm_reply`): its command spellings
    (`_SLASH_CONFIRM_CMD_CHOICES`, `/approve`, `/always`, `/cancel`...) first, then its
    words (`approval.inputs.confirm_*`, English and the active language), read as it
    reads them. None when it reads none, it cannot be read, or the card does not offer it."""
    try:
        from gateway.run_inbound import GatewayInboundMixin
        commands = GatewayInboundMixin._SLASH_CONFIRM_CMD_CHOICES
        words = GatewayInboundMixin._slash_confirm_text_choices(GatewayInboundMixin)
    except Exception:
        logger.warning("Hermes's typed replies to a confirmation could not be read", exc_info=True)
        return None
    stripped = text.strip()
    command = (stripped.split(maxsplit=1)[0][1:].lower().split("@", 1)[0]
               if stripped.startswith("/") else None)
    choice = commands.get(command) or words.get(stripped.lstrip("!/").lower())
    return choice if choice in offered else None


@dataclass
class Binding:
    """One pending Hermes confirm. Its handler is Hermes's own, wrapped so the channel
    learns which choice ran it, whoever answered: the card, or a reply typed in the
    composer, which Hermes reads itself."""
    native: Any
    session_key: str
    confirm_id: str
    command: str
    choices: tuple
    created: float
    timeout: float
    # The card's answer being resolved now: (state, answer, request id).
    answering: tuple | None = None
    # What the channel saw Hermes run: (state, answer[, request id]).
    settled: tuple | None = None

    def _entry(self):
        entry = self.native.get_pending(self.session_key)
        return entry if entry and entry.get("confirm_id") == self.confirm_id else None

    def _expired(self, now=time.time):
        return now() - self.created > self.timeout

    def observed(self):
        """None while it waits. Else what became of it: the choice Hermes ran it with;
        expired, once Hermes no longer takes an answer; cancelled, when it was dropped
        (a session reset, a newer confirm, the channel closing)."""
        if self.settled is not None:
            return self.settled
        if self._expired():
            return "expired", None
        return None if self._entry() is not None else ("cancelled", None)

    def pending(self):
        return self.observed() is None

    def _ran(self, choice):
        answering, self.answering = self.answering, None
        if answering is not None:
            self.settled = answering
        elif choice in self.choices:
            # Typed in the composer: the agent's report, not a device's answer.
            self.settled = ("answered", {"kind": "choices", "indices": [self.choices.index(choice)]})
        else:
            self.settled = ("answered", None)

    async def resolve(self, choice, answering):
        """Hermes's own resolver, as its button adapters call it; its handler's reply,
        or None when it took nothing (stale, or answered meanwhile)."""
        self.answering = answering
        try:
            return await self.native.resolve(self.session_key, self.confirm_id, choice)
        finally:
            self.answering = None

    def clear(self):
        """Drops the pending confirm, if it is still this one."""
        if self._entry() is not None:
            self.native.clear(self.session_key)


def bind(native, session_key, confirm_id):
    """A binding to Hermes's pending confirm `confirm_id` of `session_key`, its handler
    wrapped through Hermes's own `register` (same id, command and authority); None
    when there is no such confirm, or it cannot be wrapped."""
    entry = native.get_pending(session_key)
    if not entry or entry.get("confirm_id") != confirm_id or not callable(entry.get("handler")):
        return None
    original = entry["handler"]
    command = str(entry.get("command") or "")
    choices = tuple(c for c in CHOICES if not (c == "always" and command in ONCE_ONLY))
    binding = Binding(native, session_key, confirm_id, command, choices, time.time(),
                      float(getattr(native, "DEFAULT_TIMEOUT_SECONDS", 300)))

    async def handler(choice):
        # No await between Hermes's pop and this call: the choice is known before
        # anything else on the loop runs.
        binding._ran(choice)
        return await original(choice)

    try:
        extra = {}
        if "authority" in entry and "authority" in inspect.signature(native.register).parameters:
            extra["authority"] = entry["authority"]
        native.register(session_key, confirm_id, command, handler, **extra)
    except (TypeError, ValueError):
        logger.warning("A slash-command confirmation could not be bound; it is sent as text", exc_info=True)
        return None
    registered = native.get_pending(session_key) or {}
    binding.created = float(registered.get("created_at") or binding.created)
    return binding


def card_text(message, title):
    """Hermes's prompt, without its typed-reply line (it names `/approve`, which the
    app does not pass on) or characters the card cannot show, and what the card is."""
    paragraphs = [p for p in visible.stripped(message or "", lines=True).split("\n\n")
                  if p.strip() and "`/approve`" not in p]
    return "\n\n".join(paragraphs).strip() or visible.stripped(title or "", lines=False).strip()


def definition(question_id, title, message, binding):
    notes = [NOTE] + ([ALWAYS_NOTE] if "always" in binding.choices else [])
    heading = card_text(message, title)
    return {"id": question_id, "text": "\n\n".join(([heading] if heading else []) + [" ".join(notes)]),
            "choices": [LABELS[c] for c in binding.choices], "multiple": False}


def fallback_text(text, binding):
    """The card as text, for a bridge that refused it or cannot show it: Hermes's
    English words, which it always reads, answer it in the composer."""
    words = "yes, always or cancel" if "always" in binding.choices else "yes or cancel"
    return f"{text}\n\nReply {words}."
