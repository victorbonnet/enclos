"""Hermes's command confirmations, shown as question cards.

Hermes asks the person to confirm some of their own commands before they run:
`/new` (and its alias `/reset`) and `/undo` while `approvals.destructive_slash_confirm`
is on, `/reload-mcp` while `approvals.mcp_reload_confirm` is, and a `/model` switch
its guard warns about. It calls an adapter's `send_slash_confirm`, keeps one pending
confirmation per session key in `tools.slash_confirm`, and runs the command's handler
when `resolve(session_key, confirm_id, choice)` is called with "once", "always" or
"cancel", as its own button adapters (Telegram, Slack, Discord) do. A card is bound
to that exact confirmation, its session key and confirm id; `questions.Manager`
delivers it with the question transport. A command confirmation is not a runtime
approval: it grants the agent nothing, and the bridge does not sign its answer.
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
LABELS = {"once": "Approve once", "always": "Always", "cancel": "Cancel"}
# A command whose "always" proceeds as "once" does and writes nothing (Hermes's model
# guard has no opt-out): its card offers no Always.
ONCE_ONLY = frozenset(("model",))
NOTE = "Hermes asks before it runs this command. This is not a runtime approval, and it changes no access."
# Hermes writes its opt-out to the agent's `config.yaml` and reads it before each such
# command; enclos leaves those keys out of the settings that restart the gateway.
ALWAYS_NOTE = "Always also turns this confirmation off in the agent's settings: Hermes will not ask it again."
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
        logger.warning("Hermes's command confirmations lack %s: they are sent as Hermes's text",
                       ", ".join(missing) if slash_confirm is not None else "tools.slash_confirm")
    return None


def offered(command):
    """The choices a confirmation of `command` offers, in order."""
    return tuple(c for c in CHOICES if not (c == "always" and command in ONCE_ONLY))


def pending(native, session_key, confirm_id=None):
    """Hermes's pending confirmation of `session_key` (that of `confirm_id`, when given), or None."""
    entry = native.get_pending(session_key)
    if not entry or (confirm_id is not None and entry.get("confirm_id") != confirm_id):
        return None
    return entry


def typed_choice(text, choices):
    """The choice Hermes would take `text` for, typed as a reply to a confirmation
    (`GatewayInboundMixin._hm_slash_confirm_reply`): its command spellings
    (`_SLASH_CONFIRM_CMD_CHOICES`, `/approve`, `/always`, `/cancel`...) first, then its
    words (`approval.inputs.confirm_*`, English and the active language), read as it
    reads them. None when it reads none, it cannot be read, or `choices` lacks it."""
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
    return choice if choice in choices else None


@dataclass
class Binding:
    """One pending Hermes confirmation. Its handler is Hermes's own, wrapped so the
    channel learns which choice ran it, whoever answered: the card, or a reply typed
    in the composer."""
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
        return pending(self.native, self.session_key, self.confirm_id)

    def _expired(self, now=time.time):
        return now() - self.created > self.timeout

    def observed(self):
        """None while it waits. Else what became of it: the choice Hermes ran it with;
        cancelled, when Hermes dropped it (a session reset, a newer confirmation) or the
        channel closed; expired, once Hermes's five minutes are over by this clock,
        after which Hermes takes no answer."""
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

    async def resolve(self, choice, answering=None):
        """Hermes's own resolver, as its button adapters call it, with `answering` the
        card's answer it carries out. Hermes returns its handler's reply when that is
        text, and None when it took nothing (expired, or answered or dropped meanwhile)."""
        self.answering = answering
        try:
            return await self.native.resolve(self.session_key, self.confirm_id, choice)
        finally:
            self.answering = None

    def clear(self):
        """Drops the pending confirmation, if it is still this one."""
        if self._entry() is not None:
            self.native.clear(self.session_key)


def bind(native, session_key, confirm_id):
    """A binding to Hermes's pending confirmation `confirm_id` of `session_key`, its
    handler wrapped through Hermes's own `register` (same id, command and authority);
    None when there is none, or it cannot be wrapped (said in the log)."""
    entry = pending(native, session_key, confirm_id)
    if entry is None or not callable(entry.get("handler")):
        return None
    original = entry["handler"]
    command = str(entry.get("command") or "")
    binding = Binding(native, session_key, confirm_id, command, offered(command), time.time(),
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
        registered = native.get_pending(session_key) or {}
        binding.created = float(registered.get("created_at") or binding.created)
    except Exception:
        logger.warning("Command confirmation %s could not be bound to a card", confirm_id, exc_info=True)
        return None
    return binding


def card_text(message, title):
    """Hermes's prompt, without its typed-reply line (it names `/approve`, which the
    app does not pass on) or characters the card cannot show."""
    paragraphs = [p for p in visible.stripped(message or "", lines=True).split("\n\n")
                  if p.strip() and "`/approve`" not in p]
    return "\n\n".join(paragraphs).strip() or visible.stripped(title or "", lines=False).strip()


def prompt_text(title, message, choices):
    """What the card says, or the text that stands for it: Hermes's prompt, then what
    a command confirmation is."""
    notes = [NOTE] + ([ALWAYS_NOTE] if "always" in choices else [])
    heading = card_text(message, title)
    return "\n\n".join(([heading] if heading else []) + [" ".join(notes)])


def definition(question_id, text, choices):
    return {"id": question_id, "text": text, "choices": [LABELS[c] for c in choices], "multiple": False}


def reply_words(choices):
    """Hermes's English words for `choices`, which it always reads."""
    return "yes, always or cancel" if "always" in choices else "yes or cancel"


def fallback_text(text, choices):
    """The confirmation as text, where no card shows it: a reply in the composer
    answers it, read as Hermes reads one (the channel reads it itself while a turn
    runs)."""
    return f"{text}\n\nReply {reply_words(choices)}."
