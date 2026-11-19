"""What each Hermes agent used of its model providers, read inside the sandbox.

`enclos usage` runs this with Hermes's own Python, in the sandbox, so the host
never opens a database the agent can write. It reads each agent's `state.db`
read-only and writes enclos's runtime-neutral usage report (format 1, design
§11, Usage) to the file it is given, which enclos then reads on the host.

Arguments: the report's path, the window's start (Unix seconds), then the
agents' names. `default` is Hermes's built-in agent, whose home is `~/.hermes`;
any other is a profile under `~/.hermes/profiles/`.

Hermes counts per session, its word for a native chat. Its `sessions` row
holds the main loop's counters only, under the model the chat started with;
`session_model_usage` holds every call by the model it went to, background
calls too (titles, compression, approvals, background reviews). As Hermes's
own Insights does (`agent/insights.py`, `_compute_model_breakdown`), the
reader sums `session_model_usage` by model, then adds what each chat's
counters hold beyond its rows under the chat's model, and uses the counters
alone where the table is missing. A chat counts whole when its last activity
is in the window, so totals are those of chats active since then, not tokens
spent since then.

Whatever goes wrong is written into the report (`error`), never to the
terminal: enclos sends this program's output nowhere.
"""

import json
import math
import os
import sqlite3
import sys

FORMAT = 1
MAX_MODELS = 50
TOP_CHATS = 5
MAX_TEXT = 200
# The most a count may be: the report's counts are unsigned 64-bit.
MAX_COUNT = 2**64 - 1
TOKENS = ("input", "output", "cache_read", "cache_write", "reasoning")
SENT = ("input", "output", "cache_read", "cache_write")
FIELDS = ("calls",) + TOKENS
# Hermes's column for each field of the report, in both tables.
COLUMNS = {
    "calls": "api_call_count",
    "input": "input_tokens",
    "output": "output_tokens",
    "cache_read": "cache_read_tokens",
    "cache_write": "cache_write_tokens",
    "reasoning": "reasoning_tokens",
}
COST_KINDS = ("actual", "estimated", "included", "unknown")


class Unread(Exception):
    """An agent's records that cannot be read as Hermes writes them."""


def agent_db(home, agent):
    hermes = os.path.join(home, ".hermes")
    if agent == "default":
        return os.path.join(hermes, "state.db")
    return os.path.join(hermes, "profiles", agent, "state.db")


def text(value):
    if value is None:
        return None
    return str(value)[:MAX_TEXT]


def count(value):
    """A count Hermes stored: a whole number of at least 0, else unknown."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return min(value, MAX_COUNT)


def amount(value):
    """A sum of money or a time Hermes stored: finite and at least 0, else unknown."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return float(value)


def money_of(actual, estimated):
    """What a call cost: the provider's figure when Hermes has one, else its estimate."""
    return amount(actual) if amount(actual) else amount(estimated)


def provider_of(value):
    """The provider Hermes billed a call through (`billing_provider`), or None
    when it does not say: its empty default, or nothing stored."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def cost_kind(statuses):
    kinds = {s if s in COST_KINDS else "unknown" for s in statuses}
    if not kinds:
        return "unknown"
    if len(kinds) == 1:
        return kinds.pop()
    return "mixed"


class Sum:
    """Counts of one model, or one chat: each field known, not kept by any
    table (None), or known in some rows only (`incomplete`)."""

    def __init__(self, kept):
        self.values = {f: (0 if f in kept else None) for f in FIELDS}
        # The fields some row held a value of.
        self.known = set()
        self.incomplete = set()
        self.cost = None
        self.statuses = set()
        self.chats = set()

    def add(self, chat, values, money, status):
        self.chats.add(chat)
        for f in FIELDS:
            if self.values[f] is None:
                continue
            v = count(values.get(f))
            if v is None:
                self.incomplete.add(f)
            else:
                self.known.add(f)
                self.values[f] = min(self.values[f] + v, MAX_COUNT)
        if money is not None:
            self.cost = (self.cost or 0.0) + money
            self.statuses.add(status if isinstance(status, str) else "unknown")
        else:
            # A cost Hermes does not know: the sum is not all of it.
            self.statuses.add("included" if status == "included" else "unknown")

    def value(self, f):
        """The sum, at least; unknown when no row held a value of it."""
        if f in self.incomplete and f not in self.known:
            return None
        return self.values[f]

    def partial(self):
        """The fields some rows held and others did not."""
        return sorted(self.incomplete & self.known)

    def total(self):
        return sum(self.value(t) or 0 for t in SENT)

    def tokens(self):
        return {t: self.value(t) for t in TOKENS}

    def entry(self, model, provider):
        entry = {
            "model": text(model),
            "provider": text(provider),
            "chats": len(self.chats),
            "calls": self.value("calls"),
            "tokens": self.tokens(),
            "cost": {"usd": self.cost, "kind": cost_kind(self.statuses)},
        }
        if self.partial():
            entry["incomplete"] = self.partial()
        return entry


def columns(db, table):
    return {row[1] for row in db.execute("PRAGMA table_info({})".format(table))}


def read_agent(path, since):
    try:
        os.stat(path)
    except FileNotFoundError:
        return {"found": False, "models": [], "top": []}
    # Read-only, never creating the file; a schema it did not write runs no
    # function of the agent's (`trusted_schema`).
    db = sqlite3.connect("file:" + path + "?mode=ro", uri=True, timeout=5)
    try:
        db.execute("PRAGMA trusted_schema = OFF")
        chats_kept = columns(db, "sessions")
        if not chats_kept:
            raise Unread("it has no sessions table")
        rows_kept = columns(db, "session_model_usage")

        def col(kept, name, prefix):
            return prefix + name if name in kept else "NULL"

        when = "COALESCE({}, {}, s.started_at)".format(
            col(chats_kept, "last_activity_at", "s."), col(chats_kept, "ended_at", "s.")
        )
        chats = db.execute(
            "SELECT s.id, {model}, {source}, {title}, s.started_at, {fields}, {actual}, {estimated}, {status}, "
            "{provider} FROM sessions s WHERE {when} >= ?".format(
                model=col(chats_kept, "model", "s."),
                source=col(chats_kept, "source", "s."),
                title=col(chats_kept, "title", "s."),
                fields=", ".join(col(chats_kept, COLUMNS[f], "s.") for f in FIELDS),
                actual=col(chats_kept, "actual_cost_usd", "s."),
                estimated=col(chats_kept, "estimated_cost_usd", "s."),
                status=col(chats_kept, "cost_status", "s."),
                provider=col(chats_kept, "billing_provider", "s."),
                when=when,
            ),
            (since,),
        ).fetchall()
        calls = []
        if rows_kept:
            calls = db.execute(
                "SELECT u.session_id, u.model, {fields}, {actual}, {estimated}, {status}, {provider} "
                "FROM session_model_usage u JOIN sessions s ON s.id = u.session_id "
                "WHERE {when} >= ?".format(
                    fields=", ".join(col(rows_kept, COLUMNS[f], "u.") for f in FIELDS),
                    actual=col(rows_kept, "actual_cost_usd", "u."),
                    estimated=col(rows_kept, "estimated_cost_usd", "u."),
                    status=col(rows_kept, "cost_status", "u."),
                    provider=col(rows_kept, "billing_provider", "u."),
                    when=when,
                ),
                (since,),
            ).fetchall()
    finally:
        db.close()

    kept = {f for f in FIELDS if COLUMNS[f] in chats_kept or COLUMNS[f] in rows_kept}
    models = {}
    by_chat = {}
    attributed = {}
    # A background call's row has no cost status of its own; it went through
    # its chat's provider, so it takes its chat's.
    chat_status = {row[0]: row[13] for row in chats}
    # Likewise its provider, when the row does not name one.
    chat_provider = {row[0]: provider_of(row[14]) for row in chats}
    for row in calls:
        sid, model = row[0], row[1]
        values = dict(zip(FIELDS, row[2:8]))
        money = money_of(row[8], row[9])
        status = row[10] if row[10] is not None else chat_status.get(sid)
        provider = provider_of(row[11]) or chat_provider.get(sid)
        models.setdefault((model, provider), Sum(kept)).add(sid, values, money, status)
        by_chat.setdefault(sid, Sum(kept)).add(sid, values, money, status)
        seen = attributed.setdefault(sid, dict.fromkeys(FIELDS, 0) | {"money": 0.0})
        for f in FIELDS:
            seen[f] += count(values[f]) or 0
        seen["money"] += money or 0.0

    listed = []
    for row in chats:
        sid, model, source, title, started = row[:5]
        values = dict(zip(FIELDS, row[5:11]))
        money, status = money_of(row[11], row[12]), row[13]
        seen = attributed.get(sid)
        if seen is None:
            # Counters only: a chat from before `session_model_usage`.
            rest, rest_money = values, money
        else:
            # What the counters hold beyond the chat's rows; reasoning is
            # counted in the rows alone, as Insights does.
            rest = {"reasoning": 0}
            for f in FIELDS[:-1]:
                v = count(values[f])
                rest[f] = None if v is None else max(0, v - seen[f])
            rest_money = None if money is None else max(0.0, money - seen["money"])
            if not any(rest.values()) and not rest_money:
                rest = None
        chat = by_chat.setdefault(sid, Sum(kept))
        if rest is not None:
            models.setdefault((model, provider_of(row[14])), Sum(kept)).add(sid, rest, rest_money, status)
            chat.add(sid, rest, rest_money, status)
        listed.append(
            {
                "chat": text(sid),
                "source": text(source),
                "title": text(title),
                "started_at": amount(started),
                "model": text(model),
                "calls": chat.value("calls"),
                "tokens": chat.tokens(),
            }
        )

    ordered = sorted(models.items(), key=lambda m: -m[1].total())
    report = [s.entry(model, provider) for (model, provider), s in ordered[:MAX_MODELS]]
    if len(ordered) > MAX_MODELS:
        # The rest in one row, so the agent's totals stay whole.
        rest = Sum(kept)
        for _, s in ordered[MAX_MODELS - 1:]:
            rest.chats |= s.chats
            rest.incomplete |= s.incomplete
            rest.known |= s.known
            rest.statuses |= s.statuses
            for f in FIELDS:
                if rest.values[f] is not None and s.values[f] is not None:
                    rest.values[f] = min(rest.values[f] + s.values[f], MAX_COUNT)
            if s.cost is not None:
                rest.cost = (rest.cost or 0.0) + s.cost
        report = report[: MAX_MODELS - 1] + [rest.entry("{} other models".format(len(ordered) - MAX_MODELS + 1), None)]
    listed.sort(key=lambda c: -sum(c["tokens"][t] or 0 for t in SENT))
    return {"found": True, "models": report, "top": listed[:TOP_CHATS]}


def write(out, report):
    # Created here, never replaced: enclos checks that it reads a plain file.
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(report, f, allow_nan=False)


def main(argv):
    out = argv[1]
    try:
        since, agents = float(argv[2]), argv[3:]
        home = os.environ["HOME"]
        report = {"format": FORMAT, "agents": []}
        for agent in agents:
            try:
                read = read_agent(agent_db(home, agent), since)
            except (sqlite3.Error, OSError, Unread) as e:
                read = {"error": text("state.db: {}".format(e))}
            read["agent"] = agent
            report["agents"].append(read)
        write(out, report)
    except Exception as e:
        # Said in the report, which enclos shows escaped, never on a terminal.
        write(out, {"format": FORMAT, "agents": [], "error": text("{}: {}".format(type(e).__name__, e))})


if __name__ == "__main__":
    main(sys.argv)
