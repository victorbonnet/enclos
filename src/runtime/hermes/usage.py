"""What each Hermes agent used of its model providers, read inside the sandbox.

`enclos usage` runs this with Hermes's own Python, in the sandbox, so the host
never opens a database the agent can write. It reads each agent's `state.db`
read-only and writes enclos's runtime-neutral usage report (format 1, design
§11, Usage) to the file it is given, which enclos then reads on the host.

Arguments: the report's path, the window's start (Unix seconds), then the
agents' names. `default` is Hermes's built-in agent, whose home is `~/.hermes`;
any other is a profile under `~/.hermes/profiles/`.

Hermes counts per session, its word for a native chat (`sessions` table). A chat
counts whole when its last activity is in the window, so totals are those of
chats active since then, not tokens spent since then.
"""

import json
import os
import sqlite3
import sys

FORMAT = 1
MAX_MODELS = 50
TOP_CHATS = 5
MAX_TEXT = 200
TOKENS = ("input", "output", "cache_read", "cache_write", "reasoning")
# Hermes's column for each field of the report; a column an older Hermes
# lacks is reported as not provided (null), never 0.
COLUMNS = {
    "calls": "api_call_count",
    "input": "input_tokens",
    "output": "output_tokens",
    "cache_read": "cache_read_tokens",
    "cache_write": "cache_write_tokens",
    "reasoning": "reasoning_tokens",
}
COST_KINDS = ("actual", "estimated", "included", "unknown")


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
    """A token count Hermes stored: a non-negative integer, else unknown."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def cost_kind(statuses):
    kinds = {s if s in COST_KINDS else "unknown" for s in statuses}
    if not kinds:
        return "unknown"
    if len(kinds) == 1:
        return kinds.pop()
    return "mixed"


def read_agent(path, since):
    if not os.path.isfile(path):
        return {"found": False, "models": [], "top": []}
    # Read-only, never creating the file, and no query planner surprises from
    # a schema Hermes did not write: only plain SELECTs on named columns.
    db = sqlite3.connect("file:" + path + "?mode=ro", uri=True, timeout=5)
    try:
        db.execute("PRAGMA trusted_schema = OFF")
        columns = {row[1] for row in db.execute("PRAGMA table_info(sessions)")}
        if not columns:
            return {"found": False, "models": [], "top": []}
        has = {field: COLUMNS[field] in columns for field in COLUMNS}

        def col(name, default="NULL"):
            return name if name in columns else default

        when = "COALESCE({}, {}, started_at)".format(
            col("last_activity_at"), col("ended_at")
        )
        fields = ", ".join(
            col(COLUMNS[f]) + " AS " + f for f in ("calls",) + TOKENS
        )
        rows = db.execute(
            "SELECT id, {model}, {source}, {title}, started_at, {fields}, "
            "{actual}, {estimated}, {status} FROM sessions WHERE {when} >= ?".format(
                model=col("model"),
                source=col("source"),
                title=col("title"),
                fields=fields,
                actual=col("actual_cost_usd"),
                estimated=col("estimated_cost_usd"),
                status=col("cost_status"),
                when=when,
            ),
            (since,),
        ).fetchall()
    finally:
        db.close()

    models = {}
    chats = []
    for row in rows:
        sid, model, source, title, started = row[:5]
        values = dict(zip(("calls",) + TOKENS, row[5:11]))
        actual, estimated, status = row[11:14]
        entry = models.setdefault(
            model,
            {
                "model": text(model),
                "chats": 0,
                "calls": 0 if has["calls"] else None,
                "tokens": {t: (0 if has[t] else None) for t in TOKENS},
                "cost_usd": None,
                "statuses": set(),
            },
        )
        entry["chats"] += 1
        if has["calls"]:
            entry["calls"] += count(values["calls"]) or 0
        for t in TOKENS:
            if has[t]:
                entry["tokens"][t] += count(values[t]) or 0
        amount = actual if actual is not None else estimated
        if isinstance(amount, (int, float)) and amount >= 0:
            entry["cost_usd"] = (entry["cost_usd"] or 0) + float(amount)
        entry["statuses"].add(status if isinstance(status, str) else "unknown")
        chats.append(
            {
                "chat": text(sid),
                "source": text(source),
                "title": text(title),
                "started_at": started if isinstance(started, (int, float)) else None,
                "model": text(model),
                "calls": count(values["calls"]) if has["calls"] else None,
                "tokens": {t: (count(values[t]) if has[t] else None) for t in TOKENS},
            }
        )

    listed = []
    for entry in models.values():
        entry["cost"] = {"usd": entry.pop("cost_usd"), "kind": cost_kind(entry.pop("statuses"))}
        listed.append(entry)
    listed.sort(key=lambda m: -total(m["tokens"]))
    chats.sort(key=lambda s: -total(s["tokens"]))
    return {"found": True, "models": listed[:MAX_MODELS], "top": chats[:TOP_CHATS]}


def total(tokens):
    return sum(v for v in tokens.values() if isinstance(v, int))


def main(argv):
    out, since, agents = argv[1], float(argv[2]), argv[3:]
    home = os.environ["HOME"]
    report = {"format": FORMAT, "agents": []}
    for agent in agents:
        try:
            read = read_agent(agent_db(home, agent), since)
        except sqlite3.Error as e:
            read = {"error": "state.db: " + text(e)}
        read["agent"] = agent
        report["agents"].append(read)
    # Created here, never replaced: enclos checks that it reads a plain file.
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(report, f)


if __name__ == "__main__":
    main(sys.argv)
