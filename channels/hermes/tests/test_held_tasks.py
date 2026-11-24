"""Held tasks (ADR 0066): what the plugin reads from Hermes's kanban board,
what it sends the bridge, and how it resumes a task.

Most tests use a stand-in for the parts of Hermes's `kanban_db` the plugin
calls, over SQLite files, so they run without Hermes. `NativeHermesHeldTasks`
runs against a real Hermes checkout, on a board in a temporary home:

ENCLOS_HERMES_SOURCE=/path/to/hermes-agent python3 -m unittest discover -s channels/hermes/tests
"""

import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import sqlite3
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from typing import Optional
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enclos import asks, held_tasks, protocol  # noqa: E402


@dataclasses.dataclass
class Task:
    id: str
    title: str
    assignee: Optional[str]
    status: str
    created_by: Optional[str]
    created_at: Optional[int]
    last_failure_error: Optional[str] = None


# As Hermes writes its own SCHEMA_SQL: one column a line.
SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    assignee TEXT,
    status TEXT NOT NULL,
    created_by TEXT,
    created_at INTEGER,
    last_failure_error TEXT
);

CREATE TABLE IF NOT EXISTS task_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id    TEXT NOT NULL,
    run_id     INTEGER,
    kind       TEXT NOT NULL,
    payload    TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS kanban_notify_subs (
    task_id       TEXT NOT NULL,
    platform      TEXT NOT NULL,
    chat_id       TEXT NOT NULL,
    thread_id     TEXT NOT NULL DEFAULT '',
    user_id       TEXT,
    user_id_alt   TEXT,
    chat_type     TEXT,
    notifier_profile TEXT,
    delivery_mode TEXT NOT NULL DEFAULT 'notify',
    delivery_metadata TEXT,
    created_at    INTEGER NOT NULL,
    last_event_id INTEGER NOT NULL DEFAULT 0,
    last_ping_event_id INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (task_id, platform, chat_id, thread_id)
);
"""


class FakeKanban:
    """What the plugin uses of Hermes's `hermes_cli.kanban_db`, over SQLite."""

    DEFAULT_BOARD = "default"
    SCHEMA_SQL = SCHEMA
    Task = Task
    # A Hermes with triage says so; one that does not say is read as having none.
    VALID_STATUSES = frozenset({"triage", "todo", "ready", "running", "blocked", "review", "done", "archived"})

    def __init__(self, root: Path):
        self.root = root
        self.dbs: dict[str, Path] = {}
        # The databases Hermes's writer (`connect`) opened.
        self.opened: list[Path] = []
        self.unblock_result: Optional[bool] = None
        self.unblock_error: Optional[Exception] = None
        # The fields each specify_triage_task was given.
        self.specified: list[dict] = []
        self.raise_after_commit = False
        self.listing_error: Optional[Exception] = None
        self.add_board("default", root / "kanban.db")

    # Hermes's functions

    def list_boards(self, *, include_archived=True):
        if self.listing_error:
            raise self.listing_error
        return [{"slug": slug, "db_path": str(path)} for slug, path in self.dbs.items()]

    def kanban_db_path(self, board=None):
        return self.dbs[board or self.DEFAULT_BOARD]

    def pin_first_board_resolution(self):
        return contextlib.nullcontext()

    def list_tasks(self, conn, *, status=None):
        rows = conn.execute("SELECT * FROM tasks WHERE status = ?", (status,)).fetchall()
        return [Task(**dict(row)) for row in rows]

    def get_task(self, conn, task_id):
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return Task(**dict(row)) if row else None

    def unblock_task(self, conn, task_id):
        if self.unblock_error:
            raise self.unblock_error
        if self.unblock_result is not None:
            return self.unblock_result
        with conn:
            changed = conn.execute("UPDATE tasks SET status = 'ready', last_failure_error = NULL "
                                   "WHERE id = ? AND status = 'blocked'", (task_id,)).rowcount
            if changed:
                self._event(conn, task_id, "unblocked", None)
        if self.raise_after_commit:
            # As Hermes's write_txn checks the file after its COMMIT.
            raise RuntimeError("the database file shrank after commit")
        return changed == 1

    def specify_triage_task(self, conn, task_id, **fields):
        self.specified.append(fields)
        if self.unblock_error:
            raise self.unblock_error
        if self.unblock_result is not None:
            return self.unblock_result
        with conn:
            changed = conn.execute("UPDATE tasks SET status = 'todo' WHERE id = ? AND status = 'triage'",
                                   (task_id,)).rowcount
            if changed:
                self._event(conn, task_id, "specified", None)
        if self.raise_after_commit:
            # As Hermes's recompute_ready, in its own transaction after the specify's.
            raise RuntimeError("database is locked")
        return changed == 1

    def connect(self, db_path):
        self.opened.append(Path(db_path))
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        return conn

    # The test's own

    def add_board(self, slug, path=None):
        path = path or self.root / "boards" / slug / "kanban.db"
        path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.closing(sqlite3.connect(path)) as conn:
            conn.executescript(SCHEMA)
        self.dbs[slug] = path

    def db(self, board="default"):
        conn = sqlite3.connect(self.dbs[board])
        conn.row_factory = sqlite3.Row
        return contextlib.closing(conn)

    @staticmethod
    def _event(conn, task_id, kind, payload, at=None):
        conn.execute("INSERT INTO task_events (task_id, kind, payload, created_at) VALUES (?, ?, ?, ?)",
                     (task_id, kind, payload if isinstance(payload, str) else
                      json.dumps(payload) if payload is not None else None, at or int(time.time())))

    def create(self, task_id, title="Write the weekly report", created_by="main", assignee=None,
               status="ready", board="default", at=1_000):
        with self.db(board) as conn, conn:
            conn.execute("INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, NULL)",
                         (task_id, title, assignee, status, created_by, at))
            self._event(conn, task_id, "created", {"status": status}, at)

    def hold(self, task_id, kind="blocked", payload=None, at=2_000, board="default", error=None):
        with self.db(board) as conn, conn:
            conn.execute("UPDATE tasks SET status = 'blocked', last_failure_error = ? WHERE id = ?", (error, task_id))
            self._event(conn, task_id, kind, payload or {}, at)

    def loop(self, task_id, payload=None, at=2_000, board="default"):
        """As Hermes's loop breaker: to `triage`, with its event."""
        self.move(task_id, "triage", "block_loop_detected",
                  {"reason": "Which client?", "kind": "needs_input", "recurrences": 2, "limit": 2}
                  if payload is None else payload, at, board)

    def move(self, task_id, status, kind, payload=None, at=None, board="default"):
        with self.db(board) as conn, conn:
            conn.execute("UPDATE tasks SET status = ? WHERE id = ?", (status, task_id))
            if kind:
                self._event(conn, task_id, kind, payload, at)

    def comment(self, task_id, board="default"):
        with self.db(board) as conn, conn:
            self._event(conn, task_id, "commented", {"author": "someone"})

    def subscribe(self, task_id, profile="main", mode="notify+wake", chat_id="chat-1", board="default"):
        """As Hermes subscribes a chat to a task, the one asking for it."""
        with self.db(board) as conn, conn:
            conn.execute("INSERT INTO kanban_notify_subs (task_id, platform, chat_id, notifier_profile, "
                         "delivery_mode, created_at) VALUES (?, 'enclos', ?, ?, ?, ?)",
                         (task_id, chat_id, profile, mode, int(time.time())))

    def unsubscribe_all(self, board="default"):
        with self.db(board) as conn, conn:
            conn.execute("DELETE FROM kanban_notify_subs")

    def status(self, task_id, board="default"):
        with self.db(board) as conn:
            return conn.execute("SELECT status FROM tasks WHERE id = ?", (task_id,)).fetchone()[0]


class FakeBoardCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.kb = FakeKanban(Path(self.temporary.name))
        self.board = held_tasks.Board(self.kb, self.kb.connect)

    def revision(self, task_id, board="default"):
        with self.kb.db(board) as conn:
            return "e:%d" % conn.execute("SELECT MAX(id) FROM task_events WHERE task_id = ?", (task_id,)).fetchone()[0]


def fake_hermes(**changes):
    """`hermes_cli`'s kanban modules for `sys.modules`, from a FakeKanban, with `changes`."""
    kb = types.ModuleType("hermes_cli.kanban_db")
    fake = FakeKanban(Path(tempfile.mkdtemp()))
    for name in ("list_tasks", "get_task", "unblock_task", "list_boards", "pin_first_board_resolution",
                 "kanban_db_path"):
        setattr(kb, name, getattr(fake, name))
    kb.DEFAULT_BOARD, kb.SCHEMA_SQL, kb.Task = "default", SCHEMA, Task
    for name, value in changes.items():
        setattr(kb, name, value)
    connect = types.ModuleType("hermes_cli.kanban_db_connect")
    connect.connect = fake.connect
    package = types.ModuleType("hermes_cli")
    package.kanban_db, package.kanban_db_connect = kb, connect
    return {"hermes_cli": package, "hermes_cli.kanban_db": kb, "hermes_cli.kanban_db_connect": connect}


class StatusesHidden:
    """A facade over a `kanban_db` (`kb`, the stand-in or a real Hermes's)
    that, once `hidden`, no longer says it has triage: `VALID_STATUSES` is
    missing (or `statuses`, such as `()`), and `list_tasks` refuses `triage`
    as a Hermes without it would. Not a historical Hermes release: every
    other name is `kb`'s own."""

    MISSING = object()

    def __init__(self, kb, statuses=MISSING):
        self._kb, self._statuses = kb, statuses
        self.hidden = False
        # The statuses listed, and those refused, in order.
        self.asked, self.refused = [], []

    def __getattr__(self, name):
        if name == "VALID_STATUSES" and self.__dict__["hidden"]:
            if self.__dict__["_statuses"] is StatusesHidden.MISSING:
                raise AttributeError(name)
            return self.__dict__["_statuses"]
        return getattr(self.__dict__["_kb"], name)

    def list_tasks(self, conn, *, status=None, **rest):
        self.asked.append(status)
        if self.hidden and status == "triage":
            self.refused.append(status)
            raise ValueError("status must be one of the statuses this Hermes has")
        return self._kb.list_tasks(conn, status=status, **rest)


class Availability(unittest.TestCase):
    def test_without_hermes_there_is_no_board_and_the_hello_says_nothing(self):
        hidden = {"hermes_cli": None, "hermes_cli.kanban_db": None, "hermes_cli.kanban_db_connect": None}
        with patch.dict(sys.modules, hidden):
            with self.assertRaises(held_tasks.Unavailable):
                held_tasks.native()
            with self.assertLogs("enclos.held_tasks", "WARNING") as logs:
                manager = held_tasks.Manager("main", None)
        self.assertIn("Held tasks are off", logs.output[0])
        manager.bridge_supports = True
        self.assertFalse(manager.native)
        self.assertFalse(manager.available)

    def test_a_hermes_with_what_it_needs_has_a_board(self):
        with patch.dict(sys.modules, fake_hermes()):
            self.assertIsInstance(held_tasks.native(), held_tasks.Board)

    def test_a_hermes_missing_a_part_says_which(self):
        @dataclasses.dataclass
        class OldTask:
            id: str
            title: str

        without_payload = SCHEMA.replace("    payload    TEXT,\n", "")
        for changes, said in (({"unblock_task": None}, "unblock_task"),
                              ({"list_tasks": None, "get_task": None}, "list_tasks, get_task"),
                              ({"kanban_db_path": None}, "kanban_db_path"),
                              ({"SCHEMA_SQL": "CREATE TABLE tasks (id TEXT)"}, "task_events"),
                              ({"SCHEMA_SQL": "-- task_events is in a comment only"}, "task_events"),
                              ({"SCHEMA_SQL": without_payload}, "payload"),
                              ({"Task": OldTask}, "created_by")):
            with self.subTest(said), patch.dict(sys.modules, fake_hermes(**changes)):
                with self.assertRaises(held_tasks.Unavailable) as raised:
                    held_tasks.native()
                self.assertIn(said, str(raised.exception))


class Reading(FakeBoardCase):
    def test_only_blocked_tasks_this_agent_created(self):
        self.kb.create("t_mine")
        self.kb.hold("t_mine", payload={"reason": "Which client is it for?", "kind": "needs_input"}, at=5_000)
        self.kb.create("t_running")
        self.kb.create("t_theirs", created_by="research")
        self.kb.hold("t_theirs", payload={"reason": "Theirs"})
        self.assertEqual(self.board.read("main"), [{
            "task": "t_mine", "title": "Write the weekly report", "reason": "Which client is it for?",
            "since": 5_000, "revision": self.revision("t_mine"), "resume": held_tasks.RESUME, "resumable": True,
            "waits_on": "person",
        }])
        self.assertEqual([t["task"] for t in self.board.read("research")], ["t_theirs"])

    def test_the_board_is_read_read_only_never_through_hermes_s_writer(self):
        self.kb.create("t_1")
        self.kb.hold("t_1")
        before = self.kb.dbs["default"].read_bytes()
        self.assertEqual(len(self.board.read("main")), 1)
        self.assertEqual(self.kb.opened, [])
        self.assertEqual(self.kb.dbs["default"].read_bytes(), before)
        self.board.resume("main", "t_1", self.revision("t_1"))
        self.assertEqual(self.kb.opened, [self.kb.dbs["default"]])

    def test_a_task_that_gave_up_says_after_how_many_failures_and_the_last_error(self):
        self.kb.create("t_a1b2", assignee="writer")
        self.kb.hold("t_a1b2", "gave_up", {"failures": 3, "error": "rate limited"}, at=1_763_164_800,
                     error="rate limited by the provider")
        expected = json.loads((Path(__file__).resolve().parents[3] / "crates" / "enclos-protocol" / "tests"
                               / "fixtures" / "plugin" / "from_plugin_held_tasks.json").read_text())["tasks"][0]
        expected["revision"] = self.revision("t_a1b2")
        self.assertEqual(self.board.read("main"), [expected])

    def test_the_gave_up_event_s_error_stands_in_for_a_cleared_one_and_one_failure_is_singular(self):
        self.kb.create("t_1")
        self.kb.hold("t_1", "gave_up", {"failures": 1, "error": "the worker crashed"})
        [task] = self.board.read("main")
        self.assertEqual((task["reason"], task["last_error"]), ("Gave up after 1 consecutive failure.",
                                                                "the worker crashed"))

    def test_a_block_with_no_reason_says_its_kind_and_one_with_neither_says_nothing(self):
        self.kb.create("t_kind")
        self.kb.hold("t_kind", payload={"reason": None, "kind": "needs_input"}, at=3_000)
        self.kb.create("t_bare")
        self.kb.hold("t_bare", payload={}, at=2_000)
        self.assertEqual([(t["task"], t["reason"]) for t in self.board.read("main")],
                         [("t_kind", "Needs input."), ("t_bare", "")])

    def test_a_task_created_blocked_is_held_since_it_was_created_with_no_reason(self):
        self.kb.create("t_parked", status="blocked", at=4_000)
        [task] = self.board.read("main")
        self.assertEqual((task["reason"], task["since"]), ("", 4_000))

    def test_an_older_block_does_not_explain_a_later_hold(self):
        self.kb.create("t_again")
        self.kb.hold("t_again", payload={"reason": "Old reason"}, at=2_000)
        with self.kb.db() as conn, conn:
            self.kb._event(conn, "t_again", "unblocked", None, 3_000)
        [task] = self.board.read("main")
        self.assertEqual((task["reason"], task["since"]), ("", 3_000))

    def test_an_event_time_the_wire_cannot_carry_gives_way_to_the_creation_time_said_once(self):
        with self.kb.db() as conn, conn:
            conn.execute("INSERT INTO tasks VALUES ('t_far', 'Far', NULL, 'blocked', 'main', 1500, NULL)")
            conn.execute("INSERT INTO task_events (task_id, kind, payload, created_at) "
                         "VALUES ('t_far', 'blocked', '{}', '1e20')")
            conn.execute("INSERT INTO tasks VALUES ('t_before', 'Before', NULL, 'blocked', 'main', -5, NULL)")
            conn.execute("INSERT INTO task_events (task_id, kind, payload, created_at) "
                         "VALUES ('t_before', 'blocked', '{}', -7)")
        with self.assertLogs("enclos.held_tasks", "WARNING") as logs:
            found = {t["task"]: t["since"] for t in self.board.read("main")}
        self.assertEqual(found, {"t_far": 1500, "t_before": 0})
        self.assertEqual(len(logs.output), 2)
        with self.assertNoLogs("enclos.held_tasks", "WARNING"):
            self.board.read("main")

    def test_text_the_sandbox_wrote_with_a_lone_surrogate_still_encodes(self):
        self.kb.create("t_1", assignee="writer")
        self.kb.hold("t_1", "gave_up", '{"failures": 2, "error": "bad \\ud800 byte"}')
        self.kb.create("t_2")
        self.kb.hold("t_2", payload='{"reason": "why \\udfff not"}', at=3_000)
        tasks = self.board.read("main")
        line = protocol.encode_line(protocol.held_tasks(tasks))
        self.assertIn("why", tasks[0]["reason"])
        self.assertNotIn("\udfff", tasks[0]["reason"])
        self.assertEqual(tasks[1]["last_error"].count("�") > 0, True)
        self.assertTrue(line.endswith(b"\n"))

    def test_the_assignee_is_named_only_when_another_agent_does_the_work(self):
        self.kb.create("t_self", assignee="main")
        self.kb.hold("t_self")
        self.kb.create("t_other", assignee="writer")
        self.kb.hold("t_other", at=1_500)
        tasks = {t["task"]: t for t in self.board.read("main")}
        self.assertNotIn("assignee", tasks["t_self"])
        self.assertEqual(tasks["t_other"]["assignee"], "writer")

    def test_every_held_task_newest_first(self):
        for n in range(40):
            self.kb.create(f"t_{n:02}")
            self.kb.hold(f"t_{n:02}", at=10_000 + n)
        self.assertEqual([t["task"] for t in self.board.read("main")], [f"t_{n:02}" for n in range(39, -1, -1)])

    def test_the_revision_is_the_task_s_latest_event_so_a_comment_moves_it(self):
        self.kb.create("t_1")
        self.kb.hold("t_1")
        before = self.board.read("main")[0]["revision"]
        self.kb.comment("t_1")
        after = self.board.read("main")[0]["revision"]
        self.assertNotEqual(before, after)
        self.assertEqual(after, self.revision("t_1"))

    def test_long_fields_are_cut_to_the_bridge_s_bounds_and_the_title_is_one_line(self):
        self.kb.create("t_long", title="Line one\nline two " + "x" * 300, assignee="w" * 100)
        self.kb.hold("t_long", payload={"reason": "r" * 2_000}, error="e" * 3_000)
        [task] = self.board.read("main")
        self.assertTrue(task["title"].startswith("Line one line two x"))
        self.assertEqual([len(task[k]) for k in ("title", "reason", "last_error", "assignee")],
                         [200, 1_000, 2_000, 64])

    def test_an_id_the_wire_cannot_carry_is_left_out_and_said_once(self):
        for bad in ("t_\x07bell", "t_" + "x" * 200, "t_​hidden", "ops/t_1"):
            self.kb.create(bad)
            self.kb.hold(bad)
        self.kb.create("t_good")
        self.kb.hold("t_good")
        with self.assertLogs("enclos.held_tasks", "WARNING") as logs:
            self.assertEqual([t["task"] for t in self.board.read("main")], ["t_good"])
        self.assertEqual(len(logs.output), 4)
        with self.assertNoLogs("enclos.held_tasks", "WARNING"):
            self.board.read("main")

    def test_every_live_board_is_read_and_another_board_s_task_is_named_with_it(self):
        self.kb.add_board("ops")
        self.kb.create("t_1", board="ops")
        self.kb.hold("t_1", board="ops", at=3_000)
        self.kb.create("t_1")
        self.kb.hold("t_1", at=2_000)
        self.assertEqual([t["task"] for t in self.board.read("main")], ["ops/t_1", "t_1"])

    def test_a_board_pinned_to_the_same_database_is_read_once(self):
        self.kb.dbs["ops"] = self.kb.dbs["default"]
        self.kb.create("t_1")
        self.kb.hold("t_1")
        self.assertEqual([t["task"] for t in self.board.read("main")], ["t_1"])

    def test_a_task_two_boards_would_name_alike_is_listed_once(self):
        copy = Path(self.temporary.name) / "copy.db"
        self.kb.create("t_1")
        self.kb.hold("t_1")
        copy.write_bytes(self.kb.dbs["default"].read_bytes())
        listing = self.kb.list_boards
        self.kb.list_boards = lambda **_: [*listing(), {"slug": "default", "db_path": str(copy)}]
        self.assertEqual([t["task"] for t in self.board.read("main")], ["t_1"])

    def test_a_board_without_a_database_is_neither_read_nor_created(self):
        missing = Path(self.temporary.name) / "boards" / "new" / "kanban.db"
        self.kb.dbs["new"] = missing
        self.assertEqual(self.board.read("main"), [])
        self.assertFalse(missing.exists())

    def test_a_board_that_cannot_be_read_stands_as_last_read_and_the_others_are_reported(self):
        self.kb.add_board("ops")
        self.kb.create("t_ops", board="ops")
        self.kb.hold("t_ops", board="ops", at=3_000)
        self.kb.create("t_1")
        self.kb.hold("t_1")
        self.assertEqual([t["task"] for t in self.board.read("main")], ["ops/t_ops", "t_1"])
        good = self.kb.dbs["ops"].read_bytes()
        self.kb.dbs["ops"].write_bytes(b"not a database" * 100)
        self.kb.create("t_2")
        self.kb.hold("t_2", at=4_000)
        with self.assertLogs("enclos.held_tasks", "WARNING") as logs:
            self.assertEqual([t["task"] for t in self.board.read("main")], ["t_2", "ops/t_ops", "t_1"])
        self.assertIn("ops", logs.output[0])
        # Said again only after a while
        with self.assertNoLogs("enclos.held_tasks", "WARNING"):
            self.board.read("main")
        with patch.object(held_tasks, "RETELL_SECONDS", 0), self.assertLogs("enclos.held_tasks", "WARNING"):
            self.board.read("main")
        self.kb.dbs["ops"].write_bytes(good)
        with self.assertLogs("enclos.held_tasks", "WARNING") as logs:
            self.board.read("main")
        self.assertIn("reads again", logs.output[0])

    def test_boards_that_cannot_be_listed_raise(self):
        self.kb.listing_error = RuntimeError("no root")
        with self.assertRaises(RuntimeError):
            self.board.read("main")

    def test_waits_on_needs_input_without_and_with_ask(self):
        self.kb.create("t_plain")
        self.kb.hold("t_plain", payload={"reason": "Which client?", "kind": "needs_input"}, at=2_000)
        self.kb.create("t_asked")
        self.kb.hold("t_asked", payload={"reason": "Pick one", "kind": "needs_input"}, at=3_000)
        entries = self.board.read("main")
        store = asks.Asks(str(Path(self.temporary.name) / "main.sock.held-asks.json"))
        store.put("t_asked", 3_000, {"decision": "Proceed?", "blocked": "Waiting", "choices": ["Yes", "No"]})
        attached = {entry["task"]: entry for entry in store.attach(entries, 4_000)}
        self.assertEqual(attached["t_plain"]["waits_on"], "person")
        self.assertEqual(attached["t_asked"]["waits_on"], "person")
        self.assertIn("ask", attached["t_asked"])

    def test_waits_on_capability(self):
        self.kb.create("t_cap")
        self.kb.hold("t_cap", payload={"reason": "No network", "kind": "capability"})
        [entry] = self.board.read("main")
        self.assertEqual(entry["waits_on"], "team")

    def test_waits_on_dependency(self):
        self.kb.create("t_dep")
        self.kb.hold("t_dep", payload={"reason": "Waiting on upstream", "kind": "dependency"})
        [entry] = self.board.read("main")
        self.assertEqual(entry["waits_on"], "team")

    def test_waits_on_transient(self):
        self.kb.create("t_tr")
        self.kb.hold("t_tr", payload={"reason": "Rate limited", "kind": "transient"})
        [entry] = self.board.read("main")
        self.assertEqual(entry["waits_on"], "team")

    def test_waits_on_missing_kind_key(self):
        self.kb.create("t_nokind")
        self.kb.hold("t_nokind", payload={"reason": "Stopped"})
        [entry] = self.board.read("main")
        self.assertEqual(entry["waits_on"], "person")

    def test_waits_on_empty_or_non_string_kind(self):
        for name, value in (("t_null", None), ("t_empty", ""), ("t_int", 3)):
            self.kb.create(name)
            self.kb.hold(name, payload={"reason": "Stopped", "kind": value})
        got = {entry["task"]: entry["waits_on"] for entry in self.board.read("main")}
        self.assertEqual(got, {"t_null": "person", "t_empty": "person", "t_int": "person"})

    def test_waits_on_unknown_kind(self):
        self.kb.create("t_unk")
        self.kb.hold("t_unk", payload={"reason": "Stopped", "kind": "future_kind"})
        [entry] = self.board.read("main")
        self.assertEqual(entry["waits_on"], "person")

    def test_waits_on_strips_and_lowercases_kind(self):
        self.kb.create("t_padded")
        self.kb.hold("t_padded", payload={"reason": "Waiting", "kind": " Dependency "})
        [entry] = self.board.read("main")
        self.assertEqual(entry["waits_on"], "team")

    def test_waits_on_gave_up_with_and_without_carried_kind(self):
        self.kb.create("t_gu1")
        self.kb.hold("t_gu1", "gave_up", {"failures": 3, "error": "boom"})
        self.kb.create("t_gu2")
        self.kb.hold("t_gu2", "gave_up", {"failures": 3, "error": "boom", "kind": "transient"})
        got = {entry["task"]: entry["waits_on"] for entry in self.board.read("main")}
        self.assertEqual(got, {"t_gu1": "person", "t_gu2": "person"})

    def test_waits_on_loop_triaged_card(self):
        self.kb.create("t_loop_team")
        self.kb.loop("t_loop_team", payload={"reason": "Looped", "kind": "transient", "recurrences": 2, "limit": 2})
        [entry] = self.board.read("main")
        self.assertEqual(entry["waits_on"], "person")

    def test_waits_on_blocked_with_no_bound_event(self):
        self.kb.create("t_nobound", status="blocked", at=4_000)
        [entry] = self.board.read("main")
        self.assertEqual(entry["waits_on"], "person")

    def test_waits_on_report_every_entry_carries_person_or_team_and_unparseable_payload_reads_person(self):
        self.kb.create("t_team")
        self.kb.hold("t_team", payload={"reason": "Dep", "kind": "dependency"})
        self.kb.create("t_person")
        self.kb.hold("t_person", payload={"reason": "Ask", "kind": "needs_input"})
        self.kb.create("t_badjson")
        with self.kb.db() as conn, conn:
            conn.execute("UPDATE tasks SET status = 'blocked' WHERE id = 't_badjson'")
            conn.execute("INSERT INTO task_events (task_id, kind, payload, created_at) "
                         "VALUES ('t_badjson', 'blocked', '{not valid json', 3000)")
        entries = self.board.read("main")
        self.assertEqual(len(entries), 3)
        for entry in entries:
            self.assertIn(entry["waits_on"], ("person", "team"))
        by_task = {entry["task"]: entry["waits_on"] for entry in entries}
        self.assertEqual(by_task["t_badjson"], "person")

    def test_a_triage_task_is_held_only_while_the_loop_breaker_s_event_is_its_latest_move(self):
        self.kb.create("t_loop")
        self.kb.loop("t_loop", at=5_000)
        self.kb.comment("t_loop")
        # Blocked and unblocked once (Hermes keeps its block kind), then put
        # in triage by hand: a stale block history is no hold.
        self.kb.create("t_by_hand")
        self.kb.hold("t_by_hand", payload={"reason": "Old", "kind": "needs_input"})
        self.kb.move("t_by_hand", "ready", "unblocked")
        self.kb.move("t_by_hand", "triage", "status", {"status": "triage"})
        # Held, specified, then put back in triage by hand.
        self.kb.create("t_again")
        self.kb.loop("t_again")
        self.kb.move("t_again", "todo", "specified")
        self.kb.move("t_again", "triage", "status", {"status": "triage"})
        # Held, then parked in triage by an import.
        self.kb.create("t_imported")
        self.kb.loop("t_imported")
        self.kb.move("t_imported", "triage", "imported", {"board": "default", "parked": True})
        # In triage with the event, its later move out of it not followed by one back.
        self.kb.create("t_odd")
        self.kb.loop("t_odd")
        self.kb.move("t_odd", "triage", "specified")
        # In triage with no event at all.
        with self.kb.db() as conn, conn:
            conn.execute("INSERT INTO tasks VALUES ('t_bare', 'Bare', NULL, 'triage', 'main', 1000, NULL)")
        self.kb.create("t_proposal", status="triage")
        self.assertEqual(self.board.read("main"), [{
            "task": "t_loop", "title": "Write the weekly report", "reason": "Which client?", "since": 5_000,
            "revision": self.revision("t_loop"), "resume": "Decide on the agent's task board.", "resumable": False,
            "waits_on": "person"}])

    def test_a_hermes_with_no_triage_status_still_reports_its_blocked_tasks(self):
        self.kb.create("t_1")
        self.kb.hold("t_1")
        listing = self.kb.list_tasks

        def list_tasks(conn, *, status=None):
            if status not in self.kb.VALID_STATUSES:
                raise ValueError(f"status must be one of {sorted(self.kb.VALID_STATUSES)}")
            return listing(conn, status=status)

        with patch.object(self.kb, "list_tasks", list_tasks), \
                patch.object(self.kb, "VALID_STATUSES", {"todo", "ready", "running", "blocked", "done"},
                             create=True), \
                self.assertNoLogs("enclos.held_tasks", "WARNING"):
            self.assertEqual([t["task"] for t in self.board.read("main")], ["t_1"])

    def test_a_blocked_card_read_while_triage_was_named_follows_its_task_once_it_is_not(self):
        # A good reading first, while this Hermes names triage; then it no
        # longer does (VALID_STATUSES missing, or empty) and refuses to list
        # triage. The blocked card's last good reading must not stand frozen.
        for name, statuses in (("missing", StatusesHidden.MISSING), ("empty", ())):
            with self.subTest(name):
                kb = FakeKanban(Path(self.temporary.name) / name)
                kb.create("t_1")
                kb.hold("t_1", payload={"reason": "Which client?"}, at=2_000)
                facade, opened = StatusesHidden(kb, statuses), []
                board = held_tasks.Board(facade, lambda *args, **kwargs: opened.append(args))

                def reading():
                    return [{k: t[k] for k in ("task", "reason", "since", "revision", "resumable")}
                            for t in board.read("main")]

                with kb.db() as conn:
                    first_revision = "e:%d" % conn.execute("SELECT MAX(id) FROM task_events").fetchone()[0]
                self.assertEqual(reading(), [{"task": "t_1", "reason": "Which client?", "since": 2_000,
                                              "revision": first_revision, "resumable": True}])
                self.assertEqual(facade.asked, ["blocked", "triage"])

                facade.hidden, facade.asked = True, []
                if statuses is StatusesHidden.MISSING:
                    self.assertFalse(hasattr(facade, "VALID_STATUSES"))
                else:
                    self.assertEqual(facade.VALID_STATUSES, ())
                with self.assertNoLogs("enclos.held_tasks", "WARNING"):
                    # Resumed on the board, then blocked for another cause.
                    kb.move("t_1", "ready", "unblocked", at=2_500)
                    kb.hold("t_1", payload={"reason": "It needs a browser."}, at=3_000)
                    with kb.db() as conn:
                        changed_revision = "e:%d" % conn.execute(
                            "SELECT MAX(id) FROM task_events").fetchone()[0]
                    self.assertNotEqual(changed_revision, first_revision)
                    changed = reading()
                    # Then no longer held.
                    kb.move("t_1", "ready", "unblocked", at=3_500)
                    released = reading()
                self.assertEqual(changed, [{"task": "t_1", "reason": "It needs a browser.", "since": 3_000,
                                            "revision": changed_revision, "resumable": True}])
                self.assertEqual(released, [])
                self.assertEqual((facade.asked, facade.refused, opened, kb.opened),
                                 (["blocked", "blocked"], [], [], []))

    def test_a_triage_hold_says_its_kind_with_no_reason_and_nothing_with_an_unreadable_event(self):
        self.kb.create("t_kind")
        self.kb.loop("t_kind", {"reason": None, "kind": "needs_input"}, at=3_000)
        self.kb.create("t_garbled")
        self.kb.loop("t_garbled", "{not json", at=2_000)
        self.assertEqual([(t["task"], t["reason"]) for t in self.board.read("main")],
                         [("t_kind", "Needs input."), ("t_garbled", "")])

    def test_a_triage_hold_is_cut_to_the_bridge_s_bounds_and_named_with_its_board(self):
        self.kb.add_board("ops")
        self.kb.create("t_long", title="Line one\nline two " + "x" * 300, assignee="w" * 100, board="ops")
        self.kb.loop("t_long", {"reason": "r" * 2_000, "kind": "needs_input"}, board="ops")
        self.kb.create("t_long", created_by="research")
        self.kb.loop("t_long")
        [task] = self.board.read("main")
        self.assertEqual(task["task"], "ops/t_long")
        self.assertTrue(task["title"].startswith("Line one line two x"))
        self.assertEqual([len(task[k]) for k in ("title", "reason", "assignee")], [200, 1_000, 64])

    def test_reading_a_triage_hold_changes_no_board(self):
        self.kb.create("t_1")
        self.kb.loop("t_1")
        self.kb.create("t_2", status="triage")
        before = self.kb.dbs["default"].read_bytes()
        self.assertEqual(len(self.board.read("main")), 1)
        self.assertEqual((self.kb.opened, self.kb.specified), ([], []))
        self.assertEqual(self.kb.dbs["default"].read_bytes(), before)


class Resuming(FakeBoardCase):
    def setUp(self):
        super().setUp()
        self.kb.create("t_1")
        self.kb.hold("t_1")

    def resume_error(self, ref, revision, profile="main"):
        with self.assertRaises(held_tasks.HeldTaskError) as raised:
            self.board.resume(profile, ref, revision)
        return raised.exception.code

    def test_a_task_held_at_that_revision_is_unblocked(self):
        self.board.resume("main", "t_1", self.revision("t_1"))
        self.assertEqual(self.kb.status("t_1"), "ready")
        self.assertEqual(self.board.read("main"), [])

    def test_a_stale_revision_or_a_task_no_longer_held_is_a_conflict(self):
        stale = self.revision("t_1")
        self.kb.comment("t_1")
        self.assertEqual(self.resume_error("t_1", stale), "conflict")
        self.assertEqual(self.kb.status("t_1"), "blocked")
        self.board.resume("main", "t_1", self.revision("t_1"))
        self.assertEqual(self.resume_error("t_1", self.revision("t_1")), "conflict")

    def test_hermes_refusing_the_unblock_is_a_conflict(self):
        self.kb.unblock_result = False
        self.assertEqual(self.resume_error("t_1", self.revision("t_1")), "conflict")

    def test_hermes_raising_after_it_committed_the_unblock_is_a_resume(self):
        self.kb.raise_after_commit = True
        with self.assertLogs("enclos.held_tasks", "WARNING"):
            self.board.resume("main", "t_1", self.revision("t_1"))
        self.assertEqual(self.kb.status("t_1"), "ready")

    def test_hermes_raising_before_it_unblocked_is_raised(self):
        self.kb.unblock_error = RuntimeError("database is locked")
        with self.assertRaises(RuntimeError):
            self.board.resume("main", "t_1", self.revision("t_1"))
        self.assertEqual(self.kb.status("t_1"), "blocked")

    def test_another_agent_s_task_or_an_unknown_one_is_not_found(self):
        self.kb.create("t_theirs", created_by="research")
        self.kb.hold("t_theirs")
        self.assertEqual(self.resume_error("t_theirs", self.revision("t_theirs")), "not_found")
        self.assertEqual(self.kb.status("t_theirs"), "blocked")
        self.assertEqual(self.resume_error("t_nope", "e:1"), "not_found")
        self.assertEqual(self.resume_error("nowhere/t_1", self.revision("t_1")), "not_found")

    def test_another_board_s_task_is_resumed_on_that_board(self):
        self.kb.add_board("ops")
        self.kb.create("t_1", board="ops")
        self.kb.hold("t_1", board="ops")
        self.board.resume("main", "ops/t_1", self.revision("t_1", "ops"))
        self.assertEqual((self.kb.status("t_1", "ops"), self.kb.status("t_1")), ("ready", "blocked"))

    def test_a_triage_hold_is_unsupported_before_hermes_s_writer_opens_and_a_blocked_one_still_resumes(self):
        self.kb.create("t_loop")
        self.kb.loop("t_loop")
        revision = self.revision("t_loop")
        before = self.kb.dbs["default"].read_bytes()
        self.assertEqual(self.resume_error("t_loop", revision), "unsupported")
        self.assertEqual((self.kb.opened, self.kb.specified), ([], []))
        self.assertEqual(self.kb.dbs["default"].read_bytes(), before)
        self.board.resume("main", "t_1", self.revision("t_1"))
        self.assertEqual((self.kb.status("t_1"), self.kb.status("t_loop")), ("ready", "triage"))

    def test_a_triage_task_that_is_no_hold_is_a_conflict_and_nothing_is_written(self):
        self.kb.create("t_proposal", status="triage")
        self.kb.create("t_by_hand")
        self.kb.loop("t_by_hand")
        self.kb.move("t_by_hand", "todo", "specified")
        self.kb.move("t_by_hand", "triage", "status", {"status": "triage"})
        for task_id in ("t_proposal", "t_by_hand"):
            self.assertEqual(self.resume_error(task_id, self.revision(task_id)), "conflict")
            self.assertEqual(self.kb.status(task_id), "triage")
        self.assertEqual((self.kb.opened, self.kb.specified), ([], []))

    def test_a_triage_hold_is_unsupported_whatever_hermes_s_specify_would_do(self):
        # Refusing, raising before or after it committed: never reached, so
        # no answer is inferred from what the task looks like afterwards.
        self.kb.create("t_loop")
        self.kb.loop("t_loop")
        for result, error, after in ((False, None, False), (None, RuntimeError("database is locked"), False),
                                     (None, None, True)):
            self.kb.unblock_result, self.kb.unblock_error, self.kb.raise_after_commit = result, error, after
            with self.subTest(result=result, error=error, after=after):
                self.assertEqual(self.resume_error("t_loop", self.revision("t_loop")), "unsupported")
                self.assertEqual((self.kb.status("t_loop"), self.kb.opened, self.kb.specified), ("triage", [], []))


class Sent(FakeBoardCase, unittest.IsolatedAsyncioTestCase):
    """What the manager sends the bridge."""

    def setUp(self):
        super().setUp()
        self.sent: list[dict] = []
        self.connected = True
        self.failures: list[Exception] = []
        self.arrived: Optional[asyncio.Event] = None

    async def write(self, message):
        if self.failures:
            raise self.failures.pop(0)
        if not self.connected:
            return False
        self.sent.append(message)
        if self.arrived is not None:
            self.arrived.set()
        return True

    def manager(self, bridge=True, refresh_seconds=3600):
        manager = held_tasks.Manager("main", self.write, board=self.board, refresh_seconds=refresh_seconds)
        manager.bridge_supports = bridge
        return manager

    async def lists_reach(self, count):
        """Waits until `count` lists were sent."""
        self.arrived = self.arrived or asyncio.Event()
        while len(self.lists()) < count:
            self.arrived.clear()
            await asyncio.wait_for(self.arrived.wait(), 5)

    def lists(self):
        return [[t["task"] for t in m["tasks"]] for m in self.sent if m["type"] == "held_tasks"]

    async def test_the_whole_list_after_the_hello_then_only_when_it_changes(self):
        self.kb.create("t_1")
        self.kb.hold("t_1")
        manager = self.manager()
        manager.start()
        await self.lists_reach(1)
        await manager.refresh()
        self.assertEqual(self.lists(), [["t_1"]])
        self.kb.create("t_2")
        self.kb.hold("t_2", at=3_000)
        manager.poke()
        await self.lists_reach(2)
        self.assertEqual(self.lists(), [["t_1"], ["t_2", "t_1"]])
        # A new connection gets the whole list again
        manager.start()
        await self.lists_reach(3)
        self.assertEqual(self.lists()[-1], ["t_2", "t_1"])
        manager.stop()

    async def test_an_empty_list_is_sent_so_the_bridge_releases_old_cards(self):
        await self.manager().refresh()
        self.assertEqual(self.lists(), [[]])

    async def test_the_timer_reads_the_board_again(self):
        manager = self.manager(refresh_seconds=0.02)
        manager.start()
        await self.lists_reach(1)
        self.kb.create("t_1")
        self.kb.hold("t_1")
        await self.lists_reach(2)
        manager.stop()
        self.assertEqual(self.lists()[:2], [[], ["t_1"]])

    async def test_nothing_is_sent_to_a_bridge_without_the_capability(self):
        manager = self.manager(bridge=False)
        manager.start()
        await manager.refresh()
        await manager.resume(protocol.message("held_task.resume", task="t_1", revision="e:1",
                                              person="p@example.com", device="d-1"))
        self.assertEqual([(m["type"], m.get("code")) for m in self.sent], [("error", "unsupported")])

    async def test_boards_that_cannot_be_listed_send_nothing_rather_than_an_empty_list(self):
        self.kb.create("t_1")
        self.kb.hold("t_1")
        manager = self.manager()
        await manager.refresh()
        self.kb.listing_error = RuntimeError("no root")
        with self.assertLogs("enclos.held_tasks", "ERROR"):
            await manager.refresh(force=True)
        self.assertEqual(self.lists(), [["t_1"]])

    async def test_a_failure_while_sending_does_not_stop_the_reports(self):
        manager = self.manager()
        self.failures.append(UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed"))
        with self.assertLogs("enclos.held_tasks", "ERROR"):
            manager.start()
            await asyncio.sleep(0)
            for _ in range(100):
                if not self.failures:
                    break
                await asyncio.sleep(0.01)
        self.kb.create("t_1")
        self.kb.hold("t_1")
        manager.poke()
        await self.lists_reach(1)
        self.assertEqual(self.lists(), [["t_1"]])
        manager.stop()

    async def test_a_list_the_bridge_refused_is_sent_again_unless_it_could_not_read_it(self):
        manager = self.manager()
        await manager.refresh()
        manager.refused(self.sent[-1]["id"], "bad_message")
        await manager.refresh()
        self.assertEqual(len(self.lists()), 1)
        manager.refused(self.sent[-1]["id"], "internal")
        await manager.refresh()
        self.assertEqual(len(self.lists()), 2)

    async def test_past_32_the_newest_go_and_the_cut_is_said_once_per_change(self):
        for n in range(34):
            self.kb.create(f"t_{n:02}")
            self.kb.hold(f"t_{n:02}", at=10_000 + n)
        manager = self.manager()
        with self.assertLogs("enclos.held_tasks", "WARNING") as logs:
            await manager.refresh()
        self.assertIn("t_00, t_01", logs.output[0])
        self.assertEqual(self.lists()[0], [f"t_{n:02}" for n in range(33, 1, -1)])
        with self.assertNoLogs("enclos.held_tasks", "WARNING"):
            await manager.refresh(force=True)
        self.kb.create("t_99")
        self.kb.hold("t_99", at=20_000)
        with self.assertLogs("enclos.held_tasks", "WARNING"):
            await manager.refresh()

    async def test_past_32_triage_holds_and_blocked_tasks_are_cut_together_newest_first(self):
        for n in range(34):
            self.kb.create(f"t_{n:02}")
            if n % 2:
                self.kb.loop(f"t_{n:02}", at=10_000 + n)
            else:
                self.kb.hold(f"t_{n:02}", at=10_000 + n)
        manager = self.manager()
        with self.assertLogs("enclos.held_tasks", "WARNING") as logs:
            await manager.refresh()
        self.assertIn("t_00, t_01", logs.output[0])
        self.assertEqual(self.lists()[0], [f"t_{n:02}" for n in range(33, 1, -1)])
        self.assertEqual({t["resume"] for t in self.sent[0]["tasks"]}, {held_tasks.RESUME,
                                                                         held_tasks.NOT_RESUMABLE})

    async def test_a_triage_resume_answers_unsupported_whatever_this_hermes_offers(self):
        self.kb.create("t_loop")
        self.kb.loop("t_loop")
        for specify in (self.kb.specify_triage_task, None):
            with self.subTest(specify=bool(specify)), patch.object(self.kb, "specify_triage_task", specify):
                self.sent.clear()
                manager = self.manager()
                await manager.refresh()
                self.assertEqual(self.sent[0]["tasks"][0]["resume"], held_tasks.NOT_RESUMABLE)
                message = await self.resume(manager, task="t_loop", revision=self.revision("t_loop"))
                self.assertEqual([(m["type"], m.get("code"), m.get("of")) for m in self.sent[1:]],
                                 [("error", "unsupported", message["id"]), ("held_tasks", None, None)])
                self.assertIn("kanban board", self.sent[1]["message"])
                self.assertEqual(self.sent[2]["tasks"], self.sent[0]["tasks"])
                self.assertEqual((self.kb.status("t_loop"), self.kb.opened, self.kb.specified), ("triage", [], []))

    async def resume(self, manager, **fields):
        message = protocol.message("held_task.resume", person="p@example.com", device="d-1", **fields)
        await manager.resume(message)
        return message

    async def test_a_resume_answers_resumed_then_sends_a_fresh_list(self):
        self.kb.create("t_1")
        self.kb.hold("t_1")
        manager = self.manager()
        with self.assertLogs("enclos.held_tasks", "INFO") as logs:
            message = await self.resume(manager, task="t_1", revision=self.revision("t_1"))
        self.assertEqual([(m["type"], m.get("of")) for m in self.sent],
                         [("held_task.resumed", message["id"]), ("held_tasks", None)])
        self.assertEqual(self.sent[1]["tasks"], [])
        self.assertTrue(any("p@example.com" in line and "d-1" in line for line in logs.output))

    async def test_a_list_read_before_a_resume_is_never_sent_after_its_answer(self):
        self.kb.create("t_1")
        self.kb.hold("t_1")
        revision = self.revision("t_1")
        reading, release = threading.Event(), threading.Event()
        read = self.board.read

        def slow_read(profile):
            found = read(profile)
            reading.set()
            release.wait(5)
            return found

        manager = self.manager()
        with patch.object(self.board, "read", slow_read):
            refresh = asyncio.create_task(manager.refresh())
            await asyncio.to_thread(reading.wait, 5)
            resume = asyncio.create_task(self.resume(manager, task="t_1", revision=revision))
            await asyncio.sleep(0.01)
            release.set()
            await asyncio.gather(refresh, resume)
        types_ = [m["type"] for m in self.sent]
        after = self.sent[types_.index("held_task.resumed") + 1:]
        self.assertTrue(after)
        self.assertTrue(all("t_1" not in [t["task"] for t in m["tasks"]] for m in after))

    async def test_a_refused_resume_answers_its_code_then_sends_the_list_all_the_same(self):
        self.kb.create("t_1")
        self.kb.hold("t_1")
        manager = self.manager()
        message = await self.resume(manager, task="t_1", revision="e:1")
        self.assertEqual([(m["type"], m.get("code"), m.get("of")) for m in self.sent],
                         [("error", "conflict", message["id"]), ("held_tasks", None, None)])
        self.sent.clear()
        await self.resume(manager, task="t_2", revision="e:1")
        self.assertEqual([(m["type"], m.get("code")) for m in self.sent],
                         [("error", "not_found"), ("held_tasks", None)])

    async def test_hermes_failing_answers_internal_and_is_logged(self):
        self.kb.create("t_1")
        self.kb.hold("t_1")
        self.kb.unblock_error = RuntimeError("database is locked")
        manager = self.manager()
        with self.assertLogs("enclos.held_tasks", "ERROR"):
            await self.resume(manager, task="t_1", revision=self.revision("t_1"))
        self.assertEqual(self.sent[0]["code"], "internal")
        self.assertNotIn("database is locked", self.sent[0]["message"])

    async def test_hermes_failing_after_it_committed_answers_resumed(self):
        self.kb.create("t_1")
        self.kb.hold("t_1")
        self.kb.raise_after_commit = True
        manager = self.manager()
        with self.assertLogs("enclos.held_tasks", "WARNING"):
            await self.resume(manager, task="t_1", revision=self.revision("t_1"))
        self.assertEqual(self.sent[0]["type"], "held_task.resumed")

    async def test_an_answer_that_cannot_be_sent_is_logged(self):
        self.kb.create("t_1")
        self.kb.hold("t_1")
        self.connected = False
        manager = self.manager()
        with self.assertLogs("enclos.held_tasks", "WARNING") as logs:
            await self.resume(manager, task="t_1", revision=self.revision("t_1"))
        self.assertTrue(any("could not be sent" in line for line in logs.output))

    async def test_a_resume_that_fails_beside_the_connection_is_logged(self):
        manager = self.manager()

        async def broken():
            raise RuntimeError("unexpected")

        with self.assertLogs("enclos.held_tasks", "ERROR"):
            task = asyncio.create_task(broken())
            manager.track(task)
            with contextlib.suppress(RuntimeError):
                await task
            await asyncio.sleep(0)
        self.assertEqual(manager.tasks, set())


ASK = {"task": "t_1", "decision": "Which client is the report for?",
       "blocked": "The writer cannot tell which client the report is for.",
       "choices": ["Acme", "Globex"], "recommended": 0}


class AgentFirst(FakeBoardCase, unittest.IsolatedAsyncioTestCase):
    """A hold goes to the agent that created the task first (ADR 0072): one
    Hermes wakes that agent for is left out of the list until it asks."""

    def setUp(self):
        super().setUp()
        self.sent: list[dict] = []
        self.kb.create("t_1")
        self.kb.hold("t_1", payload={"reason": "Which client?", "kind": "needs_input"})
        self.manager = held_tasks.Manager("main", self.write, board=self.board, refresh_seconds=3600)
        self.manager.bridge_supports = True
        self.manager.asks = asks.Asks(str(Path(self.temporary.name) / "main.sock.held-asks.json"))

    async def write(self, message):
        self.sent.append(message)
        return True

    async def listed(self):
        """The tasks of the list the next read sends, forced."""
        await self.manager.refresh(force=True)
        tasks = self.sent[-1]["tasks"]
        self.assertTrue(all(held_tasks.WOKEN not in task for task in tasks))
        return tasks

    def ask(self):
        task, ask = asks.validate(ASK)
        self.manager.asks.put(task, self.board.read("main")[0]["since"], ask)

    async def test_a_hold_hermes_wakes_the_agent_for_is_read_but_not_sent(self):
        self.kb.subscribe("t_1")
        [task] = self.board.read("main")
        self.assertIs(task[held_tasks.WOKEN], True)
        self.assertEqual(await self.listed(), [])

    async def test_either_waking_mode_leaves_the_hold_with_the_agent(self):
        for mode in ("wake", "notify+wake"):
            with self.subTest(mode):
                self.kb.unsubscribe_all()
                self.kb.subscribe("t_1", mode=mode)
                self.assertEqual(await self.listed(), [])

    async def test_a_woken_hold_is_sent_once_the_agent_asks_and_still_once_it_is_settled(self):
        self.kb.subscribe("t_1")
        self.ask()
        [task] = await self.listed()
        self.assertEqual((task["task"], task["ask"]["decision"]), ("t_1", ASK["decision"]))
        self.manager.asks.settle("t_1", task["since"], task["title"])
        [task] = await self.listed()
        self.assertTrue(task["ask"]["settled"])

    async def test_an_answer_the_agent_reports_for_a_hold_it_never_handed_over_sends_nothing(self):
        # `enclos_person_answered` on a woken hold the agent never asked about
        # makes up a settled ask: the person never saw this hold, so no card.
        self.kb.subscribe("t_1")
        [task] = self.board.read("main")
        self.manager.asks.settle("t_1", task["since"], task["title"])
        self.assertEqual(await self.listed(), [])
        # Unwoken, the same made-up ask still answers the card the person has.
        self.kb.unsubscribe_all()
        [task] = await self.listed()
        self.assertTrue(task["ask"]["settled"])

    async def test_a_hold_no_subscription_wakes_this_agent_for_is_the_person_s(self):
        for case, subscribe in (("notify only", dict(mode="notify")),
                                ("another profile's wake", dict(profile="research")),
                                ("no profile", dict(profile=None)),
                                ("a blank profile", dict(profile=""))):
            with self.subTest(case):
                self.kb.unsubscribe_all()
                self.kb.subscribe("t_1", **subscribe)
                self.assertEqual([t["task"] for t in await self.listed()], ["t_1"])

    async def test_a_board_without_hermes_s_subscriptions_wakes_no_one(self):
        with self.kb.db() as conn, conn:
            conn.execute("DROP TABLE kanban_notify_subs")
        self.assertNotIn(held_tasks.WOKEN, self.board.read("main")[0])
        self.assertEqual([t["task"] for t in await self.listed()], ["t_1"])

    async def test_a_hold_that_becomes_woken_leaves_the_list_and_one_no_longer_woken_comes_back(self):
        self.assertEqual([t["task"] for t in await self.listed()], ["t_1"])
        self.kb.subscribe("t_1")
        self.assertEqual(await self.listed(), [])
        # Hermes drops a subscription whose wakes keep failing: the hold is the person's.
        self.kb.unsubscribe_all()
        self.assertEqual([t["task"] for t in await self.listed()], ["t_1"])

    async def test_an_ask_on_a_woken_hold_is_kept_while_the_hold_is_left_out(self):
        self.ask()
        self.kb.subscribe("t_1")
        self.kb.create("t_2")
        self.kb.hold("t_2", at=3_000)
        self.kb.subscribe("t_2")
        self.assertEqual([t["task"] for t in await self.listed()], ["t_1"])
        self.assertEqual([t["task"] for t in await self.listed()], ["t_1"])

    async def test_another_board_s_subscription_is_read_on_that_board(self):
        self.kb.add_board("ops")
        self.kb.create("t_1", board="ops")
        self.kb.hold("t_1", board="ops", at=3_000)
        self.kb.subscribe("t_1", board="ops")
        self.assertEqual([t["task"] for t in await self.listed()], ["t_1"])


@unittest.skipUnless(os.environ.get("ENCLOS_HERMES_SOURCE"), "optional real Hermes checkout")
class NativeHermesHeldTasks(unittest.TestCase):
    """Against a real Hermes, on boards in a temporary home: no dispatcher or worker runs."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        home = Path(self.temporary.name) / "hermes"
        home.mkdir()
        env = patch.dict(os.environ, {"HERMES_HOME": str(home), "HERMES_KANBAN_HOME": str(home)})
        env.start()
        self.addCleanup(env.stop)
        for pin in ("HERMES_KANBAN_DB", "HERMES_KANBAN_BOARD", "HERMES_KANBAN_TASK"):
            os.environ.pop(pin, None)
        sys.path.insert(0, os.environ["ENCLOS_HERMES_SOURCE"])
        self.addCleanup(sys.path.remove, os.environ["ENCLOS_HERMES_SOURCE"])
        self.board = held_tasks.native()
        self.kb = self.board.kb
        from hermes_cli.kanban_db_connect import connect
        self.conn = connect()
        self.addCleanup(self.conn.close)

    def held(self, title="Write the weekly report", created_by="main", assignee="writer", reason="Which client?"):
        task_id = self.kb.create_task(self.conn, title=title, assignee=assignee, created_by=created_by)
        self.assertTrue(self.kb.block_task(self.conn, task_id, reason=reason, kind="needs_input"))
        return task_id

    def latest(self, conn, task_id):
        return "e:%d" % max(event.id for event in self.kb.list_events(conn, task_id))

    def test_the_plugin_s_dispatch_hook_is_one_hermes_fires(self):
        from hermes_cli.plugins import VALID_HOOKS
        self.assertIn("on_kanban_dispatch_tick", VALID_HOOKS)

    def test_a_blocked_task_is_reported_and_resumed_with_a_fresh_retry_budget(self):
        task_id = self.held()
        self.held(title="Someone else's", created_by="research")
        [task] = self.board.read("main")
        self.assertEqual({k: task[k] for k in ("task", "title", "assignee", "reason", "revision", "resume")}, {
            "task": task_id, "title": "Write the weekly report", "assignee": "writer", "reason": "Which client?",
            "revision": self.latest(self.conn, task_id), "resume": held_tasks.RESUME})
        self.assertLessEqual(abs(task["since"] - time.time()), 60)
        self.board.resume("main", task_id, task["revision"])
        native = self.kb.get_task(self.conn, task_id)
        # The retry budget is Hermes's `consecutive_failures`, a public Task
        # field; unblock_task resets it.
        self.assertEqual((native.status, native.consecutive_failures), ("ready", 0))
        self.assertEqual(self.board.read("main"), [])

    def test_a_hermes_that_does_not_name_its_statuses_still_reports_its_blocked_tasks_as_they_change(self):
        # An older Hermes: its kanban_db has no VALID_STATUSES, and its
        # list_tasks refuses `triage`, a status it does not have. Read through
        # this Hermes's own functions otherwise, never its writer.
        real = self.kb
        statuses = frozenset(real.VALID_STATUSES) - {"triage"}
        asked, refused, told, opened = [], [], [], []

        def list_tasks(conn, *, status=None, **rest):
            asked.append(status)
            if status is not None and status not in statuses:
                refused.append(status)
                raise ValueError(f"status must be one of {sorted(statuses)}")
            return real.list_tasks(conn, status=status, **rest)

        class OlderHermes:
            def __getattr__(self, name):
                if name == "VALID_STATUSES":
                    raise AttributeError(name)
                return list_tasks if name == "list_tasks" else getattr(real, name)

        older = OlderHermes()
        self.assertFalse(hasattr(older, "VALID_STATUSES"))
        board = held_tasks.Board(older, lambda **kwargs: opened.append(kwargs))

        class Told(logging.Handler):
            def emit(self, record):
                told.append(record.getMessage())

        handler = Told(logging.WARNING)
        logging.getLogger("enclos.held_tasks").addHandler(handler)
        self.addCleanup(logging.getLogger("enclos.held_tasks").removeHandler, handler)

        def reading():
            return [{k: task[k] for k in ("task", "reason", "revision", "resume")} for task in board.read("main")]

        task_id = self.held(reason="Which client?")
        first = reading()
        first_revision = self.latest(self.conn, task_id)
        # Its hold changes: resumed on the board, then blocked for another cause.
        self.assertTrue(real.unblock_task(self.conn, task_id))
        self.assertTrue(real.block_task(self.conn, task_id, reason="It needs a browser.", kind="capability"))
        self.assertEqual(real.get_task(self.conn, task_id).status, "blocked")
        changed = reading()
        changed_revision = self.latest(self.conn, task_id)
        self.assertNotEqual(first_revision, changed_revision)
        # Then it is no longer held.
        self.assertTrue(real.unblock_task(self.conn, task_id))
        released = reading()
        self.maxDiff = None
        self.assertEqual({
            "readings": [first, changed, released], "asked": asked, "refused": refused, "told": told,
            "writer opened": opened,
        }, {
            "readings": [
                [{"task": task_id, "reason": "Which client?", "revision": first_revision,
                  "resume": held_tasks.RESUME}],
                [{"task": task_id, "reason": "It needs a browser.", "revision": changed_revision,
                  "resume": held_tasks.RESUME}],
                [],
            ],
            "asked": ["blocked"] * 3, "refused": [], "told": [], "writer opened": [],
        })

    def test_a_blocked_card_read_while_triage_was_named_follows_its_task_once_this_hermes_stops_naming_it(self):
        # This Hermes's own kanban_db, found through native(), behind a facade
        # (StatusesHidden; not a historical release) that first passes its
        # VALID_STATUSES through, then hides it (missing, or empty) and
        # refuses to list triage. The board's last good reading, made while
        # triage was named, must not stand frozen afterwards.
        import hermes_cli

        real = self.kb
        self.assertIn("triage", real.VALID_STATUSES)
        told = []

        class Told(logging.Handler):
            def emit(self, record):
                told.append(record.getMessage())

        handler = Told(logging.WARNING)
        logging.getLogger("enclos.held_tasks").addHandler(handler)
        self.addCleanup(logging.getLogger("enclos.held_tasks").removeHandler, handler)

        for name, statuses in (("missing", StatusesHidden.MISSING), ("empty", ())):
            with self.subTest(name):
                told.clear()
                facade, opened = StatusesHidden(real, statuses), []
                with patch.dict(sys.modules, {"hermes_cli.kanban_db": facade}), \
                        patch.object(hermes_cli, "kanban_db", facade):
                    board = held_tasks.native()
                self.assertIs(board.kb, facade)
                board.connect = lambda *args, **kwargs: opened.append(args)

                def reading():
                    return [{k: t[k] for k in ("task", "reason", "revision", "resume", "resumable")}
                            for t in board.read("main")]

                task_id = self.held(reason="Which client?")
                first_revision = self.latest(self.conn, task_id)
                first = reading()
                self.assertEqual(facade.asked, ["blocked", "triage"])

                facade.hidden, facade.asked = True, []
                self.assertEqual(hasattr(facade, "VALID_STATUSES"), statuses is not StatusesHidden.MISSING)
                # Resumed on the board, then blocked for another cause.
                self.assertTrue(real.unblock_task(self.conn, task_id))
                self.assertTrue(real.block_task(self.conn, task_id, reason="It needs a browser.",
                                                kind="capability"))
                changed_revision = self.latest(self.conn, task_id)
                changed = reading()
                # Then no longer held.
                self.assertTrue(real.unblock_task(self.conn, task_id))
                released = reading()
                self.maxDiff = None
                self.assertEqual({
                    "readings": [first, changed, released], "asked": facade.asked, "refused": facade.refused,
                    "told": told, "writer opened": opened,
                }, {
                    "readings": [
                        [{"task": task_id, "reason": "Which client?", "revision": first_revision,
                          "resume": held_tasks.RESUME, "resumable": True}],
                        [{"task": task_id, "reason": "It needs a browser.", "revision": changed_revision,
                          "resume": held_tasks.RESUME, "resumable": True}],
                        [],
                    ],
                    "asked": ["blocked", "blocked"], "refused": [], "told": [], "writer opened": [],
                })
                self.assertNotEqual(first_revision, changed_revision)

    def test_a_task_hermes_moved_to_triage_for_a_block_loop_is_still_held_with_its_latest_reason(self):
        # Hermes's loop breaker: blocked again for the same kind after an
        # unblock, BLOCK_RECURRENCE_LIMIT times, the task goes to `triage`
        # with a `block_loop_detected` event, not to `blocked`.
        task_id = self.kb.create_task(self.conn, title="Write the weekly report", assignee="writer",
                                      created_by="main")
        reasons = [f"Which client? (asked {n + 1} times)" for n in range(self.kb.BLOCK_RECURRENCE_LIMIT)]
        for n, reason in enumerate(reasons):
            if n:
                self.assertTrue(self.kb.unblock_task(self.conn, task_id))
            self.assertTrue(self.kb.block_task(self.conn, task_id, reason=reason, kind="needs_input"))
        self.assertEqual(self.kb.get_task(self.conn, task_id).status, "triage")
        events = self.kb.list_events(self.conn, task_id)
        [loop] = [event for event in events if event.kind == "block_loop_detected"]
        tasks = self.board.read("main")
        self.assertEqual([task["task"] for task in tasks], [task_id])
        self.assertEqual({k: tasks[0].get(k) for k in ("title", "assignee", "reason", "since", "revision")}, {
            "title": "Write the weekly report", "assignee": "writer", "reason": reasons[-1],
            "since": loop.created_at, "revision": self.latest(self.conn, task_id)})

    def looped(self, conn=None, title="Write the weekly report", created_by="main", assignee="writer",
               reason="Which client?", **create):
        """A task Hermes's loop breaker moved to `triage`: blocked for the
        same kind BLOCK_RECURRENCE_LIMIT times, each after an unblock."""
        conn = conn or self.conn
        task_id = self.kb.create_task(conn, title=title, assignee=assignee, created_by=created_by, **create)
        for n in range(self.kb.BLOCK_RECURRENCE_LIMIT):
            if n:
                self.assertTrue(self.kb.unblock_task(conn, task_id))
            self.assertTrue(self.kb.block_task(conn, task_id, reason=reason, kind="needs_input"))
        self.assertEqual(self.kb.get_task(conn, task_id).status, "triage")
        return task_id

    def test_a_triage_proposal_is_not_held_whatever_its_text_says(self):
        # A task created in triage waits to be specified, not for a person
        # to resume it; text that reads like Hermes's notice changes nothing.
        notice = "Block loop detected: blocked 2 times for needs_input. Moved to triage."
        proposal = self.kb.create_task(self.conn, title=notice, body=notice, assignee="writer",
                                       created_by="main", triage=True)
        self.kb.add_comment(self.conn, proposal, "main", notice)
        self.assertEqual(self.kb.get_task(self.conn, proposal).status, "triage")
        looped = self.looped()
        self.assertEqual([task["task"] for task in self.board.read("main")], [looped])

    def resume_error(self, ref, revision, profile="main"):
        with self.assertRaises(held_tasks.HeldTaskError) as raised:
            self.board.resume(profile, ref, revision)
        return raised.exception.code

    def tables(self, conn=None):
        """Every table of a board, row for row."""
        conn = conn or self.conn
        names = [name for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
        return {name: sorted((tuple(row) for row in conn.execute(f'SELECT * FROM "{name}"')), key=repr)
                for name in names}

    # Hermes's calls that move a task on: none is reached by a triage resume.
    NATIVE_WRITES = ("specify_triage_task", "unblock_task", "recompute_ready", "claim_task")

    def spied_resume(self, ref, revision, at_writer=None, instead=None):
        """The production `Board.resume`, with Hermes's writer and
        `NATIVE_WRITES` spied: (its error code or None, writers opened, native
        calls). `at_writer` runs as the writer opens, after the check, as a
        competing writer would; `instead` replaces native calls (still spied)."""
        opened, called = [], []
        connect = self.board.connect

        def writer(**kwargs):
            opened.append(kwargs)
            if at_writer:
                at_writer()
            return connect(**kwargs)

        def spy(name):
            native = (instead or {}).get(name) or getattr(self.kb, name)

            def call(*args, **kwargs):
                called.append(name)
                return native(*args, **kwargs)
            return call

        with patch.object(self.board, "connect", writer), \
                patch.multiple(self.kb, **{name: spy(name) for name in self.NATIVE_WRITES}):
            try:
                self.board.resume("main", ref, revision)
            except held_tasks.HeldTaskError as error:
                return error.code, opened, called
        return None, opened, called

    def test_a_task_held_in_triage_and_specified_on_its_board_is_no_longer_listed_and_waits_for_its_parent(self):
        # The app does not resume it; specified on the board, Hermes gates it
        # on its parent, and the list releases it as for any other end.
        parent = self.kb.create_task(self.conn, title="Collect the figures", created_by="main")
        task_id = self.looped(body="For the board meeting")
        self.kb.link_tasks(self.conn, parent, task_id)
        [task] = self.board.read("main")
        self.assertEqual((task["resume"], task["resumable"]), (held_tasks.NOT_RESUMABLE, False))
        kept = ("title", "body", "assignee", "created_by", "consecutive_failures")
        held = self.kb.get_task(self.conn, task_id)
        before = (self.tables(), self.kb.parent_ids(self.conn, task_id))
        self.assertEqual(self.spied_resume(task_id, task["revision"]), ("unsupported", [], []))
        self.assertEqual((self.tables(), self.kb.parent_ids(self.conn, task_id)), before)
        # Not the app: Hermes's specify, called on the board directly.
        self.assertTrue(self.kb.specify_triage_task(self.conn, task_id))
        specified = self.kb.get_task(self.conn, task_id)
        self.assertEqual(specified.status, "todo")
        self.assertEqual({k: getattr(specified, k) for k in kept}, {k: getattr(held, k) for k in kept})
        self.assertEqual(self.kb.parent_ids(self.conn, task_id), [parent])
        self.assertEqual(self.board.read("main"), [])
        self.assertTrue(self.kb.complete_task(self.conn, parent, result="done"))
        self.assertEqual(self.kb.get_task(self.conn, task_id).status, "ready")

    def test_a_task_held_in_triage_specified_on_its_board_with_no_parent_runs_again_at_once(self):
        task_id = self.looped()
        self.assertEqual(len(self.board.read("main")), 1)
        self.assertTrue(self.kb.specify_triage_task(self.conn, task_id))
        self.assertEqual(self.kb.get_task(self.conn, task_id).status, "ready")
        self.assertEqual(self.board.read("main"), [])

    def test_no_change_after_the_check_is_reached_by_a_triage_resume(self):
        # The schedules that resumed changed, newer or ordinary triage work
        # when a triage resume specified it: each change is set to run as
        # Hermes's writer opens, or inside its specify, after this module's
        # check. None runs, as nothing past the check is reached.
        ran = []

        def edit(task_id):
            ran.append("edit")
            self.assertTrue(self.kb.edit_task(self.conn, task_id, title="Newer title", body="Changed body"))

        def held_again(task_id):
            ran.append("held again")
            self.assertTrue(self.kb.specify_triage_task(self.conn, task_id))
            self.assertTrue(self.kb.block_task(self.conn, task_id, reason="A newer hold", kind="needs_input"))

        def to_triage_by_hand(task_id):
            # Hermes has no call that does it; were it reached, it would fail.
            ran.append("to triage by hand")
            self.fail("reached Hermes's writer")

        def cleared(task_id):
            ran.append("cleared")
            self.assertTrue(self.kb.specify_triage_task(self.conn, task_id))

        def archived_then_failed(task_id):
            def specify(conn, ref, **fields):
                ran.append("archived, then specify failed")
                self.assertTrue(self.kb.archive_task(self.conn, ref))
                raise RuntimeError("failed before specifying")
            return {"specify_triage_task": specify}

        def ready_failed(task_id):
            def recompute(conn, *args, **kwargs):
                ran.append("recompute failed")
                raise RuntimeError("failed to ready it")
            return {"recompute_ready": recompute}

        def failed_before_commit(task_id):
            # Hermes's own specify, failing inside its transaction before it commits.
            native = self.kb.specify_triage_task

            def specify(conn, ref, **fields):
                ran.append("specify failed before commit")

                def append_event(*args, **kwargs):
                    raise RuntimeError("failed before commit")
                with patch.object(self.kb, "_append_event", append_event):
                    return native(conn, ref, **fields)
            return {"specify_triage_task": specify}

        schedules = [("writer", edit), ("writer", held_again), ("writer", to_triage_by_hand),
                     ("writer", cleared), ("specify", archived_then_failed), ("specify", ready_failed),
                     ("specify", failed_before_commit)]
        for where, change in schedules:
            with self.subTest(change.__name__):
                task_id = self.looped()
                listed = self.board.read("main")
                [task] = [t for t in listed if t["task"] == task_id]
                before = self.tables()
                if where == "writer":
                    outcome = self.spied_resume(task_id, task["revision"], at_writer=lambda: change(task_id))
                else:
                    outcome = self.spied_resume(task_id, task["revision"], instead=change(task_id))
                kinds = {event.kind for event in self.kb.list_events(self.conn, task_id)}
                self.assertEqual({
                    "outcome": outcome, "ran": ran, "status": self.kb.get_task(self.conn, task_id).status,
                    "revision": self.latest(self.conn, task_id), "board unchanged": self.tables() == before,
                    "moved on": kinds & {"specified", "promoted", "claimed", "archived", "edited"},
                    "listed": self.board.read("main"),
                }, {
                    "outcome": ("unsupported", [], []), "ran": [], "status": "triage",
                    "revision": task["revision"], "board unchanged": True, "moved on": set(), "listed": listed,
                })

    def test_a_triage_hold_changed_before_the_check_conflicts_and_another_s_or_none_is_not_found_alike(self):
        task_id = self.looped()
        stale = self.board.read("main")[0]["revision"]
        self.assertTrue(self.kb.edit_task(self.conn, task_id, body="Changed before the check"))
        theirs = self.looped(created_by="research")
        before = self.tables()
        self.assertEqual(self.spied_resume(task_id, stale), ("conflict", [], []))
        answers = []
        for ref, revision in ((theirs, self.latest(self.conn, theirs)), ("t_none", stale)):
            with self.assertRaises(held_tasks.HeldTaskError) as raised:
                self.board.resume("main", ref, revision)
            answers.append((raised.exception.code, str(raised.exception)))
        self.assertEqual(answers[0], answers[1])
        self.assertEqual(answers[0][0], "not_found")
        self.assertEqual(self.tables(), before)
        self.assertEqual([self.kb.get_task(self.conn, t).status for t in (task_id, theirs)], ["triage", "triage"])

    def test_a_triage_resume_is_refused_unless_held_there_at_that_revision_by_this_agent(self):
        task_id = self.looped()
        stale = self.board.read("main")[0]["revision"]
        self.kb.add_comment(self.conn, task_id, "research", "Any news?")
        self.assertEqual(self.resume_error(task_id, stale), "conflict")
        proposal = self.kb.create_task(self.conn, title="An idea", created_by="main", triage=True)
        self.assertEqual(self.resume_error(proposal, self.latest(self.conn, proposal)), "conflict")
        theirs = self.looped(created_by="research")
        self.assertEqual(self.resume_error(theirs, self.latest(self.conn, theirs)), "not_found")
        for unchanged in (task_id, proposal, theirs):
            self.assertEqual(self.kb.get_task(self.conn, unchanged).status, "triage")
            self.assertNotIn("specified", [e.kind for e in self.kb.list_events(self.conn, unchanged)])

    def test_a_hermes_that_cannot_specify_says_so_and_still_resumes_a_blocked_task(self):
        class WithoutSpecify:
            def __init__(self, kb):
                self._kb = kb

            def __getattr__(self, name):
                if name == "specify_triage_task":
                    raise AttributeError(name)
                return getattr(self._kb, name)

        opened = []

        def connect(**kwargs):
            opened.append(kwargs)
            return self.board.connect(**kwargs)

        board = held_tasks.Board(WithoutSpecify(self.kb), connect)
        looped = self.looped()
        blocked = self.held()
        tasks = {task["task"]: task for task in board.read("main")}
        self.assertEqual((tasks[looped]["resume"], tasks[looped]["resumable"]), (held_tasks.NOT_RESUMABLE, False))
        self.assertEqual((tasks[blocked]["resume"], tasks[blocked]["resumable"]), (held_tasks.RESUME, True))
        before, revision, listed = self.tables(), self.latest(self.conn, looped), board.read("main")
        with self.assertRaises(held_tasks.HeldTaskError) as raised:
            board.resume("main", looped, tasks[looped]["revision"])
        self.assertEqual(raised.exception.code, "unsupported")
        kinds = {event.kind for event in self.kb.list_events(self.conn, looped)}
        self.assertEqual({
            "writers": opened, "status": self.kb.get_task(self.conn, looped).status,
            "revision": self.latest(self.conn, looped), "board unchanged": self.tables() == before,
            "moved on": kinds & {"specified", "promoted", "claimed"}, "listed": board.read("main"),
        }, {
            "writers": [], "status": "triage", "revision": revision, "board unchanged": True, "moved on": set(),
            "listed": listed,
        })
        board.resume("main", blocked, tasks[blocked]["revision"])
        self.assertEqual(self.kb.get_task(self.conn, blocked).status, "ready")

    def test_a_task_held_in_triage_is_not_resumed_from_here_even_by_a_hermes_that_can_specify(self):
        # Hermes's specify takes no revision and checks only the id and
        # `triage`, in its own transaction after this module's checks: a task
        # changed, held again or moved back to triage by hand in between would
        # be specified all the same. So the resume of a task held in triage,
        # by its creator at its current revision, answers `unsupported` before
        # Hermes's writer opens, whatever this Hermes offers.
        task_id = self.looped()
        self.assertTrue(callable(getattr(self.kb, "specify_triage_task", None)))
        [task] = self.board.read("main")
        self.assertEqual((task["task"], task["revision"]), (task_id, self.latest(self.conn, task_id)))
        opened, called = [], []
        connect = self.board.connect

        def writer(**kwargs):
            opened.append(kwargs)
            return connect(**kwargs)

        def spy(name):
            native = getattr(self.kb, name)

            def call(*args, **kwargs):
                called.append(name)
                return native(*args, **kwargs)
            return call

        def snapshot():
            tables = [name for (name,) in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
            return {table: sorted((tuple(row) for row in self.conn.execute(f'SELECT * FROM "{table}"')), key=repr)
                    for table in tables}

        before = snapshot()
        natives = ("specify_triage_task", "unblock_task", "recompute_ready", "claim_task")
        with patch.object(self.board, "connect", writer), \
                patch.multiple(self.kb, **{name: spy(name) for name in natives}):
            try:
                self.board.resume("main", task_id, task["revision"])
            except held_tasks.HeldTaskError as error:
                code = error.code
            else:
                code = None
        self.assertEqual({
            "code": code, "writers": opened, "native calls": called,
            "status": self.kb.get_task(self.conn, task_id).status, "revision": self.latest(self.conn, task_id),
            "board unchanged": snapshot() == before, "listed": self.board.read("main"),
        }, {
            "code": "unsupported", "writers": [], "native calls": [], "status": "triage",
            "revision": task["revision"], "board unchanged": True, "listed": [task],
        })

    def test_a_task_looped_again_says_its_latest_reason_and_a_comment_moves_only_the_revision(self):
        task_id = self.looped(reason="Which client?")
        # Specified on its board, as the app does not resume it.
        self.assertTrue(self.kb.specify_triage_task(self.conn, task_id))
        self.assertEqual(self.kb.get_task(self.conn, task_id).status, "ready")
        # The same kind again: Hermes kept its count, so straight to triage.
        self.assertTrue(self.kb.block_task(self.conn, task_id, reason="Which quarter?", kind="needs_input"))
        self.assertEqual(self.kb.get_task(self.conn, task_id).status, "triage")
        loops = [event for event in self.kb.list_events(self.conn, task_id) if event.kind == "block_loop_detected"]
        self.assertEqual(len(loops), 2)
        [task] = self.board.read("main")
        self.assertEqual((task["reason"], task["since"], task["revision"]),
                         ("Which quarter?", loops[-1].created_at, self.latest(self.conn, task_id)))
        self.kb.add_comment(self.conn, task_id, "research", "Q3, I think")
        [commented] = self.board.read("main")
        self.assertEqual((commented["reason"], commented["since"]), (task["reason"], task["since"]))
        self.assertNotEqual(commented["revision"], task["revision"])
        self.assertEqual(commented["revision"], self.latest(self.conn, task_id))

    def test_a_triage_hold_cleared_or_finished_on_the_board_or_another_agent_s_is_not_listed(self):
        theirs = self.looped(created_by="research")
        specified = self.looped()
        self.assertTrue(self.kb.specify_triage_task(self.conn, specified))
        finished = self.looped()
        self.assertTrue(self.kb.specify_triage_task(self.conn, finished))
        self.assertTrue(self.kb.complete_task(self.conn, finished, result="done by hand"))
        archived = self.looped()
        self.assertTrue(self.kb.archive_task(self.conn, archived))
        self.assertEqual(self.board.read("main"), [])
        self.assertEqual([task["task"] for task in self.board.read("research")], [theirs])

    def test_reading_a_triage_hold_never_opens_hermes_s_writer_or_changes_the_board(self):
        opened = []
        board = held_tasks.Board(self.kb, lambda **kwargs: opened.append(kwargs))
        self.looped()
        self.kb.create_task(self.conn, title="An idea", created_by="main", triage=True)
        self.held()

        def snapshot():
            return [self.conn.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
                    for table in ("tasks", "task_events", "task_runs", "task_comments")]

        before = [[tuple(row) for row in rows] for rows in snapshot()]
        self.assertEqual(len(board.read("main")), 2)
        self.assertEqual(len(board.read("main")), 2)
        self.assertEqual([[tuple(row) for row in rows] for rows in snapshot()], before)
        self.assertEqual(opened, [])

    def test_another_board_s_triage_hold_is_named_with_it_and_no_board_changes_on_its_resume(self):
        self.kb.create_board("ops")
        from hermes_cli.kanban_db_connect import connect
        with contextlib.closing(connect(board="ops")) as ops:
            on_ops = self.looped(ops, title="Deploy", board="ops")
            on_default = self.looped()
            listed = self.board.read("main")
            tasks = {task["task"]: task for task in listed}
            self.assertEqual(set(tasks), {f"ops/{on_ops}", on_default})
            before = (self.tables(ops), self.tables())
            self.assertEqual(self.spied_resume(f"nowhere/{on_ops}", tasks[f"ops/{on_ops}"]["revision"]),
                             ("not_found", [], []))
            self.assertEqual(self.spied_resume(f"ops/{on_ops}", tasks[f"ops/{on_ops}"]["revision"]),
                             ("unsupported", [], []))
            self.assertEqual((self.tables(ops), self.tables()), before)
            self.assertEqual(self.board.read("main"), listed)

    def test_the_manager_lists_a_triage_hold_and_answers_its_resume_unsupported(self):
        task_id = self.looped()
        proposal = self.kb.create_task(self.conn, title="An idea", created_by="main", triage=True)
        sent, asked, opened = [], [], []

        async def write(message):
            sent.append(message)
            return True

        async def run():
            manager = held_tasks.Manager("main", write, board=self.board, refresh_seconds=3600)
            manager.bridge_supports = True
            await manager.refresh()
            revision = sent[0]["tasks"][0]["revision"]
            for task in (proposal, task_id):
                asked.append(protocol.message("held_task.resume", task=task, revision=revision,
                                              person="p@example.com", device="d-1"))
                await manager.resume(asked[-1])

        before = self.tables()
        with patch.object(self.board, "connect", lambda **kwargs: opened.append(kwargs)):
            asyncio.run(run())
        self.assertEqual([(m["type"], m.get("code"), m.get("of")) for m in sent], [
            ("held_tasks", None, None), ("error", "conflict", asked[0]["id"]), ("held_tasks", None, None),
            ("error", "unsupported", asked[1]["id"]), ("held_tasks", None, None)])
        self.assertEqual([m["tasks"] for m in sent if m["type"] == "held_tasks"], [sent[0]["tasks"]] * 3)
        self.assertEqual([t["task"] for t in sent[0]["tasks"]], [task_id])
        self.assertEqual((sent[0]["tasks"][0]["resume"], sent[0]["tasks"][0]["resumable"]),
                         (held_tasks.NOT_RESUMABLE, False))
        self.assertEqual((opened, self.tables() == before), ([], True))
        self.assertEqual([self.kb.get_task(self.conn, t).status for t in (task_id, proposal)], ["triage", "triage"])

    def test_a_stale_revision_is_a_conflict_and_another_agent_s_task_is_not_found(self):
        task_id = self.held()
        stale = self.board.read("main")[0]["revision"]
        self.kb.add_comment(self.conn, task_id, "research", "Any news?")
        with self.assertRaises(held_tasks.HeldTaskError) as raised:
            self.board.resume("main", task_id, stale)
        self.assertEqual(raised.exception.code, "conflict")
        self.assertEqual(self.kb.get_task(self.conn, task_id).status, "blocked")
        theirs = self.held(created_by="research")
        with self.assertRaises(held_tasks.HeldTaskError) as raised:
            self.board.resume("main", theirs, self.latest(self.conn, theirs))
        self.assertEqual(raised.exception.code, "not_found")
        self.assertEqual(self.kb.get_task(self.conn, theirs).status, "blocked")

    def test_a_task_the_dispatcher_gave_up_on_says_so(self):
        task_id = self.kb.create_task(self.conn, title="Fetch the feed", assignee="main", created_by="main",
                                      max_retries=1)
        # Hermes has no public call that makes the dispatcher give up: its own
        # failure recorder is the one path that writes a `gave_up` event.
        from hermes_cli.kanban_db_dispatch import _record_task_failure
        self.assertTrue(_record_task_failure(self.conn, task_id, "rate limited", outcome="crashed"))
        [task] = self.board.read("main")
        self.assertEqual((task["reason"], task["last_error"]), ("Gave up after 1 consecutive failure.",
                                                                "rate limited"))
        self.assertNotIn("assignee", task)

    def test_another_board_s_task_is_named_with_it_and_resumed_there(self):
        self.kb.create_board("ops")
        from hermes_cli.kanban_db_connect import connect
        with contextlib.closing(connect(board="ops")) as ops:
            task_id = self.kb.create_task(ops, title="Deploy", created_by="main", board="ops")
            self.assertTrue(self.kb.block_task(ops, task_id, reason="Approve the window?", kind="needs_input"))
            [task] = self.board.read("main")
            self.assertEqual(task["task"], f"ops/{task_id}")
            self.board.resume("main", task["task"], self.latest(ops, task_id))
            self.assertEqual(self.kb.get_task(ops, task_id).status, "ready")

    def test_reading_never_creates_a_board_s_database(self):
        self.kb.create_board("empty")
        database = Path(self.kb.list_boards(include_archived=False)[-1]["db_path"])
        database.unlink()
        for sidecar in ("-wal", "-shm"):
            Path(f"{database}{sidecar}").unlink(missing_ok=True)
        self.held()
        self.assertEqual(len(self.board.read("main")), 1)
        self.assertFalse(database.exists())

    def test_a_hold_hermes_wakes_the_agent_for_is_not_sent_until_it_asks(self):
        try:
            from hermes_cli.kanban_db_notify import add_notify_sub
        except ImportError:
            add_notify_sub = getattr(self.kb, "add_notify_sub", None)
        if not callable(add_notify_sub):
            self.skipTest("this Hermes has no add_notify_sub")
        woken = self.held()
        told = self.held(title="Check the invoices")
        # As Hermes subscribes the chat a task was asked from (its kanban tool's
        # `_maybe_auto_subscribe`): `notify+wake` for the asking profile.
        add_notify_sub(self.conn, task_id=woken, platform="enclos", chat_id="main-home", notifier_profile="main",
                       delivery_mode="notify+wake")
        add_notify_sub(self.conn, task_id=told, platform="enclos", chat_id="main-home", notifier_profile="main",
                       delivery_mode="notify")
        read = {task["task"]: task.get(held_tasks.WOKEN, False) for task in self.board.read("main")}
        self.assertEqual(read, {woken: True, told: False})
        sent = []

        async def write(message):
            sent.append(message)
            return True

        async def run():
            manager = held_tasks.Manager("main", write, board=self.board, refresh_seconds=3600)
            manager.bridge_supports = True
            await manager.refresh()

        asyncio.run(run())
        self.assertEqual([t["task"] for t in sent[0]["tasks"]], [told])

    def test_the_manager_sends_the_list_and_answers_a_resume(self):
        task_id = self.held()
        sent = []

        async def write(message):
            sent.append(message)
            return True

        async def run():
            manager = held_tasks.Manager("main", write, board=self.board, refresh_seconds=3600)
            manager.bridge_supports = True
            await manager.refresh()
            revision = sent[0]["tasks"][0]["revision"]
            await manager.resume(protocol.message("held_task.resume", task=task_id, revision=revision,
                                                  person="p@example.com", device="d-1"))

        asyncio.run(run())
        self.assertEqual([m["type"] for m in sent], ["held_tasks", "held_task.resumed", "held_tasks"])
        self.assertEqual([[t["task"] for t in m["tasks"]] for m in (sent[0], sent[2])], [[task_id], []])


if __name__ == "__main__":
    unittest.main()
