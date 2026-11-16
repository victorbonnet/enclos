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
from enclos import held_tasks, protocol  # noqa: E402


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
"""


class FakeKanban:
    """What the plugin uses of Hermes's `hermes_cli.kanban_db`, over SQLite."""

    DEFAULT_BOARD = "default"
    SCHEMA_SQL = SCHEMA
    Task = Task

    def __init__(self, root: Path):
        self.root = root
        self.dbs: dict[str, Path] = {}
        # The databases Hermes's writer (`connect`) opened.
        self.opened: list[Path] = []
        self.unblock_result: Optional[bool] = None
        self.unblock_error: Optional[Exception] = None
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

    def comment(self, task_id, board="default"):
        with self.db(board) as conn, conn:
            self._event(conn, task_id, "commented", {"author": "someone"})

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
            "since": 5_000, "revision": self.revision("t_mine"), "resume": held_tasks.RESUME,
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
