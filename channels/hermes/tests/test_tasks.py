"""Tasks and agent activity (docs/protocol.md, Tasks and agent activity): a
scratch board with only the columns the plugin reads, and optionally a board
a real Hermes checkout makes, in temporary homes only.

ENCLOS_HERMES_SOURCE=/path/to/hermes-agent python3 -m unittest discover ...
"""

import asyncio
import contextlib
import json
import os
import sqlite3
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enclos import protocol, tasks

NOW = 1_800_000_000
DAY = 24 * 3600

SCHEMA = """
CREATE TABLE tasks (id TEXT PRIMARY KEY, title TEXT, assignee TEXT, status TEXT, created_by TEXT,
                    created_at INTEGER, started_at INTEGER, completed_at INTEGER, result TEXT);
CREATE TABLE task_events (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT, kind TEXT, created_at INTEGER);
CREATE TABLE kanban_notify_subs (task_id TEXT, platform TEXT, chat_id TEXT, created_at INTEGER);
"""


class Scratch:
    """A board database with what the plugin reads of Hermes's."""

    def __init__(self, folder):
        self.path = os.path.join(folder, f"kanban-{len(os.listdir(folder))}.db")
        with contextlib.closing(sqlite3.connect(self.path)) as conn:
            conn.executescript(SCHEMA)

    def run(self, sql, *args):
        with contextlib.closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute(sql, args)

    def task(self, task_id, status="ready", assignee="engineer", title="Write the report", created_at=NOW - 100,
             **fields):
        row = {"id": task_id, "title": title, "assignee": assignee, "status": status, "created_at": created_at,
               "created_by": None, "started_at": None, "completed_at": None, "result": None, **fields}
        self.run(f"INSERT INTO tasks ({','.join(row)}) VALUES ({','.join('?' * len(row))})", *row.values())
        self.event(task_id, "created", created_at)

    def event(self, task_id, kind, at):
        self.run("INSERT INTO task_events (task_id, kind, created_at) VALUES (?, ?, ?)", task_id, kind, at)

    def set(self, task_id, **fields):
        for key, value in fields.items():
            self.run(f"UPDATE tasks SET {key} = ? WHERE id = ?", value, task_id)


class BoardTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.scratch = Scratch(self.folder)
        self.board = tasks.Board("engineer", lambda: [self.scratch.path], "enclos")

    def read(self):
        return {t["id"]: t for t in self.board.read("engineer")[1]}

    def test_each_hermes_status_is_a_state(self):
        expected = {"triage": "queued", "todo": "queued", "scheduled": "queued", "ready": "queued",
                    "running": "running", "blocked": "blocked", "review": "blocked", "done": "done"}
        for status in (*expected, "archived", "a-later-one"):
            self.scratch.task(f"t-{status}", status)
        found = self.read()
        self.assertEqual({k: t["state"] for k, t in found.items()}, {f"t-{s}": v for s, v in expected.items()})

    def test_a_task_carries_its_assignee_requester_and_result(self):
        self.scratch.task("t-1", "done", created_by="main", completed_at=NOW - 10, result="All\nfine")
        self.assertEqual(self.read()["t-1"], {
            "id": "t-1", "title": "Write the report", "assignee": "engineer", "asked_by": "main",
            "state": "done", "since": NOW - 10, "summary": "All fine"})

    def test_another_profiles_task_is_not_its(self):
        self.scratch.task("t-1", assignee="reviewer")
        self.assertEqual(self.read(), {})

    def test_a_retry_after_a_crash_is_queued_again_since_it_went_back(self):
        self.scratch.task("t-1", "running", started_at=NOW - 90)
        self.scratch.event("t-1", "claimed", NOW - 90)
        self.assertEqual((self.read()["t-1"]["state"], self.read()["t-1"]["since"]), ("running", NOW - 90))
        self.scratch.set("t-1", status="ready")
        self.scratch.event("t-1", "reclaimed", NOW - 50)
        self.assertEqual((self.read()["t-1"]["state"], self.read()["t-1"]["since"]), ("queued", NOW - 50))
        # Claimed again: running since this claim, not Hermes's first `started_at`
        self.scratch.set("t-1", status="running")
        self.scratch.event("t-1", "claimed", NOW - 20)
        self.assertEqual((self.read()["t-1"]["state"], self.read()["t-1"]["since"]), ("running", NOW - 20))

    def test_since_falls_back_to_the_row_without_events(self):
        self.scratch.task("t-1", "blocked")
        self.scratch.run("DELETE FROM task_events")
        self.assertEqual(self.read()["t-1"]["since"], NOW - 100)

    def test_the_conversation_is_its_enclos_subscription(self):
        for task_id, platform, chat_id in (("t-1", "enclos", "c-1"), ("t-2", "telegram", "12345"),
                                           ("t-3", "enclos", "c" * 129), ("t-4", "enclos", "c-4\n")):
            self.scratch.task(task_id)
            self.scratch.run("INSERT INTO kanban_notify_subs VALUES (?, ?, ?, ?)", task_id, platform, chat_id, NOW)
        self.scratch.task("t-5")
        found = self.read()
        self.assertEqual({k: t.get("conversation") for k, t in found.items()},
                         {"t-1": "c-1", "t-2": None, "t-3": None, "t-4": None, "t-5": None})

    def test_an_id_or_title_the_bridge_refuses_is_left_out_and_text_is_cut(self):
        self.scratch.task("t" * 129)
        self.scratch.task("t-\x07")
        self.scratch.task("t-\u200b")
        self.scratch.task(" ")
        self.scratch.task("t-blank", title=" \n ")
        self.scratch.task("t-long", "done", title="x" * 300, result="y" * 900)
        found = self.read()
        self.assertEqual(list(found), ["t-long"])
        self.assertEqual((len(found["t-long"]["title"]), len(found["t-long"]["summary"])), (120, 500))

    def test_every_board_is_read_newest_first(self):
        other = Scratch(self.folder)
        self.board = tasks.Board("engineer", lambda: [self.scratch.path, other.path], "enclos")
        self.scratch.task("t-old", created_at=NOW - 300)
        other.task("t-new", created_at=NOW - 10)
        self.scratch.task("t-middle", created_at=NOW - 100)
        self.assertEqual([t["id"] for t in self.board.read("engineer")[1]], ["t-new", "t-middle", "t-old"])

    def test_the_cursor_moves_with_the_event_log(self):
        before = self.board.cursor()
        self.scratch.task("t-1")
        self.assertNotEqual(self.board.cursor(), before)

    def test_the_board_is_opened_read_only(self):
        with contextlib.closing(tasks.Board._open(self.scratch.path)) as conn:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("DELETE FROM tasks")


class ListTest(unittest.TestCase):
    def task(self, n, state="queued", since=NOW):
        return {"id": f"t-{n}", "title": "x", "assignee": "engineer", "state": state, "since": since}

    def test_an_ended_task_is_listed_for_three_days(self):
        found = [self.task(1, "done", NOW - 3 * DAY), self.task(2, "done", NOW - 3 * DAY - 1),
                 self.task(3, "queued", NOW - 30 * DAY), self.task(4, "blocked", NOW - 30 * DAY)]
        self.assertEqual([t["id"] for t in tasks.listed(found, NOW)], ["t-1", "t-3", "t-4"])

    def test_at_most_a_hundred_the_newest(self):
        found = [self.task(n) for n in range(150)]
        self.assertEqual(tasks.listed(found, NOW), found[:100])


class Sent:
    """What the reporter writes, as the bridge would read it."""

    def __init__(self):
        self.messages = []

    async def __call__(self, message):
        self.messages.append(json.loads(protocol.encode_line(message)))
        return True

    def take(self):
        taken, self.messages = self.messages, []
        return [(m["type"], m.get("doing", m.get("tasks", m.get("task")))) for m in taken]


class ReporterTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.scratch = Scratch(tempfile.mkdtemp())
        self.sent = Sent()
        self.reporter = tasks.Reporter("engineer", self.sent,
                                       tasks.Board("engineer", lambda: [self.scratch.path], "enclos"))
        self.reporter.bridge = frozenset({"activity", "tasks"})

    async def watch_once(self):
        """One look at the board, as the watch does after each poll."""
        cursor = self.reporter.board.cursor()
        if cursor != self.reporter._cursor and await self.reporter._refresh(whole=False):
            await self.reporter._send_activity()

    def test_tasks_is_announced_only_with_a_board(self):
        self.assertEqual(self.reporter.capabilities, ("activity", "tasks"))
        self.assertEqual(tasks.Reporter("engineer", self.sent).capabilities, ("activity",))

    async def test_an_idle_agent_says_so_after_the_hello(self):
        await self.reporter.connected()
        self.assertEqual(self.sent.messages[-1]["type"], "agent.activity")
        self.assertEqual((self.sent.messages[-1]["doing"], self.sent.messages[-1]["since"]), ([], 0))
        self.assertEqual(self.sent.take(), [("tasks", []), ("agent.activity", [])])

    async def test_activity_lists_its_answers_and_running_tasks(self):
        self.scratch.task("t-1", "running")
        self.scratch.task("t-2", "ready")
        await self.reporter.connected()
        self.sent.take()
        await self.reporter.answering("c-1", True)
        await self.reporter.answering("c-1", True)  # Hermes repeats it every 2 s
        [message] = self.sent.messages
        self.assertEqual(message["doing"], [{"kind": "answering", "conversation": "c-1"},
                                            {"kind": "task", "task": "t-1"}])
        self.assertGreater(message["since"], 0)
        self.sent.take()
        await self.reporter.answering("c-1", False)
        self.scratch.set("t-1", status="done")
        self.scratch.event("t-1", "completed", NOW)
        await self.watch_once()
        self.assertEqual([m for m in self.sent.messages if m["type"] == "agent.activity"][-1]["since"], 0)

    async def test_the_hello_gets_the_whole_list(self):
        self.scratch.task("t-1", "running", created_at=NOW - 50)
        self.scratch.task("t-2", "ready", created_at=NOW - 10)
        await self.reporter.connected()
        self.assertEqual([t["id"] for t in self.sent.messages[0]["tasks"]], ["t-2", "t-1"])

    async def test_a_change_is_one_update_and_an_archived_task_a_new_list(self):
        self.scratch.task("t-1", "ready")
        self.scratch.task("t-2", "ready")
        await self.reporter.connected()
        self.sent.take()
        await self.watch_once()
        self.assertEqual(self.sent.take(), [])  # nothing changed
        self.scratch.set("t-1", status="blocked")
        self.scratch.event("t-1", "blocked", NOW)
        await self.watch_once()
        [(kind, task)] = self.sent.take()
        self.assertEqual((kind, task["id"], task["state"]), ("task.update", "t-1", "blocked"))
        self.scratch.set("t-2", status="archived")
        self.scratch.event("t-2", "archived", NOW)
        await self.watch_once()
        [(kind, listed)] = self.sent.take()
        self.assertEqual((kind, [t["id"] for t in listed]), ("tasks", ["t-1"]))

    async def test_a_bridge_without_the_capabilities_gets_neither(self):
        self.scratch.task("t-1", "running")
        self.reporter.bridge = frozenset()
        await self.reporter.connected()
        await self.reporter.answering("c-1", True)
        self.assertEqual(self.sent.messages, [])
        self.reporter.bridge = frozenset({"activity"})
        await self.reporter.connected()
        self.assertEqual([m["type"] for m in self.sent.messages], ["agent.activity"])

    async def test_a_board_it_cannot_read_reports_nothing_and_is_said_once(self):
        self.scratch.task("t-1")
        await self.reporter.connected()
        self.sent.take()
        Path(self.scratch.path).write_bytes(b"not a database")
        with self.assertLogs("enclos.tasks", "WARNING") as logs:
            await self.reporter.connected()
            await self.reporter._refresh(whole=False)
        self.assertEqual(len(logs.output), 1)
        self.assertEqual(self.sent.take(), [("agent.activity", [])])

    async def test_a_hook_cue_reads_the_board_before_the_poll(self):
        await self.reporter.connected()
        self.sent.take()
        self.reporter.start()
        try:
            self.scratch.task("t-1", "running")
            self.reporter.cue()
            for _ in range(100):
                if self.sent.messages:
                    break
                await asyncio.sleep(0.02)
        finally:
            await self.reporter.stop()
        self.assertEqual([k for k, _ in self.sent.take()], ["task.update", "agent.activity"])


class HermesBoardTest(unittest.TestCase):
    def test_a_hermes_without_a_board_has_no_tasks(self):
        with patch.dict(sys.modules, {"hermes_cli": None, "hermes_cli.kanban_db": None}):
            self.assertIsNone(tasks.hermes_board(Path("/home/agent/.hermes"), "enclos"))
        old = types.ModuleType("hermes_cli.kanban_db")
        old.list_tasks = lambda *a, **k: []  # no list_boards
        package = types.ModuleType("hermes_cli")
        package.kanban_db = old
        constants = types.ModuleType("hermes_constants")
        constants.profile_name_for_home = lambda home: "engineer"
        with patch.dict(sys.modules, {"hermes_cli": package, "hermes_cli.kanban_db": old,
                                      "hermes_constants": constants}):
            self.assertIsNone(tasks.hermes_board(Path("/home/agent/.hermes"), "enclos"))


@unittest.skipUnless(os.environ.get("ENCLOS_HERMES_SOURCE"), "optional real Hermes checkout")
class RealHermesBoardTest(unittest.TestCase):
    """A board Hermes's own functions make, read by the plugin: the columns and
    tables it reads are Hermes's, and its statuses come out as the protocol's."""

    def setUp(self):
        sys.path.insert(0, os.environ["ENCLOS_HERMES_SOURCE"])
        self.addCleanup(sys.path.remove, os.environ["ENCLOS_HERMES_SOURCE"])
        self.root = Path(tempfile.mkdtemp())
        self.home = self.root / "profiles" / "engineer"
        self.home.mkdir(parents=True)
        environment = patch.dict(os.environ, {"HERMES_HOME": str(self.home), "HERMES_KANBAN_HOME": str(self.root)})
        environment.start()
        self.addCleanup(environment.stop)
        for name in ("HERMES_KANBAN_DB", "HERMES_KANBAN_BOARD"):
            os.environ.pop(name, None)

    def test_the_plugin_reads_what_hermes_writes(self):
        from hermes_cli import kanban_db as kb
        from hermes_cli.kanban_db_connect import connect
        from hermes_cli.kanban_db_notify import add_notify_sub
        with contextlib.closing(connect()) as conn:
            done = kb.create_task(conn, title="Write the report", assignee="engineer", created_by="main")
            add_notify_sub(conn, task_id=done, platform="enclos", chat_id="c-1")
            kb.claim_task(conn, done)
            kb.complete_task(conn, done, result="All done")
            blocked = kb.create_task(conn, title="Ask first", assignee="engineer")
            kb.claim_task(conn, blocked)
            kb.block_task(conn, blocked, reason="needs input")
            archived = kb.create_task(conn, title="Never mind", assignee="engineer")
            kb.archive_task(conn, archived)
            kb.create_task(conn, title="Not mine", assignee="reviewer")
        kb.create_board("side")
        with contextlib.closing(connect(board="side")) as conn:
            running = kb.create_task(conn, title="On the side", assignee="engineer")
            kb.claim_task(conn, running)
        board = tasks.hermes_board(self.home, "enclos")
        self.assertIsNotNone(board)
        _, found = board.read("engineer")
        by_id = {t["id"]: t for t in found}
        self.assertEqual({k: t["state"] for k, t in by_id.items()},
                         {done: "done", blocked: "blocked", running: "running"})
        self.assertEqual((by_id[done]["conversation"], by_id[done]["asked_by"], by_id[done]["summary"]),
                         ("c-1", "main", "All done"))
        self.assertTrue(all(t["since"] > 0 and t["assignee"] == "engineer" for t in found))


if __name__ == "__main__":
    unittest.main()
