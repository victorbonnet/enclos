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
CREATE TABLE tasks (id TEXT PRIMARY KEY, title TEXT, body TEXT, assignee TEXT, status TEXT, created_by TEXT,
                    created_at INTEGER, started_at INTEGER, completed_at INTEGER, result TEXT);
CREATE TABLE task_events (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT, kind TEXT, payload TEXT,
                          created_at INTEGER);
CREATE TABLE kanban_notify_subs (task_id TEXT, platform TEXT, chat_id TEXT, created_at INTEGER);
CREATE TABLE task_comments (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT, author TEXT, body TEXT,
                            created_at INTEGER);
CREATE TABLE task_links (parent_id TEXT, child_id TEXT);
CREATE TABLE task_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT, profile TEXT, started_at INTEGER,
                        ended_at INTEGER, outcome TEXT, summary TEXT, error TEXT);
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

    def event(self, task_id, kind, at, payload=None):
        self.run("INSERT INTO task_events (task_id, kind, payload, created_at) VALUES (?, ?, ?, ?)", task_id, kind,
                 json.dumps(payload) if payload is not None else None, at)

    def comment(self, task_id, author, body, at):
        self.run("INSERT INTO task_comments (task_id, author, body, created_at) VALUES (?, ?, ?, ?)",
                 task_id, author, body, at)

    def link(self, parent, child):
        self.run("INSERT INTO task_links (parent_id, child_id) VALUES (?, ?)", parent, child)

    def attempt(self, task_id, profile, started, ended=None, outcome=None, summary=None, error=None):
        self.run("INSERT INTO task_runs (task_id, profile, started_at, ended_at, outcome, summary, error)"
                 " VALUES (?, ?, ?, ?, ?, ?, ?)", task_id, profile, started, ended, outcome, summary, error)

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
            "state": "done", "since": NOW - 10, "summary": "All fine", "comments": 0})

    def test_a_task_counts_its_comments(self):
        self.scratch.task("t-1")
        self.scratch.comment("t-1", "lead", "Go", NOW - 5)
        self.scratch.comment("t-1", "engineer", "On it", NOW - 4)
        self.scratch.comment("t-2", "lead", "Another task's", NOW - 3)
        self.assertEqual(self.read()["t-1"]["comments"], 2)

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

    def test_a_cell_of_invalid_utf8_does_not_stop_the_reading(self):
        self.scratch.task("t-1")
        self.scratch.task("t-2", "done", created_at=NOW - 50)
        self.scratch.run("UPDATE tasks SET title = CAST(x'ff' AS TEXT) || ' report' WHERE id = 't-1'")
        # A BLOB cell is text too, not b'...'.
        self.scratch.run("UPDATE tasks SET result = x'416c6c20ff66696e65' WHERE id = 't-2'")
        found = self.read()
        self.assertEqual(found["t-1"]["title"], "� report")
        self.assertEqual(found["t-2"]["summary"], "All �fine")

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


class DetailTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.scratch = Scratch(self.folder)
        self.board = tasks.Board("engineer", lambda: [self.scratch.path], "enclos")

    def test_the_body_keeps_its_lines_and_the_related_tasks_their_state(self):
        self.scratch.task("t-1", "running", body="Fix the threads.\r\n\nThen reply.  \n", created_by="lead")
        self.scratch.task("t-0", "done", assignee="pm", title="Shared\ncontract")
        self.scratch.task("t-2", "todo", assignee="reviewer", title="Review it")
        self.scratch.task("t-3", "archived", assignee="", title="Old")
        self.scratch.link("t-0", "t-1")
        self.scratch.link("t-1", "t-2")
        self.scratch.link("t-1", "t-3")
        detail = self.board.detail("t-1")
        self.assertEqual(detail["body"], "Fix the threads.\n\nThen reply.")
        self.assertEqual(detail["related"], [
            {"id": "t-0", "title": "Shared contract", "relation": "parent", "state": "done", "assignee": "pm"},
            {"id": "t-2", "title": "Review it", "relation": "child", "state": "queued", "assignee": "reviewer"},
            {"id": "t-3", "title": "Old", "relation": "child"}])

    def test_the_newest_comments_come_oldest_first_with_their_total(self):
        self.scratch.task("t-1")
        for n in range(25):
            self.scratch.comment("t-1", "lead" if n % 2 else "default", f"note {n}\nsecond line", NOW - 100 + n)
        self.scratch.comment("t-1", "lead", "  \n ", NOW)
        detail = self.board.detail("t-1")
        self.assertEqual(len(detail["comments"]), tasks.MAX_COMMENTS - 1)
        self.assertEqual(detail["comments"][0], {"author": "default", "time": NOW - 94, "text": "note 6\nsecond line"})
        self.assertEqual(detail["comments_total"], 26)

    def test_the_history_is_its_attempts_and_the_events_a_person_reads(self):
        self.scratch.task("t-1", "running", created_by="lead", created_at=NOW - 100)
        self.scratch.event("t-1", "dependency_wait", NOW - 90, {"reason": None, "kind": "dependency"})
        self.scratch.event("t-1", "promoted", NOW - 80)
        self.scratch.event("t-1", "claimed", NOW - 70)
        self.scratch.event("t-1", "heartbeat", NOW - 65)
        self.scratch.attempt("t-1", "engineer", NOW - 70, NOW - 60, "crashed", error="worker exited 1")
        self.scratch.event("t-1", "blocked", NOW - 50, {"reason": "Needs the API key", "actor": "engineer"})
        self.scratch.event("t-1", "unblocked", NOW - 40)
        self.scratch.attempt("t-1", "engineer", NOW - 30, NOW - 20, "a-later-end", summary="Half done")
        self.scratch.attempt("t-1", "engineer", NOW - 10)
        self.assertEqual(self.board.detail("t-1")["history"], [
            {"kind": "created", "time": NOW - 100, "by": "lead"},
            {"kind": "blocked", "time": NOW - 90, "text": tasks.WAITS_FOR_TASKS},
            {"kind": "attempt", "time": NOW - 70, "until": NOW - 60, "outcome": "crashed", "by": "engineer",
             "text": "worker exited 1"},
            {"kind": "blocked", "time": NOW - 50, "by": "engineer", "text": "Needs the API key"},
            {"kind": "unblocked", "time": NOW - 40},
            {"kind": "attempt", "time": NOW - 30, "until": NOW - 20, "by": "engineer", "text": "Half done"},
            {"kind": "attempt", "time": NOW - 10, "by": "engineer"}])

    def test_within_one_second_the_history_keeps_the_boards_order(self):
        # Hermes names each attempt's run on its events: an attempt takes its
        # place at its run's first one.
        self.scratch.run("ALTER TABLE task_events ADD COLUMN run_id INTEGER")
        self.scratch.task("t-1", "running", created_at=NOW)
        self.scratch.attempt("t-1", "engineer", NOW, NOW, "blocked", summary="Needs the key")
        self.scratch.attempt("t-1", "engineer", NOW)
        for kind, run in (("claimed", 1), ("blocked", 1), ("unblocked", None), ("claimed", 2)):
            self.scratch.run("INSERT INTO task_events (task_id, kind, created_at, run_id) VALUES (?, ?, ?, ?)",
                             "t-1", kind, NOW, run)
        self.assertEqual([(e["kind"], e.get("outcome")) for e in self.board.detail("t-1")["history"]], [
            ("created", None), ("attempt", "blocked"), ("blocked", None), ("unblocked", None), ("attempt", None)])

    def test_retries_running_out_show_as_a_block_saying_why(self):
        # As Hermes's dispatcher does: the timed-out run keeps its outcome,
        # then `_record_task_failure` blocks the task and writes only
        # `gave_up`, with the error and not a reason.
        self.scratch.run("ALTER TABLE task_events ADD COLUMN run_id INTEGER")
        self.scratch.task("t-1", "blocked", created_at=NOW - 100)
        self.scratch.attempt("t-1", "engineer", NOW - 90, NOW - 30, "timed_out", error="no heartbeat for 60s")
        self.scratch.run("INSERT INTO task_events (task_id, kind, created_at, run_id) VALUES (?, ?, ?, ?)",
                         "t-1", "claimed", NOW - 90, 1)
        self.scratch.run("INSERT INTO task_events (task_id, kind, created_at, run_id) VALUES (?, ?, ?, ?)",
                         "t-1", "timed_out", NOW - 30, 1)
        self.scratch.event("t-1", "gave_up", NOW - 30, {"failures": 2, "error": "no heartbeat\nfor 60s",
                                                         "trigger_outcome": "timed_out"})
        self.scratch.event("t-1", "gave_up", NOW - 20, {"failures": 1})
        self.scratch.event("t-1", "gave_up", NOW - 10, {})
        history = self.board.detail("t-1")["history"]
        self.assertEqual([(e["kind"], e.get("outcome"), e.get("text")) for e in history], [
            ("created", None, None),
            ("attempt", "timed_out", "no heartbeat for 60s"),
            ("blocked", None, "Stopped retrying after 2 failed attempts: no heartbeat for 60s"),
            ("blocked", None, "Stopped retrying after 1 failed attempt"),
            ("blocked", None, "Stopped retrying")])

    def test_only_the_profiles_own_task_is_read(self):
        self.scratch.task("t-1", assignee="reviewer")
        self.scratch.task("t-2", "archived")
        self.assertIsNone(self.board.detail("t-1"))
        self.assertIsNone(self.board.detail("t-2"))
        self.assertIsNone(self.board.detail("t-9"))

    def test_the_detail_is_read_read_only(self):
        self.scratch.task("t-1")
        opened = []
        real = tasks.Board._open

        def watched(path):
            conn = real(path)
            opened.append(conn)
            return conn
        with patch.object(tasks.Board, "_open", staticmethod(watched)):
            self.board.detail("t-1")
        self.assertTrue(opened)
        with contextlib.closing(tasks.read_only(self.scratch.path)) as conn:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("DELETE FROM tasks")


class HeldDetailTest(unittest.TestCase):
    def test_review_board_without_db_path_uses_the_pinned_native_resolver(self):
        with tempfile.TemporaryDirectory() as folder:
            board=Scratch(folder)
            board.task("same-id","blocked",assignee="reviewer",created_by="lead",body="Exact board")
            native=types.SimpleNamespace(DEFAULT_BOARD="default",list_tasks=lambda:[],list_boards=lambda **_: [{"slug":"app"}],kanban_db_path=lambda slug: board.path,pin_first_board_resolution=contextlib.nullcontext)
            package=types.ModuleType("hermes_cli");package.kanban_db=native
            constants=types.SimpleNamespace(profile_name_for_home=lambda _:"lead")
            with patch.dict(sys.modules,{"hermes_cli":package,"hermes_cli.kanban_db":native,"hermes_constants":constants}):
                actual=tasks.hermes_board(Path(folder),"enclos")
                self.assertEqual(actual.held_detail("app/same-id")["body"],"Exact board")

    def test_exact_board_reference_and_creator_with_description_and_comments(self):
        with tempfile.TemporaryDirectory() as folder:
            first, second = Scratch(folder), Scratch(folder)
            for board, text in ((first, "First board"), (second, "Second board")):
                board.task("same-id", "blocked", assignee="reviewer", created_by="lead", body=text)
                board.comment("same-id", "reviewer", text + " comment", NOW)
            board = tasks.Board("lead", lambda: [first.path, second.path], "enclos",
                                held_boards=lambda: [("default", first.path), ("app", second.path)],
                                default_board="default")
            self.assertEqual(board.held_detail("app/same-id")["body"], "Second board")
            self.assertEqual(board.held_detail("app/same-id")["comments"][0]["text"], "Second board comment")
            self.assertEqual(board.held_detail("same-id")["body"], "First board")
            self.assertIsNone(board.held_detail("missing/same-id"))
            second.set("same-id", created_by="other")
            self.assertIsNone(board.held_detail("app/same-id"))
            self.assertEqual(board.held_detail("default/same-id")["body"], "First board")
            first.set("same-id", status="archived")
            self.assertIsNone(board.held_detail("same-id"))


class WritingHintTest(unittest.TestCase):
    """The hint promises what the app draws of a task, as the platform hint does of a message."""

    def test_it_names_what_the_app_draws_as_the_platform_hint_does(self):
        # The elements themselves are checked once, in test_protocol's Hint.
        self.assertIn(f"body and its comments render as Markdown: {protocol.MARKDOWN_ELEMENTS}", tasks.WRITING_HINT)
        self.assertIn(protocol.MARKDOWN_ELEMENTS, protocol.PLATFORM_HINT)
        self.assertIn("web and mailto links", tasks.WRITING_HINT)

    def test_it_says_the_title_and_result_are_plain(self):
        for part in ("title", "result", "plain line"):
            with self.subTest(part):
                self.assertIn(part, tasks.WRITING_HINT)

    def test_it_stays_short_for_every_turn(self):
        self.assertLess(len(tasks.WRITING_HINT), 500)


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
        self.assertEqual(self.reporter.capabilities, ("activity", "tasks", "task_details"))
        self.assertEqual(tasks.Reporter("engineer", self.sent).capabilities, ("activity",))

    async def test_a_task_get_is_answered_with_its_detail_or_an_error(self):
        self.scratch.task("t-1", "running", body="Fix it")
        self.scratch.task("t-2", assignee="reviewer")
        await self.reporter.detail({"id": "b-1", "type": "task.get", "task": "t-1"})
        answer = self.sent.messages[-1]
        self.assertEqual((answer["type"], answer["of"], answer["detail"]["body"]), ("task.detail", "b-1", "Fix it"))
        # Another profile's task, and one no board has.
        for task_id in ("t-2", "t-9"):
            await self.reporter.detail({"id": "b-2", "type": "task.get", "task": task_id})
            self.assertEqual((self.sent.messages[-1]["type"], self.sent.messages[-1]["code"]), ("error", "not_found"))
        os.remove(self.scratch.path)
        with self.assertLogs("enclos.tasks", "WARNING"):
            await self.reporter.detail({"id": "b-3", "type": "task.get", "task": "t-1"})
        self.assertEqual((self.sent.messages[-1]["code"], self.sent.messages[-1]["of"]), ("internal", "b-3"))
        await tasks.Reporter("engineer", self.sent).detail({"id": "b-4", "type": "task.get", "task": "t-1"})
        self.assertEqual(self.sent.messages[-1]["code"], "unsupported")

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

    async def test_a_second_hello_repeats_the_whole_state(self):
        # The bridge makes the agent idle when a connection closes, and keeps
        # only the tasks of the last list: the next hello repeats both.
        self.scratch.task("t-1")
        await self.reporter.connected()
        await self.reporter.answering("c-1", True)
        [(_, [task]), _, _] = self.sent.take()
        await self.reporter.connected()
        self.assertEqual(self.sent.take(), [("tasks", [task]),
                                            ("agent.activity", [{"kind": "answering", "conversation": "c-1"}])])

    async def test_a_refused_update_is_sent_again_at_the_next_reading(self):
        self.scratch.task("t-1")
        await self.reporter.connected()
        self.reporter.acknowledged(self.sent.messages[0]["id"])
        self.sent.take()
        self.scratch.set("t-1", status="blocked")
        self.scratch.event("t-1", "blocked", NOW)
        await self.watch_once()
        [update] = self.sent.messages
        self.sent.take()
        # The bridge's answer to a refused message: an error, then the ack.
        self.reporter.refused(update["id"])
        self.reporter.acknowledged(update["id"])
        self.scratch.task("t-2")
        await self.watch_once()
        self.assertEqual(sorted((k, t["id"], t["state"]) for k, t in self.sent.take()),
                         [("task.update", "t-1", "blocked"), ("task.update", "t-2", "queued")])

    async def test_each_task_of_a_refused_list_is_sent_again_at_the_next_reading(self):
        self.scratch.task("t-1")
        self.scratch.task("t-2")
        await self.reporter.connected()
        [listed, _] = self.sent.messages
        self.sent.take()
        self.reporter.refused(listed["id"])
        self.scratch.task("t-3", assignee="reviewer")  # the board changed, not this agent's tasks
        await self.watch_once()
        self.assertEqual(sorted((k, t["id"]) for k, t in self.sent.take()),
                         [("task.update", "t-1"), ("task.update", "t-2")])

    async def test_an_ack_clears_what_a_task_message_carried(self):
        self.scratch.task("t-1")
        await self.reporter.connected()
        [listed, _] = self.sent.messages
        self.sent.take()
        self.assertEqual(dict(self.reporter._unanswered), {listed["id"]: ["t-1"]})
        self.reporter.acknowledged(listed["id"])
        self.assertEqual(dict(self.reporter._unanswered), {})
        # An error that comes after the ack, or for another message, changes nothing.
        self.reporter.refused(listed["id"])
        self.reporter.refused("m-other")
        self.scratch.task("t-2", assignee="reviewer")
        await self.watch_once()
        self.assertEqual(self.sent.take(), [])

    async def test_unanswered_task_messages_are_bounded(self):
        self.scratch.task("t-1")
        with patch.object(tasks, "MAX_UNANSWERED", 3):
            for _ in range(5):
                await self.reporter._refresh(whole=True)
        self.assertEqual(len(self.reporter._unanswered), 3)
        self.assertEqual(list(self.reporter._unanswered), [m["id"] for m in self.sent.messages[-3:]])

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
            self.assertIsNone(tasks.hermes_board(Path("/home/alice/.hermes"), "enclos"))
        old = types.ModuleType("hermes_cli.kanban_db")
        old.list_tasks = lambda *a, **k: []  # no list_boards
        package = types.ModuleType("hermes_cli")
        package.kanban_db = old
        constants = types.ModuleType("hermes_constants")
        constants.profile_name_for_home = lambda home: "engineer"
        with patch.dict(sys.modules, {"hermes_cli": package, "hermes_cli.kanban_db": old,
                                      "hermes_constants": constants}):
            self.assertIsNone(tasks.hermes_board(Path("/home/alice/.hermes"), "enclos"))


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

    def test_the_plugin_reads_the_detail_hermes_writes(self):
        from hermes_cli import kanban_db as kb
        from hermes_cli.kanban_db_connect import connect
        with contextlib.closing(connect()) as conn:
            parent = kb.create_task(conn, title="Shared contract", assignee="pm", created_by="lead")
            task = kb.create_task(conn, title="Fix the threads", body="Fix them.\n\nThen reply.",
                                  assignee="engineer", created_by="lead", parents=[parent])
            child = kb.create_task(conn, title="Review the fix", assignee="reviewer", parents=[task])
            kb.add_comment(conn, task, "lead", "Implement with the engineer.\nReview after.")
            kb.claim_task(conn, parent)
            kb.complete_task(conn, parent, result="Agreed")
            kb.claim_task(conn, task)
            kb.block_task(conn, task, reason="Needs the API key")
            kb.unblock_task(conn, task)
            kb.claim_task(conn, task)
        board = tasks.hermes_board(self.home, "enclos")
        _, found = board.read("engineer")
        self.assertEqual(found[0]["comments"], 1)
        detail = board.detail(task)
        self.assertEqual(detail["body"], "Fix them.\n\nThen reply.")
        self.assertEqual({(r["id"], r["relation"], r.get("state")) for r in detail["related"]},
                         {(parent, "parent", "done"), (child, "child", "queued")})
        self.assertEqual([(c["author"], c["text"]) for c in detail["comments"]],
                         [("lead", "Implement with the engineer.\nReview after.")])
        self.assertEqual(detail["comments_total"], 1)
        kinds = [(e["kind"], e.get("outcome")) for e in detail["history"]]
        self.assertEqual(kinds[0], ("created", None))
        self.assertIn(("attempt", "blocked"), kinds)
        self.assertIn(("blocked", None), kinds)
        self.assertIn(("unblocked", None), kinds)
        self.assertEqual(kinds[-1], ("attempt", None))
        self.assertIsNone(board.detail(child))

    def test_every_board_hook_is_one_hermes_has(self):
        from hermes_cli.plugins import VALID_HOOKS
        self.assertEqual(set(tasks.HOOKS) - set(VALID_HOOKS), set())


if __name__ == "__main__":
    unittest.main()
