"""Task events (ADR 0071): Hermes's kanban pings told from the agent's own
messages, by their wording and by the board, and what the line says, read
from the board.

Most tests use a scratch board with the columns the plugin reads.
`NativeHermesPings` renders pings with a real Hermes's own notifier, on a
board in a temporary home:

ENCLOS_HERMES_SOURCE=/path/to/hermes-agent python3 -m unittest discover -s channels/hermes/tests
"""

import contextlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enclos import protocol, task_events  # noqa: E402

SCHEMA = """
CREATE TABLE tasks (id TEXT PRIMARY KEY, title TEXT, assignee TEXT, status TEXT);
CREATE TABLE task_events (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT, kind TEXT, payload TEXT,
                          created_at INTEGER);
CREATE TABLE kanban_notify_subs (task_id TEXT, platform TEXT, chat_id TEXT, thread_id TEXT DEFAULT '',
                                 delivery_mode TEXT DEFAULT 'notify', last_event_id INTEGER DEFAULT 0);
"""

# Hermes's English pings, as its notifier renders them.
TRIAGE = ("🛑 [enclos-org] @reviewer Kanban t_a09759c7 routed to TRIAGE — needs a human decision "
          "(blocked 3x for the same cause): which st…")


class Scratch:
    def __init__(self, folder, name="kanban.db"):
        self.path = os.path.join(folder, name)
        with contextlib.closing(sqlite3.connect(self.path)) as conn:
            conn.executescript(SCHEMA)

    def run(self, sql, *args):
        with contextlib.closing(sqlite3.connect(self.path)) as conn, conn:
            return conn.execute(sql, args).lastrowid

    def task(self, task_id, title="S2a", assignee="reviewer", status="triage"):
        self.run("INSERT INTO tasks VALUES (?, ?, ?, ?)", task_id, title, assignee, status)

    def event(self, task_id, kind, payload=None):
        return self.run("INSERT INTO task_events (task_id, kind, payload, created_at) VALUES (?, ?, ?, 0)",
                        task_id, kind, json.dumps(payload) if payload is not None else None)

    def subscribe(self, task_id, chat_id="c-1", platform="enclos", mode="notify+wake", cursor=None):
        if cursor is None:
            cursor = self._latest()
        self.run("INSERT INTO kanban_notify_subs (task_id, platform, chat_id, delivery_mode, last_event_id)"
                 " VALUES (?, ?, ?, ?, ?)", task_id, platform, chat_id, mode, cursor)

    def _latest(self):
        with contextlib.closing(sqlite3.connect(self.path)) as conn:
            return conn.execute("SELECT COALESCE(MAX(id), 0) FROM task_events").fetchone()[0]


class Candidates(unittest.TestCase):
    """The wording: Hermes's templates, rendered in the gateway's language."""

    def test_each_kind_of_ping_is_read_with_its_task_board_and_assignee(self):
        pings = {
            "completed": "✔ [default] @engineer Kanban t_1 done — Write the report\nAll fine",
            "review_requested": "👀 [default] @engineer Kanban t_1 ready for review — Write the report",
            "changes_requested": "🛑 [default] Kanban t_1 review requested changes/BLOCK: tests fail — reviewer @qa",
            "block_loop_detected": TRIAGE.replace("t_a09759c7", "t_1").replace("[enclos-org] @reviewer", "[default] @engineer"),
            "gave_up": "⛔ [default] @engineer Kanban t_1 is now blocked: it failed 3 times in a row (last: boom). "
                       "Fix the cause, then `hermes kanban unblock t_1`.",
            "timed_out": "⏱ [default] @engineer Kanban t_1 ran past its 30-minute limit and was stopped; "
                         "it will be retried automatically.",
            "blocked": "⏸ [default] @engineer Kanban t_1 blocked: Which client?",
            "crashed": "✖ [default] @engineer Kanban t_1 — its worker stopped unexpectedly; "
                       "it will be retried automatically.",
            "status": "🔄 [default] @engineer Kanban t_1 → ready",
        }
        self.assertEqual(set(pings), set(task_events.PINGS))
        for kind, text in pings.items():
            with self.subTest(kind):
                assignee = None if kind == "changes_requested" else "engineer"
                self.assertIn({"kind": kind, "task": "t_1", "board": "default", "assignee": assignee},
                              task_events.candidates(text))

    def test_the_board_and_assignee_tags_are_optional(self):
        self.assertEqual(task_events.candidates("⏸ Kanban t_1 blocked"),
                         [{"kind": "blocked", "task": "t_1", "board": None, "assignee": None}])

    def test_an_agents_text_that_starts_like_a_ping_is_not_one(self):
        for text in [
            "Kanban t_1 done — all good",  # no emoji
            "✔ Kanban t_1 is finished",  # not Hermes's words
            "✔ Kanban t_1",  # no words of an event
            "I moved Kanban t_1 to done — the report is in.",
            "🛑 Kanban routed to TRIAGE — needs a human decision",  # no task id
            "Here is the status:\n✔ Kanban t_1 done — Write the report",  # not at the start
            "",
        ]:
            with self.subTest(text):
                self.assertEqual(task_events.candidates(text), [])

    def test_the_gateways_language_is_read_from_hermes_and_english_still_reads(self):
        french = {
            "gateway.kanban.ping.completed": "✔ {head} terminée — {title}{handoff}",
            task_events.HEAD_KEY: "{board_tag}{assignee_tag}Kanban {task_id}",
            task_events.BOARD_TAG_KEY: "[{board}] ",
            task_events.ASSIGNEE_TAG_KEY: "@{assignee} ",
        }
        with patch.object(task_events, "_translations", return_value=lambda key: french.get(key, key)):
            self.assertEqual(task_events.candidates("✔ [default] Kanban t_1 terminée — Rapport"),
                             [{"kind": "completed", "task": "t_1", "board": "default", "assignee": None}])
            self.assertEqual(task_events.candidates("✔ [default] Kanban t_1 done — Report")[0]["kind"],
                             "completed")

    def test_a_language_whose_words_follow_the_id_without_a_space_reads(self):
        chinese = {
            "gateway.kanban.ping.crashed": "✖ {head}——其工作进程意外停止；将自动重试。",
            task_events.HEAD_KEY: "{board_tag}{assignee_tag}看板 {task_id}",
        }
        with patch.object(task_events, "_translations", return_value=lambda key: chinese.get(key, key)):
            self.assertEqual(task_events.candidates("✖ [default] 看板 t_1——其工作进程意外停止；将自动重试。"),
                             [{"kind": "crashed", "task": "t_1", "board": "default", "assignee": None}])


class Recognising(unittest.TestCase):
    """The board: a live subscription of this chat to that task, and an event
    of that kind Hermes claimed for it; the line's fields read from there."""

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.scratch = Scratch(self.folder)
        self.boards = [("enclos-org", Path(self.scratch.path))]
        self.recogniser = task_events.Recogniser(lambda: self.boards, "enclos")

    def pinged(self, kind="block_loop_detected", payload=None, **subscription):
        self.scratch.task("t_a09759c7", title="S2a\nreview store", status="triage")
        self.scratch.event("t_a09759c7", "created")
        self.scratch.event("t_a09759c7", kind, payload)
        self.scratch.subscribe("t_a09759c7", **subscription)

    def test_a_ping_for_a_subscribed_task_is_a_task_event_with_the_boards_fields(self):
        self.pinged()
        self.assertEqual(self.recogniser.recognise("c-1", TRIAGE), {
            "task": "t_a09759c7", "title": "S2a review store", "assignee": "reviewer", "event": "triage",
            "state": "queued"})

    def test_the_title_and_assignee_come_from_the_board_not_the_text(self):
        self.pinged()
        self.scratch.run("UPDATE tasks SET assignee = 'engineer', title = 'Renamed' WHERE id = 't_a09759c7'")
        event = self.recogniser.recognise("c-1", TRIAGE)
        self.assertEqual((event["title"], event["assignee"]), ("Renamed", "engineer"))

    def test_without_a_subscription_of_this_chat_it_is_the_agents_message(self):
        self.pinged(chat_id="c-other")
        self.assertIsNone(self.recogniser.recognise("c-1", TRIAGE))

    def test_another_platforms_subscription_is_not_this_chats(self):
        self.pinged(platform="telegram")
        self.assertIsNone(self.recogniser.recognise("c-1", TRIAGE))

    def test_a_wake_only_subscription_sends_no_ping(self):
        self.pinged(mode="wake")
        self.assertIsNone(self.recogniser.recognise("c-1", TRIAGE))

    def test_an_event_of_that_kind_must_have_been_claimed_for_the_subscription(self):
        # Subscribed, but the task was never routed to triage: an agent's own
        # sentence about its task, worded as a ping.
        self.pinged(kind="blocked")
        self.assertIsNone(self.recogniser.recognise("c-1", TRIAGE))
        # Routed to triage after Hermes's last claim: not pinged yet.
        self.scratch.event("t_a09759c7", "block_loop_detected")
        self.assertIsNone(self.recogniser.recognise("c-1", TRIAGE))

    def test_another_boards_ping_is_not_read_on_this_board(self):
        self.pinged()
        self.boards = [("default", Path(self.scratch.path))]
        self.assertIsNone(self.recogniser.recognise("c-1", TRIAGE))

    def test_a_status_change_says_the_status_it_announced(self):
        self.pinged(kind="status", payload={"status": "ready"})
        event = self.recogniser.recognise("c-1", "🔄 [enclos-org] @reviewer Kanban t_a09759c7 → ready")
        self.assertEqual((event["event"], event["state"]), ("changed", "queued"))

    def test_an_assignee_or_a_task_the_protocol_would_refuse_is_left_out(self):
        self.pinged()
        self.scratch.run("UPDATE tasks SET assignee = 'a/b' WHERE id = 't_a09759c7'")
        self.assertNotIn("assignee", self.recogniser.recognise("c-1", TRIAGE))
        self.scratch.run("UPDATE tasks SET title = '  ' WHERE id = 't_a09759c7'")
        self.assertIsNone(self.recogniser.recognise("c-1", TRIAGE))

    def test_a_board_that_cannot_be_read_leaves_the_text_a_message(self):
        self.pinged()
        os.unlink(self.scratch.path)
        with self.assertLogs("enclos.task_events", "WARNING"):
            self.assertIsNone(self.recogniser.recognise("c-1", TRIAGE))

    def test_boards_that_cannot_be_listed_leave_the_text_a_message(self):
        def broken():
            raise OSError("no boards")

        recogniser = task_events.Recogniser(broken, "enclos")
        with self.assertLogs("enclos.task_events", "WARNING"):
            self.assertIsNone(recogniser.recognise("c-1", TRIAGE))

    def test_a_hermes_without_a_kanban_board_tells_no_ping(self):
        with patch.dict(sys.modules, {"hermes_cli": None}):
            self.assertIsNone(task_events.hermes("enclos"))


class ToTheBridge(unittest.TestCase):
    EVENT = {"task": "t_a09759c7", "title": "S2a", "assignee": "reviewer", "event": "triage", "state": "queued"}

    def test_a_task_event_has_the_fixtures_shape(self):
        here = Path(__file__).resolve().parents[3]
        path = here / "crates/enclos-protocol/tests/fixtures/plugin/from_plugin_message_out_task_event.json"
        expected = json.loads(path.read_text(encoding="utf-8"))
        message = protocol.message_out("home.lab.main", expected["text"], task_event=self.EVENT)
        self.assertEqual(set(message), set(expected))
        for key in expected:
            if key != "id":
                self.assertEqual(message[key], expected[key], key)

    def test_an_older_bridge_gets_the_pings_text_as_a_notify_under_the_same_id(self):
        message = protocol.message_out("c-1", TRIAGE, task_event=self.EVENT)
        older = protocol.for_bridge(message, task_events=False)
        self.assertEqual(older, {"v": 1, "id": message["id"], "type": "message.out", "conversation": "c-1",
                                 "text": TRIAGE, "kind": "notify"})
        self.assertIs(protocol.for_bridge(message, task_events=True), message)
        # The kept message is untouched: a newer bridge still gets the line.
        self.assertEqual(message["kind"], "task_event")
        reply = protocol.message_out("c-1", "Hi", "m-1")
        self.assertIs(protocol.for_bridge(reply, task_events=False), reply)


@unittest.skipUnless(os.environ.get("ENCLOS_HERMES_SOURCE"), "optional real Hermes checkout")
class NativeHermesPings(unittest.TestCase):
    """Pings rendered by a real Hermes's notifier, for events on a board in a
    temporary home that a subscription of this platform claimed: each is told
    as the task event it is, and only for the subscribed chat."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        home = Path(self.temporary.name) / "hermes"
        home.mkdir()
        env = patch.dict(os.environ, {"HERMES_HOME": str(home), "HERMES_KANBAN_HOME": str(home),
                                      "HERMES_LANGUAGE": "en"})
        env.start()
        self.addCleanup(env.stop)
        for pin in ("HERMES_KANBAN_DB", "HERMES_KANBAN_BOARD", "HERMES_KANBAN_TASK"):
            os.environ.pop(pin, None)
        sys.path.insert(0, os.environ["ENCLOS_HERMES_SOURCE"])
        self.addCleanup(sys.path.remove, os.environ["ENCLOS_HERMES_SOURCE"])
        from hermes_cli import kanban_db, kanban_db_notify
        from hermes_cli.kanban_db_connect import connect
        self.kb, self.notify = kanban_db, kanban_db_notify
        self.conn = connect()
        self.addCleanup(self.conn.close)
        self.recogniser = task_events.hermes("enclos")
        self.assertIsNotNone(self.recogniser)

    def pings(self, task_id):
        """Hermes's own claim and rendering of the subscription's new events."""
        from gateway import kanban_watchers_notifier as notifier
        _, cursor, events = self.notify.claim_unseen_events_for_sub(
            self.conn, task_id=task_id, platform="enclos", chat_id="c-1", kinds=notifier.TERMINAL_KINDS)
        board = self.kb.DEFAULT_BOARD
        sub = {"task_id": task_id, "platform": "enclos", "chat_id": "c-1", "delivery_mode": "notify+wake"}
        rendering = notifier._KanbanNotification(None, {"sub": sub, "task": self.kb.get_task(self.conn, task_id),
                                                       "board": board, "events": events, "cursor": cursor},
                                                 platform_cls=None, sub_fail_counts={})
        return [(event.kind, rendering.format_event(event)) for event in events
                if rendering.format_event(event) is not None]

    def test_hermes_pings_are_told_as_task_events_for_the_subscribed_chat_only(self):
        task_id = self.kb.create_task(self.conn, title="Write the report", assignee="engineer", created_by="main")
        self.notify.add_notify_sub(self.conn, task_id=task_id, platform="enclos", chat_id="c-1",
                                   delivery_mode="notify+wake")
        self.assertTrue(self.kb.block_task(self.conn, task_id, reason="Which client?", kind="needs_input"))
        [(kind, text)] = self.pings(task_id)
        self.assertEqual(kind, "blocked")
        self.assertEqual(self.recogniser.recognise("c-1", text), {
            "task": task_id, "title": "Write the report", "assignee": "engineer", "event": "blocked",
            "state": "blocked"})
        self.assertIsNone(self.recogniser.recognise("c-2", text))
        self.assertTrue(self.kb.unblock_task(self.conn, task_id))
        self.assertTrue(self.kb.complete_task(self.conn, task_id, result="Sent to the client."))
        rendered = dict(self.pings(task_id))
        self.assertIn("completed", rendered)
        event = self.recogniser.recognise("c-1", rendered["completed"])
        self.assertEqual((event["event"], event["state"]), ("done", "done"))

    def test_every_ping_template_reads_with_its_task_board_and_assignee(self):
        from agent.i18n import t
        head = t(task_events.HEAD_KEY, board_tag=t(task_events.BOARD_TAG_KEY, board="ops"),
                 assignee_tag=t(task_events.ASSIGNEE_TAG_KEY, assignee="engineer"), task_id="t_1")
        for kind, (key, _) in task_events.PINGS.items():
            with self.subTest(kind):
                text = t(key, head=head, title="Write the report", handoff="", board_tag="[ops] ", task_id="t_1",
                         reason="Which client?", provenance="", why="x", recurrences="", count="3 times",
                         last="", span="its limit", status="ready")
                assignee = None if kind == "changes_requested" else "engineer"
                self.assertIn({"kind": kind, "task": "t_1", "board": "ops", "assignee": assignee},
                              task_events.candidates(text))
                # Hermes's English template is still the plugin's fallback.
                self.assertEqual(t(key), task_events.ENGLISH[key])
