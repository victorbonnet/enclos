"""What an agent writes for the person on a held task (ADR 0073): the tool's
checks, the asks kept per hold, the two tools, and the list that carries them."""

import asyncio
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from enclos import asks, held_tasks  # noqa: E402


def entry(task="t_1", since=100, **more):
    return {"task": task, "title": f"Task {task}", "reason": "r", "since": since, "revision": "e:1",
            "resume": held_tasks.RESUME, "resumable": True, **more}


GOOD = {"task": "t_1", "decision": "Allow one more hour to fix backups?",
        "blocked": "Both reviews found chat text can stop a backup. The two coding runs are used up.",
        "choices": ["Allow one 60-min fix", "Keep paused"], "recommended": 0}


class Validate(unittest.TestCase):
    def test_a_good_ask_is_kept_as_given(self):
        task, ask = asks.validate(GOOD)
        self.assertEqual(task, "t_1")
        self.assertEqual(ask, {"decision": GOOD["decision"], "blocked": GOOD["blocked"],
                               "choices": GOOD["choices"], "recommended": 0})
        _, free = asks.validate({**GOOD, "choices": [], "recommended": None})
        self.assertEqual(free["choices"], [])
        self.assertNotIn("recommended", free)

    def test_what_the_card_cannot_show_is_refused_with_why(self):
        for bad, said in [
            ({"decision": " "}, "decision"),
            ({"decision": "a" * 121}, "120"),
            ({"decision": "Two\nlines?"}, "one visible line"),
            ({"blocked": ""}, "blocked"),
            ({"blocked": "b" * 401}, "400"),
            ({"choices": ["a", "b", "c", "d", "e"]}, "at most 4"),
            ({"choices": ["Keep paused", " Keep paused "]}, "differ"),
            ({"choices": ["Keep​ paused"]}, "one visible line"),
            ({"choices": ["x" * 81]}, "80"),
            ({"recommended": 2}, "index"),
            ({"recommended": True}, "index"),
            ({"task": ""}, "task"),
        ]:
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError, said):
                    asks.validate({**GOOD, **bad})


class Store(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.folder.name, "main.sock.held-asks.json")
        self.asks = asks.Asks(self.path)

    def tearDown(self):
        self.folder.cleanup()

    def test_an_ask_rides_its_hold_and_survives_a_restart(self):
        _, ask = asks.validate(GOOD)
        self.asks.put("t_1", 100, ask)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        # Another process (a restart) reads the same file.
        again = asks.Asks(self.path)
        listed = again.attach([entry("t_1", 100), entry("t_2", 100)])
        sent = dict(listed[0]["ask"])
        self.assertIsInstance(sent.pop("asked"), int)
        self.assertEqual(sent, ask)
        self.assertNotIn("ask", listed[1])

    def test_the_same_words_asked_again_carry_a_new_stamp(self):
        _, ask = asks.validate(GOOD)
        self.asks.put("t_1", 100, ask)
        first = self.asks.attach([entry("t_1", 100)])[0]["ask"]["asked"]
        time.sleep(0.002)
        self.asks.put("t_1", 100, ask)
        self.assertGreater(self.asks.attach([entry("t_1", 100)])[0]["ask"]["asked"], first)

    def test_an_ask_is_forgotten_once_its_task_is_no_longer_held_or_held_anew(self):
        _, ask = asks.validate(GOOD)
        self.asks.put("t_1", 100, ask)
        self.asks.put("t_2", 100, ask)
        listed = self.asks.attach([entry("t_1", 200)], read_at=time.time() + 1)
        self.assertNotIn("ask", listed[0])
        self.assertEqual(json.loads(Path(self.path).read_text()), {})

    def test_an_ask_kept_after_a_reading_began_outlives_that_reading(self):
        # A refresh read the board before the task was held anew; the agent
        # then asked about the new hold, before the refresh attached.
        read_at = time.time()
        _, ask = asks.validate(GOOD)
        self.asks.put("t_1", 200, ask)
        listed = self.asks.attach([entry("t_1", 100)], read_at=read_at)
        self.assertNotIn("ask", listed[0])
        self.assertEqual(self.asks.attach([entry("t_1", 200)], read_at=read_at)[0]["ask"]["decision"],
                         GOOD["decision"])

    def test_settling_marks_the_ask_or_stands_for_the_task_when_there_was_none(self):
        _, ask = asks.validate(GOOD)
        self.asks.put("t_1", 100, ask)
        self.asks.settle("t_1", 100, "Task t_1")
        self.asks.settle("t_2", 100, "Task t_2", "Waiting on a reviewer.")
        listed = self.asks.attach([entry("t_1"), entry("t_2")])
        self.assertTrue(listed[0]["ask"]["settled"])
        self.assertEqual(listed[0]["ask"]["decision"], ask["decision"])
        self.assertEqual(listed[1]["ask"], {"decision": "Task t_2", "blocked": "Waiting on a reviewer.",
                                            "choices": [], "settled": True})

    def test_a_file_that_does_not_read_is_an_error_and_is_not_written_over(self):
        Path(self.path).write_text("not json")
        with self.assertRaises(OSError):
            self.asks.attach([entry()])
        _, ask = asks.validate(GOOD)
        with self.assertRaises(OSError):
            self.asks.put("t_1", 100, ask)
        self.assertEqual(Path(self.path).read_text(), "not json")


class Board:
    def __init__(self, held):
        self.held = held

    def read(self, profile):
        return list(self.held.get(profile, []))


class Loop:
    def __init__(self):
        self.called = []

    def call_soon_threadsafe(self, function):
        self.called.append(function)


class Channel:
    def __init__(self, agent, held, folder):
        self._agent = agent
        self._held = held_tasks.Manager(agent, None, board=Board(held))
        self._asks = asks.Asks(os.path.join(folder, f"{agent}.sock.held-asks.json"))
        self._loop = Loop()


class Context:
    def __init__(self):
        self.tools = {}

    def register_tool(self, name, toolset, handler, description, schema):
        self.tools[name] = (handler, schema)


class Tools(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        held = {"main": [entry("t_1", 100)], "other": [entry("t_9", 100)]}
        self.main = Channel("main", held, self.folder.name)
        self.other = Channel("other", held, self.folder.name)
        self.agent = "main"
        self.ctx = Context()
        asks.register(self.ctx, [self.other, self.main], lambda: self.agent)

    def tearDown(self):
        self.folder.cleanup()

    def call(self, tool, args):
        return json.loads(self.ctx.tools[tool][0](args))

    def test_the_tools_are_described_for_the_agent(self):
        self.assertEqual(set(self.ctx.tools), {"enclos_ask_person", "enclos_person_answered"})
        schema = self.ctx.tools["enclos_ask_person"][1]
        self.assertEqual(schema["parameters"]["required"], ["task", "decision", "blocked"])

    def test_an_ask_for_a_task_held_now_is_kept_and_the_list_read_again(self):
        said = self.call("enclos_ask_person", GOOD)
        self.assertEqual(said["status"], "asked")
        self.assertEqual(self.main._loop.called, [self.main._held.poke])
        listed = self.main._asks.attach([entry("t_1", 100)])
        self.assertEqual(listed[0]["ask"]["decision"], GOOD["decision"])
        self.assertEqual(self.other._loop.called, [])

    def test_a_task_not_held_or_another_agent_s_is_refused_and_nothing_kept(self):
        for task in ("t_2", "t_9"):
            said = self.call("enclos_ask_person", {**GOOD, "task": task})
            self.assertIn("not held now", said["error"])
        self.agent = "nobody"
        self.assertIn("not connected", self.call("enclos_ask_person", GOOD)["error"])
        self.assertEqual(self.main._asks.attach([entry("t_1", 100)]), [entry("t_1", 100)])

    def test_the_person_answered_in_the_conversation(self):
        self.call("enclos_ask_person", GOOD)
        said = self.call("enclos_person_answered", {"task": "t_1"})
        self.assertEqual(said["status"], "answered")
        self.assertTrue(self.main._asks.attach([entry("t_1", 100)])[0]["ask"]["settled"])


class List(unittest.TestCase):
    def test_the_list_sent_carries_each_hold_s_ask(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        sent = []

        async def write(message):
            sent.append(message)
            return True

        manager = held_tasks.Manager("main", write, board=Board({"main": [entry("t_1", 100)]}))
        manager.bridge_supports = True
        manager.asks = asks.Asks(os.path.join(folder.name, "main.sock.held-asks.json"))
        _, ask = asks.validate(GOOD)
        manager.asks.put("t_1", 100, ask)

        async def run():
            await manager.refresh()
            await manager.refresh()
            manager.asks.settle("t_1", 100, "Task t_1")
            await manager.refresh()

        asyncio.run(run())
        # Sent when it changed only: with the ask, then settled.
        self.assertEqual(len(sent), 2)
        self.assertEqual(sent[0]["tasks"][0]["ask"]["decision"], ask["decision"])
        self.assertTrue(sent[1]["tasks"][0]["ask"]["settled"])

    def test_asks_that_cannot_be_read_send_no_list(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        sent = []

        async def write(message):
            sent.append(message)
            return True

        manager = held_tasks.Manager("main", write, board=Board({"main": [entry("t_1", 100)]}))
        manager.bridge_supports = True
        path = os.path.join(folder.name, "main.sock.held-asks.json")
        Path(path).write_text("[")
        manager.asks = asks.Asks(path)
        with self.assertLogs(held_tasks.logger, "ERROR"):
            asyncio.run(manager.refresh())
        # A list without the asks would withdraw them from the cards.
        self.assertEqual(sent, [])


class Hint(unittest.TestCase):
    def test_the_hint_names_both_tools_and_is_short(self):
        text = asks.context()["context"]
        self.assertIn("enclos_ask_person", text)
        self.assertIn("enclos_person_answered", text)
        self.assertLess(len(text), 700)


if __name__ == "__main__":
    unittest.main()
