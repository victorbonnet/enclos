"""Tests of dashboard-cmd.py's pure parts: the refusal of a second run, what
status says, the audit record. Runs anywhere, on a temporary folder:

    python3 -I prototype/m3/test_dashboard_cmd.py
"""

import importlib.util
import json
import os
import re
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), f"{HERE}/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cmd = load("dashboard-cmd")


class AlreadyRunning(unittest.TestCase):
    def test_a_second_run_cannot_take_the_lock_until_the_first_ends(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "dashboard.lock")
            first = cmd.take_lock(path)
            self.assertIsNotNone(first)
            self.assertIsNone(cmd.take_lock(path))
            first.close()
            again = cmd.take_lock(path)
            self.assertIsNotNone(again)
            again.close()

    def test_the_refusal_names_the_first_run(self):
        record = {"pid": 42, "session": "abc", "started": "then", "url": "http://127.0.0.1:1/"}
        text = cmd.refusal("proto", record)
        for part in ("proto", "42", "abc", "http://127.0.0.1:1/"):
            self.assertIn(part, text)

    def test_a_first_run_with_no_record_yet_is_still_refused(self):
        self.assertIn("starting", cmd.refusal("proto", None))
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(cmd.read_record(os.path.join(d, "none")))


class Status(unittest.TestCase):
    def test_status_names_the_command_and_gives_no_url(self):
        text = cmd.status_text("proto")
        self.assertIn("enclos dashboard proto", text)
        self.assertNotIn("http", text)
        self.assertIn("ssh", text)


class ControlPair(unittest.TestCase):
    def test_only_the_fixed_half_sets_no_proxy_and_both_run_the_dashboard(self):
        self.assertNotIn("NO_PROXY", cmd.command(False))
        fixed = cmd.command(True)
        for part in ("NO_PROXY=127.0.0.1,localhost,::1", "no_proxy=127.0.0.1,localhost,::1"):
            self.assertIn(part, fixed)
        self.assertTrue(fixed.endswith(cmd.COMMAND))


def rows(failed):
    """A pair's verdicts, every row of both rounds, with `failed` as FAIL."""
    names = ("no loopback denial in the proxy log while the terminal is used",
             "the Chat tab's backend connection is established",
             "a prompt typed on /api/pty gets an answer in the terminal",
             "a prompt typed in the Chat tab gets an answer")
    return [f"{label}: {name}\t{'FAIL' if (label, i) in failed else 'pass'}\t"
            for label in ("as-is", "fixed") for i, name in enumerate(names)]


class ChatReading(unittest.TestCase):
    NO_ANSWER = {("as-is", 2), ("as-is", 3), ("fixed", 2), ("fixed", 3)}

    def setUp(self):
        self.chat = load("chat-reading")

    def test_the_sentence_comes_from_the_backend_rows_alone(self):
        text = self.chat.backend(rows({("as-is", 0), ("as-is", 1)} | self.NO_ANSWER))
        self.assertIn("connection is established", text)
        self.assertNotIn("whole cause", text)

    def test_missing_answers_name_no_cause(self):
        text = self.chat.answers(rows(self.NO_ANSWER), 120)
        self.assertIn("within the 120 s window", text)
        self.assertIn("cause not shown", text)

    def test_a_fix_that_leaves_the_backend_refused_says_so(self):
        self.assertIn("still does not reach", self.chat.backend(rows({("fixed", 1)})))

    def test_no_failure_as_it_is_is_not_reproduced(self):
        self.assertIn("does not reproduce", self.chat.backend(rows(set())))

    def test_a_round_that_never_started_is_not_a_pass(self):
        started = [row for row in rows(set()) if not row.startswith("fixed: ")]
        started.append("fixed: the command starts\tFAIL\t")
        self.assertIn("did not reach", self.chat.backend(started))

    def test_an_answer_in_both_rounds_is_said(self):
        self.assertIn("got an answer", self.chat.answers(rows(set()), 120))


class ChatAnswer(unittest.TestCase):
    def test_what_the_turn_said_in_that_round_is_an_answer(self):
        with open(f"{HERE}/dashboard-chat-check.sh") as f:
            pattern = re.search(r"^ANSWER='(.*)'$", f.read(), re.M).group(1)
        self.assertRegex("Hermes could not start the assistant for this session".lower(), pattern)

    def test_the_window_outlasts_what_the_terminal_used(self):
        self.assertGreaterEqual(load("host-client").ANSWER_SECONDS, 120)
        with open(f"{HERE}/browser-chat.py") as f:
            self.assertIn("client.ANSWER_SECONDS", f.read())


class Audit(unittest.TestCase):
    def test_each_event_is_one_json_line(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.jsonl")
            cmd.audit(path, "dashboard-start", sandbox="proto")
            cmd.audit(path, "dashboard-end", sandbox="proto", reason="stopped")
            with open(path) as f:
                events = [json.loads(line)["event"] for line in f]
        self.assertEqual(events, ["dashboard-start", "dashboard-end"])


if __name__ == "__main__":
    unittest.main()
