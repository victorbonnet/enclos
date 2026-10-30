"""Tests of dashboard-cmd.py's pure parts: the refusal of a second run, what
status says, the audit record. Runs anywhere, on a temporary folder:

    python3 -I prototype/m3/test_dashboard_cmd.py
"""

import importlib.util
import json
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("dashboard_cmd", f"{HERE}/dashboard-cmd.py")
cmd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cmd)


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
