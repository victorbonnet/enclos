"""Tests of the bwrap-prototype workflow's text: which runners it names and
that it runs the prototype's Python tests. They read two files and run nothing
else, so they run anywhere:

    python3 -I prototype/m3/test_workflow.py
"""

import glob
import os
import re
import unittest

M3 = os.path.dirname(os.path.abspath(__file__))
WORKFLOW = os.path.join(M3, "..", "..", ".github", "workflows", "bwrap-prototype.yml")


def read(path):
    with open(path) as f:
        return f.read()


class WorkflowTest(unittest.TestCase):
    def test_the_runners_are_named_by_release(self):
        matrix = re.search(r"^\s+os: \[(.*)\]$", read(WORKFLOW), re.M).group(1)
        self.assertEqual(matrix.split(", "), ["ubuntu-24.04", "ubuntu-26.04", "ubuntu-24.04-arm"])

    def test_nothing_names_a_runner_that_moves(self):
        self.assertNotIn("ubuntu-latest", read(WORKFLOW))
        self.assertNotIn("ubuntu-latest", read(os.path.join(M3, "README.md")))

    def test_every_python_test_runs_in_the_workflow(self):
        text = read(WORKFLOW)
        for path in glob.glob(os.path.join(M3, "test_*.py")):
            self.assertIn(f"python3 -I prototype/m3/{os.path.basename(path)}", text)


if __name__ == "__main__":
    unittest.main()
