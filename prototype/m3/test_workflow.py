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
WORKFLOWS = os.path.join(M3, "..", "..", ".github", "workflows")
WORKFLOW = os.path.join(WORKFLOWS, "bwrap-prototype.yml")
PROTOTYPE_WORKFLOWS = [WORKFLOW, os.path.join(WORKFLOWS, "namespaces-prototype.yml")]


def read(path):
    with open(path) as f:
        return f.read()


class WorkflowTest(unittest.TestCase):
    def test_the_runners_are_named_by_release(self):
        matrix = re.search(r"^\s+os: \[(.*)\]$", read(WORKFLOW), re.M).group(1)
        self.assertEqual(matrix.split(", "), ["ubuntu-24.04", "ubuntu-26.04", "ubuntu-24.04-arm"])

    def test_nothing_names_a_runner_that_moves(self):
        for w in PROTOTYPE_WORKFLOWS:
            if os.path.exists(w):
                self.assertNotIn("ubuntu-latest", read(w))
        self.assertNotIn("ubuntu-latest", read(os.path.join(M3, "README.md")))

    def test_every_python_test_runs_in_a_prototype_workflow(self):
        text = "".join(read(w) for w in PROTOTYPE_WORKFLOWS if os.path.exists(w))
        for path in glob.glob(os.path.join(M3, "test_*.py")):
            self.assertIn(f"python3 -I prototype/m3/{os.path.basename(path)}", text)

    def test_the_unshare_test_has_its_variable(self):
        self.assertIn('ENCLOS_PROTO_NAMESPACES: "1"\n        run: python3 -I prototype/m3/test_probe.py',
                      read(WORKFLOW))

    def test_the_landlock_regression_runs_first_and_has_its_variable(self):
        text = read(WORKFLOW)
        step = text.index("- name: Landlock proc O_TRUNC regression")
        self.assertLess(step, text.index("- name: Set up the runner"))
        self.assertLess(text.index("test_oom.py GrantsTest"), step)
        self.assertIn('ENCLOS_PROTO_LANDLOCK: "1"\n        run: python3 -I prototype/m3/test_oom.py ProcTruncateTest',
                      text[step:])


if __name__ == "__main__":
    unittest.main()
