"""The /proc rule's TRUNCATE, kept out of the grant and handled all the same
(design §14). A write with `>` opens the file with O_TRUNC, so with TRUNCATE
handled and the draft rules, a shell's write to its own oom_score_adj must be
refused, and with `proc_truncate` it must pass. What Chromium does is not
tested here.

GrantsTest touches nothing, so it runs anywhere:

    python3 -I prototype/m3/test_oom.py GrantsTest

ProcTruncateTest applies Landlock to one child process, which then writes its
own value and exits; the test's process and the host's services are left
alone. It runs only on a GitHub-hosted runner with ENCLOS_PROTO_LANDLOCK=1, as
the bwrap-prototype workflow sets, and skips, saying why, anywhere else or
where the kernel's Landlock has no TRUNCATE.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

M3 = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, M3)
import compile as comp  # noqa: E402
import inside

TRUNCATE_BIT = 1 << 14  # LANDLOCK_ACCESS_FS_TRUNCATE
WRITE = "echo 0 > /proc/self/oom_score_adj"
CHILD = """
import json, os, sys
sys.path.insert(0, sys.argv[1])
import inside
inside.apply_landlock(json.loads(sys.argv[2]), proc_truncate=sys.argv[3] == "1")
os.execl("/bin/sh", "sh", "-c", sys.argv[4])
"""


def draft_rules():
    """The Landlock rules compile.py writes, for a temporary home."""
    with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
        home = os.path.realpath(os.path.join(tmp, "home"))
        os.mkdir(home)
        out = os.path.join(tmp, "compiled.json")
        comp.main(["--host-home", home, "--sandbox-dir", f"{home}/.enclos/sandboxes/proto", "--out", out])
        with open(out) as f:
            return json.load(f)["landlock"]


def refusal(env):
    """Why this environment may not apply Landlock to a process, or None."""
    if env.get("GITHUB_ACTIONS") != "true" or env.get("RUNNER_ENVIRONMENT") != "github-hosted":
        return "applies Landlock to a process, so it runs only on a GitHub-hosted runner"
    if env.get("ENCLOS_PROTO_LANDLOCK") != "1":
        return "applies Landlock to a process, so it runs only with ENCLOS_PROTO_LANDLOCK=1"
    return None


def missing_truncate(abi, err):
    """Why this kernel's Landlock cannot show the refusal, or None."""
    if abi is None:
        return f"no Landlock on this kernel ({err})"
    if abi < 3:
        return f"Landlock ABI {abi} has no TRUNCATE (it came with ABI 3)"
    return None


class ProcTruncateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        why = refusal(os.environ)
        if why:
            raise unittest.SkipTest(why)
        cls.abi, err = inside.landlock_abi()
        why = missing_truncate(cls.abi, err)
        if why:
            raise unittest.SkipTest(why)
        cls.rules = draft_rules()

    def write_under_landlock(self, proc_truncate):
        r = subprocess.run(
            [sys.executable, "-I", "-c", CHILD, M3, json.dumps(self.rules),
             "1" if proc_truncate else "0", WRITE],
            capture_output=True, text=True, timeout=30, env={**os.environ, "LC_ALL": "C"})
        print(f"proc_truncate={proc_truncate}: exit {r.returncode}: {r.stderr.strip()}")
        applied = re.search(r"landlock=applied abi=\d+ handled=0x([0-9a-f]+)", r.stderr)
        self.assertTrue(applied, r.stderr)
        self.assertTrue(int(applied.group(1), 16) & TRUNCATE_BIT, r.stderr)
        self.assertTrue(inside.handled_for(self.abi) & TRUNCATE_BIT)
        return r

    def test_the_draft_rules_refuse_the_write(self):
        r = self.write_under_landlock(proc_truncate=False)
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("Permission denied", r.stderr)

    def test_truncate_on_the_proc_rule_lets_the_write_through(self):
        r = self.write_under_landlock(proc_truncate=True)
        self.assertEqual(r.returncode, 0, r.stderr)


class GrantsTest(unittest.TestCase):
    def test_the_bit_is_the_kernels(self):
        self.assertEqual(inside.TRUNCATE, TRUNCATE_BIT)

    def test_the_proc_grant_leaves_truncate_out_by_default(self):
        self.assertFalse(dict(inside.landlock_grants(draft_rules()))["/proc"] & TRUNCATE_BIT)

    def test_the_proc_grant_holds_truncate_when_asked(self):
        grants = dict(inside.landlock_grants(draft_rules(), proc_truncate=True))
        self.assertTrue(grants["/proc"] & TRUNCATE_BIT)

    def test_only_the_proc_grant_changes(self):
        rules = draft_rules()
        without = dict(inside.landlock_grants(rules))
        asked = dict(inside.landlock_grants(rules, proc_truncate=True))
        self.assertEqual([p for p in asked if asked[p] != without[p]], ["/proc"])
        for path in rules["write"] + rules["devices"]:
            self.assertTrue(without[path] & TRUNCATE_BIT, path)

    def test_truncate_is_handled_from_abi_3(self):
        self.assertFalse(inside.handled_for(2) & TRUNCATE_BIT)
        for abi in range(3, 10):
            self.assertTrue(inside.handled_for(abi) & TRUNCATE_BIT, abi)

    def test_only_a_github_hosted_runner_with_the_variable_may_apply_landlock(self):
        hosted = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
        self.assertIsNone(refusal({**hosted, "ENCLOS_PROTO_LANDLOCK": "1"}))
        self.assertIn("ENCLOS_PROTO_LANDLOCK=1", refusal(hosted))
        for env in [{}, {"ENCLOS_PROTO_LANDLOCK": "1"},
                    {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted",
                     "ENCLOS_PROTO_LANDLOCK": "1"}]:
            self.assertIn("GitHub-hosted runner", refusal(env))

    def skipped(self, abi=None):
        """Runs ProcTruncateTest with nothing able to apply Landlock; the reasons it skipped."""
        result = unittest.TestResult()
        with patch.object(inside, "landlock_abi", return_value=abi) as ask, \
                patch.object(subprocess, "run") as run:
            unittest.defaultTestLoader.loadTestsFromTestCase(ProcTruncateTest).run(result)
        run.assert_not_called()
        self.assertTrue(result.wasSuccessful())
        return ask, [why for _, why in result.skipped]

    def test_outside_a_runner_it_skips_before_asking_the_kernel(self):
        with patch.dict(os.environ, clear=True):
            ask, reasons = self.skipped()
        ask.assert_not_called()
        self.assertIn("GitHub-hosted runner", reasons[0])

    def test_it_skips_on_a_kernel_without_truncate(self):
        for abi, why in [((None, "ENOSYS"), "no Landlock on this kernel (ENOSYS)"),
                         ((2, None), "Landlock ABI 2 has no TRUNCATE")]:
            with patch(f"{__name__}.refusal", return_value=None):
                _, reasons = self.skipped(abi)
            self.assertIn(why, reasons[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
