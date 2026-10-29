"""Tests of nsjoin.py: each way of joining the sandbox's namespaces rewrites
the compiled arguments as its docstring says. Pure, so it runs anywhere:

    python3 -I prototype/m3/test_nsjoin.py
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nsjoin  # noqa: E402

COMPILED = ["--ro-bind", "/", "/", "--unshare-user", "--disable-userns", "--unshare-pid",
            "--unshare-net", "--unshare-ipc", "--die-with-parent", "--chdir", "/h"]


class Join(unittest.TestCase):
    def test_own_changes_nothing(self):
        self.assertEqual(nsjoin.join(COMPILED, "own"), ([], COMPILED, []))

    def test_every_joined_way_shares_the_network_and_closes_the_descriptors(self):
        for way in nsjoin.WAYS[1:]:
            prefix, args, inside = nsjoin.join(COMPILED, way)
            self.assertNotIn("--unshare-net", args, way)
            for fd in ("10", "11", "12"):
                self.assertIn(["--close-fd", fd], [inside[i:i + 2] for i in range(len(inside))], way)
            self.assertIn("--unshare-ipc", args, way)
            self.assertEqual(args[-2:], ["--chdir", "/h"], way)

    def test_nsenter_nests_a_user_namespace_and_keeps_its_own_pids(self):
        prefix, args, _ = nsjoin.join(COMPILED, "nsenter")
        self.assertEqual(prefix, ["nsenter", "--user=/proc/self/fd/10", "--net=/proc/self/fd/12",
                                  "--preserve-credentials", "--"])
        self.assertIn("--unshare-user", args)
        self.assertIn("--unshare-pid", args)

    def test_nsenter_pid_enters_the_holders_pids(self):
        prefix, args, _ = nsjoin.join(COMPILED, "nsenter-pid")
        self.assertIn("--pid=/proc/self/fd/11", prefix)
        self.assertNotIn("--unshare-pid", args)

    def test_nsenter_userns_hands_bubblewrap_the_user_namespace_it_is_in(self):
        _, args, _ = nsjoin.join(COMPILED, "nsenter-userns")
        self.assertEqual(args[:2], ["--userns", "10"])
        self.assertNotIn("--unshare-user", args)
        self.assertNotIn("--disable-userns", args)

    def test_userns_joins_user_and_pid_and_leaves_the_network_to_inside(self):
        prefix, args, inside = nsjoin.join(COMPILED, "userns")
        self.assertEqual(prefix, [])
        self.assertEqual(args[:6], ["--userns", "10", "--pidns", "11", "--cap-add", "CAP_SYS_ADMIN"])
        for flag in ("--unshare-user", "--disable-userns", "--unshare-pid"):
            self.assertNotIn(flag, args)
        self.assertEqual(inside[:2], ["--setns-net-fd", "12"])

    def test_userns_subpid_keeps_a_pid_namespace_of_its_own(self):
        _, args, _ = nsjoin.join(COMPILED, "userns-subpid")
        self.assertIn("--unshare-pid", args)
        self.assertIn("--pidns", args)

    def test_an_unknown_way_is_refused(self):
        with self.assertRaises(ValueError):
            nsjoin.join(COMPILED, "other")


class Command(unittest.TestCase):
    def test_the_extra_options_go_before_inside_pys_separator(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "compiled.json")
            with open(path, "w") as f:
                json.dump({"bwrap": COMPILED}, f)
            out = subprocess.run(
                [sys.executable, "-I", nsjoin.__file__, "--compiled", path, "--join", "userns", "--",
                 "python3", "-I", "inside.py", "--seccomp", "on", "--", "sh", "-c", "a -- b"],
                capture_output=True, check=True).stdout.decode()
        cmd = out.split("\0")[:-1]
        self.assertEqual(cmd[0], "bwrap")
        sep = cmd.index("--")
        self.assertEqual(cmd[1:sep][:2], ["--userns", "10"])
        self.assertEqual(cmd[sep + 1:sep + 6], ["python3", "-I", "inside.py", "--seccomp", "on"])
        self.assertEqual(cmd[sep + 6:sep + 8], ["--setns-net-fd", "12"])
        self.assertEqual(cmd[-4:], ["--", "sh", "-c", "a -- b"])


if __name__ == "__main__":
    unittest.main()
