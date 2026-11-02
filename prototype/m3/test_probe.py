"""Tests of the probes. Those of what the exec probes run copy a shell to a
temporary folder and run it as this user, with no sandbox, so they run
anywhere:

    python3 -I prototype/m3/test_probe.py

UnshareOnRunnerTest makes a namespace in a process of its own. It runs only on
a GitHub-hosted runner with ENCLOS_PROTO_NAMESPACES=1, as the bwrap-prototype
workflow sets, and skips, saying why, anywhere else; UnshareTest stands in for
the call, so it runs anywhere.
"""

import errno
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

M3 = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, M3)
import probe  # noqa: E402

PROBE = f"import sys; sys.path.insert(0, {M3!r}); import probe; print(probe.p_exec(sys.argv[1]))"
COREUTILS = "true|false|cat|cp|echo|env|id|ls|mv|rm|sleep|touch"


class ExecProbeTest(unittest.TestCase):
    def test_a_copied_shell_runs_and_ends_with_stdin_left_open(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            copy = os.path.join(tmp, "sh-copy")
            shutil.copy(os.path.realpath("/bin/sh"), copy)
            r_end, w_end = os.pipe()  # nothing ever writes or closes it here
            self.addCleanup(os.close, r_end)
            self.addCleanup(os.close, w_end)
            r = subprocess.run([sys.executable, "-I", "-c", PROBE, copy], stdin=r_end,
                               capture_output=True, text=True, timeout=15)
        self.assertEqual(r.stdout.strip(), "('ok', '')", r.stderr)

    def test_no_check_copies_a_coreutils_program(self):
        # On a multi-call coreutils the copy's new name is no command it knows.
        for path in glob.glob(os.path.join(M3, "*.sh")):
            with open(path) as f:
                self.assertIsNone(re.search(rf"\bcp\s+\S*/({COREUTILS})\s", f.read()), path)


class UnshareTest(unittest.TestCase):
    def test_the_call_runs_in_another_process_than_the_probes(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            seen = os.path.join(tmp, "pid")

            def stand_in(flag):
                with open(seen, "w") as f:
                    f.write(str(os.getpid()))

            with patch.object(probe.os, "unshare", stand_in):
                self.assertEqual(probe.p_unshare("user"), ("ok", "made a user namespace"))
            with open(seen) as f:
                self.assertNotEqual(int(f.read()), os.getpid())

    def test_the_other_process_reports_its_errno(self):
        for code in [errno.EPERM, errno.ENOSPC, errno.EACCES]:
            with patch.object(probe.os, "unshare", side_effect=OSError(code, "refused")):
                self.assertEqual(probe.p_unshare("net"), (errno.errorcode[code], ""))


class UnshareOnRunnerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        hosted = os.environ.get("GITHUB_ACTIONS") == "true" \
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        if not hosted or os.environ.get("ENCLOS_PROTO_NAMESPACES") != "1":
            raise unittest.SkipTest("makes a namespace, so it runs only on a GitHub-hosted "
                                    "runner with ENCLOS_PROTO_NAMESPACES=1")

    def test_the_probes_process_keeps_its_user_namespace(self):
        before = os.readlink("/proc/self/ns/user")
        result = probe.p_unshare("user")
        print(f"unshare user: {result}")
        self.assertEqual(os.readlink("/proc/self/ns/user"), before)


if __name__ == "__main__":
    unittest.main()
