"""Tests of what the exec probes run. They copy a shell to a temporary folder
and run it as this user, with no sandbox, so they run anywhere:

    python3 -I prototype/m3/test_probe.py
"""

import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

M3 = os.path.dirname(os.path.abspath(__file__))
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


if __name__ == "__main__":
    unittest.main()
