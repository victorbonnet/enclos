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
from unittest.mock import MagicMock, patch

M3 = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, M3)
import probe  # noqa: E402

PROBE = f"import sys; sys.path.insert(0, {M3!r}); import probe; print(probe.p_exec(sys.argv[1]))"
COREUTILS = "true|false|cat|cp|echo|env|id|ls|mv|rm|sleep|touch"


class SocketFamilyTest(unittest.TestCase):
    def test_a_family_let_through_reads_ok(self):
        self.assertEqual(probe.p_socket_family("1")[0], "ok")

    def test_a_refusal_reads_as_its_error(self):
        with patch.object(probe.socket, "socket", side_effect=PermissionError(errno.EPERM, "")):
            self.assertEqual(probe.p_socket_family("40")[0], "EPERM")


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


class RoutesAroundTheExecuteRuleTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(tmp.cleanup)
        self.copy = os.path.join(tmp.name, "sh-copy")
        shutil.copy(os.path.realpath("/bin/sh"), self.copy)

    def test_the_loader_runs_a_program_as_its_argument(self):
        self.assertEqual(probe.p_exec_loader(self.copy), ("ok", ""))

    def test_a_memfd_runs_what_was_copied_into_it(self):
        self.assertEqual(probe.p_exec_memfd(self.copy), ("ok", ""))

    def test_a_program_that_is_not_there_reads_as_refused_not_as_broken(self):
        self.assertEqual(probe.p_exec_memfd(self.copy + "-gone")[0], "ENOENT")

    def test_sandbox_check_runs_them_on_the_copy_the_execute_rule_refuses(self):
        with open(os.path.join(M3, "sandbox-check.sh")) as f:
            check = f.read()
        self.assertIn('"exec-loader $WORK/sh-copy"', check)
        self.assertIn('"exec-memfd $WORK/sh-copy"', check)


class VsockTest(unittest.TestCase):
    """A stand-in for the socket: making a real one can load a kernel module."""

    def result(self, **kinds):
        sock = MagicMock()
        sock.connect.side_effect = kinds.get("connect")
        make = MagicMock(return_value=sock, side_effect=kinds.get("make"))
        with patch.object(probe.socket, "socket", make):
            return probe.p_connect_vsock("2", "9"), sock

    def test_it_connects_to_the_cid_and_port_it_is_given(self):
        result, sock = self.result()
        self.assertEqual(result, ("ok", "connected"))
        sock.connect.assert_called_once_with((2, 9))
        sock.close.assert_called_once()

    def test_a_refused_connection_reports_its_error(self):
        result, _ = self.result(connect=OSError(errno.ECONNRESET, "reset"))
        self.assertEqual(result, ("ECONNRESET", ""))

    def test_no_such_family_reports_its_error(self):
        result, _ = self.result(make=OSError(errno.EAFNOSUPPORT, "not supported"))
        self.assertEqual(result, ("EAFNOSUPPORT", ""))

    def test_sandbox_check_asks_for_the_hypervisor_and_the_local_cid(self):
        with open(os.path.join(M3, "sandbox-check.sh")) as f:
            check = f.read()
        self.assertIn('"connect-vsock 2 ', check)
        self.assertIn('"connect-vsock 1 ', check)


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
