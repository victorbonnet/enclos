"""Tests of what inside.py does when Landlock or seccomp fails. A stand-in
takes the place of the kernel's answer and of libseccomp, so nothing is applied
to any process and python3-seccomp need not be installed. They run anywhere:

    python3 -I prototype/m3/test_inside.py
"""

import errno
import os
import signal
import socket
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compile as comp  # noqa: E402
import inside

RULES = {"read": [], "execute": [], "write": [], "devices": [], "proc_write": [], "scoped": []}
SPEC = {"errno": "EPERM", "deny": comp.SECCOMP_DENY, "ioctl": {"TIOCSTI": 0x5412},
        "clone_flags": {"CLONE_NEWUSER": 0x10000000}, "enosys": ["clone3"]}


def stand_in(negative=(), raises=()):
    """A `seccomp` module: `negative` names resolve to a negative number, as
    libseccomp answers for a call this architecture lacks or a name it does not
    know, and `raises` names fail in add_rule. load() is recorded."""
    module = types.ModuleType("seccomp")
    module.ALLOW = "allow"
    module.ERRNO = lambda e: ("errno", e)
    module.MASKED_EQ = "masked_eq"
    module.Arg = lambda *a: a
    module.Arch = types.SimpleNamespace(NATIVE=0)
    module.resolve_syscall = lambda arch, name: -101 if name in negative else 1
    module.rules = []
    module.loaded = []

    class SyscallFilter:
        def __init__(self, defaction):
            pass

        def add_rule(self, action, name, *args):
            if name in raises:
                raise RuntimeError(f"no rule for {name}")
            module.rules.append(name)

        def load(self):
            module.loaded.append(True)

    module.SyscallFilter = SyscallFilter
    return module


class LandlockTest(unittest.TestCase):
    def applied(self, err):
        with patch.object(inside, "landlock_abi", return_value=(None, err)):
            inside.apply_landlock(RULES)

    def test_a_kernel_without_landlock_carries_on(self):
        for code in [errno.ENOSYS, errno.EOPNOTSUPP]:
            self.applied(errno.errorcode[code])

    def test_any_other_error_stops_the_session(self):
        for name in ["EPERM", "ENOMEM", "EINVAL", "?"]:
            with self.subTest(name), self.assertRaises(SystemExit):
                self.applied(name)

    def test_the_kernels_answer_reaches_the_decision(self):
        with patch.object(inside.libc, "syscall", return_value=-1), \
                patch.object(inside.ctypes, "get_errno", return_value=errno.EPERM), \
                self.assertRaises(SystemExit):
            inside.apply_landlock(RULES)


class SeccompTest(unittest.TestCase):
    def applied(self, module, machine="x86_64", extra=()):
        with patch.dict(sys.modules, {"seccomp": module}), \
                patch.object(inside.platform, "machine", return_value=machine):
            inside.apply_seccomp({**SPEC, "deny": comp.SECCOMP_DENY + list(extra)})

    def test_every_call_gets_its_rule_and_the_filter_loads(self):
        module = stand_in()
        self.applied(module)
        self.assertLessEqual(set(comp.SECCOMP_DENY), set(module.rules))
        self.assertEqual(module.loaded, [True])

    def test_arm64_skips_its_fixed_set_alone(self):
        absent = {"ioperm", "iopl", "uselib"}
        module = stand_in(negative=absent)
        self.applied(module, "aarch64")
        self.assertEqual(set(comp.SECCOMP_DENY) - set(module.rules), absent)
        self.assertEqual(module.loaded, [True])

    def test_a_call_the_fixed_set_leaves_out_stops_the_session(self):
        for machine, name in [("x86_64", "ioperm"), ("aarch64", "keyctl"), ("aarch64", "not_a_call")]:
            module = stand_in(negative={name})
            with self.subTest(machine=machine, name=name), self.assertRaises(SystemExit):
                self.applied(module, machine, [name])
            self.assertEqual(module.loaded, [])

    def test_a_rule_that_fails_stops_the_session(self):
        module = stand_in(raises={"bpf"})
        with self.assertRaises(SystemExit):
            self.applied(module)
        self.assertEqual(module.loaded, [])


class ServiceForward(unittest.TestCase):
    """The forward forks a child of this test, stopped at the end."""

    def answer_with_port(self, text):
        """What a client of the forward gets when the port file holds `text`."""
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path, port_file = os.path.join(d.name, "service.sock"), os.path.join(d.name, "service.port")
        with open(port_file, "w") as f:
            f.write(text)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        srv.listen()
        real, children = os.fork, []

        def fork():
            pid = real()
            if pid:
                children.append(pid)
            return pid
        with patch("os.fork", fork), patch.object(inside, "say"):
            inside.start_service_forward(srv.detach(), port_file)
        for pid in children:
            self.addCleanup(os.waitpid, pid, 0)
            self.addCleanup(os.kill, pid, signal.SIGKILL)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(path)
            return client.recv(1)

    def test_a_port_out_of_range_reaches_nothing(self):
        # getaddrinfo wraps a port past 65535, so this would reach `other`.
        with socket.socket() as other:
            other.bind(("127.0.0.1", 0))
            other.listen()
            other.settimeout(0.5)
            self.assertEqual(self.answer_with_port(str(65536 + other.getsockname()[1])), b"")
            with self.assertRaises(TimeoutError):
                other.accept()

    def test_no_valid_port_closes_the_connection(self):
        for text in ("0", "nope", ""):
            with self.subTest(text=text):
                self.assertEqual(self.answer_with_port(text), b"")


if __name__ == "__main__":
    unittest.main()
