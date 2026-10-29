"""Tests of the prototype's compile step, on a temporary folder standing in
for the home. They read and write nothing else and run no bubblewrap, so
they run anywhere:

    python3 -I prototype/m3/test_compile.py
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compile as comp  # noqa: E402


class CompileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        h = self.h = os.path.join(self.tmp.name, "home")
        for d in [".ssh", ".config/google-chrome", ".config/other", "work", "proj"]:
            os.makedirs(os.path.join(h, d))
        open(os.path.join(h, "notes.txt"), "w").close()
        os.symlink("notes.txt", os.path.join(h, "link"))
        self.sbx = os.path.join(h, ".enclos/sandboxes/s1")
        os.makedirs(self.sbx)

    def tearDown(self):
        self.tmp.cleanup()

    def compiled(self, *extra):
        out = os.path.join(self.tmp.name, "compiled.json")
        comp.main(["--host-home", self.h, "--sandbox-dir", self.sbx,
                   "--workspace", f"{self.h}/proj",
                   "--deny", f"{self.h}/.ssh", "--deny", f"{self.h}/.config/google-chrome",
                   "--deny", f"{self.h}/.enclos", "--out", out, *extra])
        with open(out) as f:
            return json.load(f)

    def pairs(self, args, option):
        return [args[i + 1] for i, a in enumerate(args) if a == option]

    def test_denied_paths_are_not_mounted(self):
        args = self.compiled()["bwrap"]
        binds = self.pairs(args, "--ro-bind")
        h = self.h
        self.assertEqual(self.pairs(args, "--tmpfs")[:2], [h, f"{h}/.config"])
        for denied in [".ssh", ".config/google-chrome", ".enclos"]:
            self.assertNotIn(f"{h}/{denied}", binds)
        for kept in ["notes.txt", "work", "proj", ".config/other"]:
            self.assertIn(f"{h}/{kept}", binds)
        self.assertIn("notes.txt", self.pairs(args, "--symlink"))

    def test_folders_that_hide_a_path_go_read_only_after_every_mount(self):
        args = self.compiled()["bwrap"]
        self.assertEqual(self.pairs(args, "--remount-ro"), [self.h, f"{self.h}/.config"])
        last_mount = max(i for i, a in enumerate(args) if a in ("--bind", "--ro-bind", "--tmpfs"))
        self.assertLess(last_mount, args.index("--remount-ro"))

    def test_the_sandbox_writes_its_home_and_workspaces_only(self):
        c = self.compiled()
        home = f"{self.sbx}/home"
        self.assertEqual(self.pairs(c["bwrap"], "--bind"), [home, f"{self.h}/proj"])
        self.assertIn(f"{self.sbx}/run", self.pairs(c["bwrap"], "--ro-bind"))
        self.assertEqual(c["landlock"]["write"][:2], [home, f"{self.h}/proj"])
        self.assertIn(home, c["landlock"]["execute"])
        self.assertNotIn(f"{self.h}/proj", c["landlock"]["execute"])

    def test_namespaces_and_no_user_namespace_inside(self):
        args = self.compiled()["bwrap"]
        for opt in ["--unshare-user", "--disable-userns", "--unshare-pid", "--unshare-net",
                    "--unshare-ipc", "--clearenv", "--die-with-parent"]:
            self.assertIn(opt, args)
        self.assertNotIn("--new-session", args)
        self.assertIn("--new-session", self.compiled("--new-session")["bwrap"])

    def test_seccomp_refuses_the_listed_calls(self):
        s = self.compiled()["seccomp"]
        for call in ["keyctl", "bpf", "perf_event_open", "userfaultfd", "mount", "setns"]:
            self.assertIn(call, s["deny"])
        self.assertEqual(s["ioctl"]["TIOCSTI"], 0x5412)
        self.assertEqual(s["clone_flags"]["CLONE_NEWUSER"], 0x10000000)
        self.assertEqual(s["enosys"], ["clone3"])

    def test_a_deny_entry_outside_the_home_is_refused(self):
        with self.assertRaises(SystemExit):
            comp.main(["--host-home", self.h, "--sandbox-dir", self.sbx, "--deny", "/etc/shadow",
                       "--out", os.path.join(self.tmp.name, "x.json")])


if __name__ == "__main__":
    unittest.main()
