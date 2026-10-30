"""Tests of the prototype's compile and wrap steps, on a temporary folder standing in
for the home. They read and write nothing else and run no bubblewrap, so
they run anywhere:

    python3 -I prototype/m3/test_compile.py
"""

import argparse
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compile as comp  # noqa: E402
import inside
import wrap
from unittest.mock import patch


def view(args, path):
    """What the sandbox sees at `path` once bubblewrap has run `args`: the
    last mount made at or above it, as (option, writable)."""
    mounts = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--bind", "--ro-bind", "--ro-bind-try"):
            mounts.append([a, args[i + 1], args[i + 2], a == "--bind"])
            i += 3
        elif a == "--tmpfs":
            # The sandbox's own /tmp is left out: the test's home may be under it.
            if args[i + 1] not in comp.OWN_TMPFS:
                mounts.append([a, None, args[i + 1], True])
            i += 2
        elif a == "--remount-ro":
            [m for m in mounts if m[2] == args[i + 1]][-1][3] = False
            i += 2
        else:
            i += 1
    for option, _, dest, writable in reversed(mounts):
        if comp.under(path, dest):
            return option, writable
    raise AssertionError(f"nothing mounted at {path}")


class Case(unittest.TestCase):
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
            c = json.load(f)
            c["bwrap"] = wrap.arguments(c, wrap.read_host(c))
            return c

    def bare(self, *extra):
        """The compiled policy, before the wrap step."""
        out = f"{self.tmp.name}/bare.json"
        comp.main(["--host-home", self.h, "--sandbox-dir", self.sbx, "--workspace", f"{self.h}/proj",
                   "--deny", f"{self.h}/.ssh", "--deny", f"{self.h}/.config/google-chrome",
                   "--out", out, *extra])
        with open(out) as f:
            return json.load(f)

    def pairs(self, args, option):
        return [args[i + 1] for i, a in enumerate(args) if a == option]


class CompileTest(Case):
    def test_denied_paths_are_not_mounted(self):
        args = self.compiled()["bwrap"]
        binds = self.pairs(args, "--ro-bind-try")
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
        self.assertEqual(self.pairs(c["bwrap"], "--bind"), [f"{self.h}/proj", home])
        self.assertIn(f"{self.sbx}/run/visible", self.pairs(c["bwrap"], "--ro-bind"))
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

    def test_the_proc_rule_holds_truncate_only_when_asked(self):
        rules = self.compiled()["landlock"]
        for asked, granted in [(False, 0), (True, inside.TRUNCATE)]:
            rights = dict(inside.landlock_grants(rules, asked))["/proc"]
            self.assertEqual(rights & inside.TRUNCATE, granted)

    def test_a_deny_entry_outside_the_home_is_refused(self):
        with self.assertRaises(SystemExit):
            comp.main(["--host-home", self.h, "--sandbox-dir", self.sbx, "--deny", "/etc/shadow",
                       "--out", os.path.join(self.tmp.name, "x.json")])


    def test_a_grant_at_or_inside_a_deny_entry_is_refused(self):
        deny = f"{self.h}/dev/work"
        for option in ["--workspace", "--read-only"]:
            for grant in [deny, f"{deny}/child"]:
                with self.subTest(option=option, grant=grant), self.assertRaises(SystemExit):
                    self.compiled(option, grant, "--deny", deny)

    def test_a_grant_through_a_link_into_a_deny_entry_is_refused(self):
        os.symlink(".ssh", f"{self.h}/keys")
        with self.assertRaises(SystemExit):
            self.compiled("--workspace", f"{self.h}/keys")

    def test_compile_reads_nothing_of_the_host(self):
        refused = AssertionError("compile read the host")
        with patch.object(comp.os, "listdir", side_effect=refused), \
                patch.object(comp.os, "scandir", side_effect=refused), \
                patch.object(comp.os, "readlink", side_effect=refused), \
                patch.object(comp.os, "lstat", side_effect=refused), \
                patch.object(comp.os, "stat", side_effect=refused):
            c = comp.compile_policy(argparse.Namespace(
                host_home=self.h, sandbox_dir=self.sbx, workspace=[f"{self.h}/proj"], read_only=[],
                deny=[f"{self.h}/.ssh"], relay_port=18080, new_session=False))
        self.assertIn("@HOME_MASK@", c["bwrap"])
        self.assertIn("@GRANT_MASK@", c["bwrap"])

    def test_wrap_uses_only_the_listing_it_is_given(self):
        h = self.h
        c = self.bare()
        listing = {
            "entries": {h: {"stubbed": None, "stub-link": "there", ".ssh": None, ".config": None},
                        f"{h}/.config": {"other": None}},
            "resolved": {p: p for p in c["home_mask"]["denied"] + [f"{h}/proj"]},
            "kinds": {},
        }
        with patch.object(wrap.os, "listdir", side_effect=AssertionError("wrap listed the host")):
            args = wrap.arguments(c, listing)
        binds = self.pairs(args, "--ro-bind-try")
        self.assertEqual(binds, [f"{h}/.config/other", f"{h}/stubbed"])
        self.assertNotIn(f"{h}/notes.txt", binds)
        self.assertIn("there", self.pairs(args, "--symlink"))
        self.assertNotIn("@HOME_MASK@", args)
        self.assertNotIn("@GRANT_MASK@", args)

    def test_the_listing_is_taken_at_each_session_start(self):
        c = self.bare()
        open(f"{self.h}/new-at-launch", "w").close()
        self.assertIn(f"{self.h}/new-at-launch", wrap.arguments(c, wrap.read_host(c)))
        os.unlink(f"{self.h}/new-at-launch")
        self.assertNotIn(f"{self.h}/new-at-launch", wrap.arguments(c, wrap.read_host(c)))

    def test_an_entry_deleted_after_compile_leaves_a_valid_command(self):
        h = self.h
        c = self.bare()
        for gone in [f"{h}/notes.txt", f"{h}/link"]:
            os.unlink(gone)
        os.rmdir(f"{h}/.config/other")
        os.rmdir(f"{h}/.config/google-chrome")
        os.rmdir(f"{h}/.config")
        args = wrap.arguments(c, wrap.read_host(c))
        self.assertNotIn(f"{h}/notes.txt", args)
        self.assertEqual(self.pairs(args, "--tmpfs")[0], h)
        self.assertNotIn(f"{h}/.config", args)

    def test_an_entry_deleted_after_the_listing_is_bound_with_try(self):
        c = self.bare()
        listing = wrap.read_host(c)
        os.unlink(f"{self.h}/notes.txt")
        args = wrap.arguments(c, listing)
        self.assertEqual(args[args.index(f"{self.h}/notes.txt") - 1], "--ro-bind-try")
        for i, a in enumerate(args):
            if a == "--ro-bind":
                self.assertNotEqual(args[i + 1], f"{self.h}/notes.txt")

    def test_a_folder_that_cannot_be_listed_stops_the_session(self):
        c = self.bare()
        with patch.object(wrap.os, "listdir", side_effect=PermissionError), \
                self.assertRaises(PermissionError):
            wrap.read_host(c)


class DenyInsideAGrantTest(Case):
    """Design §5: a grant may hold a deny entry; the entry stays hidden and
    the rest of the grant stays as granted."""

    def setUp(self):
        super().setUp()
        for d in ["dev/work", "dev/other", "dev/deep/er/secret"]:
            os.makedirs(f"{self.h}/{d}")
        open(f"{self.h}/dev/token", "w").close()

    def test_a_folder_denied_inside_a_workspace(self):
        h = self.h
        args = self.compiled("--workspace", f"{h}/dev", "--deny", f"{h}/dev/work")["bwrap"]
        self.assertEqual(view(args, f"{h}/dev/work"), ("--tmpfs", False))
        self.assertEqual(view(args, f"{h}/dev/work/old-file"), ("--tmpfs", False))
        self.assertEqual(view(args, f"{h}/dev"), ("--bind", True))
        self.assertEqual(view(args, f"{h}/dev/other"), ("--bind", True))
        self.assertEqual(view(args, f"{h}/dev/new-file"), ("--bind", True))
        self.assertEqual(view(args, h), ("--tmpfs", False))

    def test_a_file_denied_inside_a_workspace(self):
        h = self.h
        args = self.compiled("--workspace", f"{h}/dev", "--deny", f"{h}/dev/token")["bwrap"]
        self.assertEqual(view(args, f"{h}/dev/token"), ("--ro-bind", False))
        self.assertIn("/dev/null", self.pairs(args, "--ro-bind"))
        self.assertEqual(view(args, f"{h}/dev/other"), ("--bind", True))

    def test_a_deny_entry_deep_inside_a_workspace_inside_a_masked_folder(self):
        h = self.h
        args = self.compiled("--workspace", f"{h}/dev/deep", "--deny", f"{h}/dev/deep/er/secret",
                             "--deny", f"{h}/dev/work")["bwrap"]
        self.assertEqual(view(args, f"{h}/dev/deep/er/secret"), ("--tmpfs", False))
        self.assertEqual(view(args, f"{h}/dev/deep/er"), ("--bind", True))
        self.assertEqual(view(args, f"{h}/dev"), ("--tmpfs", False))
        self.assertEqual(view(args, f"{h}/dev/other"), ("--ro-bind-try", False))
        self.assertNotIn(f"{h}/dev/work", self.pairs(args, "--ro-bind-try"))

    def test_a_deny_entry_inside_a_read_only_grant(self):
        h = self.h
        args = self.compiled("--read-only", f"{h}/dev", "--deny", f"{h}/dev/work",
                             "--deny", f"{h}/dev/token")["bwrap"]
        self.assertEqual(view(args, f"{h}/dev/work"), ("--tmpfs", False))
        self.assertEqual(view(args, f"{h}/dev/token"), ("--ro-bind", False))
        self.assertEqual(view(args, f"{h}/dev/other"), ("--ro-bind", False))

    def test_a_workspace_reached_through_a_link_still_hides_what_it_holds(self):
        h = self.h
        os.symlink("dev", f"{h}/d")
        args = self.compiled("--workspace", f"{h}/d", "--deny", f"{h}/dev/work")["bwrap"]
        self.assertEqual(view(args, f"{h}/d/work"), ("--tmpfs", False))

    def test_the_users_whole_home_as_a_workspace(self):
        h = self.h
        args = self.compiled("--workspace", h)["bwrap"]
        self.assertEqual(view(args, f"{h}/new-file"), ("--bind", True))
        self.assertEqual(view(args, f"{h}/.ssh"), ("--tmpfs", False))
        self.assertEqual(view(args, f"{h}/.enclos"), ("--tmpfs", False))
        self.assertEqual(view(args, f"{self.sbx}/home"), ("--bind", True))
        self.assertEqual(view(args, f"{self.sbx}/compiled"), ("--ro-bind", False))

    def test_a_deny_entry_that_does_not_exist_cannot_be_made_in_a_workspace(self):
        h = self.h
        args = self.compiled("--workspace", f"{h}/dev", "--deny", f"{h}/dev/not-yet")["bwrap"]
        self.assertEqual(view(args, f"{h}/dev/not-yet"), ("--tmpfs", False))

    def test_a_deny_entry_that_does_not_exist_in_a_read_only_grant_needs_no_mount(self):
        # bubblewrap could not make its mount point there, and nothing can make the path.
        h = self.h
        args = self.compiled("--read-only", f"{h}/dev", "--deny", f"{h}/dev/not-yet")["bwrap"]
        self.assertEqual(view(args, f"{h}/dev/not-yet"), ("--ro-bind", False))


if __name__ == "__main__":
    unittest.main()
