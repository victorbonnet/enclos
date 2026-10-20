"""Exercise install.sh without network access or changes to the host.

Run with: python3 tests/test_install.py
"""

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"
PACKAGER = ROOT / "scripts" / "package-release.sh"
ASSET = "enclos-aarch64-apple-darwin.tar.gz"
RELEASES = "https://github.com/victorbonnet/enclos/releases"

STUB = r'''
import json
import os
from pathlib import Path
import sys

name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["INSTALL_TEST_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"command": name, "args": args}) + "\n")

def value(key, default):
    return os.environ.get("INSTALL_TEST_" + key, default)

if name == "uname":
    print(value("ARCH", "arm64") if "-m" in args else value("OS", "Darwin"))
elif name == "sysctl":
    capable = value("ARM64_CAPABLE", "1")
    if not capable:
        sys.exit(1)
    print(capable)
elif name == "id":
    print(value("UID", "501"))
elif name == "sw_vers":
    print(value("MACOS_VERSION", "14.7"))
elif name == "curl":
    urls = [arg for arg in args if arg.startswith("https://")]
    if len(urls) != 1:
        sys.exit(96)
    url = urls[0]
    output = None
    for index, arg in enumerate(args):
        if arg in ("-o", "--output"):
            output = args[index + 1]
    if url.endswith("/releases/latest"):
        if value("LATEST_FAIL", "0") == "1":
            sys.exit(22)
        print(value("LATEST_URL", "https://github.com/victorbonnet/enclos/releases/tag/v0.2.0"), end="")
        sys.exit(0)
    if "/releases/download/" not in url:
        sys.exit(95)
    if url.endswith(".tar.gz.sha256"):
        if value("CHECKSUM_DOWNLOAD_FAIL", "0") == "1":
            sys.exit(22)
        data = Path(os.environ["INSTALL_TEST_CHECKSUM"]).read_bytes()
    elif url.endswith(".tar.gz"):
        if value("ASSET_DOWNLOAD_FAIL", "0") == "1":
            sys.exit(22)
        data = Path(os.environ["INSTALL_TEST_RELEASE_ARCHIVE"]).read_bytes()
    else:
        sys.exit(95)
    Path(output).write_bytes(data)
elif name == "tar":
    mode = args[0] if args else ""
    if "t" in mode and value("LIST_FAIL", "0") == "1":
        sys.exit(2)
    if "x" in mode and value("EXTRACT_FAIL", "0") == "1":
        sys.exit(2)
    os.execv("/usr/bin/tar", ["/usr/bin/tar", *args])
else:
    sys.exit(99)
'''


def fake_enclos(version="0.2.0", *, fails=False):
    """A stand-in release binary that logs its calls and prints its version."""
    return (
        "#!" + sys.executable + "\n"
        "import json, os, sys\n"
        "with open(os.environ['INSTALL_TEST_LOG'], 'a') as log:\n"
        "    log.write(json.dumps({'command': 'enclos', 'args': sys.argv[1:]}) + '\\n')\n"
        "print('enclos " + version + "')\n"
        + ("sys.exit(42)\n" if fails else "")
    ).encode()


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="enclos installer test ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home with spaces"
        self.home.mkdir()
        self.temp = self.root / "temporary files"
        self.temp.mkdir()
        self.bin = self.root / "command stubs"
        self.bin.mkdir()
        self.log = self.root / "commands.jsonl"
        for command in ("uname", "sysctl", "id", "sw_vers", "curl", "tar"):
            stub = self.bin / command
            stub.write_text("#!" + sys.executable + "\n" + textwrap.dedent(STUB), encoding="utf-8")
            stub.chmod(0o755)
        self.installer = self.root / "install.sh"
        shutil.copyfile(INSTALLER, self.installer)
        self.release_archive = self.root / "release.tar.gz"
        self.make_archive(self.release_archive, {"enclos": fake_enclos()})
        self.startup_files = {}
        for name in (".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile"):
            path = self.home / name
            contents = "# Existing user settings: " + name + "\n"
            path.write_text(contents, encoding="utf-8")
            self.startup_files[path] = contents

    def make_archive(self, path, files, *, links=None):
        with tarfile.open(path, "w:gz") as archive:
            for name, data in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mode = 0o755
                archive.addfile(entry, io.BytesIO(data))
            for name, target in (links or {}).items():
                entry = tarfile.TarInfo(name)
                entry.type = tarfile.SYMTYPE
                entry.linkname = target
                archive.addfile(entry)

    def installed_binary(self, prefix=None):
        return (prefix or self.home / ".local") / "bin" / "enclos"

    def seed_existing_binary(self, prefix=None):
        binary = self.installed_binary(prefix)
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"existing installation\n")
        binary.chmod(0o755)
        return binary

    def run_installer(self, *args, settings=None, archive=None, checksum=None, path_first=(), script=None):
        """Runs the installer as a file, or piped when `script` gives its text."""
        archive = archive or self.release_archive
        if checksum is None:
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + ASSET + "\n"
        checksum_file = self.root / "release.tar.gz.sha256"
        checksum_file.write_text(checksum)
        env = {
            "HOME": str(self.home),
            "TMPDIR": str(self.temp),
            "PATH": ":".join([*map(str, path_first), str(self.bin), "/usr/bin", "/bin"]),
            "LC_ALL": "C",
            "INSTALL_TEST_LOG": str(self.log),
            "INSTALL_TEST_RELEASE_ARCHIVE": str(archive),
            "INSTALL_TEST_CHECKSUM": str(checksum_file),
        }
        for key, value in (settings or {}).items():
            env["INSTALL_TEST_" + key] = value
        command = ["/bin/bash", "-s", "--"] if script is not None else ["/bin/bash", str(self.installer)]
        result = subprocess.run(
            [*command, *map(str, args)],
            cwd=self.root,
            env=env,
            input=script,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        for path, contents in self.startup_files.items():
            self.assertEqual(path.read_text(encoding="utf-8"), contents)
        self.assertFalse((self.home / ".enclos").exists(), "installer initialized enclos state")
        self.assertEqual(list(self.temp.iterdir()), [], "temporary installer files were not cleaned up")
        return result

    def commands(self, name=None):
        events = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return [event for event in events if name is None or event["command"] == name]

    def urls(self):
        return [arg for event in self.commands("curl") for arg in event["args"] if arg.startswith("https://")]

    def assert_failed(self, result, message):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)
        self.assertNotIn("Installed enclos", result.stdout)

    def test_installs_the_latest_release_from_a_file_or_a_pipe(self):
        for piped in (False, True):
            with self.subTest(piped=piped):
                self.log.unlink(missing_ok=True)
                self.installed_binary().unlink(missing_ok=True)
                result = self.run_installer(script=INSTALLER.read_text() if piped else None)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.urls(), [
                    RELEASES + "/latest",
                    RELEASES + "/download/v0.2.0/" + ASSET,
                    RELEASES + "/download/v0.2.0/" + ASSET + ".sha256",
                ])
                binary = self.installed_binary()
                with tarfile.open(self.release_archive, "r:gz") as archive:
                    self.assertEqual(binary.read_bytes(), archive.extractfile("enclos").read())
                self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
                self.assertEqual(self.commands("enclos"), [{"command": "enclos", "args": ["--version"]}])
                self.assertIn("enclos 0.2.0", result.stdout)
                self.assertIn("Installed enclos in " + str(self.home / ".local") + "/bin.", result.stdout)
                self.assertIn("export PATH=", result.stdout)
                self.assertNotIn("Another enclos", result.stdout)

    def test_every_download_is_https_only_and_bounded(self):
        self.run_installer()
        calls = self.commands("curl")
        self.assertEqual(len(calls), 3)
        for call in calls:
            args = call["args"]
            for flag, value in (("--proto", "=https"), ("--proto-redir", "=https")):
                self.assertEqual(args[args.index(flag) + 1], value, args)
            for flag in ("--tlsv1.2", "--fail", "--connect-timeout", "--max-time"):
                self.assertIn(flag, args)

    def test_the_old_binary_is_replaced_in_one_step(self):
        prefix = self.root / "custom prefix"
        binary = self.seed_existing_binary(prefix)
        # A hard link keeps the old file's content only if the installer
        # renames a new file into place instead of writing over the old one.
        old = binary.parent / "old"
        os.link(binary, old)
        result = self.run_installer("--prefix", str(prefix) + "//")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(old.read_bytes(), b"existing installation\n")
        self.assertNotEqual(binary.read_bytes(), b"existing installation\n")
        self.assertEqual(sorted(p.name for p in binary.parent.iterdir()), ["enclos", "old"])

    def test_no_release_yet_is_said_and_nothing_is_downloaded(self):
        for url in (RELEASES, RELEASES + "/"):
            with self.subTest(url=url):
                self.log.unlink(missing_ok=True)
                self.assert_failed(self.run_installer(settings={"LATEST_URL": url}), "no published release yet")
                self.assertEqual(self.urls(), [RELEASES + "/latest"])
                self.assertFalse(self.installed_binary().exists())

    def test_an_unexpected_latest_answer_downloads_nothing(self):
        for url, message in (
            (RELEASES + "/latest", "GitHub did not name a release"),
            ("https://github.com/other/repository/releases/tag/v0.2.0", "GitHub did not name a release"),
            (RELEASES + "/tag/v0.2.0-rc.1", "Unexpected release tag"),
            (RELEASES + "/tag/v0.2.0/../../x", "Unexpected release tag"),
        ):
            with self.subTest(url=url):
                self.log.unlink(missing_ok=True)
                self.assert_failed(self.run_installer(settings={"LATEST_URL": url}), message)
                self.assertEqual(self.urls(), [RELEASES + "/latest"])

    def test_each_failure_says_why_and_keeps_the_existing_binary(self):
        digest = hashlib.sha256(self.release_archive.read_bytes()).hexdigest()
        archives = {}
        def archive(name, files, links=None):
            path = self.root / (name + ".tar.gz")
            self.make_archive(path, files, links=links)
            archives[name] = path
            return path
        not_gzip = self.root / "not gzip.tar.gz"
        not_gzip.write_bytes(b"not a gzip archive")
        cases = [
            ({"settings": {"LATEST_FAIL": "1"}}, "Could not get the latest release"),
            ({"settings": {"ASSET_DOWNLOAD_FAIL": "1"}}, "Could not download " + ASSET),
            ({"settings": {"CHECKSUM_DOWNLOAD_FAIL": "1"}}, "Could not download the checksum"),
            ({"checksum": "0" * 64 + "  " + ASSET + "\n"}, "checksum does not match"),
            ({"checksum": digest + "  other.tar.gz\n"}, "checksum names another file"),
            ({"checksum": digest + "  " + ASSET + " extra\n"}, "checksum file is invalid"),
            ({"checksum": digest.upper() + "  " + ASSET + "\n"}, "checksum file is invalid"),
            ({"checksum": digest[:63] + "  " + ASSET + "\n"}, "checksum file is invalid"),
            ({"checksum": ""}, "checksum file is invalid"),
            ({"settings": {"LIST_FAIL": "1"}}, "cannot be read"),
            ({"archive": not_gzip, "checksum": None}, "cannot be read"),
            ({"settings": {"EXTRACT_FAIL": "1"}}, "Could not unpack"),
            ({"archive": archive("readme", {"README.txt": b"hi"})}, "must hold only enclos"),
            ({"archive": archive("escape", {"enclos": fake_enclos(), "../evil": b"x"})}, "must hold only enclos"),
            ({"archive": archive("link", {}, links={"enclos": "/bin/sh"})}, "executable is empty"),
            ({"archive": archive("fails", {"enclos": fake_enclos(fails=True)})}, "did not run"),
            ({"archive": archive("wrong", {"enclos": fake_enclos("99.0.0")})}, "says 'enclos 99.0.0', not v0.2.0"),
        ]
        for options, message in cases:
            with self.subTest(message=message, options=options):
                self.log.unlink(missing_ok=True)
                binary = self.seed_existing_binary()
                self.assert_failed(self.run_installer(**options), message)
                self.assertEqual(binary.read_bytes(), b"existing installation\n")
                self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
                self.assertEqual(list(binary.parent.iterdir()), [binary])
                self.assertFalse((self.root / "evil").exists())

    def test_a_bad_checksum_stops_before_unpacking_or_running(self):
        self.assert_failed(self.run_installer(checksum="0" * 64 + "  " + ASSET + "\n"), "does not match")
        self.assertEqual(self.commands("tar"), [])
        self.assertEqual(self.commands("enclos"), [])

    def test_shasum_binary_marks_and_a_missing_final_newline_are_accepted(self):
        digest = hashlib.sha256(self.release_archive.read_bytes()).hexdigest()
        for checksum in (digest + " *" + ASSET + "\n", digest + "  " + ASSET):
            with self.subTest(checksum=checksum):
                self.installed_binary().unlink(missing_ok=True)
                result = self.run_installer(checksum=checksum)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(self.installed_binary().is_file())

    def test_a_folder_at_the_destination_is_refused(self):
        folder = self.installed_binary()
        folder.mkdir(parents=True)
        self.assert_failed(self.run_installer(), "is a folder")
        self.assertEqual(list(folder.iterdir()), [])

    def test_a_prefix_it_cannot_create_says_so(self):
        if os.geteuid() == 0:
            self.skipTest("root can write anywhere")
        locked = self.root / "locked"
        locked.mkdir()
        locked.chmod(0o500)
        self.addCleanup(locked.chmod, 0o700)
        self.assert_failed(self.run_installer("--prefix", locked / "tools"), "Cannot create")
        self.assertFalse((locked / "tools").exists())

    def test_another_enclos_first_on_path_is_named(self):
        shadow = self.root / "cargo bin"
        shadow.mkdir()
        (shadow / "enclos").write_text("#!/bin/sh\necho old\n")
        (shadow / "enclos").chmod(0o755)
        result = self.run_installer(path_first=[shadow])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Another enclos comes first on your PATH: " + str(shadow / "enclos"), result.stdout)
        self.assertIn("cargo uninstall enclos", result.stdout)

        prefix_bin = self.home / ".local" / "bin"
        result = self.run_installer(path_first=[prefix_bin, shadow])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Another enclos", result.stdout)
        self.assertNotIn("export PATH=", result.stdout)

    def test_a_rosetta_shell_on_apple_silicon_installs_and_an_intel_mac_does_not(self):
        result = self.run_installer(settings={"ARCH": "x86_64", "ARM64_CAPABLE": "1"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.log.unlink()
        self.assert_failed(self.run_installer(settings={"ARCH": "x86_64", "ARM64_CAPABLE": ""}), "Apple silicon")
        self.assertEqual(self.commands("curl"), [])

    def test_unsupported_hosts_and_root_stop_before_any_download(self):
        for settings, message in (
            ({"OS": "Linux"}, "only macOS"),
            ({"MACOS_VERSION": "13.6"}, "macOS 14 or later"),
            ({"MACOS_VERSION": "beta"}, "Cannot tell the macOS version"),
            ({"UID": "0"}, "without sudo"),
        ):
            with self.subTest(settings=settings):
                self.log.unlink(missing_ok=True)
                self.assert_failed(self.run_installer(settings=settings), message)
                self.assertEqual(self.commands("curl"), [])

    def test_a_truncated_download_installs_nothing(self):
        text = INSTALLER.read_text()
        last = text.rindex('main "$@"')
        for cut in (len(text) // 4, len(text) // 2, last, last + 3):
            with self.subTest(cut=cut):
                self.log.unlink(missing_ok=True)
                self.run_installer(script=text[:cut])
                self.assertEqual(self.commands("curl"), [])
                self.assertFalse(self.installed_binary().exists())

    def test_the_release_packaging_is_what_the_installer_reads(self):
        binary = self.root / "built enclos"
        binary.write_bytes(fake_enclos())
        out = self.root / "dist"
        pack_temp = self.root / "packaging temp"
        pack_temp.mkdir()
        packed = subprocess.run(
            ["/bin/bash", str(PACKAGER), str(binary), str(out)],
            env={"PATH": "/usr/bin:/bin", "TMPDIR": str(pack_temp), "LC_ALL": "C"},
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(packed.returncode, 0, packed.stdout + packed.stderr)
        self.assertEqual(list(pack_temp.iterdir()), [])
        archive = out / ASSET
        result = self.run_installer(archive=archive, checksum=(out / (ASSET + ".sha256")).read_text())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.installed_binary().read_bytes(), fake_enclos())

    def test_help_installs_nothing(self):
        result = self.run_installer("--help")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--prefix", result.stdout)
        self.assertEqual(self.commands("curl"), [])

    def test_invalid_arguments_stop_before_any_download(self):
        for args, message in (
            (("--unknown",), "Unknown option"),
            (("--version", "v0.1.0"), "Unknown option"),
            (("--source", "."), "Unknown option"),
            (("--prefix",), "needs a value"),
            (("--prefix", ""), "needs a value"),
            (("--prefix", "relative/path"), "absolute path"),
            (("--prefix", "/"), "filesystem root"),
            (("--prefix", "////"), "filesystem root"),
        ):
            with self.subTest(args=args):
                self.log.unlink(missing_ok=True)
                self.assert_failed(self.run_installer(*args), message)
                self.assertEqual(self.commands("curl"), [])


if __name__ == "__main__":
    unittest.main()
