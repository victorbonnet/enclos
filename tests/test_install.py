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


INSTALLER = Path(__file__).resolve().parents[1] / "install.sh"

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
elif name == "id":
    print(value("UID", "501"))
elif name == "sw_vers":
    print(value("MACOS_VERSION", "14.7"))
elif name == "curl":
    if value("DOWNLOAD_FAIL", "0") == "1":
        sys.exit(22)
    urls = [arg for arg in args if arg.startswith("https://")]
    if len(urls) != 1:
        sys.exit(96)
    url = urls[0]
    output = None
    for index, arg in enumerate(args):
        if arg in ("-o", "--output"):
            output = args[index + 1]
        elif arg.startswith("--output="):
            output = arg.split("=", 1)[1]
    if url.endswith("/releases/latest"):
        if value("LATEST_FAIL", "0") == "1":
            sys.exit(22)
        print(value("LATEST_URL", "https://github.com/victorbonnet/enclos/releases/tag/v0.2.0"), end="")
        sys.exit(0)
    if "/releases/download/" in url:
        if value("ASSET_DOWNLOAD_FAIL", "0") == "1":
            sys.exit(22)
        if url.endswith(".tar.gz.sha256"):
            if value("CHECKSUM_DOWNLOAD_FAIL", "0") == "1":
                sys.exit(22)
            data = Path(os.environ["INSTALL_TEST_CHECKSUM"]).read_bytes()
        elif url.endswith(".tar.gz"):
            data = Path(os.environ["INSTALL_TEST_RELEASE_ARCHIVE"]).read_bytes()
        else:
            sys.exit(95)
    else:
        sys.exit(95)
    if output:
        Path(output).write_bytes(data)
    else:
        sys.stdout.buffer.write(data)
elif name == "tar":
    if value("EXTRACT_FAIL", "0") == "1":
        sys.exit(2)
    os.execv("/usr/bin/tar", ["/usr/bin/tar", *args])
else:
    sys.exit(99)
'''


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
        for command in ("uname", "id", "sw_vers", "curl", "tar"):
            self.make_stub(command)
        self.installer = self.root / "install.sh"
        shutil.copyfile(INSTALLER, self.installer)
        self.release_archive = self.root / "release.tar.gz"
        self.make_release_archive(self.release_archive)
        self.startup_files = {}
        for name in (".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile"):
            path = self.home / name
            contents = "# Existing user settings: " + name + "\n"
            path.write_text(contents, encoding="utf-8")
            self.startup_files[path] = contents

    def make_stub(self, command):
        stub = self.bin / command
        stub.write_text("#!" + sys.executable + "\n" + textwrap.dedent(STUB), encoding="utf-8")
        stub.chmod(0o755)

    def make_release_archive(self, path, *, missing_binary=False, version_failure=False, version="0.2.0"):
        binary = (
            "#!" + sys.executable + "\n"
            "import json, os, sys\n"
            "with open(os.environ['INSTALL_TEST_LOG'], 'a') as log:\n"
            "    log.write(json.dumps({'command': 'enclos', 'args': sys.argv[1:]}) + '\\n')\n"
            "print('enclos " + version + "')\n"
            + ("sys.exit(42)\n" if version_failure else "")
        ).encode()
        with tarfile.open(path, "w:gz") as archive:
            entry = tarfile.TarInfo("README.txt" if missing_binary else "enclos")
            entry.size = len(binary)
            entry.mode = 0o755
            archive.addfile(entry, io.BytesIO(binary))

    def installed_binary(self, prefix=None):
        return (prefix or self.home / ".local") / "bin" / "enclos"

    def installed_release_bytes(self):
        with tarfile.open(self.release_archive, "r:gz") as archive:
            return archive.extractfile("enclos").read()

    def seed_existing_binary(self, prefix=None):
        binary = self.installed_binary(prefix)
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"existing installation\n")
        binary.chmod(0o755)
        return binary

    def run_installer(self, *args, settings=None, piped=False):
        settings = dict(settings or {})
        archive = Path(settings.pop("RELEASE_ARCHIVE", self.release_archive))
        checksum = self.root / "release.tar.gz.sha256"
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if settings.pop("CHECKSUM_MISMATCH", "0") == "1":
            digest = "0" * 64
        checksum.write_text(digest + "  " + settings.pop("CHECKSUM_NAME", "enclos-aarch64-apple-darwin.tar.gz") + "\n")
        env = {
            "HOME": str(self.home),
            "TMPDIR": str(self.temp),
            "PATH": str(self.bin) + ":/usr/bin:/bin",
            "LC_ALL": "C",
            "INSTALL_TEST_LOG": str(self.log),
            "INSTALL_TEST_RELEASE_ARCHIVE": str(archive),
            "INSTALL_TEST_CHECKSUM": str(checksum),
        }
        for key, value in settings.items():
            env["INSTALL_TEST_" + key] = value
        command = ["/bin/bash", "-s", "--"] if piped else ["/bin/bash", str(self.installer)]
        result = subprocess.run(
            [*command, *map(str, args)],
            cwd=self.root,
            env=env,
            input=INSTALLER.read_text(encoding="utf-8") if piped else None,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assert_untouched_home()
        self.assertEqual(list(self.temp.iterdir()), [], "temporary installer files were not cleaned up")
        return result

    def assert_untouched_home(self):
        for path, contents in self.startup_files.items():
            self.assertEqual(path.read_text(encoding="utf-8"), contents)
        self.assertFalse((self.home / ".enclos").exists(), "installer initialized enclos state")

    def commands(self, name=None):
        events = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return [event for event in events if name is None or event["command"] == name]

    def urls(self):
        return [arg for event in self.commands("curl") for arg in event["args"] if arg.startswith("https://")]

    def assert_failed(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Installed enclos", result.stdout + result.stderr)

    def test_installs_the_latest_release(self):
        for piped in (False, True):
            with self.subTest(piped=piped):
                self.log.unlink(missing_ok=True)
                self.installed_binary().unlink(missing_ok=True)
                result = self.run_installer(piped=piped)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                base = "https://github.com/victorbonnet/enclos/releases"
                asset = "enclos-aarch64-apple-darwin.tar.gz"
                self.assertEqual(self.urls(), [
                    base + "/latest",
                    base + "/download/v0.2.0/" + asset,
                    base + "/download/v0.2.0/" + asset + ".sha256",
                ])
                latest = self.commands("curl")[0]["args"]
                self.assertIn("%{url_effective}", latest)
                self.assertIn("/dev/null", latest)
                self.assertEqual(self.installed_binary().read_bytes(), self.installed_release_bytes())
                self.assertEqual(self.installed_binary().stat().st_mode & 0o777, 0o755)
                self.assertEqual(self.commands("enclos"), [{"command": "enclos", "args": ["--version"]}])
                self.assertIn("enclos 0.2.0", result.stdout)
                self.assertIn("export PATH=", result.stdout)

    def test_a_prefix_with_spaces_replaces_the_existing_binary(self):
        prefix = self.root / "custom release prefix"
        binary = self.seed_existing_binary(prefix)
        result = self.run_installer("--prefix", str(prefix) + "//")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(binary.read_bytes(), self.installed_release_bytes())
        self.assertEqual(list(binary.parent.iterdir()), [binary])

    def test_no_release_yet_is_said_and_nothing_is_downloaded(self):
        for url in (
            "https://github.com/victorbonnet/enclos/releases",
            "https://github.com/victorbonnet/enclos/releases/",
        ):
            with self.subTest(url=url):
                self.log.unlink(missing_ok=True)
                result = self.run_installer(settings={"LATEST_URL": url})
                self.assert_failed(result)
                self.assertIn("no published release yet", result.stderr)
                self.assertEqual(len(self.urls()), 1)
                self.assertFalse(self.installed_binary().exists())

    def test_an_unexpected_latest_answer_downloads_nothing(self):
        for url in (
            "https://github.com/victorbonnet/enclos/releases/latest",
            "https://github.com/other/repository/releases/tag/v0.2.0",
            "https://github.com/victorbonnet/enclos/releases/tag/v0.2.0-rc.1",
            "https://github.com/victorbonnet/enclos/releases/tag/v0.2.0/../../x",
        ):
            with self.subTest(url=url):
                self.log.unlink(missing_ok=True)
                result = self.run_installer(settings={"LATEST_URL": url})
                self.assert_failed(result)
                self.assertEqual(len(self.urls()), 1)
                self.assertEqual(self.commands("tar"), [])

    def test_release_failures_keep_the_existing_binary(self):
        bad_archive = self.root / "bad archive.tar.gz"
        bad_archive.write_bytes(b"not a gzip archive")
        missing_binary = self.root / "missing binary.tar.gz"
        self.make_release_archive(missing_binary, missing_binary=True)
        failed_version = self.root / "failed version.tar.gz"
        self.make_release_archive(failed_version, version_failure=True)
        wrong_version = self.root / "wrong version.tar.gz"
        self.make_release_archive(wrong_version, version="99.0.0")
        for settings in (
            {"LATEST_FAIL": "1"},
            {"ASSET_DOWNLOAD_FAIL": "1"},
            {"CHECKSUM_DOWNLOAD_FAIL": "1"},
            {"CHECKSUM_MISMATCH": "1"},
            {"CHECKSUM_NAME": "other.tar.gz"},
            {"EXTRACT_FAIL": "1"},
            {"RELEASE_ARCHIVE": str(bad_archive)},
            {"RELEASE_ARCHIVE": str(missing_binary)},
            {"RELEASE_ARCHIVE": str(failed_version)},
            {"RELEASE_ARCHIVE": str(wrong_version)},
        ):
            with self.subTest(settings=settings):
                self.log.unlink(missing_ok=True)
                binary = self.seed_existing_binary()
                self.assert_failed(self.run_installer(settings=settings))
                self.assertEqual(binary.read_bytes(), b"existing installation\n")
                self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
                self.assertEqual(list(binary.parent.iterdir()), [binary])

    def test_a_bad_checksum_stops_before_unpacking_or_running(self):
        self.assert_failed(self.run_installer(settings={"CHECKSUM_MISMATCH": "1"}))
        self.assertEqual(self.commands("tar"), [])
        self.assertEqual(self.commands("enclos"), [])

    def test_unsupported_hosts_and_root_stop_before_any_download(self):
        for settings in ({"OS": "Linux"}, {"ARCH": "x86_64"}, {"MACOS_VERSION": "13.6"}, {"UID": "0"}):
            with self.subTest(settings=settings):
                self.log.unlink(missing_ok=True)
                self.assert_failed(self.run_installer(settings=settings))
                self.assertEqual(self.commands("curl"), [])

    def test_help_installs_nothing(self):
        result = self.run_installer("--help")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--prefix", result.stdout)
        self.assertEqual(self.commands("curl"), [])

    def test_invalid_arguments_stop_before_any_download(self):
        for args in (
            ("--unknown",),
            ("--version", "v0.1.0"),
            ("--source", "."),
            ("--prefix",),
            ("--prefix", ""),
            ("--prefix", "relative/path"),
            ("--prefix", "/"),
            ("--prefix", "////"),
        ):
            with self.subTest(args=args):
                self.log.unlink(missing_ok=True)
                self.assert_failed(self.run_installer(*args))
                self.assertEqual(self.commands("curl"), [])


if __name__ == "__main__":
    unittest.main()
