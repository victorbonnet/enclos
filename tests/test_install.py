"""Exercise release and source installation without network or host changes.

Run with: python3 -m unittest discover -s tests -p 'test_install.py'
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

def install_binary(install_args):
    if value("BUILD_FAIL", "0") == "1":
        sys.exit(42)
    prefix = Path(install_args[install_args.index("--root") + 1])
    binary = prefix / "bin" / "enclos"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text(
        "#!" + sys.executable + "\n"
        "import json, os, sys\n"
        "with open(os.environ['INSTALL_TEST_LOG'], 'a') as log:\n"
        "    log.write(json.dumps({'command': 'enclos', 'args': sys.argv[1:]}) + '\\n')\n"
        "print('enclos 0.1.0')\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)

if name == "uname":
    print(value("ARCH", "arm64") if "-m" in args else value("OS", "Darwin"))
elif name == "id":
    print(value("UID", "501"))
elif name == "sw_vers":
    print(value("MACOS_VERSION", "14.7"))
elif name == "xcode-select":
    if value("CLT_FAIL", "0") == "1":
        sys.exit(2)
    print("/Library/Developer/CommandLineTools")
elif name == "rustup":
    if value("TOOLCHAIN_FAIL", "0") == "1":
        sys.exit(1)
    if args == ["toolchain", "list"]:
        print("1.99.1-aarch64-apple-darwin (default)")
    elif args[:4] == ["run", "1.99.1", "cargo", "--version"]:
        print("cargo 1.99.1 (test)")
    elif args[:4] == ["run", "1.99.1", "cargo", "install"]:
        install_binary(args)
    else:
        print("Unexpected rustup invocation: " + repr(args), file=sys.stderr)
        sys.exit(97)
elif name == "cargo":
    if args == ["--version"]:
        print("cargo " + value("CARGO_VERSION", "1.99.1") + " (test)")
    elif args and args[0] == "install":
        install_binary(args)
    else:
        sys.exit(97)
elif name == "rustc":
    if args == ["--version"]:
        print("rustc " + value("RUSTC_VERSION", "1.99.1") + " (test)")
    else:
        sys.exit(97)
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
    elif url.startswith("https://codeload.github.com/victorbonnet/enclos/tar.gz/"):
        data = Path(os.environ["INSTALL_TEST_SOURCE_ARCHIVE"]).read_bytes()
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
        for command in ("uname", "id", "sw_vers", "xcode-select", "rustup", "curl", "tar"):
            self.make_stub(command)
        self.source = self.root / "source checkout"
        self.make_source(self.source)
        self.installer = self.source / "install.sh"
        shutil.copyfile(INSTALLER, self.installer)
        self.release_archive = self.root / "release.tar.gz"
        self.make_release_archive(self.release_archive)
        self.source_archive = self.root / "source.tar.gz"
        with tarfile.open(self.source_archive, "w:gz") as archive:
            archive.add(self.source, arcname="enclos-test")
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

    def seed_existing_binary(self, prefix=None):
        binary = self.installed_binary(prefix)
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"existing installation\n")
        binary.chmod(0o755)
        return binary

    def use_direct_toolchain(self):
        (self.bin / "rustup").unlink()
        self.make_stub("cargo")
        self.make_stub("rustc")

    @staticmethod
    def make_source(path):
        path.mkdir(parents=True)
        (path / "Cargo.toml").write_text('[package]\nname = "enclos"\nversion = "0.1.0"\n')
        (path / "Cargo.lock").write_text("version = 4\n")
        (path / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "1.99.1"\n')
        (path / "src").mkdir()
        (path / "src" / "main.rs").write_text("fn main() {}\n")

    def run_installer(self, *args, settings=None, standalone=False, piped=False):
        installer = self.installer
        if standalone:
            installer = self.root / "standalone install.sh"
            shutil.copyfile(INSTALLER, installer)
        settings = dict(settings or {})
        archive = Path(settings.pop("RELEASE_ARCHIVE", self.release_archive))
        checksum = self.root / "release.tar.gz.sha256"
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if settings.pop("CHECKSUM_MISMATCH", "0") == "1":
            digest = "0" * 64
        checksum.write_text(digest + "  enclos-aarch64-apple-darwin.tar.gz\n")
        env = {
            "HOME": str(self.home),
            "TMPDIR": str(self.temp),
            "PATH": str(self.bin) + ":/usr/bin:/bin",
            "LC_ALL": "C",
            "INSTALL_TEST_LOG": str(self.log),
            "INSTALL_TEST_RELEASE_ARCHIVE": str(archive),
            "INSTALL_TEST_CHECKSUM": str(checksum),
            "INSTALL_TEST_SOURCE_ARCHIVE": str(self.source_archive),
        }
        for key, value in settings.items():
            env["INSTALL_TEST_" + key] = value
        command = ["/bin/bash", "-s", "--"] if piped else ["/bin/bash", str(installer)]
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
        self.assertFalse((self.home / ".enclos").exists(), "installer initialized Enclos state")

    def commands(self, name=None):
        events = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return [event for event in events if name is None or event["command"] == name]

    def assert_no_build(self):
        self.assertFalse(any("install" in event["args"] for event in self.commands("rustup")))
        self.assertFalse(any("install" in event["args"] for event in self.commands("cargo")))
        self.assertFalse((self.home / ".local" / "bin" / "enclos").exists())

    def test_explicit_checkout_builds_locked_with_pinned_toolchain(self):
        result = self.run_installer("--source", self.source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        installs = [event["args"] for event in self.commands("rustup") if "install" in event["args"]]
        self.assertEqual(len(installs), 1)
        args = installs[0]
        self.assertEqual(args[:4], ["run", "1.99.1", "cargo", "install"])
        self.assertIn("--locked", args)
        self.assertEqual(Path(args[args.index("--path") + 1]).resolve(), self.source.resolve())
        self.assertEqual(Path(args[args.index("--root") + 1]), self.home / ".local")
        self.assertEqual(self.commands("enclos"), [{"command": "enclos", "args": ["--version"]}])
        self.assertEqual(self.commands("curl"), [])
        self.assertIn(str(self.home / ".local" / "bin"), result.stdout + result.stderr)

    def test_explicit_source_and_prefix_preserve_spaces(self):
        source = self.root / "another source checkout"
        self.make_source(source)
        prefix = self.root / "custom install prefix"
        result = self.run_installer("--source", source, "--prefix", prefix, standalone=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        installs = [event["args"] for event in self.commands("rustup") if "install" in event["args"]]
        args = installs[0]
        self.assertEqual(Path(args[args.index("--path") + 1]).resolve(), source.resolve())
        self.assertEqual(Path(args[args.index("--root") + 1]), prefix)
        self.assertTrue((prefix / "bin" / "enclos").exists())
        self.assertEqual(self.commands("curl"), [])

    def test_matching_direct_toolchain_builds_without_rustup(self):
        self.use_direct_toolchain()
        result = self.run_installer("--source", self.source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.commands("rustup"), [])
        self.assertEqual(self.commands("rustc"), [{"command": "rustc", "args": ["--version"]}])
        installs = [event["args"] for event in self.commands("cargo") if "install" in event["args"]]
        self.assertEqual(len(installs), 1)
        args = installs[0]
        self.assertEqual(args[0], "install")
        self.assertIn("--locked", args)
        self.assertEqual(Path(args[args.index("--path") + 1]).resolve(), self.source.resolve())
        self.assertEqual(Path(args[args.index("--root") + 1]), self.home / ".local")
        self.assertEqual(self.commands("enclos"), [{"command": "enclos", "args": ["--version"]}])

    def test_mismatched_direct_cargo_or_rustc_stops_before_build(self):
        self.use_direct_toolchain()
        for settings in (
            {"CARGO_VERSION": "1.98.0"},
            {"RUSTC_VERSION": "1.98.0"},
            {"CARGO_VERSION": "1.99.1-nightly"},
            {"RUSTC_VERSION": "1.99.1-nightly"},
        ):
            with self.subTest(settings=settings):
                self.log.unlink(missing_ok=True)
                result = self.run_installer("--source", self.source, settings=settings)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_no_build()
                self.assertEqual(self.commands("enclos"), [])

    def test_direct_toolchain_requires_rustc_too(self):
        self.use_direct_toolchain()
        (self.bin / "rustc").unlink()
        result = self.run_installer("--source", self.source)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_build()

    def test_rustup_takes_precedence_over_direct_toolchain(self):
        self.make_stub("cargo")
        self.make_stub("rustc")
        result = self.run_installer("--source", self.source, settings={"CARGO_VERSION": "1.98.0", "RUSTC_VERSION": "1.98.0"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.commands("cargo"), [])
        self.assertEqual(self.commands("rustc"), [])
        self.assertTrue(any("install" in event["args"] for event in self.commands("rustup")))

    def test_direct_toolchain_build_failure_does_not_run_binary(self):
        self.use_direct_toolchain()
        result = self.run_installer("--source", self.source, settings={"BUILD_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.commands("enclos"), [])
        self.assertFalse((self.home / ".local" / "bin" / "enclos").exists())

    def test_explicit_ref_downloads_instead_of_using_adjacent_checkout(self):
        result = self.run_installer("--ref", "v0.1.0-test")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        downloads = self.commands("curl")
        self.assertEqual(len(downloads), 1)
        self.assertTrue(any("v0.1.0-test" in arg for arg in downloads[0]["args"]))
        self.assertEqual(len(self.commands("tar")), 1)
        args = next(event["args"] for event in self.commands("rustup") if "install" in event["args"])
        self.assertNotEqual(Path(args[args.index("--path") + 1]).resolve(), self.source.resolve())

    def test_unsupported_hosts_and_root_stop_before_build(self):
        for settings in ({"OS": "Linux"}, {"ARCH": "x86_64"}, {"MACOS_VERSION": "13.6"}, {"UID": "0"}):
            with self.subTest(settings=settings):
                self.log.unlink(missing_ok=True)
                result = self.run_installer(settings=settings)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_no_build()
                self.assertEqual(self.commands("curl"), [])

    def test_missing_prerequisites_do_not_install_them(self):
        for settings in ({"CLT_FAIL": "1"}, {"TOOLCHAIN_FAIL": "1"}):
            with self.subTest(settings=settings):
                self.log.unlink(missing_ok=True)
                result = self.run_installer("--source", self.source, settings=settings)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_no_build()
                self.assertFalse(any("toolchain" in event["args"] and "install" in event["args"] for event in self.commands("rustup")))
        (self.bin / "rustup").unlink()
        self.log.unlink(missing_ok=True)
        result = self.run_installer("--source", self.source)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_build()
        self.assertIn("rustup", (result.stdout + result.stderr).lower())

    def test_download_failure_never_builds_or_reports_success(self):
        result = self.run_installer("--ref", "v0.1.0-test", settings={"DOWNLOAD_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_build()
        self.assertEqual(self.commands("tar"), [])
        self.assertEqual(self.commands("enclos"), [])

    def test_extraction_failure_cleans_up_without_building(self):
        result = self.run_installer("--ref", "v0.1.0-test", settings={"EXTRACT_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_build()
        self.assertEqual(len(self.commands("tar")), 1)
        self.assertEqual(self.commands("enclos"), [])

    def assert_release_downloads(self, tag, *, latest=True):
        downloads = self.commands("curl")
        urls = [arg for event in downloads for arg in event["args"] if arg.startswith("https://")]
        base = "https://github.com/victorbonnet/enclos"
        asset = "enclos-aarch64-apple-darwin.tar.gz"
        expected = [base + "/releases/latest"] if latest else []
        expected += [base + "/releases/download/" + tag + "/" + asset,
                     base + "/releases/download/" + tag + "/" + asset + ".sha256"]
        self.assertCountEqual(urls, expected)
        if latest:
            latest_args = next(event["args"] for event in downloads if base + "/releases/latest" in event["args"])
            self.assertIn("%{url_effective}", latest_args)
            self.assertIn("/dev/null", latest_args)
        self.assertFalse(self.commands("rustup"))
        self.assertFalse(self.commands("cargo"))
        self.assertFalse(self.commands("rustc"))
        self.assertFalse(self.commands("xcode-select"))

    def test_default_installs_latest_release_even_next_to_checkout(self):
        result = self.run_installer(settings={"CLT_FAIL": "1", "TOOLCHAIN_FAIL": "1"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_release_downloads("v0.2.0")
        self.assertTrue(self.installed_binary().is_file())
        self.assertEqual(self.commands("enclos"), [{"command": "enclos", "args": ["--version"]}])

    def test_standalone_and_piped_scripts_default_to_latest_release(self):
        for piped in (False, True):
            with self.subTest(piped=piped):
                self.log.unlink(missing_ok=True)
                self.installed_binary().unlink(missing_ok=True)
                result = self.run_installer(standalone=True, piped=piped)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_release_downloads("v0.2.0")
                self.assertTrue(self.installed_binary().is_file())

    def test_explicit_version_skips_latest_resolution(self):
        self.make_release_archive(self.release_archive, version="0.1.7")
        result = self.run_installer("--version", "v0.1.7")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_release_downloads("v0.1.7", latest=False)

    def test_release_prefix_preserves_spaces_and_replaces_existing_binary(self):
        prefix = self.root / "custom release prefix"
        binary = self.seed_existing_binary(prefix)
        result = self.run_installer("--prefix", prefix)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotEqual(binary.read_bytes(), b"existing installation\n")
        self.assertEqual(binary.read_bytes(), self.installed_release_bytes())
        self.assert_release_downloads("v0.2.0")

    def installed_release_bytes(self):
        with tarfile.open(self.release_archive, "r:gz") as archive:
            return archive.extractfile("enclos").read()

    def test_missing_or_invalid_latest_release_never_falls_back_to_source(self):
        for settings in (
            {"LATEST_FAIL": "1"},
            {"LATEST_URL": "https://github.com/victorbonnet/enclos/releases/latest"},
            {"LATEST_URL": "https://github.com/other/repository/releases/tag/v0.2.0"},
        ):
            with self.subTest(settings=settings):
                self.log.unlink(missing_ok=True)
                result = self.run_installer(settings=settings)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_no_build()
                self.assertEqual(len(self.commands("curl")), 1)
                self.assertEqual(self.commands("enclos"), [])
                self.assertEqual(self.commands("tar"), [])

    def test_release_failures_preserve_existing_binary(self):
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
            {"EXTRACT_FAIL": "1"},
            {"RELEASE_ARCHIVE": str(bad_archive)},
            {"RELEASE_ARCHIVE": str(missing_binary)},
            {"RELEASE_ARCHIVE": str(failed_version)},
            {"RELEASE_ARCHIVE": str(wrong_version)},
        ):
            with self.subTest(settings=settings):
                self.log.unlink(missing_ok=True)
                binary = self.seed_existing_binary()
                result = self.run_installer(settings=settings)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(binary.read_bytes(), b"existing installation\n")
                self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
                self.assertEqual(list(binary.parent.iterdir()), [binary])
                self.assertFalse(any("install" in event["args"] for event in self.commands("rustup")))
                self.assertFalse(any("install" in event["args"] for event in self.commands("cargo")))
                self.assertFalse(any("codeload.github.com" in arg for event in self.commands("curl") for arg in event["args"]))
                self.assertNotIn("Installed enclos", result.stdout + result.stderr)

    def test_bad_checksum_stops_before_extraction_or_execution(self):
        result = self.run_installer(settings={"CHECKSUM_MISMATCH": "1"})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_build()
        self.assertEqual(self.commands("tar"), [])
        self.assertEqual(self.commands("enclos"), [])

    def test_source_requires_lockfile_and_numeric_toolchain(self):
        (self.source / "Cargo.lock").unlink()
        result = self.run_installer("--source", self.source)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_build()
        (self.source / "Cargo.lock").write_text("version = 4\n")
        for channel in ("stable", "nightly", "1.99.1\n1.99.0"):
            with self.subTest(channel=channel):
                self.log.unlink(missing_ok=True)
                (self.source / "rust-toolchain.toml").write_text(
                    '[toolchain]\nchannel = "' + channel + '"\n'
                )
                result = self.run_installer("--source", self.source)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_no_build()

    def test_build_failure_does_not_run_binary(self):
        result = self.run_installer("--source", self.source, settings={"BUILD_FAIL": "1"})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.commands("enclos"), [])
        self.assertFalse((self.home / ".local" / "bin" / "enclos").exists())

    def test_help_does_not_install(self):
        result = self.run_installer("--help")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--version", result.stdout + result.stderr)
        self.assertIn("--source", result.stdout + result.stderr)
        self.assertIn("--ref", result.stdout + result.stderr)
        self.assertIn("--prefix", result.stdout + result.stderr)
        self.assert_no_build()
        self.assertEqual(self.commands("curl"), [])

    def test_invalid_arguments_stop_before_build(self):
        for args in (
            ("--unknown",),
            ("--prefix",),
            ("--version",),
            ("--version", ""),
            ("--version", "../v0.1.0"),
            ("--version", "v0.1.0?query"),
            ("--version", "v0.1.0", "--ref", "main"),
            ("--source", self.source, "--version", "v0.1.0"),
            ("--prefix", "relative/path"),
            ("--prefix", "/"),
            ("--prefix", "//"),
            ("--prefix", "////"),
            ("--source", self.root / "missing"),
            ("--source", self.source, "--ref", "main"),
        ):
            with self.subTest(args=args):
                self.log.unlink(missing_ok=True)
                result = self.run_installer(*args)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_no_build()
                self.assertEqual(self.commands("curl"), [])


if __name__ == "__main__":
    unittest.main()
