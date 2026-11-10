//! What an install puts beside the sandbox's home: the adapter's files and
//! the runtime's installer, downloaded on the host (ADR 0029). The compiled
//! policy denies the sandbox writes to `installers/`, which is what keeps
//! the host's plain writes from following a link the sandbox planted.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::Engine;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::model::runtime::RuntimeKind;
use crate::model::sandbox::SandboxName;
use crate::policy::sha256_hex;
use crate::runtime::{HomeFile, RuntimeAdapter, SandboxCommand};

/// An installer larger than this is not an install script: refused.
const INSTALLER_MAX_BYTES: u64 = 20 * 1024 * 1024;

/// Gets a file onto the host.
pub trait Downloader {
    /// Downloads `url` to `to`. An implementation must refuse a URL or a
    /// redirect not on HTTPS with [`DownloadFailed::NotHttps`]: nothing else
    /// checks. A failure may leave part of the file at `to`.
    fn download(&self, url: &str, to: &Path) -> std::result::Result<(), DownloadFailed>;
}

/// Why a download did not end with the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadFailed {
    /// The downloader could not run: what stopped it, said whole.
    NotRun(String),
    /// Refused, as not on HTTPS: the URL or a redirect.
    NotHttps,
    /// It ran and failed: how it ended.
    Ended(String),
}

/// Downloads with the host's `curl`.
pub struct Curl;

impl Downloader for Curl {
    fn download(&self, url: &str, to: &Path) -> std::result::Result<(), DownloadFailed> {
        let status = Command::new("/usr/bin/curl")
            .args(download_args(url, to))
            .stdin(Stdio::null())
            .status()
            .map_err(|e| DownloadFailed::NotRun(format!("cannot run curl: {e}")))?;
        match status.code() {
            _ if status.success() => Ok(()),
            // curl exits 1, unsupported protocol, when `--proto` or
            // `--proto-redir` refuses the URL or a redirect; it says what
            // it refused itself, and exits 1 too on an HTTP/0.9 reply.
            Some(1) => Err(DownloadFailed::NotHttps),
            _ => Err(DownloadFailed::Ended(status.to_string())),
        }
    }
}

impl Engine {
    /// Stages what an install needs in the sandbox's `installers/` folder,
    /// beside its home. Returns the command that installs: it copies the
    /// adapter's files into the home from inside the sandbox, under its
    /// policy, then runs the installer, with the installer's SHA-256. The
    /// command reads those files and the installer, and nothing else
    /// staged.
    pub(super) fn stage_install(
        &self,
        name: &SandboxName,
        runtime: &dyn RuntimeAdapter,
    ) -> Result<(SandboxCommand, String)> {
        let dir = self.layout.sandbox_installers(name.as_str());
        std::fs::create_dir_all(&dir).map_err(io(&dir))?;
        let files = runtime.home_files(self.recorded_backend(name)?);
        let staged = stage_files(&dir, &files, runtime.kind())?;
        let (installer, sha256) = download_installer(self.downloader.as_ref(), &dir, runtime)?;
        let mut script = home_files_script(&staged);
        script.push_str("exec /bin/bash \"$0\" \"$@\"\n");
        let mut reads: Vec<PathBuf> = staged.into_iter().map(|(path, _)| path).collect();
        reads.push(installer.clone());
        let mut words: Vec<OsString> = vec![
            "/bin/sh".into(),
            "-c".into(),
            script.into(),
            installer.into_os_string(),
        ];
        words.extend(runtime.installer().args.iter().map(Into::into));
        Ok((SandboxCommand::new(words).reading(reads), sha256))
    }
}

/// What failing to write or make `path` is.
fn io(path: &Path) -> impl FnOnce(std::io::Error) -> Error {
    let path = path.to_owned();
    move |source| Error::Layout(LayoutError::Io { path, source })
}

/// Writes the adapter's `files` into `dir`, and says where each went.
fn stage_files<'a>(
    dir: &Path,
    files: &'a [HomeFile],
    kind: RuntimeKind,
) -> Result<Vec<(PathBuf, &'a HomeFile)>> {
    let mut staged = Vec::new();
    for (i, file) in files.iter().enumerate() {
        if !file.path_is_inside_home() {
            return Err(Error::Session {
                what: format!(
                    "the {kind} adapter names a file outside the sandbox home: {}",
                    file.path
                ),
            });
        }
        let path = dir.join(format!("home-{i}"));
        std::fs::write(&path, file.contents).map_err(io(&path))?;
        staged.push((path, file));
    }
    Ok(staged)
}

/// Downloads the runtime's installer on the host into `dir`, outside the
/// sandbox home, with its SHA-256, which the audit entry names. Any
/// version is run (ADR 0029), so the file is named after its hash: an
/// install running at the same time that got another version moves its
/// own to another path, and the bytes this install runs are the ones its
/// entry names. It is downloaded under a name of its own and moved into
/// place once read.
fn download_installer(
    downloader: &dyn Downloader,
    dir: &Path,
    runtime: &dyn RuntimeAdapter,
) -> Result<(PathBuf, String)> {
    let installer = runtime.installer();
    let part = dir.join(format!(
        "{}-install.{}.part",
        runtime.kind(),
        std::process::id()
    ));
    let failed = |what: String| Error::Session { what };
    if let Err(why) = downloader.download(&installer.url, &part) {
        let _ = std::fs::remove_file(&part);
        return Err(failed(match why {
            DownloadFailed::NotRun(what) => what,
            DownloadFailed::NotHttps => format!(
                "could not download {}: it is not served over HTTPS, or redirects off HTTPS, and enclos downloads installers over HTTPS only. Update enclos, or report it if the {} installer moved",
                installer.url,
                runtime.kind()
            ),
            DownloadFailed::Ended(how) => {
                format!("could not download {} ({how})", installer.url)
            }
        }));
    }
    let bytes =
        std::fs::read(&part).map_err(|e| failed(format!("cannot read {}: {e}", part.display())))?;
    let sha256 = sha256_hex(&bytes);
    let path = dir.join(format!("{}-install-{sha256}.sh", runtime.kind()));
    std::fs::rename(&part, &path).map_err(|e| {
        failed(format!(
            "cannot move the installer into place at {}: {e}",
            path.display()
        ))
    })?;
    Ok((path, sha256))
}

/// The `sh` lines that copy staged files into the sandbox home. They run
/// inside the sandbox, so a link the sandbox planted can only lead where
/// the sandbox may write anyway. Whatever is at the target first goes
/// (a link, a folder), and the copy must leave a plain file.
pub(crate) fn home_files_script(staged: &[(PathBuf, &HomeFile)]) -> String {
    let mut script = String::from("set -e\n");
    for (path, file) in staged {
        let target = format!("\"$HOME\"/{}", sh_word(file.path));
        let mode = if file.executable { "700" } else { "600" };
        script.push_str(&format!(
            "mkdir -p \"$(dirname {target})\"\n\
             rm -rf -- {target}\n\
             cp {} {target} && test -f {target} && ! test -L {target} || {{ echo {} >&2; exit 1; }}\n\
             chmod {mode} {target}\n",
            sh_word(&path.display().to_string()),
            sh_word(&format!(
                "enclos: cannot put {} in the sandbox home: something the sandbox may not replace is in the way",
                file.path
            )),
        ));
    }
    script
}

/// The arguments of the curl that downloads an installer from `url` to
/// `out`. `-q` comes first, the only place curl reads it, so no `.curlrc`
/// adds options; curl's environment variables, such as `https_proxy`, still
/// apply. The download and every redirect must stay on HTTPS, so curl
/// refuses any other URL.
fn download_args(url: &str, out: &Path) -> Vec<OsString> {
    vec![
        "-q".into(),
        "--proto".into(),
        "=https".into(),
        "--proto-redir".into(),
        "=https".into(),
        "-fsSL".into(),
        "--max-time".into(),
        "120".into(),
        "--max-filesize".into(),
        INSTALLER_MAX_BYTES.to_string().into(),
        "-o".into(),
        out.into(),
        url.into(),
    ]
}

/// `s` as one `sh` word.
fn sh_word(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::runtime::hermes::Hermes;

    /// Stands in for the network: writes `partly`, then ends as `then` says.
    struct Stub {
        partly: &'static str,
        then: std::result::Result<(), DownloadFailed>,
    }

    impl Downloader for Stub {
        fn download(&self, _: &str, to: &Path) -> std::result::Result<(), DownloadFailed> {
            std::fs::write(to, self.partly).unwrap();
            self.then.clone()
        }
    }

    /// What is left in `dir`, by name.
    fn left(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn an_installer_is_named_after_its_hash_and_no_part_stays() {
        let dir = tempfile::tempdir().unwrap();
        let stub = Stub {
            partly: "echo hi\n",
            then: Ok(()),
        };
        let (path, sha256) = download_installer(&stub, dir.path(), &Hermes).unwrap();
        assert_eq!(sha256, sha256_hex(b"echo hi\n"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "echo hi\n");
        assert_eq!(left(dir.path()), [format!("hermes-install-{sha256}.sh")]);
    }

    /// Downloads run outside the state lock, so two installs at once must
    /// not write the same part file.
    #[test]
    fn a_download_goes_to_a_part_file_of_this_process() {
        struct Records(std::cell::RefCell<PathBuf>);
        impl Downloader for Records {
            fn download(&self, _: &str, to: &Path) -> std::result::Result<(), DownloadFailed> {
                *self.0.borrow_mut() = to.to_owned();
                std::fs::write(to, "x").unwrap();
                Ok(())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let records = Records(Default::default());
        download_installer(&records, dir.path(), &Hermes).unwrap();
        assert_eq!(
            *records.0.borrow(),
            dir.path()
                .join(format!("hermes-install.{}.part", std::process::id()))
        );
    }

    /// A staged path holding a quote stays one word for `sh`.
    #[test]
    fn a_staged_path_with_a_quote_is_copied() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("it's staged");
        std::fs::write(&staged, "first").unwrap();
        let file = HomeFile {
            path: "bin/one",
            contents: "",
            executable: true,
        };
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(home_files_script(&[(staged, &file)]))
            .env("HOME", dir.path())
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("bin/one")).unwrap(),
            "first"
        );
    }

    /// Each way a download fails is said, and leaves no part of it.
    #[test]
    fn a_failed_download_says_why_and_leaves_nothing() {
        let url = Hermes.installer().url;
        for (why, says) in [
            (
                DownloadFailed::NotHttps,
                format!("could not download {url}: it is not served over HTTPS"),
            ),
            (
                DownloadFailed::Ended("exit status: 22".into()),
                format!("could not download {url} (exit status: 22)"),
            ),
            (
                DownloadFailed::NotRun("cannot run curl: gone".into()),
                "cannot run curl: gone".to_owned(),
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let stub = Stub {
                partly: "ech",
                then: Err(why),
            };
            let err = download_installer(&stub, dir.path(), &Hermes).unwrap_err();
            assert!(err.to_string().contains(&says), "{err}");
            assert_eq!(left(dir.path()), Vec::<String>::new());
        }
    }

    /// curl's exit 1 is what `--proto` refusing a URL ends with.
    #[test]
    fn curl_refusing_a_url_is_said_as_not_https() {
        let dir = tempfile::tempdir().unwrap();
        let to = dir.path().join("x.part");
        assert_eq!(
            Curl.download("http://127.0.0.1:9/install.sh", &to),
            Err(DownloadFailed::NotHttps)
        );
    }

    #[test]
    fn an_adapter_file_outside_the_home_is_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let files = [HomeFile {
            path: "../outside",
            contents: "x",
            executable: false,
        }];
        let err = stage_files(dir.path(), &files, Hermes.kind()).unwrap_err();
        assert!(
            err.to_string()
                .contains("names a file outside the sandbox home: ../outside"),
            "{err}"
        );
        assert_eq!(left(dir.path()), Vec::<String>::new());
    }

    #[test]
    fn staged_files_are_written_and_named_by_their_place() {
        let dir = tempfile::tempdir().unwrap();
        let files = [HomeFile {
            path: "bin/one",
            contents: "first",
            executable: true,
        }];
        let staged = stage_files(dir.path(), &files, Hermes.kind()).unwrap();
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[0].0, dir.path().join("home-0"));
        assert_eq!(std::fs::read_to_string(&staged[0].0).unwrap(), "first");
    }

    #[test]
    fn the_installer_download_reads_no_curlrc_and_stays_on_https() {
        for url in [
            "https://example.com/install.sh",
            "http://example.com/install.sh",
        ] {
            let args = download_args(url, Path::new("/tmp/x.part"));
            let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap()).collect();
            // curl reads `-q` only as its first argument.
            assert_eq!(args[0], "-q", "{args:?}");
            let pair = |flag: &str, value: &str| args.windows(2).any(|w| w == [flag, value]);
            assert!(pair("--proto", "=https"), "{args:?}");
            assert!(pair("--proto-redir", "=https"), "{args:?}");
            assert!(args.contains(&"-fsSL"), "{args:?}");
            assert!(pair("--max-time", "120"), "{args:?}");
            assert!(
                pair("--max-filesize", &INSTALLER_MAX_BYTES.to_string()),
                "{args:?}"
            );
            assert!(pair("-o", "/tmp/x.part"), "{args:?}");
            assert_eq!(args.last(), Some(&url));
        }
    }

    #[test]
    fn an_installer_url_to_a_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("install.sh");
        std::fs::write(&src, "echo hi\n").unwrap();
        let url = format!("file://{}", src.display());
        assert_eq!(
            Curl.download(&url, &dir.path().join("x.part")),
            Err(DownloadFailed::NotHttps)
        );
    }

    #[test]
    fn the_host_curl_reads_no_curlrc_for_an_installer_download() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".curlrc"),
            "write-out = \"CURLRC-READ\\n\"\n",
        )
        .unwrap();
        let src = dir.path().join("install.sh");
        std::fs::write(&src, "echo hi\n").unwrap();
        let out = dir.path().join("install.part");
        let url = format!("file://{}", src.display());
        let curl = |args: &[OsString]| {
            let output = Command::new("/usr/bin/curl")
                .args(args)
                .env("CURL_HOME", dir.path())
                .env("HOME", dir.path())
                .env_remove("XDG_CONFIG_HOME")
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            String::from_utf8_lossy(&output.stdout).into_owned()
        };
        // The real arguments, but for the protocol: a file needs no server.
        let args: Vec<OsString> = download_args(&url, &out)
            .into_iter()
            .map(|a| if a == "=https" { "=file".into() } else { a })
            .collect();
        assert!(!curl(&args).contains("CURLRC-READ"));
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "echo hi\n");
        // Without `-q` the same curl reads it, so the check above can fail.
        assert!(curl(&args[1..]).contains("CURLRC-READ"));
    }
}
