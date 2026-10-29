//! Where enclos keeps its files (design §11), and creating them.
//!
//! macOS: everything in `~/.enclos`. Linux: data in `$XDG_DATA_HOME/enclos`
//! and configuration in `$XDG_CONFIG_HOME/enclos`. `ENCLOS_HOME` puts
//! everything in one folder instead, on either system.

use std::ffi::OsString;
use std::fs::{DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The environment variable that overrides where enclos keeps its files.
pub const HOME_VAR: &str = "ENCLOS_HOME";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    MacOs,
    Linux,
}

impl Os {
    pub fn current() -> Os {
        if cfg!(target_os = "macos") {
            Os::MacOs
        } else {
            Os::Linux
        }
    }
}

/// The folders enclos owns on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    data: PathBuf,
    config: PathBuf,
    /// The user's home folder, which `~` in policies means.
    user_home: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum LayoutError {
    #[error(
        "cannot find your home folder: HOME is not set. Set HOME, or set {HOME_VAR} to the folder enclos should use"
    )]
    NoHome,
    #[error("{var} must be an absolute path, such as /Users/alice/.enclos; it is `{value}`")]
    NotAbsolute { var: &'static str, value: String },
    #[error("cannot create {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl Layout {
    /// Everything in one folder; `~` is the folder that holds it.
    pub fn at(root: impl Into<PathBuf>) -> Layout {
        let root = root.into();
        let user_home = root.parent().unwrap_or(&root).to_owned();
        Layout {
            data: root.clone(),
            config: root,
            user_home,
        }
    }

    /// The same layout, with `~` meaning `home`.
    pub fn with_user_home(mut self, home: impl Into<PathBuf>) -> Layout {
        self.user_home = home.into();
        self
    }

    /// The layout for this host and its environment variables.
    pub fn from_env() -> Result<Layout, LayoutError> {
        Layout::resolve(Os::current(), |var| std::env::var_os(var))
    }

    /// The layout for `os`, reading environment variables through `var`.
    pub fn resolve(os: Os, var: impl Fn(&str) -> Option<OsString>) -> Result<Layout, LayoutError> {
        let set = |name: &str| {
            var(name)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        };
        if let Some(root) = set(HOME_VAR) {
            let layout = Layout::at(absolute(HOME_VAR, root)?);
            return Ok(match set("HOME").filter(|h| h.is_absolute()) {
                Some(home) => layout.with_user_home(home),
                None => layout,
            });
        }
        let home = absolute("HOME", set("HOME").ok_or(LayoutError::NoHome)?)?;
        Ok(match os {
            Os::MacOs => Layout::at(home.join(".enclos")).with_user_home(home),
            Os::Linux => {
                // The XDG spec says to ignore relative values.
                let xdg = |name: &str, default: &str| {
                    set(name)
                        .filter(|p| p.is_absolute())
                        .unwrap_or_else(|| home.join(default))
                        .join("enclos")
                };
                Layout {
                    data: xdg("XDG_DATA_HOME", ".local/share"),
                    config: xdg("XDG_CONFIG_HOME", ".config"),
                    user_home: home.clone(),
                }
            }
        })
    }

    pub fn data(&self) -> &Path {
        &self.data
    }

    /// What tells this install apart from the user's other ones
    /// (`ENCLOS_HOME`) where they share a name space, as in launchd labels
    /// and Keychain items: the first 8 hex digits of the SHA-256 of the data
    /// folder, with links and `.` resolved, so that every spelling of the
    /// folder names the same install.
    pub fn install_id(&self) -> Result<String, LayoutError> {
        use std::os::unix::ffi::OsStrExt;
        let data = match std::fs::canonicalize(&self.data) {
            Ok(data) => data,
            // Missing, the folder holds nothing yet to name.
            Err(e) if e.kind() == ErrorKind::NotFound => self.data.clone(),
            Err(source) => {
                return Err(LayoutError::Io {
                    path: self.data.clone(),
                    source,
                });
            }
        };
        Ok(crate::policy::sha256_hex(data.as_os_str().as_bytes())[..8].to_owned())
    }

    pub fn config(&self) -> &Path {
        &self.config
    }

    pub fn user_home(&self) -> &Path {
        &self.user_home
    }

    /// The variables with which another enclos process, such as a service
    /// started with only `HOME`, resolves this same layout: `ENCLOS_HOME`
    /// when everything is in one folder, else both XDG folders.
    pub fn env(&self) -> Vec<(String, String)> {
        let var = |name: &str, path: &Path| (name.to_owned(), path.display().to_string());
        if self.data == self.config {
            return vec![var(HOME_VAR, &self.data)];
        }
        // Two folders come only from `resolve`'s Linux branch, each `<XDG
        // folder, set or defaulted>/enclos`: the parent is the value to pass.
        let parent = |path: &Path| path.parent().unwrap_or(path).to_owned();
        vec![
            var("XDG_DATA_HOME", &parent(&self.data)),
            var("XDG_CONFIG_HOME", &parent(&self.config)),
        ]
    }

    /// The enclos data and config folders: what sandboxes may never write
    /// outside their own home (ADR 0010).
    pub fn protected(&self) -> Vec<PathBuf> {
        self.roots()
    }

    /// The folder holding every sandbox's folder.
    pub fn sandboxes_dir(&self) -> PathBuf {
        self.data.join("sandboxes")
    }

    pub fn sandbox_dir(&self, name: &str) -> PathBuf {
        self.sandboxes_dir().join(name)
    }

    /// Where a runtime that reads its secrets from a file finds them while
    /// the sandbox's services run (ADR 0034): in the sandbox's folder,
    /// which the sandbox reads but never writes, and no other sandbox
    /// reads.
    pub fn sandbox_secrets_dir(&self, name: &str) -> PathBuf {
        self.sandbox_dir(name).join("secrets")
    }

    /// The sandbox's home folder: the runtime's home and the one place it may
    /// write by default.
    pub fn sandbox_home(&self, name: &str) -> PathBuf {
        self.sandbox_dir(name).join("home")
    }

    /// The sandbox's `policy.toml`: its overrides of the template.
    pub fn policy_file(&self, name: &str) -> PathBuf {
        self.sandbox_dir(name).join("policy.toml")
    }

    pub fn config_file(&self) -> PathBuf {
        self.config.join("config.toml")
    }

    pub fn state_db(&self) -> PathBuf {
        self.data.join("state.db")
    }

    /// The file the state lock is held on.
    pub fn state_lock(&self) -> PathBuf {
        self.data.join("state.lock")
    }

    pub fn audit_log(&self) -> PathBuf {
        self.data.join("audit.jsonl")
    }

    /// The proxies' control sockets.
    pub fn run_dir(&self) -> PathBuf {
        self.data.join("run")
    }

    /// Files no sandbox may read (ADR 0010). Each covers every file whose
    /// name starts with it too, such as `state.db-journal` or
    /// `audit.jsonl.torn-12`.
    pub fn hidden_files(&self) -> Vec<PathBuf> {
        vec![
            self.state_db(),
            self.state_lock(),
            self.audit_log(),
            self.config_file(),
        ]
    }

    /// Folders no sandbox may read (ADR 0010), besides other sandboxes'.
    pub fn hidden_dirs(&self) -> Vec<PathBuf> {
        vec![self.run_dir()]
    }

    fn roots(&self) -> Vec<PathBuf> {
        let mut roots = vec![self.data.clone()];
        if self.config != self.data {
            roots.push(self.config.clone());
        }
        roots
    }

    /// Every folder and file `enclos init` creates.
    pub fn paths(&self) -> Vec<PathBuf> {
        let mut paths = self.roots();
        paths.extend([
            self.config_file(),
            self.state_db(),
            self.audit_log(),
            self.data.join("runtimes"),
            self.config.join("templates"),
            self.run_dir(),
            self.sandboxes_dir(),
        ]);
        paths
    }

    /// The paths of [`Layout::paths`] that do not exist yet.
    pub fn missing(&self) -> Vec<PathBuf> {
        self.paths().into_iter().filter(|p| !p.exists()).collect()
    }

    /// Creates the top folders, which hold the state lock and the audit log.
    pub fn create_roots(&self) -> Result<(), LayoutError> {
        self.roots().iter().try_for_each(|dir| create_dir(dir))
    }

    /// Creates the folders under the top folders.
    pub fn create_dirs(&self) -> Result<(), LayoutError> {
        [
            self.data.join("runtimes"),
            self.config.join("templates"),
            self.run_dir(),
            self.sandboxes_dir(),
        ]
        .iter()
        .try_for_each(|dir| create_dir(dir))
    }

    /// Writes `config.toml` unless it exists. Returns whether it wrote it.
    pub fn write_config(&self, contents: &str) -> Result<bool, LayoutError> {
        let path = self.config_file();
        let io_err = |source| LayoutError::Io {
            path: path.clone(),
            source,
        };
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::AlreadyExists => return Ok(false),
            Err(e) => return Err(io_err(e)),
        };
        file.write_all(contents.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(io_err)?;
        Ok(true)
    }

    /// Creates a sandbox's folder, its home, and the home's `tmp`, which
    /// `TMPDIR` points at: the sandbox cannot write `/tmp`.
    pub fn create_sandbox_dirs(&self, name: &str) -> Result<(), LayoutError> {
        create_dir(&self.sandbox_home(name).join("tmp"))
    }

    pub fn read_policy(&self, name: &str) -> Result<String, LayoutError> {
        let path = self.policy_file(name);
        std::fs::read_to_string(&path).map_err(|source| LayoutError::Io { path, source })
    }

    /// Replaces a sandbox's `policy.toml` in one step: written beside it,
    /// then renamed over it, so a crash leaves the old or the new file.
    pub fn write_policy(&self, name: &str, contents: &str) -> Result<(), LayoutError> {
        let path = self.policy_file(name);
        let tmp = path.with_extension("toml.new");
        let io_err = |path: &Path| {
            let path = path.to_owned();
            move |source| LayoutError::Io { path, source }
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(io_err(&tmp))?;
        file.write_all(contents.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(io_err(&tmp))?;
        std::fs::rename(&tmp, &path).map_err(io_err(&path))
    }
}

fn absolute(var: &'static str, path: PathBuf) -> Result<PathBuf, LayoutError> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(LayoutError::NotAbsolute {
            var,
            value: path.display().to_string(),
        })
    }
}

/// Creates `dir` and its missing parents, readable only by the user.
fn create_dir(dir: &Path) -> Result<(), LayoutError> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|source| LayoutError::Io {
            path: dir.to_owned(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| OsString::from(v))
        }
    }

    #[test]
    fn macos_uses_dot_enclos_in_home() {
        let layout = Layout::resolve(Os::MacOs, env(&[("HOME", "/Users/alice")])).unwrap();
        assert_eq!(layout, Layout::at("/Users/alice/.enclos"));
    }

    #[test]
    fn a_process_given_the_layout_env_resolves_the_same_layout() {
        let cases: [(Os, &[(&str, &str)]); 4] = [
            (Os::MacOs, &[("HOME", "/Users/alice")]),
            (Os::Linux, &[("HOME", "/home/alice")]),
            (
                Os::Linux,
                &[
                    ("HOME", "/home/alice"),
                    ("XDG_DATA_HOME", "/data"),
                    ("XDG_CONFIG_HOME", "/cfg"),
                ],
            ),
            (
                Os::Linux,
                &[("HOME", "/home/alice"), ("ENCLOS_HOME", "/srv/enclos")],
            ),
        ];
        for (os, vars) in cases {
            let layout = Layout::resolve(os, env(vars)).unwrap();
            let given = layout.env();
            // A service starts with the user's HOME and nothing else.
            let home = vars.iter().find(|(k, _)| *k == "HOME").unwrap().1;
            let mut child: Vec<(&str, &str)> = given
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            child.push(("HOME", home));
            assert_eq!(
                Layout::resolve(os, env(&child)).unwrap(),
                layout,
                "{vars:?}"
            );
        }
    }

    #[test]
    fn linux_uses_xdg_folders() {
        let vars = [
            ("HOME", "/home/alice"),
            ("XDG_DATA_HOME", "/data"),
            ("XDG_CONFIG_HOME", "/cfg"),
        ];
        let layout = Layout::resolve(Os::Linux, env(&vars)).unwrap();
        assert_eq!(layout.data(), Path::new("/data/enclos"));
        assert_eq!(layout.config(), Path::new("/cfg/enclos"));
        assert_eq!(layout.config_file(), Path::new("/cfg/enclos/config.toml"));
        assert_eq!(layout.audit_log(), Path::new("/data/enclos/audit.jsonl"));
    }

    #[test]
    fn linux_falls_back_to_xdg_defaults() {
        let vars = [("HOME", "/home/alice"), ("XDG_DATA_HOME", "relative")];
        let layout = Layout::resolve(Os::Linux, env(&vars)).unwrap();
        assert_eq!(layout.data(), Path::new("/home/alice/.local/share/enclos"));
        assert_eq!(layout.config(), Path::new("/home/alice/.config/enclos"));
    }

    #[test]
    fn enclos_home_overrides_everything() {
        let vars = [("HOME", "/home/alice"), (HOME_VAR, "/tmp/e")];
        for os in [Os::MacOs, Os::Linux] {
            assert_eq!(
                Layout::resolve(os, env(&vars)).unwrap(),
                Layout::at("/tmp/e").with_user_home("/home/alice")
            );
        }
    }

    #[test]
    fn rejects_relative_and_missing_homes() {
        let relative = Layout::resolve(Os::MacOs, env(&[(HOME_VAR, "e")]));
        assert!(matches!(relative, Err(LayoutError::NotAbsolute { .. })));
        let none = Layout::resolve(Os::Linux, env(&[]));
        assert!(matches!(none, Err(LayoutError::NoHome)));
    }

    #[test]
    fn creates_every_path_but_the_files_it_does_not_own() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::at(dir.path().join("e"));
        assert_eq!(layout.missing(), layout.paths());
        layout.create_roots().unwrap();
        layout.create_dirs().unwrap();
        assert!(layout.write_config("schema_version = 1\n").unwrap());
        assert!(!layout.write_config("other").unwrap());
        let missing = layout.missing();
        assert_eq!(missing, [layout.state_db(), layout.audit_log()]);
    }
}
