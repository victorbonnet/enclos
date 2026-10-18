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
    /// Everything in one folder.
    pub fn at(root: impl Into<PathBuf>) -> Layout {
        let root = root.into();
        Layout {
            data: root.clone(),
            config: root,
        }
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
            return absolute(HOME_VAR, root).map(Layout::at);
        }
        let home = absolute("HOME", set("HOME").ok_or(LayoutError::NoHome)?)?;
        Ok(match os {
            Os::MacOs => Layout::at(home.join(".enclos")),
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
                }
            }
        })
    }

    pub fn data(&self) -> &Path {
        &self.data
    }

    pub fn config(&self) -> &Path {
        &self.config
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
            self.data.join("run"),
            self.data.join("sandboxes"),
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
            self.data.join("run"),
            self.data.join("sandboxes"),
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
                Layout::at("/tmp/e")
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
