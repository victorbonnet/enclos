//! Compiling a sandbox's active policy for its backend (design §8, step 2).
//! Compiled policies are stored by content under the sandbox's folder, so a
//! new enclos version or a new snapshot gets a new file and an unchanged one
//! is reused.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::Engine;
use crate::backend::{Backend, Probe, SandboxContext};
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::model::sandbox::SandboxName;
use crate::policy::sha256_hex;

impl Engine {
    /// The backend of the sandbox, refused when this host cannot run it
    /// (ADR 0009: no override).
    pub(crate) fn backend_of(&self, name: &SandboxName) -> Result<&dyn Backend> {
        let record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        let unavailable = |reason: String| Error::BackendUnavailable {
            sandbox: name.to_string(),
            backend: record.backend.to_string(),
            reason,
        };
        let backend = self
            .backends
            .iter()
            .find(|b| b.kind() == record.backend)
            .ok_or_else(|| unavailable("this build of enclos does not include it".to_owned()))?;
        match backend.probe() {
            Probe::Available => Ok(backend.as_ref()),
            Probe::Unavailable { reason } => Err(unavailable(reason)),
        }
    }

    /// What the backend needs to know about the sandbox.
    pub(crate) fn sandbox_context(&self, name: &SandboxName, proxy_port: u16) -> SandboxContext {
        SandboxContext::new(&self.layout, name, proxy_port)
    }

    /// Compiles the sandbox's active policy for its backend, with the proxy
    /// port it may reach, and returns the file the backend reads. A file
    /// already there is reused only when it holds exactly the compiled text:
    /// a cut-off Seatbelt profile can still be valid and leave out every
    /// restriction after the cut.
    pub fn compile_policy(&self, name: &SandboxName, proxy_port: u16) -> Result<PathBuf> {
        let (file, text) = self.compiled_file(name, proxy_port)?;
        if std::fs::read(&file).ok().as_deref() != Some(text.as_bytes()) {
            let dir = file.parent().unwrap_or(&file);
            std::fs::create_dir_all(dir).map_err(io(dir))?;
            publish(&file, text.as_bytes())?;
        }
        Ok(file)
    }

    /// The file the active policy compiles to, and its text, without
    /// writing it.
    pub(crate) fn compiled_file(
        &self,
        name: &SandboxName,
        proxy_port: u16,
    ) -> Result<(PathBuf, String)> {
        let backend = self.backend_of(name)?;
        let policy = self.policy(name)?.snapshot.policy;
        let ctx = self.sandbox_context(name, proxy_port);
        let compiled = backend.compile(&policy, &ctx)?;
        let digest = sha256_hex(compiled.text.as_bytes());
        let file =
            ctx.dir
                .join("compiled")
                .join(format!("{}.{}", &digest[..16], compiled.extension));
        Ok((file, compiled.text))
    }
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> Error {
    let path = path.to_owned();
    move |source| Error::Layout(LayoutError::Io { path, source })
}

/// Puts `contents` at `path` in one step: written in full to a new file
/// beside it, then renamed over it, so `path` never holds part of it.
fn publish(path: &Path, contents: &[u8]) -> Result<()> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.{}.{nanos}.new", std::process::id()));
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| f.write_all(contents).and_then(|()| f.sync_all()))
        .and_then(|()| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written.map_err(io(path))
}
