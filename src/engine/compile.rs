//! Compiling a sandbox's active policy for its backend (design §8, step 2).
//! Compiled policies are stored by content under the sandbox's folder, so a
//! new enclos version or a new snapshot gets a new file and an unchanged one
//! is reused.

use std::path::PathBuf;

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
    pub(crate) fn sandbox_context(
        &self,
        name: &SandboxName,
        proxy_ports: &[u16],
    ) -> SandboxContext {
        SandboxContext {
            name: name.clone(),
            dir: self.layout.sandbox_dir(name.as_str()),
            home: self.layout.sandbox_home(name.as_str()),
            user_home: self.layout.user_home().to_owned(),
            protected: self.layout.protected(),
            sandboxes: self.layout.data().join("sandboxes"),
            data: self.layout.data().to_owned(),
            config_file: self.layout.config_file(),
            proxy_ports: proxy_ports.to_vec(),
        }
    }

    /// Compiles the sandbox's active policy for its backend, with the proxy
    /// ports it may reach, and returns the file the backend reads.
    pub fn compile_policy(&self, name: &SandboxName, proxy_ports: &[u16]) -> Result<PathBuf> {
        let backend = self.backend_of(name)?;
        let policy = self.policy(name)?.snapshot.policy;
        let ctx = self.sandbox_context(name, proxy_ports);
        let compiled = backend.compile(&policy, &ctx)?;
        let digest = sha256_hex(compiled.text.as_bytes());
        let dir = ctx.dir.join("compiled");
        let file = dir.join(format!("{}.{}", &digest[..16], compiled.extension));
        if !file.exists() {
            let io = |path: &PathBuf| {
                let path = path.clone();
                move |source| Error::Layout(LayoutError::Io { path, source })
            };
            std::fs::create_dir_all(&dir).map_err(io(&dir))?;
            std::fs::write(&file, &compiled.text).map_err(io(&file))?;
        }
        Ok(file)
    }
}
