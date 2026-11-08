//! A sandbox's namespace holder (ADR 0039), for a backend whose sessions
//! join one: one of the sandbox's services, which `sandbox start` installs
//! with the others, and the first session of a sandbox that was never
//! started installs alone. It stays until `sandbox stop`, and nothing enclos
//! does replaces one that answers: its network namespace holds the sandbox's
//! open sessions and services, and a new one would split them.

use std::fs::File;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use super::Engine;
use super::service::{PROXY_WAIT, Unit};
use crate::backend::{HeldNamespace, NamespaceHolder};
use crate::error::{Error, Result};
use crate::model::sandbox::{BackendKind, SandboxName, SandboxRecord};
use crate::service::ServiceLabel;

/// How often a wait for the namespace holder asks it again.
const HOLDER_POLL: Duration = Duration::from_millis(100);

impl Engine {
    /// The namespace holder of a sandbox on `backend`, when its sessions
    /// join one. Found among the backends this build has without asking
    /// whether it runs here, so a host where it does not still names the
    /// sandbox's services.
    pub(super) fn holder_of(&self, backend: BackendKind) -> Option<&dyn NamespaceHolder> {
        self.backends
            .iter()
            .find(|b| b.kind() == backend)?
            .namespace_holder()
    }

    /// What `record`'s namespace holder says of its namespace, when its
    /// sessions join one: an error when none answers.
    pub(super) fn held_namespace(
        &self,
        record: &SandboxRecord,
    ) -> Option<std::result::Result<HeldNamespace, String>> {
        let holder = self.holder_of(record.backend)?;
        Some(holder.ask(&self.sandbox_context(&record.name, record.proxy_port)))
    }

    /// The label of `record`'s namespace holder when one answers now, which
    /// `sandbox start` keeps as it runs.
    pub(super) fn answering_holder(&self, record: &SandboxRecord) -> Result<Option<ServiceLabel>> {
        match self.held_namespace(record) {
            Some(Ok(_)) => Ok(Some(self.label(&record.name, Unit::Holder)?)),
            Some(Err(_)) | None => Ok(None),
        }
    }

    /// Makes sure `record`'s namespace holder answers before one of its
    /// sessions starts, when its sessions join one: installs its service
    /// when it is not installed, as when the sandbox was never started, and
    /// waits for it. One installed already is the service manager's to start
    /// again, so this only waits for it. A session that did not wait would
    /// fail to join.
    pub(super) fn ensure_holder(&self, record: &SandboxRecord) -> Result<()> {
        let Some(holder) = self.holder_of(record.backend) else {
            return Ok(());
        };
        let name = &record.name;
        let ctx = self.sandbox_context(name, record.proxy_port);
        if holder.ask(&ctx).is_ok() {
            return Ok(());
        }
        if !self.unit_installed(name, Unit::Holder)? {
            crate::notes::say(&format!(
                "starting the namespace holder of sandbox {name}, whose network namespace its sessions join; it runs until `enclos sandbox stop {name}`"
            ));
            // Made by no one else yet when nothing of the sandbox ran before.
            self.create_logs_dir(name)?;
            self.services
                .start(&self.service_unit(record, Unit::Holder, &[])?)?;
        }
        self.holder_answers(name, holder, &ctx, PROXY_WAIT)
    }

    /// Waits up to `wait` for the namespace holder to answer, then says why
    /// it did not, as a session's start that cannot go on.
    fn holder_answers(
        &self,
        name: &SandboxName,
        holder: &dyn NamespaceHolder,
        ctx: &crate::backend::SandboxContext,
        wait: Duration,
    ) -> Result<()> {
        let begun = Instant::now();
        loop {
            let why = match holder.ask(ctx) {
                Ok(_) => return Ok(()),
                Err(why) => why,
            };
            if begun.elapsed() >= wait {
                return Err(Error::Session {
                    what: format!(
                        "the namespace holder of sandbox {name}, whose network namespace its sessions join, did not answer within {} s ({why}); `enclos logs {name}` shows its log",
                        wait.as_secs()
                    ),
                });
            }
            std::thread::sleep(HOLDER_POLL);
        }
    }

    /// `enclos holder run`: runs the sandbox's namespace holder to its end,
    /// as the service manager runs it (ADR 0039), with `stderr` as its
    /// stderr. How it ended, or why it could not start.
    pub fn run_holder(&self, name: &SandboxName, stderr: &File) -> Result<ExitStatus> {
        let record = self.record(name)?;
        let backend = self.backend_of(name)?;
        let holder = backend.namespace_holder().ok_or_else(|| Error::Holder {
            why: format!(
                "sandbox {name} is on {}, whose sessions join no namespace holder",
                record.backend
            ),
        })?;
        // The proxy's socket folder too, which the relay reaches.
        self.layout
            .create_proxy_socket_dir(name.as_str())
            .map_err(|source| crate::layout::LayoutError::Io {
                path: self.layout.sandbox_run_dir(name.as_str()),
                source,
            })?;
        let ctx = self.sandbox_context(name, record.proxy_port);
        holder
            .run(&ctx, stderr)
            .map_err(|e| Error::Holder { why: e.to_string() })
    }
}
