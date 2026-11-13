//! Portable agent exports. Only the adapter knows the runtime's archive or command.
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::import::{Source, opened_path};
use super::{Archive, Engine};
use crate::agent_export::{self, Manifest, Presentation};
use crate::bridge::{ids::new_id, store::Store};
use crate::error::{Error, Result};
use crate::model::{
    agent::AgentName,
    audit::Actor,
    plan::{Confirm, Plan, Planned},
    sandbox::SandboxName,
};
use crate::runtime::{RuntimeAgentName, adapter};

struct Temporary {
    path: PathBuf,
    keep: bool,
}
impl Temporary {
    fn new(path: PathBuf) -> Self {
        Self { path, keep: true }
    }
    fn create(&mut self) -> Result<File> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.path)
            .map_err(failed)?;
        self.keep = false;
        Ok(file)
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.keep
            && let Err(e) = std::fs::remove_file(&self.path)
            && e.kind() != io::ErrorKind::NotFound
        {
            eprintln!(
                "enclos: remove temporary export {}: {e}",
                self.path.display()
            );
        }
    }
}

impl Engine {
    /// Exports runtime data inside the sandbox, then wraps it with host-owned presentation.
    pub fn export_agent(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: &AgentName,
        to: &Path,
        confirm: Confirm,
    ) -> Result<Planned<Archive>> {
        let kind = self.runtime_of(name)?;
        let runtime = adapter(kind);
        self.portable_agent_exists(name, agent)?;
        let to = self.export_destination(to)?;
        let home = self.sandbox_home(name);
        let prefix = home.join(format!(
            ".enclos-export-{}.archive",
            new_id().map_err(failed)?
        ));
        let export = runtime.export_agent(agent, &prefix).ok_or_else(|| {
            failed(format!(
                "{} has no agent export command",
                kind.display_name()
            ))
        })?;
        let runtime_path = export.archive;
        let command = export.command;
        if runtime_path.parent() != Some(home.as_path()) {
            return Err(failed(
                "the runtime export must be a file in the sandbox home",
            ));
        }
        if confirm == Confirm::DryRun {
            return Ok(Planned::DryRun(Plan { create: vec![to], changes: vec![
                format!("run `{}` in sandbox {name}", command.shown()),
                "save the opaque runtime export, display name and image; no Enclos credentials or policy grants".into(),
            ] }));
        }
        let mut _runtime_cleanup = Temporary::new(runtime_path.clone());
        _runtime_cleanup.keep = false;
        let ended = self.run_in_sandbox(by, name, command, "agent export session")?;
        if ended.exit != 0 {
            return Err(failed(format!(
                "the runtime export exited with {}",
                ended.exit
            )));
        }
        let flags = (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits();
        let mut payload = OpenOptions::new()
            .read(true)
            .custom_flags(flags as i32)
            .open(&runtime_path)
            .map_err(failed)?;
        if !payload.metadata().map_err(failed)?.is_file()
            || !opened_path(&payload)
                .map_err(failed)?
                .starts_with(home.canonicalize().map_err(failed)?)
        {
            return Err(failed(
                "the runtime export is not a plain file in the sandbox home",
            ));
        }
        let presentation = self.export_presentation(&format!("{name}/{agent}"))?;
        let mut output_cleanup = Temporary::new(to.clone());
        // A failed create must never let cleanup delete an existing destination.
        output_cleanup.keep = true;
        let mut output = output_cleanup.create()?;
        output_cleanup.keep = false;
        let exported = self.write(
            by,
            "agent export",
            Some(format!("{name}/{agent}")),
            |a: &Archive| {
                format!(
                    "exported {} (sha256 {}) with its display name and image",
                    a.path.display(),
                    a.sha256
                )
            },
            |_| {
                agent_export::write(
                    &mut payload,
                    &mut output,
                    kind,
                    format!("{name}/{agent}"),
                    presentation,
                )
                .map_err(failed)?;
                output.sync_all().map_err(failed)?;
                Source::open(&self.layout, &to)?.hash()
            },
        )?;
        output_cleanup.keep = true;
        Ok(Planned::Done(exported))
    }

    /// Imports an Enclos export; the runtime still extracts its own payload inside the sandbox.
    pub fn import_agent_export(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: AgentName,
        from: &Path,
        metadata_only: bool,
        confirm: Confirm,
    ) -> Result<Planned<Manifest>> {
        let kind = self.runtime_of(name)?;
        let mut source = Source::open(&self.layout, from)?;
        // A dry run validates every byte but writes no temporary file or database.
        if confirm == Confirm::DryRun {
            let manifest = agent_export::read(&mut source.file, &mut io::sink()).map_err(failed)?;
            if manifest.runtime != kind.as_str() {
                return Err(failed(
                    "the export's runtime differs from the destination sandbox",
                ));
            }
            if metadata_only {
                self.portable_agent_exists(name, &agent)?;
            }
            return Ok(Planned::DryRun(Plan {
                changes: vec![
                    format!(
                        "{} {name}/{agent} from {}",
                        if metadata_only {
                            "restore presentation of"
                        } else {
                            "import"
                        },
                        source.path.display()
                    ),
                    "restore the display name and image, without policy grants or device pairings"
                        .into(),
                ],
                ..Plan::default()
            }));
        }
        if metadata_only {
            self.portable_agent_exists(name, &agent)?;
        }
        let dir = self.layout.data().join("agent-transfers");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(failed)?;
        let id = new_id().map_err(failed)?;
        let mut outer = Temporary::new(dir.join(format!("{id}.enclos")));
        let archive = self.write(
            by,
            "agent import export",
            Some(format!("{name}/{agent}")),
            |a: &Archive| {
                format!(
                    "copied Enclos export {} (sha256 {})",
                    a.path.display(),
                    a.sha256
                )
            },
            |_| {
                let copied = source.stage(&outer.path)?;
                outer.keep = false;
                Ok(copied)
            },
        )?;
        let mut payload = Temporary::new(dir.join(format!("{id}.runtime")));
        let mut input = File::open(&outer.path).map_err(failed)?;
        let manifest = {
            let mut output = payload.create()?;
            agent_export::read(&mut input, &mut output).map_err(failed)?
        };
        if manifest.runtime != kind.as_str() {
            return Err(failed(
                "the export's runtime differs from the destination sandbox",
            ));
        }
        if !metadata_only {
            self.import_agent(by, name, agent.clone(), &payload.path, confirm)?;
        }
        let image = manifest.presentation.image().map_err(failed)?;
        self.write(by, "agent import presentation", Some(format!("{name}/{agent}")),
            |_| format!("restored display name and image from {} (sha256 {})", archive.path.display(), archive.sha256),
            |_| {
                let store = Store::open(&self.app_store_path()).map_err(failed)?;
                store.import_presentation(&format!("{name}/{agent}"), manifest.presentation.display_name.as_deref(), image.as_deref()).map_err(failed)
            }).map_err(|error| if metadata_only { error } else { Error::FailedAfter {
                error: Box::new(error), done: format!("importing {name}/{agent}; restore its name and image with agent import --metadata-only"),
            }})?;
        Ok(Planned::Done(manifest))
    }

    fn portable_agent_exists(&self, name: &SandboxName, agent: &AgentName) -> Result<()> {
        let runtime = adapter(self.runtime_of(name)?);
        if runtime
            .builtin_agent()
            .is_some_and(|b| b.as_str() == agent.as_str())
        {
            return Ok(());
        }
        let found = runtime
            .agents_in(&self.sandbox_home(name))
            .map_err(failed)?;
        if !found.contains(&RuntimeAgentName::from(agent)) {
            return Err(failed(format!("no runtime agent {name}/{agent}")));
        }
        Ok(())
    }

    fn export_presentation(&self, agent: &str) -> Result<Presentation> {
        if !self.app_store_path().exists() {
            return Ok(Presentation::default());
        }
        let store = Store::open(&self.app_store_path()).map_err(failed)?;
        let name = store.agent_name(agent).map_err(failed)?;
        let avatar = store.avatar(agent).map_err(failed)?;
        Ok(Presentation {
            display_name: name.display_name,
            avatar: avatar
                .image
                .as_deref()
                .map(enclos_protocol::pairing::encode),
        })
    }

    fn export_destination(&self, to: &Path) -> Result<PathBuf> {
        let path = std::path::absolute(to).map_err(failed)?;
        let parent = path
            .parent()
            .ok_or_else(|| failed("the export needs a parent directory"))?
            .canonicalize()
            .map_err(failed)?;
        let sandboxes = self.layout.sandboxes_dir().canonicalize().map_err(failed)?;
        if parent.starts_with(sandboxes) {
            return Err(failed("save the export outside the sandboxes' folders"));
        }
        if path.symlink_metadata().is_ok() {
            return Err(failed("the export destination already exists"));
        }
        Ok(parent.join(
            path.file_name()
                .ok_or_else(|| failed("name the export file"))?,
        ))
    }
}

fn failed(e: impl std::fmt::Display) -> Error {
    Error::Session {
        what: e.to_string(),
    }
}
