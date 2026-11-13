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
        let format = export.format;
        let command = export.command;
        if runtime_path.parent() != Some(home.as_path()) {
            return Err(failed(
                "the runtime export must be a file in the sandbox home",
            ));
        }
        if confirm == Confirm::DryRun {
            return Ok(Planned::DryRun(Plan { create: vec![to], changes: vec![
                format!("run {}'s complete export inside sandbox {name}", kind.display_name()),
                "save complete runtime data, credentials, display name, image and app history in a private, unencrypted file".into(),
            ] }));
        }
        if confirm == Confirm::Ask {
            self.plan_restart(name)?
                .confirm(&format!("exporting {name}/{agent}"))?;
        }
        let paused = self.pause_runtime(by, name, "agent export")?;
        let result = (|| {
            let state = self.export_host_state(name, agent)?;
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
            let scratch =
                to.with_file_name(format!(".enclos-export-{}.tmp", new_id().map_err(failed)?));
            let mut output_cleanup = Temporary::new(scratch.clone());
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
                        "exported complete private agent data to {} (sha256 {})",
                        a.path.display(),
                        a.sha256
                    )
                },
                |_| {
                    agent_export::write_complete(
                        &mut payload,
                        &mut output,
                        kind,
                        format!("{name}/{agent}"),
                        presentation,
                        format,
                        &state,
                    )
                    .map_err(failed)?;
                    output.sync_all().map_err(failed)?;
                    let hash = Source::open(&self.layout, &scratch)?.hash()?.sha256;
                    // Publish a complete file without replacing a path created
                    // concurrently. Both names are on the same filesystem.
                    std::fs::hard_link(&scratch, &to).map_err(failed)?;
                    Ok(Archive {
                        path: to.clone(),
                        sha256: hash,
                    })
                },
            )?;
            Ok(Planned::Done(exported))
        })();
        let resumed = self.resume_runtime(by, name, paused);
        match (result, resumed) {
            (Ok(exported), Ok(())) => Ok(exported),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(Error::FailedAfter {
                error: Box::new(error),
                done: "writing the complete export".into(),
            }),
            (Err(error), Err(resume)) => Err(failed(format!(
                "{error}; also could not resume runtime: {resume}"
            ))),
        }
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
            let (manifest, state) =
                agent_export::read_complete(&mut source.file, &mut io::sink()).map_err(failed)?;
            if !metadata_only {
                self.preflight_host_import(name, &agent, state.as_ref())?;
            }
            if !metadata_only && runtime_import_unsupported(kind, &agent, &manifest.runtime_format)
            {
                return Err(failed("unsupported runtime export format"));
            }
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
                    "restore presentation and, for a complete import, agent credentials and app history; retain destination host policy and pairings"
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
        let (manifest, state) = {
            let mut output = payload.create()?;
            agent_export::read_complete(&mut input, &mut output).map_err(failed)?
        };
        if manifest.runtime != kind.as_str() {
            return Err(failed(
                "the export's runtime differs from the destination sandbox",
            ));
        }
        if !metadata_only {
            self.preflight_host_import(name, &agent, state.as_ref())?;
            if runtime_import_unsupported(kind, &agent, &manifest.runtime_format) {
                return Err(failed("unsupported runtime export format"));
            }
        }
        let conversations = state
            .as_ref()
            .map(|s| s.history.conversation_map(&format!("{name}/{agent}")))
            .transpose()
            .map_err(failed)?
            .unwrap_or_default();
        let context =
            serde_json::json!({"source_agent":manifest.source_agent,"conversations":conversations})
                .to_string();
        let paused = if !metadata_only {
            if confirm == Confirm::Ask {
                self.plan_restart(name)?
                    .confirm(&format!("importing {name}/{agent}"))?;
            }
            Some(self.pause_runtime(by, name, "agent import")?)
        } else {
            None
        };
        if !metadata_only {
            let imported = self.import_agent_data(
                by,
                name,
                agent.clone(),
                &payload.path,
                Some((&manifest.runtime_format, &context)),
                Confirm::Yes,
            );
            if let Err(error) = imported {
                return Err(Error::WithContext {
                    error: Box::new(error),
                    what: format!(
                        "import did not finish; sandbox {name}'s runtime remains stopped. Inspect the destination before restarting it"
                    ),
                });
            }
            if let Some(state) = &state {
                self.restore_host_state(by, name, &agent, state, &conversations).map_err(|error| Error::FailedAfter { error: Box::new(error), done: format!("importing {name}/{agent}'s runtime data; its runtime remains stopped. Remove the imported agent and retry after fixing the cause") })?;
            }
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
        if let Some(paused) = paused {
            self.resume_runtime(by, name, paused)?;
        }
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

fn runtime_import_unsupported(
    kind: crate::model::runtime::RuntimeKind,
    agent: &AgentName,
    format: &str,
) -> bool {
    adapter(kind)
        .import_export(agent, Path::new("/export/runtime"), format, "{}")
        .is_none()
}
