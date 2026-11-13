//! Portable agent exports. Only the adapter knows the runtime's archive or command.
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::import::{ImportArchive, Source, opened_path};
use super::{Added, AgentAdded, Archive, Engine};
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

/// What a portable import restored, including the runtime's session/cleanup report.
#[derive(Debug, Clone)]
pub struct ImportedAgentExport {
    pub manifest: Manifest,
    pub added: Option<AgentAdded>,
    pub archive: Archive,
}

struct Temporary {
    path: PathBuf,
    armed: bool,
}
impl Temporary {
    fn created(path: PathBuf) -> Result<(Self, File)> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(failed)?;
        Ok((Self { path, armed: true }, file))
    }
    fn runtime_output(path: PathBuf) -> Result<Self> {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Err(failed("runtime export output already exists")),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(failed(e)),
        }
        Ok(Self { path, armed: true })
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if self.armed
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
            let _runtime_cleanup = Temporary::runtime_output(runtime_path.clone())?;
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
            let (_output_cleanup, mut output) = Temporary::created(scratch.clone())?;
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
                    let mut hashed = agent_export::Hashed::new(&mut output);
                    agent_export::write_complete(
                        &mut payload,
                        &mut hashed,
                        kind,
                        format!("{name}/{agent}"),
                        presentation,
                        format,
                        &state,
                    )
                    .map_err(failed)?;
                    let hash = hashed.sha256();
                    output.sync_all().map_err(failed)?;
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
    ) -> Result<Planned<ImportedAgentExport>> {
        let kind = self.runtime_of(name)?;
        let mut source = Source::open(&self.layout, from)?;
        if !metadata_only {
            self.preflight_host_import(name, &agent, None)?;
        }
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
            let services = if metadata_only {
                Vec::new()
            } else {
                self.plan_restart(name)?.plan(&format!("{name}/{agent}"))
            };
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
                ].into_iter().chain(services).collect(),
                ..Plan::default()
            }));
        }
        if metadata_only {
            self.portable_agent_exists(name, &agent)?;
        }
        let id = new_id().map_err(failed)?;
        let dir = self.layout.sandbox_installers(name.as_str());
        let (mut payload, mut output) = if metadata_only {
            (None, None)
        } else {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .map_err(failed)?;
            let (guard, file) =
                Temporary::created(dir.join(format!("agent-{agent}.{id}.runtime")))?;
            (Some(guard), Some(file))
        };
        let (manifest, state, archive) = self.write(
            by,
            "agent import export",
            Some(format!("{name}/{agent}")),
            |data: &(
                Manifest,
                Option<crate::bridge::portable::HostState>,
                Archive,
            )| {
                format!(
                    "validated Enclos export {} (sha256 {}); runtime payload staged once",
                    data.2.path.display(),
                    data.2.sha256
                )
            },
            |_| {
                let mut input = agent_export::Hashed::new(&mut source.file);
                let (manifest, state) = if let Some(output) = &mut output {
                    agent_export::read_complete(&mut input, output)
                } else {
                    agent_export::read_complete(&mut input, &mut io::sink())
                }
                .map_err(failed)?;
                let archive = Archive {
                    path: source.path.clone(),
                    sha256: input.sha256(),
                };
                Ok((manifest, state, archive))
            },
        )?;
        drop(output);
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
        let mut added = None;
        if !metadata_only {
            let runtime_archive = Archive {
                path: payload.as_ref().expect("runtime payload").path.clone(),
                sha256: manifest.payload_sha256.clone(),
            };
            let imported = self.import_agent_data(
                by,
                name,
                agent.clone(),
                ImportArchive::Staged(runtime_archive),
                Some((&manifest.runtime_format, &context)),
                Confirm::Yes,
            );
            added = match imported {
                Ok(Planned::Done(added)) => {
                    if matches!(
                        &added.how,
                        Added::Imported {
                            copy_left: Some(_),
                            ..
                        }
                    ) {
                        payload.as_mut().expect("runtime payload").disarm();
                    }
                    Some(added)
                }
                Ok(Planned::DryRun(_)) => unreachable!("confirmed import"),
                Err(error) => {
                    let what = format!(
                        "{error}; import did not finish; sandbox {name}'s runtime remains stopped. If the runtime agent was created, restore its name and photo with `agent import --metadata-only`; inspect the destination before restarting or retrying the full import"
                    );
                    return Err(Error::WithContext {
                        error: Box::new(error),
                        what,
                    });
                }
            };
            if let Some(state) = &state {
                self.restore_host_state(by, name, &agent, state, &conversations).map_err(|error| with_import_copy(Error::FailedAfter { error: Box::new(error), done: format!("importing {name}/{agent}'s runtime data; its runtime remains stopped. Recover its name and photo with `agent import --metadata-only`, or remove the partial agent and retry the full import after fixing the cause") }, &added))?;
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
            }}).map_err(|error| with_import_copy(error, &added))?;
        if let Some(paused) = paused {
            self.resume_runtime(by, name, paused)
                .map_err(|error| Error::FailedAfter {
                    error: Box::new(error),
                    done: format!("restoring complete data and presentation for {name}/{agent}"),
                })
                .map_err(|error| with_import_copy(error, &added))?;
        }
        Ok(Planned::Done(ImportedAgentExport {
            manifest,
            added,
            archive,
        }))
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
            photo: avatar
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

fn with_import_copy(error: Error, added: &Option<AgentAdded>) -> Error {
    if let Some(AgentAdded {
        how: Added::Imported {
            copy_left: Some(left),
            ..
        },
        ..
    }) = added
    {
        Error::CleanupFailed {
            error: Box::new(error),
            left: left.to_string(),
        }
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn review_cleanup_owns_only_files_whose_creation_succeeded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing");
        std::fs::write(&path, b"user data").unwrap();
        assert!(Temporary::created(path.clone()).is_err());
        assert!(Temporary::runtime_output(path.clone()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"user data");
        let owned = dir.path().join("owned");
        let (guard, file) = Temporary::created(owned.clone()).unwrap();
        drop(file);
        drop(guard);
        assert!(!owned.exists());
        let kept = dir.path().join("left-for-user");
        let (mut guard, file) = Temporary::created(kept.clone()).unwrap();
        drop(file);
        guard.disarm();
        drop(guard);
        assert!(kept.exists());
    }
}
