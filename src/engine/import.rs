//! Importing an agent from an export the runtime made on the host:
//! `enclos agent add <sandbox>/<agent> --from <archive>` (issue #34, design
//! §9 "Agents imported from the host"). The host copies the archive beside
//! the sandbox home and the runtime extracts it inside the sandbox; enclos
//! never looks inside it.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::Engine;
use super::runtime::{Added, AgentAdded, hex};
use crate::error::{Error, Result};
use crate::layout::Layout;
use crate::model::agent::AgentName;
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::sandbox::SandboxName;
use crate::runtime::{RuntimeAgentName, adapter};

/// An archive on the host that an agent was imported from: an export made
/// with the runtime's own command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archive {
    /// Its absolute path, as the audit entry records it.
    pub path: PathBuf,
    /// The SHA-256 of the bytes the runtime was given, recorded in the
    /// audit entries so an agent's origin is traceable.
    pub sha256: String,
}

/// An archive the user named, opened once: the bytes hashed are the bytes
/// copied. Written by whoever wrote the file, so it is a plain file, never
/// a link, and never inside a sandbox's folder.
struct Source {
    path: PathBuf,
    file: File,
}

impl Engine {
    /// Adds an agent from the archive at `from`, an export the runtime's own
    /// command made on the host, such as `hermes profile export` (issue
    /// #34). enclos copies the archive beside the sandbox home, where the
    /// sandbox reads and never writes, as an audited step that records the
    /// archive's SHA-256; the runtime's own import then extracts it inside
    /// the sandbox, under its policy, so the host never does; and enclos
    /// records the agent. enclos copies no host login in (ADR 0022): what
    /// the archive holds is the runtime's export to decide. Nothing in it
    /// widens the policy: what the imported configuration reaches shows in
    /// `enclos net log`, and what was refused in `enclos net denied`.
    pub fn import_agent(
        &self,
        by: &Actor,
        name: &SandboxName,
        agent: AgentName,
        from: &Path,
        confirm: Confirm,
    ) -> Result<Planned<AgentAdded>> {
        let kind = self.runtime_of(name)?;
        let runtime = adapter(kind);
        let shown = kind.display_name();
        // One copy per run, so two imports of the same name never share it.
        let staged = self
            .layout
            .sandbox_dir(name.as_str())
            .join("installers")
            .join(format!("agent-{agent}.{}.tar.gz", std::process::id()));
        let Some(command) = runtime.import_agent(&agent, &staged) else {
            return Err(failed(format!(
                "{shown} cannot import an agent from an archive. `enclos agent add {name}/{agent}` creates a new one"
            )));
        };
        self.refuse_builtin(name, kind, agent.as_str())?;
        self.refuse_known_agent(name, &agent)?;
        // The runtime would refuse to import over an agent it has, and
        // enclos never replaces one. When the list cannot be read, enclos
        // cannot tell, and says so rather than run the runtime on a guess.
        match runtime.agents_in(&self.sandbox_home(name)) {
            Ok(found) if found.contains(&RuntimeAgentName::from(&agent)) => {
                return Err(failed(format!(
                    "{shown} already has an agent named {agent} in sandbox {name}, and an import needs a fresh name. `enclos agent add {name}/{agent}` records the existing one as it is"
                )));
            }
            Ok(_) => {}
            Err(why) => {
                return Err(failed(format!(
                    "enclos cannot read {shown}'s agents in sandbox {name} ({why}), so it cannot tell whether agent {agent} is already there. Look at the sandbox home with `enclos connect {name}` first"
                )));
            }
        }
        if let Some(path) = self.command_named(name, &agent)? {
            return Err(failed(format!(
                "`{agent}` is a command on the sandbox's PATH ({}); {shown} would not give the agent its alias. Pick another name",
                path.display()
            )));
        }
        let source = Source::open(&self.layout, from)?;
        if confirm == Confirm::DryRun {
            let version = self.policy(name)?.version.version;
            let Archive { path, sha256 } = source.hash()?;
            return Ok(Planned::DryRun(Plan {
                changes: vec![
                    format!(
                        "copy {} (sha256 {sha256} now) to {}, beside the home of sandbox {name}, where the sandbox reads it and cannot write",
                        path.display(),
                        staged.display()
                    ),
                    format!(
                        "run `{}` in sandbox {name} under policy v{version}: {shown} extracts the archive inside the sandbox",
                        command.shown()
                    ),
                    format!("record agent {name}/{agent} as imported from that archive"),
                ],
                ..Plan::default()
            }));
        }
        // Staging is audited on its own, so the archive and its hash are in
        // the audit log before the runtime runs, whatever happens after.
        let archive = self.write(
            by,
            "agent import",
            Some(format!("{name}/{agent}")),
            |a: &Archive| format!("staged {} (sha256 {})", a.path.display(), a.sha256),
            |_| source.stage(&staged),
        )?;
        let ran = self.run_in_sandbox(by, name, command, "agent import run");
        // The copy served its one import; the sandbox keeps what it took.
        let copy_left = match std::fs::remove_file(&staged) {
            Ok(()) => None,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => Some(staged),
        };
        // When the import fails, the runtime may have made the agent anyway.
        let delete_it = match runtime.delete_agent(&agent) {
            Some(delete) => format!("`enclos connect {name} -- {}`", delete.shown()),
            None => format!("{shown}'s own commands"),
        };
        let end = match ran {
            Ok(end) if end.exit == 0 => end,
            Ok(end) => {
                let error = failed(format!(
                    "{shown} could not import agent {agent} from {} (exit {}): its output above says why. Nothing was recorded. If {shown} has the agent anyway, `enclos agent list {name}` reports it: delete it with {delete_it} and import again",
                    archive.path.display(),
                    end.exit
                ));
                return Err(with_copy_left(error, copy_left.as_deref()));
            }
            Err(e) => {
                let error = failed(format!(
                    "enclos lost track of the import of {} into sandbox {name}: {e}. Nothing was recorded. If {shown} has agent {agent} now, `enclos agent list {name}` reports it: record it with `enclos agent add {name}/{agent}`, or delete it with {delete_it}; otherwise import again",
                    archive.path.display()
                ));
                return Err(with_copy_left(error, copy_left.as_deref()));
            }
        };
        let mut outcome = format!(
            "imported from {} (sha256 {})",
            archive.path.display(),
            archive.sha256
        );
        if let Some(copy) = &copy_left {
            outcome.push_str(&format!(
                "; the copy at {} could not be removed",
                copy.display()
            ));
        }
        let then = format!(
            "Run `enclos agent add {name}/{agent}` (without --from): it records the agent {shown} imported; the archive's SHA-256 is in the `agent import` audit entry"
        );
        let record = self.record_agent(by, name, &agent, kind, outcome, &then)?;
        Ok(Planned::Done(AgentAdded {
            agent: record,
            kind,
            how: Added::Imported {
                end,
                archive,
                copy_left,
            },
        }))
    }
}

impl Source {
    /// Opens the archive the user named. It must be a plain file, not a link
    /// and not inside a sandbox's folder: a sandbox writes its folder, and
    /// the host must never carry what a sandbox points at into another
    /// sandbox (ADR 0023). The file is checked, then opened, then checked
    /// to be the same file, so nothing swapped in between is read.
    fn open(layout: &Layout, path: &Path) -> Result<Source> {
        let path = std::path::absolute(path).map_err(|e| {
            failed(format!(
                "cannot resolve the archive path {}: {e}",
                path.display()
            ))
        })?;
        let shown = path.display();
        let name_an_export = "Name an export the runtime's own command made on this Mac";
        let meta = std::fs::symlink_metadata(&path).map_err(|e| {
            failed(format!(
                "cannot read the archive at {shown}: {e}. {name_an_export}"
            ))
        })?;
        if meta.file_type().is_symlink() {
            return Err(failed(format!(
                "{shown} is a link. Name the archive file itself"
            )));
        }
        if !meta.is_file() {
            return Err(failed(format!("{shown} is not a file. {name_an_export}")));
        }
        if inside(&path, &layout.sandboxes_dir()) {
            return Err(failed(format!(
                "{shown} is inside a sandbox's folder, which that sandbox writes. Copy the export to a folder of your own first, then import the copy"
            )));
        }
        let unreadable =
            |e: std::io::Error| failed(format!("cannot read the archive at {shown}: {e}"));
        let file = File::open(&path).map_err(unreadable)?;
        let opened = file.metadata().map_err(unreadable)?;
        if (opened.dev(), opened.ino()) != (meta.dev(), meta.ino()) {
            return Err(failed(format!(
                "{shown} changed while enclos opened it. Import again"
            )));
        }
        Ok(Source { path, file })
    }

    /// The archive as it is now, with its SHA-256, for a dry run.
    fn hash(mut self) -> Result<Archive> {
        let sha256 = stream(&mut self.file, None).map_err(|e| {
            failed(format!(
                "cannot read the archive at {}: {e}",
                self.path.display()
            ))
        })?;
        Ok(Archive {
            path: self.path,
            sha256,
        })
    }

    /// Copies the archive to `staged`, a new file in the sandbox's
    /// `installers/` folder, which the compiled policy denies the sandbox
    /// writes to, hashing the bytes as they go. A failed copy leaves no
    /// partial file behind.
    fn stage(mut self, staged: &Path) -> Result<Archive> {
        let dir = staged.parent().unwrap_or(staged);
        std::fs::create_dir_all(dir)
            .map_err(|e| failed(format!("cannot create {}: {e}", dir.display())))?;
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(staged)
            .map_err(|e| {
                failed(format!(
                    "cannot create the copy of the archive at {}: {e}. Remove what is there and import again",
                    staged.display()
                ))
            })?;
        let sha256 = match stream(&mut self.file, Some(&mut target)) {
            Ok(sha256) => sha256,
            Err(e) => {
                let _ = std::fs::remove_file(staged);
                return Err(failed(format!(
                    "cannot copy {} to {}: {e}. Check the disk and the folder's permissions",
                    self.path.display(),
                    staged.display()
                )));
            }
        };
        Ok(Archive {
            path: self.path,
            sha256,
        })
    }
}

/// The error of a step that failed, saying what to do next.
fn failed(what: String) -> Error {
    Error::Session { what }
}

/// `error`, and what is left behind when enclos could not remove its copy
/// of the archive, which the sandbox can read.
fn with_copy_left(error: Error, copy_left: Option<&Path>) -> Error {
    match copy_left {
        None => error,
        Some(copy) => Error::CleanupFailed {
            error: Box::new(error),
            left: format!(
                "enclos's copy of the archive at {}, which the sandbox can read: remove it yourself",
                copy.display()
            ),
        },
    }
}

/// Reads `file` to its end, hashing it, and writes it to `sink` if given.
/// A `File` is unbuffered, so there is nothing to flush.
fn stream(file: &mut File, mut sink: Option<&mut File>) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        if let Some(sink) = sink.as_mut() {
            sink.write_all(&buffer[..n])?;
        }
    }
    Ok(hex(&hasher.finalize()))
}

/// Whether `path` is under `folder`, by the paths as given and as resolved,
/// so a link in a parent folder does not hide it.
fn inside(path: &Path, folder: &Path) -> bool {
    if path.starts_with(folder) {
        return true;
    }
    match (path.canonicalize(), folder.canonicalize()) {
        (Ok(p), Ok(f)) => p.starts_with(f),
        _ => false,
    }
}
