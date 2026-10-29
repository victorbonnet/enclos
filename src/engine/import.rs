//! Importing an agent from an export the runtime made on the host:
//! `enclos agent add <sandbox>/<agent> --from <archive>` (issue #34, design
//! §9 "Agents imported from the host"). The host copies the archive beside
//! the sandbox home and the runtime extracts it inside the sandbox; enclos
//! never looks inside it.

use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rustix::fs::OFlags;
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

/// enclos's copy of an archive beside the sandbox home that it could not
/// remove: the sandbox can read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftCopy {
    pub path: PathBuf,
    /// Why it could not be removed.
    pub why: String,
}

/// An archive the user named, opened once so the bytes hashed are the bytes
/// copied. Refused when it is a link, not a plain file, or under a
/// sandbox's folder, whose home the sandbox writes.
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
        // One copy per enclos process, so two imports of the same name never
        // share it.
        let installers = self.layout.sandbox_dir(name.as_str()).join("installers");
        let copy_named = |id: &str| installers.join(format!("agent-{agent}.{id}.tar.gz"));
        let staged = copy_named(&std::process::id().to_string());
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
            // The real run names its copy after its own process.
            let planned = copy_named("<pid>");
            let command = runtime.import_agent(&agent, &planned).unwrap_or(command);
            return Ok(Planned::DryRun(Plan {
                changes: vec![
                    format!(
                        "copy {} (sha256 {sha256} now) to a new file such as {}, beside the home of sandbox {name}, where the sandbox reads it and cannot write",
                        path.display(),
                        planned.display()
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
        let copied = Cell::new(false);
        let staging = self.write(
            by,
            "agent import",
            Some(format!("{name}/{agent}")),
            |a: &Archive| {
                format!(
                    "copied {} (sha256 {}) to {}",
                    a.path.display(),
                    a.sha256,
                    staged.display()
                )
            },
            |_| {
                let archive = source.stage(&staged)?;
                copied.set(true);
                Ok(archive)
            },
        );
        let archive = match staging {
            Ok(archive) => archive,
            // The copy was made but its audit entry could not be closed: it
            // goes, since the runtime will not run.
            Err(e) if copied.get() => return Err(with_copy_left(e, remove_copy(&staged))),
            Err(e) => return Err(e),
        };
        let ran = self.run_in_sandbox(by, name, command, "agent import session");
        // The copy served its one import; the sandbox keeps what it took.
        let copy_left = remove_copy(&staged);
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
                return Err(with_copy_left(error, copy_left));
            }
            Err(e) => {
                // The session may not have started (the proxy, the policy),
                // or may have started and then failed to report back.
                let what = format!(
                    "the import of {} into sandbox {name} did not finish: {e}. Nothing was recorded. If {shown} has agent {agent} anyway, `enclos agent list {name}` reports it: record it with `enclos agent add {name}/{agent}`, or delete it with {delete_it}; otherwise import again",
                    archive.path.display()
                );
                let error = Error::WithContext {
                    error: Box::new(e),
                    what,
                };
                return Err(with_copy_left(error, copy_left));
            }
        };
        // As for an agent `agent add` makes: the archive's settings may name
        // another agent's secrets, or a helper of the host's (ADR 0036).
        for then in runtime.after_create_agent(&agent) {
            let shown_then = then.shown();
            let ended = self.run_in_sandbox(by, name, then, "agent import session")?;
            if ended.exit != 0 {
                let error = Error::FailedAfter {
                    error: Box::new(failed(format!(
                        "`{shown_then}` exited with {} in sandbox {name}: its output above says why. Run it with `enclos connect {name} -- {shown_then}`, then `enclos agent add {name}/{agent}`, which tracks the agent as it is",
                        ended.exit
                    ))),
                    done: format!("importing agent {agent} into sandbox {name}"),
                };
                return Err(with_copy_left(error, copy_left));
            }
        }
        let how = Added::Imported {
            end,
            archive,
            copy_left,
        };
        let record = self
            .record_agent(by, name, &agent, kind, &how)
            .map_err(|e| match &how {
                Added::Imported { copy_left, .. } => with_copy_left(e, copy_left.clone()),
                _ => e,
            })?;
        Ok(Planned::Done(AgentAdded {
            agent: record,
            kind,
            how,
        }))
    }
}

impl Source {
    /// Opens the archive the user named. It must be a plain file, not a link
    /// and not under a sandbox's folder: a sandbox writes its home there,
    /// and the host must never copy what a sandbox put or pointed at into a
    /// sandbox. The file is opened without following a last link, and
    /// without waiting on a pipe; the checks then hold for the opened file
    /// itself, wherever its path pointed while it was opened. A workspace a
    /// sandbox may write is not checked: an archive there is the user's call.
    fn open(layout: &Layout, path: &Path) -> Result<Source> {
        let path = std::path::absolute(path).map_err(|e| {
            failed(format!(
                "cannot resolve the archive path {}: {e}",
                path.display()
            ))
        })?;
        let shown = path.display();
        let name_an_export = "Name an export the runtime's own command made on this Mac";
        let sandboxes = layout.sandboxes_dir();
        let under_a_sandbox = || {
            failed(format!(
                "{shown} is under a sandbox's folder, whose home that sandbox writes. Copy the export to a folder of your own first, then import the copy"
            ))
        };
        if path.starts_with(&sandboxes) {
            return Err(under_a_sandbox());
        }
        let no_follow = (OFlags::NOFOLLOW | OFlags::NONBLOCK).bits();
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(no_follow as i32)
            .open(&path)
            .map_err(|e| match e.raw_os_error() {
                Some(code) if code == rustix::io::Errno::LOOP.raw_os_error() => {
                    failed(format!("{shown} is a link. Name the archive file itself"))
                }
                _ => failed(format!(
                    "cannot read the archive at {shown}: {e}. {name_an_export}"
                )),
            })?;
        let unreadable =
            |e: std::io::Error| failed(format!("cannot read the archive at {shown}: {e}"));
        if !file.metadata().map_err(unreadable)?.is_file() {
            return Err(failed(format!("{shown} is not a file. {name_an_export}")));
        }
        // Where the opened file really is, with every link on the way
        // resolved; when enclos cannot tell, it refuses.
        let opened = opened_path(&file).map_err(unreadable)?;
        let sandboxes = match sandboxes.canonicalize() {
            Ok(dir) => Some(dir),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => {
                return Err(failed(format!(
                    "cannot tell whether {shown} is under a sandbox's folder: {}: {e}",
                    sandboxes.display()
                )));
            }
        };
        if sandboxes.is_some_and(|dir| opened.starts_with(dir)) {
            return Err(under_a_sandbox());
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
    /// writes to, hashing the bytes as they go. A copy that fails is
    /// removed, or reported when it cannot be; one cut short by enclos
    /// being killed stays.
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
                let error = failed(format!(
                    "cannot copy {} to {}: {e}. Check the disk and the folder's permissions",
                    self.path.display(),
                    staged.display()
                ));
                return Err(with_copy_left(error, remove_copy(staged)));
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

/// Removes enclos's copy of an archive; what is left when it cannot.
fn remove_copy(staged: &Path) -> Option<LeftCopy> {
    match std::fs::remove_file(staged) {
        Ok(()) => None,
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => Some(LeftCopy {
            path: staged.to_owned(),
            why: e.to_string(),
        }),
    }
}

/// `error`, and the copy of the archive enclos could not remove, which the
/// sandbox can read.
fn with_copy_left(error: Error, copy_left: Option<LeftCopy>) -> Error {
    match copy_left {
        None => error,
        Some(copy) => Error::CleanupFailed {
            error: Box::new(error),
            left: copy.to_string(),
        },
    }
}

impl std::fmt::Display for LeftCopy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "enclos's copy of the archive at {}, which the sandbox can read ({}): remove it yourself",
            self.path.display(),
            self.why
        )
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

/// The path of an opened file, from the file itself, with every link
/// resolved.
#[cfg(target_os = "macos")]
fn opened_path(file: &File) -> std::io::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let path = rustix::fs::getpath(file)?;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(
        path.into_bytes(),
    )))
}

/// The path of an opened file, from the file itself, with every link
/// resolved.
#[cfg(not(target_os = "macos"))]
fn opened_path(file: &File) -> std::io::Result<PathBuf> {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_left_behind_turns_the_error_into_a_cleanup_failure() {
        let error = || failed("the import failed".into());
        assert_eq!(
            with_copy_left(error(), None).to_string(),
            error().to_string()
        );
        let left = LeftCopy {
            path: "/x/installers/agent-main.1.tar.gz".into(),
            why: "Operation not permitted".into(),
        };
        let Error::CleanupFailed { error: inner, left } = with_copy_left(error(), Some(left))
        else {
            panic!("not a cleanup failure");
        };
        assert_eq!(inner.to_string(), "the import failed");
        assert!(left.contains("/x/installers/agent-main.1.tar.gz"), "{left}");
        assert!(left.contains("Operation not permitted"), "{left}");
    }
}
