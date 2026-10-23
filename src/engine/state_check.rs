//! `enclos state check` and `state repair` (design §11): enclos's records
//! compared with what is on the host. The check changes nothing; the repair
//! fixes what it can show is safe to fix, and names the rest with what a
//! person does about it. Neither ever signals a process.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::FileType;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::Engine;
use super::printable_line;
use super::session::marked_in;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::lifecycle::members::{find, is_gone};
use crate::lifecycle::process::{Proc, processes};
use crate::lifecycle::programs::program_files;
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
use crate::model::session::SessionId;
use crate::state::StateLock;

/// Something enclos's records say that the host does not, or the reverse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub subject: Subject,
    pub what: String,
    pub remedy: Remedy,
}

/// What a finding is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    Sandbox(SandboxName),
    /// A folder in the sandboxes' folder that no record names, by its name
    /// escaped for a terminal.
    Folder(String),
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subject::Sandbox(name) => write!(f, "{name}"),
            Subject::Folder(folder) => f.write_str(folder),
        }
    }
}

/// What is done about a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remedy {
    /// What `state repair` does.
    Repairs(Repair),
    /// What `state repair` tried and could not do, and why: no record of
    /// the sandbox was changed.
    Failed { repair: Repair, error: String },
    /// What a person does: `state repair` leaves it.
    Manual(String),
}

impl Remedy {
    /// Whether a person still has something to do about it.
    pub fn is_left(&self) -> bool {
        !matches!(self, Remedy::Repairs(_))
    }
}

/// A change `state repair` makes; it reads as what it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repair(Fix);

#[derive(Debug, Clone, PartialEq, Eq)]
enum Fix {
    /// Record the end of these gone sessions.
    EndSessions(Vec<SessionId>),
    /// Record stopped a sandbox recorded running of which nothing runs.
    RecordStopped,
    /// Write `policy.toml` again with the text its latest snapshot, pending
    /// or active, was resolved from.
    WritePolicy { text: String, pending: bool },
}

impl fmt::Display for Repair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Fix::EndSessions(ids) if ids.len() == 1 => f.write_str("record its end"),
            Fix::EndSessions(_) => f.write_str("record their end"),
            Fix::RecordStopped => f.write_str("record it stopped"),
            Fix::WritePolicy { pending, .. } => write!(
                f,
                "write policy.toml again from the text its {} policy was resolved from",
                if *pending { "pending" } else { "active" }
            ),
        }
    }
}

/// What the host runs, listed once for every sandbox looked at.
struct Host {
    procs: Vec<Proc>,
    programs: BTreeMap<u32, Vec<PathBuf>>,
}

impl Engine {
    /// What differs between enclos's records and the host, for `only` or
    /// every sandbox; changes nothing. A sandbox enclos cannot look at is a
    /// finding, so that one does not hide the others.
    pub fn state_check(&self, only: Option<&SandboxName>) -> Result<Vec<Finding>> {
        // Under the lock: a session starts under it, so a program started
        // and not yet recorded is not taken for one that left its session.
        let _lock = self.state.lock()?;
        self.look(only)
    }

    /// Fixes what `state_check` finds that it can fix, under the lock, with
    /// an audit entry; returns every finding, as fixed ([`Remedy::Repairs`]),
    /// failed or left. Asks nothing: it changes only enclos's own records
    /// and `policy.toml`, to agree with the host and the snapshots.
    pub fn state_repair(
        &self,
        by: &Actor,
        only: Option<&SandboxName>,
        confirm: Confirm,
    ) -> Result<Planned<Vec<Finding>>> {
        if confirm == Confirm::DryRun {
            let changes = self
                .state_check(only)?
                .iter()
                .filter_map(|f| match &f.remedy {
                    Remedy::Repairs(repair) => Some(format!("{repair} (sandbox {})", f.subject)),
                    _ => None,
                })
                .collect();
            return Ok(Planned::DryRun(Plan {
                changes,
                ..Plan::default()
            }));
        }
        let found = self.write(
            by,
            "state repair",
            only.map(ToString::to_string),
            |found: &Vec<Finding>| {
                let count =
                    |want: fn(&Remedy) -> bool| found.iter().filter(|f| want(&f.remedy)).count();
                let fixed = count(|r| matches!(r, Remedy::Repairs(_)));
                let failed = count(|r| matches!(r, Remedy::Failed { .. }));
                let left = count(|r| matches!(r, Remedy::Manual(_)));
                match (fixed, failed, left) {
                    (0, 0, 0) => "nothing to repair".to_owned(),
                    (fixed, 0, left) => format!("repaired {fixed}, left {left} for a person"),
                    (fixed, failed, left) => format!(
                        "repaired {fixed}, failed to repair {failed}, left {left} for a person"
                    ),
                }
            },
            |lock| {
                // Looked at again under the lock: what was found before may
                // have changed meanwhile.
                let mut found = self.look(only)?;
                let names: BTreeSet<SandboxName> = found
                    .iter()
                    .filter_map(|f| match (&f.subject, &f.remedy) {
                        (Subject::Sandbox(name), Remedy::Repairs(_)) => Some(name.clone()),
                        _ => None,
                    })
                    .collect();
                for name in names {
                    let mine = |f: &Finding| f.subject == Subject::Sandbox(name.clone());
                    let repairs: Vec<&Repair> = found
                        .iter()
                        .filter(|f| mine(f))
                        .filter_map(|f| match &f.remedy {
                            Remedy::Repairs(repair) => Some(repair),
                            _ => None,
                        })
                        .collect();
                    if let Err(error) = self.repair(lock, &name, &repairs) {
                        let error = error.to_string();
                        for f in found.iter_mut().filter(|f| mine(f)) {
                            if let Remedy::Repairs(repair) = &f.remedy {
                                f.remedy = Remedy::Failed {
                                    repair: repair.clone(),
                                    error: error.clone(),
                                };
                            }
                        }
                    }
                }
                Ok(found)
            },
        )?;
        Ok(Planned::Done(found))
    }

    /// Makes one sandbox's repairs. The file first: written from a snapshot,
    /// it is right whatever follows, and a failure to write it then changes
    /// no record.
    fn repair(&self, lock: &StateLock, name: &SandboxName, repairs: &[&Repair]) -> Result<()> {
        for repair in repairs {
            if let Fix::WritePolicy { text, .. } = &repair.0 {
                self.layout.write_policy(name.as_str(), text)?;
            }
        }
        let mut record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        let mut ended = Vec::new();
        let mut stopped = false;
        for repair in repairs {
            match &repair.0 {
                Fix::EndSessions(ids) => ended.extend(ids),
                Fix::RecordStopped => stopped = true,
                Fix::WritePolicy { .. } => {}
            }
        }
        if stopped {
            record.state = SandboxState::Stopped;
        }
        if !ended.is_empty() {
            // Saves the record too, in the same transaction.
            self.state.end_sessions(lock, &ended, &record)?;
            for session in self.state.sessions(name, false)? {
                if ended.contains(&session.id) {
                    self.forget_marker(&session);
                }
            }
        } else if stopped {
            self.state.put(lock, &record)?;
        }
        Ok(())
    }

    fn look(&self, only: Option<&SandboxName>) -> Result<Vec<Finding>> {
        let records: Vec<SandboxRecord> = match only {
            Some(name) => vec![self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                name: name.to_string(),
            })?],
            None => self.state.list()?,
        };
        let host = Host {
            procs: processes()?,
            programs: program_files()?,
        };
        let mut found = Vec::new();
        for record in &records {
            let name = &record.name;
            if let Err(error) = self.look_at(record, &host, &mut found) {
                found.push(Finding {
                    subject: Subject::Sandbox(name.clone()),
                    what: format!("enclos cannot look at it: {error}"),
                    remedy: Remedy::Manual(format!(
                        "fix what keeps enclos from looking, then run `enclos state check {name}` again"
                    )),
                });
            }
        }
        if only.is_none() {
            self.look_for_folders(&records, &mut found)?;
        }
        Ok(found)
    }

    fn look_at(&self, record: &SandboxRecord, host: &Host, found: &mut Vec<Finding>) -> Result<()> {
        let name = &record.name;
        let mut push = |what: String, remedy: Remedy| {
            found.push(Finding {
                subject: Subject::Sandbox(name.clone()),
                what,
                remedy,
            });
        };
        let dir = self.layout.sandbox_dir(name.as_str());
        let home = self.layout.sandbox_home(name.as_str());
        let policy_file = self.layout.policy_file(name.as_str());
        let dir_found = found_at(&dir)?;
        match dir_found {
            None => push(
                format!("its folder {} is gone", dir.display()),
                Remedy::Manual(format!(
                    "`enclos sandbox rm {name}` removes its record, its policy history and its secrets, whose values are kept nowhere else; stop its services first with `enclos sandbox stop {name}` if they are installed"
                )),
            ),
            Some(kind) if !kind.is_dir() => push(
                format!("its folder {} is not a folder", dir.display()),
                Remedy::Manual("move what is there away, and look at what it is".to_owned()),
            ),
            Some(_) => {
                match found_at(&home)? {
                    None => push(
                        format!("its home {} is gone, with what the sandbox kept in it", home.display()),
                        Remedy::Manual(format!(
                            "`mkdir {}` makes it again, empty; sessions refuse to start until it is a folder",
                            home.display()
                        )),
                    ),
                    Some(kind) if !kind.is_dir() => push(
                        format!("its home {} is not a folder", home.display()),
                        Remedy::Manual(
                            "move what is there away and make the folder again; sessions refuse to start until then"
                                .to_owned(),
                        ),
                    ),
                    Some(_) => {}
                }
                match found_at(&policy_file)? {
                    None => {
                        let what = format!("its {} is gone", policy_file.display());
                        match self.latest_policy_text(name)? {
                            Some((text, pending)) => push(
                                what,
                                Remedy::Repairs(Repair(Fix::WritePolicy { text, pending })),
                            ),
                            None => push(
                                what,
                                Remedy::Manual(format!(
                                    "enclos does not keep the text it came from: write the file yourself (with only `extends = \"{}\"`, it keeps its template alone), then `enclos policy edit {name}`",
                                    record.template
                                )),
                            ),
                        }
                    }
                    Some(kind) if !kind.is_file() => push(
                        format!("its {} is not a file", policy_file.display()),
                        Remedy::Manual(
                            "move what is there away; `enclos state repair` then writes the file again"
                                .to_owned(),
                        ),
                    ),
                    Some(_) => {}
                }
            }
        }

        // Gone sessions: recorded open, and nothing of them runs.
        let held = self.held(name)?;
        let open = self.state.sessions(name, true)?;
        let mut gone = Vec::new();
        let mut members: BTreeSet<u32> = BTreeSet::new();
        for session in &open {
            let tracked = marked_in(session, &session.tracked, &host.procs, &held);
            let mut marked = session.clone();
            marked.tracked = tracked.clone();
            if is_gone(&host.procs, &marked) {
                gone.push(session.id);
            } else {
                members.extend(
                    find(&host.procs, session, &tracked)
                        .iter()
                        .map(|f| f.member.pid),
                );
            }
        }
        if !gone.is_empty() {
            let ids: Vec<String> = gone.iter().map(ToString::to_string).collect();
            let what = match ids.as_slice() {
                [id] => format!("session {id} is gone, and recorded open"),
                ids => format!("sessions {} are gone, and recorded open", ids.join(", ")),
            };
            push(
                what,
                Remedy::Repairs(Repair(Fix::EndSessions(gone.clone()))),
            );
        }

        // A process running a program file from the sandbox's folder that no
        // session of it tracks, such as one that left its session (design
        // §8, known gaps). Named, never stopped: enclos cannot show it is
        // the sandbox's.
        let mut escaped = 0;
        if dir_found.is_some_and(|k| k.is_dir()) {
            let real = std::fs::canonicalize(&dir).map_err(|source| LayoutError::Io {
                path: dir.clone(),
                source,
            })?;
            for (pid, files) in &host.programs {
                let Some(file) = files.iter().find(|f| f.starts_with(&real)) else {
                    continue;
                };
                if members.contains(pid) || *pid == std::process::id() {
                    continue;
                }
                let command = host
                    .procs
                    .iter()
                    .find(|p| p.pid == *pid)
                    .map_or_else(String::new, |p| {
                        format!(", listed as {}", printable_line(&p.command))
                    });
                escaped += 1;
                push(
                    format!(
                        "process {pid} runs {}{command}, and no session of it tracks that process",
                        printable_line(&file.display().to_string())
                    ),
                    Remedy::Manual(format!(
                        "enclos stops only what it shows is a sandbox's: look at it (`ps -p {pid}`), and stop it yourself if it is"
                    )),
                );
            }
        }
        // Services: some installed and others not, as after one's launchd
        // job was removed by hand; one installed that enclos no longer runs;
        // installed while not recorded running.
        let installed = self.installed_labels(name)?;
        let expected = self.service_labels(name)?;
        let missing: Vec<String> = expected
            .iter()
            .filter(|l| !installed.contains(l))
            .map(ToString::to_string)
            .collect();
        if installed.iter().any(|l| expected.contains(l)) && !missing.is_empty() {
            let what = match missing.as_slice() {
                [one] => format!(
                    "its service {one} is not installed while its others are, as when its launchd job was removed by hand"
                ),
                more => format!(
                    "its services {} are not installed while its others are, as when their launchd jobs were removed by hand",
                    more.join(", ")
                ),
            };
            push(
                what,
                Remedy::Manual(format!(
                    "`enclos sandbox stop {name}`, then `enclos sandbox start {name}`, installs every service again"
                )),
            );
        }
        let stale: Vec<String> = installed
            .iter()
            .filter(|l| !expected.contains(l))
            .map(ToString::to_string)
            .collect();
        if !stale.is_empty() {
            push(
                format!(
                    "service {} is installed, and enclos no longer runs it",
                    stale.join(", ")
                ),
                Remedy::Manual(format!(
                    "`enclos sandbox stop {name}` removes it, with its other services"
                )),
            );
        }
        if !installed.is_empty() && !matches!(record.state, SandboxState::Running) {
            push(
                format!(
                    "its services are installed while it is recorded {}",
                    state_word(&record.state)
                ),
                Remedy::Manual(format!(
                    "`enclos sandbox start {name}` records it running, or `enclos sandbox stop {name}` removes them"
                )),
            );
        }
        let live = open.len() > gone.len();
        // A process found running from its folder keeps it from being
        // recorded stopped: something of it may still run.
        if matches!(record.state, SandboxState::Running)
            && !live
            && installed.is_empty()
            && escaped == 0
        {
            push(
                "it is recorded running, and nothing of it runs".to_owned(),
                Remedy::Repairs(Repair(Fix::RecordStopped)),
            );
        }

        Ok(())
    }

    /// The text `policy.toml` holds for the sandbox's latest snapshot, its
    /// pending one if a change waits, and whether it is pending; none when
    /// the snapshot does not keep the text it was resolved from.
    fn latest_policy_text(&self, name: &SandboxName) -> Result<Option<(String, bool)>> {
        if let Some((_, snapshot)) = self.state.pending_policy(name)? {
            return Ok(snapshot.overrides_text().map(|t| (t.to_owned(), true)));
        }
        Ok(self
            .state
            .active_policy(name)?
            .and_then(|(_, snapshot)| snapshot.overrides_text().map(|t| (t.to_owned(), false))))
    }

    /// Folders in the sandboxes' folder that no record names: left by a
    /// crash during `sandbox create`, or kept by `sandbox rm --keep-data`.
    fn look_for_folders(&self, records: &[SandboxRecord], found: &mut Vec<Finding>) -> Result<()> {
        let dir = self.layout.sandboxes_dir();
        let io = |source| {
            Error::Layout(LayoutError::Io {
                path: dir.clone(),
                source,
            })
        };
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(io(e)),
        };
        for entry in entries {
            let entry = entry.map_err(io)?;
            if !entry.file_type().map_err(io)?.is_dir() {
                continue;
            }
            let folder = entry.file_name().to_string_lossy().into_owned();
            if records.iter().any(|r| r.name.as_str() == folder) {
                continue;
            }
            let shown = printable_line(&folder);
            let remedy = match folder.parse::<SandboxName>() {
                Ok(name) => format!(
                    "`enclos sandbox create {name}` takes it up again, keeping its home; or remove it yourself"
                ),
                Err(_) => "its name is not a sandbox's: remove it yourself".to_owned(),
            };
            found.push(Finding {
                subject: Subject::Folder(shown),
                what: format!(
                    "folder {} has no record",
                    printable_line(&entry.path().display().to_string())
                ),
                remedy: Remedy::Manual(remedy),
            });
        }
        Ok(())
    }
}

/// What is at `path`, a final link not followed; none when nothing is. Only
/// "not found" is none: a path enclos cannot look at is an error.
fn found_at(path: &Path) -> Result<Option<FileType>> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(meta.file_type())),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(source) => Err(Error::Layout(LayoutError::Io {
            path: path.to_owned(),
            source,
        })),
    }
}

fn state_word(state: &SandboxState) -> &'static str {
    match state {
        SandboxState::Created => "created",
        SandboxState::Running => "running",
        SandboxState::Stopped => "stopped",
        SandboxState::Failed { .. } => "failed",
    }
}
