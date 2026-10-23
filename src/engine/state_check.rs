//! `enclos state check` and `state repair` (design §11): enclos's records
//! compared with what is on the host. The check changes nothing; the repair
//! fixes what it can show is safe to fix, and names the rest with what a
//! person does about it. Neither ever signals a process.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::FileType;
use std::io::ErrorKind;
use std::path::Path;

use super::Engine;
use super::printable_line;
use super::session::marked_in;
use crate::error::{Error, Result};
use crate::layout::LayoutError;
use crate::lifecycle::members::{find, is_gone};
use crate::lifecycle::process::{Proc, processes};
use crate::lifecycle::programs::{lsof_name, program_files};
use crate::model::audit::{Actor, Outcome};
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
use crate::model::session::SessionId;
use crate::state::{StateError, StateLock};

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
    /// As `lsof` writes their names: see [`lsof_name`].
    programs: BTreeMap<u32, Vec<String>>,
}

impl Host {
    /// Program files first: a process listed there and not by `ps` after is
    /// one that ended between the two, not one that left its session, which
    /// ran before either. With no sandbox, nothing is listed: no process can
    /// be one's.
    fn list(sandboxes: usize) -> Result<Host> {
        if sandboxes == 0 {
            return Ok(Host {
                procs: Vec::new(),
                programs: BTreeMap::new(),
            });
        }
        let programs = program_files()?;
        Ok(Host {
            procs: processes()?,
            programs,
        })
    }
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
    /// an audit entry, failed when a repair failed; returns every finding, as
    /// fixed ([`Remedy::Repairs`]), failed or left. Asks nothing: it changes
    /// only enclos's own records and `policy.toml`, to agree with the host
    /// and the snapshots. Its dry run is `state_check`, which finds the same.
    pub fn state_repair(&self, by: &Actor, only: Option<&SandboxName>) -> Result<Vec<Finding>> {
        self.write_with_outcome(
            by,
            "state repair",
            only.map(ToString::to_string),
            |found: &Vec<Finding>| {
                let count =
                    |want: fn(&Remedy) -> bool| found.iter().filter(|f| want(&f.remedy)).count();
                let fixed = count(|r| matches!(r, Remedy::Repairs(_)));
                let failed = count(|r| matches!(r, Remedy::Failed { .. }));
                let manual = count(|r| matches!(r, Remedy::Manual(_)));
                match (fixed, failed, manual) {
                    (0, 0, 0) => Outcome::ok("nothing to repair"),
                    (fixed, 0, manual) => {
                        Outcome::ok(format!("repaired {fixed}, left {manual} for a person"))
                    }
                    (fixed, failed, manual) => Outcome::failed(format!(
                        "repaired {fixed}, failed to repair {failed}, left {} for a person",
                        failed + manual
                    )),
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
                    let file = self.repair_file(&name, &repairs).err();
                    let records = self.repair_records(lock, &name, &repairs).err();
                    for f in found.iter_mut().filter(|f| mine(f)) {
                        let Remedy::Repairs(repair) = &f.remedy else {
                            continue;
                        };
                        // Each repair is told the error of its own step.
                        let error = match repair.0 {
                            Fix::WritePolicy { .. } => &file,
                            Fix::EndSessions(_) | Fix::RecordStopped => &records,
                        };
                        if let Some(error) = error {
                            f.remedy = Remedy::Failed {
                                repair: repair.clone(),
                                error: printable_line(&error.to_string()),
                            };
                        }
                    }
                }
                Ok(found)
            },
        )
    }

    /// Writes the sandbox's `policy.toml` again, when a repair says so,
    /// from a snapshot: right whatever becomes of its records.
    fn repair_file(&self, name: &SandboxName, repairs: &[&Repair]) -> Result<()> {
        for repair in repairs {
            if let Fix::WritePolicy { text, .. } = &repair.0 {
                self.layout.write_policy(name.as_str(), text)?;
            }
        }
        Ok(())
    }

    /// Records the end of gone sessions and a sandbox stopped, when repairs
    /// say so, in one transaction, after which nothing can fail: a failure
    /// leaves every record as it was. Done whatever became of the file.
    fn repair_records(
        &self,
        lock: &StateLock,
        name: &SandboxName,
        repairs: &[&Repair],
    ) -> Result<()> {
        let mut ended = Vec::new();
        let mut stopped = false;
        for repair in repairs {
            match &repair.0 {
                Fix::EndSessions(ids) => ended.extend(ids),
                Fix::RecordStopped => stopped = true,
                Fix::WritePolicy { .. } => {}
            }
        }
        if ended.is_empty() && !stopped {
            return Ok(());
        }
        let mut record = self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
            name: name.to_string(),
        })?;
        if stopped {
            record.state = SandboxState::Stopped;
        }
        if ended.is_empty() {
            return Ok(self.state.put(lock, &record)?);
        }
        // Listed before the commit, so that nothing after it can fail.
        let sessions = self.state.sessions(name, true)?;
        // Saves the record too, in the same transaction.
        self.state.end_sessions(lock, &ended, &record)?;
        for session in sessions.iter().filter(|s| ended.contains(&s.id)) {
            self.forget_marker(session);
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
        let host = Host::list(records.len())?;
        let mut found = Vec::new();
        for record in &records {
            let name = &record.name;
            let dir = self.layout.sandbox_dir(name.as_str());
            match self.look_at(record, &host, &mut found) {
                Ok(()) => {}
                // What fails for the whole host fails the check, once.
                Err(error) if !about_this_sandbox(&error, &dir) => return Err(error),
                Err(error) => found.push(Finding {
                    subject: Subject::Sandbox(name.clone()),
                    what: format!(
                        "enclos cannot look at it: {}",
                        printable_line(&error.to_string())
                    ),
                    remedy: Remedy::Manual(format!(
                        "fix what keeps enclos from looking, then run `enclos state check {name}` again"
                    )),
                }),
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
                            // The template the active policy is built on,
                            // which `policy.toml` may have changed since the
                            // sandbox was created.
                            None => push(
                                what,
                                Remedy::Manual(format!(
                                    "enclos does not keep the text it came from: write the file yourself (with only `extends = \"{}\"`, it keeps its template alone), then `enclos policy edit {name}`",
                                    self.state.active_policy(name)?.map_or_else(
                                        || record.created_from.clone(),
                                        |(_, snapshot)| snapshot.inputs.template
                                    )
                                )),
                            ),
                        }
                    }
                    Some(kind) if !kind.is_file() => push(
                        format!("its {} is not a file", policy_file.display()),
                        Remedy::Manual(
                            "move what is there away, then run `enclos state check` again"
                                .to_owned(),
                        ),
                    ),
                    Some(_) => {}
                }
            }
        }

        // Gone sessions: recorded open, and nothing of them runs. Markers are
        // only looked for in a folder: one gone or replaced holds none.
        let held = match dir_found.is_some_and(|k| k.is_dir()) {
            true => self.held(name)?,
            false => Default::default(),
        };
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
        let scanned = dir_found.is_some_and(|k| k.is_dir());
        if scanned {
            let real = std::fs::canonicalize(&dir).map_err(|source| LayoutError::Io {
                path: dir.clone(),
                source,
            })?;
            let inside = format!("{}/", lsof_name(&real));
            for (pid, files) in &host.programs {
                let Some(file) = files.iter().find(|f| f.starts_with(&inside)) else {
                    continue;
                };
                if members.contains(pid) || *pid == std::process::id() {
                    continue;
                }
                let Some(listed) = host.procs.iter().find(|p| p.pid == *pid) else {
                    continue;
                };
                let command = format!(", listed as {}", printable_line(&listed.command));
                escaped += 1;
                push(
                    format!(
                        "process {pid} runs {}{command}, and no session of it tracks that process",
                        printable_line(file)
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
        if matches!(record.state, SandboxState::Running) && !live && installed.is_empty() {
            match (scanned, escaped) {
                (true, 0) => push(
                    "it is recorded running, and nothing of it runs".to_owned(),
                    Remedy::Repairs(Repair(Fix::RecordStopped)),
                ),
                (true, _) => {}
                (false, _) => push(
                    "it is recorded running, and no session or service of it runs".to_owned(),
                    Remedy::Manual(format!(
                        "enclos cannot look for processes running from its folder while it is gone or not a folder; `enclos sandbox stop {name}` records it stopped"
                    )),
                ),
            }
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

/// Whether `error` is the sandbox's alone: about files in its folder `dir`,
/// its markers, or a record of its that does not read. What fails for the
/// host, such as the state database itself or the service manager, is not.
fn about_this_sandbox(error: &Error, dir: &Path) -> bool {
    match error {
        Error::Layout(LayoutError::Io { path, .. }) => path.starts_with(dir),
        Error::Markers(_) | Error::State(StateError::Corrupt { .. }) => true,
        _ => false,
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
