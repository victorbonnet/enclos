//! `enclos state check` and `state repair` (design §11, acceptance step 8):
//! enclos's records compared with what is on the host. The check changes
//! nothing; the repair fixes what it can show is safe to fix, and names the
//! rest with what a person does about it. Neither ever signals a process:
//! one enclos cannot show is a sandbox's member is only named.

use std::collections::BTreeSet;

use super::Engine;
use super::session::marked_in;
use crate::error::Result;
use crate::lifecycle::members::{find, is_gone};
use crate::lifecycle::process::processes;
use crate::model::audit::Actor;
use crate::model::plan::{Confirm, Plan, Planned};
use crate::model::sandbox::{SandboxName, SandboxRecord, SandboxState};
use crate::model::session::SessionId;

/// Something enclos's records say that the host does not, or the reverse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The sandbox it is about, or the folder name of one with no record.
    pub sandbox: String,
    pub what: String,
    pub remedy: Remedy,
}

/// What is done about a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remedy {
    /// What `state repair` does.
    Repairs(String),
    /// What a person does: `state repair` leaves it.
    Manual(String),
}

/// What `state repair` changes for one sandbox.
#[derive(Debug, Default)]
struct Fixes {
    ended: Vec<SessionId>,
    stopped: bool,
    policy_text: Option<String>,
}

impl Engine {
    /// What differs between enclos's records and the host, for `only` or
    /// every sandbox; changes nothing.
    pub fn state_check(&self, only: Option<&SandboxName>) -> Result<Vec<Finding>> {
        Ok(self.look(only)?.into_iter().map(|(f, _)| f).collect())
    }

    /// Fixes what `state_check` finds that it can fix, under the lock, with
    /// an audit entry; returns every finding, those fixed with
    /// [`Remedy::Repairs`] and those left with [`Remedy::Manual`].
    pub fn state_repair(
        &self,
        by: &Actor,
        only: Option<&SandboxName>,
        confirm: Confirm,
    ) -> Result<Planned<Vec<Finding>>> {
        if confirm == Confirm::DryRun {
            let findings = self.state_check(only)?;
            return Ok(Planned::DryRun(Plan {
                changes: findings
                    .iter()
                    .filter_map(|f| match &f.remedy {
                        Remedy::Repairs(what) => Some(format!("{what} (sandbox {})", f.sandbox)),
                        Remedy::Manual(_) => None,
                    })
                    .collect(),
                ..Plan::default()
            }));
        }
        let findings = self.write(
            by,
            "state repair",
            only.map(ToString::to_string),
            |found: &Vec<Finding>| {
                let fixed = found
                    .iter()
                    .filter(|f| matches!(f.remedy, Remedy::Repairs(_)))
                    .count();
                let left = found.len() - fixed;
                match (fixed, left) {
                    (0, 0) => "nothing to repair".to_owned(),
                    (fixed, left) => format!("repaired {fixed}, left {left} for a person"),
                }
            },
            |lock| {
                // Looked at again under the lock: what was found before may
                // have changed meanwhile.
                let found = self.look(only)?;
                let mut by_sandbox: Vec<(SandboxRecord, Fixes)> = Vec::new();
                for (_, fix) in &found {
                    let Some((record, fix)) = fix else { continue };
                    let at = match by_sandbox.iter().position(|(r, _)| r.name == record.name) {
                        Some(at) => at,
                        None => {
                            by_sandbox.push((record.clone(), Fixes::default()));
                            by_sandbox.len() - 1
                        }
                    };
                    let fixes = &mut by_sandbox[at].1;
                    match fix {
                        Fix::End(ids) => fixes.ended.extend(ids),
                        Fix::Stopped => fixes.stopped = true,
                        Fix::PolicyText(text) => fixes.policy_text = Some(text.clone()),
                    }
                }
                for (record, fixes) in by_sandbox {
                    let mut record = record;
                    if fixes.stopped {
                        record.state = SandboxState::Stopped;
                    }
                    if !fixes.ended.is_empty() {
                        self.state.end_sessions(lock, &fixes.ended, &record)?;
                    } else if fixes.stopped {
                        self.state.put(lock, &record)?;
                    }
                    if let Some(text) = fixes.policy_text {
                        let file = self.layout.policy_file(record.name.as_str());
                        std::fs::write(&file, text).map_err(|source| {
                            crate::layout::LayoutError::Io { path: file, source }
                        })?;
                    }
                }
                Ok(found.into_iter().map(|(f, _)| f).collect())
            },
        )?;
        Ok(Planned::Done(findings))
    }

    /// Each finding, with the fix `state repair` makes for it, if any.
    fn look(&self, only: Option<&SandboxName>) -> Result<Vec<Looked>> {
        let records: Vec<SandboxRecord> =
            match only {
                Some(name) => vec![self.state.get(name)?.ok_or_else(|| {
                    crate::error::Error::NoSuchSandbox {
                        name: name.to_string(),
                    }
                })?],
                None => self.state.list()?,
            };
        let procs = processes()?;
        let mut found = Vec::new();
        for record in &records {
            self.look_at(record, &procs, &mut found)?;
        }
        if only.is_none() {
            self.look_for_folders(&records, &mut found);
        }
        Ok(found)
    }

    fn look_at(
        &self,
        record: &SandboxRecord,
        procs: &[crate::lifecycle::process::Proc],
        found: &mut Vec<Looked>,
    ) -> Result<()> {
        let name = &record.name;
        let finding = |what: String, remedy: Remedy| Finding {
            sandbox: name.to_string(),
            what,
            remedy,
        };
        let dir = self.layout.sandbox_dir(name.as_str());
        let home = self.layout.sandbox_home(name.as_str());
        if !dir.is_dir() {
            found.push((
                finding(
                    format!("its folder {} is gone", dir.display()),
                    Remedy::Manual(format!(
                        "`enclos sandbox rm {name} --keep-data` removes its record; nothing of it is left to keep"
                    )),
                ),
                None,
            ));
            return Ok(());
        }
        if !home.is_dir() {
            found.push((
                finding(
                    format!("its home {} is gone", home.display()),
                    Remedy::Manual(format!(
                        "`enclos sandbox rm {name}`, then `enclos sandbox create {name}` makes it again, empty"
                    )),
                ),
                None,
            ));
        }
        let policy_file = self.layout.policy_file(name.as_str());
        if !policy_file.is_file() {
            let text = self
                .state
                .active_policy(name)?
                .and_then(|(_, s)| s.overrides_text().map(str::to_owned));
            found.push(match text {
                Some(text) => (
                    finding(
                        format!("its {} is gone", policy_file.display()),
                        Remedy::Repairs(
                            "write policy.toml again from the policy in force".to_owned(),
                        ),
                    ),
                    Some((record.clone(), Fix::PolicyText(text))),
                ),
                None => (
                    finding(
                        format!("its {} is gone", policy_file.display()),
                        Remedy::Manual(format!(
                            "the policy in force does not keep the text it came from: write it again with `enclos policy edit {name}`"
                        )),
                    ),
                    None,
                ),
            });
        }

        // Sessions recorded open of which nothing runs.
        let held = self.held(name)?;
        let open = self.state.sessions(name, true)?;
        let mut gone = Vec::new();
        let mut members: BTreeSet<u32> = BTreeSet::new();
        for session in &open {
            let tracked = marked_in(session, &session.tracked, procs, &held);
            let mut marked = session.clone();
            marked.tracked = tracked.clone();
            match is_gone(procs, &marked) {
                true => gone.push(session.id),
                false => {
                    members.extend(find(procs, session, &tracked).iter().map(|f| f.member.pid))
                }
            }
        }
        if !gone.is_empty() {
            let ids: Vec<String> = gone.iter().map(ToString::to_string).collect();
            found.push((
                finding(
                    format!(
                        "sessions {} are recorded open, and nothing of them runs",
                        ids.join(", ")
                    ),
                    Remedy::Repairs("record their end".to_owned()),
                ),
                Some((record.clone(), Fix::End(gone.clone()))),
            ));
        }

        // Services: some installed and others not, as after one's job was
        // removed by hand; installed while recorded stopped.
        let installed = self.installed_labels(name)?;
        let expected = self.service_labels(name)?;
        let missing: Vec<String> = expected
            .iter()
            .filter(|l| !installed.contains(l))
            .map(ToString::to_string)
            .collect();
        if !installed.is_empty() && !missing.is_empty() {
            found.push((
                finding(
                    format!(
                        "service {} is not installed while its others are, as when its job was removed by hand",
                        missing.join(", ")
                    ),
                    Remedy::Manual(format!(
                        "`enclos sandbox start {name}` installs every service again"
                    )),
                ),
                None,
            ));
        }
        let live = open.len() > gone.len();
        if !installed.is_empty() && !matches!(record.state, SandboxState::Running) {
            found.push((
                finding(
                    format!(
                        "its services are installed while it is recorded {}",
                        state_word(&record.state)
                    ),
                    Remedy::Manual(format!(
                        "`enclos sandbox start {name}` records it running, or `enclos sandbox stop {name}` removes them"
                    )),
                ),
                None,
            ));
        }
        if matches!(record.state, SandboxState::Running) && !live && installed.is_empty() {
            found.push((
                finding(
                    "it is recorded running, and nothing of it runs".to_owned(),
                    Remedy::Repairs("record it stopped".to_owned()),
                ),
                Some((record.clone(), Fix::Stopped)),
            ));
        }

        // A program of the sandbox's that no session tracks: one that left
        // its session (design §8, known gaps). Named, never stopped: enclos
        // cannot show it is the sandbox's.
        for p in procs {
            let from_here = std::path::Path::new(&p.command).starts_with(&dir);
            if from_here && !members.contains(&p.pid) {
                found.push((
                    finding(
                        format!(
                            "process {} ({}) runs a program from its folder, and no session of it tracks that process",
                            p.pid,
                            super::printable_line(&p.command)
                        ),
                        Remedy::Manual(format!(
                            "enclos stops only what it shows is a sandbox's: look at it (`ps -p {}`), and stop it yourself if it is",
                            p.pid
                        )),
                    ),
                    None,
                ));
            }
        }
        Ok(())
    }

    /// Folders in the sandboxes' folder that no record names: left by a
    /// crash during `sandbox create`, or kept by `sandbox rm --keep-data`.
    fn look_for_folders(&self, records: &[SandboxRecord], found: &mut Vec<Looked>) {
        let Ok(entries) = std::fs::read_dir(self.layout.sandboxes_dir()) else {
            return;
        };
        for entry in entries.flatten() {
            let folder = entry.file_name().to_string_lossy().into_owned();
            if entry.path().is_dir() && !records.iter().any(|r| r.name.as_str() == folder) {
                found.push((
                    Finding {
                        sandbox: super::printable_line(&folder),
                        what: format!("folder {} has no record", entry.path().display()),
                        remedy: Remedy::Manual(format!(
                            "`enclos sandbox create {folder}` takes it up again, keeping its home; or remove it yourself"
                        )),
                    },
                    None,
                ));
            }
        }
    }
}

/// A finding, with the fix `state repair` makes for it, if any.
type Looked = (Finding, Option<(SandboxRecord, Fix)>);

/// What `state repair` changes for a finding.
enum Fix {
    End(Vec<SessionId>),
    Stopped,
    PolicyText(String),
}

fn state_word(state: &SandboxState) -> &'static str {
    match state {
        SandboxState::Created => "created",
        SandboxState::Running => "running",
        SandboxState::Stopped => "stopped",
        SandboxState::Failed { .. } => "failed",
    }
}
