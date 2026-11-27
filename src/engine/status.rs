//! `enclos status`: what is on this host, what it costs on disk, and what
//! the user could do about it (issue #29). A read: no lock, no audit
//! entry, and nothing runs in a sandbox, so it works on stopped ones. It
//! may look up each runtime's latest release on the network, once per
//! runtime, and writes only what it keeps of the answer
//! (`runtime-releases.json`, `releases.rs`).
//!
//! Facts come from enclos's own records (trusted), from the service
//! manager, and from the sandbox home, which the sandbox writes. The
//! runtime adapter names paths and lists its agents; every read of the home
//! goes through descriptors that never follow a link (`runtime::home`, ADR
//! 0023), sizes and counts are bounded, and "cannot tell", with why, is an
//! answer.

mod disk;
mod facts;
mod printable;
mod suggestion;
mod view;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::Engine;
use super::releases::Releases;
use super::sandbox::{compile_refused, needs_restart};
use crate::error::{Error, Result};
use crate::lifecycle::listeners::tcp_listeners_of;
use crate::lifecycle::look::Look;
use crate::lifecycle::process::is_same;
use crate::model::Timestamp;
use crate::model::agent::AgentName;
use crate::model::net::Reason;
use crate::model::now;
use crate::model::runtime::{RuntimeKind, RuntimeVersion};
use crate::model::sandbox::{SandboxName, SandboxRecord};
use crate::model::session::{ProcessRef, SessionKind, SessionRecord};
use crate::runtime::{RuntimeAdapter, RuntimeAgentName, adapter};
use disk::disk_usage;
pub use disk::{Disk, human_bytes};
pub(super) use facts::read_provider;
use facts::{exists, newest, read_value};
pub(super) use printable::printable;
pub use printable::printable_line;
use suggestion::REFUSED_DAYS;
pub use suggestion::{IDLE_DAYS, Suggestion, suggest};
pub use view::{
    AgentKind, AgentList, AgentStatus, Fact, LatestRelease, NetworkListener, Presence,
    RuntimeStatus, SandboxStatus, ServiceLine, ServiceState, StatusView, Unlisted,
};

impl Engine {
    /// The overview of every sandbox, or of one. A sandbox enclos cannot
    /// look at is listed with why, and the others still show.
    pub fn status(&self, only: Option<&SandboxName>) -> Result<StatusView> {
        let records = match only {
            Some(name) => vec![self.state.get(name)?.ok_or_else(|| Error::NoSuchSandbox {
                name: name.to_string(),
            })?],
            None => self.state.list()?,
        };
        let now = now();
        let mut sandboxes = Vec::new();
        let mut unlisted = Vec::new();
        let dashboard_services = super::listener::HostServices::default();
        let releases = Releases::looking_up();
        for record in records {
            let name = record.name.clone();
            let runtime = record.runtime.map(adapter);
            let seen = (&dashboard_services, &releases);
            match self.sandbox_status_in(record, runtime.as_deref(), now, seen) {
                Ok(s) => sandboxes.push(s),
                Err(e) => unlisted.push(Unlisted {
                    name,
                    error: e.to_string(),
                }),
            }
        }
        // What could not be kept, where the person running `status` sees it.
        for note in releases.notes() {
            eprintln!("enclos: {note}");
        }
        let suggestions = suggest(&sandboxes, now);
        let pause = self.read_host_pause();
        Ok(StatusView {
            data: self.layout.data().to_owned(),
            bytes: sandboxes.iter().map(|s| s.disk.total).sum(),
            // A sandbox left out is left out of `bytes` too.
            complete: unlisted.is_empty() && sandboxes.iter().all(|s| s.disk.incomplete.is_none()),
            idle_days: IDLE_DAYS,
            pause,
            sandboxes,
            unlisted,
            suggestions,
        })
    }

    #[cfg(test)]
    pub(super) fn sandbox_status(
        &self,
        record: SandboxRecord,
        runtime: Option<&dyn RuntimeAdapter>,
        now: Timestamp,
    ) -> Result<SandboxStatus> {
        let seen = (
            &super::listener::HostServices::default(),
            &Releases::looking_up(),
        );
        self.sandbox_status_in(record, runtime, now, seen)
    }

    /// One sandbox's status. `seen` holds what this `status` already asked
    /// of the host: its services, and each runtime's latest release, looked
    /// up once whatever sandboxes have that runtime.
    fn sandbox_status_in(
        &self,
        record: SandboxRecord,
        runtime: Option<&dyn RuntimeAdapter>,
        now: Timestamp,
        seen: (&super::listener::HostServices, &Releases),
    ) -> Result<SandboxStatus> {
        let (dashboard_services, releases) = seen;
        let name = record.name.clone();
        let dir = self.layout.sandbox_dir(name.as_str());
        let home = self.layout.sandbox_home(name.as_str());
        let active = self.state.active_policy(&name)?.map(|(v, _)| v.version);
        let compiled = self.active_compiled(&record);
        let open = self.state.sessions(&name, true)?;
        let look = self.look_open(&name, &open)?;
        // With what holds each session's marker, its members too (ADR 0030).
        let (gone, running): (Vec<_>, Vec<_>) = open
            .iter()
            .map(|s| look.marked(s))
            .partition(|s| look.is_gone(s));
        let sessions = self.state.sessions(&name, false)?;
        let last_connect = sessions
            .iter()
            .filter(|s| s.kind == SessionKind::Interactive)
            .map(|s| s.started_at)
            .max();
        let last_network = self.state.last_event(&name)?;
        let last_used = last_used(record.created_at, &sessions, last_network);
        let since = now
            .checked_sub(jiff::SignedDuration::from_hours(24 * REFUSED_DAYS))
            .unwrap_or(now);
        let denied: Vec<_> = self
            .state
            .denied(&name)?
            .into_iter()
            .filter(|d| d.last >= since)
            .collect();
        let refused_recently = denied
            .iter()
            .filter(|d| !d.reason.nothing_to_allow())
            .count();
        let unreadable = || {
            denied
                .iter()
                .filter(|d| d.reason == Reason::PolicyUnreadable)
        };
        let policy_unreadable_at = unreadable().map(|d| d.last).max();
        let policy_unreadable_refused = unreadable().map(|d| d.count).sum();
        let services = match self.service_status(&name) {
            Ok(list) => Fact::Known(
                list.into_iter()
                    .map(|(label, status)| ServiceLine::new(&label, status))
                    .collect(),
            ),
            Err(e) => Fact::CannotTell(e.to_string()),
        };

        let agents = runtime
            .map(|rt| self.agent_list(&name, &home, rt))
            .transpose()?;
        // The host does not reach a listener in the sandbox's own network
        // namespace (ADR 0039, ADR 0040), so there is none to look for.
        let own_network = self.holder_of(record.backend).is_some();
        let network_listeners = match own_network {
            true => Fact::NotProvided,
            false => network_listeners(&look, &running),
        };
        let dashboard_command = runtime.and_then(|rt| {
            self.dashboard_of(&record, rt, dashboard_services)
                .ok()
                .map(|_| format!("enclos dashboard {name}"))
        });
        let (disk, agent_bytes) = disk_usage(&dir, &home, runtime, agents.as_ref());
        let agents = agents.map(|mut list| {
            for a in &mut list.agents {
                if let Some(bytes) = agent_bytes.get(&a.name) {
                    a.bytes = bytes.clone();
                }
            }
            list
        });

        let pause = self.read_sandbox_pause(&record);
        Ok(SandboxStatus {
            runtime: match (record.runtime, runtime) {
                (Some(kind), Some(rt)) => {
                    let facts = rt.runtime_facts();
                    let versions = self.versions_of(&name, rt, releases, now);
                    Some(RuntimeStatus {
                        kind,
                        name: kind.display_name(),
                        version: versions.version,
                        latest: versions.latest,
                        outdated: versions.outdated,
                        logged_in: facts.login.map_or(Fact::NotProvided, |f| exists(&home, &f)),
                        installed: facts
                            .install
                            .map_or(Fact::NotProvided, |f| exists(&home, &f)),
                        login: rt.login(),
                    })
                }
                _ => None,
            },
            state: record.state,
            pause,
            created_at: record.created_at,
            services,
            policy_version: active,
            running_sessions: running.len(),
            gone_sessions: gone.len(),
            restart_needed: running
                .iter()
                .any(|s| needs_restart(s, compiled.as_ref().ok().map(PathBuf::as_path))),
            policy_refused: compile_refused(&compiled),
            last_connect,
            last_network,
            last_used,
            refused_recently,
            policy_unreadable_at,
            policy_unreadable_refused,
            agents,
            disk,
            dashboard_command,
            network_listeners,
            name,
        })
    }

    /// The agents of a sandbox: the runtime's built-in one, enclos's
    /// records, and the runtime's own list, or why it could not be read.
    fn agent_list(
        &self,
        name: &SandboxName,
        home: &Path,
        runtime: &dyn RuntimeAdapter,
    ) -> Result<AgentList> {
        let tracked = self.state.agents(name)?;
        let found = runtime.agents_in(home);
        // What the running app bridge last heard each agent's plugin say it
        // is doing: nothing without a bridge database or a bridge that runs,
        // and said when either cannot be read.
        let (activity, activity_unreadable) = bridge_activity(&self.layout.app_store());
        let builtin = runtime.builtin_agent().map(|b| b.runtime_name());
        let mut names: Vec<RuntimeAgentName> = builtin.iter().cloned().collect();
        for n in tracked
            .iter()
            .map(|t| RuntimeAgentName::from(&t.name))
            .chain(found.iter().flatten().cloned())
        {
            if !names.contains(&n) {
                names.push(n);
            }
        }
        let agents = names
            .into_iter()
            .map(|agent| {
                let listed = found.as_ref().map(|f| f.contains(&agent));
                let kind = if Some(&agent) == builtin.as_ref() {
                    AgentKind::Builtin
                } else if tracked
                    .iter()
                    .any(|t| RuntimeAgentName::from(&t.name) == agent)
                {
                    AgentKind::Tracked {
                        in_runtime: match listed {
                            Ok(true) => Presence::Present,
                            Ok(false) => Presence::Gone,
                            Err(_) => Presence::Unknown,
                        },
                    }
                } else if agent.as_str().parse::<AgentName>().is_ok() {
                    AgentKind::Untracked
                } else {
                    AgentKind::Untrackable
                };
                let facts = runtime.agent_facts(&agent);
                let (provider, choose_provider) =
                    read_provider(home, facts.provider.as_ref(), runtime);
                AgentStatus {
                    working: activity
                        .get(&format!("{name}/{}", agent.as_str()))
                        .map(|a| a.kinds())
                        .unwrap_or_default(),
                    provider,
                    choose_provider,
                    kind,
                    last_active: newest(home, &facts.activity),
                    model: facts
                        .model
                        .map_or(Fact::NotProvided, |v| read_value(home, &v, runtime)),
                    // Filled in from the walk.
                    bytes: Fact::NotProvided,
                    name: agent,
                }
            })
            .collect();
        Ok(AgentList {
            agents,
            unreadable: found.err().map(|why| why.to_string()),
            activity_unreadable,
        })
    }
}

/// What each agent (`<sandbox>/<agent>`) is doing, as the app bridge whose
/// database is `store` recorded it, if that bridge runs; and why it could
/// not be read, if it could not. A bridge that stopped or crashed left its
/// last state behind, which says nothing now.
pub(super) fn bridge_activity(
    store: &Path,
) -> (
    std::collections::HashMap<String, enclos_protocol::task::Activity>,
    Option<String>,
) {
    if !store.exists() {
        return Default::default();
    }
    let read = crate::bridge::store::bridge_runs(store).and_then(|runs| match runs {
        true => crate::bridge::store::Store::read_activity(store).map_err(std::io::Error::other),
        false => Ok(Default::default()),
    });
    match read {
        Ok(activity) => (activity, None),
        Err(e) => (Default::default(), Some(e.to_string())),
    }
}

/// A sandbox runtime's version and latest release, as `status` shows them
/// (ADR 0074, proposed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeVersions {
    /// The version installed.
    pub version: Fact<String>,
    pub latest: Fact<LatestRelease>,
    /// Whether `latest` is newer than `version`.
    pub outdated: Fact<bool>,
}

impl Engine {
    /// Sandbox `name`'s versions of `kind`, its runtime, the latest release
    /// as `releases` finds it: for the mobile app's bridge, which lists the
    /// sandboxes without the rest of their status.
    pub fn runtime_versions(
        &self,
        name: &SandboxName,
        kind: RuntimeKind,
        releases: &Releases,
    ) -> RuntimeVersions {
        self.versions_of(name, adapter(kind).as_ref(), releases, now())
    }

    /// The version `rt` reports for sandbox `name`, read the same way
    /// `enclos status` reads it: from the runtime's live home fact when it
    /// provides one, else from `state.db`.
    pub(super) fn current_version(
        &self,
        name: &SandboxName,
        rt: &dyn RuntimeAdapter,
    ) -> Fact<String> {
        let home = self.layout.sandbox_home(name.as_str());
        match rt.runtime_facts().version {
            Some(at) => read_value(&home, &at, rt),
            None => self.reported_version(name, rt),
        }
    }

    fn versions_of(
        &self,
        name: &SandboxName,
        rt: &dyn RuntimeAdapter,
        releases: &Releases,
        now: Timestamp,
    ) -> RuntimeVersions {
        let version = self.current_version(name, rt);
        let latest = releases.of(self, rt, now);
        RuntimeVersions {
            outdated: outdated(&version, &latest),
            version,
            latest,
        }
    }

    /// The version the sandbox's runtime last reported, for a runtime whose
    /// home holds none enclos reads: absent until it reported one, after
    /// an install.
    fn reported_version(&self, name: &SandboxName, runtime: &dyn RuntimeAdapter) -> Fact<String> {
        if runtime.version_command(Path::new("")).is_none() {
            return Fact::NotProvided;
        }
        match self.state.runtime_version(name) {
            Ok(Some((kind, version))) if kind == runtime.kind() => {
                Fact::Known(version.as_str().to_owned())
            }
            Ok(_) => Fact::Absent,
            Err(e) => Fact::CannotTell(e.to_string()),
        }
    }
}

/// Whether `latest` is newer than the version installed.
fn outdated(installed: &Fact<String>, latest: &Fact<LatestRelease>) -> Fact<bool> {
    let (installed, latest) = match (installed, latest) {
        (_, Fact::NotProvided) => return Fact::NotProvided,
        (Fact::Known(installed), Fact::Known(latest)) => (installed, latest),
        (_, Fact::Known(_)) => {
            return Fact::CannotTell("the version installed is not known".into());
        }
        (_, _) => return Fact::CannotTell("the latest release is not known".into()),
    };
    let newer = RuntimeVersion::new(installed)
        .zip(RuntimeVersion::new(&latest.version))
        .and_then(|(installed, latest)| latest.newer_than(&installed));
    match newer {
        Some(newer) => Fact::Known(newer),
        None => Fact::CannotTell(format!(
            "enclos cannot order versions {installed} and {}",
            latest.version
        )),
    }
}

/// The latest of: `created`, a `connect` or service session starting or
/// ending, and `last_network`. The proxy alone does not count as use.
pub(super) fn last_used(
    created: Timestamp,
    sessions: &[SessionRecord],
    last_network: Option<Timestamp>,
) -> Timestamp {
    sessions
        .iter()
        .filter(|s| s.kind != SessionKind::Proxy)
        .flat_map(|s| [Some(s.started_at), s.ended_at])
        .flatten()
        .chain(last_network)
        .fold(created, Timestamp::max)
}

/// Members of the `running` sessions that run in the sandbox (the proxy runs
/// outside it) listening beyond loopback, which the host's network can
/// reach: nothing narrows a sandbox's listener to loopback (ADR 0028). Each
/// pid and address once, a listener on every address (`0.0.0.0` or `[::]`)
/// shown as `*:<port>`. A pid is named only while it is still the member
/// `look` listed, checked after the look at its sockets, so a pid reused
/// meanwhile is not.
fn network_listeners(look: &Look, running: &[SessionRecord]) -> Fact<Vec<NetworkListener>> {
    let mut members: BTreeMap<u32, (ProcessRef, String)> = BTreeMap::new();
    for session in running.iter().filter(|s| s.kind != SessionKind::Proxy) {
        for found in look.members(session) {
            let member = found.member;
            let at = ProcessRef {
                pid: member.pid,
                started: member.started,
            };
            members.insert(member.pid, (at, member.command));
        }
    }
    let pids: Vec<u32> = members.keys().copied().collect();
    let held = match tcp_listeners_of(&pids) {
        Ok(held) => held,
        Err(e) => return Fact::CannotTell(e.to_string()),
    };
    let mut shown: BTreeSet<(u32, String)> = BTreeSet::new();
    for (pid, addr) in held {
        // A v4-mapped address is the IPv4 one (`::ffff:127.0.0.1`).
        let ip = addr.ip().to_canonical();
        if ip.is_loopback() {
            continue;
        }
        let address = match ip.is_unspecified() {
            true => format!("*:{}", addr.port()),
            false => addr.to_string(),
        };
        shown.insert((pid, address));
    }
    let mut found = Vec::new();
    for (pid, address) in shown {
        let Some((at, command)) = members.get(&pid) else {
            return Fact::CannotTell(format!(
                "a look answered for pid {pid}, which was not asked"
            ));
        };
        match is_same(at) {
            Ok(true) => found.push(NetworkListener {
                pid,
                command: printable(command),
                address,
            }),
            // Gone, or another process now: not the member's listener.
            Ok(false) => {}
            Err(e) => return Fact::CannotTell(e.to_string()),
        }
    }
    Fact::Known(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::marker::spawn_unmarked;

    #[test]
    fn outdated_is_known_only_when_both_versions_are_known_and_ordered() {
        let installed = |v: &str| Fact::Known(v.to_owned());
        let latest = |v: &str| {
            Fact::Known(LatestRelease {
                version: v.to_owned(),
                checked: false,
            })
        };
        assert_eq!(
            outdated(&installed("0.23.1"), &latest("0.23.2")),
            Fact::Known(true)
        );
        assert_eq!(
            outdated(&installed("0.23.2"), &latest("0.23.2")),
            Fact::Known(false)
        );
        assert_eq!(
            outdated(&installed("0.24.0"), &latest("0.23.2")),
            Fact::Known(false)
        );
        assert_eq!(
            outdated(&installed("2026.11.5-beta.1"), &latest("2026.11.5-beta.1")),
            Fact::Known(false)
        );
        assert_eq!(
            outdated(&installed("2026.11.5-beta.1"), &latest("2026.11.5")),
            Fact::CannotTell("enclos cannot order versions 2026.11.5-beta.1 and 2026.11.5".into())
        );
        assert_eq!(
            outdated(&Fact::Absent, &latest("0.23.2")),
            Fact::CannotTell("the version installed is not known".into())
        );
        assert_eq!(
            outdated(&installed("0.23.1"), &Fact::CannotTell("offline".into())),
            Fact::CannotTell("the latest release is not known".into())
        );
        assert_eq!(
            outdated(&installed("0.23.1"), &Fact::NotProvided),
            Fact::NotProvided
        );
        // What the sandbox wrote in its home is not a version: no order.
        assert!(matches!(
            outdated(&installed("0.23\u{1b}[31m"), &latest("0.23.2")),
            Fact::CannotTell(_)
        ));
    }

    /// A running session of `kind` whose root is `root`.
    fn session_of(kind: SessionKind, root: crate::model::session::ProcessRef) -> SessionRecord {
        SessionRecord {
            id: crate::model::session::SessionId(1),
            sandbox: "home".parse().unwrap(),
            kind,
            service: None,
            version: 1,
            snapshot: crate::model::policy::SnapshotId("s".into()),
            compiled: None,
            root,
            pgid: None,
            cgroup: None,
            tracked: Vec::new(),
            started_at: now(),
            ended_at: None,
        }
    }

    /// Listens on every address and on loopback, and says both ports. Perl,
    /// which macOS signs, so the firewall asks nothing of whoever runs the
    /// tests.
    fn listens() -> String {
        format!(
            "{}for my $a (INADDR_ANY, INADDR_LOOPBACK) {{ my $s = listener($a); push @s, $s; print((sockaddr_in(getsockname($s)))[0], qq(\\n)); }} $| = 1; STDOUT->flush; sleep 30",
            crate::test_ports::perl_listener()
        )
    }

    #[test]
    fn listeners_beyond_loopback_are_named_and_loopback_ones_are_not() {
        use std::io::BufRead;
        let mut child = spawn_unmarked(
            std::process::Command::new("/usr/bin/perl")
                .args(["-e", &listens()])
                .stdout(std::process::Stdio::piped()),
        )
        .unwrap();
        let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let mut port = || lines.next().unwrap().unwrap();
        let (wide, narrow) = (port(), port());
        let root = crate::lifecycle::process::reference_of_child(&child).unwrap();
        let procs = crate::lifecycle::process::processes().unwrap();
        let running = [session_of(SessionKind::Interactive, root.clone())];
        let hierarchy = crate::lifecycle::cgroup::Hierarchy::host();
        let look = Look::markers_unseen(&procs, &hierarchy, &running).unwrap();
        let found = network_listeners(&look, &running);
        // The proxy runs on the host, not in the sandbox: never counted.
        let proxy = network_listeners(&look, &[session_of(SessionKind::Proxy, root)]);
        let _ = child.kill();
        let _ = child.wait();
        let Fact::Known(found) = found else {
            panic!("could not look: {found:?}");
        };
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].pid, child.id());
        assert_eq!(found[0].address, format!("*:{wide}"));
        assert!(found[0].command.ends_with("perl"), "{found:?}");
        assert!(
            !found
                .iter()
                .any(|l| l.address.ends_with(&format!(":{narrow}")))
        );
        assert_eq!(proxy, Fact::Known(Vec::new()));
    }
}
