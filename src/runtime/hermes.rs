//! The Hermes Agent adapter (Nous Research), from the milestone 1 prototype
//! (issue #5): installed per sandbox with Hermes's own installer (ADR 0020),
//! meant to be logged in with a ChatGPT subscription through Hermes's
//! device-code flow, each agent a Hermes profile under `~/.hermes/profiles`,
//! all sharing the sandbox's one Hermes login (`~/.hermes/auth.json`), as
//! the prototype used them (design §14: to verify in this build).

use std::ffi::OsString;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;

use super::{
    AgentFacts, DiskPart, HomeFile, Installer, NotRead, RuntimeAdapter, RuntimeAgentName,
    RuntimeFacts, RuntimeService, SandboxCommand, ServiceName, Unreadable, ValueAt,
};
use crate::model::agent::AgentName;
use crate::model::runtime::RuntimeKind;

pub struct Hermes;

/// The installer the official docs and README point to. The script is
/// pinned: a changed one is refused until enclos is updated to it. The Hermes
/// version it installs is not: it is whatever the stable channel serves at
/// install time.
pub const INSTALLER_URL: &str = "https://hermes-agent.nousresearch.com/install.sh";
pub const INSTALLER_SHA256: &str =
    "20f44240ebada354a468104a6a6724d037afcb8883d4d09ddeb4815622c52d8b";

/// `hermes`, as the installer puts it on the sandbox's PATH.
const HERMES: &str = "hermes";
const GATEWAY: ServiceName = ServiceName::new("gateway");

/// Hermes's built-in profile, the root of its home.
const DEFAULT_PROFILE: &str = "default";

/// The files that make a folder under `~/.hermes/profiles/` a profile, as
/// Hermes decides it: `_PROFILE_IDENTITY_MARKERS` in `hermes_constants.py`,
/// read in Hermes 0.22.2. A Hermes change here needs the adapter updated
/// (design §14).
const PROFILE_MARKERS: [&str; 6] = [
    "config.yaml",
    ".env",
    "SOUL.md",
    "profile.yaml",
    "auth.json",
    "state.db",
];

/// At most this many entries of `~/.hermes/profiles/` are read; more means
/// "cannot tell", never a partial list.
const MAX_ENTRIES: usize = 512;

const PROFILES: &str = "~/.hermes/profiles";
const DELETED: &str = "~/.hermes/profiles/.deleted";

/// Hermes's profile id rule, `PROFILE_ID_RE` in `hermes_cli/profiles.py`
/// (Hermes 0.22.2): `^[a-z0-9][a-z0-9_-]{0,63}$`.
fn hermes_id(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        && name.len() <= 64
}

fn unreadable(path: &str, why: NotRead) -> Unreadable {
    Unreadable {
        path: path.to_owned(),
        why,
    }
}

fn io(path: &str, e: Errno) -> Unreadable {
    unreadable(path, NotRead::Io(e.to_string()))
}

/// Opens the folder `name` inside the open folder `dir`, through its
/// descriptor and without following a link in its place, so what the
/// sandbox puts there, before or during the read, leads nowhere. `Ok(None)`
/// when there is no such entry; a link or a non-folder is `Unreadable`.
fn open_folder(dir: impl AsFd, name: &str, shown: &str) -> Result<Option<OwnedFd>, Unreadable> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match rustix::fs::openat(&dir, name, flags, Mode::empty()) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT) => Ok(None),
        // A link is refused as a loop (Linux) or as not a folder (macOS).
        Err(Errno::LOOP | Errno::NOTDIR) => {
            let link = entry_type(&dir, name, shown)?.is_some_and(FileType::is_symlink);
            Err(unreadable(
                shown,
                if link {
                    NotRead::Link
                } else {
                    NotRead::NotAFolder
                },
            ))
        }
        Err(e) => Err(io(shown, e)),
    }
}

/// What `name` is inside the open folder `dir`, without following a link
/// at its end: `None` when there is no such entry.
fn entry_type(dir: impl AsFd, name: &str, shown: &str) -> Result<Option<FileType>, Unreadable> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => Ok(Some(FileType::from_raw_mode(stat.st_mode))),
        Err(Errno::NOENT) => Ok(None),
        Err(e) => Err(io(shown, e)),
    }
}

impl RuntimeAdapter for Hermes {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Hermes
    }

    fn version(&self) -> &'static str {
        "1"
    }

    fn endpoints(&self) -> &'static str {
        include_str!("hermes/endpoints.toml")
    }

    fn installer(&self) -> Installer {
        Installer {
            url: INSTALLER_URL.to_owned(),
            sha256: INSTALLER_SHA256.to_owned(),
            // No setup and no `gateway install` (no launchd job of its own),
            // and no computer-use driver.
            args: vec!["--non-interactive".into(), "--skip-computer-use".into()],
        }
    }

    fn home_files(&self) -> Vec<HomeFile> {
        vec![HomeFile {
            path: "bin/mktemp",
            contents: include_str!("hermes/mktemp"),
            executable: true,
        }]
    }

    fn login(&self) -> String {
        // Hermes's setup wizard: the provider and its login, the model, and
        // optional sections. `hermes model` covers only provider, login and
        // model, which the prototype used (`setup` in the sandbox: to verify).
        format!("{HERMES} setup")
    }

    fn create_agent(&self, name: &AgentName) -> SandboxCommand {
        // Hermes calls an agent a profile: each enclos agent is the Hermes
        // profile of the same name, created and selected with Hermes's
        // own `profile` command and `-p` flag.
        SandboxCommand::from_words(&[HERMES, "profile", "create", name.as_str()])
    }

    fn agent_files(&self, name: &AgentName) -> String {
        format!("~/.hermes/profiles/{name}")
    }

    fn delete_agent(&self, name: &AgentName) -> Option<Vec<OsString>> {
        // Hermes's own delete: the profile folder, its wrapper, and its
        // records, which a plain `rm` would leave behind.
        Some(args(&[HERMES, "profile", "delete", name.as_str(), "--yes"]))
    }

    fn disk_parts(&self) -> Vec<(DiskPart, PathBuf)> {
        let runtime = ["hermes-agent", "tools", "installs"]
            .map(|p| (DiskPart::Runtime, Path::new(".hermes").join(p)));
        let caches =
            [".hermes/cache", ".npm", ".cache", "tmp"].map(|p| (DiskPart::Cache, p.into()));
        runtime.into_iter().chain(caches).collect()
    }

    fn runtime_facts(&self) -> RuntimeFacts {
        RuntimeFacts {
            // Not on disk where enclos can rely on it: `pyproject.toml` says
            // 0.0.0 (to verify, design §14).
            version: None,
            // Agents share the root login (prototype, issue #5).
            login: Some(".hermes/auth.json".into()),
        }
    }

    fn agent_facts(&self, agent: &str) -> AgentFacts {
        // The built-in agent's folder is the whole home of Hermes: the parts
        // counted on their own (runtime, caches, other profiles) leave it its
        // own data.
        let folder = if agent == DEFAULT_PROFILE {
            PathBuf::from(".hermes")
        } else {
            Path::new(".hermes/profiles").join(agent)
        };
        AgentFacts {
            model: Some(ValueAt {
                file: folder.join("config.yaml"),
                // Hermes reads either key.
                keys: vec!["model.default", "model.model"],
            }),
            // What changed when an agent was used; `sessions/` did not (to
            // verify, design §14).
            activity: [".hermes_history", "state.db", "state.db-wal"]
                .map(|f| folder.join(f))
                .to_vec(),
            folder: Some(folder),
        }
    }

    fn talk(&self, agent: &AgentName) -> String {
        if Some(agent.as_str()) == self.builtin_agent() {
            return HERMES.to_owned();
        }
        // Hermes also writes a wrapper named after the agent on the sandbox
        // PATH (`main` runs `hermes -p main`); enclos's messages use the
        // form that does not depend on it.
        format!("{HERMES} -p {agent}")
    }

    fn builtin_agent(&self) -> Option<&'static str> {
        // Hermes's own `default` profile: the root of its home, which
        // `hermes` uses when no `-p` is given.
        Some(DEFAULT_PROFILE)
    }

    fn services(&self) -> Vec<RuntimeService> {
        // One gateway per Hermes home serves every agent: cron, housekeeping
        // and, later, messaging (prototype, issue #5). The backend starts
        // programs from an empty environment, which clears the markers
        // Hermes reads to find its supervisor (`XPC_SERVICE_NAME` for
        // launchd, `INVOCATION_ID` for systemd), so the flag says that one
        // restarts it: on an in-chat restart or update it exits (75) for the
        // service manager to start it again, rather than starting a detached
        // replacement that no session would hold.
        vec![RuntimeService {
            name: GATEWAY,
            command: SandboxCommand::from_words(&[
                HERMES,
                "gateway",
                "run",
                "--external-supervisor",
            ]),
        }]
    }

    fn agents_in(&self, home: &Path) -> Result<Vec<RuntimeAgentName>, Unreadable> {
        // Hermes lists a named profile when its folder under
        // `~/.hermes/profiles/` has a valid id, is not `default` (the Hermes
        // home itself), has one of its identity files, and has no marker
        // under `profiles/.deleted/`. Where Hermes follows links (a marker
        // that `is_file` or `is_symlink`, a tombstone that `exists`), enclos
        // looks without following: a link or a folder in a marker's place
        // counts as Hermes would count a link, and a dangling link counts as
        // a tombstone where Hermes would not. Every folder is opened by its
        // descriptor, so a link the sandbox plants, before or during the
        // read, is never followed: `.hermes`, `profiles` or `.deleted` as a
        // link means "cannot tell", and a linked profile folder is not
        // listed.
        let home = rustix::fs::open(
            home,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| match e {
            Errno::NOENT => unreadable("~", NotRead::Missing),
            Errno::NOTDIR => unreadable("~", NotRead::NotAFolder),
            e => io("~", e),
        })?;
        let Some(hermes) = open_folder(&home, ".hermes", "~/.hermes")? else {
            return Ok(Vec::new());
        };
        let Some(profiles) = open_folder(&hermes, "profiles", PROFILES)? else {
            return Ok(Vec::new());
        };
        let deleted = open_folder(&profiles, ".deleted", DELETED)?;
        let mut entries = Vec::new();
        for entry in Dir::read_from(&profiles).map_err(|e| io(PROFILES, e))? {
            let entry = entry.map_err(|e| io(PROFILES, e))?;
            // A name that is not text is not a Hermes id either.
            let Ok(name) = entry.file_name().to_str() else {
                continue;
            };
            if name == "." || name == ".." {
                continue;
            }
            if entries.len() == MAX_ENTRIES {
                return Err(unreadable(PROFILES, NotRead::TooManyEntries(MAX_ENTRIES)));
            }
            entries.push(name.to_owned());
        }
        let mut names = Vec::new();
        for name in entries {
            if name == "default" || !hermes_id(&name) {
                continue;
            }
            // Every Hermes id is a runtime agent name.
            let Some(agent) = RuntimeAgentName::new(&name) else {
                continue;
            };
            let shown = format!("{PROFILES}/{name}");
            let profile = match open_folder(&profiles, &name, &shown) {
                Ok(Some(fd)) => fd,
                Ok(None) => continue,
                Err(Unreadable {
                    why: NotRead::Link | NotRead::NotAFolder,
                    ..
                }) => continue,
                Err(e) => return Err(e),
            };
            let mut identity = false;
            for marker in PROFILE_MARKERS {
                if entry_type(&profile, marker, &shown)?
                    .is_some_and(|t| t.is_file() || t.is_symlink())
                {
                    identity = true;
                    break;
                }
            }
            if !identity {
                continue;
            }
            if let Some(deleted) = &deleted
                && entry_type(deleted, &name, DELETED)?.is_some()
            {
                continue;
            }
            names.push(agent);
        }
        names.sort();
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::file::{FsLayer, PolicyFile};

    #[test]
    fn the_endpoints_add_exactly_the_model_login_and_install_hosts_and_nothing_else() {
        let layer = PolicyFile::parse("hermes adapter", Hermes.endpoints()).unwrap();
        assert!(layer.beyond_destinations().is_empty(), "{layer:?}");
        assert_eq!(layer.filesystem, FsLayer::default());
        let mut allow = layer.network.allow_add.clone();
        allow.sort();
        // Any new or broader host is a deliberate change here.
        assert_eq!(
            allow,
            [
                "api.github.com",
                "auth.openai.com",
                "cdn.playwright.dev",
                "chatgpt.com",
                "ffmpeg.martin-riedl.de",
                "files.pythonhosted.org",
                "github.com",
                "nodejs.org",
                "pypi.org",
                "registry.npmjs.org",
                "release-assets.githubusercontent.com",
                "releases.astral.sh",
                "storage.googleapis.com",
            ]
        );
        for entry in &allow {
            crate::net::host::AllowEntry::parse(entry).unwrap();
            assert!(!entry.starts_with('*'), "no wildcard: {entry}");
        }
    }

    fn names(names: &[&str]) -> Vec<RuntimeAgentName> {
        names
            .iter()
            .map(|n| RuntimeAgentName::new(n).unwrap())
            .collect()
    }

    /// A home with a `.hermes/profiles` folder, and a way to make a profile
    /// in it with one identity marker.
    fn hermes_home() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        impl Fn(&str, Option<&str>),
    ) {
        let home = tempfile::tempdir().unwrap();
        let profiles = home.path().join(".hermes/profiles");
        std::fs::create_dir_all(&profiles).unwrap();
        let at = profiles.clone();
        let profile = move |name: &str, marker: Option<&str>| {
            std::fs::create_dir_all(at.join(name)).unwrap();
            if let Some(m) = marker {
                std::fs::write(at.join(name).join(m), "").unwrap();
            }
        };
        (home, profiles, profile)
    }

    #[test]
    fn agents_are_listed_as_hermes_lists_its_named_profiles() {
        let (home, profiles, profile) = hermes_home();
        profile("main", Some("config.yaml"));
        profile("my_bot", Some("SOUL.md")); // a Hermes name enclos cannot use
        profile("default", Some("config.yaml")); // the Hermes home itself
        profile("ghost", None); // no identity file: not a profile
        profile("gone", Some(".env"));
        std::fs::create_dir_all(profiles.join(".deleted/gone")).unwrap();
        profile("Upper", Some(".env")); // not a Hermes id
        std::fs::write(profiles.join("file"), "").unwrap();
        // A marker that is a folder does not count; a link does, as for
        // Hermes, even a dangling one.
        profile("boxed", None);
        std::fs::create_dir(profiles.join("boxed/config.yaml")).unwrap();
        profile("linked-marker", None);
        std::os::unix::fs::symlink("/nonexistent", profiles.join("linked-marker/auth.json"))
            .unwrap();
        // A tombstone that is a dangling link counts (Hermes would not).
        profile("buried", Some("config.yaml"));
        std::os::unix::fs::symlink("/nonexistent", profiles.join(".deleted/buried")).unwrap();
        // A linked profile folder is not listed.
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("config.yaml"), "").unwrap();
        std::os::unix::fs::symlink(outside.path(), profiles.join("linked")).unwrap();
        assert_eq!(
            Hermes.agents_in(home.path()),
            Ok(names(&["linked-marker", "main", "my_bot"]))
        );
    }

    #[test]
    fn a_missing_hermes_or_profiles_folder_means_no_agents() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(Hermes.agents_in(home.path()), Ok(vec![]));
        std::fs::create_dir(home.path().join(".hermes")).unwrap();
        assert_eq!(Hermes.agents_in(home.path()), Ok(vec![]));
    }

    #[test]
    fn a_link_or_a_file_in_a_folders_place_cannot_be_read_and_says_which() {
        let at = |path: &str, why| Unreadable {
            path: path.to_owned(),
            why,
        };
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("profiles/main")).unwrap();
        std::fs::write(outside.path().join("profiles/main/config.yaml"), "").unwrap();

        let home = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join(".hermes")).unwrap();
        assert_eq!(
            Hermes.agents_in(home.path()),
            Err(at("~/.hermes", NotRead::Link))
        );

        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(".hermes"), "").unwrap();
        assert_eq!(
            Hermes.agents_in(home.path()),
            Err(at("~/.hermes", NotRead::NotAFolder))
        );

        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".hermes")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("profiles"),
            home.path().join(".hermes/profiles"),
        )
        .unwrap();
        assert_eq!(
            Hermes.agents_in(home.path()),
            Err(at("~/.hermes/profiles", NotRead::Link))
        );

        let (home, profiles, profile) = hermes_home();
        profile("main", Some("config.yaml"));
        std::os::unix::fs::symlink(outside.path(), profiles.join(".deleted")).unwrap();
        assert_eq!(
            Hermes.agents_in(home.path()),
            Err(at("~/.hermes/profiles/.deleted", NotRead::Link))
        );

        let gone = tempfile::tempdir().unwrap();
        let path = gone.path().to_owned();
        drop(gone);
        assert_eq!(Hermes.agents_in(&path), Err(at("~", NotRead::Missing)));
    }

    #[test]
    fn more_entries_than_the_cap_cannot_be_read() {
        let (home, profiles, profile) = hermes_home();
        for i in 0..MAX_ENTRIES {
            std::fs::write(profiles.join(format!("f{i}")), "").unwrap();
        }
        profile("main", Some("config.yaml"));
        assert_eq!(
            Hermes.agents_in(home.path()),
            Err(Unreadable {
                path: "~/.hermes/profiles".to_owned(),
                why: NotRead::TooManyEntries(MAX_ENTRIES),
            })
        );
        std::fs::remove_file(profiles.join("f0")).unwrap();
        assert_eq!(Hermes.agents_in(home.path()), Ok(names(&["main"])));
    }

    #[test]
    fn commands_name_the_agent_and_the_home_file_stays_inside_the_home() {
        let main: AgentName = "main".parse().unwrap();
        assert_eq!(Hermes.talk(&main), "hermes -p main");
        assert_eq!(Hermes.login(), "hermes setup");
        assert_eq!(Hermes.agent_files(&main), "~/.hermes/profiles/main");
        assert_eq!(
            Hermes.delete_agent(&main),
            Some(args(&["hermes", "profile", "delete", "main", "--yes"]))
        );
        let default: AgentName = "default".parse().unwrap();
        assert_eq!(Hermes.builtin_agent(), Some("default"));
        assert_eq!(Hermes.talk(&default), "hermes");
        assert_eq!(
            Hermes.agent_facts("default").folder.as_deref(),
            Some(Path::new(".hermes"))
        );
        let facts = Hermes.agent_facts("main");
        assert_eq!(
            facts.folder.as_deref(),
            Some(Path::new(".hermes/profiles/main"))
        );
        assert!(
            facts
                .activity
                .iter()
                .all(|f| f.starts_with(".hermes/profiles/main"))
        );
        assert_eq!(
            Hermes.create_agent(&main),
            SandboxCommand::from_words(&["hermes", "profile", "create", "main"])
        );
        assert_eq!(Hermes.installer().sha256.len(), 64);
        assert!(
            Hermes
                .home_files()
                .iter()
                .all(HomeFile::path_is_inside_home)
        );
    }

    #[test]
    fn one_gateway_serves_the_sandbox_and_says_launchd_restarts_it() {
        let services = Hermes.services();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name.as_str(), "gateway");
        assert_eq!(
            services[0].command,
            SandboxCommand::from_words(&["hermes", "gateway", "run", "--external-supervisor"])
        );
    }
}
