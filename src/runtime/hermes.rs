//! The Hermes Agent adapter (Nous Research), from the milestone 1 prototype
//! (issue #5): installed per sandbox with Hermes's own installer (ADR 0020),
//! meant to be logged in with a ChatGPT subscription through Hermes's
//! device-code flow, each agent a Hermes profile under `~/.hermes/profiles`,
//! all sharing the sandbox's one Hermes login (`~/.hermes/auth.json`), as
//! the prototype used them (design §14: to verify in this build).

use std::ffi::OsString;
use std::path::Path;

use rustix::fs::{Dir, FileType};

use super::home::{entry_stat, io, open_folder, open_home, unreadable};
use super::{
    AgentFacts, BuiltinAgent, DiskPart, HomeFile, HomePath, Installer, NotRead, RuntimeAdapter,
    RuntimeAgentName, RuntimeFacts, RuntimeListener, RuntimeService, SandboxCommand, ServiceName,
    Unreadable, ValueAt,
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
const DEFAULT_PROFILE: BuiltinAgent = BuiltinAgent::new("default");

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

/// A path of the home Hermes writes; every one here is a literal.
fn at(path: &str) -> HomePath {
    HomePath::new(path).expect("a plain path inside the home")
}

/// Whether the entry is a link or a plain file, without following it.
fn file_or_link(dir: &rustix::fd::OwnedFd, name: &str, shown: &str) -> Result<bool, Unreadable> {
    Ok(entry_stat(dir, name, shown)?.is_some_and(|s| {
        let t = FileType::from_raw_mode(s.st_mode);
        t.is_file() || t.is_symlink()
    }))
}

impl RuntimeAdapter for Hermes {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Hermes
    }

    fn version(&self) -> &'static str {
        // 2: the gateway listens (ADR 0028).
        "2"
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
        // For the root profile, whose login every agent shares: without `-p`,
        // Hermes uses the profile `hermes profile use` last saved in
        // `~/.hermes/active_profile` (`hermes_cli/main.py`, Hermes 0.22.2).
        format!("{HERMES} -p {DEFAULT_PROFILE} setup")
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

    fn delete_agent(&self, name: &AgentName) -> Option<SandboxCommand> {
        // Hermes's own delete, so whatever it keeps beside the profile
        // folder goes with it (what that is: to verify, design §14).
        Some(SandboxCommand::from_words(&[
            HERMES,
            "profile",
            "delete",
            name.as_str(),
            "--yes",
        ]))
    }

    fn import_agent(&self, name: &AgentName, archive: &Path) -> Option<SandboxCommand> {
        // Hermes's own import of an archive its `profile export` made, by
        // Hermes 0.22.2's code: it extracts without following links or
        // leaving the profile folder, refuses an existing profile and
        // `default`, removes the archive's `installs`, `tools` and `cache`
        // folders, and writes the profile's wrapper unless the name
        // collides with a command. Its export leaves out `auth.json`, `.env`
        // and the browser's data and scrubs secret-shaped strings. Neither
        // is shown by a prototype yet (design §14).
        let mut words: Vec<OsString> = [HERMES, "profile", "import"].map(OsString::from).to_vec();
        words.push(archive.as_os_str().to_owned());
        words.extend(["--name", name.as_str()].map(OsString::from));
        Some(SandboxCommand::new(words))
    }

    fn disk_parts(&self) -> Vec<(DiskPart, HomePath)> {
        let runtime = [".hermes/hermes-agent", ".hermes/tools", ".hermes/installs"]
            .map(|p| (DiskPart::Runtime, at(p)));
        let caches = [".hermes/cache", ".npm", ".cache", "tmp"].map(|p| (DiskPart::Cache, at(p)));
        runtime.into_iter().chain(caches).collect()
    }

    fn runtime_facts(&self) -> RuntimeFacts {
        RuntimeFacts {
            // Not on disk where enclos can rely on it: `pyproject.toml` says
            // 0.0.0 (to verify, design §14).
            version: None,
            // Agents share the root login (prototype, issue #5).
            login: Some(at(".hermes/auth.json")),
            // Where the installer puts Hermes itself.
            install: Some(at(".hermes/hermes-agent")),
        }
    }

    fn agent_facts(&self, agent: &RuntimeAgentName) -> AgentFacts {
        // The built-in agent's folder is the whole home of Hermes: the parts
        // counted on their own (runtime, caches, other profiles) leave it its
        // own data.
        let folder = if agent.as_str() == DEFAULT_PROFILE.as_str() {
            at(".hermes")
        } else {
            at(".hermes/profiles").join(agent)
        };
        let file = |name: &str| folder.child(name).expect("a plain file name");
        AgentFacts {
            model: Some(ValueAt {
                file: file("config.yaml"),
                // Hermes reads either key.
                keys: &["model.default", "model.model"],
            }),
            // What changed when an agent was used; `sessions/` did not (to
            // verify, design §14).
            activity: [".hermes_history", "state.db", "state.db-wal"]
                .map(file)
                .to_vec(),
            folder: Some(folder),
        }
    }

    fn talk(&self, agent: &AgentName) -> String {
        // Hermes also writes a wrapper named after the agent on the sandbox
        // PATH (`main` runs `hermes -p main`); enclos's messages use the
        // form that does not depend on it. The built-in agent is named too:
        // bare `hermes` follows the saved active profile, not always it.
        format!("{HERMES} -p {agent}")
    }

    fn builtin_agent(&self) -> Option<BuiltinAgent> {
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

    fn listener(&self) -> Option<RuntimeListener> {
        // Hermes 0.22.3's chat (CLI, TUI, stream-json) cannot run without the
        // gateway: it finds it, gets a ticket for its own agent (a Hermes
        // profile) over
        // `gateway.sock` in the home, and dials the WebSocket the gateway
        // serves on 127.0.0.1:0 (`gateway/run_api.py`,
        // `hermes_cli/gateway_client.py`).
        Some(RuntimeListener {
            service: GATEWAY,
            // Its web dashboard, on the same listener. Bound to loopback,
            // Hermes asks no login for it, by its code
            // (`listener_auth_required` in `gateway/run_api.py`).
            page: Some("/"),
        })
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
        let home = open_home(home)?;
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
            if name == DEFAULT_PROFILE.as_str() || !hermes_id(&name) {
                continue;
            }
            // Every Hermes id is a runtime agent name.
            let Some(agent) = RuntimeAgentName::new(&name) else {
                continue;
            };
            let shown = format!("{PROFILES}/{name}");
            let profile = match open_folder(&profiles, name.as_str(), &shown) {
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
                if file_or_link(&profile, marker, &shown)? {
                    identity = true;
                    break;
                }
            }
            if !identity {
                continue;
            }
            if let Some(deleted) = &deleted
                && entry_stat(deleted, name.as_str(), DELETED)?.is_some()
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

    #[test]
    fn the_gateway_may_listen() {
        // Hermes 0.22.3's gateway binds its own listener (ADR 0028).
        let layer = PolicyFile::parse("hermes adapter", Hermes.endpoints()).unwrap();
        assert_eq!(layer.network.listen, Some(true));
    }

    #[test]
    fn the_listening_service_is_one_of_its_services() {
        let listener = Hermes.listener().unwrap();
        assert_eq!(listener.service.as_str(), "gateway");
        assert!(Hermes.services().iter().any(|s| s.name == listener.service));
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
        assert_eq!(Hermes.login(), "hermes -p default setup");
        assert_eq!(Hermes.agent_files(&main), "~/.hermes/profiles/main");
        assert_eq!(
            Hermes.delete_agent(&main),
            Some(SandboxCommand::from_words(&[
                "hermes", "profile", "delete", "main", "--yes"
            ]))
        );
        let default: AgentName = "default".parse().unwrap();
        assert_eq!(Hermes.builtin_agent(), Some(DEFAULT_PROFILE));
        assert_eq!(Hermes.talk(&default), "hermes -p default");
        let facts = |n: &str| Hermes.agent_facts(&RuntimeAgentName::new(n).unwrap());
        assert_eq!(facts("default").folder, Some(at(".hermes")));
        let main_facts = facts("main");
        assert_eq!(main_facts.folder, Some(at(".hermes/profiles/main")));
        assert_eq!(
            main_facts.model,
            Some(ValueAt {
                file: at(".hermes/profiles/main/config.yaml"),
                keys: &["model.default", "model.model"],
            })
        );
        assert_eq!(
            main_facts.activity,
            [".hermes_history", "state.db", "state.db-wal"]
                .map(|f| at(&format!(".hermes/profiles/main/{f}")))
        );
        // What `status` counts on its own; a rename here changes what it shows.
        let parts: Vec<(DiskPart, String)> = Hermes
            .disk_parts()
            .into_iter()
            .map(|(p, path)| (p, path.to_string()))
            .collect();
        assert_eq!(
            parts,
            [
                (DiskPart::Runtime, "~/.hermes/hermes-agent"),
                (DiskPart::Runtime, "~/.hermes/tools"),
                (DiskPart::Runtime, "~/.hermes/installs"),
                (DiskPart::Cache, "~/.hermes/cache"),
                (DiskPart::Cache, "~/.npm"),
                (DiskPart::Cache, "~/.cache"),
                (DiskPart::Cache, "~/tmp"),
            ]
            .map(|(p, s)| (p, s.to_owned()))
        );
        let rt = Hermes.runtime_facts();
        assert_eq!(
            (rt.version, rt.login, rt.install),
            (
                None,
                Some(at(".hermes/auth.json")),
                Some(at(".hermes/hermes-agent"))
            )
        );
        assert_eq!(
            Hermes.create_agent(&main),
            SandboxCommand::from_words(&["hermes", "profile", "create", "main"])
        );
        assert_eq!(
            Hermes.import_agent(&main, Path::new("/x/installers/agent-main.tar.gz")),
            Some(SandboxCommand::from_words(&[
                "hermes",
                "profile",
                "import",
                "/x/installers/agent-main.tar.gz",
                "--name",
                "main"
            ]))
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
