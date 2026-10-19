//! The Hermes Agent adapter (Nous Research), from the milestone 1 prototype
//! (issue #5): installed per sandbox with Hermes's own installer (ADR 0021),
//! logged in with a ChatGPT subscription through Hermes's device-code flow,
//! each agent a Hermes profile under `~/.hermes/profiles`, all sharing the
//! root login.

use std::ffi::OsString;
use std::path::Path;

use super::{HomeFile, Installer, RuntimeAdapter};
use crate::model::agent::AgentName;
use crate::model::runtime::RuntimeKind;

pub struct Hermes;

/// The installer the official docs and README point to. Its content is
/// pinned: a new installer is refused until enclos is updated to it.
pub const INSTALLER_URL: &str = "https://hermes-agent.nousresearch.com/install.sh";
pub const INSTALLER_SHA256: &str =
    "20f44240ebada354a468104a6a6724d037afcb8883d4d09ddeb4815622c52d8b";

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

/// `hermes`, as the installer puts it on the sandbox's PATH.
const HERMES: &str = "hermes";

/// The files that make a folder under `~/.hermes/profiles/` a profile, as
/// Hermes decides it (`_PROFILE_IDENTITY_MARKERS`, Hermes 0.22).
const PROFILE_MARKERS: [&str; 6] = [
    "config.yaml",
    ".env",
    "SOUL.md",
    "profile.yaml",
    "auth.json",
    "state.db",
];

/// At most this many entries of `~/.hermes/profiles/` are read.
const MAX_ENTRIES: usize = 512;

/// Hermes's profile id rule: `^[a-z0-9][a-z0-9_-]{0,63}$`.
fn hermes_id(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        && name.len() <= 64
}

/// Whether `path` exists, without following a link at its end.
fn present(path: &Path) -> bool {
    path.symlink_metadata().is_ok()
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
            url: INSTALLER_URL,
            sha256: INSTALLER_SHA256,
            // No setup and no `gateway install` (no launchd job of its own),
            // and no computer-use driver.
            args: &["--non-interactive", "--skip-computer-use"],
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

    fn create_agent(&self, name: &AgentName) -> Vec<OsString> {
        // Hermes calls an agent a profile: each enclos agent is the Hermes
        // profile of the same name, created and selected with Hermes's
        // own `profile` command and `-p` flag.
        args(&[HERMES, "profile", "create", name.as_str()])
    }

    fn talk(&self, agent: &AgentName) -> String {
        // Hermes also writes a wrapper named after the agent (`main` runs
        // `hermes -p main`), but not for one created with `--no-alias`.
        format!("{HERMES} -p {agent}")
    }

    fn service(&self) -> Option<Vec<OsString>> {
        // One gateway per Hermes home serves every agent: cron, housekeeping
        // and, later, messaging (prototype, issue #5).
        Some(args(&[HERMES, "gateway", "run"]))
    }

    fn agents_in(&self, home: &Path) -> Option<Vec<String>> {
        // Hermes lists a profile when its folder under `~/.hermes/profiles/`
        // has a valid id, one of its identity files, and no marker under
        // `profiles/.deleted/`. The sandbox writes all of this, so a link is
        // never followed: a linked `.hermes` or `profiles` means "cannot
        // tell", and a linked profile folder is not listed.
        let hermes = home.join(".hermes");
        let profiles = hermes.join("profiles");
        for dir in [&hermes, &profiles] {
            match dir.symlink_metadata() {
                Ok(meta) if meta.is_dir() => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(Vec::new()),
                _ => return None,
            }
        }
        let mut names: Vec<String> = std::fs::read_dir(&profiles)
            .ok()?
            .take(MAX_ENTRIES)
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().into_string().ok()?;
                let folder = entry.file_type().ok()?.is_dir();
                let profile = folder
                    && name != "default"
                    && hermes_id(&name)
                    && PROFILE_MARKERS
                        .iter()
                        .any(|m| present(&entry.path().join(m)))
                    && !present(&profiles.join(".deleted").join(&name));
                profile.then_some(name)
            })
            .collect();
        names.sort();
        Some(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::file::PolicyFile;

    #[test]
    fn the_endpoints_are_a_valid_policy_layer_with_the_model_and_login_hosts() {
        let layer = PolicyFile::parse("hermes adapter", Hermes.endpoints()).unwrap();
        let allow = &layer.network.allow_add;
        assert!(
            allow.contains(&"chatgpt.com".to_owned())
                && allow.contains(&"auth.openai.com".to_owned())
        );
        for entry in allow {
            crate::net::host::AllowEntry::parse(entry).unwrap();
        }
    }

    #[test]
    fn agents_are_listed_as_hermes_lists_its_profiles() {
        let home = tempfile::tempdir().unwrap();
        let profiles = home.path().join(".hermes/profiles");
        let profile = |name: &str, marker: Option<&str>| {
            std::fs::create_dir_all(profiles.join(name)).unwrap();
            if let Some(m) = marker {
                std::fs::write(profiles.join(name).join(m), "").unwrap();
            }
        };
        profile("main", Some("config.yaml"));
        profile("my_bot", Some("SOUL.md")); // a Hermes name enclos cannot use
        profile("ghost", None); // no identity file: not a profile
        profile("gone", Some(".env"));
        std::fs::create_dir_all(profiles.join(".deleted/gone")).unwrap();
        profile("Upper", Some(".env")); // not a Hermes id
        std::fs::write(profiles.join("file"), "").unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("config.yaml"), "").unwrap();
        std::os::unix::fs::symlink(outside.path(), profiles.join("linked")).unwrap();
        assert_eq!(
            Hermes.agents_in(home.path()),
            Some(vec!["main".to_owned(), "my_bot".to_owned()])
        );
    }

    #[test]
    fn a_missing_hermes_has_no_agents_and_a_linked_one_cannot_be_read() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(Hermes.agents_in(home.path()), Some(vec![]));
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("profiles/main")).unwrap();
        std::fs::write(outside.path().join("profiles/main/config.yaml"), "").unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join(".hermes")).unwrap();
        assert_eq!(Hermes.agents_in(home.path()), None);
    }

    #[test]
    fn commands_name_the_agent() {
        let main: AgentName = "main".parse().unwrap();
        assert_eq!(Hermes.talk(&main), "hermes -p main");
        assert_eq!(Hermes.login(), "hermes setup");
        assert_eq!(
            Hermes.create_agent(&main),
            args(&["hermes", "profile", "create", "main"])
        );
        assert_eq!(Hermes.installer().sha256.len(), 64);
    }
}
