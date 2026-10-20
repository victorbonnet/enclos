//! The Hermes Agent adapter (Nous Research), from the milestone 1 prototype
//! (issue #5): installed per sandbox with Hermes's own installer (ADR 0020),
//! meant to be logged in with a ChatGPT subscription through Hermes's
//! device-code flow, each agent a Hermes profile under `~/.hermes/profiles`,
//! all sharing the sandbox's one Hermes login (`~/.hermes/auth.json`), as
//! the prototype used them (design §14: to verify in this build).

use super::{HomeFile, Installer, RuntimeAdapter, SandboxCommand};
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

    fn talk(&self, agent: &AgentName) -> String {
        // Hermes also writes a wrapper named after the agent on the sandbox
        // PATH (`main` runs `hermes -p main`); enclos's messages use the
        // form that does not depend on it.
        format!("{HERMES} -p {agent}")
    }

    fn service(&self) -> Option<SandboxCommand> {
        // One gateway per Hermes home serves every agent: cron, housekeeping
        // and, later, messaging (prototype, issue #5).
        Some(SandboxCommand::from_words(&[HERMES, "gateway", "run"]))
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
    fn commands_name_the_agent_and_the_home_file_stays_inside_the_home() {
        let main: AgentName = "main".parse().unwrap();
        assert_eq!(Hermes.talk(&main), "hermes -p main");
        assert_eq!(Hermes.login(), "hermes setup");
        assert_eq!(Hermes.agent_files(&main), "~/.hermes/profiles/main");
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
}
