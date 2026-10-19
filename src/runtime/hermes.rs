//! The Hermes Agent adapter (Nous Research), from the milestone 1 prototype
//! (issue #5): installed per sandbox with Hermes's own installer (ADR 0021),
//! logged in with a ChatGPT subscription through Hermes's device-code flow,
//! each agent a Hermes profile under `~/.hermes/profiles`, all sharing the
//! root login.

use std::ffi::OsString;

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
