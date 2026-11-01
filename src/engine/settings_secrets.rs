//! Secrets in a runtime's settings files in the sandbox home, which `enclos
//! doctor` reports (design §10): a value written there in plain text, which
//! every agent of the sandbox reads (ADR 0003), and a `${VAR}` reference to
//! a variable the active policy does not grant the agent the file belongs
//! to (ADR 0036). Whatever wrote them: the runtime's own setup, a person
//! through `enclos connect`, or `runtime configure`. With them, the agents
//! granted secrets of their own that do not read them. Only names and line
//! numbers are kept, never a value.

use std::collections::BTreeSet;

use super::Engine;
use super::restart::MAX_SETTINGS;
use crate::model::sandbox::SandboxRecord;
use crate::model::secret::{is_variable_name, reserved_variable};
use crate::runtime::home::read_text;
use crate::runtime::{HomePath, RuntimeAgentName, adapter};

/// A settings file read from the home, and what the active policy grants
/// the agent it belongs to: the whole sandbox's secrets and the agent's own.
struct SettingsFile {
    agent: RuntimeAgentName,
    path: HomePath,
    text: String,
    granted: BTreeSet<String>,
}

/// What `doctor` reports of a runtime's settings. `line` counts from 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsFinding {
    /// The line sets `held` to a value in plain text: a variable the active
    /// policy grants `agent`, or a name that says it holds a secret.
    Plain {
        agent: RuntimeAgentName,
        file: HomePath,
        line: usize,
        held: Held,
    },
    /// The line refers to `${variable}`, which the active policy does not
    /// grant `agent` and `agent`'s own `.env` does not set: nothing enclos
    /// gives the agent sets it.
    NotGranted {
        agent: RuntimeAgentName,
        file: HomePath,
        line: usize,
        variable: String,
    },
    /// The active policy grants `agent` secrets of its own, and it does not
    /// read them: the runtime has no such agent, or its settings do not
    /// point it at them, which `runtime configure` does (ADR 0036).
    NotSetUp { agent: RuntimeAgentName },
}

/// What a settings line sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    /// A variable of a `.env` file; `granted`: one the active policy grants
    /// the agent.
    Variable { name: String, granted: bool },
    /// A key of a YAML file, as written on its line (`token`, not the
    /// dotted path above it).
    Key(String),
}

/// Whether a name says it holds a secret, by its last word, words split at
/// `_`, `-` and `.`, any case: `key` or `apikey`, or one holding a secret, a
/// password or a token, but for a count of tokens: `TELEGRAM_BOT_TOKEN`,
/// `api_key`, `secretKey`, not `max_tokens`.
pub(super) fn names_a_secret(name: &str) -> bool {
    name.rsplit(['_', '-', '.']).next().is_some_and(|last| {
        let last = last.to_ascii_lowercase();
        matches!(last.as_str(), "key" | "apikey")
            || ["secret", "password", "passwd"]
                .iter()
                .any(|word| last.contains(word))
            || (last.contains("token") && !last.ends_with("tokens"))
    })
}

/// A `.env` line's variable and value, both trimmed: `NAME=value` or
/// `export NAME=value`. `None` for a comment, a blank line, or a name that
/// is not a variable's.
pub(super) fn dotenv_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_start();
    let line = line.strip_prefix("export ").unwrap_or(line);
    let (name, value) = line.split_once('=')?;
    let name = name.trim();
    is_variable_name(name).then(|| (name, value.trim()))
}

/// A YAML line's key and value, both trimmed, its comment left out: `key:
/// value` or `- key: value`. `None` for a comment, a blank line, or a line
/// that is not one key.
fn yaml_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_start();
    let line = line.strip_prefix("- ").unwrap_or(line).trim_start();
    let (key, value) = line.split_once(':')?;
    let key = unquoted(key.trim_end());
    let plain_key = !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b));
    if !plain_key {
        return None;
    }
    // A `:` not followed by a space or the end is part of a plain scalar,
    // not a key's end.
    if !(value.is_empty() || value.starts_with([' ', '\t'])) {
        return None;
    }
    let value = value.trim();
    let value = match value.chars().next() {
        // Up to its closing quote, so a comment after it is left out.
        Some(quote @ ('"' | '\'')) => value[1..]
            .find(quote)
            .map_or(value, |end| &value[..end + 2]),
        Some('#') => "",
        _ => value.split(" #").next().unwrap_or("").trim_end(),
    };
    Some((key, value))
}

/// `value` without one pair of matching quotes around it.
fn unquoted(value: &str) -> &str {
    for q in ['"', '\''] {
        if let Some(inner) = value.strip_prefix(q).and_then(|v| v.strip_suffix(q)) {
            return inner;
        }
    }
    value
}

/// Whether `value` holds a value of its own: not empty, not null or a
/// boolean, not only a `${...}` reference, whatever its source, and in YAML
/// not a mapping, list, block or alias whose value is elsewhere, nor a tag
/// or an anchor alone.
fn holds_a_value(value: &str, yaml: bool) -> bool {
    let inner = unquoted(value).trim();
    let reference = inner
        .strip_prefix("${")
        .and_then(|v| v.strip_suffix('}'))
        .is_some_and(|v| !v.contains('}'));
    let elsewhere = yaml
        && value == inner
        && (inner.starts_with(['{', '[', '|', '>', '*'])
            || (inner.starts_with(['&', '!']) && !inner.contains(' ')));
    !inner.is_empty()
        && !reference
        && !elsewhere
        && !matches!(inner, "~" | "null" | "true" | "false")
}

/// The variables `${NAME}` or `${env:NAME}` refers to on `line`, in order:
/// Hermes's two forms of a reference to a variable.
fn references(line: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find("${") {
        rest = &rest[start + 2..];
        if let Some(end) = rest.find('}') {
            let inner = rest[..end].trim();
            let name = inner.strip_prefix("env:").unwrap_or(inner).trim();
            if is_variable_name(name) {
                found.push(name);
                rest = &rest[end + 1..];
            }
        }
    }
    found
}

fn is_dotenv(file: &HomePath) -> bool {
    file.as_path().file_name().is_some_and(|n| n == ".env")
}

/// The secrets found in `files`. A `.env` file is read as `NAME=value`
/// lines, any other as YAML, line by line: a value spread over several
/// lines is not looked at.
fn findings(files: &[SettingsFile]) -> Vec<SettingsFinding> {
    let comment = |line: &str| line.trim_start().starts_with('#');
    let mut found = Vec::new();
    for SettingsFile {
        agent,
        path: file,
        text,
        granted,
    } in files
    {
        // What its agent's `.env` sets the agent has, whatever the policy
        // grants; Hermes keeps each profile's apart.
        let set: BTreeSet<&str> = files
            .iter()
            .filter(|other| other.agent == *agent && is_dotenv(&other.path))
            .flat_map(|other| other.text.lines().filter_map(dotenv_line))
            .filter(|(_, value)| !unquoted(value).trim().is_empty())
            .map(|(name, _)| name)
            .collect();
        let mut referred: BTreeSet<&str> = BTreeSet::new();
        for (n, line) in text.lines().enumerate() {
            if comment(line) {
                continue;
            }
            let line_no = n + 1;
            let held = match is_dotenv(file) {
                true => dotenv_line(line).map(|(name, value)| {
                    let granted = granted.contains(name);
                    let plain = holds_a_value(value, false) && (granted || names_a_secret(name));
                    let name = name.to_owned();
                    (plain, Held::Variable { name, granted })
                }),
                false => yaml_line(line).map(|(key, value)| {
                    let plain = holds_a_value(value, true) && names_a_secret(key);
                    (plain, Held::Key(key.to_owned()))
                }),
            };
            if let Some((true, held)) = held {
                found.push(SettingsFinding::Plain {
                    agent: agent.clone(),
                    file: file.clone(),
                    line: line_no,
                    held,
                });
                // What it holds is a value: nothing of it is shown.
                continue;
            }
            let referring = match is_dotenv(file) {
                true => line,
                false => yaml_line(line).map_or(line, |(_, value)| value),
            };
            for variable in references(referring) {
                let given = granted.contains(variable)
                    || reserved_variable(variable)
                    || set.contains(variable);
                // Each variable once per file, at its first line.
                if !given && referred.insert(variable) {
                    found.push(SettingsFinding::NotGranted {
                        agent: agent.clone(),
                        file: file.clone(),
                        line: line_no,
                        variable: variable.to_owned(),
                    });
                }
            }
        }
    }
    found
}

impl Engine {
    /// What is reported of the settings files of the sandbox's runtime,
    /// for its built-in agent and every agent the runtime has (ADR 0031's
    /// files), read as other files of the home are (ADR 0023), and of each
    /// agent the policy grants secrets of its own. What could not be read
    /// is in `unreadable`; a sandbox without a runtime has nothing to look
    /// at.
    pub(super) fn settings_secrets(
        &self,
        record: &SandboxRecord,
        unreadable: &mut Vec<String>,
    ) -> Vec<SettingsFinding> {
        let Some(kind) = record.runtime else {
            return Vec::new();
        };
        let runtime = adapter(kind);
        let name = &record.name;
        let policy = match self.policy(name) {
            Ok(view) => view.snapshot.policy,
            Err(e) => {
                unreadable.push(format!(
                    "did not look for secrets in {}'s settings: cannot read its active policy: {e}",
                    kind.display_name()
                ));
                return Vec::new();
            }
        };
        let home = self.sandbox_home(name);
        let listed = runtime.agents_in(&home);
        let whole_list = listed.is_ok();
        let agents = listed.unwrap_or_else(|e| {
            unreadable.push(format!(
                "did not look for secrets in the settings of {}'s other agents: cannot list them: {e}",
                kind.display_name()
            ));
            Vec::new()
        });
        let builtin = runtime.builtin_agent().map(|b| b.runtime_name());
        let looked_at: Vec<_> = builtin.into_iter().chain(agents).collect();
        let mut files = Vec::new();
        let mut not_set_up = Vec::new();
        for agent in &looked_at {
            let own = policy.agent_secrets.get(agent.as_str());
            let granted: BTreeSet<String> = policy
                .secrets
                .keys()
                .chain(own.into_iter().flat_map(|g| g.keys()))
                .cloned()
                .collect();
            let secrets_file = self
                .layout
                .agent_secrets_file(name.as_str(), agent.as_str());
            let (mut reads, mut whole) = (false, true);
            for path in runtime.agent_settings_files(agent) {
                match read_text(&home, &path, MAX_SETTINGS) {
                    Ok(Some(text)) => {
                        reads |= runtime.reads_agent_secrets(&text, &secrets_file);
                        files.push(SettingsFile {
                            agent: agent.clone(),
                            path,
                            text,
                            granted: granted.clone(),
                        });
                    }
                    Ok(None) => {}
                    Err(e) => {
                        whole = false;
                        unreadable.push(format!("did not look for secrets in {path}: {e}"));
                    }
                }
            }
            if whole && !reads && own.is_some() {
                not_set_up.push(SettingsFinding::NotSetUp {
                    agent: agent.clone(),
                });
            }
        }
        // Granted to an agent the runtime does not have: it reaches no one.
        if whole_list {
            let absent = policy
                .agent_secrets
                .keys()
                .map(RuntimeAgentName::from)
                .filter(|agent| !looked_at.contains(agent));
            not_set_up.extend(absent.map(|agent| SettingsFinding::NotSetUp { agent }));
        }
        let mut found = findings(&files);
        found.append(&mut not_set_up);
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(path: &str) -> HomePath {
        HomePath::new(path).unwrap()
    }

    fn agent(name: &str) -> RuntimeAgentName {
        RuntimeAgentName::new(name).unwrap()
    }

    fn file(owner: &str, path: &str, text: &str, granted: &[&str]) -> SettingsFile {
        SettingsFile {
            agent: agent(owner),
            path: at(path),
            text: text.to_owned(),
            granted: granted.iter().map(|n| (*n).to_owned()).collect(),
        }
    }

    fn variable(name: &str, granted: bool) -> Held {
        Held::Variable {
            name: name.to_owned(),
            granted,
        }
    }

    fn plain(file: &str, line: usize, held: Held) -> SettingsFinding {
        SettingsFinding::Plain {
            agent: agent("default"),
            file: at(file),
            line,
            held,
        }
    }

    fn not_granted(owner: &str, file: &str, line: usize, variable: &str) -> SettingsFinding {
        SettingsFinding::NotGranted {
            agent: agent(owner),
            file: at(file),
            line,
            variable: variable.to_owned(),
        }
    }

    #[test]
    fn a_name_says_it_holds_a_secret_by_its_last_word() {
        for secret in [
            "TELEGRAM_BOT_TOKEN",
            "OPENROUTER_API_KEY",
            "api_key",
            "token",
            "client-secret",
            "db.password",
            "APIKEY",
            "x.botToken",
            "x.apitoken",
            "x.api-key",
            "storage.secretKey",
            "x.tokenValue",
            "x.passwordHash",
        ] {
            assert!(names_a_secret(secret), "{secret}");
        }
        for not in [
            "TELEGRAM_ALLOWED_USERS",
            "max_tokens",
            "token_limit",
            "hotkey",
            "key_env",
            "monkey",
            "PRIVATE_KEY_PATH",
        ] {
            assert!(!names_a_secret(not), "{not}");
        }
    }

    #[test]
    fn a_value_of_its_own_is_told_from_a_reference_and_from_nothing() {
        for value in ["abc", "\"abc\"", "'123:tok'", "x${Y}", "${Y}z", "1234"] {
            assert!(holds_a_value(value, true), "{value:?}");
        }
        for nothing in [
            "",
            "\"\"",
            "''",
            "~",
            "null",
            "true",
            "false",
            "${TOKEN}",
            "\"${TOKEN}\"",
            "${env:TOKEN}",
            "${bitwarden:item}",
        ] {
            assert!(!holds_a_value(nothing, true), "{nothing:?}");
            assert!(!holds_a_value(nothing, false), "{nothing:?}");
        }
        // What only YAML writes elsewhere: in a `.env` these are values.
        for elsewhere in ["{}", "[a]", "|", ">-", "&anchor", "*alias", "!secret"] {
            assert!(!holds_a_value(elsewhere, true), "{elsewhere:?}");
            assert!(holds_a_value(elsewhere, false), "{elsewhere:?}");
        }
        // An anchor or a tag before a value does not hide it.
        assert!(holds_a_value("&a abc", true));
        assert!(holds_a_value("!!str abc", true));
        // Quoted, a marker is the value's own start.
        assert!(holds_a_value("\"*hunter2\"", true));
        // Text between references is a value.
        assert!(holds_a_value("${A}abc${B}", true));
    }

    #[test]
    fn a_yaml_line_gives_its_key_and_value_without_its_comment() {
        assert_eq!(yaml_line("  token: abc # mine"), Some(("token", "abc")));
        assert_eq!(
            yaml_line("- api_key: \"a #b\""),
            Some(("api_key", "\"a #b\""))
        );
        assert_eq!(yaml_line("telegram:"), Some(("telegram", "")));
        assert_eq!(yaml_line("token : abc"), Some(("token", "abc")));
        assert_eq!(yaml_line("\"token\": abc"), Some(("token", "abc")));
        assert_eq!(yaml_line("token: \"\" # mine"), Some(("token", "\"\"")));
        assert_eq!(yaml_line("token: # mine"), Some(("token", "")));
        assert_eq!(yaml_line("url: http://x"), Some(("url", "http://x")));
        assert_eq!(yaml_line("http://x"), None);
        assert_eq!(yaml_line("a b: c"), None);
        assert_eq!(yaml_line("- item"), None);
    }

    #[test]
    fn references_are_found_in_order_and_only_to_variables() {
        assert_eq!(references("a ${A} b ${B_2}"), ["A", "B_2"]);
        assert_eq!(references("${env:A} ${ B }"), ["A", "B"]);
        assert_eq!(
            references("${} ${1X} ${A-b} ${vault:c} $C ${D"),
            Vec::<&str>::new()
        );
    }

    /// A secret written in plain text is found by the policy's grant or its
    /// name, in `.env` and in YAML; the value is never kept.
    #[test]
    fn a_secret_in_plain_text_is_found_and_its_value_never_kept() {
        let env = ".hermes/.env";
        let config = ".hermes/config.yaml";
        let grants = ["GRANTED", "MY_LOGIN"];
        let files = vec![
            file(
                "default",
                env,
                "# TELEGRAM_BOT_TOKEN=commented\nTELEGRAM_ALLOWED_USERS=111\nexport TELEGRAM_BOT_TOKEN=\"999:plain\"\nOPENROUTER_API_KEY=sk-x\nMY_LOGIN=hunter2\nEMPTY_TOKEN=\nREF_TOKEN=${GRANTED}\n",
                &grants,
            ),
            file(
                "default",
                config,
                "platforms:\n  telegram:\n    token: 999:plain\n    enabled: true\n  slack:\n    bot_token: ${GRANTED}\nmodel:\n  max_tokens: 4096\n",
                &grants,
            ),
        ];
        let found = findings(&files);
        assert_eq!(
            found,
            [
                plain(env, 3, variable("TELEGRAM_BOT_TOKEN", false)),
                plain(env, 4, variable("OPENROUTER_API_KEY", false)),
                // Named like no secret, but the policy grants it.
                plain(env, 5, variable("MY_LOGIN", true)),
                plain(config, 3, Held::Key("token".into())),
            ]
        );
        let shown = format!("{found:?}");
        for value in ["999:plain", "sk-x", "hunter2"] {
            assert!(!shown.contains(value), "{shown}");
        }
    }

    /// A reference the policy does not grant is found once per file; one
    /// the policy grants, enclos sets, or a `.env` sets is not.
    #[test]
    fn a_reference_the_policy_does_not_grant_is_found_once_per_file() {
        let config = ".hermes/profiles/main/config.yaml";
        let files = vec![
            file(
                "main",
                ".hermes/profiles/main/.env",
                "FROM_ENV=x\nALIAS=${FROM_ENV}\n",
                &[],
            ),
            file(
                "main",
                config,
                "# token: ${IN_A_COMMENT}\ntoken: ${MISSING}\nagain: ${MISSING}\nok: ${GRANTED}\nhome: ${HOME}/x\nenv: ${FROM_ENV} ${ALIAS}\nother: ${OTHER}\nnoted: 1 # ${IN_A_NOTE}\n",
                &["GRANTED"],
            ),
        ];
        assert_eq!(
            findings(&files),
            [
                not_granted("main", config, 2, "MISSING"),
                not_granted("main", config, 7, "OTHER")
            ]
        );
    }

    /// What the policy grants one agent is granted in that agent's files
    /// alone: in another's it is not, and held there in plain text it counts
    /// as a name, not as a grant.
    #[test]
    fn a_secret_granted_to_one_agent_is_granted_in_its_files_alone() {
        let main = ".hermes/profiles/main/config.yaml";
        let scout = ".hermes/profiles/scout/config.yaml";
        let files = vec![
            file("main", main, "token: ${MAIN_BOT}\n", &["MAIN_BOT"]),
            file("scout", scout, "token: ${MAIN_BOT}\n", &[]),
        ];
        assert_eq!(
            findings(&files),
            [not_granted("scout", scout, 1, "MAIN_BOT")]
        );
    }

    /// A reference on a line with no key, such as a list item, counts.
    #[test]
    fn a_reference_in_a_list_item_is_found() {
        let config = ".hermes/config.yaml";
        let files = vec![file("default", config, "items:\n  - ${MISSING}\n", &[])];
        assert_eq!(
            findings(&files),
            [not_granted("default", config, 2, "MISSING")]
        );
    }

    /// A variable a `.env` leaves empty is not set by it.
    #[test]
    fn a_dotenv_line_with_no_value_sets_nothing() {
        let config = ".hermes/config.yaml";
        let files = vec![
            file("default", ".hermes/.env", "FOO=\n", &[]),
            file("default", config, "a: ${FOO}\n", &[]),
        ];
        assert_eq!(findings(&files), [not_granted("default", config, 1, "FOO")]);
    }

    /// Hermes keeps each profile's `.env` apart: what one agent's sets is
    /// not set for another.
    #[test]
    fn a_dotenv_sets_a_variable_for_its_own_agent_alone() {
        let scout = ".hermes/profiles/scout/config.yaml";
        let files = vec![
            file("main", ".hermes/profiles/main/.env", "FOO=x\n", &[]),
            file(
                "main",
                ".hermes/profiles/main/config.yaml",
                "a: ${FOO}\n",
                &[],
            ),
            file("scout", scout, "a: ${FOO}\n", &[]),
        ];
        assert_eq!(findings(&files), [not_granted("scout", scout, 1, "FOO")]);
    }

    /// YAML's markers are values in a `.env`: a password that starts with
    /// one is found.
    #[test]
    fn a_dotenv_value_that_looks_like_yaml_is_still_a_value() {
        let env = ".hermes/.env";
        let files = vec![file("default", env, "SMTP_PASSWORD=!hunter2\n", &[])];
        assert_eq!(
            findings(&files),
            [plain(env, 1, variable("SMTP_PASSWORD", false))]
        );
    }

    /// A value in plain text that holds what looks like a reference is
    /// reported as a value, and nothing of it is taken for a variable's
    /// name, which `doctor` would print.
    #[test]
    fn a_value_in_plain_text_gives_no_reference() {
        let env = ".hermes/.env";
        let files = vec![file("default", env, "DB_PASSWORD=ab${Cd3f}gh\n", &[])];
        assert_eq!(
            findings(&files),
            [plain(env, 1, variable("DB_PASSWORD", false))]
        );
    }

    /// The same `.env` parser `runtime configure` refuses a plain token with.
    #[test]
    fn a_dotenv_line_gives_its_variable_and_value() {
        assert_eq!(dotenv_line("  export T = 'x' "), Some(("T", "'x'")));
        assert_eq!(dotenv_line("T="), Some(("T", "")));
        assert_eq!(dotenv_line("# T=x"), None);
        assert_eq!(dotenv_line("not a line"), None);
    }
}
