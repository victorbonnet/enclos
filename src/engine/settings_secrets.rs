//! Secrets in a runtime's settings files in the sandbox home, which `enclos
//! doctor` reports (design §10, ADR 0036, proposed): a value written there
//! in plain text, which every agent of the sandbox and any backup of the
//! home reads (ADR 0022), and a `${VAR}` reference to a variable the active
//! policy does not grant. Whatever wrote them: the runtime's own setup, a
//! person through `enclos connect`, or `runtime configure`. Only names and
//! line numbers are kept, never a value.

use std::collections::BTreeSet;

use super::Engine;
use super::restart::MAX_SETTINGS;
use crate::model::sandbox::SandboxRecord;
use crate::model::secret::{is_variable_name, reserved_variable};
use crate::runtime::home::read_text;
use crate::runtime::{HomePath, adapter};

/// A secret found in a runtime's settings files. `line` counts from 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsFinding {
    /// The line sets `held` to a value in plain text: a variable the active
    /// policy grants (`granted`), or a name that says it holds a secret.
    Plain {
        file: HomePath,
        line: usize,
        held: Held,
        granted: bool,
    },
    /// The line refers to `${variable}`, which the active policy does not
    /// grant and no `.env` among the files sets: nothing enclos gives the
    /// sandbox sets it.
    NotGranted {
        file: HomePath,
        line: usize,
        variable: String,
    },
}

/// What a settings line sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Held {
    /// A variable of a `.env` file.
    Variable(String),
    /// A key of a YAML file, as written on its line (`token`, not the
    /// dotted path above it).
    Key(String),
}

/// The last word of a name that says it holds a secret, words split at
/// `_`, `-` and `.`, any case: `TELEGRAM_BOT_TOKEN`, `api_key`.
const SECRET_WORDS: [&str; 6] = ["token", "key", "secret", "password", "passwd", "apikey"];

fn names_a_secret(name: &str) -> bool {
    name.rsplit(['_', '-', '.'])
        .next()
        .is_some_and(|last| SECRET_WORDS.contains(&last.to_ascii_lowercase().as_str()))
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
    let value = match value.starts_with(['"', '\'']) {
        true => value,
        false => value.split(" #").next().unwrap_or("").trim_end(),
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

/// Whether `value` holds a value of its own: not empty, not YAML's null or
/// a boolean, not a mapping, list, block or alias whose value is elsewhere,
/// and not only a `${VAR}` reference.
fn holds_a_value(value: &str) -> bool {
    let inner = unquoted(value).trim();
    let reference = inner
        .strip_prefix("${")
        .and_then(|v| v.strip_suffix('}'))
        .is_some_and(is_variable_name);
    !inner.is_empty()
        && !reference
        && !matches!(inner, "~" | "null" | "true" | "false")
        && !(value == inner && inner.starts_with(['{', '[', '|', '>', '&', '*', '!']))
}

/// The variables `${NAME}` refers to on `line`, in order.
fn references(line: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find("${") {
        rest = &rest[start + 2..];
        if let Some(end) = rest.find('}')
            && is_variable_name(&rest[..end])
        {
            found.push(&rest[..end]);
            rest = &rest[end + 1..];
        }
    }
    found
}

fn is_dotenv(file: &HomePath) -> bool {
    file.as_path().file_name().is_some_and(|n| n == ".env")
}

/// The secrets found in `files`, each a settings file and its text, given
/// the variables the active policy grants. A `.env` file is read as
/// `NAME=value` lines, any other as YAML, line by line: a value spread over
/// several lines is not looked at.
pub fn findings(files: &[(HomePath, String)], granted: &BTreeSet<String>) -> Vec<SettingsFinding> {
    let comment = |line: &str| line.trim_start().starts_with('#');
    // A variable a `.env` sets is in the runtime's environment, whatever
    // the policy grants.
    let set: BTreeSet<&str> = files
        .iter()
        .filter(|(file, _)| is_dotenv(file))
        .flat_map(|(_, text)| text.lines().filter_map(dotenv_line))
        .filter(|(_, value)| !unquoted(value).trim().is_empty())
        .map(|(name, _)| name)
        .collect();
    let mut found = Vec::new();
    for (file, text) in files {
        let mut referred: BTreeSet<&str> = BTreeSet::new();
        for (n, line) in text.lines().enumerate() {
            if comment(line) {
                continue;
            }
            let line_no = n + 1;
            let held = match is_dotenv(file) {
                true => dotenv_line(line).map(|(name, value)| {
                    let granted = granted.contains(name);
                    let plain = holds_a_value(value) && (granted || names_a_secret(name));
                    (plain, Held::Variable(name.to_owned()), granted)
                }),
                false => yaml_line(line).map(|(key, value)| {
                    let plain = holds_a_value(value) && names_a_secret(key);
                    (plain, Held::Key(key.to_owned()), false)
                }),
            };
            if let Some((true, held, granted)) = held {
                found.push(SettingsFinding::Plain {
                    file: file.clone(),
                    line: line_no,
                    held,
                    granted,
                });
            }
            for variable in references(line) {
                let given = granted.contains(variable)
                    || reserved_variable(variable)
                    || set.contains(variable);
                // Each variable once per file, at its first line.
                if !given && referred.insert(variable) {
                    found.push(SettingsFinding::NotGranted {
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
    /// The secrets found in the settings files of the sandbox's runtime,
    /// for its built-in agent and every agent the runtime has (ADR 0031's
    /// files), read as other files of the home are (ADR 0023). What could
    /// not be read is in `unreadable`; a sandbox without a runtime has
    /// nothing to look at.
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
        let granted: BTreeSet<String> = match self.policy(name) {
            Ok(view) => view.snapshot.policy.secrets.keys().cloned().collect(),
            Err(e) => {
                unreadable.push(format!(
                    "did not look for secrets in {}'s settings: cannot read its active policy: {e}",
                    kind.display_name()
                ));
                return Vec::new();
            }
        };
        let home = self.sandbox_home(name);
        let agents = runtime.agents_in(&home).unwrap_or_else(|e| {
            unreadable.push(format!(
                "looked for secrets in the built-in agent's settings only: cannot list {}'s agents: {e}",
                kind.display_name()
            ));
            Vec::new()
        });
        let mut files = Vec::new();
        for file in runtime.settings_files(&agents) {
            match read_text(&home, &file, MAX_SETTINGS) {
                Ok(Some(text)) => files.push((file, text)),
                Ok(None) => {}
                Err(e) => unreadable.push(format!("did not look for secrets in {file}: {e}")),
            }
        }
        findings(&files, &granted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(path: &str) -> HomePath {
        HomePath::new(path).unwrap()
    }

    fn granted(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    fn plain(file: &str, line: usize, held: Held, granted: bool) -> SettingsFinding {
        SettingsFinding::Plain {
            file: at(file),
            line,
            held,
            granted,
        }
    }

    fn not_granted(file: &str, line: usize, variable: &str) -> SettingsFinding {
        SettingsFinding::NotGranted {
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
            assert!(holds_a_value(value), "{value:?}");
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
            "{}",
            "[a]",
            "|",
            ">-",
            "&anchor",
            "*alias",
            "!secret",
        ] {
            assert!(!holds_a_value(nothing), "{nothing:?}");
        }
    }

    #[test]
    fn a_yaml_line_gives_its_key_and_value_without_its_comment() {
        assert_eq!(yaml_line("  token: abc # mine"), Some(("token", "abc")));
        assert_eq!(
            yaml_line("- api_key: \"a #b\""),
            Some(("api_key", "\"a #b\""))
        );
        assert_eq!(yaml_line("telegram:"), Some(("telegram", "")));
        assert_eq!(yaml_line("url: http://x"), Some(("url", "http://x")));
        assert_eq!(yaml_line("http://x"), None);
        assert_eq!(yaml_line("a b: c"), None);
        assert_eq!(yaml_line("- item"), None);
    }

    #[test]
    fn references_are_found_in_order_and_only_to_variables() {
        assert_eq!(references("a ${A} b ${B_2}"), ["A", "B_2"]);
        assert_eq!(references("${} ${1X} ${A-b} $C ${D"), Vec::<&str>::new());
    }

    /// A secret written in plain text is found by the policy's grant or its
    /// name, in `.env` and in YAML; the value is never kept.
    #[test]
    fn a_secret_in_plain_text_is_found_and_its_value_never_kept() {
        let env = ".hermes/.env";
        let config = ".hermes/config.yaml";
        let files = vec![
            (
                at(env),
                "# TELEGRAM_BOT_TOKEN=commented\nTELEGRAM_ALLOWED_USERS=111\nexport TELEGRAM_BOT_TOKEN=\"999:plain\"\nOPENROUTER_API_KEY=sk-x\nMY_LOGIN=hunter2\nEMPTY_TOKEN=\nREF_TOKEN=${GRANTED}\n".to_owned(),
            ),
            (
                at(config),
                "platforms:\n  telegram:\n    token: 999:plain\n    enabled: true\n  slack:\n    bot_token: ${GRANTED}\nmodel:\n  max_tokens: 4096\n".to_owned(),
            ),
        ];
        let found = findings(&files, &granted(&["GRANTED", "MY_LOGIN"]));
        assert_eq!(
            found,
            [
                plain(env, 3, Held::Variable("TELEGRAM_BOT_TOKEN".into()), false),
                plain(env, 4, Held::Variable("OPENROUTER_API_KEY".into()), false),
                // Named like no secret, but the policy grants it.
                plain(env, 5, Held::Variable("MY_LOGIN".into()), true),
                plain(config, 3, Held::Key("token".into()), false),
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
            (at(".hermes/.env"), "FROM_ENV=x\nALIAS=${FROM_ENV}\n".to_owned()),
            (
                at(config),
                "# token: ${IN_A_COMMENT}\ntoken: ${MISSING}\nagain: ${MISSING}\nok: ${GRANTED}\nhome: ${HOME}/x\nenv: ${FROM_ENV} ${ALIAS}\nother: ${OTHER}\n".to_owned(),
            ),
        ];
        assert_eq!(
            findings(&files, &granted(&["GRANTED"])),
            [
                not_granted(config, 2, "MISSING"),
                not_granted(config, 7, "OTHER")
            ]
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
