//! Facts read from the sandbox home, which the sandbox writes: whether a
//! file is there, when it changed, and a value in it. "Cannot tell", with
//! why, is an answer (ADR 0023).

use std::path::Path;

use rustix::fs::Stat;

use super::{Fact, printable};
use crate::model::Timestamp;
use crate::runtime::home::{self, wide};
use crate::runtime::{HomePath, ValueAt};

/// The largest file of the sandbox home read for a fact.
const MAX_FACT_FILE: u64 = 256 * 1024;

pub(super) fn exists(home: &Path, rel: &HomePath) -> Fact<bool> {
    match home::stat(home, rel) {
        Ok(found) => Fact::Known(found.is_some()),
        Err(why) => Fact::CannotTell(why.to_string()),
    }
}

/// When `stat` says the entry last changed.
fn mtime(stat: &Stat) -> Option<Timestamp> {
    let seconds = i64::try_from(wide(stat.st_mtime)).ok()?;
    let nanos = i32::try_from(wide(stat.st_mtime_nsec)).ok()?;
    Timestamp::new(seconds, nanos).ok()
}

/// The newest change among `files`: absent when none exists, and "cannot
/// tell" when none could be read and one could not.
pub(super) fn newest(home: &Path, files: &[HomePath]) -> Fact<Timestamp> {
    if files.is_empty() {
        return Fact::NotProvided;
    }
    let mut newest = None;
    let mut cannot = None;
    for file in files {
        match home::stat(home, file) {
            Ok(Some(stat)) => match mtime(&stat) {
                Some(t) => newest = newest.max(Some(t)),
                None => cannot = cannot.or(Some(format!("{file}: a time enclos cannot read"))),
            },
            Ok(None) => {}
            Err(why) => cannot = cannot.or(Some(why.to_string())),
        }
    }
    match (newest, cannot) {
        (Some(t), _) => Fact::Known(t),
        (None, Some(why)) => Fact::CannotTell(why),
        (None, None) => Fact::Absent,
    }
}

/// A value from a small YAML file of the home, made safe to print.
pub(super) fn read_value(home: &Path, at: &ValueAt) -> Fact<String> {
    let text = match home::read_text(home, &at.file, MAX_FACT_FILE) {
        Ok(Some(text)) => text,
        Ok(None) => return Fact::Absent,
        Err(why) => return Fact::CannotTell(why.to_string()),
    };
    for key in at.keys {
        match yaml_value(&text, key) {
            Yaml::Found(v) => return Fact::Known(printable(&v)),
            Yaml::Missing => {}
            Yaml::Unsure => {
                return Fact::CannotTell(format!(
                    "{}: `{key}` is written in YAML enclos does not read",
                    at.file
                ));
            }
        }
    }
    Fact::Absent
}

/// What [`yaml_value`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Yaml {
    Found(String),
    Missing,
    /// The file uses YAML this reader does not handle, there or around the
    /// key, so any answer would be a guess.
    Unsure,
}

/// A scalar under a dotted key of a YAML mapping, such as `model.default`.
/// Enough YAML for a runtime's config: block mappings nested by spaces,
/// plain or quoted one-line scalars, and comments. Sequences and block
/// scalars are skipped whole. A tab in the indentation, a key given twice,
/// and a value that is a block scalar, an anchor, an alias, a tag, a flow
/// collection or a quoted scalar with escapes answer `Unsure`.
pub(super) fn yaml_value(text: &str, key: &str) -> Yaml {
    let want: Vec<&str> = key.split('.').collect();
    let mut path: Vec<(usize, String)> = Vec::new();
    // Lines deeper than this belong to a sequence or a block scalar.
    let mut skip_deeper: Option<usize> = None;
    let mut found = None;
    for line in text.lines() {
        let trimmed = line.trim_start_matches(' ');
        let indent = line.len() - trimmed.len();
        if trimmed.starts_with('\t') {
            return Yaml::Unsure;
        }
        let content = trimmed.trim_end();
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        if let Some(limit) = skip_deeper {
            if indent > limit {
                continue;
            }
            skip_deeper = None;
        }
        match content {
            "---" => continue,
            "..." => break,
            _ => {}
        }
        if content == "-" || content.starts_with("- ") {
            skip_deeper = Some(indent);
            continue;
        }
        let (k, rest) = match content.split_once(": ") {
            Some(pair) => pair,
            None => match content.strip_suffix(':') {
                Some(k) => (k, ""),
                // Not `key: value`: the rest of a scalar.
                None => continue,
            },
        };
        let k = k.trim().trim_matches(|c| c == '"' || c == '\'');
        while path.last().is_some_and(|(i, _)| *i >= indent) {
            path.pop();
        }
        path.push((indent, k.to_owned()));
        let rest = rest.trim();
        if rest.starts_with('|') || rest.starts_with('>') {
            skip_deeper = Some(indent);
        }
        if path
            .iter()
            .map(|(_, k)| k.as_str())
            .eq(want.iter().copied())
        {
            if found.is_some() {
                return Yaml::Unsure;
            }
            found = Some(scalar(rest));
        }
    }
    found.unwrap_or(Yaml::Missing)
}

/// The value after `key:`, on its line.
fn scalar(rest: &str) -> Yaml {
    let ends_cleanly = |after: &str| {
        let after = after.trim_start();
        after.is_empty() || after.starts_with('#')
    };
    let value = match rest.chars().next() {
        // Nothing, or a comment: the key holds a mapping, or nothing.
        None | Some('#') => return Yaml::Missing,
        Some('|' | '>' | '&' | '*' | '!' | '{' | '[' | '%' | '@' | '`') => return Yaml::Unsure,
        Some('"') => {
            let inner = &rest[1..];
            match inner.find('"') {
                Some(end) if !inner[..end].contains('\\') && ends_cleanly(&inner[end + 1..]) => {
                    &inner[..end]
                }
                _ => return Yaml::Unsure,
            }
        }
        Some('\'') => {
            let inner = &rest[1..];
            match inner.find('\'') {
                // `''` is an escaped quote.
                Some(end) if ends_cleanly(&inner[end + 1..]) => &inner[..end],
                _ => return Yaml::Unsure,
            }
        }
        Some(_) => rest.split(" #").next().unwrap_or("").trim(),
    };
    match value.is_empty() {
        true => Yaml::Missing,
        false => Yaml::Found(value.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &Path, bytes: usize) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, vec![b'x'; bytes]).unwrap();
    }

    fn rel(p: &str) -> HomePath {
        HomePath::new(p).unwrap()
    }

    #[test]
    fn facts_read_from_the_home_say_why_they_cannot_tell() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("config.yaml"),
            "model:\n  default: host\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join("linked")).unwrap();
        let at = |file: &str| ValueAt {
            file: rel(file),
            keys: &["model.default", "model.model"],
        };
        assert_eq!(
            read_value(home.path(), &at("linked/config.yaml")),
            Fact::CannotTell("~/linked is a link".into())
        );
        assert_eq!(
            exists(home.path(), &rel("linked/config.yaml")),
            Fact::CannotTell("~/linked is a link".into())
        );
        assert_eq!(exists(home.path(), &rel("missing")), Fact::Known(false));
        assert_eq!(read_value(home.path(), &at("missing")), Fact::Absent);

        file(&home.path().join("a/config.yaml"), 0);
        std::fs::write(
            home.path().join("a/config.yaml"),
            "x: 1\nmodel:\n  # the model\n  default: \"gpt-6.1\u{1b}[2J\"\n  model: other\nother: 2\n",
        )
        .unwrap();
        // The first key wins, escaped.
        assert_eq!(
            read_value(home.path(), &at("a/config.yaml")),
            Fact::Known("gpt-6.1\\u{1b}[2J".into())
        );
        std::fs::write(home.path().join("a/config.yaml"), "model:\n  model: m2\n").unwrap();
        assert_eq!(
            read_value(home.path(), &at("a/config.yaml")),
            Fact::Known("m2".into())
        );
        std::fs::write(
            home.path().join("a/config.yaml"),
            "model:\n  default: |\n    x\n",
        )
        .unwrap();
        assert!(matches!(
            read_value(home.path(), &at("a/config.yaml")),
            Fact::CannotTell(why) if why.contains("YAML enclos does not read")
        ));
        file(
            &home.path().join("a/big.yaml"),
            (MAX_FACT_FILE + 1) as usize,
        );
        assert!(matches!(
            read_value(home.path(), &at("a/big.yaml")),
            Fact::CannotTell(why) if why.contains("larger than")
        ));

        // The newest activity, or why there is none.
        assert_eq!(newest(home.path(), &[]), Fact::NotProvided);
        assert_eq!(newest(home.path(), &[rel("nope")]), Fact::Absent);
        assert!(matches!(
            newest(home.path(), &[rel("linked/x")]),
            Fact::CannotTell(_)
        ));
        assert!(matches!(
            newest(home.path(), &[rel("linked/x"), rel("a/config.yaml")]),
            Fact::Known(_)
        ));
    }

    #[test]
    fn yaml_values_are_found_by_dotted_key_and_anything_unsure_says_so() {
        let found = |text: &str, key: &str| match yaml_value(text, key) {
            Yaml::Found(v) => Some(v),
            _ => None,
        };
        let text = "model:\n  default: gpt-6.1-sol # comment\n  provider: 'openai'\nother:\n  default: no\n";
        assert_eq!(found(text, "model.default").as_deref(), Some("gpt-6.1-sol"));
        assert_eq!(found(text, "model.provider").as_deref(), Some("openai"));
        assert_eq!(yaml_value(text, "model.missing"), Yaml::Missing);
        assert_eq!(found("model: gpt\n", "model").as_deref(), Some("gpt"));
        // Siblings after a nested mapping, a value with a colon, a `#` in quotes.
        let text = "a:\n  b:\n    c: x\n  d: y\nurl: http://x:1\nq: \"a # b\"\n\"k\": v\n";
        assert_eq!(found(text, "a.d").as_deref(), Some("y"));
        assert_eq!(found(text, "a.b.d"), None);
        assert_eq!(found(text, "url").as_deref(), Some("http://x:1"));
        assert_eq!(found(text, "q").as_deref(), Some("a # b"));
        assert_eq!(found(text, "k").as_deref(), Some("v"));
        // A sequence's items do not count toward the key above them.
        let text = "model:\n  - default: listed\n    x: 1\n  default: real\n";
        assert_eq!(found(text, "model.default").as_deref(), Some("real"));
        // A block scalar's lines are not keys.
        let text = "notes: |\n  default: inside\nmodel:\n  default: m\n";
        assert_eq!(found(text, "model.default").as_deref(), Some("m"));
        assert_eq!(found(text, "default"), None);
        for unsure in [
            "model:\n  default: |\n    x\n",
            "model:\n  default: >\n    x\n",
            "model:\n  default: &a gpt\n",
            "model:\n  default: *a\n",
            "model:\n  default: !!str x\n",
            "model: {default: x}\n",
            "model:\n\tdefault: x\n",
            "model:\n  default: a\n  default: b\n",
            "model:\n  default: \"a\\\"b\"\n",
            "model:\n  default: 'it''s'\n",
        ] {
            assert_eq!(
                yaml_value(unsure, "model.default"),
                if unsure.starts_with("model: {") {
                    Yaml::Missing
                } else {
                    Yaml::Unsure
                },
                "{unsure:?}"
            );
        }
        assert_eq!(yaml_value("model: {default: x}\n", "model"), Yaml::Unsure);
        assert_eq!(
            yaml_value("model:\n  default: # c\n", "model.default"),
            Yaml::Missing
        );
        assert_eq!(
            yaml_value("\"model.default\": x\n", "model.default"),
            Yaml::Missing
        );
    }
}
