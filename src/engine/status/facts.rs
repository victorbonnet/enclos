//! Facts read from the sandbox home, which the sandbox writes: whether a
//! file is there, when it changed, and a value in it. "Cannot tell", with
//! why, is an answer (ADR 0023).

use std::path::Path;

use rustix::fs::Stat;

use super::{Fact, printable};
use crate::model::Timestamp;
use crate::runtime::home::{self, wide};
use crate::runtime::{HomePath, ProviderAt, RuntimeAdapter, ValueAt};

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

/// Read a bounded home file, ask its runtime to interpret it, and make the
/// result safe to print. The engine knows no native configuration format.
pub(super) fn read_value(home: &Path, at: &ValueAt, runtime: &dyn RuntimeAdapter) -> Fact<String> {
    let text = match home::read_text(home, &at.file, MAX_FACT_FILE) {
        Ok(Some(text)) => text,
        Ok(None) => return Fact::Absent,
        Err(why) => return Fact::CannotTell(why.to_string()),
    };
    match runtime.fact_value(at, &text) {
        Ok(Some(value)) => Fact::Known(printable(&value)),
        Ok(None) => Fact::Absent,
        Err(why) => Fact::CannotTell(format!("{}: {}", at.file, printable(&why))),
    }
}

/// An agent's provider, as its settings name it, and, when that means it
/// has none chosen, what a person runs in the sandbox to choose one.
pub(in crate::engine) fn read_provider(
    home: &Path,
    at: Option<&ProviderAt>,
    runtime: &dyn RuntimeAdapter,
) -> (Fact<String>, Option<String>) {
    let Some(at) = at else {
        return (Fact::NotProvided, None);
    };
    let value = read_value(home, &at.at, runtime);
    let choose = match &value {
        Fact::Known(v) if at.unchosen.contains(&v.trim()) => Some(at.choose.clone()),
        _ => None,
    };
    (value, choose)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::hermes::Hermes;

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
            keys: vec!["model.default".into(), "model.model".into()],
        };
        assert_eq!(
            read_value(home.path(), &at("linked/config.yaml"), &Hermes),
            Fact::CannotTell("~/linked is a link".into())
        );
        assert_eq!(
            exists(home.path(), &rel("linked/config.yaml")),
            Fact::CannotTell("~/linked is a link".into())
        );
        assert_eq!(exists(home.path(), &rel("missing")), Fact::Known(false));
        assert_eq!(
            read_value(home.path(), &at("missing"), &Hermes),
            Fact::Absent
        );

        file(&home.path().join("a/config.yaml"), 0);
        std::fs::write(
            home.path().join("a/config.yaml"),
            "x: 1\nmodel:\n  # the model\n  default: \"gpt-6.1\u{1b}[2J\"\n  model: other\nother: 2\n",
        )
        .unwrap();
        // The first key wins, escaped.
        assert_eq!(
            read_value(home.path(), &at("a/config.yaml"), &Hermes),
            Fact::Known("gpt-6.1\\u{1b}[2J".into())
        );
        std::fs::write(home.path().join("a/config.yaml"), "model:\n  model: m2\n").unwrap();
        assert_eq!(
            read_value(home.path(), &at("a/config.yaml"), &Hermes),
            Fact::Known("m2".into())
        );
        std::fs::write(
            home.path().join("a/config.yaml"),
            "model:\n  default: |\n    x\n",
        )
        .unwrap();
        assert!(matches!(
            read_value(home.path(), &at("a/config.yaml"), &Hermes),
            Fact::CannotTell(why) if why.contains("YAML enclos does not read")
        ));
        file(
            &home.path().join("a/big.yaml"),
            (MAX_FACT_FILE + 1) as usize,
        );
        assert!(matches!(
            read_value(home.path(), &at("a/big.yaml"), &Hermes),
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
}
