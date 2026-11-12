//! `config.toml`: host-wide settings. Written by `enclos init`; `sandbox
//! create` reads its default backend.

use crate::model::sandbox::BackendKind;

pub const SCHEMA_VERSION: u32 = 1;

/// The line `enclos init` writes in place of `default_backend` while no
/// backend is available.
const NO_BACKEND: &str =
    "# default_backend: no backend in this build of enclos is available on this host yet\n";

/// The `config.toml` that `enclos init` writes.
pub fn initial(default_backend: Option<BackendKind>) -> String {
    let backend = match default_backend {
        Some(kind) => backend_line(kind),
        None => NO_BACKEND.to_owned(),
    };
    format!("# enclos configuration\nschema_version = {SCHEMA_VERSION}\n{backend}")
}

fn backend_line(kind: BackendKind) -> String {
    format!("default_backend = \"{kind}\"\n")
}

/// What an existing `config.toml`'s text says of the default backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendNamed {
    Named,
    /// It names none, and holds the line `enclos init` writes while none is
    /// available, as it wrote it.
    Placeholder,
    /// It names none, and the placeholder is not there: changed by hand.
    NotNamed,
}

/// Whether `text`, a `config.toml`, names the default backend; why not when
/// it does not parse.
pub fn backend_named(text: &str) -> Result<BackendNamed, String> {
    let table = text.parse::<toml::Table>().map_err(|e| e.to_string())?;
    Ok(
        match (
            table.contains_key("default_backend"),
            text.contains(NO_BACKEND),
        ) {
            (true, _) => BackendNamed::Named,
            (false, true) => BackendNamed::Placeholder,
            (false, false) => BackendNamed::NotNamed,
        },
    )
}

/// The default backend `text`, a `config.toml`, names: none when it names
/// none; why not when it does not parse, or names something else than a
/// backend.
pub fn default_backend(text: &str) -> Result<Option<BackendKind>, String> {
    let table = text.parse::<toml::Table>().map_err(|e| e.to_string())?;
    match table.get("default_backend") {
        None => Ok(None),
        Some(toml::Value::String(name)) => name.parse().map(Some).map_err(|e| format!("{e}")),
        Some(other) => Err(format!(
            "`default_backend` is {}, not the name of a backend",
            other.type_str()
        )),
    }
}

/// `text` with its placeholder line replaced by `kind`, as [`initial`] would
/// have written it.
pub fn with_backend(text: &str, kind: BackendKind) -> String {
    text.replacen(NO_BACKEND, &backend_line(kind), 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_the_schema_version_and_default_backend() {
        let config = initial(Some(BackendKind::Seatbelt));
        assert!(config.contains("schema_version = 1\n"));
        assert!(config.contains("default_backend = \"seatbelt\"\n"));
        assert!(initial(None).contains("# default_backend"));
        let none = initial(None);
        assert_eq!(
            backend_named(&initial(Some(BackendKind::Seatbelt))),
            Ok(BackendNamed::Named)
        );
        assert_eq!(backend_named(&none), Ok(BackendNamed::Placeholder));
        let filled = with_backend(&none, BackendKind::Seatbelt);
        assert_eq!(filled, initial(Some(BackendKind::Seatbelt)));
        let edited = none.replace("# default_backend", "# mine");
        assert_eq!(backend_named(&edited), Ok(BackendNamed::NotNamed));
        assert!(backend_named("not = [toml").is_err());
    }

    #[test]
    fn reads_the_default_backend_it_names() {
        for kind in [BackendKind::Seatbelt, BackendKind::Bubblewrap] {
            assert_eq!(default_backend(&initial(Some(kind))), Ok(Some(kind)));
        }
        assert_eq!(default_backend(&initial(None)), Ok(None));
        assert_eq!(default_backend(""), Ok(None));
        let unknown = default_backend("default_backend = \"jail\"\n").unwrap_err();
        assert!(unknown.contains("unknown backend `jail`"), "{unknown}");
        let number = default_backend("default_backend = 1\n").unwrap_err();
        assert!(number.contains("not the name of a backend"), "{number}");
        assert!(default_backend("not = [toml").is_err());
    }
}
