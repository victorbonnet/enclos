//! `config.toml`: host-wide settings. Only written by `enclos init` so far;
//! reading it comes with the first setting a command uses.

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
}
