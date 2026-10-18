//! `config.toml`: host-wide settings. Only written by `enclos init` so far;
//! reading it comes with the first setting a command uses.

use crate::model::sandbox::BackendKind;

pub const SCHEMA_VERSION: u32 = 1;

/// The `config.toml` that `enclos init` writes.
pub fn initial(default_backend: Option<BackendKind>) -> String {
    let backend = match default_backend {
        Some(kind) => format!("default_backend = \"{kind}\"\n"),
        None => {
            "# default_backend: no backend in this build of enclos is available on this host yet\n"
                .to_owned()
        }
    };
    format!("# enclos configuration\nschema_version = {SCHEMA_VERSION}\n{backend}")
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
    }
}
