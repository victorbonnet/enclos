//! Keeps the enclos plugin (`plugins/enclos/`) loadable by both host
//! assistants and in step with the crate: one name and one version across
//! the marketplace and both manifests, and the version is enclos's own.

use std::fs;
use std::path::Path;

use serde_json::Value;

fn json(path: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

const CLAUDE: &str = "plugins/enclos/.claude-plugin/plugin.json";
const CODEX: &str = "plugins/enclos/.codex-plugin/plugin.json";

#[test]
fn both_manifests_carry_the_crates_version() {
    for manifest in [CLAUDE, CODEX] {
        assert_eq!(
            json(manifest)["version"],
            env!("CARGO_PKG_VERSION"),
            "{manifest}: set the plugin's version with the crate's (docs/releases.md)"
        );
    }
}

#[test]
fn the_marketplace_lists_the_plugin_by_its_manifests_name() {
    let marketplace = json(".claude-plugin/marketplace.json");
    let plugins = marketplace["plugins"].as_array().unwrap();
    assert_eq!(plugins.len(), 1);
    assert_eq!(plugins[0]["source"], "./plugins/enclos");
    for manifest in [CLAUDE, CODEX] {
        assert_eq!(plugins[0]["name"], json(manifest)["name"], "{manifest}");
    }
}

#[test]
fn the_codex_manifest_names_its_skills() {
    // Codex finds a plugin's skills only through this field.
    assert_eq!(json(CODEX)["skills"], "./skills");
    let skill = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugins/enclos/skills/enclos/SKILL.md");
    assert!(skill.is_file(), "{}", skill.display());
}
