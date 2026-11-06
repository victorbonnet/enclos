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

/// Every Markdown file of the plugin, with its path.
fn markdown(dir: &Path, found: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            markdown(&path, found);
        } else if path.extension().is_some_and(|e| e == "md") {
            found.push(path);
        }
    }
}

/// GitHub's anchor for a heading: lowercase, spaces to hyphens, and only
/// letters, digits, hyphens and underscores kept.
fn anchor(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
            _ => None,
        })
        .collect()
}

fn anchors(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.strip_prefix('#'))
        .map(|l| anchor(l.trim_start_matches('#')))
        .collect()
}

/// The skill points the assistant from file to file: a link that leads
/// nowhere would leave it without the step it was sent for.
#[test]
fn every_link_inside_the_plugin_leads_somewhere() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugins/enclos");
    let mut files = Vec::new();
    markdown(&root, &mut files);
    let mut broken = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).unwrap();
        for (i, _) in text.match_indices("](") {
            let target = &text[i + 2..];
            let target = &target[..target.find(')').unwrap()];
            if target.starts_with("http") {
                continue;
            }
            let (path, fragment) = target.split_once('#').unwrap_or((target, ""));
            let linked = if path.is_empty() {
                file.clone()
            } else {
                file.parent().unwrap().join(path)
            };
            let Ok(linked_text) = fs::read_to_string(&linked) else {
                broken.push(format!("{}: {target}", file.display()));
                continue;
            };
            if !fragment.is_empty() && !anchors(&linked_text).iter().any(|a| a == fragment) {
                broken.push(format!("{}: {target}", file.display()));
            }
        }
    }
    assert!(broken.is_empty(), "links that lead nowhere: {broken:#?}");
}

#[test]
fn the_codex_manifest_names_its_skills() {
    // Codex finds a plugin's skills only through this field.
    assert_eq!(json(CODEX)["skills"], "./skills");
    let skill = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugins/enclos/skills/enclos/SKILL.md");
    assert!(skill.is_file(), "{}", skill.display());
}
