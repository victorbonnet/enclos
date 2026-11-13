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

/// The files written by hand, as opposed to the generated references.
fn written_by_hand() -> Vec<(std::path::PathBuf, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugins/enclos");
    let mut files = Vec::new();
    markdown(&root, &mut files);
    files
        .into_iter()
        .filter(|f| !f.ends_with("reference/commands.md") && !f.ends_with("reference/policy.md"))
        .map(|f| {
            let text = fs::read_to_string(&f).unwrap();
            (f, text)
        })
        .collect()
}

/// A Linux host or an `ENCLOS_HOME` keeps enclos's files elsewhere: a path
/// built on `~/.enclos/` would read another install's files, or none.
#[test]
fn no_path_assumes_the_macos_data_folder() {
    for (file, text) in written_by_hand() {
        assert!(!text.contains("~/.enclos/"), "{}", file.display());
    }
}

/// A runtime that listens can be reached outside the proxy (ADR 0028): the
/// skill says so, and nothing calls the proxy a sandbox's only way out.
#[test]
fn the_listening_exception_is_said() {
    for (file, text) in written_by_hand() {
        assert!(!text.contains("only way out"), "{}", file.display());
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugins/enclos/skills/enclos");
    let skill = fs::read_to_string(root.join("SKILL.md")).unwrap();
    assert!(skill.contains("**The exception: listening.**"));
    let gaps = fs::read_to_string(root.join("reference/troubleshooting.md")).unwrap();
    assert!(gaps.contains("- **Listening:**"));
}

/// A private host the policy allows and names in `private` is reachable
/// (ADR 0017): no line promises the local network is out of reach without
/// naming that opt-in.
#[test]
fn the_local_network_names_the_private_opt_in() {
    for (file, text) in written_by_hand() {
        for line in text.lines().filter(|l| l.contains("local network")) {
            assert!(line.contains("`private`"), "{}: {line}", file.display());
        }
    }
}

/// A running gateway does not show that the provider and the model work
/// (#171): setup sends one message through `exec`, in the step that starts
/// the sandbox, and its summary reports the answer.
#[test]
fn setup_checks_the_agent_answers_through_exec() {
    let setup = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("plugins/enclos/skills/setup/SKILL.md"),
    )
    .unwrap();
    let run = &setup[setup.find("## 9. Run it").unwrap()..setup.find("## 10.").unwrap()];
    assert!(run.contains("**Check that the agent answers.**"));
    assert!(run.contains("enclos exec <sandbox> -- hermes chat --help"));
    assert!(run.contains("`-p <agent>`"));
    assert!(setup.contains("whether the agent answered through `exec`"));
}

/// The manual end-to-end test removes its home in §15: the plugin's section
/// must make its own, or an assistant runs on the user's real state (#172).
#[test]
fn the_plugin_e2e_section_makes_its_own_throwaway_home() {
    let e2e = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/manual-e2e.md"))
        .unwrap();
    let cleanup = e2e.find("## 15. Remove everything").unwrap();
    let plugin = e2e.find("## 17. The enclos plugin").unwrap();
    assert!(cleanup < plugin);
    let section = &e2e[plugin..e2e.find("## Known gaps").unwrap()];
    let home = section.find("export ENCLOS_HOME=").unwrap();
    let first_prompt = section.find("1. \"What is enclos").unwrap();
    assert!(
        home < first_prompt,
        "the home is set before any assistant runs"
    );
    assert!(
        section.contains("NOTES.md"),
        "the section makes its own fixtures"
    );
    assert!(
        section.contains("`data` is `$ENCLOS_HOME`"),
        "each assistant is checked against it"
    );
    assert!(
        section.contains("rm -rf \"$ENCLOS_HOME\"; unset ENCLOS_HOME"),
        "and it cleans up"
    );
}

#[test]
fn the_codex_manifest_names_its_skills() {
    // Codex finds a plugin's skills only through this field.
    assert_eq!(json(CODEX)["skills"], "./skills");
    let skill = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugins/enclos/skills/enclos/SKILL.md");
    assert!(skill.is_file(), "{}", skill.display());
}
