//! Keeps `docs/design.md` true to CLAUDE.md's rule that proposed and decided
//! statements stay apart: an ADR with `status: proposed` is never presented
//! as decided.

use std::fs;
use std::path::Path;

fn design() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/design.md")).unwrap()
}

/// The file names under `docs/adr/` whose front matter says `status: proposed`.
fn proposed_adrs() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/adr");
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            fs::read_to_string(entry.path())
                .unwrap()
                .lines()
                .any(|line| line == "status: proposed")
        })
        .map(|entry| entry.file_name().into_string().unwrap())
        .collect()
}

#[test]
fn the_decided_list_names_no_proposed_adr() {
    let design = design();
    let decided = design
        .lines()
        .find(|line| line.starts_with("Decided since the first draft"))
        .expect("§15's decided list");
    let proposed = proposed_adrs();
    assert!(!proposed.is_empty());
    for adr in proposed {
        assert!(!decided.contains(&adr), "{adr} is proposed: {decided}");
    }
}

#[test]
fn a_line_citing_a_proposed_adr_says_it_is_proposed() {
    let design = design();
    let proposed = proposed_adrs();
    let unmarked: Vec<&str> = design
        .lines()
        .filter(|line| proposed.iter().any(|adr| line.contains(adr.as_str())))
        .filter(|line| !line.to_lowercase().contains("proposed"))
        .collect();
    assert!(unmarked.is_empty(), "{unmarked:#?}");
}

/// Every Markdown file under `docs/`, its path relative to `docs/`.
fn docs_markdown() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs");
    let mut found = Vec::new();
    let mut dirs = vec![root.clone()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|ext| ext == "md") {
                let name = path.strip_prefix(&root).unwrap().display().to_string();
                found.push((name, fs::read_to_string(&path).unwrap()));
            }
        }
    }
    found
}

#[test]
fn the_verdict_on_a_field_not_enforced_is_spelled_out_in_one_document() {
    // A proposed output format copied into several documents drifts; the
    // others name the rule and point to the one that gives it.
    let spelled_out: Vec<String> = docs_markdown()
        .into_iter()
        .filter(|(_, text)| text.contains("field not enforced: ") || text.contains("not_enforced"))
        .map(|(name, _)| name)
        .collect();
    assert_eq!(spelled_out.len(), 1, "{spelled_out:?}");
}

#[test]
fn the_design_cites_no_ci_run() {
    // A run's evidence lives in the prototype's README, beside its source;
    // the design states the result once and points there.
    let design = design();
    let runs: Vec<&str> = design
        .lines()
        .filter(|line| line.contains("/actions/runs/"))
        .map(|line| line.get(..80).unwrap_or(line))
        .collect();
    assert!(runs.is_empty(), "{runs:#?}");
}
