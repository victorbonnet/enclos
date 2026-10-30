//! Keeps `docs/design.md` true to CLAUDE.md's rule that proposed and decided
//! statements stay apart: an ADR with `status: proposed` is never presented
//! as decided.

use std::fs;
use std::path::Path;

fn design() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/design.md")).unwrap()
}

fn adr(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs/adr")
        .join(name);
    fs::read_to_string(path).unwrap()
}

const ADR_0037: &str = "0037-landlock-where-the-kernel-has-it.md";
const ADR_0038: &str = "0038-a-memory-limit-the-host-cannot-hold-runs-unapplied-once-accepted.md";

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

#[test]
fn adr_0038_gives_the_verdict_on_a_field_not_enforced() {
    let adr = adr(ADR_0038);
    for rule in [
        "`READY, 1 field not enforced: memory (accepted)`",
        "`ready: true` and a `not_enforced` list with each field, reason and acceptance",
        "no recorded acceptance, or whose acceptance no longer matches the field's value, is `NOT READY`",
        "A host with no Landlock and no `[exec]` section stays `READY` and prints one line naming the degraded control",
    ] {
        assert!(adr.contains(rule), "{rule}");
    }
}

#[test]
fn adr_0037_points_to_the_verdict_in_adr_0038() {
    assert!(adr(ADR_0037).contains("`policy test`'s verdict follows 0038's rule"));
}
