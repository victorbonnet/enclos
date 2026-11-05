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

/// The lines of the design from the first line starting with `start` up to,
/// not including, the next line starting with `end`.
fn section<'a>(design: &'a str, start: &str, end: &str) -> Vec<&'a str> {
    design
        .lines()
        .skip_while(|line| !line.starts_with(start))
        .take_while(|line| !line.starts_with(end))
        .collect()
}

/// Whether `line` names a CI run by its number: "run" followed by digits.
fn names_a_run_number(line: &str) -> bool {
    line.split("run ")
        .skip(1)
        .any(|rest| rest.chars().take_while(char::is_ascii_digit).count() >= 6)
}

#[test]
fn milestone_3_awaiting_verification_holds_only_what_is_still_to_show() {
    // A result a prototype showed moves into the section it describes; §14
    // keeps what is still to show, and points to the README for the runs.
    let design = design();
    let milestone_3 = section(&design, "**Milestone 3**", "## 15.");
    assert!(!milestone_3.is_empty(), "§14's milestone 3 list");
    assert!(
        milestone_3[0].contains("Results are in `prototype/m3/README.md`"),
        "{}",
        milestone_3[0]
    );
    let with_results: Vec<&str> = milestone_3
        .iter()
        .copied()
        .filter(|line| {
            line.contains("PR #")
                || line.contains("M3-")
                || line.contains("Shown by")
                || names_a_run_number(line)
        })
        .map(|line| line.get(..100).unwrap_or(line))
        .collect();
    assert!(with_results.is_empty(), "{with_results:#?}");
}

#[test]
fn the_chat_tabs_control_pair_is_recorded_as_measured() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("prototype/m3/README.md");
    let readme = fs::read_to_string(path).unwrap();
    assert!(!readme.contains("Pending run"));
    assert!(!readme.contains("expected to fail as things stand"));
    let table = readme
        .lines()
        .find(|line| line.starts_with("| Question | Ubuntu 24.04 runner, x86_64 | Ubuntu 24.04 runner, arm64 | Ubuntu 26.04"))
        .expect("the control pair's table");
    assert!(table.contains("x86_64 |"), "{table}");
    let design = design();
    let item = design
        .lines()
        .find(|line| line.starts_with("- `enclos dashboard`"))
        .expect("§14's item");
    for part in ["M3-20", "`NO_PROXY` for loopback is needed", "not shown"] {
        assert!(item.contains(part), "{part}");
    }
}

#[test]
fn the_namespaces_text_gives_the_prototypes_answer() {
    let design = design();
    for stale in [
        "no way tried of joining",
        "own network, PID and IPC namespaces",
        "the relayed port",
        "reached from inside the sandbox",
        "will be rewritten before they are accepted",
    ] {
        assert!(!design.contains(stale), "{stale}");
    }
    let adr_0039 = adr("0039-a-bubblewrap-sandbox-has-one-network-namespace-its-sessions-join.md");
    assert!(adr_0039.contains("`nsenter`"));
    assert!(adr_0039.contains("only Landlock's scope separates them"));
    assert!(!adr_0039.contains("Review correction"));
    let adr_0040 = adr("0040-on-linux-enclos-dashboard-opens-a-sandboxs-service-to-its-user.md");
    assert!(adr_0040.contains("`enclos dashboard <sandbox>`"));
    let glossary_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("GLOSSARY.md");
    let glossary = fs::read_to_string(glossary_path).unwrap();
    assert!(!glossary.contains("the session's own 127.0.0.1"));
}

#[test]
fn a_session_sees_run_visible_and_never_the_host_only_folder() {
    let design = design();
    let adr_0039 = adr("0039-a-bubblewrap-sandbox-has-one-network-namespace-its-sessions-join.md");
    for text in [&design, &adr_0039] {
        assert!(!text.contains("reads `run/`"));
        assert!(!text.contains("reads its own `run/`"));
        assert!(text.contains("`run/<sandbox>/visible/`"));
        assert!(text.contains("host-only `run/<sandbox>/`, which no session mounts"));
    }
}

#[test]
fn a_bubblewrap_sandboxs_proxy_leaves_its_reserved_port_to_enclos_dashboard() {
    // `enclos dashboard` listens on the host's 127.0.0.1 at the sandbox's
    // reserved port, so the proxy of a bubblewrap sandbox must not hold it.
    let design = design();
    let adr_0040 = adr("0040-on-linux-enclos-dashboard-opens-a-sandboxs-service-to-its-user.md");
    let find = |start: &str| {
        design
            .lines()
            .find(|line| line.starts_with(start))
            .unwrap_or_else(|| panic!("no line starting with {start}"))
            .to_string()
    };
    let milestone_bullet = find("   - the proxy listening on a Unix socket");
    let network_section = find("**The runtime's own service on Linux**");
    let awaiting_item = find("- `enclos dashboard`");
    for text in [&adr_0040, &milestone_bullet, &network_section] {
        assert!(text.contains("no TCP listener"), "{text}");
    }
    assert!(!milestone_bullet.contains("beside its TCP listener"));
    assert!(awaiting_item.contains("reserved port"), "{awaiting_item}");
}

#[test]
fn an_adrs_consequences_section_holds_only_its_list() {
    // A paragraph after an ADR's consequences sits outside its structure and
    // can decide what its Decision section does not.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/adr");
    let mut stray = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let text = fs::read_to_string(&path).unwrap();
        let after = text
            .lines()
            .skip_while(|line| *line != "## Consequences")
            .skip(1)
            .take_while(|line| !line.starts_with("## "));
        for line in after {
            let in_list = line.trim().is_empty()
                || line.starts_with("- ")
                || line.starts_with("  ")
                || line.ends_with(':');
            if !in_list {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                stray.push(format!("{name}: {}", line.get(..60).unwrap_or(line)));
            }
        }
    }
    assert!(stray.is_empty(), "{stray:#?}");
}

#[test]
fn the_relay_has_one_runner_and_the_holders_part_is_proposed() {
    // ADR 0039, proposed, gives the relay to the namespace holder; until it
    // is accepted, the design cites it where it says so and keeps the case
    // where a session runs its relay.
    let design = design();
    let find = |start: &str| {
        design
            .lines()
            .find(|line| line.starts_with(start))
            .unwrap_or_else(|| panic!("no line starting with {start}"))
            .to_string()
    };
    let networking = find("**Linux networking.**");
    assert!(networking.contains("adr/0039-"), "{networking}");
    assert!(networking.contains("kill or replace its relay"), "{networking}");
    let backend = find("   - the bubblewrap backend");
    assert!(!backend.contains("relay"), "{backend}");
    let proxy = find("   - the proxy listening on a Unix socket");
    assert!(proxy.contains("holder, which runs the relay"), "{proxy}");
}

#[test]
fn the_design_ends_with_the_open_decisions_and_lays_out_every_run_folder() {
    // Nothing after §15's table makes decisions outside it, and every folder
    // under `run/<sandbox>/` the design names is in §11's layout.
    let design = design();
    let last = design.lines().rev().find(|line| !line.trim().is_empty());
    assert!(last.is_some_and(|line| line.starts_with('|')), "{last:?}");
    let layout = section(&design, "## 11.", "## 12.").join("\n");
    let marker = "run/<sandbox>/";
    for line in design.lines() {
        for rest in line.split(marker).skip(1) {
            let sub: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                .collect();
            if !sub.is_empty() {
                assert!(
                    layout.contains(&format!("{sub}/")),
                    "{marker}{sub} not in §11"
                );
            }
        }
    }
}
