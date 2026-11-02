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

#[test]
fn principle_6_gives_the_proposed_verdict() {
    let design = design();
    let principle = design
        .lines()
        .find(|line| line.starts_with("6. **Never claim isolation"))
        .expect("§1's principle 6");
    assert!(principle.contains("Proposed for a field the host does not enforce"));
    assert!(principle.contains("`READY, 1 field not enforced: memory (accepted)`"));
    assert!(principle.contains("no longer matches the field's value, it is `NOT READY`"));
}

#[test]
fn acceptance_steps_2_and_5_agree_on_the_verdict() {
    let design = design();
    let step = |start: &str| {
        design
            .lines()
            .skip_while(|line| !line.starts_with("**Acceptance scenario (milestone 3).**"))
            .find(|line| line.starts_with(start))
            .unwrap()
            .to_owned()
    };
    assert!(
        step("2. **The same policy.**")
            .contains("`READY, 1 field not enforced: memory (accepted)`")
    );
    let escape = step("5. **Escape probes.**");
    assert!(escape.contains("is NOT READY"));
    assert!(escape.contains("one line naming the missing Landlock"));
}

#[test]
fn no_open_decision_is_left_on_the_verdict() {
    let design = design();
    assert!(!design.contains("| What `policy test` reports"));
    assert!(!design.contains("gives no verdict"));
}

#[test]
fn the_lingering_row_holds_the_evidence_and_its_recommendation() {
    let design = design();
    let row = design
        .lines()
        .find(|line| line.starts_with("| Sandboxes on a headless Linux host"))
        .expect("§15's row on lingering");
    for text in [
        "without lingering the unit goes with the user manager",
        "with lingering it survives",
        "on x86_64",
        "on arm64",
        "`Linger` was already `yes`",
        "`gone` is what the script prints when the manager is inactive",
        "Recommendation: enclos never turns lingering on itself;",
    ] {
        assert!(row.contains(text), "{text}");
    }
    assert!(design.contains("| Where bubblewrap comes from (milestone 3) |"));
}

#[test]
fn the_host_adrs_stay_proposed() {
    let proposed = proposed_adrs();
    for adr in [ADR_0037, ADR_0038] {
        assert!(proposed.iter().any(|name| name == adr), "{adr}");
    }
}

#[test]
fn the_host_survey_fails_when_a_script_does() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/host-survey.yml");
    let workflow = fs::read_to_string(path).unwrap();
    // GitHub adds pipefail only for a named shell; `| tee` hides the status otherwise
    assert!(workflow.contains("    defaults:\n      run:\n        shell: bash\n"));
}

#[test]
fn ubuntu_26_04_is_not_read_as_24_04() {
    let design = design();
    assert!(!design.contains("Ubuntu 24.04 and later"));
    assert!(design.contains("`/etc/apparmor.d/bwrap-userns-restrict`"));
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("prototype/m3/README.md");
    let readme = fs::read_to_string(path).unwrap();
    let header = readme
        .lines()
        .find(|line| line.starts_with("| | Ubuntu 24.04"))
        .expect("the results table");
    assert!(!header.contains("ubuntu-latest"), "{header}");
    assert!(header.contains("`ubuntu-26.04`"), "{header}");
}

#[test]
fn no_runner_cell_waits_for_a_run() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("prototype/m3/README.md");
    let readme = fs::read_to_string(path).unwrap();
    assert!(!readme.contains("to measure (CI)"));
    assert!(!readme.contains("the next run of the workflow"));
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
        .find(|line| line.starts_with("- The dashboard's terminal"))
        .expect("§14's item");
    for part in ["M3-20", "`NO_PROXY` for loopback is needed", "not shown"] {
        assert!(item.contains(part), "{part}");
    }
}

#[test]
fn an_older_landlock_abi_leaves_execute_open() {
    let (adr_0037, adr_0038, design) = (adr(ADR_0037), adr(ADR_0038), design());
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("prototype/m3/README.md");
    let readme = fs::read_to_string(path).unwrap();
    assert!(adr_0037.contains("- **Where it is missing**, the backend still runs."));
    assert!(adr_0037.contains(
        "The rights that ABI has apply, as a layer over the mounts, and the rights it lacks rest on the mounts alone."
    ));
    assert!(!adr_0037.contains("left to the code"));
    assert!(!adr_0038.contains("too old a Landlock"));
    assert!(design.contains("the rights that ABI has apply as a layer over the mounts"));
    assert!(!design.contains("or its ABI is older than the backend's rules need, writes are held"));

    // Both options stay on the table: the open row names them, and nothing
    // else in these documents takes either side.
    let row = design
        .lines()
        .find(|line| line.starts_with("| Execute rules on an older Landlock ABI"))
        .expect("the open decision in §15");
    assert!(row.contains("A: execute rules apply on every ABI, with no acceptance"));
    assert!(row.contains(
        "B: an older ABI declares the weaker execute control and `[exec]` needs `--accept-unenforced exec`"
    ));
    let design_without_row = design.replace(row, "");
    for (name, text) in [
        ("ADR 0037", &adr_0037),
        ("ADR 0038", &adr_0038),
        ("the design", &design_without_row),
        ("the README", &readme),
    ] {
        assert!(
            text.contains("open (design §15)") || text.contains("open (§15)"),
            "{name}"
        );
        for answer in [
            "execute rules apply on every ABI",
            "needs no acceptance",
            "keep the execute control",
            "execute included",
            "execute among them",
            "declares the weaker execute control and",
        ] {
            assert!(!text.contains(answer), "{name}: {answer}");
        }
    }
    for text in [&adr_0037, &adr_0038] {
        assert!(text.lines().any(|line| line == "status: proposed"));
    }
}

#[test]
fn doctor_weighs_the_profile_before_printing_it() {
    let design = design();
    let item = design
        .lines()
        .find(|line| line.starts_with("- That bubblewrap runs as an unprivileged user"))
        .expect("§14's item on bubblewrap");
    assert!(item.contains("the narrower of the two tried on Ubuntu 24.04, in a VM"));
}
