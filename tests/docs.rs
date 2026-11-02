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
    assert!(design.contains("no mount holds `IOCTL_DEV` or a scope"));
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

/// Paths on the deny list since before Linux's were added, checked or listed
/// on their own: the rest of `~/.config` and `~/.local` is Linux's.
const SHARED_DENIES: &[&str] = &[
    "~/.config/gcloud",
    "~/.config/gh",
    "~/.config/hub",
    "~/.config/glab-cli",
    "~/.config/rclone",
    "~/.config/op",
    "~/.config/opencode",
    "~/.local/share/fish",
    "~/.local/share/atuin",
    "~/.local/share/opencode",
];

/// A `wrap` that kept the old order would let a later `--bind` uncover a mask.
#[test]
fn masks_in_a_writable_folder_come_after_the_arguments_that_bind_it() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let read = |file: &str| fs::read_to_string(root.join(file)).unwrap();
    for (doc, anchor) in [
        (design(), "**The order `wrap` keeps:**"),
        (
            read("docs/policy-compilation.md"),
            "`wrap` runs `before_home_mask`",
        ),
        (
            read("src/backend/bubblewrap/compile.rs"),
            "The arguments `wrap` runs are",
        ),
    ] {
        let text = &doc[doc.find(anchor).expect(anchor)..];
        let order: Vec<usize> = [
            "before_home_mask",
            "after_home_mask",
            "`unmovable`",
            "`in_sandbox_home` and `in_workspace`",
            "`--remount-ro`",
        ]
        .iter()
        .map(|word| text.find(word).expect(word))
        .collect();
        assert!(order.is_sorted(), "{anchor}: {order:?}");
    }
}

/// What compiling leaves open stays written down for the work that picks it up.
#[test]
fn what_compiling_leaves_to_later_work_stays_written_down() {
    let design = design();
    let to_verify = design
        .split("Awaiting prototype verification")
        .last()
        .unwrap();
    // A workspace through a link the user made passes every check.
    assert!(to_verify.contains("`~/cargo -> ~/.cargo`"));
    assert!(!design.contains("the write checks still run on real paths"));
    // The relay moves with the namespace, so it is more than one constant.
    assert!(design.contains("the holder serves the one relay"));
    // Landlock's rights add up, so a workspace under `/opt` runs programs.
    assert!(design.contains("A workspace under one of them can run programs"));
}

#[test]
fn every_deny_entry_named_from_memory_is_listed_to_verify() {
    let defaults = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/policy/templates/defaults.toml"),
    )
    .unwrap();
    let design = design();
    let to_verify = design
        .split("Awaiting prototype verification")
        .last()
        .unwrap();
    let elsewhere = [
        "~/.pki",
        "~/.mozilla",
        "~/.thunderbird",
        "~/snap",
        "~/.var/app",
        "~/.1password",
        "~/.bitwarden-ssh-agent.sock",
        "~/Library/Application Support/Signal",
        "~/Library/Application Support/Slack",
        "~/Library/Application Support/discord",
        "~/Library/Application Support/Telegram Desktop",
    ];
    let entries = defaults
        .lines()
        .filter_map(|line| line.trim().strip_prefix('"')?.strip_suffix("\","))
        .filter(|entry| {
            entry.starts_with('/')
                || entry.starts_with("~/.config/")
                || entry.starts_with("~/.local/")
                || elsewhere.contains(entry)
        })
        .filter(|entry| !SHARED_DENIES.contains(entry));
    let missing: Vec<&str> = entries
        .filter(|entry| !to_verify.contains(&format!("`{entry}`")))
        .collect();
    assert!(missing.is_empty(), "not listed to verify: {missing:?}");
}

/// `run/` holds more than a folder per sandbox.
#[test]
fn the_tree_lists_each_sandboxs_connect_lock() {
    assert!(design().contains("run/<sandbox>.connect.lock"));
}
