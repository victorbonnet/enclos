//! A bubblewrap sandbox's `[resources]` (design §7): `memory` and `cpu` on
//! the session's scope, `open_files` on each process. Each with a control:
//! the same program under a limit it does not reach, or none.

use super::{Lab, on_a_runner, text};

/// Allocates 256M, 16M at a time, every byte written so each page is used,
/// saying how far it got, then `done`.
const ALLOCATE: &str = r#"
chunks = []
for i in range(16):
    chunks.append(b"x" * (16 << 20))
    print("allocated", (i + 1) * 16, flush=True)
print("done", flush=True)
"#;

/// Spins for 4 s of wall time, then prints the CPU time it got per second.
const SPIN: &str = r#"
import time
wall, cpu = time.monotonic(), time.process_time()
while time.monotonic() - wall < 4:
    pass
print(round((time.process_time() - cpu) / (time.monotonic() - wall), 2))
"#;

/// Opens /dev/null 300 times, or until refused, and says how many it held.
const OPEN: &str = r#"
held = []
try:
    for _ in range(300):
        held.append(open("/dev/null"))
except OSError as e:
    print("refused", e.errno)
print("held", len(held))
"#;

impl Lab {
    /// Makes `lines` the `[resources]` section of `lab`'s policy, through
    /// `policy edit` as a person would, with an editor that writes it.
    fn set_resources(&self, lines: &str) {
        let file = self.root.path().join("sandboxes/lab/policy.toml");
        let current = std::fs::read_to_string(&file).unwrap();
        let kept = current.split("\n[resources]\n").next().unwrap();
        let wanted = self.root.path().join("wanted.toml");
        std::fs::write(&wanted, format!("{kept}\n[resources]\n{lines}\n")).unwrap();
        let out = self
            .command(&["policy", "edit", "lab"])
            .env_remove("VISUAL")
            .env("EDITOR", format!("cp '{}'", wanted.display()))
            .output()
            .unwrap();
        assert!(out.status.success(), "{lines}: {out:?}");
    }

    /// `connect lab -- python3 -c program`.
    fn python(&self, program: &str) -> std::process::Output {
        self.command(&["connect", "lab", "--", "/usr/bin/python3", "-c", program])
            .output()
            .unwrap()
    }
}

#[test]
fn on_a_runner_a_process_allocating_past_memory_is_stopped() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    // The control: under a limit it does not reach, it allocates it all.
    lab.set_resources("memory = \"1G\"");
    let out = lab.python(ALLOCATE);
    assert!(out.status.success(), "{out:?}");
    assert!(text(&out.stdout).ends_with("done"), "{out:?}");
    lab.set_resources("memory = \"128M\"");
    let out = lab.python(ALLOCATE);
    let said = text(&out.stdout);
    assert!(!out.status.success(), "{out:?}");
    assert!(!said.contains("done"), "{out:?}");
    assert!(!said.contains("allocated 128"), "{out:?}");
}

#[test]
fn on_a_runner_a_share_of_the_cpu_holds() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let share = |out: std::process::Output| -> f64 {
        assert!(out.status.success(), "{out:?}");
        text(&out.stdout).parse().unwrap()
    };
    // The control: with no share set, a spinning process gets a core.
    let free = share(lab.python(SPIN));
    assert!(free > 0.7, "{free}");
    lab.set_resources("cpu = \"0.25\"");
    let held = share(lab.python(SPIN));
    assert!(
        held < 0.4,
        "{held} of a core under cpu = 0.25, {free} without"
    );
}

#[test]
fn on_a_runner_open_files_holds_each_process() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    // The control: with no limit, the hard limit is above 128, and the
    // program holds every file it opens.
    let out = lab.connect("ulimit -Hn");
    assert!(text(&out.stdout).parse::<u64>().unwrap() > 128, "{out:?}");
    assert_eq!(text(&lab.python(OPEN).stdout), "held 300");
    lab.set_resources("open_files = 128");
    let out = lab.connect("ulimit -Hn; ulimit -Sn");
    assert_eq!(text(&out.stdout), "128\n128", "{out:?}");
    let said = text(&lab.python(OPEN).stdout);
    // EMFILE, before 128 descriptors, the ones it had included.
    assert!(said.starts_with("refused 24\nheld "), "{said}");
    let held: u32 = said.rsplit(' ').next().unwrap().parse().unwrap();
    assert!(held < 128, "{said}");
}
