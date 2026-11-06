//! A bubblewrap sandbox's `[resources]` (design §7): `memory` and `cpu` on
//! the sandbox's slice, which its sessions share, `open_files` on each
//! process. Each with a control: the same programs under a limit they do
//! not reach, or none.

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

/// Allocates 160M, 16M at a time, every byte written, then says it is
/// ready in `~/ready-<argv[1]>` and waits up to 30 s for the other session
/// named by `argv[2]` to be ready too: `done` once both held theirs at once.
const ALLOCATE_BESIDE: &str = r#"
import os, sys, time
chunks = [b"x" * (16 << 20) for _ in range(10)]
home = os.environ["HOME"]
open(os.path.join(home, "ready-" + sys.argv[1]), "w").close()
other = os.path.join(home, "ready-" + sys.argv[2])
start = time.monotonic()
while not os.path.exists(other) and time.monotonic() - start < 30:
    time.sleep(0.1)
if os.path.exists(other):
    time.sleep(1)
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
        self.python_with(program, &[]).output().unwrap()
    }

    /// The command that runs `program` with `args` in a session of `lab`.
    fn python_with(&self, program: &str, args: &[&str]) -> std::process::Command {
        let mut command =
            self.command(&["connect", "lab", "--", "/usr/bin/python3", "-c", program]);
        command
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        command
    }

    /// Two sessions of `lab` at once, each running `program` with its own
    /// arguments, and what each did.
    fn two_sessions(&self, program: &str, args: [&[&str]; 2]) -> [std::process::Output; 2] {
        // The namespace holder started first, by a session alone.
        assert!(self.connect(":").status.success());
        let children = args.map(|args| self.python_with(program, args).spawn().unwrap());
        children.map(|child| child.wait_with_output().unwrap())
    }

    /// Two sessions allocating 160M each, together, from a clean home.
    fn allocating_together(&self) -> [std::process::Output; 2] {
        for name in ["ready-a", "ready-b"] {
            let _ = std::fs::remove_file(self.sandbox_home().join(name));
        }
        self.two_sessions(ALLOCATE_BESIDE, [&["a", "b"], &["b", "a"]])
    }
}

fn finished(out: &std::process::Output) -> bool {
    out.status.success() && text(&out.stdout) == "done"
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

/// The sandbox's sessions share one cap: each stays within it alone, and
/// together they do not.
#[test]
fn on_a_runner_two_sessions_together_past_memory_are_stopped() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    // The control: under a cap they do not reach together, both finish.
    lab.set_resources("memory = \"1G\"");
    let [a, b] = lab.allocating_together();
    assert!(finished(&a) && finished(&b), "{a:?}\n{b:?}");
    lab.set_resources("memory = \"256M\"");
    let [a, b] = lab.allocating_together();
    assert!(!(finished(&a) && finished(&b)), "{a:?}\n{b:?}");
    assert!(!a.status.success() || !b.status.success(), "{a:?}\n{b:?}");
}

/// Two sessions spinning at once share the sandbox's 0.25 of a core.
#[test]
fn on_a_runner_a_share_of_the_cpu_holds_the_sessions_together() {
    if !on_a_runner() {
        return;
    }
    let lab = Lab::new();
    let shares = |outs: [std::process::Output; 2]| -> [f64; 2] {
        outs.map(|out| {
            assert!(out.status.success(), "{out:?}");
            text(&out.stdout).parse().unwrap()
        })
    };
    let spin_together = || shares(lab.two_sessions(SPIN, [&[], &[]]));
    // The control: with no share set, each spinning process gets a core.
    let free = spin_together();
    assert!(free.iter().all(|s| *s > 0.7), "{free:?}");
    lab.set_resources("cpu = \"0.25\"");
    let held = spin_together();
    let together: f64 = held.iter().sum();
    assert!(
        together < 0.4,
        "{held:?} of a core together under cpu = 0.25, {free:?} without"
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
