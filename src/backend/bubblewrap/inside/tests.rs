use super::*;

/// Records what is called and fails where it is told to: nothing here is
/// applied to any process.
#[derive(Default)]
struct Recorded {
    calls: Vec<&'static str>,
    said: Vec<String>,
    fails: Option<&'static str>,
    landlock: Option<Landlock>,
}

impl Recorded {
    fn step(&mut self, name: &'static str) -> Result<(), InsideError> {
        self.calls.push(name);
        match self.fails == Some(name) {
            true => Err(InsideError::Seccomp(name.to_owned())),
            false => Ok(()),
        }
    }
}

impl Confine for Recorded {
    fn apply_landlock(&mut self) -> Result<Landlock, InsideError> {
        self.step("landlock")?;
        Ok(self.landlock.unwrap_or(Landlock::Full))
    }

    fn apply_seccomp(&mut self) -> Result<(), InsideError> {
        self.step("seccomp")
    }

    fn say(&mut self, line: &str) {
        self.said.push(line.to_owned());
    }
}

impl SessionSteps for Recorded {
    fn start_relay(&mut self) -> Result<(), InsideError> {
        self.step("relay")
    }

    fn run_command(&mut self) -> InsideError {
        self.calls.push("command");
        InsideError::NoCommand
    }
}

impl RelaySteps for Recorded {
    fn say_ready(&mut self) -> Result<(), InsideError> {
        self.step("ready")
    }

    fn serve(&mut self) -> InsideError {
        self.calls.push("serve");
        InsideError::NoCommand
    }
}

/// The relay is a program of its own, which Landlock's execute rules would
/// refuse from an enclos under the user's home: it starts before them.
#[test]
fn the_relay_starts_before_the_rules_and_the_command_after_them() {
    let mut steps = Recorded::default();
    in_session(&mut steps);
    assert_eq!(steps.calls, ["relay", "landlock", "seccomp", "command"]);
}

#[test]
fn the_relay_is_confined_before_it_says_ready_and_serves() {
    let mut steps = Recorded::default();
    as_relay(&mut steps);
    assert_eq!(steps.calls, ["landlock", "seccomp", "ready", "serve"]);
}

#[test]
fn no_command_runs_once_a_step_has_failed() {
    for (fails, reached) in [
        ("relay", &["relay"][..]),
        ("landlock", &["relay", "landlock"]),
        ("seccomp", &["relay", "landlock", "seccomp"]),
    ] {
        let mut steps = Recorded {
            fails: Some(fails),
            ..Recorded::default()
        };
        let stopped = in_session(&mut steps).to_string();
        assert!(stopped.contains(fails), "{stopped}");
        assert_eq!(steps.calls, reached);
    }
}

#[test]
fn a_relay_that_failed_to_confine_itself_never_serves() {
    for fails in ["landlock", "seccomp", "ready"] {
        let mut steps = Recorded {
            fails: Some(fails),
            ..Recorded::default()
        };
        as_relay(&mut steps);
        assert!(!steps.calls.contains(&"serve"), "{fails}");
    }
}

/// ADR 0037: seccomp's filter is the same, and the command runs.
#[test]
fn no_landlock_is_reported_and_the_session_goes_on() {
    let mut steps = Recorded {
        landlock: Some(Landlock::Missing),
        ..Recorded::default()
    };
    in_session(&mut steps);
    assert_eq!(steps.calls, ["relay", "landlock", "seccomp", "command"]);
    assert_eq!(steps.said.len(), 1);
    assert!(steps.said[0].contains("no Landlock"), "{:?}", steps.said);
}

#[test]
fn every_rule_held_says_nothing() {
    let mut steps = Recorded::default();
    in_session(&mut steps);
    assert!(steps.said.is_empty());
}

#[test]
fn a_file_that_is_not_there_or_not_compiled_is_told_before_anything_applies() {
    let dir = tempfile::tempdir().unwrap();
    let missing = Prepared::read(&dir.path().join("none.json")).err().unwrap();
    assert!(matches!(missing, InsideError::Read { .. }), "{missing:?}");
    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, "{}").unwrap();
    let parsed = Prepared::read(&bad).err().unwrap();
    assert!(matches!(parsed, InsideError::Parse { .. }), "{parsed:?}");
}

/// The JSON compile wrote is read as it is, with nothing worked out again.
#[test]
fn what_compile_writes_is_what_is_read() {
    use crate::backend::SandboxContext;
    use crate::layout::Layout;
    use crate::model::policy::Policy;
    let layout = Layout::at("/nonexistent-enclos-test/alice/.enclos");
    let ctx = SandboxContext::new(&layout, &"home".parse().unwrap(), 41001);
    let text = crate::backend::bubblewrap::compile(&Policy::default(), &ctx)
        .unwrap()
        .text;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("compiled.json");
    std::fs::write(&file, &text).unwrap();
    let prepared = Prepared::read(&file).unwrap();
    assert_eq!(prepared.compiled.relay.log, "/tmp/enclos-relay.log");
    assert_eq!(prepared.compiled.relay.port, 41001);
    assert!(prepared.grants.iter().any(|g| g.path == "/dev"));
    assert!(!prepared.programs.is_empty());
}
