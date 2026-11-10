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
    fn run_command(&mut self) -> Result<u8, InsideError> {
        self.calls.push("command");
        Ok(0)
    }
}

/// The session starts nothing before it is confined: the relay to the proxy
/// is the namespace holder's (ADR 0039), so the command is the first process
/// it starts.
#[test]
fn the_rules_apply_before_the_command() {
    let mut steps = Recorded::default();
    assert_eq!(in_session(&mut steps).unwrap(), 0);
    assert_eq!(steps.calls, ["landlock", "seccomp", "command"]);
}

#[test]
fn no_command_runs_once_a_step_has_failed() {
    for (fails, reached) in [
        ("landlock", &["landlock"][..]),
        ("seccomp", &["landlock", "seccomp"]),
    ] {
        let mut steps = Recorded {
            fails: Some(fails),
            ..Recorded::default()
        };
        let stopped = in_session(&mut steps).unwrap_err().to_string();
        assert!(stopped.contains(fails), "{stopped}");
        assert_eq!(steps.calls, reached);
    }
}

/// ADR 0037: seccomp's filter is the same, and the command runs.
#[test]
fn no_landlock_is_reported_and_the_session_goes_on() {
    let mut steps = Recorded {
        landlock: Some(Landlock::Missing),
        ..Recorded::default()
    };
    assert_eq!(in_session(&mut steps).unwrap(), 0);
    assert_eq!(steps.calls, ["landlock", "seccomp", "command"]);
    assert_eq!(steps.said.len(), 1);
    assert!(steps.said[0].contains("no Landlock"), "{:?}", steps.said);
}

#[test]
fn every_rule_held_says_nothing() {
    let mut steps = Recorded::default();
    assert_eq!(in_session(&mut steps).unwrap(), 0);
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
    assert!(prepared.grants.iter().any(|g| g.path == "/dev"));
    assert!(!prepared.programs.is_empty());
}

/// Every orphan the session leaves is reaped here, PID 1 of its namespace,
/// until the command ends, whose code is the session's.
#[test]
fn the_session_reaps_its_orphans_until_its_command_ends() {
    let mut found = vec![
        Ok(Some((9, Some(Ended::Exited(0))))),
        Err(io::Error::from(io::ErrorKind::Interrupted)),
        Ok(Some((7, None))),
        Ok(Some((8, Some(Ended::Killed(9))))),
        Ok(Some((7, Some(Ended::Exited(3))))),
        Ok(Some((7, Some(Ended::Exited(4))))),
    ]
    .into_iter();
    let code = reap_until(7, || found.next().unwrap()).unwrap();
    assert_eq!(code, 3);
    assert_eq!(found.len(), 1, "it went on past its command");
}

/// As a shell gives it, so `connect` reports the same either way.
#[test]
fn a_command_a_signal_ended_gives_128_and_the_signal() {
    let mut found = [Ok(Some((7, Some(Ended::Killed(2)))))].into_iter();
    assert_eq!(reap_until(7, || found.next().unwrap()).unwrap(), 130);
}

#[test]
fn a_session_that_lost_its_children_says_so() {
    let e = reap_until(7, || Err(io::Error::from_raw_os_error(10))).unwrap_err();
    assert!(e.to_string().contains("lost the session's command"), "{e}");
}

/// What `wait` reports of a child this test started: its exit code, the
/// signal that ended it, and nothing for one that was only stopped. Each
/// child is reaped by `waitpid`, which clippy's lint does not see.
#[test]
#[allow(clippy::zombie_processes)]
fn a_child_that_stopped_has_not_ended() {
    use rustix::process::{Pid, Signal, WaitOptions, kill_process, waitpid};
    let wait = |child: &std::process::Child, options| {
        let pid = Pid::from_child(child);
        let (_, status) = waitpid(Some(pid), options).unwrap().unwrap();
        Ended::of(status)
    };
    let exits = std::process::Command::new("/bin/sh")
        .args(["-c", "exit 3"])
        .spawn()
        .unwrap();
    assert_eq!(wait(&exits, WaitOptions::empty()), Some(Ended::Exited(3)));

    let sleeps = std::process::Command::new("/usr/bin/sleep")
        .arg("60")
        .spawn()
        .unwrap();
    let pid = Pid::from_child(&sleeps);
    kill_process(pid, Signal::STOP).unwrap();
    assert_eq!(wait(&sleeps, WaitOptions::UNTRACED), None);
    kill_process(pid, Signal::KILL).unwrap();
    assert_eq!(
        wait(&sleeps, WaitOptions::empty()),
        Some(Ended::Killed(Signal::KILL.as_raw()))
    );
}
