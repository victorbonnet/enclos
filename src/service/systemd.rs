//! systemd user units (Linux): one unit file per service in the user's
//! systemd folder, run by the user's own manager through `systemctl --user`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use super::{ServiceError, ServiceLabel, ServiceManager, ServiceStatus, ServiceUnit};

pub struct Systemd {
    /// The folder unit files go in.
    units_dir: PathBuf,
    systemctl: PathBuf,
}

const SYSTEMCTL: &str = "/usr/bin/systemctl";
/// How long `start` waits for what runs under the same label to end before
/// it starts its own. `start` runs under enclos's state lock, which a runtime
/// service being ended needs to record its end, so it does not wait long:
/// the engine removes a sandbox's services before it starts them, outside
/// the lock, so a unit still running here was started by another command
/// meanwhile.
const REPLACE_WAIT: Duration = Duration::from_secs(10);
/// How often the manager is asked whether what runs has ended meanwhile.
const REPLACE_POLL: Duration = Duration::from_millis(100);

impl Systemd {
    pub fn for_user(units_dir: &Path) -> Systemd {
        Systemd {
            units_dir: units_dir.to_owned(),
            systemctl: SYSTEMCTL.into(),
        }
    }

    fn unit_path(&self, label: &ServiceLabel) -> PathBuf {
        self.units_dir.join(unit_name(label))
    }

    fn systemctl(&self, args: &[&str]) -> Result<Output, ServiceError> {
        Command::new(&self.systemctl)
            .arg("--user")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| ServiceError {
                what: format!("cannot run systemctl: {e}"),
            })
    }

    /// `systemctl --user <args>`; an error when it refuses, saying `what`
    /// it was asked.
    fn must(&self, what: &str, args: &[&str]) -> Result<(), ServiceError> {
        let out = self.systemctl(args)?;
        if !out.status.success() {
            return Err(ServiceError {
                what: format!(
                    "systemd did not {what}: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            });
        }
        Ok(())
    }

    /// What the manager says of the unit now.
    fn show(&self, label: &ServiceLabel) -> Result<Shown, ServiceError> {
        let name = unit_name(label);
        let out = self.systemctl(&["show", &name, "--property=LoadState,ActiveState,MainPID"])?;
        if !out.status.success() {
            return Err(ServiceError {
                what: format!(
                    "systemctl cannot say whether {label} runs (exit {}): {}",
                    out.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            });
        }
        Ok(parse_show(&String::from_utf8_lossy(&out.stdout)))
    }

    /// Ends what runs under the unit, if anything does, without waiting
    /// past `REPLACE_WAIT`.
    fn end_what_runs(&self, label: &ServiceLabel) -> Result<(), ServiceError> {
        let name = unit_name(label);
        self.must(&format!("stop {label}"), &["stop", "--no-block", &name])?;
        let deadline = Instant::now() + REPLACE_WAIT;
        while !self.show(label)?.ended() {
            if Instant::now() >= deadline {
                return Err(ServiceError {
                    what: format!(
                        "systemd did not stop {label}: it was still running after {} s; another enclos command may be starting or stopping this sandbox's services",
                        REPLACE_WAIT.as_secs()
                    ),
                });
            }
            std::thread::sleep(REPLACE_POLL);
        }
        Ok(())
    }
}

fn unit_name(label: &ServiceLabel) -> String {
    format!("{label}.service")
}

/// Removes `file`, which may not be there.
fn remove(file: &Path) -> Result<(), ServiceError> {
    match std::fs::remove_file(file) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(ServiceError {
            what: format!("cannot remove {}: {e}", file.display()),
        }),
        _ => Ok(()),
    }
}

/// The properties `systemctl --user show` printed for a unit.
#[derive(Debug, Default, PartialEq, Eq)]
struct Shown {
    load_state: String,
    active_state: String,
    main_pid: u32,
}

impl Shown {
    /// Nothing of the unit runs and no restart is pending.
    fn ended(&self) -> bool {
        matches!(self.active_state.as_str(), "inactive" | "failed")
    }

    fn status(&self) -> ServiceStatus {
        match (self.main_pid, self.load_state.as_str()) {
            (0, "not-found") => ServiceStatus::NotLoaded,
            (0, _) => ServiceStatus::Loaded,
            (pid, _) => ServiceStatus::Running { pid },
        }
    }
}

fn parse_show(text: &str) -> Shown {
    let mut shown = Shown::default();
    for (key, value) in text.lines().filter_map(|l| l.split_once('=')) {
        match key {
            "LoadState" => shown.load_state = value.to_owned(),
            "ActiveState" => shown.active_state = value.to_owned(),
            "MainPID" => shown.main_pid = value.parse().unwrap_or(0),
            _ => {}
        }
    }
    shown
}

/// The folders of `UnitPath=` in what `systemctl show` printed: separated
/// by spaces, with a folder that holds a space or `$` double-quoted.
fn search_path(text: &str) -> Vec<String> {
    let Some(value) = text.lines().find_map(|l| l.strip_prefix("UnitPath=")) else {
        return Vec::new();
    };
    let mut folders = vec![String::new()];
    let mut in_quotes = false;
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => in_quotes = !in_quotes,
            '\\' if in_quotes => folders.last_mut().unwrap().extend(chars.next()),
            ' ' if !in_quotes => folders.push(String::new()),
            c => folders.last_mut().unwrap().push(c),
        }
    }
    folders
}

/// `text` as one quoted word of a unit file, which systemd reads back with
/// no specifier expanded and no character changed.
fn quoted(text: &str) -> String {
    let mut word = String::from("\"");
    for c in text.chars() {
        match c {
            '\\' => word.push_str("\\\\"),
            '"' => word.push_str("\\\""),
            '%' => word.push_str("%%"),
            c if c.is_ascii_control() => word.push_str(&format!("\\x{:02x}", c as u32)),
            c => word.push(c),
        }
    }
    word.push('"');
    word
}

/// An argument of `ExecStart=`, where systemd also expands variables. The
/// program's own path is not expanded, so it is only [`quoted`].
fn exec_word(text: &str) -> String {
    quoted(text).replace('$', "$$")
}

/// The unit file, a pure function of `unit`: started now and at each login,
/// with its output in the unit's log; restarted after a non-zero exit or a
/// signal (systemd counts SIGHUP, SIGINT, SIGPIPE and SIGTERM as clean
/// unless told otherwise), never after exit 0, the delay growing from 1
/// second to 10. `stop` sends TERM to the program alone, which may be
/// stopping what it runs, and KILL to what stays in the unit's cgroup when it
/// exits or after the unit's stop timeout: the proxy, or `enclos launch`
/// itself. A runtime service's program runs in a scope of its own (design
/// §8), so it is `launch`'s to stop. An error when the log's path holds a
/// control character, which `append:` cannot quote.
pub fn unit_file(unit: &ServiceUnit) -> Result<String, ServiceError> {
    let log = unit.log.display().to_string();
    if log.chars().any(|c| c.is_control()) {
        return Err(ServiceError {
            what: format!(
                "cannot write a systemd unit for {}: its log's path has a control character: {log:?}",
                unit.label
            ),
        });
    }
    let log = log.replace('%', "%%");
    let mut exec = vec![quoted(&unit.program.display().to_string())];
    exec.extend(unit.args.iter().map(|a| exec_word(&a.to_string_lossy())));
    let env: String = unit
        .env
        .iter()
        .map(|(k, v)| format!("Environment={}\n", quoted(&format!("{k}={v}"))))
        .collect();
    Ok(format!(
        "# Written by enclos; `enclos sandbox stop` removes it.
[Unit]
Description=enclos service {label}
StartLimitIntervalSec=0

[Service]
ExecStart={exec}
{env}Restart=on-failure
RestartForceExitStatus=SIGHUP SIGINT SIGPIPE SIGTERM
RestartSec=1
RestartSteps=4
RestartMaxDelaySec=10
KillMode=mixed
TimeoutStopSec={timeout}
StandardOutput=append:{log}
StandardError=append:{log}

[Install]
WantedBy=default.target
",
        label = unit.label,
        exec = exec.join(" "),
        // 0 would mean no timeout at all.
        timeout = unit.stop_timeout.as_secs().max(1),
    ))
}

impl ServiceManager for Systemd {
    /// That the user's manager answers and searches the folder units go in.
    /// That folder comes from this process's environment and the manager
    /// reads its own, so they can differ, and a unit written elsewhere would
    /// never load.
    fn available(&self) -> Result<(), ServiceError> {
        let out = self.systemctl(&["show", "--property=UnitPath"])?;
        if !out.status.success() {
            return Err(ServiceError {
                what: format!(
                    "systemd did not answer as your user's manager, which runs enclos's services: {}; log in as this user directly, not through `su` or `sudo`, so that `XDG_RUNTIME_DIR` is set",
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            });
        }
        let searched = search_path(&String::from_utf8_lossy(&out.stdout));
        if !searched.iter().any(|f| Path::new(f) == self.units_dir) {
            return Err(ServiceError {
                what: format!(
                    "your user's manager does not look for units in {}: run enclos with XDG_CONFIG_HOME as the manager has it (`systemctl --user show --property=UnitPath` lists where it looks)",
                    self.units_dir.display()
                ),
            });
        }
        Ok(())
    }

    /// `installed` reads a folder named by this process's environment, so it
    /// shows nothing when the manager's is another.
    fn can_list(&self) -> Result<(), ServiceError> {
        self.available()
    }

    fn start(&self, unit: &ServiceUnit) -> Result<(), ServiceError> {
        self.available()?;
        let failed = |what: String| ServiceError { what };
        let text = unit_file(unit)?;
        std::fs::create_dir_all(&self.units_dir)
            .map_err(|e| failed(format!("cannot create {}: {e}", self.units_dir.display())))?;
        let path = self.unit_path(&unit.label);
        std::fs::write(&path, text)
            .map_err(|e| failed(format!("cannot write {}: {e}", path.display())))?;
        self.must("read its unit files again", &["daemon-reload"])?;
        // Replace what runs under the same label.
        self.end_what_runs(&unit.label)?;
        self.must(
            &format!("start {}", unit.label),
            &["enable", "--now", &unit_name(&unit.label)],
        )
    }

    fn stop(&self, label: &ServiceLabel) -> Result<(), ServiceError> {
        let name = unit_name(label);
        let loaded = self.status(label)? != ServiceStatus::NotLoaded;
        if loaded {
            // Waits while the manager sends TERM, then KILL after the
            // unit's stop timeout.
            self.must(&format!("stop {label}"), &["stop", &name])?;
            // A unit that ended in failure stays listed until told; there
            // is nothing to reset otherwise, which systemctl calls an error.
            self.systemctl(&["reset-failed", &name])?;
        }
        let path = self.unit_path(label);
        if !loaded {
            // A file the manager has not read, perhaps in a folder it does
            // not search: `disable` would refuse it.
            let link = self.units_dir.join("default.target.wants").join(&name);
            return [link, path].iter().try_for_each(|file| remove(file));
        }
        if path.exists() {
            self.must(
                &format!("disable {label}"),
                &["disable", "--no-reload", &name],
            )?;
            remove(&path)?;
            self.must("read its unit files again", &["daemon-reload"])?;
        }
        Ok(())
    }

    /// A unit systemd has not heard of is not loaded; a manager that cannot
    /// be asked is not knowing, which `stop` must not read as nothing to
    /// stop.
    fn status(&self, label: &ServiceLabel) -> Result<ServiceStatus, ServiceError> {
        Ok(self.show(label)?.status())
    }

    /// From the unit files: `start` writes one before starting it, and
    /// `stop` removes it only once the unit has stopped.
    fn installed(&self, prefix: &str) -> Result<Vec<ServiceLabel>, ServiceError> {
        let entries = match std::fs::read_dir(&self.units_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(ServiceError {
                    what: format!("cannot read {}: {e}", self.units_dir.display()),
                });
            }
        };
        let mut labels = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| ServiceError {
                what: format!("cannot read {}: {e}", self.units_dir.display()),
            })?;
            let file = entry.file_name();
            let label = file
                .to_str()
                .and_then(|f| f.strip_suffix(".service"))
                .filter(|l| l.starts_with(prefix))
                .and_then(ServiceLabel::parse);
            labels.extend(label);
        }
        labels.sort();
        Ok(labels)
    }

    fn unset_env_command(&self, var: &str) -> String {
        format!("systemctl --user unset-environment {var}")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn label(text: &str) -> ServiceLabel {
        ServiceLabel::parse(text).unwrap()
    }

    #[test]
    fn a_variable_is_unset_in_the_users_manager() {
        let systemd = Systemd::for_user(Path::new("/home/alice/.config/systemd/user"));
        assert_eq!(
            systemd.unset_env_command("ENCLOS_SEATBELT_BASELINE"),
            "systemctl --user unset-environment ENCLOS_SEATBELT_BASELINE"
        );
    }

    fn proxy() -> ServiceUnit {
        ServiceUnit {
            label: label("enclos.12345678.home.proxy"),
            program: "/usr/local/bin/enclos".into(),
            args: vec![
                "proxy".into(),
                "run".into(),
                "home".into(),
                "--port".into(),
                "41000".into(),
            ],
            log: "/home/alice/.enclos/sandboxes/home/logs/proxy.log".into(),
            env: vec![("ENCLOS_HOME".into(), "/home/alice/.enclos".into())],
            stop_timeout: Duration::from_secs(95),
        }
    }

    #[test]
    fn the_unit_file_runs_the_unit_restarts_failures_logs_and_waits_for_its_stop() {
        assert_eq!(
            unit_file(&proxy()).unwrap(),
            r#"# Written by enclos; `enclos sandbox stop` removes it.
[Unit]
Description=enclos service enclos.12345678.home.proxy
StartLimitIntervalSec=0

[Service]
ExecStart="/usr/local/bin/enclos" "proxy" "run" "home" "--port" "41000"
Environment="ENCLOS_HOME=/home/alice/.enclos"
Restart=on-failure
RestartForceExitStatus=SIGHUP SIGINT SIGPIPE SIGTERM
RestartSec=1
RestartSteps=4
RestartMaxDelaySec=10
KillMode=mixed
TimeoutStopSec=95
StandardOutput=append:/home/alice/.enclos/sandboxes/home/logs/proxy.log
StandardError=append:/home/alice/.enclos/sandboxes/home/logs/proxy.log

[Install]
WantedBy=default.target
"#
        );
    }

    #[test]
    fn systemds_own_characters_in_values_stay_literal() {
        let mut unit = proxy();
        unit.program = "/opt/my $tools/enclos".into();
        unit.args = vec!["100%".into(), "$HOME".into(), "a\"b\\c\nd".into()];
        unit.env = vec![("NAME".into(), "50% $off\"\n".into())];
        unit.log = "/home/alice/my logs/100%/proxy.log".into();
        let text = unit_file(&unit).unwrap();
        assert!(
            text.contains(r#"ExecStart="/opt/my $tools/enclos" "100%%" "$$HOME" "a\"b\\c\x0ad""#),
            "{text}"
        );
        assert!(
            text.contains(r#"Environment="NAME=50%% $off\"\x0a""#),
            "{text}"
        );
        assert!(
            text.contains("StandardOutput=append:/home/alice/my logs/100%%/proxy.log\n"),
            "{text}"
        );
    }

    #[test]
    fn a_log_path_a_unit_file_cannot_hold_is_refused() {
        let mut unit = proxy();
        unit.log = "/home/alice/logs\nExecStartPre=/bin/false".into();
        let err = unit_file(&unit).unwrap_err();
        assert!(err.what.contains("control character"), "{err}");
    }

    #[test]
    fn a_stop_timeout_under_a_second_still_kills() {
        let mut unit = proxy();
        unit.stop_timeout = Duration::from_millis(100);
        let text = unit_file(&unit).unwrap();
        assert!(text.contains("TimeoutStopSec=1\n"), "{text}");
    }

    #[test]
    fn a_unit_runs_when_the_manager_shows_its_main_process() {
        let shown = |load: &str, active: &str, pid: u32| {
            parse_show(&format!(
                "MainPID={pid}\nLoadState={load}\nActiveState={active}\n"
            ))
        };
        let running = shown("loaded", "active", 4242);
        assert_eq!(running.status(), ServiceStatus::Running { pid: 4242 });
        assert!(!running.ended());
        let waiting = shown("loaded", "activating", 0);
        assert_eq!(waiting.status(), ServiceStatus::Loaded);
        assert!(!waiting.ended(), "a restart is pending");
        let exited = shown("loaded", "inactive", 0);
        assert_eq!(exited.status(), ServiceStatus::Loaded);
        assert!(exited.ended());
        assert!(shown("loaded", "failed", 0).ended());
        assert_eq!(
            shown("not-found", "inactive", 0).status(),
            ServiceStatus::NotLoaded
        );
        assert_eq!(
            shown("not-found", "active", 7).status(),
            ServiceStatus::Running { pid: 7 },
            "its file was removed by hand, and it still runs"
        );
    }

    #[test]
    fn installed_labels_are_the_unit_files_with_the_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let systemd = Systemd::for_user(&dir.path().join("systemd/user"));
        assert!(systemd.installed("enclos.").unwrap().is_empty());
        std::fs::create_dir_all(systemd.units_dir.join("default.target.wants")).unwrap();
        for file in [
            "enclos.12345678.home.proxy.service",
            "enclos.12345678.home.gateway.service",
            "enclos.12345678.homework.proxy.service",
            "other.service",
            "enclos.12345678.home.notes",
        ] {
            std::fs::write(systemd.units_dir.join(file), "").unwrap();
        }
        assert_eq!(
            systemd.installed("enclos.12345678.home.").unwrap(),
            [
                label("enclos.12345678.home.gateway"),
                label("enclos.12345678.home.proxy")
            ]
        );
    }

    /// What the stub does when asked for `UnitPath`: `exit 1`, or print it.
    fn answer(unit_path: &str, units_dir: &Path) -> String {
        match unit_path {
            "exit 1" => "exit 1".to_owned(),
            line => format!(
                "printf '%s\\n' '{}'",
                line.replace("UNITS", &units_dir.display().to_string())
            ),
        }
    }

    /// A `Systemd` whose `systemctl` is a script in a folder of the test's:
    /// it logs its arguments and answers `show` with these lines, so nothing
    /// reaches a real manager.
    struct Stub {
        systemd: Systemd,
        log: PathBuf,
        _dir: tempfile::TempDir,
    }

    impl Stub {
        fn new(unit_path: &str, shown: &str) -> Stub {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let units_dir = dir.path().join("units");
            let log = dir.path().join("calls");
            let script = dir.path().join("systemctl");
            let text = format!(
                "#!/bin/sh\necho \"$*\" >>'{log}'\ncase \"$*\" in\n*UnitPath*) {unit_path} ;;\n*show*) printf '%s\\n' '{shown}' ;;\nesac\n",
                log = log.display(),
                unit_path = answer(unit_path, &units_dir),
            );
            std::fs::write(&script, text).unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            // Another test's child may hold the script open for a moment.
            while Command::new(&script).arg("ready").status().is_err() {
                std::thread::sleep(Duration::from_millis(10));
            }
            std::fs::remove_file(&log).unwrap();
            Stub {
                systemd: Systemd {
                    units_dir,
                    systemctl: script,
                },
                log,
                _dir: dir,
            }
        }

        fn calls(&self) -> Vec<String> {
            std::fs::read_to_string(&self.log)
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        fn called(&self, what: &str) -> bool {
            self.calls().iter().any(|call| call.contains(what))
        }
    }

    const LOADED: &str = "LoadState=loaded\nActiveState=inactive\nMainPID=0";
    const NOT_FOUND: &str = "LoadState=not-found\nActiveState=inactive\nMainPID=0";

    #[test]
    fn a_manager_that_does_not_search_the_folder_is_refused_before_anything_is_written() {
        let stub = Stub::new("UnitPath=/etc/systemd/user /elsewhere/systemd/user", LOADED);
        for err in [
            stub.systemd.available().unwrap_err(),
            stub.systemd.start(&proxy()).unwrap_err(),
        ] {
            let folder = stub.systemd.units_dir.display().to_string();
            assert!(err.what.contains(&folder), "{err}");
            assert!(err.what.contains("XDG_CONFIG_HOME"), "{err}");
        }
        assert!(!stub.systemd.units_dir.exists());
        assert!(!stub.called("daemon-reload"));
    }

    #[test]
    fn a_manager_that_does_not_answer_says_how_to_reach_it() {
        let stub = Stub::new("exit 1", LOADED);
        let err = stub.systemd.available().unwrap_err();
        assert!(err.what.contains("not through `su` or `sudo`"), "{err}");
        assert!(err.what.contains("XDG_RUNTIME_DIR"), "{err}");
    }

    #[test]
    fn a_manager_that_searches_the_folder_gets_the_unit() {
        let stub = Stub::new("UnitPath=/etc/systemd/user UNITS /run/systemd/user", LOADED);
        stub.systemd.available().unwrap();
        stub.systemd.start(&proxy()).unwrap();
        assert!(stub.systemd.unit_path(&proxy().label).exists());
        assert!(stub.called("enable --now enclos.12345678.home.proxy.service"));
    }

    #[test]
    fn stopping_a_unit_the_manager_has_not_loaded_removes_its_files_without_asking_it() {
        let stub = Stub::new("UnitPath=/etc/systemd/user", NOT_FOUND);
        let unit = proxy();
        let wants = stub.systemd.units_dir.join("default.target.wants");
        std::fs::create_dir_all(&wants).unwrap();
        let path = stub.systemd.unit_path(&unit.label);
        std::fs::write(&path, "").unwrap();
        let link = wants.join(unit_name(&unit.label));
        std::os::unix::fs::symlink(&path, &link).unwrap();
        stub.systemd.stop(&unit.label).unwrap();
        assert!(!path.exists());
        assert!(link.symlink_metadata().is_err());
        assert!(!stub.called("disable"), "{:?}", stub.calls());
    }

    #[test]
    fn stopping_a_loaded_unit_disables_it_through_the_manager() {
        let stub = Stub::new("UnitPath=UNITS", LOADED);
        let unit = proxy();
        std::fs::create_dir_all(&stub.systemd.units_dir).unwrap();
        std::fs::write(stub.systemd.unit_path(&unit.label), "").unwrap();
        stub.systemd.stop(&unit.label).unwrap();
        assert!(stub.called("disable --no-reload"), "{:?}", stub.calls());
        assert!(stub.called("daemon-reload"), "{:?}", stub.calls());
        assert!(!stub.systemd.unit_path(&unit.label).exists());
    }

    #[test]
    fn the_search_path_is_read_as_systemctl_quotes_it() {
        assert_eq!(
            search_path("UnitPath=/a/b \"/my config/sys\\$temd\" /c\n"),
            ["/a/b", "/my config/sys$temd", "/c"]
        );
        assert!(search_path("Version=255\n").is_empty());
    }

    /// Whether to run the tests below, which install real units in the
    /// user's manager, so only on a throwaway runner: CI's `systemd-units`
    /// job sets `ENCLOS_SYSTEMD_UNIT_TESTS`, and they refuse anywhere else.
    fn on_a_runner() -> bool {
        runs_real_units(|name| std::env::var(name).unwrap_or_default())
    }

    fn runs_real_units(var: impl Fn(&str) -> String) -> bool {
        if var("ENCLOS_SYSTEMD_UNIT_TESTS") != "1" {
            // That job passing with nothing tested would look like a pass.
            assert_ne!(
                var("GITHUB_JOB"),
                "systemd-units",
                "the systemd-units job lost ENCLOS_SYSTEMD_UNIT_TESTS"
            );
            eprintln!("systemd unit tests not run: CI's systemd-units job runs them");
            return false;
        }
        assert!(
            var("GITHUB_ACTIONS") == "true" && var("RUNNER_ENVIRONMENT") == "github-hosted",
            "these tests install real units: they run only on a GitHub-hosted runner"
        );
        true
    }

    fn with(vars: &[(&str, &str)], name: &str) -> String {
        let value = vars.iter().find(|(k, _)| *k == name);
        value.map_or(String::new(), |(_, v)| (*v).to_owned())
    }

    #[test]
    fn real_units_run_only_when_asked_and_only_on_a_hosted_runner() {
        assert!(!runs_real_units(|name| with(&[], name)));
        assert!(!runs_real_units(|name| with(
            &[("GITHUB_JOB", "test")],
            name
        )));
        let hosted = [
            ("ENCLOS_SYSTEMD_UNIT_TESTS", "1"),
            ("GITHUB_ACTIONS", "true"),
            ("RUNNER_ENVIRONMENT", "github-hosted"),
        ];
        assert!(runs_real_units(|name| with(&hosted, name)));
    }

    #[test]
    #[should_panic(expected = "only on a GitHub-hosted runner")]
    fn real_units_are_refused_off_a_hosted_runner() {
        runs_real_units(|name| with(&[("ENCLOS_SYSTEMD_UNIT_TESTS", "1")], name));
    }

    #[test]
    #[should_panic(expected = "lost ENCLOS_SYSTEMD_UNIT_TESTS")]
    fn the_systemd_units_job_cannot_pass_without_running_them() {
        runs_real_units(|name| with(&[("GITHUB_JOB", "systemd-units")], name));
    }

    /// A service running `script` on the runner's manager.
    struct Started {
        systemd: Systemd,
        label: ServiceLabel,
        log: PathBuf,
        _dir: tempfile::TempDir,
    }

    impl Started {
        fn new(case: &str, script: &str, stop_timeout: Duration) -> Started {
            Started::program(case, "/bin/sh".into(), script, stop_timeout)
        }

        /// `program -c script`, for a `program` that is not `/bin/sh`.
        fn program(case: &str, program: PathBuf, script: &str, stop_timeout: Duration) -> Started {
            let layout = crate::layout::Layout::from_env().unwrap();
            let systemd = Systemd::for_user(layout.units_dir());
            systemd.available().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let started = Started {
                systemd,
                label: label(&format!("enclos.ci{}.{case}.test", std::process::id())),
                log: dir.path().join("service.log"),
                _dir: dir,
            };
            started.start(program, script, stop_timeout);
            started
        }

        fn start(&self, program: PathBuf, script: &str, stop_timeout: Duration) {
            self.systemd
                .start(&ServiceUnit {
                    label: self.label.clone(),
                    program,
                    args: vec!["-c".into(), script.into()],
                    log: self.log.clone(),
                    env: Vec::new(),
                    stop_timeout,
                })
                .unwrap();
        }

        fn running(&self) -> u32 {
            match self.systemd.status(&self.label).unwrap() {
                ServiceStatus::Running { pid } => pid,
                status => panic!("{} is not running: {status:?}", self.label),
            }
        }

        fn lines(&self) -> Vec<String> {
            std::fs::read_to_string(&self.log)
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect()
        }

        /// Waits past a few restart delays for `count` lines in the log.
        fn wait_for_lines(&self, count: usize) {
            let deadline = Instant::now() + Duration::from_secs(45);
            while self.lines().len() < count {
                assert!(
                    Instant::now() < deadline,
                    "{}: {:?}",
                    self.label,
                    self.lines()
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }

        fn stop_leaves_nothing_installed(&self) {
            self.systemd.stop(&self.label).unwrap();
            let dir = &self.systemd.units_dir;
            let name = unit_name(&self.label);
            assert!(
                self.systemd
                    .installed(self.label.as_str())
                    .unwrap()
                    .is_empty()
            );
            assert!(!dir.join(&name).exists());
            let wanted = dir.join("default.target.wants").join(&name);
            assert!(wanted.symlink_metadata().is_err(), "{}", wanted.display());
            assert_eq!(
                self.systemd.status(&self.label).unwrap(),
                ServiceStatus::NotLoaded
            );
        }
    }

    const STOP_TIMEOUT: Duration = Duration::from_secs(3);

    #[test]
    fn on_a_runner_a_service_that_exits_75_is_started_again() {
        if !on_a_runner() {
            return;
        }
        let began = Instant::now();
        let service = Started::new("exits75", "echo ran; exit 75", STOP_TIMEOUT);
        service.wait_for_lines(2);
        // A settings change costs a second, not launchd's whole throttle.
        assert!(
            began.elapsed() < Duration::from_secs(8),
            "{:?}",
            began.elapsed()
        );
        service.stop_leaves_nothing_installed();
    }

    #[test]
    fn on_a_runner_a_service_that_exits_0_is_not_started_again() {
        if !on_a_runner() {
            return;
        }
        let service = Started::new("exits0", "echo ran; exit 0", STOP_TIMEOUT);
        service.wait_for_lines(1);
        // Past the restart delay of `RestartSec`.
        std::thread::sleep(Duration::from_secs(15));
        assert_eq!(service.lines().len(), 1);
        assert_eq!(
            service.systemd.status(&service.label).unwrap(),
            ServiceStatus::Loaded
        );
        service.stop_leaves_nothing_installed();
    }

    #[test]
    fn on_a_runner_a_service_ended_by_a_term_it_did_not_ask_for_is_started_again() {
        if !on_a_runner() {
            return;
        }
        let service = Started::new("signalled", "echo ran; kill -TERM $$", STOP_TIMEOUT);
        service.wait_for_lines(2);
        service.stop_leaves_nothing_installed();
    }

    #[test]
    fn on_a_runner_stop_sends_term_then_kills_after_the_timeout() {
        if !on_a_runner() {
            return;
        }
        let script = "trap 'echo term' TERM; echo ready; while :; do sleep 1; done";
        let service = Started::new("ignores", script, STOP_TIMEOUT);
        service.wait_for_lines(1);
        let pid = service.running();
        let began = Instant::now();
        service.stop_leaves_nothing_installed();
        assert!(began.elapsed() >= STOP_TIMEOUT, "{:?}", began.elapsed());
        assert_eq!(service.lines(), ["ready", "term"]);
        assert!(!Path::new("/proc").join(pid.to_string()).exists());
    }

    /// Whether process `pid` is gone within a moment: the manager reaps it.
    fn gone(pid: u32) -> bool {
        let proc = Path::new("/proc").join(pid.to_string());
        let deadline = Instant::now() + Duration::from_secs(2);
        while proc.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        !proc.exists()
    }

    #[test]
    fn on_a_runner_start_enables_the_unit_for_the_next_login() {
        if !on_a_runner() {
            return;
        }
        let service = Started::new("enabled", "echo ran; exec sleep 300", STOP_TIMEOUT);
        let name = unit_name(&service.label);
        let dir = &service.systemd.units_dir;
        let wanted = dir.join("default.target.wants").join(&name);
        assert!(wanted.symlink_metadata().is_ok(), "{}", wanted.display());
        service.stop_leaves_nothing_installed();
    }

    #[test]
    fn on_a_runner_starting_a_running_unit_replaces_it() {
        if !on_a_runner() {
            return;
        }
        let service = Started::new("replaced", "echo first; exec sleep 300", STOP_TIMEOUT);
        service.wait_for_lines(1);
        let first = service.running();
        service.start(
            "/bin/sh".into(),
            "echo second; exec sleep 300",
            STOP_TIMEOUT,
        );
        service.wait_for_lines(2);
        assert_eq!(service.lines(), ["first", "second"]);
        assert_ne!(service.running(), first);
        assert!(gone(first));
        service.stop_leaves_nothing_installed();
    }

    #[test]
    fn on_a_runner_stop_leaves_no_process_the_program_started() {
        if !on_a_runner() {
            return;
        }
        let script = "sleep 300 & echo $!; wait";
        let service = Started::new("stray", script, STOP_TIMEOUT);
        service.wait_for_lines(1);
        let stray: u32 = service.lines()[0].parse().unwrap();
        assert!(Path::new("/proc").join(stray.to_string()).exists());
        service.stop_leaves_nothing_installed();
        assert!(gone(stray));
    }

    #[test]
    fn on_a_runner_a_dollar_in_the_programs_path_runs_that_path() {
        use std::os::unix::fs::PermissionsExt;
        if !on_a_runner() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("$tools");
        std::fs::create_dir(&folder).unwrap();
        let program = folder.join("service");
        std::fs::write(&program, "#!/bin/sh\necho ran\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        let service = Started::program("dollar", program, "", STOP_TIMEOUT);
        service.wait_for_lines(1);
        service.stop_leaves_nothing_installed();
    }

    #[test]
    fn on_a_runner_a_folder_the_manager_does_not_search_is_refused() {
        if !on_a_runner() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let systemd = Systemd::for_user(&dir.path().join("systemd/user"));
        let err = systemd.available().unwrap_err();
        assert!(err.what.contains("does not look for units"), "{err}");
    }

    #[test]
    fn on_a_runner_stop_removes_a_file_the_manager_never_read() {
        if !on_a_runner() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let units_dir = dir.path().join("systemd/user");
        std::fs::create_dir_all(&units_dir).unwrap();
        let systemd = Systemd::for_user(&units_dir);
        let label = label(&format!("enclos.ci{}.unread.test", std::process::id()));
        let path = systemd.unit_path(&label);
        std::fs::write(&path, "[Service]\nExecStart=/bin/true\n").unwrap();
        systemd.stop(&label).unwrap();
        assert!(!path.exists());
    }
}
