//! systemd user units (Linux): one unit file per service in the user's
//! systemd folder, run by the user's own manager through `systemctl --user`.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use super::{ServiceError, ServiceLabel, ServiceManager, ServiceStatus, ServiceUnit};

pub struct Systemd {
    /// The folder unit files go in.
    units_dir: PathBuf,
}

const SYSTEMCTL: &str = "/usr/bin/systemctl";
/// How long `start` waits for a run of the same label to end before it
/// starts its own. `start` runs under enclos's state lock, which a runtime
/// service being ended needs to record its end, so it does not wait long:
/// the engine removes a sandbox's services before it starts them, outside
/// the lock, so a unit still running here was started by another command
/// meanwhile.
const REPLACE_WAIT: Duration = Duration::from_secs(10);
/// How often the manager is asked whether the run has ended meanwhile.
const REPLACE_POLL: Duration = Duration::from_millis(100);

impl Systemd {
    pub fn for_user(user_home: &Path) -> Systemd {
        let config_home = std::env::var_os("XDG_CONFIG_HOME");
        Systemd {
            units_dir: units_dir(user_home, config_home.as_deref()),
        }
    }

    fn unit_path(&self, label: &ServiceLabel) -> PathBuf {
        self.units_dir.join(unit_name(label))
    }

    /// `systemctl --user <args>`; an error when it refuses, saying `what`
    /// it was asked.
    fn must(&self, what: &str, args: &[&str]) -> Result<(), ServiceError> {
        let out = systemctl(args)?;
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
        let out = systemctl(&["show", &name, "--property=LoadState,ActiveState,MainPID"])?;
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

    /// Ends a run of the unit, if there is one, without waiting past
    /// `REPLACE_WAIT`.
    fn end_previous_run(&self, label: &ServiceLabel) -> Result<(), ServiceError> {
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

fn systemctl(args: &[&str]) -> Result<Output, ServiceError> {
    Command::new(SYSTEMCTL)
        .arg("--user")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| ServiceError {
            what: format!("cannot run systemctl: {e}"),
        })
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

/// The folder unit files go in, as the user's manager looks for it:
/// `$XDG_CONFIG_HOME/systemd/user` when that is an absolute path, else
/// `~/.config/systemd/user`.
fn units_dir(user_home: &Path, config_home: Option<&OsStr>) -> PathBuf {
    config_home
        .map(Path::new)
        .filter(|path| path.is_absolute())
        .map_or_else(|| user_home.join(".config"), Path::to_path_buf)
        .join("systemd/user")
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

/// One word of `ExecStart=`, where systemd also expands variables.
fn exec_word(text: &str) -> String {
    quoted(text).replace('$', "$$")
}

/// The unit file: started now and at each login, restarted after a non-zero
/// exit or a signal (systemd counts SIGHUP, SIGINT, SIGPIPE and SIGTERM as
/// clean unless told otherwise) but never after exit 0, however often, with
/// its output in the unit's log. `stop` sends TERM to the program alone,
/// which may be stopping what it runs, and KILL to what is left when it
/// exits or after the unit's stop timeout. An error when the log's path
/// cannot be written in a unit file, where `append:` takes no quoting.
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
    let mut exec = vec![exec_word(&unit.program.display().to_string())];
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
RestartSec=10
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
    fn available(&self) -> Result<(), ServiceError> {
        self.must(
            "answer as your user's manager, which runs enclos's services",
            &["show", "--property=Version"],
        )
    }

    fn start(&self, unit: &ServiceUnit) -> Result<(), ServiceError> {
        let failed = |what: String| ServiceError { what };
        let text = unit_file(unit)?;
        std::fs::create_dir_all(&self.units_dir)
            .map_err(|e| failed(format!("cannot create {}: {e}", self.units_dir.display())))?;
        let path = self.unit_path(&unit.label);
        std::fs::write(&path, text)
            .map_err(|e| failed(format!("cannot write {}: {e}", path.display())))?;
        self.must("read its unit files again", &["daemon-reload"])?;
        // Replace a previous run of the same unit.
        self.end_previous_run(&unit.label)?;
        self.must(
            &format!("start {}", unit.label),
            &["enable", "--now", &unit_name(&unit.label)],
        )
    }

    fn stop(&self, label: &ServiceLabel) -> Result<(), ServiceError> {
        let name = unit_name(label);
        if self.status(label)? != ServiceStatus::NotLoaded {
            // Waits while the manager sends TERM, then KILL after the
            // unit's stop timeout.
            self.must(&format!("stop {label}"), &["stop", &name])?;
            // A unit that ended in failure stays listed until told; there
            // is nothing to reset otherwise, which systemctl calls an error.
            systemctl(&["reset-failed", &name])?;
        }
        let path = self.unit_path(label);
        if path.exists() {
            self.must(
                &format!("disable {label}"),
                &["disable", "--no-reload", &name],
            )?;
            std::fs::remove_file(&path).map_err(|e| ServiceError {
                what: format!("cannot remove {}: {e}", path.display()),
            })?;
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
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn label(text: &str) -> ServiceLabel {
        ServiceLabel::parse(text).unwrap()
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
RestartSec=10
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
        unit.program = "/opt/my tools/enclos".into();
        unit.args = vec!["100%".into(), "$HOME".into(), "a\"b\\c\nd".into()];
        unit.env = vec![("NAME".into(), "50% $off\"\n".into())];
        unit.log = "/home/alice/my logs/100%/proxy.log".into();
        let text = unit_file(&unit).unwrap();
        assert!(
            text.contains(r#"ExecStart="/opt/my tools/enclos" "100%%" "$$HOME" "a\"b\\c\x0ad""#),
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
    fn units_go_where_the_users_manager_looks_for_them() {
        let home = Path::new("/home/alice");
        assert_eq!(
            units_dir(home, None),
            Path::new("/home/alice/.config/systemd/user")
        );
        assert_eq!(
            units_dir(home, Some(OsStr::new("/srv/config"))),
            Path::new("/srv/config/systemd/user")
        );
        assert_eq!(
            units_dir(home, Some(OsStr::new("relative"))),
            Path::new("/home/alice/.config/systemd/user"),
            "the XDG rules ignore a relative path"
        );
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
        let systemd = Systemd {
            units_dir: dir.path().join("systemd/user"),
        };
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
}
