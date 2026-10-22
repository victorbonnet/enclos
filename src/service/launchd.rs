//! launchd user agents (macOS): one job file per unit in
//! `~/Library/LaunchAgents`, loaded into the user's login session.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::{ServiceError, ServiceLabel, ServiceManager, ServiceStatus, ServiceUnit};

pub struct Launchd {
    /// The folder job files go in: `~/Library/LaunchAgents`.
    agents_dir: PathBuf,
}

/// `launchctl print` of a service the domain does not have.
const NOT_FOUND: i32 = 113;
/// `launchctl bootout` of a job launchd is still ending.
const IN_PROGRESS: i32 = 36;
/// How long a job may take to leave launchd after `bootout`: longer than
/// any unit's `ExitTimeOut` (`STOP_TIMEOUT`, 95 s), after which launchd
/// kills it.
const UNLOAD_WAIT: Duration = Duration::from_secs(150);
/// How often launchd is asked whether the job is gone meanwhile.
const UNLOAD_POLL: Duration = Duration::from_millis(100);

impl Launchd {
    pub fn for_user(user_home: &Path) -> Launchd {
        Launchd {
            agents_dir: user_home.join("Library/LaunchAgents"),
        }
    }

    fn plist_path(&self, label: &ServiceLabel) -> PathBuf {
        self.agents_dir.join(format!("{label}.plist"))
    }

    /// The user's login session, `gui/<uid>`, as launchd names it.
    fn domain() -> Result<String, ServiceError> {
        let out = Command::new("/usr/bin/id")
            .arg("-u")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| ServiceError {
                what: format!("cannot run id to find your user id for launchd: {e}"),
            })?;
        let uid = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !out.status.success() || uid.is_empty() || !uid.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ServiceError {
                what: format!(
                    "cannot find your user id for launchd: id -u said `{uid}` ({})",
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            });
        }
        Ok(format!("gui/{uid}"))
    }

    fn target(label: &ServiceLabel) -> Result<String, ServiceError> {
        Ok(format!("{}/{label}", Self::domain()?))
    }

    /// Unloads the job, which ends its process, and waits until launchd no
    /// longer has it: `bootout` can return while launchd is still ending
    /// the job (about 0.7 s for a Hermes gateway on macOS 26.5), and loading
    /// the same label meanwhile fails with `Bootstrap failed: 5`. Nothing to
    /// do when launchd has no such job.
    fn bootout(&self, label: &ServiceLabel) -> Result<(), ServiceError> {
        if self.status(label)? == ServiceStatus::NotLoaded {
            return Ok(());
        }
        let out = launchctl(&["bootout", &Self::target(label)?])?;
        let ending = out.status.success() || out.status.code() == Some(IN_PROGRESS);
        let wait = if ending { UNLOAD_WAIT } else { Duration::ZERO };
        if !until_unloaded(|| self.status(label), wait, UNLOAD_POLL)? {
            let why = match ending {
                true => format!("it was still loaded after {} s", UNLOAD_WAIT.as_secs()),
                false => String::from_utf8_lossy(&out.stderr).trim().to_owned(),
            };
            return Err(ServiceError {
                what: format!("launchd did not stop {label}: {why}"),
            });
        }
        Ok(())
    }
}

/// Whether `status` says the job is unloaded within `wait`, asking every
/// `poll`; asked once with no wait.
fn until_unloaded(
    status: impl Fn() -> Result<ServiceStatus, ServiceError>,
    wait: Duration,
    poll: Duration,
) -> Result<bool, ServiceError> {
    let deadline = Instant::now() + wait;
    loop {
        if status()? == ServiceStatus::NotLoaded {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(poll);
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The job file: started at load and at login, restarted if it crashes
/// (not when it exits cleanly), with its output in the unit's log, and
/// given the unit's stop timeout before launchd kills it.
pub fn plist(unit: &ServiceUnit) -> String {
    let mut args = vec![unit.program.display().to_string()];
    args.extend(unit.args.iter().map(|a| a.to_string_lossy().into_owned()));
    let args: String = args
        .iter()
        .map(|a| format!("\n    <string>{}</string>", escape(a)))
        .collect();
    let env: String = unit
        .env
        .iter()
        .map(|(k, v)| {
            format!(
                "\n    <key>{}</key><string>{}</string>",
                escape(k),
                escape(v)
            )
        })
        .collect();
    let log = escape(&unit.log.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by enclos; `enclos sandbox stop` removes it. -->
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>{args}
  </array>
  <key>EnvironmentVariables</key>
  <dict>{env}
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ExitTimeOut</key><integer>{exit_timeout}</integer>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
        label = escape(unit.label.as_str()),
        exit_timeout = unit.stop_timeout.as_secs(),
    )
}

fn launchctl(args: &[&str]) -> Result<std::process::Output, ServiceError> {
    Command::new("/bin/launchctl")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| ServiceError {
            what: format!("cannot run launchctl: {e}"),
        })
}

/// What `launchctl print <domain>/<label>` says of a loaded job.
fn parse_status(text: &str) -> ServiceStatus {
    text.lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("pid = ")
                .and_then(|p| p.trim().parse().ok())
        })
        .map_or(ServiceStatus::Loaded, |pid| ServiceStatus::Running { pid })
}

impl ServiceManager for Launchd {
    fn available(&self) -> Result<(), ServiceError> {
        let domain = Self::domain()?;
        let out = launchctl(&["print", &domain])?;
        if !out.status.success() {
            return Err(ServiceError {
                what: format!(
                    "launchd has no login session {domain} to run services in (are you logged in on this Mac?): {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
            });
        }
        Ok(())
    }

    fn start(&self, unit: &ServiceUnit) -> Result<(), ServiceError> {
        let failed = |what: String| ServiceError { what };
        std::fs::create_dir_all(&self.agents_dir)
            .map_err(|e| failed(format!("cannot create {}: {e}", self.agents_dir.display())))?;
        let path = self.plist_path(&unit.label);
        std::fs::write(&path, plist(unit))
            .map_err(|e| failed(format!("cannot write {}: {e}", path.display())))?;
        // Replace a previous load of the same unit.
        self.bootout(&unit.label)?;
        let out = launchctl(&["bootstrap", &Self::domain()?, &path.display().to_string()])?;
        if !out.status.success() {
            return Err(failed(format!(
                "launchd refused {}: {}",
                unit.label,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    fn stop(&self, label: &ServiceLabel) -> Result<(), ServiceError> {
        self.bootout(label)?;
        let path = self.plist_path(label);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| ServiceError {
                what: format!("cannot remove {}: {e}", path.display()),
            })?;
        }
        Ok(())
    }

    fn status(&self, label: &ServiceLabel) -> Result<ServiceStatus, ServiceError> {
        let out = launchctl(&["print", &Self::target(label)?])?;
        if out.status.success() {
            return Ok(parse_status(&String::from_utf8_lossy(&out.stdout)));
        }
        // Only "no such service" means not loaded; anything else (no such
        // domain, a refusal) is not knowing, which `stop` must not read as
        // nothing to stop.
        if out.status.code() == Some(NOT_FOUND) {
            return Ok(ServiceStatus::NotLoaded);
        }
        Err(ServiceError {
            what: format!(
                "launchctl cannot say whether {label} runs (exit {}): {}",
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        })
    }

    /// From the job files: `start` writes one before loading it, and `stop`
    /// removes it only once the job is unloaded.
    fn installed(&self, prefix: &str) -> Result<Vec<ServiceLabel>, ServiceError> {
        let entries = match std::fs::read_dir(&self.agents_dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(ServiceError {
                    what: format!("cannot read {}: {e}", self.agents_dir.display()),
                });
            }
        };
        let mut labels = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| ServiceError {
                what: format!("cannot read {}: {e}", self.agents_dir.display()),
            })?;
            let file = entry.file_name();
            let label = file
                .to_str()
                .and_then(|f| f.strip_suffix(".plist"))
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

    #[test]
    fn the_job_file_runs_the_unit_restarts_crashes_logs_and_waits_for_its_stop() {
        let unit = ServiceUnit {
            label: label("enclos.12345678.home.proxy"),
            program: "/usr/local/bin/enclos".into(),
            args: vec![
                "proxy".into(),
                "run".into(),
                "home".into(),
                "--port".into(),
                "41000".into(),
            ],
            log: "/Users/alice/.enclos/sandboxes/home/logs/proxy.log".into(),
            env: vec![("ENCLOS_HOME".into(), "/Users/alice/.enclos".into())],
            stop_timeout: Duration::from_secs(95),
        };
        let text = plist(&unit);
        assert!(text.contains("<key>Label</key><string>enclos.12345678.home.proxy</string>"));
        assert!(
            text.contains("<string>/usr/local/bin/enclos</string>\n    <string>proxy</string>")
        );
        assert!(text.contains("<key>SuccessfulExit</key><false/>"));
        assert!(text.contains("<key>ExitTimeOut</key><integer>95</integer>"));
        assert!(text.contains("<key>StandardErrorPath</key><string>/Users/alice/.enclos/sandboxes/home/logs/proxy.log</string>"));
        assert!(text.contains("<key>ENCLOS_HOME</key><string>/Users/alice/.enclos</string>"));
    }

    #[test]
    fn a_loaded_job_runs_when_launchctl_prints_its_pid() {
        let running = "enclos.12345678.home.proxy = {\n\tactive count = 1\n\tpath = /Users/alice/Library/LaunchAgents/enclos.12345678.home.proxy.plist\n\tstate = running\n\n\tprogram = /usr/local/bin/enclos\n\tpid = 4242\n\truns = 1\n}\n";
        assert_eq!(parse_status(running), ServiceStatus::Running { pid: 4242 });
        let waiting = "enclos.12345678.home.proxy = {\n\tactive count = 0\n\tstate = not running\n\truns = 3\n\tlast exit code = 1\n}\n";
        assert_eq!(parse_status(waiting), ServiceStatus::Loaded);
        assert_eq!(parse_status("\tpid = many\n"), ServiceStatus::Loaded);
    }

    #[test]
    fn installed_labels_are_the_job_files_with_the_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let launchd = Launchd::for_user(dir.path());
        assert!(launchd.installed("enclos.").unwrap().is_empty());
        std::fs::create_dir_all(&launchd.agents_dir).unwrap();
        for file in [
            "enclos.12345678.home.proxy.plist",
            "enclos.12345678.home.gateway.plist",
            "enclos.12345678.homework.proxy.plist",
            "com.example.other.plist",
            "enclos.12345678.home.notes",
        ] {
            std::fs::write(launchd.agents_dir.join(file), "").unwrap();
        }
        assert_eq!(
            launchd.installed("enclos.12345678.home.").unwrap(),
            [
                label("enclos.12345678.home.gateway"),
                label("enclos.12345678.home.proxy")
            ]
        );
    }

    #[test]
    fn markup_in_values_is_escaped() {
        assert_eq!(escape("a<b>&c"), "a&lt;b&gt;&amp;c");
    }

    #[test]
    fn a_job_launchd_is_still_ending_is_waited_for() {
        let asked = std::cell::Cell::new(0);
        let status = || {
            asked.set(asked.get() + 1);
            Ok(match asked.get() {
                1..=3 => ServiceStatus::Running { pid: 1 },
                _ => ServiceStatus::NotLoaded,
            })
        };
        let poll = Duration::from_millis(1);
        assert!(until_unloaded(status, Duration::from_secs(5), poll).unwrap());
        assert_eq!(asked.get(), 4);
    }

    #[test]
    fn a_job_still_loaded_at_the_deadline_is_not_unloaded() {
        let asked = std::cell::Cell::new(0);
        let status = || {
            asked.set(asked.get() + 1);
            Ok(ServiceStatus::Loaded)
        };
        let poll = Duration::from_millis(1);
        assert!(!until_unloaded(status, Duration::ZERO, poll).unwrap());
        assert_eq!(asked.get(), 1, "no wait asks once");
        assert!(!until_unloaded(status, Duration::from_millis(20), poll).unwrap());
        let failing = || {
            Err(ServiceError {
                what: "no domain".into(),
            })
        };
        assert!(until_unloaded(failing, Duration::from_secs(5), poll).is_err());
    }
}
