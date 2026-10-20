//! launchd user agents (macOS): one job file per unit in
//! `~/Library/LaunchAgents`, loaded into the user's login session.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use super::{ServiceError, ServiceManager, ServiceStatus, ServiceUnit};

pub struct Launchd {
    /// The folder job files go in: `~/Library/LaunchAgents`.
    pub agents_dir: PathBuf,
}

impl Launchd {
    fn plist_path(&self, label: &str) -> PathBuf {
        self.agents_dir.join(format!("{label}.plist"))
    }

    fn domain() -> String {
        format!("gui/{}", user_id())
    }
}

/// The user's numeric id, as launchd's domains name it.
fn user_id() -> String {
    Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default()
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// How long launchd waits after TERM before it kills a service: enough for
/// `enclos launch` to stop the runtime it runs (TERM, `STOP_GRACE`, KILL,
/// another `STOP_GRACE`) and record its end.
const EXIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(80);

/// The job file: started at load and at login, restarted if it crashes
/// (not when it exits cleanly), with its output in the unit's log.
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
        label = escape(&unit.label),
        exit_timeout = EXIT_TIMEOUT.as_secs(),
    )
}

fn launchctl(args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new("/bin/launchctl")
        .args(args)
        .stdin(Stdio::null())
        .output()
}

impl ServiceManager for Launchd {
    fn start(&self, unit: &ServiceUnit) -> Result<(), ServiceError> {
        let failed = |what: String| ServiceError { what };
        std::fs::create_dir_all(&self.agents_dir)
            .map_err(|e| failed(format!("cannot create {}: {e}", self.agents_dir.display())))?;
        let path = self.plist_path(&unit.label);
        std::fs::write(&path, plist(unit))
            .map_err(|e| failed(format!("cannot write {}: {e}", path.display())))?;
        // Replace a previous load of the same unit.
        if self.status(&unit.label) != ServiceStatus::NotLoaded {
            let _ = launchctl(&["bootout", &format!("{}/{}", Self::domain(), unit.label)]);
        }
        let out = launchctl(&["bootstrap", &Self::domain(), &path.display().to_string()])
            .map_err(|e| failed(format!("cannot run launchctl: {e}")))?;
        if !out.status.success() {
            return Err(failed(format!(
                "launchd refused {}: {}",
                unit.label,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    fn stop(&self, label: &str) -> Result<(), ServiceError> {
        if self.status(label) != ServiceStatus::NotLoaded {
            let out =
                launchctl(&["bootout", &format!("{}/{label}", Self::domain())]).map_err(|e| {
                    ServiceError {
                        what: format!("cannot run launchctl: {e}"),
                    }
                })?;
            if !out.status.success() && self.status(label) != ServiceStatus::NotLoaded {
                return Err(ServiceError {
                    what: format!(
                        "launchd did not stop {label}: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ),
                });
            }
        }
        let path = self.plist_path(label);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| ServiceError {
                what: format!("cannot remove {}: {e}", path.display()),
            })?;
        }
        Ok(())
    }

    fn status(&self, label: &str) -> ServiceStatus {
        let Ok(out) = launchctl(&["print", &format!("{}/{label}", Self::domain())]) else {
            return ServiceStatus::NotLoaded;
        };
        if !out.status.success() {
            return ServiceStatus::NotLoaded;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines()
            .find_map(|l| {
                l.trim()
                    .strip_prefix("pid = ")
                    .and_then(|p| p.trim().parse().ok())
            })
            .map_or(ServiceStatus::Loaded, |pid| ServiceStatus::Running { pid })
    }

    /// From the job files: `start` writes one before loading it, and `stop`
    /// removes it only once the job is unloaded.
    fn installed(&self, prefix: &str) -> Result<Vec<String>, ServiceError> {
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
                .filter(|l| l.starts_with(prefix));
            labels.extend(label.map(str::to_owned));
        }
        labels.sort();
        Ok(labels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_job_file_runs_the_unit_restarts_crashes_and_logs() {
        let unit = ServiceUnit {
            label: "enclos.home.proxy".into(),
            program: "/usr/local/bin/enclos".into(),
            args: vec![
                "proxy".into(),
                "run".into(),
                "home".into(),
                "--listen".into(),
                "127.0.0.1:41000".into(),
            ],
            log: "/Users/alice/.enclos/sandboxes/home/logs/proxy.log".into(),
            env: vec![("ENCLOS_HOME".into(), "/Users/alice/.enclos".into())],
        };
        let text = plist(&unit);
        assert!(text.contains("<key>Label</key><string>enclos.home.proxy</string>"));
        assert!(
            text.contains("<string>/usr/local/bin/enclos</string>\n    <string>proxy</string>")
        );
        assert!(text.contains("<key>SuccessfulExit</key><false/>"));
        assert!(text.contains("<key>ExitTimeOut</key><integer>80</integer>"));
        assert!(text.contains("<key>StandardErrorPath</key><string>/Users/alice/.enclos/sandboxes/home/logs/proxy.log</string>"));
        assert!(text.contains("<key>ENCLOS_HOME</key><string>/Users/alice/.enclos</string>"));
    }

    #[test]
    fn installed_labels_are_the_job_files_with_the_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let launchd = Launchd {
            agents_dir: dir.path().join("LaunchAgents"),
        };
        assert!(launchd.installed("enclos.").unwrap().is_empty());
        std::fs::create_dir(&launchd.agents_dir).unwrap();
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
            ["enclos.12345678.home.gateway", "enclos.12345678.home.proxy"]
        );
    }

    #[test]
    fn markup_in_values_is_escaped() {
        assert_eq!(escape("a<b>&c"), "a&lt;b&gt;&amp;c");
    }
}
