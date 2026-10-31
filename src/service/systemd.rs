//! systemd user units (Linux): one unit file per service in the user's
//! systemd folder, run by the user's own manager through `systemctl --user`.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::{ServiceError, ServiceLabel, ServiceUnit};

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
}
