//! A session's cgroup on Linux (design §8, ADR 0019): its program runs in a
//! scope of its own under one slice per sandbox, started by the user's
//! systemd manager through `systemd-run --user --scope`, and its members are
//! the processes in that scope's cgroup, whatever their group, parent or
//! descriptors. macOS has no cgroups: its sessions record none, and nothing
//! here runs for them.
//!
//! A scope's cgroup is read from `/proc/<pid>/cgroup` or asked of systemd,
//! never made from the names: where a slice sits in the hierarchy is
//! systemd's to say.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::descriptors::PROC;
use super::process::PsError;

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const ENV: &str = "/usr/bin/env";
/// Where the kernel shows the cgroup hierarchy.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// What `systemd-run` needs to reach the user's manager; no sandboxed
/// program gets them.
const MANAGER_VARIABLES: [&str; 2] = ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"];
/// What `systemd-run` itself may add to the program's environment.
const SCOPE_VARIABLES: [&str; 1] = ["INVOCATION_ID"];
/// How long a program has to reach its scope. `start` waits under the state
/// lock, and the program does not run before it is there.
const SCOPE_WAIT: Duration = Duration::from_secs(15);
const SCOPE_POLL: Duration = Duration::from_millis(10);

/// `text` as one part of a systemd unit name, as `systemd-escape` writes it.
/// In a slice's name a hyphen means a parent: `a-b.slice` sits under
/// `a.slice`, so sandbox `a-b` would sit inside sandbox `a`'s slice.
fn escaped(text: &str) -> String {
    let mut out = String::new();
    for (i, b) in text.bytes().enumerate() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b':' | b'_' => out.push(b as char),
            b'.' if i > 0 => out.push('.'),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

/// The slice of a sandbox's sessions: `enclos.<install>.<sandbox>.slice`,
/// named as its services are (ADR 0002).
pub fn slice_name(install: &str, sandbox: &str) -> String {
    format!("enclos.{install}.{}.slice", escaped(sandbox))
}

/// The scope of one session of a sandbox; `session` tells it from the
/// sandbox's other sessions.
pub fn scope_name(install: &str, sandbox: &str, session: &str) -> String {
    format!("enclos.{install}.{}.{session}.scope", escaped(sandbox))
}

/// The unified hierarchy's path in the text of `/proc/<pid>/cgroup`.
fn parse_proc_cgroup(text: &str) -> Option<String> {
    let path = text.lines().find_map(|l| l.strip_prefix("0::"))?;
    let path = path.strip_suffix(" (deleted)").unwrap_or(path);
    safe_path(path)
}

/// `path`, when it names a place under the hierarchy's root.
fn safe_path(path: &str) -> Option<String> {
    let parts = path.strip_prefix('/')?.split('/');
    let safe = !path.ends_with('/') && parts.into_iter().all(|p| !p.is_empty() && p != "..");
    safe.then(|| path.to_owned())
}

/// The cgroup in what `systemctl --user show --property=ControlGroup`
/// printed: none for a scope with nothing left in it.
fn parse_control_group(text: &str) -> Result<Option<String>, PsError> {
    let Some(value) = text.lines().find_map(|l| l.strip_prefix("ControlGroup=")) else {
        return Err(PsError::Cgroup(format!(
            "systemctl did not print a control group: `{}`",
            text.trim()
        )));
    };
    if value.is_empty() {
        return Ok(None);
    }
    safe_path(value)
        .map(Some)
        .ok_or_else(|| PsError::Cgroup(format!("systemd gave the control group `{value}`")))
}

/// The pids in the text of a `cgroup.procs` file. A line that does not parse
/// fails, as in a listing: a process left out would read as gone.
fn parse_procs(text: &str) -> Result<BTreeSet<u32>, PsError> {
    text.lines()
        .map(|line| {
            line.trim()
                .parse()
                .map_err(|_| PsError::Cgroup(format!("unexpected line `{line}` in cgroup.procs")))
        })
        .collect()
}

/// Whether the process's `stat` text says it is a zombie.
fn is_zombie(stat: &str) -> bool {
    // The command, in parentheses, may hold anything.
    stat.rsplit_once(')')
        .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
}

/// Where `pid` is once `unit` holds it. Until then it is `systemd-run`, in
/// the cgroup of whoever started it. A program that ended before it was
/// seen there leaves `ask` to say what is left of the scope.
fn cgroup_from(
    proc: &Path,
    pid: u32,
    unit: &str,
    wait: Duration,
    ask: &dyn Fn() -> Result<Option<String>, PsError>,
) -> Result<Option<String>, PsError> {
    let folder = proc.join(pid.to_string());
    let started = Instant::now();
    loop {
        let path = std::fs::read_to_string(folder.join("cgroup"))
            .ok()
            .and_then(|text| parse_proc_cgroup(&text));
        if let Some(path) = path.filter(|p| p.rsplit('/').next() == Some(unit)) {
            return Ok(Some(path));
        }
        let ended = std::fs::read_to_string(folder.join("stat")).map_or(true, |s| is_zombie(&s));
        if ended {
            return ask();
        }
        if started.elapsed() >= wait {
            return Err(PsError::Cgroup(format!(
                "pid {pid} did not reach {unit} within {} s",
                wait.as_secs()
            )));
        }
        std::thread::sleep(SCOPE_POLL);
    }
}

/// The scope a session's program runs in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    slice: String,
    unit: String,
}

impl Scope {
    /// A new scope for a session of `sandbox`.
    pub fn new(install: &str, sandbox: &str) -> Scope {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let session = format!("session-{}-{nanos}", std::process::id());
        Scope {
            slice: slice_name(install, sandbox),
            unit: scope_name(install, sandbox, &session),
        }
    }

    /// `command` as a program of this scope: `systemd-run` joins the scope,
    /// then becomes the program, so the pid, the group, the terminal and the
    /// inherited descriptors stay the same. `manager` holds the variables
    /// that reach the user's manager, which `/usr/bin/env` removes again.
    /// `command` gave the whole environment the program runs with, as a
    /// backend's `wrap` does for a Linux host, and no standard stream yet.
    fn around(&self, command: &Command, manager: &[(OsString, OsString)]) -> Command {
        let mut scoped = Command::new(SYSTEMD_RUN);
        scoped
            .args(["--user", "--scope", "--quiet", "--collect"])
            .arg(format!("--slice={}", self.slice))
            .arg(format!("--unit={}", self.unit))
            .args(["--", ENV]);
        for name in MANAGER_VARIABLES.iter().chain(&SCOPE_VARIABLES) {
            scoped.args(["-u", name]);
        }
        scoped.arg(command.get_program()).args(command.get_args());
        scoped.env_clear();
        for (name, value) in command.get_envs() {
            if let Some(value) = value {
                scoped.env(name, value);
            }
        }
        scoped.envs(manager.iter().map(|(n, v)| (n, v)));
        if let Some(folder) = command.get_current_dir() {
            scoped.current_dir(folder);
        }
        scoped
    }

    /// `command` as a program of this scope, reaching the manager this
    /// process reaches.
    pub fn wrap(&self, command: &Command) -> Command {
        let manager: Vec<_> = MANAGER_VARIABLES
            .iter()
            .filter_map(|name| Some((name.into(), std::env::var_os(name)?)))
            .collect();
        self.around(command, &manager)
    }

    /// The cgroup of the scope `pid` was started in, or none when the scope
    /// ended with its program.
    pub fn cgroup_of(&self, pid: u32) -> Result<Option<String>, PsError> {
        cgroup_from(Path::new(PROC), pid, &self.unit, SCOPE_WAIT, &|| {
            self.control_group()
        })
    }

    /// What systemd says of the scope's cgroup.
    fn control_group(&self) -> Result<Option<String>, PsError> {
        let out = Command::new(SYSTEMCTL)
            .args(["--user", "show", "--property=ControlGroup", &self.unit])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| PsError::Cgroup(format!("cannot run systemctl: {e}")))?;
        if !out.status.success() {
            return Err(PsError::Cgroup(format!(
                "systemctl cannot say where {} is: {}",
                self.unit,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        parse_control_group(&String::from_utf8_lossy(&out.stdout))
    }
}

/// The cgroup hierarchy of this host, or a folder standing in for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hierarchy {
    root: PathBuf,
}

impl Hierarchy {
    pub fn host() -> Hierarchy {
        Hierarchy::at(Path::new(CGROUP_ROOT))
    }

    pub fn at(root: &Path) -> Hierarchy {
        Hierarchy {
            root: root.to_owned(),
        }
    }

    fn folder(&self, cgroup: &str) -> PathBuf {
        self.root.join(cgroup.trim_start_matches('/'))
    }

    /// The pids in `cgroup` and every cgroup below it, where a same-user
    /// process may have moved. A cgroup removed is empty: systemd removes
    /// one once nothing is left in it. Any other failure is an error, never
    /// an empty answer.
    pub fn pids(&self, cgroup: &str) -> Result<BTreeSet<u32>, PsError> {
        let mut pids = BTreeSet::new();
        let mut folders = vec![self.folder(cgroup)];
        while let Some(folder) = folders.pop() {
            let failed = |e: std::io::Error| {
                PsError::Cgroup(format!("cannot read {}: {e}", folder.display()))
            };
            let gone = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound;
            match std::fs::read_to_string(folder.join("cgroup.procs")) {
                Err(e) if gone(&e) => {}
                text => pids.extend(parse_procs(&text.map_err(failed)?)?),
            }
            let entries = match std::fs::read_dir(&folder) {
                Err(e) if gone(&e) => continue,
                entries => entries.map_err(failed)?,
            };
            for entry in entries {
                let entry = entry.map_err(failed)?;
                if entry.path().is_dir() {
                    folders.push(entry.path());
                }
            }
        }
        Ok(pids)
    }

    /// Kills everything in `cgroup` and below it at once, so that a member
    /// forking meanwhile is not missed. Best effort: `cgroup.kill` needs
    /// Linux 5.14, and the caller then signals what it lists and checks what
    /// remains.
    pub fn kill(&self, cgroup: &str) {
        let _ = std::fs::write(self.folder(cgroup).join("cgroup.kill"), "1");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slice_is_named_after_the_install_and_the_sandbox() {
        assert_eq!(slice_name("1f2e3d4c", "home"), "enclos.1f2e3d4c.home.slice");
    }

    #[test]
    fn a_hyphen_in_a_sandbox_name_does_not_make_a_parent_slice() {
        let slice = slice_name("1f2e3d4c", "pi-bot");
        assert_eq!(slice, r"enclos.1f2e3d4c.pi\x2dbot.slice");
        assert!(!slice.contains('-'));
    }

    #[test]
    fn the_longest_sandbox_name_of_hyphens_stays_a_valid_unit_name() {
        let name = format!("a{}", "-".repeat(40));
        let scope = Scope::new("1f2e3d4c", &name);
        for unit in [&scope.slice, &scope.unit] {
            assert!(unit.len() <= 255, "{unit}");
            assert!(
                unit.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.:\\".contains(&b)),
                "{unit}"
            );
        }
    }

    #[test]
    fn two_scopes_of_a_sandbox_have_two_names_in_its_slice() {
        let first = Scope::new("1f2e3d4c", "home");
        std::thread::sleep(Duration::from_millis(1));
        let second = Scope::new("1f2e3d4c", "home");
        assert_eq!(first.slice, second.slice);
        assert_ne!(first.unit, second.unit);
        assert!(first.unit.starts_with("enclos.1f2e3d4c.home.session-"));
        assert!(first.unit.ends_with(".scope"));
    }

    fn words(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    fn scope() -> Scope {
        Scope {
            slice: "enclos.1f2e3d4c.home.slice".into(),
            unit: "enclos.1f2e3d4c.home.session-1.scope".into(),
        }
    }

    #[test]
    fn a_program_runs_through_systemd_run_with_no_way_to_the_manager() {
        let mut program = Command::new("/bin/prog");
        program.arg("--flag");
        let command = scope().around(&program, &[]);
        assert_eq!(command.get_program(), SYSTEMD_RUN);
        assert_eq!(
            words(&command),
            [
                "--user",
                "--scope",
                "--quiet",
                "--collect",
                "--slice=enclos.1f2e3d4c.home.slice",
                "--unit=enclos.1f2e3d4c.home.session-1.scope",
                "--",
                "/usr/bin/env",
                "-u",
                "XDG_RUNTIME_DIR",
                "-u",
                "DBUS_SESSION_BUS_ADDRESS",
                "-u",
                "INVOCATION_ID",
                "/bin/prog",
                "--flag",
            ]
        );
    }

    #[test]
    fn systemd_run_gets_the_programs_environment_and_folder_and_the_managers_variables() {
        let mut program = Command::new("/bin/prog");
        program.env_clear().env("HOME", "/h").current_dir("/h");
        let manager = [("XDG_RUNTIME_DIR".into(), "/run/user/1000".into())];
        let command = scope().around(&program, &manager);
        let env: Vec<_> = command
            .get_envs()
            .map(|(n, v)| (n.to_owned(), v.map(ToOwned::to_owned)))
            .collect();
        assert_eq!(
            env,
            [
                ("HOME".into(), Some("/h".into())),
                ("XDG_RUNTIME_DIR".into(), Some("/run/user/1000".into())),
            ]
        );
        assert_eq!(command.get_current_dir(), Some(Path::new("/h")));
    }

    const IN_SCOPE: &str =
        "/user.slice/user-1000.slice/user@1000.service/enclos.a.home.slice/s.scope";

    #[test]
    fn proc_gives_the_unified_hierarchys_path() {
        let text = format!("1:name=systemd:/other\n0::{IN_SCOPE}\n");
        assert_eq!(parse_proc_cgroup(&text).as_deref(), Some(IN_SCOPE));
        let ended = format!("0::{IN_SCOPE} (deleted)\n");
        assert_eq!(parse_proc_cgroup(&ended).as_deref(), Some(IN_SCOPE));
    }

    #[test]
    fn a_path_leaving_the_hierarchy_is_not_read() {
        for text in [
            "",
            "1:cpu:/a\n",
            "0::relative\n",
            "0::/../..\n",
            "0::/a//b\n",
        ] {
            assert_eq!(parse_proc_cgroup(text), None, "{text:?}");
        }
    }

    #[test]
    fn systemctl_gives_the_scopes_cgroup_or_none() {
        let shown = format!("ControlGroup={IN_SCOPE}\n");
        assert_eq!(
            parse_control_group(&shown).unwrap().as_deref(),
            Some(IN_SCOPE)
        );
        assert_eq!(parse_control_group("ControlGroup=\n").unwrap(), None);
        assert!(parse_control_group("Other=1\n").is_err());
        assert!(parse_control_group("ControlGroup=../x\n").is_err());
    }

    #[test]
    fn cgroup_procs_gives_its_pids_and_a_line_it_cannot_read_is_an_error() {
        assert_eq!(parse_procs("12\n7\n").unwrap(), BTreeSet::from([7, 12]));
        assert!(parse_procs("").unwrap().is_empty());
        assert!(parse_procs("12\nabc\n").is_err());
    }

    #[test]
    fn a_zombie_is_read_from_stat_whatever_its_command() {
        assert!(is_zombie("12 (a) b) Z 1 12"));
        assert!(!is_zombie("12 (Z) Z) S 1 12"));
    }

    /// A stand-in for `/proc` holding one process.
    fn proc_with(pid: u32, cgroup: &str, stat: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join(pid.to_string());
        std::fs::create_dir(&folder).unwrap();
        std::fs::write(folder.join("cgroup"), cgroup).unwrap();
        std::fs::write(folder.join("stat"), stat).unwrap();
        dir
    }

    fn never_asked() -> Result<Option<String>, PsError> {
        panic!("systemd was asked")
    }

    #[test]
    fn a_scopes_cgroup_is_read_from_proc_once_the_program_is_in_it() {
        let proc = proc_with(7, "0::/a.slice/s.scope\n", "7 (x) S 1");
        let found = cgroup_from(proc.path(), 7, "s.scope", SCOPE_WAIT, &never_asked);
        assert_eq!(found.unwrap().as_deref(), Some("/a.slice/s.scope"));
    }

    #[test]
    fn a_process_not_yet_in_its_scope_is_waited_for_then_refused() {
        let proc = proc_with(7, "0::/caller.scope\n", "7 (x) S 1");
        let found = cgroup_from(
            proc.path(),
            7,
            "s.scope",
            Duration::from_millis(30),
            &never_asked,
        );
        assert!(found.unwrap_err().to_string().contains("s.scope"));
    }

    #[test]
    fn a_program_that_ended_first_leaves_systemd_to_say() {
        let zombie = proc_with(7, "0::/caller.scope\n", "7 (x) Z 1");
        let left = || Ok(Some("/a.slice/s.scope".to_owned()));
        let found = cgroup_from(zombie.path(), 7, "s.scope", SCOPE_WAIT, &left);
        assert_eq!(found.unwrap().as_deref(), Some("/a.slice/s.scope"));
        let reaped = tempfile::tempdir().unwrap();
        let found = cgroup_from(reaped.path(), 7, "s.scope", SCOPE_WAIT, &|| Ok(None));
        assert_eq!(found.unwrap(), None);
    }

    fn hierarchy(procs: &[(&str, &str)]) -> (tempfile::TempDir, Hierarchy) {
        let dir = tempfile::tempdir().unwrap();
        for (cgroup, text) in procs {
            let folder = dir.path().join(cgroup);
            std::fs::create_dir_all(&folder).unwrap();
            std::fs::write(folder.join("cgroup.procs"), text).unwrap();
        }
        let hierarchy = Hierarchy::at(dir.path());
        (dir, hierarchy)
    }

    #[test]
    fn a_cgroups_pids_include_those_of_the_cgroups_below_it() {
        let (_dir, cgroups) = hierarchy(&[("s.scope", "1\n2\n"), ("s.scope/sub/more", "3\n")]);
        assert_eq!(cgroups.pids("/s.scope").unwrap(), BTreeSet::from([1, 2, 3]));
    }

    #[test]
    fn a_removed_cgroup_is_empty_and_one_that_cannot_be_read_is_an_error() {
        let (dir, cgroups) = hierarchy(&[("bad.scope", "x\n")]);
        assert!(cgroups.pids("/gone.scope").unwrap().is_empty());
        assert!(cgroups.pids("/bad.scope").is_err());
        std::fs::create_dir_all(dir.path().join("dir.scope/cgroup.procs")).unwrap();
        assert!(cgroups.pids("/dir.scope").is_err());
    }

    #[test]
    fn kill_asks_the_kernel_to_end_the_cgroup() {
        let (dir, cgroups) = hierarchy(&[("s.scope", "1\n")]);
        cgroups.kill("/s.scope");
        let asked = std::fs::read_to_string(dir.path().join("s.scope/cgroup.kill"));
        assert_eq!(asked.unwrap(), "1");
    }
}
