//! The probes of Linux's routes that are not files: the buses and the
//! user's manager, sockets, other processes, and what would act with more
//! than the user's rights.

use std::path::{Path, PathBuf};

use super::super::sockets::Address;
use super::calls::{self, Numbers};
use super::{BubblewrapProbes, ITSELF};
use crate::backend::environment::SANDBOX_VARIABLE;
use crate::probes::{
    Expect, Outcome, OwnReading, Probe, ProbeInputs, TARGET_VARIABLE, probe, same_outside, sh_quote,
};

/// Set-group-ID `shadow` on Debian and Ubuntu, so `chage -l` reads the
/// user's line of `/etc/shadow`, which the user alone may not.
pub(super) const CHAGE: &str = "/usr/bin/chage";
pub(super) const CRONTAB_PROGRAM: &str = "/usr/bin/crontab";
pub(super) const ATQ: &str = "/usr/bin/atq";

/// `crontab -l` without its group, which `no_new_privs` keeps it from
/// taking, cannot reach the spool: what it prints when the user has no
/// crontab says it did.
pub(super) const CRONTAB: OwnReading = OwnReading {
    label: "crontab without its group",
    read: |succeeded, output| {
        if succeeded {
            Outcome::Open("it read the crontab, so crontab ran with its group".to_owned())
        } else if output.contains("no crontab for") {
            Outcome::Open("crontab reached the spool, so it ran with its group".to_owned())
        } else {
            Outcome::Closed
        }
    },
    when_control_fails: None,
};

impl BubblewrapProbes {
    /// The buses and the user's manager, each through its own client, at
    /// the address the host has.
    pub(super) fn services(&self) -> Vec<Probe> {
        let facts = &self.facts;
        let quoted = |text: &str| sh_quote(Path::new(text));
        let mut list = Vec::new();
        if let Some(address) = &facts.session_bus {
            list.push(same_outside(
                "session bus",
                "list the names on the session bus",
                &format!(
                    "DBUS_SESSION_BUS_ADDRESS={} /usr/bin/busctl --user --no-pager list >/dev/null 2>&1",
                    quoted(address)
                ),
            ));
        }
        if let Some(socket) = &facts.system_bus {
            list.push(same_outside(
                "system bus",
                "list the names on the system bus",
                &format!(
                    "DBUS_SYSTEM_BUS_ADDRESS={} /usr/bin/busctl --system --no-pager list >/dev/null 2>&1",
                    quoted(&format!("unix:path={}", socket.display()))
                ),
            ));
        }
        if let Some(dir) = &facts.runtime_dir {
            list.push(same_outside(
                "systemd --user",
                "ask the user's systemd manager for its version",
                &format!(
                    "XDG_RUNTIME_DIR={} /usr/bin/systemctl --user --no-pager show --property=Version >/dev/null 2>&1",
                    sh_quote(dir)
                ),
            ));
        }
        list
    }

    /// Every Unix socket that answers the user on the host, enclos's own
    /// abstract one, and those listening in the other sandboxes' network
    /// namespaces.
    pub(super) fn sockets(&self) -> Vec<Probe> {
        let facts = &self.facts;
        let mut list = Vec::new();
        for socket in &facts.sockets {
            let shown = socket.address.shown();
            let route = match socket.address {
                Address::Path(_) => "host sockets",
                Address::Abstract(_) => "abstract sockets",
            };
            list.push(calls::connect_to(
                route,
                format!("connect to {shown}"),
                &shown,
                socket.kind,
            ));
        }
        if let Some(name) = &facts.abstract_target {
            list.push(calls::connect_to(
                "abstract sockets",
                format!("connect to @{name}, where enclos listens on the host"),
                &format!("@{name}"),
                1,
            ));
        }
        for other in &facts.other_sockets {
            let shown = other.socket.address.shown();
            let name = format!("connect to {shown}, of sandbox {}", other.sandbox);
            list.push(match other.socket.address {
                Address::Path(_) => {
                    calls::connect_to("other sandboxes", name, &shown, other.socket.kind)
                }
                Address::Abstract(_) => {
                    calls::connect_elsewhere(name, &shown, other.socket.kind, &other.table)
                }
            });
        }
        list
    }

    /// The process the host started for the signal probe and the other
    /// sandboxes' processes: attaching to one, and reading the start-up
    /// environment of each, which the host reads.
    pub(super) fn processes(&self, i: &ProbeInputs) -> Vec<Probe> {
        let mut list = Vec::new();
        let Some(target) = i.target else {
            return list;
        };
        if let Some(numbers) = Numbers::here() {
            list.push(numbers.ptrace(target));
        }
        list.push(environment_probe(
            "read the start-up environment of a process outside the sandbox",
            target,
            &format!("{TARGET_VARIABLE}=1"),
        ));
        for other in &self.facts.other_processes {
            list.push(environment_probe(
                &format!(
                    "read the start-up environment of a process of sandbox {}",
                    other.sandbox
                ),
                other.pid,
                &format!("{SANDBOX_VARIABLE}={}", other.sandbox),
            ));
        }
        list
    }

    /// Programs that would act with more than the user's rights, and the
    /// calls that make a namespace or a mount.
    pub(super) fn privileges(&self, i: &ProbeInputs) -> Vec<Probe> {
        let mut list = Vec::new();
        let itself = |mut probe: Probe| {
            probe.closed_by = Some(ITSELF);
            probe
        };
        // Not `passwd -S`, which prints the user's status without its
        // privileges too.
        if Path::new(CHAGE).exists() {
            list.push(itself(same_outside(
                "setuid",
                "run a setgid program, chage -l, which reads /etc/shadow",
                &format!("{CHAGE} -l \"$(/usr/bin/id -un)\" >/dev/null 2>&1"),
            )));
        }
        if Path::new(CRONTAB_PROGRAM).exists() {
            list.push(itself(probe(
                "crontab",
                "read the crontab",
                format!("{CRONTAB_PROGRAM} -l 2>&1 >/dev/null"),
                Expect::Own(CRONTAB),
                format!(
                    "{CRONTAB_PROGRAM} -l >/dev/null 2>&1 || {CRONTAB_PROGRAM} -l 2>&1 | /usr/bin/grep -q 'no crontab for'"
                ),
            )));
        }
        if Path::new(ATQ).exists() {
            list.push(itself(same_outside(
                "at",
                "list the `at` queue",
                &format!("{ATQ} >/dev/null 2>&1"),
            )));
        }
        if let Some(numbers) = Numbers::here() {
            list.push(numbers.user_namespace());
            list.push(numbers.mount(&PathBuf::from(format!("/enclos-probe-{}-missing", i.tag))));
        }
        list
    }
}

/// Reads the start-up environment of process `pid`, closed when `line` is
/// not in what it read; its control finds the line on the host. A pid the
/// session's own PID namespace happens to hold is another process, without
/// that line.
pub(super) fn environment_probe(name: &str, pid: u32, line: &str) -> Probe {
    same_outside(
        "environment",
        name,
        &format!(
            "/usr/bin/tr '\\0' '\\n' < /proc/{pid}/environ | /usr/bin/grep -qxF -- {}",
            sh_quote(Path::new(line))
        ),
    )
}
