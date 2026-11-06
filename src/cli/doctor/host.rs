//! doctor's report on the host: the systemd it found, where sessions run in
//! scopes, and what each backend, the service manager and the secret
//! stores need from the host, with what to do.

use enclos::host::{HostCheck, Verdict};
use enclos::lifecycle::cgroup::{SYSTEMD_NEEDED, Systemd};

use super::hanging;

/// The host's section as text: nothing on a host with nothing to say, as on
/// macOS.
pub fn shown(systemd: Option<&Systemd>, checks: &[HostCheck]) -> String {
    if systemd.is_none() && checks.is_empty() {
        return String::new();
    }
    let mut out = String::from("\nHost\n");
    if let Some(systemd) = systemd {
        out += &format!("  {}\n", hanging(&systemd_line(systemd), 4));
    }
    for check in checks {
        out += &check_lines(check);
    }
    out
}

fn systemd_line(systemd: &Systemd) -> String {
    match systemd {
        Systemd::Enough(version) => {
            format!("systemd {version}: enclos needs {SYSTEMD_NEEDED} or later")
        }
        other => other.refusal().unwrap_or_default(),
    }
}

/// A check's line, and under it, indented, what follows from it.
fn check_lines(check: &HostCheck) -> String {
    let tag = match check.verdict {
        Verdict::Fine | Verdict::Note => "",
        Verdict::Degraded { .. } => " (degraded)",
        Verdict::Blocks => " (keeps the backend from running)",
    };
    let mut out = format!(
        "  {}\n",
        hanging(&format!("{}{tag}: {}", check.what, check.found), 4)
    );
    let mut said = |label: &str, text: &str| {
        out += &format!("    {}\n", hanging(&format!("{label}: {text}"), 6));
    };
    if let Verdict::Degraded { not_enforced, risk } = &check.verdict {
        said("not enforced", not_enforced);
        said("risk", risk);
    }
    if let Some(fix) = &check.fix {
        said("fix", fix);
    }
    out
}

/// The systemd found, as JSON.
pub fn systemd_json(systemd: &Systemd) -> serde_json::Value {
    serde_json::json!({
        "version": match systemd {
            Systemd::Enough(version) | Systemd::TooOld(version) => Some(version),
            Systemd::Unreadable(_) => None,
        },
        "needed": SYSTEMD_NEEDED,
        "problem": systemd.refusal(),
    })
}

/// Each check, as JSON.
pub fn checks_json(checks: &[HostCheck]) -> serde_json::Value {
    use serde_json::json;
    checks
        .iter()
        .map(|c| {
            let (verdict, not_enforced, risk) = match &c.verdict {
                Verdict::Fine => ("fine", None, None),
                Verdict::Note => ("note", None, None),
                Verdict::Degraded { not_enforced, risk } => {
                    ("degraded", Some(not_enforced), Some(risk))
                }
                Verdict::Blocks => ("blocks", None, None),
            };
            json!({
                "what": c.what,
                "verdict": verdict,
                "found": c.found,
                "not_enforced": not_enforced,
                "risk": risk,
                "fix": c.fix,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn degraded() -> HostCheck {
        HostCheck::new(
            "memory controller",
            "not in the kernel: /sys/fs/cgroup/cgroup.controllers lists `cpuset cpu io pids`",
            Verdict::Degraded {
                not_enforced: "a `memory` limit".into(),
                risk: "no memory cap: a runaway agent can exhaust the host's RAM".into(),
            },
            Some("add ` cgroup_enable=memory` to the end of the single line in /boot/firmware/cmdline.txt, reboot, and check that `memory` is in /sys/fs/cgroup/cgroup.controllers".into()),
        )
    }

    #[test]
    fn nothing_is_said_of_a_host_with_nothing_to_say() {
        assert_eq!(shown(None, &[]), "");
    }

    /// The systemd line first, then each check; a degraded control with
    /// what is not enforced, the risk and the fix, each in its column.
    #[test]
    fn each_check_says_what_was_found_and_what_follows() {
        let checks = [
            HostCheck::fine(
                "bubblewrap",
                "/usr/bin/bwrap is bubblewrap 0.12.0: enclos needs 0.9.0 or later",
            ),
            degraded(),
            HostCheck::note(
                "lingering",
                "off: systemd stops your manager at your last logout",
                Some("`loginctl enable-linger`".into()),
            ),
        ];
        let text = shown(Some(&Systemd::Enough(257)), &checks);
        assert!(
            text.starts_with("\nHost\n  systemd 257: enclos needs 254 or later\n  bubblewrap: /usr/bin/bwrap is bubblewrap 0.12.0"),
            "{text}"
        );
        assert!(
            text.contains("  memory controller (degraded): not in the kernel"),
            "{text}"
        );
        assert!(
            text.contains("\n    not enforced: a `memory` limit\n"),
            "{text}"
        );
        assert!(text.contains("\n    risk: no memory cap"), "{text}");
        assert!(
            text.contains("\n    fix: add ` cgroup_enable=memory`"),
            "{text}"
        );
        assert!(text.contains("  lingering: off"), "{text}");
        for line in text.lines() {
            assert!(line.len() <= super::super::WIDTH, "{line:?}");
        }
    }

    #[test]
    fn a_check_that_blocks_says_so() {
        let check = HostCheck::blocks(
            "bubblewrap",
            "/usr/bin/bwrap is missing",
            Some("install the bubblewrap package".into()),
        );
        let text = shown(None, &[check]);
        assert!(
            text.contains("bubblewrap (keeps the backend from running): /usr/bin/bwrap"),
            "{text}"
        );
        assert!(
            text.contains("    fix: install the bubblewrap package"),
            "{text}"
        );
    }

    #[test]
    fn checks_as_json_keep_each_part() {
        let json = checks_json(&[
            degraded(),
            HostCheck::fine("Landlock", "ABI 8: the rules need 6"),
        ]);
        assert_eq!(json[0]["what"], "memory controller");
        assert_eq!(json[0]["verdict"], "degraded");
        assert_eq!(json[0]["not_enforced"], "a `memory` limit");
        assert!(
            json[0]["risk"]
                .as_str()
                .unwrap()
                .starts_with("no memory cap")
        );
        assert!(json[0]["fix"].as_str().unwrap().contains("cmdline.txt"));
        assert_eq!(json[1]["verdict"], "fine");
        assert!(json[1]["fix"].is_null());
        assert!(json[1]["not_enforced"].is_null());
    }
}
