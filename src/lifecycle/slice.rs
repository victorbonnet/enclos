//! The limits a sandbox's slice holds (design §7): `memory` and `cpu` on
//! the sandbox as a whole. Every session's scope and every service's sits in
//! the sandbox's slice (design §8), so the slice's cap holds them together.
//! They are set as the slice's properties, for this boot alone, before each
//! program of the sandbox starts, so the slice always holds what the active
//! policy says: a change of limits waits while sessions run (design §7).

use std::process::{Command, Stdio};

use super::process::PsError;

const SYSTEMCTL: &str = "/usr/bin/systemctl";

/// What a sandbox's slice holds its processes to together.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SliceLimits {
    /// The bytes of memory, with no swap beyond them: past it the kernel
    /// stops a process of the sandbox.
    pub memory: Option<u64>,
    /// A share of the CPU, as a percentage of one core: 50 is half of one.
    pub cpu_percent: Option<u32>,
}

impl SliceLimits {
    /// The slice's properties that set them, each one not set reset to no
    /// limit, so a limit a policy dropped is not left behind.
    fn properties(&self) -> Vec<String> {
        let (memory, swap) = match self.memory {
            Some(bytes) => (bytes.to_string(), "0".to_owned()),
            None => ("infinity".to_owned(), "infinity".to_owned()),
        };
        let cpu = self
            .cpu_percent
            .map(|p| format!("{p}%"))
            .unwrap_or_default();
        vec![
            format!("MemoryMax={memory}"),
            format!("MemorySwapMax={swap}"),
            format!("CPUQuota={cpu}"),
        ]
    }

    pub fn is_unset(&self) -> bool {
        *self == SliceLimits::default()
    }
}

/// Sets `limits` on `slice` in the user's systemd manager, until the next
/// boot; the slice need not run yet, and holds them once it does.
pub fn hold(slice: &str, limits: &SliceLimits) -> Result<(), PsError> {
    let out = Command::new(SYSTEMCTL)
        .args(["--user", "set-property", "--runtime", slice])
        .args(limits.properties())
        .stdin(Stdio::null())
        .output()
        .map_err(|e| PsError::Cgroup(format!("cannot run systemctl: {e}")))?;
    if !out.status.success() {
        return Err(PsError::Cgroup(format!(
            "systemctl cannot set the limits of {slice}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Stops `slice`, which systemd keeps active once a scope started in it,
/// and drops the limits [`hold`] set on it, once its sandbox is gone. Asks
/// systemd first, so a slice no session ever started is left alone.
pub fn release(slice: &str) -> Result<(), PsError> {
    let out = systemctl(&[
        "show",
        "--property=ActiveState",
        "--property=DropInPaths",
        slice,
    ])?;
    let (active, drop_ins) = state_of(&String::from_utf8_lossy(&out.stdout));
    if active {
        systemctl(&["stop", slice])?;
    }
    if drop_ins {
        systemctl(&["revert", slice])?;
    }
    Ok(())
}

/// Whether `systemctl show` says a unit is active, and has drop-ins.
fn state_of(shown: &str) -> (bool, bool) {
    let value = |name: &str| {
        shown
            .lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix('='))
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    (
        value("ActiveState") == "active",
        !value("DropInPaths").is_empty(),
    )
}

/// `systemctl --user` with `args`, failing on a failure it reports.
fn systemctl(args: &[&str]) -> Result<std::process::Output, PsError> {
    let out = Command::new(SYSTEMCTL)
        .arg("--user")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| PsError::Cgroup(format!("cannot run systemctl: {e}")))?;
    if !out.status.success() {
        return Err(PsError::Cgroup(format!(
            "systemctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A slice is stopped only when it runs, and reverted only when
    /// something set its properties.
    #[test]
    fn a_slice_is_released_by_what_systemd_says_of_it() {
        assert_eq!(
            state_of(
                "ActiveState=active\nDropInPaths=/run/user/1000/systemd/user.control/x.slice.d/50-MemoryMax.conf\n"
            ),
            (true, true)
        );
        assert_eq!(
            state_of("ActiveState=inactive\nDropInPaths=\n"),
            (false, false)
        );
        assert_eq!(state_of(""), (false, false));
    }

    /// No swap beyond the memory limit, so a process past it is stopped.
    #[test]
    fn a_slices_limits_are_its_properties() {
        let limits = SliceLimits {
            memory: Some(512 << 20),
            cpu_percent: Some(50),
        };
        assert_eq!(
            limits.properties(),
            ["MemoryMax=536870912", "MemorySwapMax=0", "CPUQuota=50%"]
        );
    }

    /// A limit the policy no longer sets is lifted, not left as it was.
    #[test]
    fn a_limit_not_set_is_reset_to_none() {
        assert_eq!(
            SliceLimits::default().properties(),
            ["MemoryMax=infinity", "MemorySwapMax=infinity", "CPUQuota="]
        );
        let cpu_only = SliceLimits {
            cpu_percent: Some(200),
            ..SliceLimits::default()
        };
        assert_eq!(cpu_only.properties()[2], "CPUQuota=200%");
    }
}
