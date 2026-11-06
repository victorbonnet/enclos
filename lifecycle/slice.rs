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

#[cfg(test)]
mod tests {
    use super::*;

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
