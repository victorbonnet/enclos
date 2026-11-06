//! The limits a sandbox's slice holds (design §7): `memory` and `cpu`, as a
//! policy writes them and as a backend reads them. The policy keeps both as
//! written, so a backend that refuses them says only that, whatever the
//! value; one that holds them reads them here.

use std::fmt;
use std::str::FromStr;

use super::policy::ByteSize;

/// The least `memory` enclos accepts: a session's own programs, bubblewrap
/// and `enclos inside` need some, and below this the first of them would be
/// stopped before the program runs.
pub const MEMORY_LEAST: u64 = 64 << 20;
/// The most: past it, a value is no limit on any host.
pub const MEMORY_MOST: u64 = 1 << 50;

/// A memory limit, as `memory` writes it: a size such as `512M` or `2G`,
/// bounded by [`MEMORY_LEAST`] and [`MEMORY_MOST`].
pub fn memory(written: &str) -> Result<ByteSize, String> {
    let size: ByteSize = written
        .parse()
        .map_err(|e| format!("resources.memory: {e}"))?;
    if !(MEMORY_LEAST..=MEMORY_MOST).contains(&size.0) {
        return Err(format!(
            "resources.memory = {written}: set it from {} to {}",
            ByteSize(MEMORY_LEAST),
            ByteSize(MEMORY_MOST)
        ));
    }
    Ok(size)
}

/// A share of the CPU, as `cpu` writes it: a number of cores, such as `0.5`
/// for half of one, or `2` for two, with at most two decimals, from 0.01 to
/// 1024. Kept as hundredths of a core, which is what systemd's `CPUQuota=`
/// takes as a percentage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CpuShare {
    hundredths: u32,
}

/// The most cores `cpu` names: more than any host has.
const CPU_MOST: u32 = 1024;

impl CpuShare {
    /// The share as a percentage of one core: `0.5` is 50, `2` is 200.
    pub fn percent(self) -> u32 {
        self.hundredths
    }
}

impl FromStr for CpuShare {
    type Err = String;

    fn from_str(written: &str) -> Result<Self, Self::Err> {
        let malformed = || {
            format!(
                "resources.cpu = {written}: write a number of cores, such as \"0.5\" or \"2\", with at most two decimals"
            )
        };
        let (whole, fraction) = written.split_once('.').unwrap_or((written, ""));
        let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
        if whole.is_empty()
            || whole.len() > 4
            || fraction.len() > 2
            || (written.contains('.') && fraction.is_empty())
            || !digits(whole)
            || !digits(fraction)
        {
            return Err(malformed());
        }
        let whole: u32 = whole.parse().map_err(|_| malformed())?;
        let fraction: u32 = format!("{fraction:0<2}").parse().map_err(|_| malformed())?;
        let hundredths = whole * 100 + fraction;
        if hundredths == 0 || hundredths > CPU_MOST * 100 {
            return Err(format!(
                "resources.cpu = {written}: set it from 0.01 to {CPU_MOST} cores"
            ));
        }
        Ok(CpuShare { hundredths })
    }
}

impl fmt::Display for CpuShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (whole, fraction) = (self.hundredths / 100, self.hundredths % 100);
        let text = match fraction {
            0 => whole.to_string(),
            f if f % 10 == 0 => format!("{whole}.{}", f / 10),
            f => format!("{whole}.{f:02}"),
        };
        f.pad(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_share_of_the_cpu_is_a_number_of_cores() {
        for (written, percent) in [
            ("0.5", 50),
            ("2", 200),
            ("0.01", 1),
            ("1.25", 125),
            ("1.5", 150),
            ("1024", 102_400),
        ] {
            let share: CpuShare = written.parse().unwrap();
            assert_eq!(share.percent(), percent, "{written}");
            assert_eq!(share.to_string(), written);
        }
    }

    #[test]
    fn a_share_written_otherwise_is_refused_with_how_to_write_it() {
        for written in [
            "", ".5", "1.", "0.125", "50%", "-1", "1e2", " 1", "one", "12345",
        ] {
            let why = written.parse::<CpuShare>().unwrap_err();
            assert!(why.contains("number of cores"), "{written}: {why}");
        }
        for written in ["0", "0.00", "1025", "1024.01"] {
            let why = written.parse::<CpuShare>().unwrap_err();
            assert!(why.contains("from 0.01 to 1024"), "{written}: {why}");
        }
    }

    #[test]
    fn a_memory_limit_is_a_size_within_bounds() {
        assert_eq!(memory("64M").unwrap(), ByteSize(64 << 20));
        assert_eq!(memory("2G").unwrap(), ByteSize(2 << 30));
        assert!(memory("63M").unwrap_err().contains("from 64M"));
        assert!(memory("lots").unwrap_err().contains("not a size"));
        assert!(memory("2048G").is_ok());
        assert!(memory(&format!("{}", MEMORY_MOST + 1)).is_err());
    }
}
