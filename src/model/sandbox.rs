//! Sandbox models. Later issues add workspaces, the runtime and its agents.

use std::fmt;
use std::str::FromStr;

use super::Timestamp;
use super::policy::TemplateName;
use super::runtime::RuntimeKind;

/// A sandbox name: a lowercase letter, then 1 to 40 lowercase letters, digits
/// or hyphens.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SandboxName(String);

/// A sandbox name that does not follow the naming rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "`{0}` is not a valid sandbox name: use a lowercase letter, then 1 to 40 lowercase letters, digits or hyphens, such as `home` or `pi-bot`"
)]
pub struct InvalidName(pub String);

impl SandboxName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The naming rule sandboxes and agents share: a lowercase letter, then 1
/// to 40 lowercase letters, digits or hyphens. Safe in a path, as one shell
/// word, and never read as a flag.
pub const fn is_short_name(s: &str) -> bool {
    // Const, so a name written in code is checked when it compiles.
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes.len() > 41 || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut i = 1;
    while i < bytes.len() {
        let b = bytes[i];
        if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
            return false;
        }
        i += 1;
    }
    true
}

impl FromStr for SandboxName {
    type Err = InvalidName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match is_short_name(s) {
            true => Ok(SandboxName(s.to_owned())),
            false => Err(InvalidName(s.to_owned())),
        }
    }
}

impl fmt::Display for SandboxName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

/// The isolation technology a sandbox is built on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendKind {
    Seatbelt,
    Bubblewrap,
    OpenShell,
    Libkrun,
}

impl BackendKind {
    pub const ALL: [BackendKind; 4] = [
        BackendKind::Seatbelt,
        BackendKind::Bubblewrap,
        BackendKind::OpenShell,
        BackendKind::Libkrun,
    ];

    /// The host, as a sentence names it: where enclos runs a sandbox of
    /// this kind. OpenShell and a microVM are not built yet, and may run on
    /// either system.
    pub const fn host(self) -> &'static str {
        match self {
            BackendKind::Seatbelt => "this Mac",
            BackendKind::Bubblewrap => "this Linux machine",
            BackendKind::OpenShell | BackendKind::Libkrun => "this host",
        }
    }

    /// Where a sandbox of this kind listens once its policy lets it (ADR
    /// 0028), and who reaches what listens there, as `policy show` and a
    /// runtime install's plan say it. A Seatbelt sandbox shares the host's
    /// network, and nothing holds its listeners to loopback. A bubblewrap
    /// sandbox listens in its own network namespace, which the host's
    /// network does not reach; `enclos dashboard` opens the runtime's
    /// dashboard to the user running it alone (ADR 0039, ADR 0040).
    /// OpenShell and a microVM are not built yet: a session of either has
    /// a network of its own, as `reaches_proxy_over_socket` says.
    pub const fn listening(self) -> &'static str {
        match self {
            BackendKind::Seatbelt => {
                "on TCP, any port but enclos's proxy ports, on every address: what listens in this sandbox can serve the network"
            }
            BackendKind::Bubblewrap => {
                "on TCP, in the sandbox's own network namespace, which its sessions share and the host's network does not reach: `enclos dashboard` opens the runtime's dashboard to the user running it alone (ADR 0040)"
            }
            BackendKind::OpenShell | BackendKind::Libkrun => "on TCP, in the sandbox's own network",
        }
    }

    /// Whether the `mktemp` a sandbox of this kind runs ignores `TMPDIR`
    /// for a call with no template, `-d` or `-t`, as macOS's
    /// `/usr/bin/mktemp` does (design §5, "System temp"). GNU `mktemp`, a
    /// Linux sandbox's, follows it.
    pub fn mktemp_ignores_tmpdir(self) -> bool {
        matches!(self, BackendKind::Seatbelt)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BackendKind::Seatbelt => "seatbelt",
            BackendKind::Bubblewrap => "bubblewrap",
            BackendKind::OpenShell => "openshell",
            BackendKind::Libkrun => "libkrun",
        }
    }

    /// Whether the sandbox's sessions reach its proxy over its Unix socket
    /// alone. A Seatbelt session shares the host's network and reaches the
    /// proxy over TCP on loopback (design §5); a session of every other kind
    /// has a network of its own, out of the host's loopback.
    pub fn reaches_proxy_over_socket(self) -> bool {
        match self {
            BackendKind::Seatbelt => false,
            BackendKind::Bubblewrap | BackendKind::OpenShell | BackendKind::Libkrun => true,
        }
    }

    /// Whether a session sees the host's files through one bind of `/`, as
    /// under bubblewrap's `--ro-bind / /`: a protected file behind a link is
    /// then there at its real path too, and is probed there. Seatbelt's
    /// rules name the real path already.
    pub fn binds_the_hosts_root(self) -> bool {
        match self {
            BackendKind::Bubblewrap => true,
            BackendKind::Seatbelt | BackendKind::OpenShell | BackendKind::Libkrun => false,
        }
    }
}

/// A backend name enclos does not know.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown backend `{0}`: use one of seatbelt, bubblewrap, openshell, libkrun")]
pub struct UnknownBackend(pub String);

impl FromStr for BackendKind {
    type Err = UnknownBackend;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BackendKind::ALL
            .into_iter()
            .find(|kind| kind.as_str() == s)
            .ok_or_else(|| UnknownBackend(s.to_owned()))
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// Where a sandbox is in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SandboxState {
    Created,
    Running,
    Stopped,
    Failed { reason: String },
}

/// What enclos records about a sandbox it created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxRecord {
    pub name: SandboxName,
    pub backend: BackendKind,
    /// The template it was created from. Its `policy.toml` may name
    /// another since; the active policy's inputs say which it is built on.
    pub created_from: TemplateName,
    pub state: SandboxState,
    /// The sandbox's proxy port on loopback (design §4), reserved when it
    /// is created.
    pub proxy_port: u16,
    /// The runtime installed in it, if any (at most one, ADR 0003).
    pub runtime: Option<RuntimeKind>,
    pub created_at: Timestamp,
}

/// The range sandbox proxy ports are taken from, every install's. A sandbox
/// that may listen binds none of them (ADR 0028), denied one by one since
/// Seatbelt has no port ranges: 1,000 rules add about 0.03 s to a launch
/// (macOS 26.5.2, ADR 0028).
pub const PORT_FIRST: u16 = 41000;
pub const PORT_LAST: u16 = 41999;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_names() {
        for name in ["home", "pi-bot", "a1", &format!("a{}", "b".repeat(40))] {
            assert!(name.parse::<SandboxName>().is_ok(), "{name}");
        }
    }

    #[test]
    fn rejects_invalid_names() {
        for name in [
            "",
            "a",
            "Home",
            "1abc",
            "-ab",
            "a_b",
            "ab/c",
            &"a".repeat(42),
        ] {
            assert!(name.parse::<SandboxName>().is_err(), "{name}");
        }
    }

    #[test]
    fn backend_kind_round_trips_through_its_name() {
        for kind in BackendKind::ALL {
            assert_eq!(kind.as_str().parse::<BackendKind>(), Ok(kind));
        }
        assert!("docker".parse::<BackendKind>().is_err());
    }

    #[test]
    fn only_seatbelt_sessions_reach_the_proxy_over_tcp() {
        for kind in BackendKind::ALL {
            assert_eq!(
                kind.reaches_proxy_over_socket(),
                kind != BackendKind::Seatbelt,
                "{kind}"
            );
        }
    }

    /// Only a Seatbelt sandbox's listeners can serve the network: a
    /// bubblewrap one's are in its own network namespace, and `enclos
    /// dashboard` is the way in (ADR 0040).
    #[test]
    fn only_a_seatbelt_sandbox_listening_can_serve_the_network() {
        for kind in BackendKind::ALL {
            assert_eq!(
                kind.listening().contains("can serve the network"),
                kind == BackendKind::Seatbelt,
                "{kind}"
            );
        }
        let bubblewrap = BackendKind::Bubblewrap.listening();
        assert!(bubblewrap.contains("own network namespace"), "{bubblewrap}");
        assert!(
            bubblewrap.contains("the host's network does not reach"),
            "{bubblewrap}"
        );
        assert!(bubblewrap.contains("`enclos dashboard`"), "{bubblewrap}");
        assert!(!bubblewrap.contains("every address"), "{bubblewrap}");
    }

    #[test]
    fn names_and_backends_honor_a_table_width() {
        let name: SandboxName = "home".parse().unwrap();
        assert_eq!(format!("{name:<6}|"), "home  |");
        assert_eq!(format!("{:<10}|", BackendKind::Seatbelt), "seatbelt  |");
    }
}
