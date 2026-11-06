//! Connections to sockets outside the sandbox, Unix and TCP.

use std::path::Path;

use super::{End, UNPREPARED, answered, call, program};
use crate::probes::{Expect, OwnReading, Probe, probe, sh_quote};

/// A connection refused: the path is not there or not a socket, nothing
/// listens under that name in the network namespace, or a rule refused it.
/// A server too busy to take it was reached.
const CONNECT: (&[&str], &[&str], &str) = (
    &["ENOENT", "ENOTDIR", "ECONNREFUSED", "EACCES", "EPERM"],
    &["timeout", "EAGAIN/EWOULDBLOCK"],
    "it reached the socket, whose server was too busy to take it",
);

pub(super) const CONNECTED: OwnReading = OwnReading {
    label: "connection refused",
    read: |succeeded, output| answered(CONNECT.0, CONNECT.1, CONNECT.2, succeeded, output),
    when_control_fails: None,
};

/// The same, for a socket in another sandbox's network namespace, which
/// the host checks is still listed there.
const CONNECTED_ELSEWHERE: OwnReading = OwnReading {
    label: "connection refused, elsewhere",
    read: CONNECTED.read,
    when_control_fails: Some("it no longer listens in that sandbox's network namespace"),
};

/// The program that connects to the Unix socket at `address` (`@` for an
/// abstract name) with a socket of type `kind`.
fn connect_unix(end: End) -> String {
    format!(
        r#"my ($kind, $at) = @ARGV; $at =~ s/^@/\0/;
socket(my $s, PF_UNIX, $kind, 0) or do {UNPREPARED};
$SIG{{ALRM}} = sub {{ print "timeout\n"; exit 3 }}; alarm 5;
my $w = word(connect($s, pack_sockaddr_un($at)));
{}"#,
        end.perl()
    )
}

/// A connection to the host's Unix socket at `address`, which the host
/// makes too, as its control.
pub(crate) fn connect_to(route: &'static str, name: String, address: &str, kind: u32) -> Probe {
    call(
        route,
        name,
        connect_unix,
        &[kind.to_string(), sh_quote(Path::new(address))],
        CONNECTED,
        &["ok"],
    )
}

/// A connection to an abstract socket in another sandbox's network
/// namespace, which the host cannot reach either: its control checks that
/// the socket is still listed in `table`, that namespace's `/proc` table.
pub(crate) fn connect_elsewhere(name: String, address: &str, kind: u32, table: &Path) -> Probe {
    let args = [kind.to_string(), sh_quote(Path::new(address))];
    probe(
        "abstract sockets",
        name,
        program(&connect_unix(End::Probe), &args),
        Expect::Own(CONNECTED_ELSEWHERE),
        format!(
            "/usr/bin/grep -qF -- {} {}",
            sh_quote(Path::new(&format!(" {address}"))),
            sh_quote(table)
        ),
    )
}

/// A TCP connection to 127.0.0.1 at `port`, where the host listens.
pub(crate) fn connect_loopback(port: u16) -> Probe {
    let code = |end: End| {
        format!(
            r#"my ($port) = @ARGV;
socket(my $s, PF_INET, SOCK_STREAM, 0) or do {UNPREPARED};
$SIG{{ALRM}} = sub {{ print "timeout\n"; exit 3 }}; alarm 5;
my $w = word(connect($s, pack_sockaddr_in($port, inet_aton("127.0.0.1"))));
{}"#,
            end.perl()
        )
    };
    call(
        "network",
        format!("connect to 127.0.0.1:{port}, where a program listens on the host"),
        code,
        &[port.to_string()],
        CONNECTED,
        &["ok"],
    )
}
