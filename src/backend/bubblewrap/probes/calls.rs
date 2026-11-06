//! The calls bubblewrap's probes make, each through perl: `/usr/bin/perl`
//! and the modules used here are in `perl-base`, which Debian and Ubuntu
//! install everywhere. Each program prints one word last, `ok` or the name
//! of the errno the call got, so a refusal is read from what the kernel
//! answered, never from a program's message in the host's language. A probe
//! and its control run the same program, which ends as [`End`] says.

use std::path::Path;

use crate::probes::{Expect, Outcome, OwnReading, Probe, last_line, probe, sh_quote};

const PERL: &str = "/usr/bin/perl";

/// What each program starts with: `word` names what the call just before it
/// got, from its result and `$!`.
const PRELUDE: &str = r#"use Errno; use Socket; sub word { return "ok" if $_[0]; my @n = sort grep { $!{$_} } keys %!; @n ? join("/", @n) : "errno " . ($! + 0) }"#;

/// How a program ends, once `$w` holds its word.
#[derive(Debug, Clone, Copy)]
enum End<'a> {
    /// The probe's: it prints the word and succeeds only on `ok`, which a
    /// program may follow with what the call did.
    Probe,
    /// Its control's: it prints the word and succeeds only on one of these,
    /// which show the route works outside the sandbox, or gets as far as
    /// the sandbox refuses it.
    Control(&'a [&'a str]),
}

impl End<'_> {
    fn perl(self) -> String {
        match self {
            End::Probe => r#"print "$w\n"; exit($w =~ /^ok/ ? 0 : 1);"#.to_owned(),
            End::Control(works) => format!(
                r#"print "$w\n"; exit((grep {{ $_ eq $w }} qw({})) ? 0 : 1);"#,
                works.join(" ")
            ),
        }
    }
}

/// The block that stops a program that could not set up its call, which
/// then shows nothing.
const UNPREPARED: &str = r#"{ print "could not prepare: ", word(0), "\n"; exit 2 }"#;

/// The command that runs perl `code` with `args`, each one shell word.
fn program(code: &str, args: &[String]) -> String {
    format!("{PERL} -e '{PRELUDE} {code}' {} 2>&1", args.join(" "))
}

/// A probe of `route` that runs `code`, given how it ends, read by
/// `reading`; its control runs the same on the host and works on one of
/// `works`.
fn call(
    route: &'static str,
    name: String,
    code: impl Fn(End) -> String,
    args: &[String],
    reading: OwnReading,
    works: &[&str],
) -> Probe {
    probe(
        route,
        name,
        program(&code(End::Probe), args),
        Expect::Own(reading),
        program(&code(End::Control(works)), args),
    )
}

/// Closed on one of `closes`, open on a success or on one of `opens`, for
/// `why_open`; any other answer is inconclusive.
fn answered(
    closes: &[&str],
    opens: &[&str],
    why_open: &str,
    succeeded: bool,
    output: &str,
) -> Outcome {
    let word = last_line(output);
    if succeeded {
        return Outcome::Open(format!("it succeeded: {word}"));
    }
    if opens.contains(&word.as_str()) {
        return Outcome::Open(format!("{why_open} ({word})"));
    }
    if closes.contains(&word.as_str()) {
        return Outcome::Closed;
    }
    Outcome::Inconclusive(format!(
        "it failed, but not with the sandbox's refusal ({}): {word}",
        closes.join(" or ")
    ))
}

/// A folder renamed or removed: refused by a read-only mount (`EROFS`),
/// which comes first, or because it is a mount point (`EBUSY`). The
/// filesystem's own refusal of a folder that is not empty means the call
/// got past both.
const MOVED: OwnReading = OwnReading {
    label: "folder held: EROFS or EBUSY",
    read: |succeeded, output| {
        answered(
            &["EROFS", "EBUSY"],
            &["ENOTEMPTY", "EEXIST"],
            "the call reached the filesystem, which refused it only because a folder was not empty",
            succeeded,
            output,
        )
    },
    when_control_fails: Some(
        "outside the sandbox, the filesystem did not refuse it as it refuses a folder that is not empty",
    ),
};

/// What refused folder moves look like outside the sandbox.
const NOT_EMPTY: &[&str] = &["ENOTEMPTY", "EEXIST"];

/// Renames `folder` onto a folder beside it, which the program makes and
/// fills first, so that the filesystem refuses the rename whatever the
/// policy and nothing moves. Where the folder's parent is read-only, as the
/// sandbox has its home's and each workspace's, the folder beside it cannot
/// be made (`EROFS`), and the rename gets the same refusal, as both are
/// checked on the one mount. What the program made is removed.
pub(super) fn rename_beside(folder: &Path, tag: u32) -> Probe {
    let beside = folder
        .parent()
        .unwrap_or(folder)
        .join(format!("enclos-probe-{tag}"));
    let code = |end: End| {
        format!(
            r#"my ($folder, $beside) = @ARGV; my $made = mkdir($beside);
if ($made) {{ if (!open(my $f, ">", "$beside/kept")) {{ my $e = word(0); rmdir($beside); print "could not prepare: $e\n"; exit 2 }} }}
elsif (!$!{{EROFS}}) {UNPREPARED}
my $w = word(rename($folder, $beside));
if ($made && $w ne "ok") {{ unlink("$beside/kept"); rmdir($beside) }}
$w = "ok: $folder is now at $beside" if $w eq "ok";
{}"#,
            end.perl()
        )
    };
    call(
        "renames",
        format!("rename {}", folder.display()),
        code,
        &[sh_quote(folder), sh_quote(&beside)],
        MOVED,
        NOT_EMPTY,
    )
}

/// Removes the sandbox `home`, which holds `tmp/`, made again first: the
/// filesystem refuses to remove a folder that is not empty, whatever the
/// policy, and the program stops before the call if it finds it empty.
pub(super) fn remove_home(home: &Path) -> Probe {
    let code = |end: End| {
        format!(
            r#"my ($home) = @ARGV; mkdir("$home/tmp");
if (!opendir(my $d, $home)) {UNPREPARED}
elsif (!grep {{ $_ ne "." && $_ ne ".." }} readdir($d)) {{ print "could not prepare: it is empty\n"; exit 2 }}
my $w = word(rmdir($home));
$w = "ok: $home was removed" if $w eq "ok";
{}"#,
            end.perl()
        )
    };
    call(
        "writable folders",
        "remove the sandbox home".to_owned(),
        code,
        &[sh_quote(home)],
        MOVED,
        NOT_EMPTY,
    )
}

/// A connection refused: the path is not there or not a socket, nothing
/// listens under that name in the network namespace, or a rule refused it.
/// A server too busy to take it was reached.
const CONNECT: (&[&str], &[&str], &str) = (
    &["ENOENT", "ENOTDIR", "ECONNREFUSED", "EACCES", "EPERM"],
    &["timeout", "EAGAIN/EWOULDBLOCK"],
    "it reached the socket, whose server was too busy to take it",
);

const CONNECTED: OwnReading = OwnReading {
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
pub(super) fn connect_to(route: &'static str, name: String, address: &str, kind: u32) -> Probe {
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
pub(super) fn connect_elsewhere(name: String, address: &str, kind: u32, table: &Path) -> Probe {
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
pub(super) fn connect_loopback(port: u16) -> Probe {
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

/// Refused by the seccomp filter, which answers `EPERM` before the kernel
/// looks at the call's arguments.
const FILTERED: OwnReading = OwnReading {
    label: "refused by the filter: EPERM",
    read: |succeeded, output| answered(&["EPERM"], &[], "", succeeded, output),
    when_control_fails: Some(
        "outside the sandbox, the call did not get as far as the sandbox refuses it",
    ),
};

/// Opens an `AF_VSOCK` socket, which no network namespace holds: refused by
/// the filter. Outside, the kernel opens one, or says it has no such family.
pub(super) fn vsock() -> Probe {
    call(
        "vsock",
        "open an AF_VSOCK socket, which reaches past the network namespace".to_owned(),
        |end| {
            format!(
                "my $w = word(socket(my $s, 40, SOCK_STREAM, 0)); {}",
                end.perl()
            )
        },
        &[],
        FILTERED,
        &["ok", "EAFNOSUPPORT"],
    )
}

/// Pushes a character into the input of a terminal the program opens and
/// makes its own, as a session would type into the terminal it runs in:
/// refused by the filter. Outside, the kernel takes it, or refuses it
/// itself where `dev.tty.legacy_tiocsti` is off (`EIO`). perl's `ioctl`
/// may write to its last argument, so each is a variable.
pub(super) fn tiocsti() -> Probe {
    let code = |end: End| {
        format!(
            r#"use POSIX ();
open(my $m, "+<", "/dev/ptmx") or do {UNPREPARED};
my $unlock = pack("i", 0); ioctl($m, 0x40045431, $unlock) or do {UNPREPARED};
my $n = pack("i", 0); ioctl($m, 0x80045430, $n) or do {UNPREPARED};
my $pid = fork(); defined($pid) or do {UNPREPARED};
if ($pid == 0) {{ POSIX::setsid(); open(my $t, "+<", "/dev/pts/" . unpack("i", $n)) or do {UNPREPARED};
my $typed = "x"; my $w = word(ioctl($t, 0x5412, $typed)); {} }}
waitpid($pid, 0); exit($? >> 8);"#,
            end.perl()
        )
    };
    call(
        "terminals",
        "type into its terminal (TIOCSTI)".to_owned(),
        code,
        &[],
        FILTERED,
        &["ok", "EIO"],
    )
}

/// The system calls perl has no function for, by number on this
/// architecture.
#[derive(Debug, Clone, Copy)]
pub(super) struct Numbers {
    ptrace: u32,
    unshare: u32,
    mount: u32,
}

impl Numbers {
    /// This host's, if enclos knows its architecture's.
    pub(super) fn here() -> Option<Numbers> {
        match std::env::consts::ARCH {
            "x86_64" => Some(Numbers {
                ptrace: 101,
                unshare: 272,
                mount: 165,
            }),
            "aarch64" => Some(Numbers {
                ptrace: 117,
                unshare: 97,
                mount: 40,
            }),
            _ => None,
        }
    }

    /// Attaches to process `pid` with `PTRACE_SEIZE`, which stops nothing,
    /// and is undone as the program exits. A process outside the session's
    /// PID namespace is not there (`ESRCH`); outside, the kernel finds it,
    /// and attaches or refuses (`EPERM`, as Yama does to a process that is
    /// not a child).
    pub(super) fn ptrace(self, pid: u32) -> Probe {
        call(
            "ptrace",
            "attach to a process outside the sandbox".to_owned(),
            |end| {
                format!(
                    "my $w = word(syscall({}, 0x4206, $ARGV[0] + 0, 0, 0) == 0); {}",
                    self.ptrace,
                    end.perl()
                )
            },
            &[pid.to_string()],
            OUT_OF_SIGHT,
            &["ok", "EPERM"],
        )
    }

    /// Makes a user namespace: refused by the filter (`EPERM`), or by
    /// bubblewrap's `--disable-userns` without it (`ENOSPC`).
    pub(super) fn user_namespace(self) -> Probe {
        call(
            "user namespace",
            "make a user namespace".to_owned(),
            |end| {
                format!(
                    "my $w = word(syscall({}, 0x10000000) == 0); {}",
                    self.unshare,
                    end.perl()
                )
            },
            &[],
            NO_NAMESPACE,
            &["ok"],
        )
    }

    /// Mounts a tmpfs on `missing`, a path that is nowhere: the filter
    /// refuses the call before the kernel looks the path up, which it does
    /// first outside (`ENOENT`), before it asks for a capability. perl's
    /// `syscall` takes no constant string, so each is a variable.
    pub(super) fn mount(self, missing: &Path) -> Probe {
        call(
            "mounts",
            "mount a filesystem".to_owned(),
            |end| {
                format!(
                    r#"my ($source, $at, $kind) = ("none", $ARGV[0], "tmpfs");
my $w = word(syscall({}, $source, $at, $kind, 0, 0) == 0); {}"#,
                    self.mount,
                    end.perl()
                )
            },
            &[sh_quote(missing)],
            FILTERED,
            &["ENOENT"],
        )
    }
}

/// A process the session's PID namespace does not hold.
const OUT_OF_SIGHT: OwnReading = OwnReading {
    label: "not there: ESRCH",
    read: |succeeded, output| answered(&["ESRCH"], &[], "", succeeded, output),
    when_control_fails: Some("outside the sandbox, ptrace did not find the process either"),
};

const NO_NAMESPACE: OwnReading = OwnReading {
    label: "refused: EPERM or ENOSPC",
    read: |succeeded, output| answered(&["EPERM", "ENOSPC"], &[], "", succeeded, output),
    when_control_fails: Some("outside the sandbox, this user may not make one either"),
};

#[cfg(test)]
mod tests {
    use super::*;

    fn read(reading: OwnReading, succeeded: bool, output: &str) -> Outcome {
        (reading.read)(succeeded, output)
    }

    /// Only the word on the last line counts: the same name elsewhere in
    /// the output, as in a message, does not close a probe.
    #[test]
    fn a_probe_is_closed_on_the_word_of_its_refusal_alone() {
        assert_eq!(read(FILTERED, false, "EPERM\n"), Outcome::Closed);
        assert!(matches!(
            read(FILTERED, false, "EPERM\nENOENT\n"),
            Outcome::Inconclusive(why) if why.contains("ENOENT")
        ));
        assert!(matches!(
            read(FILTERED, false, "could not prepare: EPERM\n"),
            Outcome::Inconclusive(_)
        ));
        assert!(matches!(read(FILTERED, true, "ok\n"), Outcome::Open(_)));
    }

    #[test]
    fn a_folder_move_that_reached_the_filesystem_is_open() {
        for word in ["EROFS", "EBUSY"] {
            assert_eq!(read(MOVED, false, word), Outcome::Closed, "{word}");
        }
        for word in ["ENOTEMPTY", "EEXIST"] {
            assert!(
                matches!(read(MOVED, false, word), Outcome::Open(_)),
                "{word}"
            );
        }
        assert!(matches!(
            read(MOVED, true, "ok: /h is now at /e"),
            Outcome::Open(why) if why.contains("/h is now at /e")
        ));
        assert!(matches!(
            read(MOVED, false, "EACCES"),
            Outcome::Inconclusive(_)
        ));
    }

    #[test]
    fn a_socket_too_busy_to_take_a_connection_was_reached() {
        for word in ["ENOENT", "ECONNREFUSED"] {
            assert_eq!(read(CONNECTED, false, word), Outcome::Closed, "{word}");
        }
        assert!(matches!(
            read(CONNECTED, false, "timeout"),
            Outcome::Open(_)
        ));
        assert!(matches!(read(CONNECTED, true, "ok"), Outcome::Open(_)));
    }

    /// Every program, the probe's and its control's, is one shell word that
    /// perl compiles (`perl -c`, which runs nothing but its `use` lines),
    /// with a quote in a path among its arguments.
    #[test]
    fn every_program_is_perl_that_compiles() {
        let numbers = Numbers {
            ptrace: 1,
            unshare: 2,
            mount: 3,
        };
        let home = Path::new("/h/it's/home");
        for probe in [
            rename_beside(home, 7),
            remove_home(home),
            connect_to("host sockets", "c".into(), "/run/it's", 1),
            connect_elsewhere("c".into(), "@x", 1, Path::new("/proc/1/net/unix")),
            connect_loopback(8080),
            vsock(),
            tiocsti(),
            numbers.ptrace(9),
            numbers.user_namespace(),
            numbers.mount(Path::new("/missing")),
        ] {
            let crate::probes::Proof::Control { control, .. } = &probe.proof else {
                panic!("{} has a control", probe.name);
            };
            for script in [probe.script.as_str(), control.as_str()] {
                if !script.starts_with(PERL) {
                    continue;
                }
                let checked = script.replacen(&format!("{PERL} -e"), &format!("{PERL} -c -e"), 1);
                let out = std::process::Command::new("/bin/sh")
                    .args(["-c", &checked])
                    .output()
                    .unwrap();
                let said = String::from_utf8_lossy(&out.stdout);
                assert!(said.contains("-e syntax OK"), "{}: {said}", probe.name);
            }
        }
    }

    /// Each kernel call's control works on this host, outside any sandbox:
    /// its program runs to the call and the kernel answers as it does
    /// outside. All are harmless: a character pushed into a terminal the
    /// program made, a mount on a path that is nowhere, a socket opened and
    /// closed, a user namespace the program leaves as it exits, and an
    /// attach to this test's own child that stops nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_each_calls_control_works_here() {
        let numbers = Numbers::here().expect("x86_64 or arm64");
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let checked = [
            tiocsti(),
            vsock(),
            numbers.mount(Path::new("/enclos-probe-missing")),
            numbers.user_namespace(),
            numbers.ptrace(child.id()),
        ]
        .map(|probe| {
            let crate::probes::Proof::Control { control, .. } = &probe.proof else {
                panic!("{} has a control", probe.name);
            };
            let out = std::process::Command::new("/bin/sh")
                .args(["-c", control.as_str()])
                .output()
                .unwrap();
            (probe.name, out)
        });
        let _ = child.kill();
        let _ = child.wait();
        for (name, out) in checked {
            assert!(out.status.success(), "{name}: {out:?}");
        }
    }

    /// The control works on the answers that show the call got as far as
    /// the sandbox refuses it; the probe on `ok` alone.
    #[test]
    fn a_control_ends_on_what_shows_the_route_works_outside() {
        let probe = End::Probe.perl();
        assert!(probe.contains("/^ok/"), "{probe}");
        let control = End::Control(&["ok", "EIO"]).perl();
        assert!(control.contains("qw(ok EIO)"), "{control}");
    }
}
