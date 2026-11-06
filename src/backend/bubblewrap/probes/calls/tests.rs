use std::path::Path;

use super::connect::{CONNECTED, connect_elsewhere, connect_loopback, connect_to};
use super::folders::{MOVED, remove_home, rename_beside};
use super::kernel::{FILTERED, Numbers, tiocsti, vsock};
use super::{End, PERL};
use crate::probes::{Outcome, OwnReading, Proof};

fn read(reading: OwnReading, succeeded: bool, output: &str) -> Outcome {
    (reading.read)(succeeded, output)
}

fn control(probe: &crate::probes::Probe) -> &str {
    let Proof::Control { control, .. } = &probe.proof else {
        panic!("{} has a control", probe.name);
    };
    control.as_str()
}

/// Only the word on the last line counts: the same name elsewhere in the
/// output, as in a message, does not close a probe.
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
/// perl compiles (`perl -c`, which runs nothing but its `use` lines), with a
/// quote in a path among its arguments.
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
        for script in [probe.script.as_str(), control(&probe)] {
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

/// Each kernel call's control works on this host, outside any sandbox: its
/// program runs to the call and the kernel answers as it does outside. All
/// are harmless: a character pushed into a terminal the program made, a
/// mount on a path that is nowhere, a socket opened and closed, a user
/// namespace the program leaves as it exits, and an attach to this test's
/// own child that stops nothing.
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
        let out = std::process::Command::new("/bin/sh")
            .args(["-c", control(&probe)])
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

/// The control works on the answers that show the call got as far as the
/// sandbox refuses it; the probe on `ok` alone.
#[test]
fn a_control_ends_on_what_shows_the_route_works_outside() {
    let probe = End::Probe.perl();
    assert!(probe.contains("/^ok/"), "{probe}");
    let control = End::Control(&["ok", "EIO"]).perl();
    assert!(control.contains("qw(ok EIO)"), "{control}");
}
