//! The calls bubblewrap's probes make, each through perl: `/usr/bin/perl`
//! and the modules used here are in `perl-base`, which Debian and Ubuntu
//! install everywhere. Each program prints one word last, `ok` or the name
//! of the errno the call got, so a refusal is read from what the kernel
//! answered, never from a program's message in the host's language. A probe
//! and its control run the same program, which ends as [`End`] says.

mod connect;
mod folders;
mod kernel;
#[cfg(test)]
mod tests;

use crate::probes::{Expect, Outcome, OwnReading, Probe, last_line, probe};

pub(super) use connect::{connect_elsewhere, connect_loopback, connect_to};
pub(super) use folders::{remove_home, rename_beside};
pub(super) use kernel::{Numbers, tiocsti, vsock};

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
