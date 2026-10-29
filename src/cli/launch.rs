//! `enclos launch` and `enclos logs`: one of a sandbox's runtime services,
//! as the host's service manager runs it, and the services' logs.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

use clap::Args;

use enclos::engine::{Engine, SessionEnd, printable_line};
use enclos::error::{Error, Result};
use enclos::model::audit::Actor;
use enclos::model::sandbox::SandboxName;

#[derive(Args)]
pub struct LaunchArgs {
    sandbox: SandboxName,
    /// The runtime's name for the service, such as `gateway`.
    service: String,
}

/// Runs one of the runtime's services in the sandbox until it exits.
pub fn run(engine: &Engine, by: &Actor, args: LaunchArgs) -> Result<u8> {
    let end = match engine.launch(by, &args.sandbox, &args.service) {
        Ok(end) => end,
        // Exits 0, so that the service manager does not start it again to
        // meet the same locked keychain every few seconds: the sandbox is
        // marked failed, saying why, until `sandbox start`.
        Err(e) if matches!(e.root(), Error::SecretsLocked { .. }) => {
            let _ = writeln!(io::stderr(), "error: {e}");
            return Ok(0);
        }
        Err(e) => return Err(e),
    };
    // Into the service's log, which `enclos logs` shows.
    super::connect::report_end(&args.sandbox, &end);
    Ok(service_exit(&end))
}

/// A service asked to restart exits non-zero, so the service manager starts
/// it again, even when its program exits 0 (ADR 0031).
fn service_exit(end: &SessionEnd) -> u8 {
    let exit = if end.restarting && end.exit == 0 {
        EX_TEMPFAIL
    } else {
        end.exit
    };
    u8::try_from(exit).unwrap_or(1)
}

/// `sysexits.h`, as Hermes exits to be restarted.
const EX_TEMPFAIL: i32 = 75;

#[derive(Args)]
pub struct LogsArgs {
    sandbox: SandboxName,
    /// Keep printing as the services write.
    #[arg(short, long)]
    follow: bool,
}

pub fn logs(engine: &Engine, args: LogsArgs) -> Result<u8> {
    let files = engine.log_files(&args.sandbox)?;
    if files.is_empty() {
        println!(
            "Sandbox {} has no service logs yet. Start it with `enclos sandbox start {}`.",
            args.sandbox, args.sandbox
        );
        return Ok(0);
    }
    let mut tail = Command::new("tail");
    tail.args(["-n", "40"]);
    if args.follow {
        tail.arg("-F");
    }
    let mut tail = tail
        .args(&files)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| failed(format!("cannot run tail: {e}")))?;
    let out = tail.stdout.take().expect("tail's output is piped");
    // What the services print comes from the sandbox: shown escaped, so it
    // cannot drive the terminal (design §4).
    let shown = show_escaped(out, &mut io::stdout().lock());
    if let Err(e) = shown {
        // tail would otherwise wait for a service's next line to learn that
        // nobody reads it any more.
        let _ = tail.kill();
        let _ = tail.wait();
        return match e {
            // Whoever read the logs, such as `head`, has what it wanted.
            Failed::Write(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(0),
            Failed::Write(e) => Err(failed(format!(
                "cannot write the logs to standard output: {e}"
            ))),
            Failed::Read(e) => Err(failed(format!("cannot read tail's output: {e}"))),
        };
    }
    let status = tail
        .wait()
        .map_err(|e| failed(format!("cannot wait for tail: {e}")))?;
    Ok(if status.success() { 0 } else { 1 })
}

fn failed(what: String) -> Error {
    Error::Session { what }
}

/// The most bytes of one line held before it is shown, its newline
/// included: a service that never ends a line cannot make `enclos logs`
/// hold all it wrote.
const MAX_LINE: u64 = 64 * 1024;

/// Which side of `show_escaped` failed.
#[derive(Debug)]
enum Failed {
    Read(io::Error),
    Write(io::Error),
}

/// Shows `from` on `to` line by line, each line escaped and without its
/// line ending (`\n` or `\r\n`). Bytes that are not UTF-8 show as U+FFFD,
/// and a line longer than `MAX_LINE` bytes is shown in pieces.
fn show_escaped(from: impl Read, to: &mut impl Write) -> std::result::Result<(), Failed> {
    let mut from = BufReader::new(from);
    let mut line = Vec::new();
    // Whether the last piece was cut before its line ended.
    let mut cut = false;
    loop {
        line.clear();
        let read = (&mut from)
            .take(MAX_LINE)
            .read_until(b'\n', &mut line)
            .map_err(Failed::Read)?;
        if read == 0 {
            return Ok(());
        }
        let ended = line.ends_with(b"\n");
        // The end of a line cut right before it is no line of its own.
        if std::mem::replace(&mut cut, !ended) && line == b"\n" {
            continue;
        }
        let text = String::from_utf8_lossy(&line);
        let text = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(&text);
        writeln!(to, "{}", printable_line(text))
            .and_then(|()| to.flush())
            .map_err(Failed::Write)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_output_is_shown_escaped_line_by_line() {
        let written = b"started\n\x1b]52;c;cHduZWQ=\x07\x1b[2Jcleared\nno end";
        let mut shown = Vec::new();
        show_escaped(&written[..], &mut shown).unwrap();
        assert_eq!(
            String::from_utf8(shown).unwrap(),
            "started\n\\u{1b}]52;c;cHduZWQ=\\u{7}\\u{1b}[2Jcleared\nno end\n"
        );
    }

    #[test]
    fn a_line_without_an_end_is_shown_in_pieces() {
        let written = vec![b'x'; MAX_LINE as usize * 2 + 1];
        let mut shown = Vec::new();
        show_escaped(&written[..], &mut shown).unwrap();
        let shown = String::from_utf8(shown).unwrap();
        let lines: Vec<_> = shown.lines().map(str::len).collect();
        assert_eq!(lines, [MAX_LINE as usize, MAX_LINE as usize, 1]);
    }

    fn shown(written: &[u8]) -> String {
        let mut shown = Vec::new();
        show_escaped(written, &mut shown).unwrap();
        String::from_utf8(shown).unwrap()
    }

    #[test]
    fn line_endings_are_not_shown_but_a_carriage_return_inside_is() {
        assert_eq!(shown(b"a\r\nb\r\n"), "a\nb\n");
        assert_eq!(shown(b"ok\rhidden\n"), "ok\\rhidden\n");
    }

    #[test]
    fn a_line_as_long_as_the_limit_is_shown_without_an_empty_line_after() {
        let max = MAX_LINE as usize;
        let mut written = vec![b'x'; max];
        written.extend_from_slice(b"\nnext\n");
        let lines: Vec<_> = shown(&written).lines().map(str::len).collect();
        assert_eq!(lines, [max, 4]);
        let mut written = vec![b'x'; max - 1];
        written.push(b'\n');
        let lines: Vec<_> = shown(&written).lines().map(str::len).collect();
        assert_eq!(lines, [max - 1]);
    }

    #[test]
    fn a_piece_cut_inside_an_escape_sequence_shows_no_control() {
        let mut written = vec![b'x'; MAX_LINE as usize - 1];
        written.extend_from_slice("\x1b[2Jé\u{9b}2J\n".as_bytes());
        let shown = shown(&written);
        assert!(
            shown.lines().all(|l| !l.chars().any(char::is_control)),
            "{shown}"
        );
        assert!(shown.contains("\\u{9b}2J"), "{shown}");
    }

    #[test]
    fn a_reader_that_left_is_a_write_failure() {
        struct Gone;
        impl Write for Gone {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let e = show_escaped(&b"line\n"[..], &mut Gone).unwrap_err();
        assert!(
            matches!(e, Failed::Write(ref e) if e.kind() == io::ErrorKind::BrokenPipe),
            "{e:?}"
        );
    }

    #[test]
    fn a_service_asked_to_restart_never_exits_0() {
        let end = |exit, restarting| SessionEnd {
            session: enclos::model::session::SessionId(1),
            exit,
            signal: None,
            left: enclos::engine::Left::Nothing,
            notes: Vec::new(),
            restarting,
        };
        assert_eq!(service_exit(&end(0, true)), 75);
        assert_eq!(service_exit(&end(75, true)), 75);
        assert_eq!(service_exit(&end(143, true)), 143);
        assert_eq!(service_exit(&end(0, false)), 0);
        assert_eq!(service_exit(&end(3, false)), 3);
    }
}
