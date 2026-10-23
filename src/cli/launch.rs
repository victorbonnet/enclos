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
    let end = engine.launch(by, &args.sandbox, &args.service)?;
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
    // With --json, JSON Lines: one `{"line": …}` per line, escaped as
    // every document is. Which file a line is from is left out: tail's
    // headers are lines a sandbox could write too.
    let json = super::output::json();
    if files.is_empty() {
        let none = format!(
            "Sandbox {} has no service logs yet. Start it with `enclos sandbox start {}`.",
            args.sandbox, args.sandbox
        );
        match json {
            true => super::output::note(&none),
            false => println!("{none}"),
        }
        return Ok(0);
    }
    let mut tail = Command::new("tail");
    tail.args(["-n", "40"]);
    if json {
        tail.arg("-q");
    }
    if args.follow {
        tail.arg("-F");
    }
    let mut tail = tail
        .args(&files)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| failed(format!("cannot run tail: {e}")))?;
    let out = tail.stdout.take().expect("tail's output is piped");
    // What the services print comes from the sandbox: shown escaped, in
    // text and in JSON, so it cannot drive the terminal (design §4).
    let shown = show_lines(out, &mut io::stdout().lock(), json);
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
    if !status.success() {
        return Err(failed(format!(
            "tail {status} reading the logs of sandbox {}; what it said is above",
            args.sandbox
        )));
    }
    Ok(0)
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

/// `show_lines` in text, as the tests use it.
#[cfg(test)]
fn show_escaped(from: impl Read, to: &mut impl Write) -> std::result::Result<(), Failed> {
    show_lines(from, to, false)
}

/// Shows `from` on `to` line by line, each line escaped and without its
/// line ending (`\n` or `\r\n`); with `json`, each as `{"line": …}`. Bytes
/// that are not UTF-8 show as U+FFFD, and a line of more than `MAX_LINE`
/// bytes before its end is shown in pieces, cut between characters, which
/// JSON numbers: `"piece": 1`, 2, …, the last ending the line. A piece 1
/// starts a line, so two cut lines in a row are told apart.
fn show_lines(from: impl Read, to: &mut impl Write, json: bool) -> std::result::Result<(), Failed> {
    let mut from = BufReader::new(from);
    let mut line = Vec::new();
    // What a cut kept back for the next piece: a character it would split.
    let mut kept = Vec::new();
    // The number of the piece just shown of a line still being cut; 0
    // outside one.
    let mut piece: u32 = 0;
    loop {
        line.clear();
        line.append(&mut kept);
        let room = MAX_LINE - line.len() as u64;
        (&mut from)
            .take(room)
            .read_until(b'\n', &mut line)
            .map_err(Failed::Read)?;
        if line.is_empty() {
            return Ok(());
        }
        let ended = line.ends_with(b"\n");
        // Full before its end: a line exactly as long as the limit is whole
        // when its end (`\n` or `\r\n`) comes next, or when the logs end
        // there; else it is cut, between characters.
        let cut = !ended && line.len() as u64 == MAX_LINE && {
            let next = from.fill_buf().map_err(Failed::Read)?;
            let end: &[u8] = match next {
                [b'\n', ..] => b"\n",
                [b'\r', b'\n', ..] => b"\r\n",
                _ => b"",
            };
            match (end.is_empty(), next.is_empty()) {
                (false, _) => {
                    let n = end.len();
                    line.extend_from_slice(end);
                    from.consume(n);
                    false
                }
                (true, empty) => !empty,
            }
        };
        if cut {
            kept = line.split_off(split_character_at(&line));
        }
        let this = match cut || piece > 0 {
            true => piece + 1,
            false => 0,
        };
        piece = if cut { this } else { 0 };
        let text = String::from_utf8_lossy(&line);
        let text = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(&text);
        let written = match (json, this) {
            (true, 0) => writeln!(
                to,
                "{}",
                super::output::line(&serde_json::json!({ "line": text }))
            ),
            (true, this) => writeln!(
                to,
                "{}",
                super::output::line(&serde_json::json!({ "line": text, "piece": this }))
            ),
            (false, _) => writeln!(to, "{}", printable_line(text)),
        };
        written.and_then(|()| to.flush()).map_err(Failed::Write)?;
    }
}

/// Where a cut of `line` goes so as not to split its last character: the
/// start of a UTF-8 sequence at its end that the cut would leave short, else
/// its end.
fn split_character_at(line: &[u8]) -> usize {
    for back in 1..=3.min(line.len()) {
        let at = line.len() - back;
        let byte = line[at];
        let needs = match byte {
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf7 => 4,
            // A continuation byte: look further back.
            0x80..=0xbf => continue,
            _ => return line.len(),
        };
        return if needs > back { at } else { line.len() };
    }
    line.len()
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
    fn in_json_each_line_is_an_object_with_its_control_characters_escaped() {
        let mut shown = Vec::new();
        show_lines(&b"started\n\x1b[2Jcleared\r\n"[..], &mut shown, true).unwrap();
        assert_eq!(
            String::from_utf8(shown).unwrap(),
            "{\"line\":\"started\"}\n{\"line\":\"\\u001b[2Jcleared\"}\n"
        );
    }

    /// The pieces of a cut line are numbered, so a reader tells them from
    /// lines and joins them; an unended last line is not a piece.
    #[test]
    fn in_json_the_pieces_of_a_cut_line_are_numbered() {
        let mut written = vec![b'x'; MAX_LINE as usize + 3];
        written.extend_from_slice(b"\nnext\nlast");
        let mut shown = Vec::new();
        show_lines(&written[..], &mut shown, true).unwrap();
        let shown: Vec<serde_json::Value> = String::from_utf8(shown)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(shown.len(), 4);
        assert_eq!(shown[0]["piece"], 1);
        assert_eq!(shown[1]["piece"], 2);
        assert_eq!(shown[1]["line"], "xxx");
        assert!(shown[2].get("piece").is_none());
        assert_eq!(shown[3]["line"], "last");
        assert!(shown[3].get("piece").is_none());
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

    fn pieces(written: &[u8]) -> Vec<serde_json::Value> {
        let mut shown = Vec::new();
        show_lines(written, &mut shown, true).unwrap();
        String::from_utf8(shown)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// Two cut lines in a row: each starts again at piece 1.
    #[test]
    fn two_cut_lines_in_a_row_are_told_apart() {
        let max = MAX_LINE as usize;
        let mut written = vec![b'x'; max + 3];
        written.push(b'\n');
        written.extend(vec![b'y'; max + 3]);
        written.push(b'\n');
        let numbers: Vec<_> = pieces(&written)
            .iter()
            .map(|v| v["piece"].clone())
            .collect();
        assert_eq!(numbers, [1, 2, 1, 2]);
    }

    /// A line exactly as long as the limit is one line, not a lone piece,
    /// whether its end follows or the logs end there.
    #[test]
    fn a_line_exactly_as_long_as_the_limit_is_not_cut() {
        let max = MAX_LINE as usize;
        let mut written = vec![b'x'; max];
        written.extend_from_slice(b"\nnext\n");
        let shown = pieces(&written);
        assert_eq!(shown.len(), 2, "{shown:?}");
        assert!(shown.iter().all(|v| v.get("piece").is_none()), "{shown:?}");
        assert_eq!(shown[0]["line"].as_str().unwrap().len(), max);
        let shown = pieces(&vec![b'x'; max]);
        assert_eq!(shown.len(), 1);
        assert!(shown[0].get("piece").is_none());
        // Ended by `\r\n` too: no empty piece after it.
        let mut written = vec![b'x'; max];
        written.extend_from_slice(b"\r\nnext\n");
        let shown = pieces(&written);
        assert_eq!(shown.len(), 2, "{shown:?}");
        assert!(shown.iter().all(|v| v.get("piece").is_none()), "{shown:?}");
        assert_eq!(shown[0]["line"].as_str().unwrap().len(), max);
    }

    /// A cut never splits a character, so joined pieces are the line; one
    /// that falls between `\r` and `\n` leaves no `\r` in a piece.
    #[test]
    fn a_cut_keeps_characters_and_line_endings_whole() {
        let max = MAX_LINE as usize;
        let mut written = vec![b'x'; max - 1];
        written.extend_from_slice("é".as_bytes());
        written.extend_from_slice(b"z\n");
        let shown = pieces(&written);
        let joined: String = shown.iter().map(|v| v["line"].as_str().unwrap()).collect();
        assert_eq!(joined, format!("{}éz", "x".repeat(max - 1)));
        assert!(!joined.contains('\u{fffd}'));

        let mut written = vec![b'x'; max - 1];
        written.extend_from_slice(b"\r\nnext\n");
        let shown = pieces(&written);
        assert_eq!(shown.len(), 2, "{shown:?}");
        assert_eq!(shown[0]["line"], "x".repeat(max - 1));
        assert!(shown[0].get("piece").is_none());
    }
}
