//! `enclos launch` and `enclos logs`: one of a sandbox's runtime services,
//! as the host's service manager runs it, and the services' logs.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

use clap::Args;

use enclos::engine::{Engine, printable_line};
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
    Ok(u8::try_from(end.exit).unwrap_or(1))
}

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
    let cannot = |e: io::Error| Error::Session {
        what: format!("cannot run tail: {e}"),
    };
    let mut tail = tail
        .args(&files)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(cannot)?;
    // The sandbox wrote these lines: shown escaped, so they cannot drive the
    // terminal (design §6).
    if let Some(out) = tail.stdout.take() {
        let shown = show_escaped(out, &mut io::stdout().lock());
        if let Err(e) = shown
            && e.kind() != io::ErrorKind::BrokenPipe
        {
            let _ = tail.kill();
            let _ = tail.wait();
            return Err(cannot(e));
        }
    }
    let status = tail.wait().map_err(cannot)?;
    Ok(if status.success() { 0 } else { 1 })
}

/// The most of one line held before it is shown: a service that never ends
/// a line cannot make `enclos logs` hold all it wrote.
const MAX_LINE: u64 = 64 * 1024;

/// Copies `from` to `to` line by line, each line escaped, and a line longer
/// than `MAX_LINE` shown in pieces.
fn show_escaped(from: impl Read, to: &mut impl Write) -> io::Result<()> {
    let mut from = BufReader::new(from);
    let mut line = Vec::new();
    loop {
        line.clear();
        if (&mut from).take(MAX_LINE).read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        let text = String::from_utf8_lossy(&line);
        writeln!(
            to,
            "{}",
            printable_line(text.strip_suffix('\n').unwrap_or(&text))
        )?;
        to.flush()?;
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
}
